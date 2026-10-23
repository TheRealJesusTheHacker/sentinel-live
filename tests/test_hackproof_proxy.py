"""HackProof payments pass-through tests.

Loads app.py from a scratch copy (its own config.yaml, data/ and logs/)
so both the disabled and enabled configurations can be imported in one
test process, and drives the proxy against a stub payments upstream
(httpx MockTransport) — no real network, no real payments service.

Proves:
  (a) disabled (the default) -> the three payments routes do not exist;
  (b) enabled -> upstream status + body pass through byte-for-byte for
      the 201 (order created / certificate issued), 202 (certificate
      held for review) and 400 (validation failed) cases, and the
      request body is forwarded intact;
  (c) /api/admin/* is never proxied, even when enabled;
  (d) upstream down -> a clean 502 JSON in the app's {"detail": ...}
      error style, with no traceback leaked.
"""
import importlib.util
import io
import json
import shutil
import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent

ORDER_BODY = b'{"order_id":"ord_1","status":"awaiting_payment","note":"caf\xc3\xa9"}'
PAID_BODY = b'{"order_id":"ord_1","status":"paid","license_key":"KEY-1"}'
ISSUED_BODY = b'{"status":"issued","cert_id":"C1"}'
HELD_BODY = b'{"status":"held_for_review","cert_id":"C2"}'
FORGED_BODY = b'{"error":"validation failed"}'
ADMIN_BODY = b'{"admin":"stub-reached"}'


def _load_app(tmp: Path, name: str, config_text: str):
    """Import app.py (and its feeds.py) from a scratch dir with the
    given config.yaml contents, under a unique module name."""
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
    (tmp / "config.yaml").write_text(config_text, encoding="utf-8")

    feeds_spec = importlib.util.spec_from_file_location(
        "feeds", tmp / "feeds.py")
    feeds_mod = importlib.util.module_from_spec(feeds_spec)
    sys.modules["feeds"] = feeds_mod
    feeds_spec.loader.exec_module(feeds_mod)

    spec = importlib.util.spec_from_file_location(name, tmp / "app.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Stub:
    """A stand-in payments service with the real API's semantics."""

    def __init__(self):
        self.admin_hits = []
        self.received = []
        self.received_headers = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/api/admin/"):
            self.admin_hits.append(path)
            return httpx.Response(200, content=ADMIN_BODY,
                                  headers={"Content-Type": "application/json"})
        self.received.append((request.method, path, request.content))
        self.received_headers.append(dict(request.headers))
        if path == "/api/orders" and request.method == "POST":
            return httpx.Response(201, content=ORDER_BODY,
                                  headers={"Content-Type": "application/json"})
        if path == "/api/certificates" and request.method == "POST":
            verdict = (json.loads(request.content)
                       .get("integrity") or {}).get("verdict")
            if verdict == "clean":
                return httpx.Response(201, content=ISSUED_BODY,
                                      headers={"Content-Type": "application/json"})
            if verdict == "flagged":
                return httpx.Response(202, content=HELD_BODY,
                                      headers={"Content-Type": "application/json"})
            return httpx.Response(400, content=FORGED_BODY,
                                  headers={"Content-Type": "application/json"})
        if path.startswith("/api/orders/") and request.method == "GET":
            return httpx.Response(200, content=PAID_BODY,
                                  headers={"Content-Type": "application/json"})
        return httpx.Response(404, content=b'{"detail":"stub 404"}',
                              headers={"Content-Type": "application/json"})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


@pytest.fixture(scope="module")
def disabled_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-disabled")
    # No hackproof_payments section at all: the defaults must govern.
    return _load_app(tmp, "sl_app_disabled", "server:\n  port: 8443\n")


@pytest.fixture(scope="module")
def enabled(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-enabled")
    mod = _load_app(tmp, "sl_app_enabled",
                    "hackproof_payments:\n  enabled: true\n"
                    "  upstream: \"http://127.0.0.1:9\"\n")
    stub = Stub()
    mod._get_payments_client = stub.client  # route the proxy at the stub
    return mod, stub


@pytest.fixture(scope="module")
def down_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-down")
    mod = _load_app(tmp, "sl_app_down",
                    "hackproof_payments:\n  enabled: true\n"
                    "  upstream: \"http://127.0.0.1:9\"\n")

    def dead_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    mod._get_payments_client = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(dead_handler))
    return mod


# --------------------------------------------------------------- (a) off
def test_disabled_routes_do_not_exist(disabled_app):
    assert disabled_app.HP_PAYMENTS_ENABLED is False
    client = TestClient(disabled_app.app, raise_server_exceptions=False)
    assert client.post("/api/orders", json={"email": "a@b.co"}).status_code == 404
    assert client.get("/api/orders/ord_1").status_code == 404
    assert client.post("/api/certificates", json={}).status_code == 404


def test_disabled_existing_behavior_intact(disabled_app):
    client = TestClient(disabled_app.app, raise_server_exceptions=False)
    # BH-2026-10-23 (H-1): /health is admin-gated in-app now (it used
    # to rely on an edge gate that did not exist in this harness). The
    # liveness contract moved to: gated without the key, open at /.
    resp = client.get("/health")
    assert resp.status_code == 403
    assert client.get("/").status_code == 200


# ----------------------------------------------------------- (b) fidelity
def test_enabled_order_created_201_byte_for_byte(enabled):
    mod, stub = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post("/api/orders", json={"email": "buyer@example.com"})
    assert resp.status_code == 201
    assert resp.content == ORDER_BODY
    assert resp.headers["content-type"].startswith("application/json")
    # the request body reached the upstream intact
    method, path, body = stub.received[-1]
    assert (method, path) == ("POST", "/api/orders")
    assert json.loads(body) == {"email": "buyer@example.com"}


def test_enabled_order_status_200_byte_for_byte(enabled):
    mod, _ = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.get("/api/orders/ord_1")
    assert resp.status_code == 200
    assert resp.content == PAID_BODY


def test_enabled_certificate_issued_201(enabled):
    mod, _ = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post("/api/certificates",
                       json={"integrity": {"verdict": "clean"}})
    assert resp.status_code == 201
    assert resp.content == ISSUED_BODY


def test_enabled_certificate_held_202(enabled):
    mod, _ = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post("/api/certificates",
                       json={"integrity": {"verdict": "flagged"}})
    assert resp.status_code == 202
    assert resp.content == HELD_BODY


def test_enabled_certificate_forged_400(enabled):
    mod, _ = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post("/api/certificates",
                       json={"integrity": {"verdict": "unreadable"}})
    assert resp.status_code == 400
    assert resp.content == FORGED_BODY


# ------------------------------------------------------- (c) admin blocked
def test_enabled_admin_is_never_proxied(enabled):
    mod, stub = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.get("/api/admin/review")
    assert resp.status_code == 404
    assert resp.content != ADMIN_BODY
    assert stub.admin_hits == []


# ------------------------------------------------------------ (d) 502 down
def test_upstream_down_is_clean_502(down_app):
    client = TestClient(down_app.app, raise_server_exceptions=False)
    resp = client.post("/api/orders", json={"email": "a@b.co"})
    assert resp.status_code == 502
    body = resp.json()
    assert "detail" in body
    assert "Traceback" not in resp.text
    assert "unavailable" in body["detail"]


# ------------------------------------------------- BH2 sweep additions
def test_proxy_does_not_leak_sensitive_headers_upstream(enabled):
    """BH2: admin key / cookies / auth sent to THIS server must never
    be forwarded to the payments upstream."""
    mod, stub = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    resp = client.post("/api/orders", json={"email": "buyer@example.com"},
                       headers={"X-Admin-Key": "topsecret",
                                "Cookie": "session=abc123",
                                "Authorization": "Bearer xyz"})
    assert resp.status_code == 201
    hdrs = stub.received_headers[-1]
    assert "x-admin-key" not in hdrs
    assert "cookie" not in hdrs
    assert "authorization" not in hdrs
    assert "topsecret" not in str(hdrs.values())
    assert "abc123" not in str(hdrs.values())


def test_order_id_traversal_is_rejected(enabled):
    """BH2-9: ids outside the token charset never reach the upstream,
    so the fixed /api/orders/{id} path can't be reshaped toward
    /api/admin/* by dot segments or encoded slashes."""
    mod, stub = enabled
    client = TestClient(mod.app, raise_server_exceptions=False)
    before = len(stub.received)
    for raw in ("ord_1%3Fadmin%3D1", "..%2F..%2Fapi%2Fadmin%2Freview",
                "%2e%2e%2Fapi%2Fadmin%2Freview", "ord%201"):
        resp = client.get(f"/api/orders/{raw}")
        assert resp.status_code in (400, 404), (raw, resp.status_code)
    assert len(stub.received) == before
    assert stub.admin_hits == []


@pytest.fixture(scope="module")
def ratelimit_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-ratelimit")
    mod = _load_app(tmp, "sl_app_ratelimit",
                    "hackproof_payments:\n  enabled: true\n"
                    "  upstream: \"http://127.0.0.1:9\"\n")
    stub = Stub()
    mod._get_payments_client = stub.client
    return mod


def test_proxy_posts_are_rate_limited(ratelimit_app):
    """BH2-8: repeated order creation is capped (429), not unbounded."""
    client = TestClient(ratelimit_app.app, raise_server_exceptions=False)
    codes = [client.post("/api/orders",
                         json={"email": "a@b.co"}).status_code
             for _ in range(11)]
    assert codes[:10] == [201] * 10
    assert codes[10] == 429


@pytest.fixture(scope="module")
def big_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-big")
    mod = _load_app(tmp, "sl_app_big",
                    "hackproof_payments:\n  enabled: true\n"
                    "  upstream: \"http://127.0.0.1:9\"\n")

    def big_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=b"x" * (mod.HP_PROXY_MAX_RESPONSE_BYTES + 1),
            headers={"Content-Type": "application/json"})

    mod._get_payments_client = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(big_handler))
    return mod


def test_oversized_upstream_response_is_clean_502(big_app):
    """BH2-11: an upstream reply past the size cap is a clean 502 in
    the app's error shape, not an unbounded buffer."""
    client = TestClient(big_app.app, raise_server_exceptions=False)
    resp = client.get("/api/orders/ord_1")
    assert resp.status_code == 502
    assert "detail" in resp.json()
    assert len(resp.content) < big_app.HP_PROXY_MAX_RESPONSE_BYTES


@pytest.fixture(scope="module")
def bad_upstream_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-badupstream")
    return _load_app(tmp, "sl_app_badupstream",
                     "hackproof_payments:\n  enabled: true\n"
                     "  upstream: \"http://127.0.0.1:8787@evil.example\"\n")


def test_non_loopback_upstream_falls_back_to_default(bad_upstream_app):
    """BH2-10: userinfo/remote upstreams are rejected at config load;
    only a bare loopback origin is honored."""
    assert bad_upstream_app.HP_PAYMENTS_UPSTREAM == "http://127.0.0.1:8787"


@pytest.fixture(scope="module")
def cors_star_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-corsstar")
    return _load_app(tmp, "sl_app_corsstar", 'cors_origins: "*"\n')


def test_cors_string_star_is_not_a_wildcard(cors_star_app):
    """BH2-12: `cors_origins: "*"` as a bare YAML string must NOT turn
    into ACAO:* (Starlette would treat the string as a wildcard)."""
    assert cors_star_app.config["cors_origins"] == []
    client = TestClient(cors_star_app.app, raise_server_exceptions=False)
    resp = client.get("/health", headers={"Origin": "https://evil.example"})
    # BH-2026-10-23 (H-1): /health is admin-gated in-app now, so the
    # response here is the 403 — what this test pins is unchanged: no
    # Access-Control-Allow-Origin is handed to an unlisted origin.
    assert resp.status_code == 403
    assert "access-control-allow-origin" not in resp.headers


@pytest.fixture(scope="module")
def tunnel_str_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-tunnelstr")
    return _load_app(tmp, "sl_app_tunnelstr", 'tunnel:\n  enabled: "false"\n')


def test_tunnel_enabled_string_false_is_not_tunnel_on(tunnel_str_app):
    """S3-1: `enabled: "false"` as a quoted YAML string is truthy in
    Python. It must NOT switch off the localhost admin bypass (the
    operator said the tunnel is OFF) nor turn on CF-Connecting-IP
    trust — only a literal bool is honored, else the default."""
    assert tunnel_str_app.config["tunnel"]["enabled"] is False
    client = TestClient(tunnel_str_app.app, raise_server_exceptions=False,
                        client=("127.0.0.1", 50000))
    assert client.get("/admin").status_code == 200


@pytest.fixture(scope="module")
def tunnel_on_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-tunnelon")
    return _load_app(tmp, "sl_app_tunnelon", "tunnel:\n  enabled: true\n")


def test_tunnel_enabled_literal_true_still_disables_bypass(tunnel_on_app):
    """S3-1 companion: a real bool true keeps the designed behavior —
    with the tunnel on, localhost no longer bypasses the admin key."""
    assert tunnel_on_app.config["tunnel"]["enabled"] is True
    client = TestClient(tunnel_on_app.app, raise_server_exceptions=False,
                        client=("127.0.0.1", 50000))
    assert client.get("/admin").status_code == 403


@pytest.fixture(scope="module")
def apikey_int_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-apikeyint")
    return _load_app(tmp, "sl_app_apikeyint", "flight_api:\n  api_key: 12345\n")


def test_non_string_flight_api_key_does_not_500_flights(apikey_int_app):
    """S3-2: a numeric api_key in a hand-edited config used to crash
    the public /flights page (.strip() on an int). It normalizes to
    the empty default, so the page renders its 'no key' state."""
    assert apikey_int_app.config["flight_api"]["api_key"] == ""
    client = TestClient(apikey_int_app.app, raise_server_exceptions=False)
    assert client.get("/flights", params={"q": "AA100"}).status_code == 200


@pytest.fixture(scope="module")
def forms_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-forms")
    return _load_app(tmp, "sl_app_forms", 'admin_key: "sekrit"\n')


def test_csv_export_neutralizes_leading_newline_formula(forms_app):
    """BH2-14 permanent pin: a stored cell starting with a newline
    then a formula char is quote-prefixed in the CSV export."""
    import csv as _csv
    client = TestClient(forms_app.app, raise_server_exceptions=False,
                        client=("127.0.0.1", 50000))
    with client:
        r = client.post("/api/contact", json={
            "name": "\n=2+5", "email": "a@b.co", "message": "hi"})
        assert r.status_code == 200
        r = client.get("/api/admin/export", params={"type": "contacts"})
    rows = list(_csv.reader(io.StringIO(r.content.decode("utf-8"))))
    flat = [c for row in rows for c in row]
    assert any(c.startswith("'") and "=2+5" in c for c in flat)


def test_admin_fail_table_prunes_stale_entries(forms_app):
    """BH2-15 permanent pin: the failed-admin-attempt table prunes
    expired entries instead of growing one row per IP forever."""
    import time as _time
    now = _time.time()
    for i in range(5000):
        forms_app._admin_fails[f"10.9.0.{i}"] = [now - 10000]
    client = TestClient(forms_app.app, raise_server_exceptions=False)
    r = client.get("/api/admin/submissions",
                   headers={"X-Admin-Key": "wrong"})
    assert r.status_code == 403
    assert len(forms_app._admin_fails) < 100


def test_newsletter_non_unique_integrity_error_surfaces(forms_app):
    """BH2-13 permanent pin: only the UNIQUE (duplicate) integrity
    error is swallowed as ok:true; any other integrity failure must
    surface instead of faking a successful signup."""
    import sqlite3 as _sqlite3
    client = TestClient(forms_app.app, raise_server_exceptions=False,
                        client=("127.0.0.1", 50000))
    with client:
        conn = _sqlite3.connect(forms_app.DB_PATH)
        conn.execute("CREATE TRIGGER s3boom BEFORE INSERT ON newsletter "
                     "BEGIN SELECT RAISE(ABORT,'custom integrity boom'); END")
        conn.commit(); conn.close()
        try:
            r = client.post("/api/newsletter", json={"email": "x@y.co"})
            assert r.status_code >= 500
        finally:
            conn = _sqlite3.connect(forms_app.DB_PATH)
            conn.execute("DROP TRIGGER s3boom"); conn.commit(); conn.close()
        r1 = client.post("/api/newsletter", json={"email": "dup@y.co"})
        r2 = client.post("/api/newsletter", json={"email": "dup@y.co"})
        assert r1.json()["ok"] is True and r2.json()["ok"] is True


@pytest.fixture(scope="module")
def cors_list_star_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-corsliststar")
    return _load_app(tmp, "sl_app_corsliststar",
                     'cors_origins: ["*", "https://ok.example"]\n')


def test_cors_list_star_entry_is_dropped(cors_list_star_app):
    """BH2-12: a "*" entry inside the list is dropped; explicit
    origins keep working."""
    assert cors_list_star_app.config["cors_origins"] == ["https://ok.example"]
    client = TestClient(cors_list_star_app.app, raise_server_exceptions=False)
    evil = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in evil.headers
    ok = client.get("/health", headers={"Origin": "https://ok.example"})
    assert ok.headers.get("access-control-allow-origin") == "https://ok.example"
