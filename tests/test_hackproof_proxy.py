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

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/api/admin/"):
            self.admin_hits.append(path)
            return httpx.Response(200, content=ADMIN_BODY,
                                  headers={"Content-Type": "application/json"})
        self.received.append((request.method, path, request.content))
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
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
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
