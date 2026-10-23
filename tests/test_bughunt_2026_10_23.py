"""Bug-hunt 2026-10-23 fix pins (Sentinel Live).

Covers the verified defects fixed in the 2026-10-23 full-site bug
hunt + security audit:

  H-1  /news, /status, /health, /api/news-data had NO in-app gate
       (edge-only). They now require the admin rule in-app, while the
       genuinely public surfaces stay public.
  H-2  require_admin's localhost bypass trusted the tunnel.enabled
       config bool alone. A request carrying Cloudflare's
       CF-Connecting-IP header is proxied by definition — the bypass
       must not apply even if the bool is stale.
  M-3  Baseline security headers on every response (frame denial,
       referrer policy, HSTS, permissions policy, nosniff).
  M-4  The refresh loop stored exception DETAIL in the store dict the
       public data APIs serve verbatim. Class name only now.
  M-1  Flight lookups validate the designator shape BEFORE any
       provider call and cache results (incl. failures) briefly —
       junk queries used to burn the 100 req/mo free quota.
  L-1  Turnstile: a token solved on a DIFFERENT site's widget
       (hostname mismatch in the siteverify result) is rejected.

Loads app.py from a scratch copy the same way the other suites do.
Hermetic: no network — the provider seam and siteverify seam are
stubbed.
"""
import asyncio
import importlib.util
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent

CONTACT = {"name": "Pat", "email": "pat@example.co", "message": "hello",
           "cf-turnstile-response": "tok"}


def _load_app(tmp: Path, name: str, config_text: str):
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


@pytest.fixture(scope="module")
def gate_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-bughunt-gate")
    return _load_app(tmp, "sl_app_bughunt_gate", 'admin_key: "sekrit"\n')


@pytest.fixture(scope="module")
def ts_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-bughunt-ts")
    return _load_app(tmp, "sl_app_bughunt_ts",
                     'admin_key: "sekrit"\n'
                     "turnstile:\n"
                     "  enabled: true\n"
                     '  secret_key: "test-secret"\n')


# --------------------------------------------------------------- H-1
@pytest.mark.parametrize("path", ["/news", "/status", "/health",
                                  "/api/news-data"])
def test_gated_surfaces_require_admin_key(gate_app, path):
    client = TestClient(gate_app.app, raise_server_exceptions=False)
    assert client.get(path).status_code == 403
    ok = client.get(path, headers={"X-Admin-Key": "sekrit"})
    assert ok.status_code == 200


@pytest.mark.parametrize("path", ["/threat-map", "/geopolitical",
                                  "/flights", "/operations",
                                  "/api/threat-data", "/api/geo-data"])
def test_public_surfaces_stay_public(gate_app, path):
    client = TestClient(gate_app.app, raise_server_exceptions=False)
    assert client.get(path).status_code == 200


# --------------------------------------------------------------- M-3
def test_security_headers_on_pages_and_apis(gate_app):
    client = TestClient(gate_app.app, raise_server_exceptions=False)
    for path in ("/threat-map", "/api/threat-data"):
        h = client.get(path).headers
        assert h["x-frame-options"] == "DENY"
        assert h["content-security-policy"] == "frame-ancestors 'none'"
        assert h["referrer-policy"] == "same-origin"
        assert "max-age=31536000" in h["strict-transport-security"]
        assert "camera=()" in h["permissions-policy"]
        assert h["x-content-type-options"] == "nosniff"


# --------------------------------------------------------------- H-2
def _fake_request(headers, host="127.0.0.1"):
    return SimpleNamespace(
        headers=headers,
        client=SimpleNamespace(host=host),
        url=SimpleNamespace(path="/admin"))


def test_localhost_bypass_ok_for_genuine_loopback(gate_app):
    # Tunnel disabled in this fixture's config; a bare loopback
    # request (no proxy headers) keeps the local-use bypass.
    assert gate_app.require_admin(_fake_request({})) is True


def test_cf_connecting_ip_defeats_localhost_bypass(gate_app):
    # Same loopback peer, but the request ARRIVED via Cloudflare —
    # the bypass must fail closed and demand the key.
    req = _fake_request({"CF-Connecting-IP": "203.0.113.9"})
    with pytest.raises(HTTPException) as exc:
        gate_app.require_admin(req)
    assert exc.value.status_code == 403
    req_ok = _fake_request({"CF-Connecting-IP": "203.0.113.9",
                            "X-Admin-Key": "sekrit"})
    # header lookup in the fake is case-sensitive dict access; the app
    # reads via Starlette's case-insensitive Headers in production.
    # The dict stands in for it here with exact case.
    assert gate_app.require_admin(req_ok) is True


# --------------------------------------------------------------- M-4
def test_refresh_loop_error_is_class_name_only(gate_app, monkeypatch):
    class Boom(Exception):
        pass

    async def bad_coro(*a):
        raise ValueError("upstream said SECRET-DETAIL-123")

    calls = {"n": 0}

    async def fake_sleep(seconds):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise Boom()

    monkeypatch.setattr(gate_app.asyncio, "sleep", fake_sleep)
    with pytest.raises(Boom):
        asyncio.run(gate_app._refresh_loop("threat", 5, bad_coro))
    err = gate_app.store["threat"].get("error")
    assert err == "ValueError"
    assert "SECRET-DETAIL" not in str(gate_app.store["threat"])


# --------------------------------------------------------------- M-1
def test_flight_validation_and_cache(gate_app, monkeypatch):
    feeds = sys.modules["feeds"]
    calls = {"n": 0}

    async def fake_provider(num, api_key, timeout=20):
        calls["n"] += 1
        return {"number": num}, None

    monkeypatch.setattr(feeds, "_lookup_flight_provider", fake_provider)
    for junk in ("", "!!!", "12345", "A1", "TOOLONG12345", "AA100000"):
        result, error = asyncio.run(feeds.lookup_flight(junk, "key"))
        assert result is None
        assert error.startswith("Enter a flight number")
    assert calls["n"] == 0  # nothing reached the provider

    r1, e1 = asyncio.run(feeds.lookup_flight("ZZ999", "key"))
    r2, e2 = asyncio.run(feeds.lookup_flight("ZZ999", "key"))
    assert r1 == r2 == {"number": "ZZ999"} and e1 is e2 is None
    assert calls["n"] == 1  # second call served from the cache


# --------------------------------------------------------------- L-1
def test_turnstile_hostname_mismatch_rejected(ts_app, monkeypatch):
    async def fake_verify(secret, token, remoteip):
        return {"success": True, "hostname": "evil.example"}

    monkeypatch.setattr(ts_app, "_turnstile_siteverify", fake_verify)
    client = TestClient(ts_app.app, raise_server_exceptions=False)
    resp = client.post("/api/contact", json=CONTACT)
    assert resp.status_code == 400
    assert "Bot check failed" in resp.json()["detail"]


def test_turnstile_hostname_match_accepted(ts_app, monkeypatch):
    async def fake_verify(secret, token, remoteip):
        return {"success": True, "hostname": "sentinelsafeguard.net"}

    monkeypatch.setattr(ts_app, "_turnstile_siteverify", fake_verify)
    # Context manager so the startup event runs (DB schema init).
    with TestClient(ts_app.app, raise_server_exceptions=False) as client:
        resp = client.post("/api/contact", json=CONTACT)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
