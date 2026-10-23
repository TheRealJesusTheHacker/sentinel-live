"""Cloudflare Turnstile bot-check tests for the public form handlers.

Loads app.py from a scratch copy (its own config.yaml, data/ and
logs/) the same way test_hackproof_proxy.py does, and stubs the one
network seam — app._turnstile_siteverify — so the suite stays
hermetic: no test here talks to Cloudflare. (The live pairing of the
real endpoint with Cloudflare's published always-pass / always-fail
test secret keys is exercised separately at change time, not in CI.)

Proves:
  (a) disabled (the default) -> all three forms behave exactly as
      before: submissions succeed with no token, and siteverify is
      never called;
  (b) enabled but no secret configured -> same as disabled (the
      documented "off until keys are in place" state);
  (c) enabled -> a missing token is a 400 and nothing is stored;
  (d) enabled -> a token Cloudflare rejects is a 400 and nothing is
      stored, on all three endpoints;
  (e) enabled -> a token Cloudflare accepts succeeds on all three
      endpoints (ticket returns its ticket_id), and the token the
      handler passes on is the payload's cf-turnstile-response value;
  (f) enabled -> a siteverify outage fails CLOSED: 503 pointing at
      the email/phone fallback, nothing stored — never a silent pass;
  (g) config type confusion (enabled: "false" as a string, a numeric
      secret) normalizes to the defaults — the check stays OFF.
"""
import importlib.util
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent

CONTACT = {"name": "Pat", "email": "pat@example.co", "message": "hello"}
TICKET = {"name": "Pat", "email": "pat@example.co", "subject": "help",
          "message": "it broke"}
NEWSLETTER = {"email": "pat@example.co"}


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


def _count(mod, table: str) -> int:
    conn = sqlite3.connect(mod.DB_PATH)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def _post_all(client, token_marker, suffix):
    """POST all three forms; token_marker=None omits the field."""
    out = {}
    for path, payload in (("/api/contact", CONTACT),
                          ("/api/ticket", TICKET),
                          ("/api/newsletter", NEWSLETTER)):
        body = dict(payload)
        body["email"] = f"{suffix}{payload['email']}"
        if token_marker is not None:
            body["cf-turnstile-response"] = token_marker
        out[path] = client.post(path, json=body)
    return out


@pytest.fixture(scope="module")
def ts_off_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-ts-off")
    mod = _load_app(tmp, "sl_app_ts_off", 'admin_key: "sekrit"\n')
    calls = []

    async def recorder(secret, token, remoteip):
        calls.append((secret, token, remoteip))
        return {"success": True}

    mod._turnstile_siteverify = recorder
    mod._ts_calls = calls
    return mod


def test_disabled_is_todays_behavior(ts_off_app):
    """(a) Default config: no token needed, siteverify never called."""
    client = TestClient(ts_off_app.app, raise_server_exceptions=False)
    with client:
        res = _post_all(client, None, "off")
        assert res["/api/contact"].status_code == 200
        assert res["/api/ticket"].status_code == 200
        assert res["/api/ticket"].json()["ticket_id"] >= 1
        assert res["/api/newsletter"].status_code == 200
        assert _count(ts_off_app, "contacts") == 1
        assert _count(ts_off_app, "tickets") == 1
        assert _count(ts_off_app, "newsletter") == 1
    assert ts_off_app._ts_calls == []


@pytest.fixture(scope="module")
def ts_nosecret_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-ts-nosecret")
    return _load_app(tmp, "sl_app_ts_nosecret",
                     "turnstile:\n  enabled: true\n  secret_key: \"\"\n")


def test_enabled_without_secret_is_off(ts_nosecret_app):
    """(b) enabled: true with an empty secret must not reject anyone —
    that is the pre-launch state while keys are still being created."""
    client = TestClient(ts_nosecret_app.app, raise_server_exceptions=False)
    with client:
        r = client.post("/api/contact", json=CONTACT)
        assert r.status_code == 200 and r.json()["ok"] is True


# NOTE on the distinct client= IPs in the ts_on tests below: the
# app's form rate limiter is ONE shared per-IP bucket across all
# three endpoints (ticket's cap is 10 hits), so tests sharing a
# module instance must not share a source IP or they 429 each other.


@pytest.fixture(scope="module")
def ts_on_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-ts-on")
    return _load_app(tmp, "sl_app_ts_on",
                     "turnstile:\n  enabled: true\n"
                     "  secret_key: \"test-secret-not-real\"\n")


def test_enabled_missing_token_rejected(ts_on_app):
    """(c) No cf-turnstile-response in the payload -> 400, no rows."""
    client = TestClient(ts_on_app.app, raise_server_exceptions=False,
                        client=("10.0.1.1", 50000))
    with client:
        before = (_count(ts_on_app, "contacts"), _count(ts_on_app, "tickets"),
                  _count(ts_on_app, "newsletter"))
        res = _post_all(client, None, "missing")
        for r in res.values():
            assert r.status_code == 400
            assert "bot check" in r.json()["detail"].lower()
        after = (_count(ts_on_app, "contacts"), _count(ts_on_app, "tickets"),
                 _count(ts_on_app, "newsletter"))
        assert before == after


def test_enabled_invalid_token_rejected(ts_on_app, monkeypatch):
    """(d) siteverify says no -> 400 on all three, nothing stored."""
    async def reject(secret, token, remoteip):
        assert secret == "test-secret-not-real"
        return {"success": False, "error-codes": ["invalid-input-response"]}

    monkeypatch.setattr(ts_on_app, "_turnstile_siteverify", reject)
    client = TestClient(ts_on_app.app, raise_server_exceptions=False,
                        client=("10.0.1.2", 50000))
    with client:
        before = (_count(ts_on_app, "contacts"), _count(ts_on_app, "tickets"),
                  _count(ts_on_app, "newsletter"))
        res = _post_all(client, "forged-token", "invalid")
        for r in res.values():
            assert r.status_code == 400
            assert "bot check failed" in r.json()["detail"].lower()
        after = (_count(ts_on_app, "contacts"), _count(ts_on_app, "tickets"),
                 _count(ts_on_app, "newsletter"))
        assert before == after


def test_enabled_valid_token_accepted(ts_on_app, monkeypatch):
    """(e) siteverify says yes -> all three succeed; the handler
    forwards the payload's cf-turnstile-response value verbatim."""
    seen = []

    async def accept(secret, token, remoteip):
        seen.append(token)
        return {"success": True, "hostname": "sentinelsafeguard.net"}

    monkeypatch.setattr(ts_on_app, "_turnstile_siteverify", accept)
    client = TestClient(ts_on_app.app, raise_server_exceptions=False,
                        client=("10.0.1.3", 50000))
    with client:
        res = _post_all(client, "real-token-abc", "valid")
        assert res["/api/contact"].status_code == 200
        assert res["/api/ticket"].status_code == 200
        assert res["/api/ticket"].json()["ticket_id"] >= 1
        assert res["/api/newsletter"].status_code == 200
    assert seen == ["real-token-abc"] * 3


def test_enabled_siteverify_outage_fails_closed(ts_on_app, monkeypatch):
    """(f) siteverify unreachable -> 503 with the email/phone
    fallback in the message, and nothing is stored. Fail closed."""
    async def boom(secret, token, remoteip):
        raise RuntimeError("simulated siteverify outage")

    monkeypatch.setattr(ts_on_app, "_turnstile_siteverify", boom)
    client = TestClient(ts_on_app.app, raise_server_exceptions=False,
                        client=("10.0.1.4", 50000))
    with client:
        before = (_count(ts_on_app, "contacts"), _count(ts_on_app, "tickets"),
                  _count(ts_on_app, "newsletter"))
        res = _post_all(client, "some-token", "outage")
        for r in res.values():
            assert r.status_code == 503
            assert "email or phone" in r.json()["detail"]
        after = (_count(ts_on_app, "contacts"), _count(ts_on_app, "tickets"),
                 _count(ts_on_app, "newsletter"))
        assert before == after


@pytest.fixture(scope="module")
def ts_confused_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-ts-confused")
    return _load_app(tmp, "sl_app_ts_confused",
                     "turnstile:\n  enabled: \"false\"\n  secret_key: 12345\n")


def test_config_type_confusion_normalized(ts_confused_app):
    """(g) A quoted "false" is truthy in YAML-land only if the code
    lets it be — the schema validation must restore the defaults, so
    the check stays off and a numeric secret becomes ""."""
    assert ts_confused_app.config["turnstile"]["enabled"] is False
    assert ts_confused_app.config["turnstile"]["secret_key"] == ""
    client = TestClient(ts_confused_app.app, raise_server_exceptions=False)
    with client:
        r = client.post("/api/contact", json=CONTACT)
        assert r.status_code == 200 and r.json()["ok"] is True
