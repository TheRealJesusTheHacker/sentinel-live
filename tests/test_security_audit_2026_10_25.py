"""Government-standard security audit pins (SECAUDIT-2026-10-25, Lane 2).

Three in-run fixes, each proven here against a scratch copy of the
app (the suite's usual harness — no production data, no network):

  1. The /internal/* gate's 404 now byte-matches the framework's
     unmatched-path 404 ({"detail": "Not Found"}). Before, a gated
     failure answered "Not found." while a nonexistent path answered
     "Not Found" — an unauthenticated prober could tell real-but-
     gated internal paths from nonexistent ones, against the
     stealth contract the gate's own comments state.
  2. _json_body requires Content-Type: application/json (415
     otherwise). The handlers parse the body regardless of media
     type, so a cross-site page could store submissions with a
     CORS-safelisted text/plain POST — no preflight, and no
     Turnstile token solved on that origin. Every real caller
     already sends application/json.
  3. /availability caches its summary on the monitor log's
     (path, mtime, size) + a one-minute bucket, so the public page
     no longer re-reads and re-parses the whole 35-day log per hit,
     while a fresh append still shows immediately and the stale
     flag is recomputed at least once a minute.
"""
import importlib.util
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent

ADMIN = {"X-Admin-Key": "sekrit"}
TOKEN = "test-internal-token"


def _load_app(tmp: Path, name: str, config_text: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
    site = tmp / "site"
    (site / "report-issue").mkdir(parents=True)
    (site / "ticket").mkdir(parents=True)
    (site / "index.html").write_text("<html>home</html>", encoding="utf-8")
    (site / "report-issue" / "index.html").write_text(
        "<html>report</html>", encoding="utf-8")
    (site / "ticket" / "index.html").write_text(
        "<html>ticket</html>", encoding="utf-8")
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
def sapp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-secaudit")
    return _load_app(tmp, "sl_app_secaudit",
                     'admin_key: "sekrit"\n'
                     "tunnel:\n"
                     "  enabled: true\n")


@pytest.fixture()
def token_env(sapp, tmp_path, monkeypatch):
    tok = tmp_path / "internal_token.txt"
    tok.write_text(TOKEN + "\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_LIVE_INTERNAL_TOKEN_PATH", str(tok))
    return TOKEN


def _client(mod):
    return TestClient(mod.app, raise_server_exceptions=False,
                      client=("127.0.0.1", 50000))


# ------------------------------------------------------------ fix 1
def test_internal_gate_404_matches_unmatched_path(sapp, token_env):
    with _client(sapp) as client:
        ghost = client.get("/definitely-not-a-real-path")
        assert ghost.status_code == 404
        assert ghost.content  # the yardstick every gate failure must match
        for url in ("/internal/tickets", "/internal/visitors"):
            for headers in ({}, {"X-Internal-Token": "wrong"},
                            {"X-Internal-Token": TOKEN,
                             "CF-Connecting-IP": "203.0.113.9"}):
                resp = client.get(url, headers=headers)
                assert resp.status_code == 404, (url, headers)
                assert resp.content == ghost.content, (url, headers)
            # X-Forwarded-For is never a gate input: the gate reads
            # the transport peer. (Under the deployed uvicorn, its
            # proxy-header handling rewrites that peer from XFF for
            # loopback callers — fail-closed there, proven against a
            # live local instance in the audit record; TestClient has
            # no such layer, so a valid token + XFF passes here and
            # the header alone changes nothing.)
        # and the gate still OPENS for the real caller shape
        ok = client.get("/internal/tickets",
                        headers={"X-Internal-Token": TOKEN})
        assert ok.status_code == 200


# ------------------------------------------------------------ fix 2
def _contact_rows(mod):
    conn = sqlite3.connect(mod.DB_PATH, timeout=5)
    try:
        return conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
    finally:
        conn.close()


def test_json_endpoints_require_json_content_type(sapp):
    payload = {"name": "Pat", "email": "pat@example.invalid",
               "message": "hello"}
    raw = json.dumps(payload)
    with _client(sapp) as client:
        before = _contact_rows(sapp)
        for ctype in ("text/plain", "application/x-www-form-urlencoded"):
            resp = client.post("/api/contact", content=raw,
                               headers={"Content-Type": ctype})
            assert resp.status_code == 415, ctype
        assert _contact_rows(sapp) == before  # nothing stored
        # the documented media type, bare and with parameters, works
        resp = client.post("/api/contact", content=raw, headers={
            "Content-Type": "application/json; charset=utf-8"})
        assert resp.status_code == 200
        assert _contact_rows(sapp) == before + 1
        # the ticket endpoint shares the same helper and the same pin
        resp = client.post("/api/ticket", content=raw,
                           headers={"Content-Type": "text/plain"})
        assert resp.status_code == 415
        # admin PATCH too — wrong media type never reaches the body
        resp = client.patch("/api/admin/tickets/1", content="{}",
                            headers={**ADMIN,
                                     "Content-Type": "text/plain"})
        assert resp.status_code == 415
        # plain bad JSON under the right media type is still the old 400
        resp = client.post("/api/contact", content="{oops", headers={
            "Content-Type": "application/json"})
        assert resp.status_code == 400


# ------------------------------------------------------------ fix 3
def test_availability_summary_is_cached_on_log_fingerprint(
        sapp, tmp_path, monkeypatch):
    log_path = tmp_path / "availability.jsonl"
    now_ms = int(time.time() * 1000)
    log_path.write_text(
        json.dumps({"ts": now_ms - 1000, "target": "public_site",
                    "ok": True, "ms": 42}) + "\n", encoding="utf-8")
    monkeypatch.setattr(sapp, "AVAILABILITY_LOG_PATH", log_path)
    sapp._availability_cache["key"] = None
    sapp._availability_cache["summary"] = None

    calls = {"n": 0}
    real_compute = sapp._availability_summary_compute

    def counting_compute():
        calls["n"] += 1
        return real_compute()

    monkeypatch.setattr(sapp, "_availability_summary_compute",
                        counting_compute)
    first = sapp._availability_summary()
    assert first["available"] is True and calls["n"] == 1
    # unchanged log + same minute: served from cache, no re-parse
    again = sapp._availability_summary()
    assert again is first and calls["n"] == 1
    # a fresh monitor append (mtime/size change) invalidates at once
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": now_ms, "target": "public_site",
                             "ok": False, "ms": 7}) + "\n")
    updated = sapp._availability_summary()
    assert calls["n"] == 2
    assert updated["rows"][0]["ok"] is False
