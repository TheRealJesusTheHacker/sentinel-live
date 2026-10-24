"""Fleet Sweep #5 fix pins (Sentinel Live, 2026-10-24).

Covers the verified defects fixed in the sweep:

  S5-1  PATCH /api/admin/tickets/{id} rewrote admin_notes from the
        body unconditionally (and required status): a status-only
        update silently erased stored notes, a notes-only update
        was a 400. PATCH is now partial — an omitted field keeps
        its stored value; providing neither is a 400.
  S5-2  Integer overflow on SQLite binding surfaced as a 500:
        GET /api/admin/submissions?offset= (past 2**63-1) and
        PATCH /api/admin/tickets/{id past 2**63-1}. Offset is now
        clamped into the bindable range (past-the-end still reads
        as an empty page); an out-of-range ticket id is a 404.
  S5-3  GET /api/admin/export silently served CSV for any format
        other than "json" — format=xml got CSV bytes with no
        signal. Undocumented formats are now a 400; csv/json are
        matched case-insensitively.
  S5-4  /internal/visitors validated days/limit as typed ints
        BEFORE the gate ran, so a malformed query answered 422
        while every gate failure answers the same plain 404 —
        an oracle against the endpoint's stealth design. The
        params are parsed after the gate: outsiders get 404 for
        every malformed request, gated callers get a 400.

Loads app.py from a scratch copy the same way the other suites do.
Hermetic: TestClient only.
"""
import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent
HUGE = "99999999999999999999"  # past SQLite INTEGER max (2**63-1)


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
def s5_app(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-sweep5")
    return _load_app(tmp, "sl_app_sweep5", 'admin_key: "sekrit"\n')


def _loop(s5_app):
    return TestClient(s5_app.app, raise_server_exceptions=False,
                      client=("127.0.0.1", 50000))


def _remote(s5_app):
    return TestClient(s5_app.app, raise_server_exceptions=False,
                      client=("203.0.113.5", 50000))


def _make_ticket(client) -> int:
    r = client.post("/api/ticket", json={
        "name": "Pat", "email": "pat@example.co",
        "subject": "help", "message": "it broke"})
    assert r.status_code == 200
    return r.json()["ticket_id"]


def _row(client, tid):
    rows = client.get(
        "/api/admin/submissions", params={"type": "tickets"}).json()["rows"]
    return next(r for r in rows if r["id"] == tid)


# --------------------------------------------------------------- S5-1
def test_status_only_patch_preserves_notes(s5_app):
    with _loop(s5_app) as client:
        tid = _make_ticket(client)
        r = client.patch(f"/api/admin/tickets/{tid}", json={
            "status": "open", "admin_notes": "KEEP-ME"})
        assert r.status_code == 200
        r = client.patch(f"/api/admin/tickets/{tid}",
                         json={"status": "resolved"})
        assert r.status_code == 200 and r.json()["status"] == "resolved"
        row = _row(client, tid)
        assert row["status"] == "resolved"
        assert row["admin_notes"] == "KEEP-ME"  # not erased


def test_notes_only_patch_preserves_status(s5_app):
    with _loop(s5_app) as client:
        tid = _make_ticket(client)
        client.patch(f"/api/admin/tickets/{tid}", json={"status": "open"})
        r = client.patch(f"/api/admin/tickets/{tid}",
                         json={"admin_notes": "called the client"})
        assert r.status_code == 200 and r.json()["status"] == "open"
        row = _row(client, tid)
        assert row["status"] == "open"
        assert row["admin_notes"] == "called the client"


def test_patch_requires_a_field_and_valid_values(s5_app):
    with _loop(s5_app) as client:
        tid = _make_ticket(client)
        assert client.patch(f"/api/admin/tickets/{tid}",
                            json={}).status_code == 400
        assert client.patch(f"/api/admin/tickets/{tid}", json={
            "status": "bogus"}).status_code == 400
        assert client.patch(f"/api/admin/tickets/{tid}", json={
            "admin_notes": 42}).status_code == 400
        assert client.patch("/api/admin/tickets/424242", json={
            "status": "open"}).status_code == 404


# --------------------------------------------------------------- S5-2
def test_submissions_huge_offset_is_empty_page_not_500(s5_app):
    with _loop(s5_app) as client:
        r = client.get("/api/admin/submissions",
                       params={"offset": HUGE})
        assert r.status_code == 200
        assert r.json()["rows"] == []
        r = client.get("/api/admin/submissions", params={"offset": -5})
        assert r.status_code == 200


def test_patch_huge_ticket_id_is_404_not_500(s5_app):
    with _loop(s5_app) as client:
        r = client.patch(f"/api/admin/tickets/{HUGE}",
                         json={"status": "open"})
        assert r.status_code == 404


# --------------------------------------------------------------- S5-3
def test_export_format_validation(s5_app):
    with _loop(s5_app) as client:
        assert client.get("/api/admin/export", params={
            "type": "tickets", "format": "xml"}).status_code == 400
        assert client.get("/api/admin/export", params={
            "type": "tickets", "format": "JSON"}).status_code == 200
        r = client.get("/api/admin/export", params={
            "type": "tickets", "format": "CSV"})
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]


# --------------------------------------------------------------- S5-4
@pytest.fixture()
def token_env(s5_app, tmp_path, monkeypatch):
    tok = tmp_path / "internal_token.txt"
    tok.write_text("test-internal-token\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_LIVE_INTERNAL_TOKEN_PATH", str(tok))
    return "test-internal-token"


def test_internal_malformed_query_is_404_for_outsiders(s5_app, token_env):
    with _remote(s5_app) as client:
        assert client.get(
            "/internal/visitors?days=abc").status_code == 404
        # Even a loopback peer without the token gets the plain 404,
        # never the 422 that would confirm the endpoint exists.
    with _loop(s5_app) as client:
        assert client.get(
            "/internal/visitors?days=abc").status_code == 404
        assert client.get("/internal/visitors?limit=1.5").status_code == 404


def test_internal_malformed_query_is_400_after_gate(s5_app, token_env):
    with _loop(s5_app) as client:
        r = client.get("/internal/visitors?days=abc",
                       headers={"X-Internal-Token": token_env})
        assert r.status_code == 400
        ok = client.get("/internal/visitors?days=2&limit=200",
                        headers={"X-Internal-Token": token_env})
        assert ok.status_code == 200
