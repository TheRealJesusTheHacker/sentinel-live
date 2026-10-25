"""Public-ticket bridge pins (Sentinel Live, ITEM6-2026-10-25).

Covers GET /internal/tickets, the feed Sentinel Command polls to
mirror website tickets into its own queue:

  * the same three gates as /internal/visitors — loopback peer, no
    CF-Connecting-IP, box token file — and EVERY failure is the
    same plain 404, including malformed after/limit values (they
    are parsed only after the gate, so they cannot oracle the
    endpoint apart from a nonexistent path);
  * the endpoint is OFF (404 to everything) when the token file
    is missing;
  * the payload contract: rows carry exactly the fields Command
    imports (no reporter ip, no admin_notes), createdAt is the
    stored timestamp verbatim;
  * cursor semantics: after=<id> returns only newer tickets,
    oldest first; limit clamps; maxId reports the table's highest
    id (0 when empty) even when the page itself is empty;
  * a ticket filed through the public POST /api/ticket appears in
    the feed with the public priority cap intact (Critical can
    never arrive from the form).

Loads app.py from a scratch copy the same way the other suites do.
Hermetic: no network (TestClient only, feed loops never fire).
"""
import importlib.util
import os
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent


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
def bapp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-ticket-bridge")
    return _load_app(tmp, "sl_app_ticket_bridge",
                     'admin_key: "sekrit"\n'
                     "tunnel:\n"
                     "  enabled: true\n")


@pytest.fixture()
def token_env(bapp, tmp_path, monkeypatch):
    tok = tmp_path / "internal_token.txt"
    tok.write_text("test-internal-token\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_LIVE_INTERNAL_TOKEN_PATH", str(tok))
    return "test-internal-token"


def _client(mod):
    """TestClient presenting a loopback peer, like uvicorn on the
    box — the default TestClient peer host is the literal string
    'testclient', which the internal-endpoint gate rightly refuses."""
    return TestClient(mod.app, raise_server_exceptions=False,
                      client=("127.0.0.1", 50000))


def _seed_ticket(mod, **kw):
    row = {"created_at": "2026-10-25T17:00:00+00:00", "name": "Rae Porter",
           "email": "rae@example.invalid", "phone": "555-0100",
           "category": "Support", "priority": "Normal",
           "subject": "Seeded subject", "message": "Seeded message.",
           "status": "new", "admin_notes": "internal only",
           "ip": "203.0.113.7"}
    row.update(kw)
    conn = sqlite3.connect(mod.DB_PATH, timeout=5)
    try:
        cur = conn.execute(
            "INSERT INTO tickets(created_at,name,email,phone,category,"
            "priority,subject,message,status,admin_notes,ip)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (row["created_at"], row["name"], row["email"], row["phone"],
             row["category"], row["priority"], row["subject"],
             row["message"], row["status"], row["admin_notes"], row["ip"]))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def _get(mod, token, qs=""):
    with _client(mod) as client:
        return client.get("/internal/tickets" + qs,
                          headers={"X-Internal-Token": token})


# --------------------------------------------------------------- gates
def test_tickets_gate_matrix(bapp, token_env):
    with _client(bapp) as client:
        assert client.get("/internal/tickets").status_code == 404
        assert client.get("/internal/tickets", headers={
            "X-Internal-Token": "wrong"}).status_code == 404
        # Tunnel evidence refuses even with the right token.
        assert client.get("/internal/tickets", headers={
            "X-Internal-Token": token_env,
            "CF-Connecting-IP": "203.0.113.9"}).status_code == 404
        # Malformed params from an outsider: still the same 404,
        # never a 422/400 oracle.
        assert client.get("/internal/tickets?after=abc").status_code == 404
        ok = client.get("/internal/tickets", headers={
            "X-Internal-Token": token_env})
    assert ok.status_code == 200


def test_tickets_off_without_token_file(bapp, tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_LIVE_INTERNAL_TOKEN_PATH",
                       str(tmp_path / "absent.txt"))
    with _client(bapp) as client:
        assert client.get("/internal/tickets", headers={
            "X-Internal-Token": "anything"}).status_code == 404


def test_tickets_bad_params_after_gate(bapp, token_env):
    r = _get(bapp, token_env, "?after=abc")
    assert r.status_code == 400
    r = _get(bapp, token_env, "?limit=xyz")
    assert r.status_code == 400


# --------------------------------------------------------------- contract
def test_tickets_empty_feed_shape(bapp, token_env):
    conn = sqlite3.connect(bapp.DB_PATH, timeout=5)
    try:
        n = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
    finally:
        conn.close()
    if n == 0:
        body = _get(bapp, token_env).json()
        assert body == {"tickets": [], "maxId": 0}


def test_tickets_payload_contract_and_cursor(bapp, token_env):
    first = _seed_ticket(bapp, subject="First seeded",
                         priority="Low")
    second = _seed_ticket(bapp, subject="Second seeded",
                          priority="High", name="Jo Second",
                          email="jo@example.invalid", phone="",
                          category="", message="Second message.")
    body = _get(bapp, token_env, f"?after={first - 1}").json()
    rows = [r for r in body["tickets"] if r["id"] in (first, second)]
    assert [r["id"] for r in rows] == [first, second]  # oldest first
    assert body["maxId"] >= second
    r0 = rows[0]
    assert set(r0) == {"id", "createdAt", "name", "email", "phone",
                       "category", "priority", "subject", "message",
                       "status"}
    assert r0["createdAt"] == "2026-10-25T17:00:00+00:00"
    assert r0["priority"] == "Low" and r0["status"] == "new"
    assert "ip" not in r0 and "admin_notes" not in r0
    # Cursor: only strictly newer rows come back.
    body2 = _get(bapp, token_env, f"?after={first}").json()
    ids2 = [r["id"] for r in body2["tickets"]]
    assert first not in ids2 and second in ids2
    # Caught up: empty page, maxId still reports the table high mark.
    body3 = _get(bapp, token_env, f"?after={body['maxId']}").json()
    assert body3["tickets"] == [] and body3["maxId"] == body["maxId"]
    # Limit clamps the page size.
    body4 = _get(bapp, token_env, f"?after={first - 1}&limit=1").json()
    assert len(body4["tickets"]) == 1
    assert body4["tickets"][0]["id"] == first


def test_public_ticket_lands_in_bridge_feed(bapp, token_env):
    with _client(bapp) as client:
        r = client.post("/api/ticket", json={
            "name": "Pat Public", "email": "pat@example.invalid",
            "phone": "", "category": "Question", "priority": "Critical",
            "subject": "Filed from the form",
            "message": "Hello from the public form."})
    assert r.status_code == 200
    tid = r.json()["ticket_id"]
    body = _get(bapp, token_env, f"?after={tid - 1}").json()
    rows = [x for x in body["tickets"] if x["id"] == tid]
    assert len(rows) == 1
    # The public form can never file Critical — the cap holds and
    # the bridge therefore never receives one from the form.
    assert rows[0]["priority"] == "Normal"
    assert rows[0]["subject"] == "Filed from the form"
    assert rows[0]["name"] == "Pat Public"
