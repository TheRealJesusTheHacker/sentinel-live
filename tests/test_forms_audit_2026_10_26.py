"""Forms audit 2026-10-26 (Phase 2) — every public form and
form-like control, pinned to its real routing.

Findings pinned here:
  * The homepage contact form carried NO booking fields while the
    /contact form carried all three — and the /contact page copy
    calls its form "the same one the homepage carries". Fixed in
    this run: the homepage form now carries service / pref_date /
    pref_window with the same options, and its payload sends them.
  * /assessment, /tools and /training/phishing are local-only by
    design: no network call exists in their code at all.
  * The ticket funnels (/report-issue/ and /ticket/) are one form
    in two byte-identical pages; every field reaches /api/ticket
    and the stored row, and the /internal/tickets bridge feed
    carries all of it to Sentinel Command (source='Website').
  * Local-only and data-page controls drive their own page only.
"""
import importlib.util
import re
import shutil
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent


def _load_app(tmp: Path, name: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    for item in ("templates", "static", "insights", "site"):
        if (SRC / item).is_dir():
            shutil.copytree(SRC / item, tmp / item)
    (tmp / "config.yaml").write_text("server:\n  port: 8443\n",
                                     encoding="utf-8")
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
def app_mod(tmp_path_factory):
    import asyncio
    tmp = tmp_path_factory.mktemp("sl-forms-audit")
    mod = _load_app(tmp, "sl_app_forms_audit")
    asyncio.run(mod.init_db())
    return mod


def _client(app_mod):
    return TestClient(app_mod.app, raise_server_exceptions=False)


def _rows(app_mod, table):
    conn = sqlite3.connect(app_mod.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(
            f"SELECT * FROM {table}").fetchall()]
    finally:
        conn.close()


def _field_ids(html, form_id):
    m = re.search(rf'<form[^>]*id="{form_id}"[^>]*>(.*?)</form>',
                  html, re.S)
    assert m, form_id
    return set(re.findall(r'id="([a-z-]+)"', m.group(1)))


# ------------------------------------------------------------- parity fix
def test_homepage_contact_form_matches_contact_page_form(app_mod):
    home = (SRC / "site" / "index.html").read_text(encoding="utf-8")
    contact = _client(app_mod).get("/contact").text
    home_fields = _field_ids(home, "contact-form")
    contact_fields = _field_ids(contact, "contact-form")
    assert home_fields == contact_fields, (
        home_fields ^ contact_fields)
    for opt in ("Penetration testing", "Security installs",
                "Incident response", "Not sure yet"):
        assert f"<option>{opt}</option>" in home, opt
    for opt in ("Morning", "Afternoon", "Evening"):
        assert f"<option>{opt}</option>" in home, opt


def test_homepage_contact_payload_sends_booking_fields():
    home = (SRC / "site" / "index.html").read_text(encoding="utf-8")
    for token in ("service:document.getElementById('cf-service').value",
                  "pref_date:document.getElementById('cf-pref-date').value",
                  "pref_window:document.getElementById('cf-pref-window').value",
                  "fetch('/api/contact'"):
        assert token in home, token
    assert ".contact-form select" in home  # selects are styled, not bare


# ------------------------------------------------------------- ticket funnel
def test_ticket_funnels_are_one_form_with_every_field():
    a = (SRC / "site" / "report-issue" / "index.html").read_text(
        encoding="utf-8")
    b = (SRC / "site" / "ticket" / "index.html").read_text(encoding="utf-8")
    assert a == b
    fields = _field_ids(a, "ticket-form")
    assert {"tf-name", "tf-email", "tf-phone", "tf-category",
            "tf-priority", "tf-subject", "tf-message"} <= fields
    for token in ("phone:document.getElementById('tf-phone').value",
                  "category:document.getElementById('tf-category').value",
                  "priority:document.getElementById('tf-priority').value",
                  "fetch('/api/ticket'",
                  "r.data.ticket_id"):
        assert token in a, token


# ------------------------------------------------------------- local-only
@pytest.mark.parametrize("tpl", ("assessment.html", "tools.html",
                                 "training_phishing.html"))
def test_local_only_pages_make_no_network_calls(tpl):
    text = (SRC / "templates" / tpl).read_text(encoding="utf-8")
    for bad in ("fetch(", "XMLHttpRequest", "sendBeacon", "/api/"):
        assert bad not in text, (tpl, bad)


def test_assessment_submit_is_a_local_score_only():
    text = (SRC / "templates" / "assessment.html").read_text(
        encoding="utf-8")
    handler = text[text.index("form.addEventListener('submit'"):]
    assert "ev.preventDefault()" in handler
    assert "assess-score" in handler  # result rendered in-page


def test_tools_and_training_buttons_cannot_submit_a_form():
    tools = (SRC / "templates" / "tools.html").read_text(encoding="utf-8")
    assert "<form" not in tools
    assert tools.count('type="button"') >= 2  # generate + copy
    assert "pwIn.addEventListener('input'" in tools  # checker is live-input
    phish = (SRC / "templates" / "training_phishing.html").read_text(
        encoding="utf-8")
    assert "<form" not in phish
    assert "bL.type = 'button'" in phish and "bP.type = 'button'" in phish


# ------------------------------------------------------------- search/data
def test_flight_search_forms_all_get_flights_with_q():
    for rel in ("site/index.html", "templates/index.html",
                "templates/flights.html"):
        text = (SRC / rel).read_text(encoding="utf-8")
        forms = re.findall(r'<form[^>]*>', text)
        flight = [f for f in forms if 'action="/flights"' in f]
        assert flight and all('method="get"' in f for f in flight), rel
        assert 'name="q"' in text, rel


def test_data_pages_fetch_only_their_own_data():
    threat = (SRC / "templates" / "threat_map.html").read_text(
        encoding="utf-8")
    geo = (SRC / "templates" / "geopolitical.html").read_text(
        encoding="utf-8")
    assert "fetch('/api/threat-data')" in threat
    assert "fetch('/api/geo-data')" in geo
    for text in (threat, geo):
        assert "method:'POST'" not in text and 'method:"POST"' not in text


# ------------------------------------------------------------- end-to-end
def test_contact_end_to_end_row_carries_every_field(app_mod):
    client = _client(app_mod)
    before = len(_rows(app_mod, "contacts"))
    resp = client.post("/api/contact", json={
        "name": "Forms Audit", "email": "audit@example.co",
        "subject": "Parity check", "service": "Security installs",
        "pref_date": "2026-11-04", "pref_window": "Morning",
        "message": "Every field must survive."})
    assert resp.status_code == 200 and resp.json()["ok"] is True
    mine = [r for r in _rows(app_mod, "contacts")
            if r["email"] == "audit@example.co"]
    assert len(mine) == 1
    row = mine[0]
    assert row["name"] == "Forms Audit"
    assert row["subject"] == "Parity check"
    assert row["service"] == "Security installs"
    assert row["pref_date"] == "2026-11-04"
    assert row["pref_window"] == "Morning"
    assert row["message"] == "Every field must survive."
    assert len(_rows(app_mod, "contacts")) == before + 1


def test_contact_invalid_submissions_create_no_row(app_mod):
    client = _client(app_mod)
    before = len(_rows(app_mod, "contacts"))
    for payload in (
            {"name": "X", "email": "x@example.co"},                # no message
            {"name": "X", "email": "not-an-email", "message": "m"},  # bad email
            {"name": "X", "email": "x@example.co", "message": "m",
             "service": "Wizardry"},                                # bad service
            {"name": "X", "email": "x@example.co", "message": "m",
             "pref_window": "Teatime"}):                            # bad window
        resp = client.post("/api/contact", json=payload)
        assert resp.status_code == 400, payload
    assert len(_rows(app_mod, "contacts")) == before


def test_ticket_end_to_end_row_and_bridge_feed(app_mod, tmp_path,
                                               monkeypatch):
    client = _client(app_mod)
    resp = client.post("/api/ticket", json={
        "name": "Forms Audit", "email": "audit@example.co",
        "phone": "816-555-0100", "category": "Security concern",
        "priority": "Critical",  # public can never file Critical
        "subject": "Audit ticket", "message": "Full field trace."})
    assert resp.status_code == 200
    tid = resp.json()["ticket_id"]
    mine = [r for r in _rows(app_mod, "tickets") if r["id"] == tid]
    assert len(mine) == 1
    row = mine[0]
    assert row["phone"] == "816-555-0100"
    assert row["category"] == "Security concern"
    assert row["priority"] == "Normal"  # clamped by design
    assert row["subject"] == "Audit ticket"
    assert row["message"] == "Full field trace."

    # The bridge feed Command polls: gated, and carries every field.
    token_file = tmp_path / "internal_token.txt"
    token_file.write_text("audit-token", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_LIVE_INTERNAL_TOKEN_PATH",
                       str(token_file))
    assert client.get("/internal/tickets").status_code == 404
    gated = TestClient(app_mod.app, raise_server_exceptions=False,
                       client=("127.0.0.1", 50000))
    feed = gated.get("/internal/tickets",
                     headers={"X-Internal-Token": "audit-token"})
    assert feed.status_code == 200
    carried = [t for t in feed.json()["tickets"] if t["id"] == tid]
    assert len(carried) == 1
    t = carried[0]
    assert t["name"] == "Forms Audit" and t["email"] == "audit@example.co"
    assert t["phone"] == "816-555-0100"
    assert t["category"] == "Security concern"
    assert t["priority"] == "Normal"
    assert t["subject"] == "Audit ticket"
    assert t["message"] == "Full field trace."


def test_ticket_invalid_submission_creates_no_row(app_mod):
    client = _client(app_mod)
    before = len(_rows(app_mod, "tickets"))
    resp = client.post("/api/ticket", json={
        "name": "X", "email": "x@example.co", "message": "no subject"})
    assert resp.status_code == 400
    assert len(_rows(app_mod, "tickets")) == before
