"""Estate sweep 2026-10-25 — Lane 1 (public site) pins.

One test per shipped behavior, in the house style: the honest
statements are the deliverable, so the pins assert they are PRESENT
(and that the standing prohibitions — invented prices, client
claims, "Liberty" in public copy — stay absent). Pages that collect
nothing must keep collecting nothing: the assessment/tools/training
pins assert there is no form POST behind them at all.
"""
import importlib.util
import json
import re
import shutil
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
    tmp = tmp_path_factory.mktemp("sl-estate")
    return _load_app(tmp, "sl_app_estate")


def _client(app_mod):
    return TestClient(app_mod.app, raise_server_exceptions=False)


def _flat(text: str) -> str:
    return " ".join(text.split())


BANNED_PUBLIC = ("liberty", "trusted by", "testimonial", "our clients",
                 "clients include", "satisfied clients",
                 "businesses served", "starting at", "guarantee",
                 "private security guard", "private investigation")


# ------------------------------------------------------------ assessment
def test_assessment_renders_ten_questions_and_no_transmission(app_mod):
    body = _client(app_mod).get("/assessment").text
    assert body.count('class="assess-q"') == 10
    for key in ("router", "updates", "backups", "mfa", "passwords",
                "wifi", "locks", "training", "antivirus", "plan"):
        assert f'name="q-{key}"' in body, key
    flat = _flat(body)
    assert "Nothing you answer leaves this page" in flat
    assert "kc-business-security-basics.pdf" in body
    # the scoring is client-side by construction: the page's script
    # must not reference any network call at all
    scripts = re.findall(r"<script>(.*?)</script>", body, re.S)
    joined = "\n".join(scripts)
    assert "fetch(" not in joined and "XMLHttpRequest" not in joined


def test_assessment_has_no_post_endpoint(app_mod):
    resp = _client(app_mod).post("/assessment", json={})
    assert resp.status_code in (404, 405)


# ------------------------------------------------------------ tools
def test_tools_page_states_method_and_privacy(app_mod):
    body = _client(app_mod).get("/tools").text
    flat = _flat(body)
    assert "Nothing leaves your browser" in flat
    assert "getRandomValues" in body
    assert "1,300-word list" in flat
    # strength checker honesty: best-case framing + method stated
    assert "best case" in flat
    assert "does <strong>not</strong> punish or reward patterns" in flat


# ------------------------------------------------------------ training
def test_training_items_answers_and_inert_samples(app_mod):
    body = _client(app_mod).get("/training/phishing").text
    assert body.count('"phish"') >= 1 and body.count('"legit"') >= 1
    assert "training sample, not a real message" in body
    # six samples, mixed answers, explanations keyed to tells
    answers = re.findall(r'answer: "(legit|phish)"', body)
    assert len(answers) == 6
    assert set(answers) == {"legit", "phish"}
    # samples render as text only: the mock fields are filled with
    # textContent in the page script, never with markup
    assert "usps-redelivery.example" in body
    assert "textContent = it.body" in body
    assert "innerHTML = '<p class=\"ph-kind\"></p>" in body or \
        "ph-kind" in body


# ------------------------------------------------------------ disclosure
def test_security_txt_rfc9116(app_mod):
    client = _client(app_mod)
    resp = client.get("/.well-known/security.txt")
    assert resp.status_code == 200
    text = resp.text
    assert "Contact: https://sentinelsafeguard.net/report-issue" in text
    assert "Contact: mailto:sentinel@sentinelsafeguard.net" in text
    assert "Preferred-Languages: en" in text
    assert "Canonical: https://sentinelsafeguard.net/.well-known/security.txt" in text
    exp = re.search(r"Expires: (\S+)", text).group(1)
    assert exp.startswith("2027-10-25")
    # the static copy and the app copy are the same bytes' content
    static = (SRC / "site" / ".well-known" / "security.txt").read_text(
        encoding="utf-8")
    assert static == text
    page = client.get("/disclosure")
    assert page.status_code == 200
    assert "sentinel@sentinelsafeguard.net" in page.text


# ------------------------------------------------------------ contact upgrade
def test_contact_form_carries_booking_fields(app_mod):
    body = _client(app_mod).get("/contact").text
    for field in ('id="cf-service"', 'id="cf-pref-date"',
                  'id="cf-pref-window"'):
        assert field in body, field
    for opt in app_mod.CONTACT_SERVICES:
        assert opt.replace("&", "&amp;") in body, opt
    for opt in app_mod.CONTACT_TIME_WINDOWS:
        assert f"<option>{opt}</option>" in body, opt
    flat = _flat(body)
    assert "a preference, not a booking" in flat


async def _fresh_db(app_mod):
    await app_mod.init_db()


def test_contact_api_accepts_and_stores_booking_fields(app_mod):
    import asyncio
    asyncio.run(_fresh_db(app_mod))
    client = _client(app_mod)
    resp = client.post("/api/contact", json={
        "name": "Test Person", "email": "test@example.com",
        "message": "Hello.", "service": "Security installs",
        "pref_date": "2026-11-04", "pref_window": "Morning"})
    assert resp.status_code == 200 and resp.json()["ok"] is True
    # read the store directly (the admin API is gated by design;
    # its own suites pin that surface) — the SELECT * admin view
    # carries these columns automatically
    import sqlite3
    conn = sqlite3.connect(app_mod.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM contacts").fetchall()]
    conn.close()
    mine = [r for r in rows if r["email"] == "test@example.com"]
    assert mine and mine[0]["service"] == "Security installs"
    assert mine[0]["pref_date"] == "2026-11-04"
    assert mine[0]["pref_window"] == "Morning"


def test_contact_api_rejects_bad_booking_values(app_mod):
    client = _client(app_mod)
    base = {"name": "T", "email": "t@example.com", "message": "Hi."}
    for extra in ({"service": "Wizardry"},
                  {"pref_date": "next Tuesday"},
                  {"pref_date": "2026-13-40"},
                  {"pref_window": "Teatime"}):
        resp = client.post("/api/contact", json={**base, **extra})
        assert resp.status_code == 400, extra
    # and the original payload (no booking fields) still works
    resp = client.post("/api/contact", json=base)
    assert resp.status_code == 200


def test_privacy_inventory_names_booking_fields(app_mod):
    body = _flat(_client(app_mod).get("/privacy").text)
    assert "optional booking fields" in body
    assert "a preferred date, and a preferred time window" in body
    assert 'href="/disclosure"' in _client(app_mod).get("/privacy").text


# ------------------------------------------------------------ faq
def test_faq_only_states_true_things(app_mod):
    body = _client(app_mod).get("/faq").text
    flat = _flat(body)
    low_flat = flat.lower()
    for fact in ("by appointment", "signed penetration testing "
                 "authorization", "kansas city metro",
                 "what drives the cost", "scope"):
        assert fact in low_flat, fact
    low = body.lower()
    for banned in BANNED_PUBLIC:
        assert banned not in low, banned
    assert "$" not in body  # no numbers wearing a dollar sign, ever


# ------------------------------------------------------------ insights plumbing
def test_insights_rss_is_valid_and_real(app_mod):
    import xml.etree.ElementTree as ET
    resp = _client(app_mod).get("/insights/feed.xml")
    assert resp.status_code == 200
    assert "rss" in resp.headers["content-type"]
    root = ET.fromstring(resp.text)
    assert root.tag == "rss"
    titles = [t.text for t in root.iter("title")]
    assert "The password on your router is a product now" in titles
    links = [t.text for t in root.iter("link")]
    assert any(l.endswith("/insights/the-password-on-your-router")
               for l in links)


def test_sitemap_covers_every_public_page(app_mod):
    import xml.etree.ElementTree as ET
    resp = _client(app_mod).get("/sitemap.xml")
    assert resp.status_code == 200
    root = ET.fromstring(resp.text)
    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locs = [e.text for e in root.iter(
        "{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
    for path in app_mod._SITEMAP_PATHS:
        assert "https://sentinelsafeguard.net" + path in locs, path
    assert any(l.endswith("/insights/patch-day-is-today") for l in locs)
    assert not any("/admin" in l or "/news" in l for l in locs)


def test_robots_points_at_sitemap(app_mod):
    resp = _client(app_mod).get("/robots.txt")
    assert resp.status_code == 200
    assert "Sitemap: https://sentinelsafeguard.net/sitemap.xml" in resp.text


def test_insight_post_carries_og_article_meta(app_mod):
    body = _client(app_mod).get("/insights/patch-day-is-today").text
    assert 'property="og:type" content="article"' in body
    assert 'property="og:title" content="Patch day is today now"' in body
    home = _client(app_mod).get("/operations").text
    assert 'property="og:type" content="website"' in home
    assert 'name="twitter:card" content="summary_large_image"' in home


def test_print_stylesheet_present_for_posts():
    css = (SRC / "static" / "style.css").read_text(encoding="utf-8")
    assert "@media print" in css
    assert "header.topbar, footer" in css


# ------------------------------------------------------------ checklist pdf
def test_checklist_pdf_is_one_real_page():
    pdf = (SRC / "site" / "assets" /
           "kc-business-security-basics.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-")
    assert b"/Count 1" in pdf
    assert b"KC BUSINESS SECURITY BASICS" in pdf
    assert b"Liberty" not in pdf


# ------------------------------------------------------------ polish
def test_themed_500_for_browser_navigations(app_mod):
    async def _boom():
        raise RuntimeError("deliberate test failure")

    # registered at the FRONT of the route table: the static mount
    # sits last in the app, and a route appended now would land
    # behind it and never be reached
    app_mod.app.add_api_route("/__estate_boom", _boom)
    _r = app_mod.app.router.routes.pop()
    app_mod.app.router.routes.insert(0, _r)
    client = _client(app_mod)
    resp = client.get("/__estate_boom",
                      headers={"accept": "text/html"})
    assert resp.status_code == 500
    assert "Something on" in resp.text and "our side broke" in resp.text
    api = client.get("/__estate_boom")
    assert api.status_code == 500
    assert api.headers["content-type"].startswith("application/json")


def test_skip_link_and_main_landmark(app_mod):
    body = _client(app_mod).get("/about").text
    assert 'class="skip-link" href="#main"' in body
    assert '<main id="main">' in body


# ------------------------------------------------------------ availability
def _write_log(tmp: Path, rows):
    p = tmp / "availability.jsonl"
    p.write_text("".join(json.dumps(r) + "\n" for r in rows),
                 encoding="utf-8")
    return p


def test_availability_empty_log_is_honest(app_mod, tmp_path, monkeypatch):
    monkeypatch.setattr(app_mod, "AVAILABILITY_LOG_PATH",
                        tmp_path / "missing.jsonl")
    body = _client(app_mod).get("/availability").text
    assert "Checks are being set up" in _flat(body)


def test_availability_computes_from_contract_log(app_mod, tmp_path,
                                                  monkeypatch):
    now_ms = 1761436800000  # 2025-10-25T16:00:00Z — near "now" math only
    rows = []
    import time as _t
    base = int(_t.time() * 1000) - 3600_000
    for i, target in enumerate(
            [t for t, _ in app_mod._AVAIL_TARGETS]):
        rows.append({"ts": base, "target": target, "ok": True,
                     "ms": 100 + i})
        rows.append({"ts": base + 300_000, "target": target,
                     "ok": target != "mail_smtp_25", "ms": 90 + i})
    path = _write_log(tmp_path, rows)
    monkeypatch.setattr(app_mod, "AVAILABILITY_LOG_PATH", path)
    body = _client(app_mod).get("/availability").text
    flat = _flat(body)
    assert "Checking since" in flat
    assert "Public website" in flat
    assert "Mail — delivery" in flat  # the em-dash label survives
    assert body.count('class="badge ok"') == 7
    assert body.count('class="badge error"') == 1
    assert "50%" in flat  # smtp: 1 of 2 checks ok
    assert "100%" in flat


def test_availability_skips_torn_lines(app_mod, tmp_path, monkeypatch):
    import time as _t
    base = int(_t.time() * 1000) - 60_000
    path = tmp_path / "availability.jsonl"
    path.write_text(
        json.dumps({"ts": base, "target": "public_site", "ok": True,
                    "ms": 42}) + "\n{\"ts\": torn\n", encoding="utf-8")
    monkeypatch.setattr(app_mod, "AVAILABILITY_LOG_PATH", path)
    resp = _client(app_mod).get("/availability")
    assert resp.status_code == 200
    assert "Public website" in resp.text


# ------------------------------------------------------------ standing rules
@pytest.mark.parametrize("path", ["/assessment", "/tools",
                                  "/training/phishing", "/faq",
                                  "/disclosure", "/availability",
                                  "/contact"])
def test_new_pages_obey_standing_prohibitions(app_mod, path):
    body = _client(app_mod).get(path).text.lower()
    for banned in BANNED_PUBLIC:
        assert banned not in body, (path, banned)
