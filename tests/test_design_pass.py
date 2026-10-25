"""Design pass pins (2026-10-25) — public-site look & feel elevation
plus the About the Company page.

Covers:
  * /about renders in the shared chrome, carries ONLY the owner's
    verified facts (president-led, Missouri LLC organized January
    2024, KC-based, by appointment only, the real lines of work,
    future services marked planned), and none of the prohibited
    claims (no client history, no testimonials, no Cyberdogs, no
    ASSE/backflow, Security+ only as in-progress).
  * The shared header gains the About link everywhere with correct
    active marking; the visitor log counts /about like every other
    public page.
  * The design system v2 is present in style.css (tokens, display
    type, selection, reveal states with a reduced-motion collapse),
    and the stylesheet version query moved with the CSS change.
  * The threat counters render as count-up targets (data-cu).

Loads app.py from a scratch copy the same way the other suites do.
Hermetic: no network — the data store is seeded directly.
"""
import importlib.util
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent


def _load_app(tmp: Path, name: str, config_text: str = "server:\n  port: 8443\n"):
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
def app_mod(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-designpass")
    return _load_app(tmp, "sl_app_designpass")


def _client(mod):
    return TestClient(mod.app, raise_server_exceptions=False)


# ------------------------------------------------------------- about
def _flat(html: str) -> str:
    """Collapse template line-wraps so phrase checks read prose."""
    return " ".join(html.split())


def test_about_page_renders_with_verified_facts(app_mod):
    resp = _client(app_mod).get("/about")
    assert resp.status_code == 200
    body = _flat(resp.text)
    for fact in (
        "Skyler Paul Henderson",
        "President &amp; Lead Director of Operations",
        "organized in January 2024",
        "Kansas City, Missouri",
        "including Liberty",
        "by appointment only",
        "816-533-8418",
        "Sentinelsafeguard@outlook.com",
        "Penetration testing",
        "Digital forensics",
        "Incident response",
        "Security system installs",
        "Education",
        "SPF, DKIM, and DMARC",
        "Technician's Toolkit",
        "Sphinx",
    ):
        assert fact in body, fact


def test_about_page_carries_no_prohibited_claims(app_mod):
    body = _client(app_mod).get("/about").text.lower()
    for banned in (
        "cyberdogs",
        "backflow",
        "asse 5110",
        "american society of sanitary",
        "trusted by",
        "testimonial",
        "our experts",
        "our team of",
        "clients include",
        "satisfied clients",
        "businesses served",
    ):
        assert banned not in body, banned


def test_about_future_services_marked_planned_only(app_mod):
    body = _flat(_client(app_mod).get("/about").text)
    assert "Planned — not yet offered" in body
    assert "not current" in body
    # the planned line is the ONLY place guards/investigation appear
    low = body.lower()
    assert low.count("private security guard") == 1
    assert low.count("private investigation") == 1


def test_about_security_plus_stated_in_progress_only(app_mod):
    body = _flat(_client(app_mod).get("/about").text)
    assert "currently completing CompTIA Security+" in body
    assert "December 2026" in body


def test_about_nav_active_and_header_link_everywhere(app_mod):
    client = _client(app_mod)
    resp = client.get("/about")
    assert 'href="/about" class="active"' in resp.text
    for path in ("/operations", "/threat-map", "/geopolitical", "/flights"):
        page = client.get(path)
        assert page.status_code == 200
        assert 'href="/about"' in page.text, path
        # footer carries the About link too
        assert page.text.count('href="/about"') >= 2, path


def test_about_counted_in_visitor_log(app_mod):
    assert "/about" in app_mod._VISITOR_PUBLIC_PATHS


# ------------------------------------------------------ design system
def test_stylesheet_version_query_bumped_for_design_pass(app_mod):
    resp = _client(app_mod).get("/operations")
    assert "/static/style.css?v=20261025-3" in resp.text


def test_design_system_tokens_present():
    css = (SRC / "static" / "style.css").read_text(encoding="utf-8")
    for token in (
        "--font-disp",
        "--font-mono",
        "--shadow-1",
        "--r-m: 12px",
        "::selection",
        "html.js .rv",
    ):
        assert token in css, token
    # reveal states collapse to visible under reduced motion
    assert "html.js .rv, html.js .rvf { opacity: 1 !important" in css


def test_base_template_favicon_is_emblem_and_fonts_loaded(app_mod):
    resp = _client(app_mod).get("/operations")
    assert 'rel="icon" type="image/jpeg" href="/assets/sentinel-safeguard-mark.jpg"' in resp.text
    assert 'rel="apple-touch-icon" href="/assets/sentinel-safeguard-mark.jpg"' in resp.text
    assert "family=Archivo" in resp.text
    assert "family=IBM+Plex+Mono" in resp.text


def test_threat_counters_are_countup_targets(app_mod):
    resp = _client(app_mod).get("/threat-map")
    assert resp.status_code == 200
    assert "data-cu" in resp.text
    assert "SSG.countUp" in resp.text
    # first-load-only animation, refreshes update in place
    assert "cuFirst" in resp.text
