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
        "Kansas City metro area",
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
    # Privacy rule (owner, 2026-10-25): his exam timing is personal
    # schedule, never public copy — the credential may appear only as
    # a dateless in-progress mention, with no target date anywhere.
    assert "December 2026" not in body
    assert "Dec 2026" not in body
    assert "exam targeted" not in body


@pytest.mark.parametrize("path", ["/", "/operations", "/threat-map",
                                  "/geopolitical", "/flights", "/about",
                                  "/services"])
def test_public_pages_never_name_liberty(app_mod, path):
    # Privacy rule (owner, 2026-10-25): the owner's home city never
    # appears in public copy — the service area is stated as Kansas
    # City / the KC metro only. (The one legitimate code-side use of
    # the word would be an identifier, not copy; pages carry none.)
    # The static pair (/report-issue, /ticket) is served from the
    # site/ tree this suite's scratch app doesn't fixture; those
    # bytes were swept clean and are re-grepped externally after
    # every deploy (see LIVE-FLIGHTS-2026-10-25, Privacy Scrub).
    resp = _client(app_mod).get(path)
    assert resp.status_code == 200
    assert "liberty" not in resp.text.lower()


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
    assert "/static/style.css?v=20261025-4" in resp.text


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


# ---------------------------------------------------------- services
def test_services_page_renders_five_sections(app_mod):
    resp = _client(app_mod).get("/services")
    assert resp.status_code == 200
    body = _flat(resp.text)
    for fact in (
        'id="penetration-testing"',
        'id="cybersecurity-it"',
        'id="security-installs"',
        'id="incident-response"',
        'id="custom-software"',
        "signed written authorization",
        "not a scare sheet",
        "Kansas City metro",
        "by appointment only",
        "816-533-8418",
        "Sentinelsafeguard@outlook.com",
        "around the clock",
    ):
        assert fact in body, fact
    # each section asks the question the visitor came with
    assert body.count("Who it is for") == 5
    assert body.count("What you walk away with") == 5
    # four sections CTA to the contact form, IR to the report page
    assert body.count('href="/#contact"') >= 5
    assert 'href="/report-issue"' in body


def test_services_page_carries_no_prohibited_claims(app_mod):
    body = _client(app_mod).get("/services").text.lower()
    for banned in (
        "cyberdogs",
        "offleash",
        "backflow",
        "trusted by",
        "testimonial",
        "our experts",
        "our team of",
        "clients include",
        "satisfied clients",
        "businesses served",
        "private security guard",
        "private investigation",
        "starting at",
        "$",
    ):
        assert banned not in body, banned


def test_services_developer_tribute_links_public_proof(app_mod):
    body = _flat(_client(app_mod).get("/services").text)
    for proof in (
        "Sentinel's President is a working developer",
        "Technician's Toolkit",
        "HackProof",
        "https://github.com/TheRealJesusTheHacker/Technicians-Toolkit",
        "https://github.com/TheRealJesusTheHacker/Sphinx/releases",
        "https://github.com/TheRealJesusTheHacker/HackProof",
        "built by the people who test other people's",
        "Eight technician tools",
        "Windows, Android, and Debian",
    ):
        assert proof in body, proof


def test_services_nav_active_and_header_link_everywhere(app_mod):
    client = _client(app_mod)
    resp = client.get("/services")
    assert 'href="/services" class="active"' in resp.text
    assert "/services" in app_mod._VISITOR_PUBLIC_PATHS
    for path in ("/about", "/operations", "/threat-map", "/geopolitical",
                 "/flights"):
        page = client.get(path)
        assert page.status_code == 200
        # nav link + footer link on every shared-chrome page
        assert page.text.count('href="/services"') >= 2, path


def test_about_cards_crosslink_to_services_anchors(app_mod):
    body = _flat(_client(app_mod).get("/about").text)
    for anchor in (
        'href="/services#penetration-testing"',
        'href="/services#cybersecurity-it"',
        'href="/services#security-installs"',
        'href="/services#incident-response"',
        'href="/services#custom-software"',
        "Custom websites &amp; software",
        "Built by a developer",
    ):
        assert anchor in body, anchor


def test_threat_counters_are_countup_targets(app_mod):
    resp = _client(app_mod).get("/threat-map")
    assert resp.status_code == 200
    assert "data-cu" in resp.text
    assert "SSG.countUp" in resp.text
    # first-load-only animation, refreshes update in place
    assert "cuFirst" in resp.text
