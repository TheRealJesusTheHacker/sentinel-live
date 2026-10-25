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
  * /how-it-works renders the six engagement steps, names the four
    real client forms exactly, carries the emergencies shortcut
    and the what-we-ask partnership block, and none of the
    prohibited claims — in particular no invented SLAs, guarantees,
    or response-times. Its nav addition (eleven destinations)
    re-opened the header-band fit question in the band pin above:
    measured ~1646px natural need, band top now 1720px.

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
                                  "/services", "/who-we-protect",
                                  "/how-it-works"])
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
    assert "/static/style.css?v=20261025-6" in resp.text


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


# --------------------------------------------------- who we protect
def test_who_we_protect_page_renders_focus_blocks(app_mod):
    resp = _client(app_mod).get("/who-we-protect")
    assert resp.status_code == 200
    body = _flat(resp.text)
    for fact in (
        'id="apartments-property"',
        'id="senior-centers"',
        'id="churches-nonprofits"',
        'id="local-services"',
        'id="residential"',
        'id="open-door"',
        "businesses and homes",
        "not a whitelist",
        "Kansas City metro",
        "By appointment only",
        "816-533-8418",
        "Sentinelsafeguard@outlook.com",
    ):
        assert fact in body, fact
    # each focus block states what Sentinel looks at first
    assert body.count("What Sentinel looks at first") == 5
    # blocks link into the matching services anchors
    assert 'href="/services#security-installs"' in body
    assert 'href="/services#cybersecurity-it"' in body


def test_who_we_protect_residential_and_open_door_present(app_mod):
    # Owner's explicit order (2026-10-25): residential clients and
    # other industries are accepted — the named industries are a
    # focus, never a fence. These two blocks are the proof.
    body = _flat(_client(app_mod).get("/who-we-protect").text)
    for phrase in (
        "Residential — homes &amp; families",
        "A home is a network now",
        "home Wi-Fi",
        "scam-proofing",
        "Don't see your world here?",
        "it was never a fence",
        "solo operators",
        'href="/#contact"',
    ):
        assert phrase in body, phrase


def test_who_we_protect_is_invitation_not_resume(app_mod):
    # The page is an invitation ("built for / common calls"), never
    # a résumé — nothing may imply an existing client base in any
    # vertical (baseline: the first booking is still ahead).
    body = _client(app_mod).get("/who-we-protect").text.lower()
    for banned in (
        "cyberdogs",
        "offleash",
        "backflow",
        "trusted by",
        "testimonial",
        "our experts",
        "our team of",
        "our clients",
        "clients include",
        "satisfied clients",
        "businesses served",
        "we currently protect",
        "private security guard",
        "private investigation",
        "starting at",
        "$",
    ):
        assert banned not in body, banned


def test_who_we_protect_tightening_band_covers_the_row():
    # Who We Protect made the shared nav ten destinations plus the
    # Contact pill. Measured in the real-font browser census
    # (2026-10-25): the full row needs ~1496px at desktop metrics
    # (the nine-destination row ~1425px) and ~1304px even at the
    # header band's original .45em link padding; the same census
    # showed the band's old fit guarantee had lapsed for the
    # nine-destination row too once the design-pass fonts landed.
    # The band therefore reaches 1560px, tightens link padding to
    # .38em, and lets the row scroll internally (scrollbar hidden,
    # the mobile header's pattern) so no page overflows at band
    # widths. Pin the values so the next nav addition re-opens the
    # question in the suite instead of silently overflowing screens.
    # How It Works (2026-10-25) was that next addition — eleven
    # destinations: the same real-font measurement reads a natural
    # header need of ~1646px at desktop metrics (fits at 1650px,
    # overshoots ~26px at 1620px), so the band's top edge moved to
    # 1720px and this pin moved with it, exactly as designed.
    css = (SRC / "static" / "style.css").read_text(encoding="utf-8")
    assert "@media (max-width: 1720px) and (min-width: 861px)" in css
    assert ".mainnav a { padding: .35em .38em; }" in css
    band = css.split("@media (max-width: 1720px)")[1].split("@media")[0]
    assert "overflow-x: auto" in band


def test_who_we_protect_nav_active_and_header_link_everywhere(app_mod):
    client = _client(app_mod)
    resp = client.get("/who-we-protect")
    assert 'href="/who-we-protect" class="active"' in resp.text
    assert "/who-we-protect" in app_mod._VISITOR_PUBLIC_PATHS
    for path in ("/about", "/services", "/operations", "/threat-map",
                 "/geopolitical", "/flights"):
        page = client.get(path)
        assert page.status_code == 200
        # nav link + footer link on every shared-chrome page
        assert page.text.count('href="/who-we-protect"') >= 2, path


# -------------------------------------------------------- how it works
def test_how_it_works_page_renders_six_steps(app_mod):
    resp = _client(app_mod).get("/how-it-works")
    assert resp.status_code == 200
    body = _flat(resp.text)
    for fact in (
        'id="reach-out"',
        'id="talk-and-look"',
        'id="in-writing"',
        'id="the-work"',
        'id="report-walkthrough"',
        'id="after"',
        "first call to finished job",
        "by appointment only",
        "816-533-8418",
        "on-site comes first",
        "documented as it goes",
        "Kansas City, Missouri",
        "By appointment only",
    ):
        assert fact in body, fact
    # the six step kickers render in order
    for kicker in ("Step 01", "Step 02", "Step 03", "Step 04",
                   "Step 05", "Step 06"):
        assert kicker in body, kicker
    # the steps cross-link the way the process flows
    assert 'href="/services#penetration-testing"' in body
    assert 'href="/services#incident-response"' in body
    assert 'href="/report-issue"' in body
    assert 'href="/#contact"' in body


def test_how_it_works_names_the_real_forms(app_mod):
    # The paperwork is real (owner order 2026-10-25): the four
    # client forms exist as final approved documents — Engagement
    # Letter, Scope of Work, Penetration Testing Authorization,
    # Chain of Custody — and the page must name them exactly, with
    # the signed-before-work rule stated, never softened.
    body = _flat(_client(app_mod).get("/how-it-works").text)
    for form in (
        "Engagement Letter",
        "Scope of Work",
        "Penetration Testing Authorization",
        "Chain of Custody",
    ):
        assert form in body, form
    for phrase in (
        "signed before work",
        "no system is ever tested without it",
        "if it is not in the Scope of Work, it does not happen",
        "yours to keep",
    ):
        assert phrase in body, phrase


def test_how_it_works_emergencies_and_asks_present(app_mod):
    # Owner's brief: an incident in progress skips the line, and
    # the small "what Sentinel asks of you" partnership block
    # (access when scheduled, one decision-maker, straight answers).
    body = _flat(_client(app_mod).get("/how-it-works").text)
    for phrase in (
        'id="emergencies"',
        "skips the line",
        "open around the clock",
        'id="what-we-ask"',
        "What Sentinel asks of you",
        "Access when it is scheduled",
        "One decision-maker",
        "Straight answers about the environment",
    ):
        assert phrase in body, phrase


def test_how_it_works_carries_no_prohibited_claims(app_mod):
    # Accuracy pins (owner's standing rules): no prices, NO
    # invented SLAs / guarantees / response-times — the page may
    # mirror the site's existing contact language only — no client
    # history, no team claims, no guards/investigations as
    # offerings, no Cyberdogs.
    body = _client(app_mod).get("/how-it-works").text.lower()
    for banned in (
        "cyberdogs",
        "offleash",
        "trusted by",
        "testimonial",
        "our experts",
        "our team of",
        "our clients",
        "satisfied clients",
        "businesses served",
        "starting at",
        "$",
        "guarantee",
        "response time",
        "respond within",
        "within 24",
        "within one business day",
        "same-day response",
        "sla",
        "private security guard",
        "private investigation",
    ):
        assert banned not in body, banned


def test_how_it_works_nav_active_and_header_link_everywhere(app_mod):
    client = _client(app_mod)
    resp = client.get("/how-it-works")
    assert 'href="/how-it-works" class="active"' in resp.text
    assert "/how-it-works" in app_mod._VISITOR_PUBLIC_PATHS
    for path in ("/about", "/services", "/who-we-protect",
                 "/operations", "/threat-map", "/geopolitical",
                 "/flights"):
        page = client.get(path)
        assert page.status_code == 200
        # nav link + footer link on every shared-chrome page
        assert page.text.count('href="/how-it-works"') >= 2, path


def test_threat_counters_are_countup_targets(app_mod):
    resp = _client(app_mod).get("/threat-map")
    assert resp.status_code == 200
    assert "data-cu" in resp.text
    assert "SSG.countUp" in resp.text
    # first-load-only animation, refreshes update in place
    assert "cuFirst" in resp.text
