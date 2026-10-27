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
  * /insights is a publishing surface, not a page: posts are data
    files in insights/ (front matter + a Markdown subset) that the
    index generates from, newest first, and each post renders at
    /insights/<slug>. Pins cover the three seed posts distilled
    from the 2026-10-25 briefing plus the five owner-approved
    2026-10-26 posts (dated, defense-only, plain language), the
    plain-404 for unknown slugs, the educational line on post
    pages, and the standing accuracy prohibitions.
    Its nav addition (twelve destinations) re-opened the band
    question again — see the updated band pin.
  * /privacy states the site's data handling, traced sentence by
    sentence to a verified inventory of the code's data flows
    (PRIVACY-PAGE-2026-10-25): the two forms' exact fields and
    storage, the visitor log (IP, user agent, path, referrer,
    Cloudflare country, bot flag) and its 90-day prune, the one
    first-party cookie (svid), the named third parties
    (Cloudflare, Esri — fonts and the Leaflet library self-hosted
    since the 2026-10-27 CSP pass), and the never list.
    Pins assert the honest disclosures EXIST and that the page
    never claims "we collect nothing", "no cookies", or an
    unqualified "anonymous" — the site collects, and the page
    says so. Its nav addition (thirteen destinations) re-opened
    the band question again — see the updated band pin.

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
    if (SRC / "insights").is_dir():
        shutil.copytree(SRC / "insights", tmp / "insights")
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
                                  "/how-it-works", "/contact", "/insights",
                                  "/privacy",
                                  "/insights/the-password-on-your-router",
                                  "/insights/patch-day-is-today",
                                  "/insights/backups-you-have-tested"])
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
        # POLISH-LANE-A-2026-10-27: bottom nav removed by owner order —
        # the link lives in the header only; the slim footer must NOT carry it.
        assert page.text.count('href="/about"') >= 1, path
        assert 'href="/about"' not in page.text.split("<footer>", 1)[1], path


def test_about_counted_in_visitor_log(app_mod):
    assert "/about" in app_mod._VISITOR_PUBLIC_PATHS


# ------------------------------------------------------ design system
def test_stylesheet_version_query_bumped_for_design_pass(app_mod):
    resp = _client(app_mod).get("/operations")
    # Re-pointed 2026-10-27 (owner order, new features): the
    # threat-level / internet-weather styles changed style.css,
    # so the version query moved to 20261027-2.
    # DEFCON-RESHAPE-2026-10-27: the DEFCON reshape widened the
    # nav band in style.css, so the version query moved to
    # 20261027-3.
    # BREACH-CHECK-2026-10-27: Breach Check widened the nav band
    # again and added its card styles, so the version query
    # moved to 20261027-4.
    # POLISH-LANE-A-2026-10-27: slim footer + social + animation pass
    # changed style.css, so the version query moved to 20261027-5.
    assert "/static/style.css?v=20261027-5" in resp.text


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
    # CSP pass 2026-10-27: the typefaces are self-hosted — the page
    # links our own fonts.css and no Google Fonts URL may appear.
    assert 'href="/static/fonts.css"' in resp.text
    assert "fonts.googleapis.com" not in resp.text
    assert "fonts.gstatic.com" not in resp.text
    css = _client(app_mod).get("/static/fonts.css").text
    assert "font-family: 'Archivo'" in css
    assert "font-family: 'IBM Plex Mono'" in css
    assert "fonts.gstatic.com" not in css


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
    # four sections CTA to the contact page, IR to the report page
    # (plus the closer's Send a message — five in the page body,
    # before the header pill and footer are counted)
    assert body.count('href="/contact"') >= 5
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
        # POLISH-LANE-A-2026-10-27: bottom nav removed by owner order —
        # the link lives in the header only; the slim footer must NOT carry it.
        assert page.text.count('href="/services"') >= 1, path
        assert 'href="/services"' not in page.text.split("<footer>", 1)[1], path


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
        'href="/contact"',
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
    # Insights (2026-10-25) is the next one after that — twelve
    # destinations: nav content now measures 1425px, natural need
    # ~1724px, and the geometry probe showed the Contact pill
    # flush against the bar's right edge (zero slack) across
    # 1721–1724px under the 1720px top edge. The band now reaches
    # 1800px (+76 over need, HIW's margin), and this pin moved
    # with it again.
    # Privacy (2026-10-25) is the next one after that — thirteen
    # destinations: measured the same way, nav content is now
    # 1512px and the natural need ~1828px (brand 261 + gap 16 +
    # nav 1512 + bar padding 38), past the 1800px top edge. The
    # band now reaches 1900px (+72 over need), and this pin moved
    # with it again.
    # Sentinel News (2026-10-26) is the next one after that —
    # fourteen destinations, promoted from the footer to its own
    # header tab by owner order: the link adds ~137px (advance
    # width at the nav's metrics, cross-checked against this
    # series' census increments), nav content ~1649px, natural
    # need ~1965px, past the 1900px top edge. The band now
    # reaches 2040px (+75 over need, in line with the earlier
    # margins), and this pin moved with it again.
    # KC Scam Alerts + Internet Weather (2026-10-27, owner
    # order) are the next additions after that — sixteen
    # destinations: the two links add ~280px at the nav's
    # metrics (estimated by this series' census increments),
    # nav content ~1929px, natural need ~2245px, past the
    # 2040px top edge. The band now reaches 2320px (+75 over
    # need, in line with the earlier margins), and this pin
    # moved with it again, exactly as designed.
    # DEFCON-RESHAPE-2026-10-27: Cyber DEFCON + Geopolitical
    # DEFCON are the next additions after that — eighteen
    # destinations: natural need ~2545px, past the 2320px top
    # edge. The band now reaches 2620px (+75 over need, in line
    # with the earlier margins), and this pin moved with it
    # again, exactly as designed.
    # BREACH-CHECK-2026-10-27: Breach Check is the next addition
    # after that — nineteen destinations: the link adds ~125px
    # at the nav's metrics, natural need ~2670px, past the
    # 2620px top edge. The band now reaches 2770px (+100 over
    # need, in line with the earlier margins), and this pin
    # moved with it again, exactly as designed.
    css = (SRC / "static" / "style.css").read_text(encoding="utf-8")
    assert "@media (max-width: 2770px) and (min-width: 861px)" in css
    assert ".mainnav a { padding: .35em .38em; }" in css
    band = css.split("@media (max-width: 2770px)")[1].split("@media")[0]
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
        # POLISH-LANE-A-2026-10-27: bottom nav removed by owner order —
        # the link lives in the header only; the slim footer must NOT carry it.
        assert page.text.count('href="/who-we-protect"') >= 1, path
        assert 'href="/who-we-protect"' not in page.text.split("<footer>", 1)[1], path


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
    assert 'href="/contact"' in body


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
        # POLISH-LANE-A-2026-10-27: bottom nav removed by owner order —
        # the link lives in the header only; the slim footer must NOT carry it.
        assert page.text.count('href="/how-it-works"') >= 1, path
        assert 'href="/how-it-works"' not in page.text.split("<footer>", 1)[1], path


def test_threat_counters_are_countup_targets(app_mod):
    resp = _client(app_mod).get("/threat-map")
    assert resp.status_code == 200
    # CSP pass 2026-10-27: page scripts are external files now; the
    # count-up behavior (incl. the data-cu counter markup the script
    # builds) is pinned where it lives.
    assert "SSG.countUp" in _client(app_mod).get("/static/js/site.js").text
    tmap = _client(app_mod).get("/static/js/threat-map.js").text
    assert "data-cu" in tmap
    assert "SSG.countUp" in tmap
    # first-load-only animation, refreshes update in place
    assert "cuFirst" in tmap


# ------------------------------------------------------------- contact
def test_contact_page_renders_direct_block_and_guidance(app_mod):
    resp = _client(app_mod).get("/contact")
    assert resp.status_code == 200
    body = _flat(resp.text)
    for fact in (
        "Contact —",
        "talk to Sentinel",
        "by appointment only",
        "no walk-ins",
        "Kansas City, Missouri",
        "816-533-8418",
        "Sentinelsafeguard@outlook.com",
        "By appointment only",
        'id="what-to-include"',
        "What to include in your message",
        "What you need protected",
        "Where it is",
        "Kansas City metro",
        "Anything already going wrong",
        'id="emergencies"',
        "Something wrong right now?",
        "open around the clock",
        'href="/report-issue"',
        'href="/services#incident-response"',
        'href="/how-it-works"',
        'href="/who-we-protect"',
        "businesses and homes",
    ):
        assert fact in body, fact
    # the form never reads as the emergency channel
    assert "This form is not the emergency channel" in body


def test_contact_form_replicates_homepage_contract(app_mod):
    # Form-contract parity with the static homepage form
    # (sentinel-live-deploy/site/index.html): same form id, same
    # field ids/names/types/limits, same Turnstile widget
    # (dark/flexible, same public sitekey), same payload keys and
    # endpoint, same success/error wording, same noscript fallback.
    body = _client(app_mod).get("/contact").text
    for snippet in (
        '<form class="contact-form" id="contact-form">',
        '<input id="cf-name" name="name" type="text" autocomplete="name" required maxlength="120">',
        '<input id="cf-email" name="email" type="email" autocomplete="email" required maxlength="160">',
        '<input id="cf-subject" name="subject" type="text" maxlength="160">',
        '<textarea id="cf-message" name="message" rows="5" required maxlength="5000"',
        'data-theme="dark" data-size="flexible" data-sitekey="0x4AAAAAAFiiv8HgOgu4CceoE"',
        'id="cf-submit"',
        'id="cf-status" role="status" aria-live="polite"',
        "This form needs JavaScript — email Sentinelsafeguard@outlook.com or call 816-533-8418 instead.",
        "https://challenges.cloudflare.com/turnstile/v0/api.js",
    ):
        assert snippet in body, snippet
    # CSP pass 2026-10-27: the submit handler is an external file;
    # its payload contract is pinned there.
    js = _client(app_mod).get("/static/js/contact.js").text
    for snippet in (
        "fetch('/api/contact'",
        "'cf-turnstile-response':tsToken()",
        "Got it — your message is in.",
        "You can also email Sentinelsafeguard@outlook.com or call 816-533-8418.",
        "That did not go through. Email Sentinelsafeguard@outlook.com or call 816-533-8418",
    ):
        assert snippet in js, snippet


def test_contact_page_carries_no_prohibited_claims(app_mod):
    # A contact page is where sites invent reply promises — this
    # one must not: no response times, no SLAs, no reply-speed
    # claims of any kind, alongside the standing prohibitions.
    body = _client(app_mod).get("/contact").text.lower()
    for banned in (
        "cyberdogs",
        "offleash",
        "trusted by",
        "testimonial",
        "our experts",
        "our team of",
        "our clients",
        "clients include",
        "satisfied clients",
        "businesses served",
        "starting at",
        "$",
        "guarantee",
        "response time",
        "respond within",
        "we reply",
        "we'll reply",
        "reply within",
        "get back to you within",
        "within 24",
        "within one business day",
        "same-day response",
        "fast response",
        "quick response",
        "sla",
        "private security guard",
        "private investigation",
    ):
        assert banned not in body, banned


def test_contact_nav_pill_active_footer_and_visitor_log(app_mod):
    client = _client(app_mod)
    resp = client.get("/contact")
    # the header pill IS the /contact link now, with active marking
    assert 'class="nav-cta active"' in resp.text
    assert 'href="/contact" aria-current="page"' in resp.text
    assert "/contact" in app_mod._VISITOR_PUBLIC_PATHS
    # no app page still points at the homepage's /#contact anchor
    for path in ("/contact", "/about", "/services", "/who-we-protect",
                 "/how-it-works", "/operations", "/threat-map",
                 "/geopolitical", "/flights"):
        page = client.get(path)
        assert page.status_code == 200
        assert 'href="/#contact"' not in page.text, path
        # pill + footer at minimum
        # POLISH-LANE-A-2026-10-27: bottom nav removed by owner order —
        # the link lives in the header only; the slim footer must NOT carry it.
        assert page.text.count('href="/contact"') >= 1, path
        assert 'href="/contact"' not in page.text.split("<footer>", 1)[1], path


# ------------------------------------------------------------ insights
_INSIGHT_SLUGS = ("what-this-weeks-breaches-teach",
                  "ten-questions-answered-honestly",
                  "spot-the-phish-six-tells",
                  "passphrases-that-actually-hold",
                  "backups-you-can-actually-restore",
                  "the-password-on-your-router", "patch-day-is-today",
                  "backups-you-have-tested")
_INSIGHT_TITLES = (
    "What this week's breaches teach a small business",
    "Ten questions, answered honestly",
    "Spot the phish: six tells worth learning",
    "Passphrases that actually hold",
    "Having backups is not the same as having a restore",
    "The password on your router is a product now",
    "Patch day is today now",
    "A backup you have never restored is a hope, not a backup",
)


def test_insights_posts_are_data_newest_first(app_mod):
    # The notebook is a publishing surface: posts load from the
    # insights/ files — the three seeds dated 2026-10-25 plus the
    # five owner-approved 2026-10-26 posts — ordered newest first
    # by date, then by the same-day weight the author set.
    posts = app_mod._load_insights()
    assert [p["slug"] for p in posts] == list(_INSIGHT_SLUGS)
    assert [p["date"] for p in posts] == (
        ["2026-10-26"] * 5 + ["2026-10-25"] * 3)
    assert [p["date_long"] for p in posts] == (
        ["October 26, 2026"] * 5 + ["October 25, 2026"] * 3)
    assert all(p["url"] == "/insights/" + p["slug"] for p in posts)


def test_insights_index_renders_dated_cards(app_mod):
    resp = _client(app_mod).get("/insights")
    assert resp.status_code == 200
    # Jinja escapes apostrophes in titles (&#39;); read them back
    # so the pins below carry the titles as written
    body = _flat(resp.text).replace("&#39;", "'")
    assert "Insights —" in body
    assert "notes from the daily watch" in body
    assert body.count("October 25, 2026") == 3
    assert body.count("October 26, 2026") == 5
    for title, slug in zip(_INSIGHT_TITLES, _INSIGHT_SLUGS):
        assert title in body, title
        assert 'href="/insights/%s"' % slug in resp.text, slug
    # newest first == the weighted seed order on the page itself
    positions = [body.index(t) for t in _INSIGHT_TITLES]
    assert positions == sorted(positions)


def test_insights_post_pages_render_from_files(app_mod):
    client = _client(app_mod)
    markers = {
        "the-password-on-your-router": (
            "What happened", "Why it matters here", "What to do",
            "70,000", "Fortinet", "Palo Alto Networks",
            "multi-factor authentication", "ten-minute version"),
        "patch-day-is-today": (
            "What happened", "Why it matters here", "What to do",
            "Known Exploited Vulnerabilities", "VeloCloud",
            "Collabora", "automatic updates", "edge first"),
        "backups-you-have-tested": (
            "What happened", "Why it matters here", "three-point check",
            "One copy the network cannot reach",
            "One restore you have actually done",
            "One calendar entry to do it again"),
        "what-this-weeks-breaches-teach": (
            "This week's reporting", "What to do",
            "Tailworm", "Gheist", "Nextcloud", "ThaiCERT", "Wiz",
            "patching is not the same as cleaning up"),
        "ten-questions-answered-honestly": (
            "What the questions are really asking",
            "What to do about a weak answer", "The front door.",
            "ten-minute version"),
        "spot-the-phish-six-tells": (
            "The practice round", "The six tells",
            "The habit that defeats most of them"),
        "passphrases-that-actually-hold": (
            "The complexity theater problem", "The math, honestly",
            "What to do", "1,306", "62 bits", "ten-minute version"),
        "backups-you-can-actually-restore": (
            "How we run our own", "The standard, in one line",
            "SHA-256 fingerprint", "The restore is a drill"),
    }
    # the 2026-10-26 batch: each post's date line and first h2
    new_batch_dates = {s: "October 26, 2026" for s in (
        "what-this-weeks-breaches-teach", "ten-questions-answered-honestly",
        "spot-the-phish-six-tells", "passphrases-that-actually-hold",
        "backups-you-can-actually-restore")}
    new_batch_h2 = {
        "what-this-weeks-breaches-teach": "This week's reporting",
        "ten-questions-answered-honestly":
            "What the questions are really asking",
        "spot-the-phish-six-tells": "The practice round",
        "passphrases-that-actually-hold": "The complexity theater problem",
        "backups-you-can-actually-restore": "How we run our own",
    }
    for slug, phrases in markers.items():
        resp = client.get("/insights/" + slug)
        assert resp.status_code == 200, slug
        # the body renderer escapes apostrophes (&#x27;); read them
        # back so the pins carry the prose as written
        body = _flat(resp.text).replace("&#x27;", "'").replace(
            "&#39;", "'")
        raw = resp.text.replace("&#x27;", "'").replace("&#39;", "'")
        assert new_batch_dates.get(slug, "October 25, 2026") in body, slug
        for phrase in phrases:
            assert phrase in body, (slug, phrase)
        # the educational line and the way back, on every post
        assert "educational notes drawn from" in body, slug
        assert "general guidance" in body, slug
        assert 'href="/insights"' in resp.text, slug
        # the body renderer emitted real structure, not raw text
        assert "<h2>%s</h2>" % new_batch_h2.get(
            slug, "What happened") in raw, slug
        assert "<strong>" in resp.text, slug


def test_insights_unknown_slug_is_plain_404(app_mod):
    client = _client(app_mod)
    resp = client.get("/insights/no-such-note")
    assert resp.status_code == 404
    # the app's plain 404 shape — the same one its APIs give
    assert resp.json() == {"detail": "Not found."}
    # and the API error behavior elsewhere is undisturbed
    assert client.get("/api/does-not-exist").status_code == 404


def test_insights_carry_no_prohibited_claims(app_mod):
    client = _client(app_mod)
    paths = ["/insights"] + ["/insights/" + s for s in _INSIGHT_SLUGS]
    for path in paths:
        body = client.get(path).text.lower()
        for banned in (
            "cyberdogs",
            "offleash",
            "trusted by",
            "testimonial",
            "our experts",
            "our team of",
            "our clients",
            "clients include",
            "satisfied clients",
            "businesses served",
            "starting at",
            "$",
            "guarantee",
            "private security guard",
            "private investigation",
            # the gated briefing is a private layer: never named
            # or linked as public content from the notebook
            "/news",
            "daily briefing",
        ):
            assert banned not in body, (path, banned)


def test_insights_nav_active_and_header_link_everywhere(app_mod):
    client = _client(app_mod)
    resp = client.get("/insights")
    assert 'href="/insights" class="active"' in resp.text
    # a post page marks Insights active too (prefix marking)
    post = client.get("/insights/patch-day-is-today")
    assert 'href="/insights" class="active"' in post.text
    assert "/insights" in app_mod._VISITOR_PUBLIC_PATHS
    # post pages are visitor-public under their own paths, and
    # gated paths are never visitor-public
    assert app_mod._visitor_is_public("/insights/patch-day-is-today")
    assert not app_mod._visitor_is_public("/admin")
    assert not app_mod._visitor_is_public("/api/news-data")
    for path in ("/about", "/services", "/who-we-protect",
                 "/how-it-works", "/contact", "/operations",
                 "/threat-map", "/geopolitical", "/flights"):
        page = client.get(path)
        assert page.status_code == 200
        # nav link + footer link on every shared-chrome page
        # POLISH-LANE-A-2026-10-27: bottom nav removed by owner order —
        # the link lives in the header only; the slim footer must NOT carry it.
        assert page.text.count('href="/insights"') >= 1, path
        assert 'href="/insights"' not in page.text.split("<footer>", 1)[1], path


# ------------------------------------------------------------ privacy
def test_privacy_page_renders_with_inventory_disclosures(app_mod):
    # Every disclosure below traces to the verified data-flow
    # inventory (PRIVACY-PAGE-2026-10-25): the page's value is
    # that these statements are TRUE, so the pins assert they are
    # PRESENT — the honest disclosures are the deliverable.
    resp = _client(app_mod).get("/privacy")
    assert resp.status_code == 200
    body = _flat(resp.text)
    for section in ('id="collects"', 'id="cookie"', 'id="never"',
                    'id="third-parties"', 'id="retention"',
                    'id="your-call"', 'id="scope"'):
        assert section in body, section
    for disclosure in (
        # the two forms, their storage, and the gate
        "When you send the contact form",
        "When you file a report",
        "network (IP) address",
        "the site’s own database",
        "gated admin side",
        # the visitor log, field by field
        "visitor log",
        "user-agent string",
        "the page that referred you",
        "country your connection appears to come from",
        "marked as bots",
        "public pages only",
        # the one cookie, named and bounded
        "exactly one cookie of its own",
        "svid",
        "HttpOnly, Secure, and",
        "SameSite=Lax",
        "thirty minutes after your last one",
        "sets no other cookies of its own",
        # the never list
        "No advertising trackers",
        "No third-party analytics",
        "no Google Analytics",
        "never sold, rented, or traded",
        "fetched by Sentinel’s server",
        # the third parties, named with their surfaces (CSP pass
        # 2026-10-27: Google Fonts and unpkg are gone — typefaces
        # and the Leaflet library are self-hosted, and the page
        # says so in the closing line)
        "Cloudflare",
        "Turnstile bot check",
        "Esri",
        "server.arcgisonline.com",
        "the typefaces, and the Leaflet map library",
        # retention, stated as it actually works
        "90 days old",
        "no automatic deletion timer",
        "until Sentinel deletes it",
        "in memory only",
        # the owner's-hand data commitment + scope + date
        "Sentinelsafeguard@outlook.com",
        "handled by the owner personally",
        "separate systems with their own sign-ins",
        'href="/how-it-works"',
        "Last updated: October 27, 2026.",
    ):
        assert disclosure in body, disclosure


def test_privacy_page_never_claims_absences_it_does_not_have(app_mod):
    # The site collects data and sets a cookie; this page must
    # never claim otherwise. "anonymous" is banned outright —
    # the log pairs an IP with the visit id, so no unqualified
    # anonymity claim is honest here. The standing prohibitions
    # ride along.
    body = _client(app_mod).get("/privacy").text.lower()
    for banned in (
        "we collect nothing",
        "collects nothing",
        "we don't collect",
        "we do not collect",
        "no data is collected",
        "no cookies",
        "cookie-free",
        "we use no cookies",
        "does not use cookies",
        "anonymous",
        "cyberdogs",
        "offleash",
        "trusted by",
        "testimonial",
        "our experts",
        "our team of",
        "our clients",
        "clients include",
        "satisfied clients",
        "businesses served",
        "starting at",
        "$",
        "guarantee",
        "private security guard",
        "private investigation",
    ):
        assert banned not in body, banned


def test_privacy_page_makes_no_newsletter_claim(app_mod):
    # Inventory verdict (PRIVACY-PAGE-2026-10-25): the newsletter
    # endpoint and table exist in the backend, but NO public page
    # or form submits to them — so the public privacy page stays
    # silent about newsletter collection rather than describing
    # a signup that does not exist.
    body = _client(app_mod).get("/privacy").text.lower()
    assert "newsletter" not in body


def test_privacy_nav_active_and_header_link_everywhere(app_mod):
    client = _client(app_mod)
    resp = client.get("/privacy")
    assert 'href="/privacy" class="active"' in resp.text
    assert "/privacy" in app_mod._VISITOR_PUBLIC_PATHS
    for path in ("/about", "/services", "/who-we-protect",
                 "/how-it-works", "/contact", "/insights",
                 "/insights/patch-day-is-today", "/operations",
                 "/threat-map", "/geopolitical", "/flights"):
        page = client.get(path)
        assert page.status_code == 200
        # nav link + footer link on every shared-chrome page
        assert page.text.count('href="/privacy"') >= 2, path
