"""Nav consistency guard (2026-10-25) — EVERY public surface carries
the same navigation, pinned once, everywhere.

Why this file exists: the site's pages live behind two different
chromes. The app pages share templates/base.html; the static front
door (site/index.html — the homepage) and the static pair
(site/report-issue + site/ticket) each carry their OWN header/footer
markup. Every 2026-10-25 page build wired only the shared chrome, so
the front door silently fell five pages behind — the owner found the
new pages missing from the homepage nav by eye. These pins define
the canonical destination set ONCE and assert it, in order, on every
surface's header nav and footer: the base template, the three static
files as committed, and every page as rendered. Adding a page now
fails this file on every surface until all of them are updated —
which is the point.

The static site/ tree is committed in the repo (it was box-only
before this fix) so the bytes the suite pins are the bytes that ship:
repo first, then server, like everything else.
"""
import importlib.util
import re
import shutil
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent
LIBRARY = "https://command.sentinelsafeguard.net/library"

# The canonical destination set, in order — mirrored from the shared
# chrome (templates/base.html is asserted against this below, so the
# reference and the pin cannot drift apart silently).
CANONICAL_NAV = [
    ("/", "Home"),
    ("/about", "About"),
    ("/services", "Services"),
    ("/who-we-protect", "Who We Protect"),
    ("/how-it-works", "How It Works"),
    ("/insights", "Insights"),
    ("/privacy", "Privacy"),
    ("/operations", "Operations"),
    ("/threat-map", "Threat Map"),
    ("/geopolitical", "Geopolitical"),
    ("/flights", "Flights"),
    (LIBRARY, "Library"),
    ("/report-issue", "Report an Issue"),
    ("/contact", "Contact"),
]

CANONICAL_FOOTER = [
    ("/about", "About"),
    ("/services", "Services"),
    ("/who-we-protect", "Who We Protect"),
    ("/how-it-works", "How It Works"),
    ("/insights", "Insights"),
    ("/privacy", "Privacy"),
    ("/operations", "Operations"),
    (LIBRARY, "Library"),
    ("/report-issue", "Report an Issue"),
    ("/contact", "Contact"),
]


class _Anchors(HTMLParser):
    """Collect (href, label) pairs from an HTML fragment, in order."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            label = " ".join("".join(self._text).split())
            self.anchors.append((self._href, label))
            self._href = None


def _region(html: str, start_pat: str) -> str:
    m = re.search(start_pat, html)
    assert m, f"region not found: {start_pat}"
    end = html.index("</nav>", m.start())
    return html[m.start():end]


def _parse(fragment: str):
    p = _Anchors()
    p.feed(fragment)
    return p.anchors


def nav_of(html: str, chrome: str):
    """The header destination sequence of a rendered page or file.

    chrome="mainnav": anchors of the shared <nav class="mainnav">.
    chrome="site-nav": the static chrome's <ul> anchors in order,
    with the Contact pill (a.nav-cta, outside the <ul>) appended —
    the static brand anchor is chrome, not a destination.
    """
    region = _region(html, r'<nav class="(?:mainnav|site-nav)"')
    if chrome == "mainnav":
        return _parse(region)
    ul = region[region.index("<ul>"):region.index("</ul>")]
    pill = re.search(r'<a class="nav-cta" href="([^"]+)">([^<]+)</a>', region)
    assert pill, "static chrome carries a Contact pill"
    return _parse(ul) + [(pill.group(1), pill.group(2))]


def footer_of(html: str):
    return _parse(_region(html, r'<nav class="foot-links"'))


# ------------------------------------------------------- source bytes
def test_base_template_matches_canonical():
    html = (SRC / "templates" / "base.html").read_text(encoding="utf-8")
    assert nav_of(html, "mainnav") == CANONICAL_NAV
    assert footer_of(html) == CANONICAL_FOOTER


@pytest.mark.parametrize("rel", ["site/index.html",
                                 "site/report-issue/index.html",
                                 "site/ticket/index.html"])
def test_static_files_match_canonical(rel):
    html = (SRC / rel).read_text(encoding="utf-8")
    assert nav_of(html, "site-nav") == CANONICAL_NAV
    assert footer_of(html) == CANONICAL_FOOTER


def test_static_pair_stays_byte_identical():
    a = (SRC / "site" / "report-issue" / "index.html").read_bytes()
    b = (SRC / "site" / "ticket" / "index.html").read_bytes()
    assert a == b


# ---------------------------------------------------- rendered pages
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
    tmp = tmp_path_factory.mktemp("sl-navconsistency")
    return _load_app(tmp, "sl_app_navconsistency")


APP_PAGES = ["/operations", "/threat-map", "/geopolitical", "/flights",
             "/about", "/services", "/who-we-protect", "/how-it-works",
             "/insights", "/insights/patch-day-is-today", "/contact",
             "/privacy"]
STATIC_PAGES = ["/", "/index.html", "/report-issue", "/ticket"]


@pytest.mark.parametrize("path", APP_PAGES)
def test_rendered_app_pages_carry_canonical_chrome(app_mod, path):
    resp = TestClient(app_mod.app,
                      raise_server_exceptions=False).get(path)
    assert resp.status_code == 200, path
    assert nav_of(resp.text, "mainnav") == CANONICAL_NAV, path
    assert footer_of(resp.text) == CANONICAL_FOOTER, path


@pytest.mark.parametrize("path", STATIC_PAGES)
def test_rendered_static_pages_carry_canonical_chrome(app_mod, path):
    resp = TestClient(app_mod.app,
                      raise_server_exceptions=False).get(path)
    assert resp.status_code == 200, path
    assert nav_of(resp.text, "site-nav") == CANONICAL_NAV, path
    assert footer_of(resp.text) == CANONICAL_FOOTER, path


def test_homepage_keeps_its_contact_form(app_mod):
    # The Contact pill now routes to /contact like everywhere else;
    # the homepage's own form section stays (the fix brief forbids
    # removing it).
    resp = TestClient(app_mod.app, raise_server_exceptions=False).get("/")
    assert resp.status_code == 200
    assert 'id="contact"' in resp.text
    assert 'id="contact-form"' in resp.text


@pytest.mark.parametrize("path", ["/report-issue", "/ticket"])
def test_ticket_pages_keep_their_form(app_mod, path):
    resp = TestClient(app_mod.app,
                      raise_server_exceptions=False).get(path)
    assert resp.status_code == 200
    assert 'id="ticket-form"' in resp.text
