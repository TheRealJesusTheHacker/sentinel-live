"""Conversion layer pins (CONVERSION-2026-10-26).

Two deliverables, pinned to their real rendering:

  * The standard reader-to-booking CTA block
    (templates/_reader_cta.html) renders at the TEMPLATE level
    on every Sentinel News permalink and every Insights post —
    current and future items alike, because it lives in the two
    article templates, never in stored item bodies. It must NOT
    appear on index/listing pages, in either RSS feed, or on
    unrelated pages.
  * Three Kansas City service landing pages under /services/,
    linked from /services, carried in the sitemap, each with a
    unique title and meta description, internal links to
    /assessment and /contact, and the same CTA treatment.

Copy discipline (the owner's standing rules) is pinned on the
new surfaces: no prices, no invented claims, Kansas City /
KC metro only — "Liberty" never appears.
"""
import asyncio
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent

KC_PAGES = [
    ("/services/cybersecurity-kansas-city",
     "Cybersecurity for Kansas City Small Businesses"),
    ("/services/it-support-kansas-city",
     "IT Support in the Kansas City Metro"),
    ("/services/network-security-installs-kansas-city",
     "Network &amp; Security Installs in the Kansas City Metro"),
]

BANNED_COPY = (
    "liberty", "cyberdogs", "trusted by", "testimonial",
    "our clients", "satisfied clients", "businesses served",
    "starting at", "$", "guarantee", "response time",
    "respond within", "within 24", "same-day response",
)


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
    tmp = tmp_path_factory.mktemp("sl-conversion")
    mod = _load_app(tmp, "sl_app_conversion")
    asyncio.run(mod.init_db())
    return mod


@pytest.fixture()
def news_dir(app_mod, tmp_path):
    d = tmp_path / "news"
    d.mkdir()
    app_mod._NEWS_DIR = d
    app_mod._news_cache = {"key": None, "items": []}
    return d


def _client(app_mod):
    return TestClient(app_mod.app, raise_server_exceptions=False)


def _write_news(d: Path, slug: str, **kw):
    item = {"slug": slug, "date": "2026-10-26", "tag": "Threat Watch",
            "title": "Title " + slug, "summary": "Summary " + slug,
            "body": "Body of " + slug, "state": "published",
            "sourceName": "BleepingComputer",
            "sourceUrl": "https://example.com/story",
            "updatedAt": "2026-10-26T12:00:00+00:00"}
    item.update(kw)
    (d / (slug + ".json")).write_text(json.dumps(item),
                                      encoding="utf-8")
    return item


# ------------------------------------------------------------ the CTA block

def test_insights_post_carries_reader_cta(app_mod):
    body = _client(app_mod).get("/insights/patch-day-is-today").text
    assert body.count('class="reader-cta"') == 1
    assert "Worried something like this could hit your business?" in body
    assert 'href="/assessment"' in body
    assert 'href="/contact"' in body
    # the block closes the article: after the rendered body
    assert body.index('class="reader-cta"') > body.index('class="ins-body"')


def test_news_permalink_carries_reader_cta(app_mod, news_dir):
    _write_news(news_dir, "cta-item")
    body = _client(app_mod).get("/sentinel-news/cta-item").text
    assert body.count('class="reader-cta"') == 1
    assert "Worried something like this could hit your business?" in body
    assert 'href="/assessment"' in body
    assert 'href="/contact"' in body
    assert body.index('class="reader-cta"') > body.index('class="ins-body"')


def test_cta_absent_from_listings_feeds_and_unrelated(app_mod, news_dir):
    _write_news(news_dir, "cta-item-two")
    client = _client(app_mod)
    for path in ("/insights", "/sentinel-news", "/insights/feed.xml",
                 "/sentinel-news/feed.xml", "/about", "/faq",
                 "/operations"):
        resp = client.get(path)
        assert resp.status_code == 200, path
        assert "reader-cta" not in resp.text, path
        assert "Worried something like this" not in resp.text, path


def test_cta_lives_in_templates_not_stored_bodies():
    # Template-level by construction: the two article templates
    # include the partial; no stored Insights body carries it, so
    # automation-filed news (data, never edited) gets it too.
    for tpl in ("insight_post.html", "sentinel_news_item.html"):
        text = (SRC / "templates" / tpl).read_text(encoding="utf-8")
        assert '{% include "_reader_cta.html" %}' in text, tpl
    for md in (SRC / "insights").glob("*.md"):
        assert "reader-cta" not in md.read_text(encoding="utf-8"), md


# ------------------------------------------------------- KC landing pages

@pytest.mark.parametrize("path,title", KC_PAGES)
def test_kc_page_renders_with_cta(app_mod, path, title):
    resp = _client(app_mod).get(path)
    assert resp.status_code == 200, path
    body = resp.text
    assert ("<title>%s — Sentinel Safeguard LLC</title>" % title) in body
    assert 'property="og:title"' in body
    # the same title rides the OG tag (its raw form carries the
    # escaped ampersand, exactly as the source templates write it)
    assert body.count(title) >= 2
    assert "Kansas City" in body
    assert "by appointment only" in body.lower()
    # conversion treatment: the shared block + both destinations
    assert body.count('class="reader-cta"') == 1, path
    assert 'href="/assessment"' in body
    assert 'href="/contact"' in body
    # rendered chrome carries no banned copy and no prices
    assert "Liberty" not in body, path
    assert "$" not in body, path


def test_kc_pages_have_unique_titles_and_descriptions(app_mod):
    client = _client(app_mod)
    titles, descs = [], []
    for path, _ in KC_PAGES:
        body = client.get(path).text
        titles.append(re.search(r"<title>(.*?)</title>", body).group(1))
        descs.append(re.search(
            r'<meta name="description" content="(.*?)"', body).group(1))
    assert len(set(titles)) == len(KC_PAGES)
    assert len(set(descs)) == len(KC_PAGES)
    # none of them falls back to the shared default description
    assert all("live operations" not in d for d in descs)


def test_kc_pages_linked_from_services(app_mod):
    body = _client(app_mod).get("/services").text
    for path, _ in KC_PAGES:
        assert ('href="%s"' % path) in body, path


def test_kc_pages_in_sitemap_and_visitor_paths(app_mod):
    body = _client(app_mod).get("/sitemap.xml").text
    for path, _ in KC_PAGES:
        assert ("https://sentinelsafeguard.net" + path) in body, path
        assert path in app_mod._SITEMAP_PATHS, path
        assert path in app_mod._VISITOR_PUBLIC_PATHS, path


def test_new_copy_carries_no_banned_claims():
    files = ["_reader_cta.html", "kc_cybersecurity.html",
             "kc_it_support.html", "kc_network_installs.html"]
    for name in files:
        text = (SRC / "templates" / name).read_text(
            encoding="utf-8").lower()
        for banned in BANNED_COPY:
            assert banned not in text, (name, banned)


def test_main_nav_unchanged_by_conversion_layer(app_mod):
    # The 15-link canonical nav is pinned in full by
    # test_nav_consistency; here the conversion surfaces simply
    # may not add a nav link of their own.
    body = _client(app_mod).get(KC_PAGES[0][0]).text
    nav = re.search(r'<nav class="mainnav".*?</nav>', body, re.S).group(0)
    for path, _ in KC_PAGES:
        assert ('href="%s"' % path) not in nav, path
