"""Sentinel News pins (SENTINEL-NEWS-2026-10-26).

Covers the public /sentinel-news page + permalinks + RSS, fed
from data files the News Desk pushes, and the push endpoint
itself (POST /internal/news, POST /internal/news-delete):

  * only published items render — a draft's permalink is the
    same plain 404 as an unknown slug (no existence oracle);
  * newest first on the index; tag, date, summary on the card;
  * the body renders through the Insights escaping standard —
    an XSS probe in a published body renders inert;
  * the RSS feed parses, carries published items only;
  * the push gate mirrors the ticket bridge: loopback peer, no
    CF-Connecting-IP, the configured key's SHA-256 — every
    failure the same plain 404, including a malformed body
    (parsed only after the gate); an unconfigured digest means
    the endpoint is OFF;
  * upsert writes the item file atomically, a state-only push
    merges instead of wiping fields, delete removes the file.

Loads app.py from a scratch copy the same way the other suites
do. Hermetic: TestClient only.
"""
import hashlib
import importlib.util
import json
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent
KEY = "test-news-push-key"
KEY_HASH = hashlib.sha256(KEY.encode("utf-8")).hexdigest()


def _load_app(tmp: Path, name: str, config_text: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    for item in ("templates", "static", "insights"):
        shutil.copytree(SRC / item, tmp / item)
    site = tmp / "site"
    (site / "report-issue").mkdir(parents=True)
    (site / "ticket").mkdir(parents=True)
    (site / "index.html").write_text("<html>home</html>",
                                     encoding="utf-8")
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
def napp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-sentinel-news")
    return _load_app(tmp, "sl_app_sentinel_news",
                     'admin_key: "sekrit"\n'
                     'news_push_key_sha256: "%s"\n' % KEY_HASH)


@pytest.fixture(scope="module")
def napp_off(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-sentinel-news-off")
    return _load_app(tmp, "sl_app_sentinel_news_off",
                     'admin_key: "sekrit"\n')


@pytest.fixture()
def news_dir(napp, tmp_path):
    d = tmp_path / "news"
    d.mkdir()
    napp._NEWS_DIR = d
    napp._news_cache = {"key": None, "items": []}
    return d


def _client(mod):
    """Loopback peer, like uvicorn on the box (the default
    TestClient peer 'testclient' is rightly refused)."""
    return TestClient(mod.app, raise_server_exceptions=False,
                      client=("127.0.0.1", 50000))


def _write(d: Path, slug: str, **kw):
    item = {"slug": slug, "date": "2026-10-26", "tag": "Announcement",
            "title": "Title " + slug, "summary": "Summary " + slug,
            "body": "Body of " + slug, "state": "published",
            "sourceName": "", "sourceUrl": "",
            "updatedAt": "2026-10-26T12:00:00+00:00"}
    item.update(kw)
    (d / (slug + ".json")).write_text(json.dumps(item),
                                       encoding="utf-8")
    return item


# ------------------------------------------------------------ public pages
def test_index_lists_published_newest_first(napp, news_dir):
    _write(news_dir, "older-item", date="2026-10-20",
           title="Older headline")
    _write(news_dir, "newer-item", date="2026-10-26",
           title="Newer headline", tag="Patch Alert")
    _write(news_dir, "draft-item", title="Draft headline",
           state="draft")
    with _client(napp) as client:
        r = client.get("/sentinel-news")
    assert r.status_code == 200
    assert "Newer headline" in r.text
    assert "Older headline" in r.text
    assert "Draft headline" not in r.text
    assert r.text.index("Newer headline") < r.text.index(
        "Older headline")
    assert "Patch Alert" in r.text  # the tag rides the card
    assert "October 26, 2026" in r.text


def test_index_empty_state(napp, news_dir):
    with _client(napp) as client:
        r = client.get("/sentinel-news")
    assert r.status_code == 200
    assert "The first stories are on their way." in r.text


def test_permalink_renders_body_and_source(napp, news_dir):
    _write(news_dir, "a-story", body="## What happened\n\nIt happened.",
           sourceName="CISA", sourceUrl="https://www.cisa.gov/example")
    with _client(napp) as client:
        r = client.get("/sentinel-news/a-story")
    assert r.status_code == 200
    assert "<h2>What happened</h2>" in r.text
    assert "It happened." in r.text
    assert "CISA" in r.text
    assert 'href="https://www.cisa.gov/example"' in r.text


def test_draft_and_unknown_permalinks_are_the_same_404(napp, news_dir):
    _write(news_dir, "hidden-draft", state="draft")
    with _client(napp) as client:
        rd = client.get("/sentinel-news/hidden-draft")
        ru = client.get("/sentinel-news/no-such-item")
    assert rd.status_code == 404 and ru.status_code == 404
    assert rd.json() == ru.json() == {"detail": "Not found."}


def test_body_xss_renders_inert(napp, news_dir):
    _write(news_dir, "probe",
           body="<script>alert(1)</script>\n\n"
                "[click](javascript:alert(2)) and "
                "**not bold <img src=x onerror=alert(3)>**")
    with _client(napp) as client:
        r = client.get("/sentinel-news/probe")
    assert r.status_code == 200
    assert "<script>alert(1)</script>" not in r.text
    assert "&lt;script&gt;" in r.text
    # the javascript: target never becomes an href — the bracket
    # text survives only as inert visible text, exactly like the
    # Insights renderer treats it
    assert 'href="javascript:' not in r.text
    assert "<img src=x" not in r.text


def test_feed_parses_and_carries_published_only(napp, news_dir):
    _write(news_dir, "feed-item", title="Feed headline")
    _write(news_dir, "feed-draft", title="Feed draft",
           state="draft")
    with _client(napp) as client:
        r = client.get("/sentinel-news/feed.xml")
    assert r.status_code == 200
    assert "application/rss+xml" in r.headers["content-type"]
    root = ET.fromstring(r.text)
    titles = [t.text for t in root.iter("title")]
    assert "Feed headline" in titles
    assert "Feed draft" not in titles


def test_sitemap_lists_page_and_published_items(napp, news_dir):
    _write(news_dir, "map-item")
    _write(news_dir, "map-draft", state="draft")
    with _client(napp) as client:
        r = client.get("/sitemap.xml")
    assert "/sentinel-news</loc>" in r.text
    assert "/sentinel-news/map-item</loc>" in r.text
    assert "map-draft" not in r.text


# ------------------------------------------------------------ push endpoint
def _push(mod, payload, key=KEY, peer=("127.0.0.1", 50000),
          headers=None, path="/internal/news"):
    h = {}
    if key is not None:
        h["X-News-Key"] = key
    if headers:
        h.update(headers)
    client = TestClient(mod.app, raise_server_exceptions=False,
                        client=peer)
    with client:
        if isinstance(payload, (bytes, str)):
            return client.post(path, content=payload, headers=h)
        return client.post(path, json=payload, headers=h)


_ITEM = {"slug": "pushed-item", "date": "2026-10-26",
         "tag": "Threat Watch", "title": "Pushed headline",
         "summary": "Pushed summary", "body": "Pushed body.",
         "state": "published", "sourceName": "", "sourceUrl": ""}


def test_push_publishes_and_renders(napp, news_dir):
    r = _push(napp, dict(_ITEM))
    assert r.status_code == 200 and r.json()["ok"] is True
    f = news_dir / "pushed-item.json"
    assert f.is_file()
    stored = json.loads(f.read_text(encoding="utf-8"))
    assert stored["state"] == "published"
    assert stored["title"] == "Pushed headline"
    assert stored["updatedAt"]  # the server stamps the push
    with _client(napp) as client:
        page = client.get("/sentinel-news/pushed-item")
    assert page.status_code == 200
    assert "Pushed headline" in page.text
    assert "Pushed body." in page.text


def test_push_state_only_merges(napp, news_dir):
    assert _push(napp, dict(_ITEM)).status_code == 200
    r = _push(napp, {"slug": "pushed-item", "state": "draft"})
    assert r.status_code == 200
    stored = json.loads(
        (news_dir / "pushed-item.json").read_text(encoding="utf-8"))
    assert stored["state"] == "draft"
    assert stored["title"] == "Pushed headline"  # body/title kept
    with _client(napp) as client:
        assert client.get(
            "/sentinel-news/pushed-item").status_code == 404


def test_push_validation_400s(napp, news_dir):
    assert _push(napp, dict(_ITEM, tag="Bogus")).status_code == 400
    assert _push(napp, dict(_ITEM, slug="Bad Slug")).status_code == 400
    assert _push(napp, dict(_ITEM, date="10/26/2026")
                 ).status_code == 400
    assert _push(napp, dict(_ITEM, state="live")).status_code == 400
    assert _push(napp, dict(_ITEM, sourceUrl="http://x.invalid")
                 ).status_code == 400
    assert not (news_dir / "pushed-item.json").exists()


def test_push_gate_refusals_are_all_the_same_404(napp, news_dir):
    # wrong key
    r = _push(napp, dict(_ITEM), key="wrong-key")
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}
    # no key
    assert _push(napp, dict(_ITEM), key=None).status_code == 404
    # non-loopback peer
    r = _push(napp, dict(_ITEM), peer=("testclient", 50000))
    assert r.status_code == 404
    # tunnel-shaped request (CF-Connecting-IP present)
    r = _push(napp, dict(_ITEM),
              headers={"CF-Connecting-IP": "203.0.113.9"})
    assert r.status_code == 404
    # malformed body from outside the gate's trust: still 404
    # with a bad key, never a distinguishing 400.
    r = _push(napp, b"{not json", key="wrong-key")
    assert r.status_code == 404
    assert not (news_dir / "pushed-item.json").exists()


def test_push_off_when_unconfigured(napp_off, tmp_path):
    napp_off._NEWS_DIR = tmp_path / "news"
    napp_off._news_cache = {"key": None, "items": []}
    client = TestClient(napp_off.app, raise_server_exceptions=False,
                        client=("127.0.0.1", 50000))
    with client:
        r = client.post("/internal/news", json=dict(_ITEM),
                        headers={"X-News-Key": KEY})
    assert r.status_code == 404


def test_delete_removes_the_item(napp, news_dir):
    assert _push(napp, dict(_ITEM)).status_code == 200
    r = _push(napp, {"slug": "pushed-item"}, path="/internal/news-delete")
    assert r.status_code == 200
    assert r.json() == {"ok": True, "slug": "pushed-item",
                        "deleted": True}
    assert not (news_dir / "pushed-item.json").exists()
    # deleting again is a successful no-op
    r = _push(napp, {"slug": "pushed-item"}, path="/internal/news-delete")
    assert r.status_code == 200 and r.json()["deleted"] is False
    # and the delete endpoint carries the same gate
    r = _push(napp, {"slug": "pushed-item"}, key="nope",
              path="/internal/news-delete")
    assert r.status_code == 404
