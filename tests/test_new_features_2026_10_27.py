"""New features pins (2026-10-27, owner order).

Covers the three features built 2026-10-27:

  * Internet Weather (/internet-weather + /api/internet-weather):
    the pure IODA/RIPEstat parser, the fetcher's honest failure
    states, and the page/API surface.
  * Sentinel Threat Level: the pure scoring formula at every
    band edge, the compute + persistence flow (snapshot write,
    same-day replace, 30-day history trim, KEV-down keeps the
    previous level), the /api/threat-level pending + populated
    shapes, and the site-wide badge band.
  * KC Scam Alerts: the scope field on news items (parse + push
    validation), the KC/Threat Watch filter, the page (populated
    and empty states), and the RSS feed.

Loads app.py from a scratch copy the same way the other suites
do. Hermetic: TestClient only, all network seams monkeypatched.
"""
import asyncio
import hashlib
import importlib.util
import json
import shutil
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent
KEY = "test-news-push-key"
KEY_HASH = hashlib.sha256(KEY.encode("utf-8")).hexdigest()


def _load_app(tmp: Path, name: str, config_text: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    for item in ("templates", "static", "insights", "site"):
        shutil.copytree(SRC / item, tmp / item)
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
    tmp = tmp_path_factory.mktemp("sl-new-features")
    return _load_app(tmp, "sl_app_new_features",
                     'admin_key: "sekrit"\n'
                     'news_push_key_sha256: "%s"\n' % KEY_HASH)


def _client(mod):
    return TestClient(mod.app, raise_server_exceptions=False)


@pytest.fixture()
def news_dir(app_mod, tmp_path, monkeypatch):
    d = tmp_path / "news"
    d.mkdir()
    monkeypatch.setattr(app_mod, "_NEWS_DIR", d)
    monkeypatch.setattr(app_mod, "_news_cache",
                        {"key": None, "items": []})
    return d


def _write(d: Path, slug: str, **kw):
    item = {"slug": slug, "date": "2026-10-26", "tag": "Threat Watch",
            "title": "Title " + slug, "summary": "Summary " + slug,
            "body": "Body of " + slug, "state": "published",
            "sourceName": "", "sourceUrl": "",
            "updatedAt": "2026-10-26T12:00:00+00:00"}
    item.update(kw)
    (d / (slug + ".json")).write_text(json.dumps(item),
                                      encoding="utf-8")
    return item


# ------------------------------------------------------- internet weather
_SUMMARY = {"data": [
    {"entity": {"code": "SS", "name": "South Sudan"}, "event_cnt": 5,
     "scores": {"overall": 999, "bgp": {"median": 1.0},
                "ping-slash24": {"median": 2.0},
                "gtr": {"sarima": 3.0}}},
    {"entity": {"code": "US", "name": "United States"},
     "event_cnt": 2,
     "scores": {"overall": 9, "bgp.median": 1.0}},
    {"entity": {"code": "ZZ", "name": "Nowhere Land"}, "event_cnt": 0,
     "scores": {"overall": 0}},
]}
_ALERTS = {"data": [
    {"datasource": "bgp", "entity": {"code": "US", "name": "United States"},
     "time": 1700000000, "level": "normal", "condition": "con"},
    {"datasource": "ping", "entity": {"code": "SS", "name": "South Sudan"},
     "time": 1700003600, "level": "critical", "condition": "drop"},
    {"datasource": "gtr", "entity": {"code": "SS", "name": "South Sudan"},
     "time": 1700007200, "level": "warning", "condition": "drop"},
]}


def test_weather_parse_totals_countries_events(app_mod):
    feeds = app_mod.feeds
    core = feeds._weather_parse(
        _SUMMARY, _ALERTS,
        {"SS": {"v4_prefixes_ris": 123, "v6_prefixes_ris": 45}})
    assert core["totals"] == {"countries_affected": 3,
                              "outage_events": 7, "alerts_24h": 3}
    ss, us, zz = core["countries"]
    # SS is one of the 2026-10-27 COUNTRY_COORDS additions.
    assert ss["lat"] is not None and ss["lon"] is not None
    assert ss["signals"] == ["bgp", "ping", "gtr"]
    assert ss["score"] == 999
    # intensity: 100*log10(1000)/log10(1000); US: log10(10)/log10(1000)
    assert ss["intensity"] == 100
    assert us["intensity"] == 33
    assert us["signals"] == ["bgp"]  # flat dotted key shape
    assert ss["ripe_v4"] == 123 and ss["ripe_v6"] == 45
    assert us["ripe_v4"] is None
    # a country without coordinates stays listed, lat/lon null
    assert zz["lat"] is None and zz["lon"] is None
    assert zz["intensity"] == 0
    # non-normal alerts first (newest-first within each group),
    # then the remaining normal alerts, capped at 12
    assert [e["level"] for e in core["events"]] == [
        "critical", "warning", "normal"]
    assert core["events"][0]["ts"].startswith("2023-11-14T")
    assert core["events"][0]["code"] == "SS"


def test_weather_parse_empty_and_max_zero(app_mod):
    core = app_mod.feeds._weather_parse({"data": []}, {"data": []}, {})
    assert core["countries"] == [] and core["events"] == []
    assert core["totals"]["countries_affected"] == 0
    core = app_mod.feeds._weather_parse(
        {"data": [{"entity": {"code": "US", "name": "United States"},
                   "event_cnt": 1, "scores": {"overall": 0}}]},
        {"data": []}, {})
    assert core["countries"][0]["intensity"] == 0  # max is 0


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def test_weather_fetch_ok_with_ripe_enrichment(app_mod, monkeypatch):
    feeds = app_mod.feeds
    # The REAL RIPEstat shape (verified live 2026-10-27): counts
    # ride the stats entry; timeline points carry only times.
    ripe_payload = {"data": {"stats": [{"timeline": [
        {"starttime": "2026-10-20T00:00:00",
         "endtime": "2026-10-20T00:00:00"},
        {"starttime": "2026-10-27T00:00:00",
         "endtime": "2026-10-27T00:00:00"}],
        "v4_prefixes_ris": 123, "v6_prefixes_ris": 45}]}}

    async def fake_get(client, url, timeout, **kw):
        if "summary" in url:
            return _FakeResp(_SUMMARY)
        if "alerts" in url:
            return _FakeResp(_ALERTS)
        if "stat.ripe.net" in url:
            return _FakeResp(ripe_payload)
        raise AssertionError(url)

    monkeypatch.setattr(feeds, "_get", fake_get)
    out = asyncio.run(feeds.fetch_internet_weather(5))
    assert out["status"] == "ok"
    assert out["sources"] == {"ioda": "ok", "ripestat": "ok"}
    assert out["window_hours"] == 24
    ss = [c for c in out["countries"] if c["code"] == "SS"][0]
    assert ss["ripe_v4"] == 123 and ss["ripe_v6"] == 45


def test_weather_fetch_ioda_down_is_honest_error(app_mod, monkeypatch):
    feeds = app_mod.feeds

    async def dead_get(client, url, timeout, **kw):
        raise ConnectionError("nope")

    monkeypatch.setattr(feeds, "_get", dead_get)
    out = asyncio.run(feeds.fetch_internet_weather(5))
    assert out["status"] == "error"
    assert out["sources"]["ioda"] == "error"
    assert out["countries"] == [] and out["events"] == []
    assert "ConnectionError" in out["error"]


def test_internet_weather_page_and_api(app_mod, monkeypatch):
    fake = {"updated": "2026-10-27T12:00:00+00:00", "status": "ok",
            "window_hours": 24,
            "sources": {"ioda": "ok", "ripestat": "ok"},
            "totals": {"countries_affected": 2, "outage_events": 7,
                       "alerts_24h": 3},
            "countries": [], "events": [], "error": None}
    monkeypatch.setitem(app_mod.store, "weather", fake)
    client = _client(app_mod)
    page = client.get("/internet-weather")
    assert page.status_code == 200
    for marker in ("Internet Weather", "IODA", "Georgia Tech",
                   "RIPEstat", 'id="map"', 'id="counters"',
                   'id="wx-countries"', 'id="wx-events"',
                   "Most affected countries", "Notable events",
                   "/static/js/internet-weather.js"):
        assert marker in page.text, marker
    api = client.get("/api/internet-weather")
    assert api.status_code == 200
    assert api.json() == fake
    assert api.headers.get("cache-control") == "no-store"


# ------------------------------------------------------------------- kev
def test_kev_parse_windows(app_mod):
    from datetime import date
    payload = {"vulnerabilities": [
        {"dateAdded": "2026-10-27"},   # today
        {"dateAdded": "2026-10-21"},   # today-6: in window
        {"dateAdded": "2026-10-20"},   # today-7: out
        {"dateAdded": "2026-09-01"},   # out
        {"dateAdded": "not-a-date"},   # skipped, still counted total
    ]}
    out = app_mod.feeds._kev_parse(payload, today=date(2026, 10, 27))
    assert out == {"total": 5, "added_7d": 2, "added_today": 1,
                   "added_dates": ["2026-10-21", "2026-10-27"]}


# ------------------------------------------------------------ threat level
@pytest.mark.parametrize("kev7,tw7,pa7,sources,parts_exp,score_exp", [
    (0, 0, 0, 0, (0, 0, 0), 0),
    (3, 0, 0, 0, (0, 0, 0), 0),          # kev band edge: 3 -> 0
    (4, 0, 0, 0, (1, 0, 0), 1),          # 4 -> 1
    (9, 0, 0, 0, (1, 0, 0), 1),          # 9 -> 1
    (10, 0, 0, 0, (2, 0, 0), 2),         # 10 -> 2
    (17, 0, 0, 0, (2, 0, 0), 2),         # 17 -> 2
    (18, 0, 0, 0, (3, 0, 0), 3),         # 18 -> 3
    (0, 24, 0, 0, (0, 0, 0), 0),         # news edge: 24 -> 0
    (0, 20, 5, 0, (0, 1, 0), 1),         # 25 combined -> 1
    (0, 44, 0, 0, (0, 1, 0), 1),         # 44 -> 1
    (0, 45, 0, 0, (0, 2, 0), 2),         # 45 -> 2
    (0, 0, 0, 179999, (0, 0, 0), 0),     # feed edge
    (0, 0, 0, 180000, (0, 0, 1), 1),
    (0, 0, 0, 259999, (0, 0, 1), 1),
    (0, 0, 0, 260000, (0, 0, 2), 2),
    (18, 45, 0, 260000, (3, 2, 2), 7),   # the maximum
])
def test_threat_level_score_bands(app_mod, kev7, tw7, pa7, sources,
                                  parts_exp, score_exp):
    score, parts = app_mod._threat_level_score(kev7, tw7, pa7, sources)
    assert score == score_exp
    assert (parts["kev_points"], parts["news_points"],
            parts["feed_points"]) == parts_exp


@pytest.mark.parametrize("score,level,name", [
    (0, 1, "ROUTINE"), (1, 1, "ROUTINE"), (2, 2, "GUARDED"),
    (3, 2, "GUARDED"), (4, 3, "ELEVATED"), (5, 3, "ELEVATED"),
    (6, 4, "HIGH"), (7, 5, "SEVERE"),
])
def test_threat_level_mapping(app_mod, score, level, name):
    assert app_mod._threat_level_for_score(score) == level
    assert app_mod._THREAT_LEVEL_NAMES[level] == name


def _seed_compute(app_mod, monkeypatch, tmp_path, kev7=20,
                  sources=300000):
    monkeypatch.setattr(app_mod, "DATA_DIR", tmp_path / "data")
    monkeypatch.setitem(app_mod.store, "kev", {
        "updated": "2026-10-27T00:00:00+00:00", "status": "ok",
        "total": 100, "added_7d": kev7, "added_today": 1,
        "added_dates": []})
    threat = dict(app_mod.store["threat"])
    threat["sources_today"] = sources
    monkeypatch.setitem(app_mod.store, "threat", threat)
    monkeypatch.setitem(app_mod.store, "threat_level", None)


def test_compute_writes_snapshot_and_api(app_mod, news_dir,
                                         monkeypatch, tmp_path):
    _seed_compute(app_mod, monkeypatch, tmp_path)
    today = app_mod._chicago_today()
    _write(news_dir, "today-tw", date=today.isoformat(),
           tag="Threat Watch")
    _write(news_dir, "today-pa", date=today.isoformat(),
           tag="Patch Alert")
    _write(news_dir, "old-tw", date="2020-01-01", tag="Threat Watch")
    current = app_mod._compute_threat_level()
    # kev 20 -> 3, news 2 -> 0, sources 300000 -> 2  ==  5 -> ELEVATED
    assert current["score"] == 5
    assert current["level"] == 3 and current["name"] == "ELEVATED"
    assert current["inputs"] == {
        "kev_added_7d": 20, "news_threat_watch_7d": 1,
        "news_patch_alert_7d": 1, "dshield_sources_today": 300000}
    assert app_mod.store["threat_level"] == current
    path = tmp_path / "data" / "threat_level.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert saved["current"] == current
    assert [h["date"] for h in saved["history"]] == [today.isoformat()]
    api = _client(app_mod).get("/api/threat-level")
    assert api.status_code == 200
    body = api.json()
    assert body["level"] == 3 and body["pending"] is False
    assert body["history"] == saved["history"]
    assert api.headers.get("cache-control") == "no-store"


def test_compute_same_day_replaces_snapshot(app_mod, news_dir,
                                            monkeypatch, tmp_path):
    _seed_compute(app_mod, monkeypatch, tmp_path)
    first = app_mod._compute_threat_level()
    assert first["level"] == 3
    _seed_compute(app_mod, monkeypatch, tmp_path, kev7=0, sources=0)
    # _seed_compute reset threat_level to None; restore the level
    # as the previous current while KEV stays ok with new inputs.
    second = app_mod._compute_threat_level()
    assert second["level"] == 1 and second["score"] == 0
    saved = json.loads(
        (tmp_path / "data" / "threat_level.json").read_text(
            encoding="utf-8"))
    assert len(saved["history"]) == 1  # replaced, not appended
    assert saved["history"][0]["level"] == 1


def test_compute_history_trims_to_30_days(app_mod, news_dir,
                                          monkeypatch, tmp_path):
    _seed_compute(app_mod, monkeypatch, tmp_path)
    today = app_mod._chicago_today()
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)
    history = [{"date": (today - timedelta(days=i)).isoformat(),
                "level": 1, "score": 0, "inputs": {}}
               for i in range(1, 41)]
    (data_dir / "threat_level.json").write_text(
        json.dumps({"current": None, "history": history}),
        encoding="utf-8")
    app_mod._compute_threat_level()
    saved = json.loads(
        (data_dir / "threat_level.json").read_text(encoding="utf-8"))
    assert len(saved["history"]) == 30
    assert saved["history"][-1]["date"] == today.isoformat()
    assert saved["history"][0]["date"] == (
        today - timedelta(days=29)).isoformat()


def test_compute_kev_down_keeps_previous(app_mod, monkeypatch,
                                         tmp_path):
    _seed_compute(app_mod, monkeypatch, tmp_path)
    previous = app_mod._compute_threat_level()
    assert previous is not None
    kev = dict(app_mod.store["kev"])
    kev["status"] = "error"
    monkeypatch.setitem(app_mod.store, "kev", kev)
    assert app_mod._compute_threat_level() == previous


def test_compute_kev_down_no_previous_is_none(app_mod, monkeypatch,
                                              tmp_path):
    monkeypatch.setattr(app_mod, "DATA_DIR", tmp_path / "empty")
    monkeypatch.setitem(app_mod.store, "kev", {
        "updated": None, "status": "starting", "total": 0,
        "added_7d": 0, "added_today": 0, "added_dates": []})
    monkeypatch.setitem(app_mod.store, "threat_level", None)
    assert app_mod._compute_threat_level() is None


def test_api_threat_level_pending(app_mod, monkeypatch, tmp_path):
    monkeypatch.setattr(app_mod, "DATA_DIR", tmp_path / "empty")
    monkeypatch.setitem(app_mod.store, "threat_level", None)
    r = _client(app_mod).get("/api/threat-level")
    assert r.status_code == 200
    body = r.json()
    assert body["level"] is None and body["pending"] is True


def test_badge_band_and_panel_render(app_mod, monkeypatch, tmp_path):
    monkeypatch.setattr(app_mod, "DATA_DIR", tmp_path / "empty")
    monkeypatch.setitem(app_mod.store, "threat_level", None)
    client = _client(app_mod)
    about = client.get("/about")
    assert about.status_code == 200
    assert 'id="tl-band"' in about.text
    assert "Sentinel Threat Level" in about.text
    assert "being computed" in about.text
    assert "/static/js/threat-level.js" in about.text
    ops = client.get("/operations")
    assert ops.status_code == 200
    assert 'id="threat-level"' in ops.text
    assert 'id="tl-panel-level"' in ops.text
    assert 'id="tl-inputs"' in ops.text
    assert 'id="tl-history"' in ops.text
    assert "no hand-tuning" in ops.text


def test_badge_band_in_static_homepage_bytes():
    home = (SRC / "site" / "index.html").read_text(encoding="utf-8")
    assert 'id="tl-band"' in home
    assert "Sentinel Threat Level" in home
    assert "/static/js/threat-level.js" in home
    assert 'id="threat-level"' in home  # the homepage panel
    assert 'id="tl-panel-level"' in home
    for rel in ("site/report-issue/index.html", "site/ticket/index.html"):
        text = (SRC / rel).read_text(encoding="utf-8")
        assert 'id="tl-band"' in text, rel
        assert "/static/js/threat-level.js" in text, rel


# ------------------------------------------------------------ kc scam alerts
def test_kc_filter_exact(app_mod, news_dir):
    _write(news_dir, "kc-alert", scope="Kansas City",
           title="KC alert headline")
    _write(news_dir, "kc-patch", scope="Kansas City",
           tag="Patch Alert", title="KC patch headline")
    _write(news_dir, "nat-alert", scope="National",
           title="National headline")
    _write(news_dir, "world-alert", scope="World",
           title="World headline")
    _write(news_dir, "kc-draft", scope="Kansas City", state="draft",
           title="KC draft headline")
    _write(news_dir, "no-scope", title="Scopeless headline")
    got = app_mod._kc_scam_alerts()
    assert [i["slug"] for i in got] == ["kc-alert"]
    assert got[0]["scope"] == "Kansas City"


def test_kc_page_populated_and_feed(app_mod, news_dir):
    _write(news_dir, "kc-alert", scope="Kansas City",
           title="Gift card drain going around",
           sourceName="Example PD")
    client = _client(app_mod)
    page = client.get("/kc-scam-alerts")
    assert page.status_code == 200
    assert "KC Scam Alerts" in page.text
    assert "Gift card drain going around" in page.text
    assert "Threat Watch" in page.text
    assert "Source: Example PD" in page.text
    assert 'href="/sentinel-news/kc-alert"' in page.text
    assert 'href="/kc-scam-alerts/feed.xml"' in page.text
    assert "Liberty" not in page.text
    feed = client.get("/kc-scam-alerts/feed.xml")
    assert feed.status_code == 200
    assert "Sentinel Safeguard \u2014 KC Scam Alerts" in feed.text
    assert "Gift card drain going around" in feed.text


def test_kc_page_empty_state(app_mod, news_dir):
    page = _client(app_mod).get("/kc-scam-alerts")
    assert page.status_code == 200
    assert "No active alerts posted right now" in page.text
    assert "quiet is good news" in " ".join(page.text.split())
    # the reader CTA still renders in the empty state
    assert "Worried something like this could hit your business?" \
        in page.text
    assert "Liberty" not in page.text


def test_sentinel_news_page_links_kc(app_mod, news_dir):
    page = _client(app_mod).get("/sentinel-news")
    assert page.status_code == 200
    assert 'href="/kc-scam-alerts"' in page.text
    assert "Kansas City scam alerts have their" in page.text


# ------------------------------------------------------------ push scope
def _push(mod, payload):
    client = TestClient(mod.app, raise_server_exceptions=False,
                        client=("127.0.0.1", 50000))
    return client.post("/internal/news", json=payload,
                       headers={"X-News-Key": KEY})


_ITEM = {"slug": "scoped-item", "date": "2026-10-26",
         "tag": "Threat Watch", "title": "Scoped headline",
         "summary": "Scoped summary", "body": "Scoped body.",
         "state": "published", "sourceName": "", "sourceUrl": ""}


def test_push_accepts_valid_scope(app_mod, news_dir):
    r = _push(app_mod, dict(_ITEM, scope="Kansas City"))
    assert r.status_code == 200
    stored = json.loads(
        (news_dir / "scoped-item.json").read_text(encoding="utf-8"))
    assert stored["scope"] == "Kansas City"
    # and the item now flows to the KC page
    assert [i["slug"] for i in app_mod._kc_scam_alerts()] == [
        "scoped-item"]


def test_push_rejects_bogus_scope(app_mod, news_dir):
    r = _push(app_mod, dict(_ITEM, scope="Missouri"))
    assert r.status_code == 400
    assert not (news_dir / "scoped-item.json").exists()
    r = _push(app_mod, dict(_ITEM, scope="kansas city"))
    assert r.status_code == 400


def test_news_parse_item_carries_scope(app_mod):
    item = app_mod._news_parse_item({
        "slug": "x-item", "date": "2026-10-26", "tag": "Threat Watch",
        "title": "T", "summary": "S", "body": "B",
        "state": "published", "scope": " National "})
    assert item["scope"] == "National"
    item = app_mod._news_parse_item({
        "slug": "x-item", "date": "2026-10-26", "tag": "Threat Watch",
        "title": "T", "summary": "S", "body": "B",
        "state": "published"})
    assert item["scope"] == ""
