"""DEFCON reshape pins (DEFCON-RESHAPE-2026-10-27, owner order).

Covers the Geopolitical DEFCON estimate built 2026-10-27:

  * the pure candidate function against the backtest anchor
    table (1962 -> 2, 1973 -> 3, 9/11 -> 3, post-2022 -> 3,
    peacetime -> 5) and the triangulation caps (pressure alone
    never reaches the severe levels; a single elevated family
    never reaches DEFCON 3);
  * the signal families on a captured-style fixture of 24
    current-era headlines landing the "today" profile;
  * inertia (a one-off spike does not move the level, 2
    consecutive evaluations move to 3/4/5, 3 are required for
    DEFCON <= 2, a revert clears the pending move), the
    change-log append on apply, and first-compute immediacy;
  * the Doomsday Clock parse/bands, last-known fallback, cold
    seed, and GDELT failure discipline (unavailable, E never
    elevated, the estimate still computes);
  * the /api/geo-defcon shape, the estimate labeling on the
    geo page, the cyber page, and the sitemap/visitor sets.

Loads app.py from a scratch copy the same way the other suites
do. Hermetic: TestClient only, all network seams stubbed.
"""
import asyncio
import hashlib
import importlib.util
import json
import shutil
import sys
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
    tmp = tmp_path_factory.mktemp("sl-defcon-reshape")
    return _load_app(tmp, "sl_app_defcon_reshape",
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


@pytest.fixture()
def geo_env(app_mod, tmp_path, monkeypatch):
    """Scratch DATA_DIR + both DEFCON stores reset."""
    monkeypatch.setattr(app_mod, "DATA_DIR", tmp_path / "data")
    monkeypatch.setitem(app_mod.store, "geo_defcon", None)
    monkeypatch.setitem(app_mod.store, "cyber_defcon", None)
    return tmp_path


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


def _set_geo(app_mod, monkeypatch, titles):
    monkeypatch.setitem(app_mod.store, "geo", {
        "updated": "2026-10-27T00:00:00+00:00", "status": "ok",
        "items": [{"title": t} for t in titles],
        "hotspots": [], "error": None})


def _neutral_news(app_mod, news_dir, slug="neutral-1"):
    today = app_mod._chicago_today().isoformat()
    return _write(news_dir, slug, date=today,
                  title="Patch Tuesday fixes arrive for admins",
                  summary="Vendors ship security updates.")


# ------------------------------------------------------------ backtest
# The anchor table from the design (DEFCON-RESHAPE-2026-10-27).
# Each row is a qualitative era profile of family scores.
@pytest.mark.parametrize("families,confrontation,imminent,expected", [
    # 1962 Cuban Missile Crisis peak: SAC reached DEFCON 2.
    ({"A": 3, "B": 3, "C": 3, "D": 0, "E": None}, True, False, 2),
    # 1973 Yom Kippur — the actual DEFCON 3. P=8 must NOT reach
    # 2 without a flag: this row pins exactly that.
    ({"A": 3, "B": 3, "C": 2, "D": 0, "E": None}, False, False, 3),
    # 9/11 — raised to DEFCON 3.
    ({"A": 3, "B": 3, "C": 0, "D": 0, "E": None}, False, False, 3),
    # Post-2022 Ukraine era / today.
    ({"A": 2, "B": 1, "C": 0, "D": 2, "E": None}, False, False, 3),
    # 1990s peacetime.
    ({"A": 1, "B": 0, "C": 0, "D": 0, "E": None}, False, False, 5),
    # Peacetime with tensions: P=3 -> DEFCON 4.
    ({"A": 1, "B": 1, "C": 0, "D": 1, "E": None}, False, False, 4),
    # Imminent synthetic: P=11 with the imminent flag -> 1.
    ({"A": 3, "B": 3, "C": 3, "D": 2, "E": None}, False, True, 1),
    # Single-family discipline: A3 alone (P=3) -> 4, never 3+.
    ({"A": 3, "B": 0, "C": 0, "D": 0, "E": None}, False, False, 4),
    # A3 + D2 (P=5, elevated {A, D}) -> 3 IS correct: two
    # independent families concur.
    ({"A": 3, "B": 0, "C": 0, "D": 2, "E": None}, False, False, 3),
])
def test_geo_backtest_anchors(app_mod, families, confrontation,
                              imminent, expected):
    assert app_mod._geo_candidate(
        families, confrontation=confrontation,
        imminent=imminent) == expected


def test_geo_triangulation_caps(app_mod):
    # P>=5 with only ONE elevated family -> 4, never 3: the
    # pressure here is inflated by E, which cannot concur.
    assert app_mod._geo_candidate(
        {"A": 3, "B": 1, "C": 1, "D": 0, "E": 2}) == 4
    # The imminent flag alone does not reach 1 without the
    # pressure + triangulation the rule requires.
    assert app_mod._geo_candidate(
        {"A": 2, "B": 2, "C": 2, "D": 0, "E": None},
        imminent=True) == 3
    # Confrontation at P=7 but only two elevated families -> 3.
    assert app_mod._geo_candidate(
        {"A": 3, "B": 1, "C": 1, "D": 2, "E": None},
        confrontation=True) == 3


def test_geo_e_never_elevated(app_mod):
    assert app_mod._geo_elevated(
        {"A": 0, "B": 0, "C": 0, "D": 0, "E": 2}) == []
    assert app_mod._geo_elevated(
        {"A": 2, "B": 0, "C": 0, "D": 2, "E": 2}) == ["A", "D"]
    # E's points still count toward pressure when available.
    assert app_mod._geo_pressure(
        {"A": 0, "B": 0, "C": 0, "D": 0, "E": 2}) == 2
    assert app_mod._geo_pressure(
        {"A": 1, "B": 1, "C": 1, "D": 1, "E": None}) == 4


def test_geo_required_confirmations(app_mod):
    assert app_mod._geo_required_confirmations(1) == 3
    assert app_mod._geo_required_confirmations(2) == 3
    assert app_mod._geo_required_confirmations(3) == 2
    assert app_mod._geo_required_confirmations(5) == 2


# ---------------------------------------------------- captured fixture
# ~24 realistic current-era headlines (12 geo + 12 news). The
# counts must land the "today" profile: A=4 stories (score 2),
# B=2 (score 1), C=0 — with the clock at its closest band (D=2)
# that is pressure 5, elevated {A, D}, candidate DEFCON 3.
_GEO_TITLES = [
    "Ukraine front line: shelling and drone strike hit frontline positions",
    "Missile strike and airstrike open new offensive in Ukraine war",
    "Ceasefire talks stall as bombardment continues",
    "Warzone medics: armed conflict grinds on in the east",
    "U.S. strike targets militia depot, Pentagon confirms",
    "NATO ministers pledge another weapons package for Kyiv",
    "Grain exports resume through Black Sea corridor",
    "Regional elections draw record turnout",
    "Earthquake relief flights arrive in the capital",
    "Oil prices steady as markets watch talks",
    "Tech summit focuses on chip exports",
    "Floods displace thousands after dam failure",
]
_NEWS_ITEMS = [
    ("Patch Tuesday fixes arrive for admins",
     "Vendors ship security updates for servers."),
    ("Ransomware crew exploits unpatched edge devices",
     "Crews are abusing exposed gateways, researchers say."),
    ("Phishing kits get cheaper and slicker",
     "New kits mimic bank login pages."),
    ("Hospital group reports billing outage",
     "Systems restored after weekend disruption."),
    ("Browser update patches sandbox escape",
     "Users urged to restart to apply the fix."),
    ("State agency warns of tax-season scams",
     "Fake refund texts are circulating."),
    ("Cloud provider rotates leaked keys",
     "Customers told to review access logs."),
    ("School district restores email after outage",
     "Classes continued during the disruption."),
    ("New guidance for small-business backups",
     "Test restores, not just backups, the guidance says."),
    ("Router flaw under active scanning",
     "Owners should update firmware this week."),
    ("Ticketing scam targets concert fans",
     "Fake resale sites copy real listings."),
    ("Water utility drills incident response",
     "The exercise simulated a billing-system failure."),
]


def test_geo_counts_land_today_profile(app_mod, geo_env, news_dir,
                                       monkeypatch):
    _set_geo(app_mod, monkeypatch, _GEO_TITLES)
    today = app_mod._chicago_today().isoformat()
    for i, (title, summary) in enumerate(_NEWS_ITEMS):
        _write(news_dir, "news-%02d" % i, date=today, title=title,
               summary=summary)
    current = app_mod._compute_geo_defcon(
        clock_seconds=89, clock_source="live")
    assert current["inputs"]["counts"] == {"A": 4, "B": 2, "C": 0}
    assert current["families"] == {"A": 2, "B": 1, "C": 0,
                                   "D": 2, "E": None}
    assert current["pressure"] == 5
    assert current["elevated"] == ["A", "D"]
    assert current["flags"] == {"confrontation": False,
                                "imminent": False}
    assert current["defcon"] == 3
    assert current["inputs"]["gdelt"] == "unavailable"
    assert current["clock_seconds"] == 89
    assert current["clock_source"] == "live"
    assert app_mod.store["geo_defcon"] == current
    saved = json.loads(
        (geo_env / "data" / "geo_defcon.json").read_text(
            encoding="utf-8"))
    assert saved["current"] == current
    assert saved["clock_seconds"] == 89
    assert [h["defcon"] for h in saved["history"]] == [3]


# ------------------------------------------------------------- inertia
_PROFILE3_GEO = _GEO_TITLES[:6]
_PROFILE2_GEO = _PROFILE3_GEO + [
    "Pentagon orders carrier group to the region",
    "Officials warn of nuclear threat as warhead deployment reported",
    "Naval blockade imposed on strait",
]
_PROFILE4_GEO = [
    "Ukraine front line quiet patrol",
    "Pentagon briefs reporters on readiness",
]


def test_geo_first_compute_immediate_and_empty_pending(
        app_mod, geo_env, news_dir, monkeypatch):
    # Both corpora empty and no current: pending — no invented
    # level, from either the compute or the API.
    _set_geo(app_mod, monkeypatch, [])
    assert app_mod._compute_geo_defcon() is None
    body = _client(app_mod).get("/api/geo-defcon").json()
    assert body["defcon"] is None and body["awaiting_first"] is True
    assert body["history"] == [] and body["changes"] == []
    # First-ever real compute applies immediately (no dwell).
    _neutral_news(app_mod, news_dir)
    _set_geo(app_mod, monkeypatch, _PROFILE4_GEO)
    current = app_mod._compute_geo_defcon(clock_seconds=100)
    assert current["defcon"] == 4  # A1 + B1 + D1 == pressure 3
    assert app_mod._get_geo_pending() is None


def test_geo_inputs_vanish_keeps_last(app_mod, geo_env, news_dir,
                                      monkeypatch, tmp_path):
    _neutral_news(app_mod, news_dir)
    _set_geo(app_mod, monkeypatch, _PROFILE4_GEO)
    previous = app_mod._compute_geo_defcon(clock_seconds=100)
    assert previous is not None
    empty = tmp_path / "empty-news"
    empty.mkdir()
    monkeypatch.setattr(app_mod, "_NEWS_DIR", empty)
    monkeypatch.setattr(app_mod, "_news_cache",
                        {"key": None, "items": []})
    _set_geo(app_mod, monkeypatch, [])
    again = app_mod._compute_geo_defcon(clock_seconds=85)
    assert again == previous  # level AND its timestamp kept


def test_geo_inertia_spike_dwell_and_confirmations(
        app_mod, geo_env, news_dir, monkeypatch):
    _neutral_news(app_mod, news_dir)
    # Quiet start: candidate 5 applies at first compute.
    _set_geo(app_mod, monkeypatch, [])
    cur = app_mod._compute_geo_defcon(clock_seconds=200)
    assert cur["defcon"] == 5
    # One-off spike to the DEFCON 3 profile: pending only.
    _set_geo(app_mod, monkeypatch, _PROFILE3_GEO)
    cur = app_mod._compute_geo_defcon(clock_seconds=85)
    assert cur["defcon"] == 5
    assert app_mod._get_geo_pending() == {"defcon": 3, "count": 1}
    # Second consecutive evaluation applies the move to 3.
    cur = app_mod._compute_geo_defcon(clock_seconds=85)
    assert cur["defcon"] == 3
    assert app_mod._get_geo_pending() is None
    changes = app_mod._get_geo_changes()
    assert len(changes) == 1
    assert changes[0]["from"] == 5 and changes[0]["to"] == 3
    assert changes[0]["pressure"] == 5
    assert changes[0]["elevated"] == ["A", "D"]
    # A move to DEFCON 2 needs THREE consecutive evaluations.
    _set_geo(app_mod, monkeypatch, _PROFILE2_GEO)
    for _ in range(2):
        cur = app_mod._compute_geo_defcon(clock_seconds=85)
        assert cur["defcon"] == 3
    assert app_mod._get_geo_pending() == {"defcon": 2, "count": 2}
    cur = app_mod._compute_geo_defcon(clock_seconds=85)
    assert cur["defcon"] == 2
    changes = app_mod._get_geo_changes()
    assert len(changes) == 2
    assert changes[1]["from"] == 3 and changes[1]["to"] == 2
    assert changes[1]["flags"]["confrontation"] is True
    # Reverting to the standing level clears a pending move.
    _set_geo(app_mod, monkeypatch, [])
    cur = app_mod._compute_geo_defcon(clock_seconds=200)
    assert cur["defcon"] == 2
    assert app_mod._get_geo_pending() == {"defcon": 5, "count": 1}
    _set_geo(app_mod, monkeypatch, _PROFILE2_GEO)
    cur = app_mod._compute_geo_defcon(clock_seconds=85)
    assert cur["defcon"] == 2
    assert app_mod._get_geo_pending() is None


def test_geo_change_log_records_drivers(app_mod, geo_env, news_dir,
                                        monkeypatch):
    _neutral_news(app_mod, news_dir)
    _set_geo(app_mod, monkeypatch, _PROFILE4_GEO)
    cur = app_mod._compute_geo_defcon(clock_seconds=100)
    assert cur["defcon"] == 4
    _set_geo(app_mod, monkeypatch, _PROFILE3_GEO)
    app_mod._compute_geo_defcon(clock_seconds=85)
    cur = app_mod._compute_geo_defcon(clock_seconds=85)
    assert cur["defcon"] == 3
    (change,) = app_mod._get_geo_changes()
    assert change["from"] == 4 and change["to"] == 3
    assert change["families"]["A"] == 2
    assert change["families"]["D"] == 2
    assert change["inputs"]["counts"] == {"A": 4, "B": 2, "C": 0}
    assert change["inputs"]["clock_seconds"] == 85
    assert change["ts"]


# ------------------------------------------------- clock + gdelt seams
def test_doomsday_parse_and_bands(app_mod):
    assert app_mod._parse_doomsday_clock(
        "It is now 85 seconds to midnight.") == 85
    # First match wins.
    assert app_mod._parse_doomsday_clock(
        "89 seconds to midnight, previously 100 seconds to "
        "midnight") == 89
    assert app_mod._parse_doomsday_clock("no clock here") is None
    assert app_mod._parse_doomsday_clock("") is None
    for seconds, score in [(85, 2), (90, 2), (91, 1), (120, 1),
                           (121, 0), (200, 0), (None, 0)]:
        assert app_mod._doomsday_score(seconds) == score, seconds


def test_gdelt_parse_ratios(app_mod):
    def payload(values):
        return {"timeline": [{"value": v} for v in values]}
    score, ratio = app_mod._gdelt_parse(payload([1, 1, 1, 2]))
    assert score == 2 and ratio == pytest.approx(1.6)
    score, ratio = app_mod._gdelt_parse(payload([2, 2, 2, 3]))
    assert score == 1
    score, ratio = app_mod._gdelt_parse(payload([1, 1, 1, 1]))
    assert score == 0 and ratio == pytest.approx(1.0)
    assert app_mod._gdelt_parse({}) == (None, None)
    assert app_mod._gdelt_parse({"timeline": []}) == (None, None)
    assert app_mod._gdelt_parse(None) == (None, None)


class _BoomClient:
    """An httpx.AsyncClient stand-in whose connect always fails."""

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        raise ConnectionError("nope")

    async def __aexit__(self, *a):
        return False


def test_external_fetches_fail_soft(app_mod, monkeypatch):
    monkeypatch.setattr(app_mod.httpx, "AsyncClient", _BoomClient)
    assert asyncio.run(app_mod._fetch_gdelt()) == (
        None, None, "unavailable")
    assert asyncio.run(app_mod._fetch_doomsday_seconds()) is None


def test_bulletin_failure_uses_last_known_and_cold_seed(
        app_mod, geo_env, news_dir, monkeypatch):
    _neutral_news(app_mod, news_dir)
    _set_geo(app_mod, monkeypatch, _PROFILE4_GEO)
    # Cold seed: no state file and no live clock -> 85 seconds,
    # last-known, D scores 2.
    cur = app_mod._compute_geo_defcon()
    assert cur["clock_seconds"] == 85
    assert cur["clock_source"] == "last-known"
    assert cur["families"]["D"] == 2
    # A live reading replaces the last-good; a later failure
    # falls back to it (100s -> D scores 1).
    cur = app_mod._compute_geo_defcon(clock_seconds=100,
                                      clock_source="live")
    assert cur["clock_seconds"] == 100
    cur = app_mod._compute_geo_defcon()
    assert cur["clock_seconds"] == 100
    assert cur["clock_source"] == "last-known"
    assert cur["families"]["D"] == 1


def test_gdelt_unavailable_estimate_still_computes(
        app_mod, geo_env, news_dir, monkeypatch):
    _neutral_news(app_mod, news_dir)
    _set_geo(app_mod, monkeypatch, _PROFILE3_GEO)
    cur = app_mod._compute_geo_defcon(
        clock_seconds=85, gdelt_status="unavailable")
    assert cur["defcon"] == 3
    assert cur["families"]["E"] is None
    assert cur["inputs"]["gdelt"] == "unavailable"
    assert "E" not in cur["elevated"]


# ------------------------------------------------------------- surfaces
def test_geo_api_shape(app_mod, geo_env, news_dir, monkeypatch):
    _set_geo(app_mod, monkeypatch, _GEO_TITLES)
    today = app_mod._chicago_today().isoformat()
    for i, (title, summary) in enumerate(_NEWS_ITEMS):
        _write(news_dir, "api-%02d" % i, date=today, title=title,
               summary=summary)
    app_mod._compute_geo_defcon(clock_seconds=89,
                                clock_source="live")
    r = _client(app_mod).get("/api/geo-defcon")
    assert r.status_code == 200
    body = r.json()
    assert body["defcon"] == 3 and body["name"] == "ELEVATED"
    assert body["pressure"] == 5
    assert body["families"] == {"A": 2, "B": 1, "C": 0, "D": 2,
                                "E": None}
    assert body["elevated"] == ["A", "D"]
    assert body["flags"] == {"confrontation": False,
                             "imminent": False}
    assert body["inputs"]["counts"] == {"A": 4, "B": 2, "C": 0}
    assert body["clock_seconds"] == 89
    assert body["clock_source"] == "live"
    assert body["inputs"]["gdelt"] == "unavailable"
    assert body["pending"] is None
    assert len(body["history"]) == 1
    assert body["changes"] == []
    assert r.headers.get("cache-control") == "no-store"


def test_geo_page_carries_estimate_label(app_mod, geo_env,
                                         news_dir, monkeypatch):
    _neutral_news(app_mod, news_dir)
    _set_geo(app_mod, monkeypatch, _PROFILE3_GEO)
    app_mod._compute_geo_defcon(clock_seconds=85)
    page = _client(app_mod).get("/geopolitical-defcon")
    assert page.status_code == 200
    text = " ".join(page.text.split())
    label = ("Open-source estimate by Sentinel Safeguard. The "
             "actual DEFCON level is classified — this is not "
             "the official level.")
    # The label rides BOTH the hero and the methodology.
    assert text.count(label) >= 2
    assert "no single feed can move this level alone" in text
    assert 'id="geo-panel-level"' in page.text
    assert 'id="geo-drivers"' in page.text
    assert 'id="geo-history"' in page.text
    assert 'id="geo-changes"' in page.text
    assert "Change log" in text
    assert "1962" in text and "1973" in text
    assert "Worried something like this could hit your business?" \
        in text
    assert "Liberty" not in page.text


def test_cyber_page(app_mod, geo_env, monkeypatch):
    monkeypatch.setitem(app_mod.store, "cyber_defcon", {
        "defcon": 4, "name": "GUARDED", "score": 3,
        "parts": {"kev_points": 1, "news_points": 1,
                  "feed_points": 1},
        "inputs": {"kev_added_7d": 9, "news_threat_watch_7d": 20,
                   "news_patch_alert_7d": 5,
                   "dshield_sources_today": 190000},
        "computed_at": "2026-10-27T12:00:00+00:00"})
    page = _client(app_mod).get("/cyber-defcon")
    assert page.status_code == 200
    text = " ".join(page.text.split())
    assert "DEFCON 4" in text and "GUARDED" in text
    # The score -> DEFCON mapping table.
    assert "Score 0&ndash;1" in text and "Score 7" in text
    # The formerly-Threat-Level note (same math, new direction).
    assert "formerly displayed as the" in text
    assert "&ldquo;Sentinel Threat Level&rdquo;" in text
    assert 'id="cyber-panel-level"' in page.text
    assert 'id="cyber-inputs"' in page.text
    assert 'id="cyber-history"' in page.text
    assert "Worried something like this could hit your business?" \
        in text
    assert "Liberty" not in page.text


def test_defcon_js_replaced_threat_level_js():
    js = (SRC / "static" / "js" / "defcon.js").read_text(
        encoding="utf-8")
    assert "/api/cyber-defcon" in js
    assert "/api/geo-defcon" in js
    assert not (SRC / "static" / "js" / "threat-level.js").exists()


def test_defcon_paths_in_sitemap_and_visitor_sets(app_mod):
    for path in ("/cyber-defcon", "/geopolitical-defcon"):
        assert path in app_mod._SITEMAP_PATHS
        assert path in app_mod._VISITOR_PUBLIC_PATHS
    sitemap = _client(app_mod).get("/sitemap.xml")
    assert sitemap.status_code == 200
    assert "https://sentinelsafeguard.net/cyber-defcon" \
        in sitemap.text
    assert "https://sentinelsafeguard.net/geopolitical-defcon" \
        in sitemap.text
