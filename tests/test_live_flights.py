"""LF-2026-10-25 pins — live flight tracker (adsb.lol ADS-B layer).

Covers the new /api/live-flights endpoint and the /flights live
layer:
  * normalization of raw ADS-B records into the one clean shape
    (trimmed callsigns, 'ground' altitudes, emergency squawks, junk
    records dropped — feed values only, nothing invented);
  * the endpoint's contract: defaults to Kansas City, validates and
    clamps parameters, carries attribution + the honesty note;
  * server-side caching + cell coalescing (visitor count can never
    multiply upstream calls) and the stale-on-failure fallback —
    last good data, flagged, with NO upstream error text leaked;
  * the page markup for the live layer (status strip, detail panel,
    altitude-band legend, small print) and the search bridge button;
  * quota discipline: the map path never touches the AviationStack
    lookup — the provider is rigged to explode and must stay silent.

Hermetic: the upstream fetcher is monkeypatched everywhere; no test
reaches the network.
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
    tmp = tmp_path_factory.mktemp("sl-live-flights")
    return _load_app(tmp, "sl_app_live_flights")


@pytest.fixture(scope="module")
def key_app(tmp_path_factory):
    # Same app with a (dummy) flight_api key configured — the /flights
    # route only spends a lookup when a key exists, so the search
    # bridge can only be exercised on this instance.
    tmp = tmp_path_factory.mktemp("sl-live-flights-key")
    return _load_app(tmp, "sl_app_live_flights_key",
                     "server:\n  port: 8443\n"
                     "flight_api:\n"
                     "  provider: aviationstack\n"
                     '  api_key: "test-key"\n')


@pytest.fixture(autouse=True)
def _fresh_live_state(app_mod):
    feeds = app_mod.feeds
    feeds._live_cache.clear()
    feeds._live_last_fetch = 0.0
    feeds._live_lock = None
    app_mod._hits.clear()
    yield


def _client(mod):
    return TestClient(mod.app, raise_server_exceptions=False)


RAW = {
    "ac": [
        {"hex": "ab805a", "flight": "FDX15   ", "r": "N840FD", "t": "B77L",
         "alt_baro": 36000, "alt_geom": 37550, "gs": 440.2, "track": 317.39,
         "baro_rate": 0, "squawk": "1530", "category": "A5",
         "lat": 39.982178, "lon": -95.555603, "seen_pos": 0.4},
        {"hex": "a00000", "flight": "GND1", "alt_baro": "ground", "gs": 0,
         "track": 90, "squawk": "1200", "lat": 39.3, "lon": -94.7},
        {"hex": "b00000", "flight": "EMG1", "alt_baro": "2500", "gs": 180,
         "track": 45, "baro_rate": -640, "squawk": "7700",
         "lat": 39.4, "lon": -94.8},
        {"hex": "broken"},
    ],
    "total": 3, "now": 1792920630500, "msg": "No error",
}


def _mock_upstream(app_mod, monkeypatch, raw=RAW):
    calls = []

    async def fake(lat, lon, dist, timeout):
        calls.append((lat, lon, dist))
        return raw

    monkeypatch.setattr(app_mod.feeds, "_fetch_live_upstream", fake)
    return calls


# -------------------------------------------------------- normalization
def test_normalize_aircraft_shape(app_mod):
    n = app_mod.feeds.normalize_aircraft
    a = n(RAW["ac"][0])
    assert a["callsign"] == "FDX15"          # feed padding trimmed
    assert a["registration"] == "N840FD"    # carried by the feed itself
    assert a["type"] == "B77L"
    assert a["altitude_ft"] == 36000 and a["on_ground"] is False
    assert a["speed_kt"] == 440.2 and a["heading"] == 317.39
    assert a["vertical_rate_fpm"] == 0
    assert a["squawk"] == "1530" and a["emergency"] is False
    assert a["category"] == "A5"
    g = n(RAW["ac"][1])
    assert g["on_ground"] is True and g["altitude_ft"] is None
    e = n(RAW["ac"][2])
    assert e["emergency"] is True           # squawk 7700
    assert e["altitude_ft"] == 2500         # numeric string coerced
    assert e["vertical_rate_fpm"] == -640
    assert n(RAW["ac"][3]) is None          # no position -> dropped
    assert n("junk") is None and n(None) is None


def test_normalize_payload_counts(app_mod):
    aircraft, total = app_mod.feeds.normalize_live_payload(RAW)
    assert len(aircraft) == 3 and total == 3
    assert app_mod.feeds.normalize_live_payload(None) == ([], 0)
    assert app_mod.feeds.normalize_live_payload({"ac": "junk"}) == ([], 0)


# ------------------------------------------------------------ endpoint
def test_live_flights_endpoint_shape(app_mod, monkeypatch):
    _mock_upstream(app_mod, monkeypatch)
    resp = _client(app_mod).get("/api/live-flights")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "adsb.lol"
    assert "ODbL" in body["note"] and "Coverage varies" in body["note"]
    assert body["center"] == {"lat": 39.1, "lon": -94.6}   # KC default
    assert body["dist"] == 100
    assert body["stale"] is False and body["total"] == 3
    assert len(body["aircraft"]) == 3
    assert body["fetched_at"]


def test_live_flights_cache_coalesces_upstream(app_mod, monkeypatch):
    calls = _mock_upstream(app_mod, monkeypatch)
    c = _client(app_mod)
    assert c.get("/api/live-flights").status_code == 200
    assert c.get("/api/live-flights").status_code == 200
    # a nearby center in the same ~11 km cell shares the same answer
    assert c.get("/api/live-flights",
                 params={"lat": 39.14, "lon": -94.64}).status_code == 200
    assert len(calls) == 1


def test_live_flights_stale_on_failure_no_leak(app_mod, monkeypatch):
    feeds = app_mod.feeds
    _mock_upstream(app_mod, monkeypatch)
    c = _client(app_mod)
    assert c.get("/api/live-flights").json()["stale"] is False

    async def boom(lat, lon, dist, timeout):
        raise RuntimeError("upstream exploded badly")

    monkeypatch.setattr(feeds, "_fetch_live_upstream", boom)
    # age the cached answer past fresh, within stale; open the gate
    for entry in feeds._live_cache.values():
        entry["fetched"] -= feeds.LIVE_CACHE_TTL + 10
    feeds._live_last_fetch = 0.0
    resp = c.get("/api/live-flights")
    assert resp.status_code == 200
    body = resp.json()
    assert body["stale"] is True
    assert len(body["aircraft"]) == 3        # last good, still served
    assert "exploded" not in resp.text       # upstream text never leaks


def test_live_flights_empty_when_no_history_and_upstream_down(
        app_mod, monkeypatch):
    async def boom(lat, lon, dist, timeout):
        raise RuntimeError("down")

    monkeypatch.setattr(app_mod.feeds, "_fetch_live_upstream", boom)
    resp = _client(app_mod).get("/api/live-flights")
    assert resp.status_code == 200
    body = resp.json()
    assert body["aircraft"] == [] and body["total"] == 0
    assert body["stale"] is True and body["fetched_at"] is None


def test_live_flights_param_validation(app_mod, monkeypatch):
    _mock_upstream(app_mod, monkeypatch)
    c = _client(app_mod)
    assert c.get("/api/live-flights",
                 params={"lat": 999}).status_code == 400
    assert c.get("/api/live-flights",
                 params={"lon": -999}).status_code == 400
    assert c.get("/api/live-flights",
                 params={"lat": "junk"}).status_code == 422
    body = c.get("/api/live-flights", params={"dist": 99999}).json()
    assert body["dist"] == 250               # clamped to the ceiling


# ------------------------------------------------------------ page layer
def test_flights_page_has_live_layer(app_mod):
    resp = _client(app_mod).get("/flights")
    assert resp.status_code == 200
    for marker in ('id="live-status"', 'id="flight-panel"', 'id="fp-close"',
                   "/api/live-flights", "adsb.lol", "Not for navigation",
                   "below 10,000 ft", "above 30,000 ft", "emergency squawk",
                   "setView(KC, 9)", "POLL_MS = 15000"):
        assert marker in resp.text, marker


def test_search_bridge_button_with_result(key_app, monkeypatch):
    result = {
        "number": "FDX15", "airline": "FedEx", "status": "en_route",
        "departure": {"iata": "MEM", "airport": "Memphis Intl",
                      "scheduled": "2026-10-25T01:00", "estimated": None,
                      "actual": None, "delay": None},
        "arrival": {"iata": "IND", "airport": "Indianapolis Intl",
                    "scheduled": "2026-10-25T03:00", "estimated": None,
                    "actual": None, "delay": None},
        "aircraft": "N840FD", "live": None,
    }

    async def fake_lookup(number, api_key, timeout):
        return result, None

    monkeypatch.setattr(key_app.feeds, "lookup_flight", fake_lookup)
    resp = _client(key_app).get("/flights", params={"q": "FDX15"})
    assert resp.status_code == 200
    assert 'id="track-live"' in resp.text
    assert "Track FDX15 live on the map" in resp.text


def test_map_path_never_spends_search_quota(app_mod, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("AviationStack provider called by the map")

    monkeypatch.setattr(app_mod.feeds, "_lookup_flight_provider", forbidden)
    _mock_upstream(app_mod, monkeypatch)
    c = _client(app_mod)
    assert c.get("/api/live-flights").status_code == 200
    assert c.get("/flights").status_code == 200
