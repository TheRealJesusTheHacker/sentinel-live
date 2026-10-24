"""Public visitor logging pins (Sentinel Live, PV-2026-10-23).

Covers the visitor_log pipeline feeding the owner's Activity
console on the public side:

  * a GET of a public HTML page that answers 200 writes exactly one
    row carrying the CF-resolved IP, country, referrer, UA, the
    normalized page path, and the svid visit id;
  * exclusions: /api/*, gated pages, static assets, non-GET,
    non-200 — nothing is logged;
  * the svid cookie is issued once per visit (128-bit random,
    HttpOnly/Secure/SameSite=Lax), a valid echoed cookie groups
    pages into one visit, an invalid one is replaced;
  * bot user agents are flagged, not hidden;
  * /internal/visitors is a three-gate endpoint (loopback peer, no
    CF-Connecting-IP, token) where EVERY failure is the same 404,
    and the payload matches the console contract;
  * summary math (Chicago-day views/uniques/visits, top lists over
    the days window);
  * retention prune removes only rows older than 90 days.

Loads app.py from a scratch copy the same way the other suites do.
Hermetic: no network (TestClient only, feed loops never fire).
"""
import importlib.util
import os
import re
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SRC = Path(__file__).resolve().parent.parent
BROWSER_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/130.0 Mobile Safari/537.36")


def _load_app(tmp: Path, name: str, config_text: str):
    for item in ("app.py", "feeds.py"):
        shutil.copy(SRC / item, tmp / item)
    shutil.copytree(SRC / "templates", tmp / "templates")
    shutil.copytree(SRC / "static", tmp / "static")
    # Minimal staged site: homepage + the two static public pages,
    # so the StaticFiles mount exists like production.
    site = tmp / "site"
    (site / "report-issue").mkdir(parents=True)
    (site / "ticket").mkdir(parents=True)
    (site / "index.html").write_text("<html>home</html>", encoding="utf-8")
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
def vapp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-visitors")
    return _load_app(tmp, "sl_app_visitors",
                     'admin_key: "sekrit"\n'
                     "tunnel:\n"
                     "  enabled: true\n")


@pytest.fixture(scope="module")
def papp(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("sl-visitors-prune")
    return _load_app(tmp, "sl_app_visitors_prune",
                     'admin_key: "sekrit"\n')


def _client(mod):
    """TestClient presenting a loopback peer, like uvicorn on the
    box — the default TestClient peer host is the literal string
    'testclient', which the internal-endpoint gate rightly refuses."""
    return TestClient(mod.app, raise_server_exceptions=False,
                      client=("127.0.0.1", 50000))


def _rows(db_path):
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(
                "SELECT * FROM visitor_log ORDER BY id")]
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return []


def _wait_rows(db_path, n, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = _rows(db_path)
        if len(rows) >= n:
            return rows
        time.sleep(0.05)
    return _rows(db_path)


def _svid_from(resp):
    sc = resp.headers.get("set-cookie", "")
    m = re.search(r"svid=([0-9a-f]{32})", sc)
    return m.group(1) if m else None


# --------------------------------------------------------------- path labels
def test_norm_path_labels(vapp):
    mod = vapp
    assert mod._visitor_norm_path("/") == "/"
    assert mod._visitor_norm_path("/index.html") == "/"
    assert mod._visitor_norm_path("/report-issue/") == "/report-issue"
    assert mod._visitor_norm_path("/report-issue") == "/report-issue"
    assert mod._visitor_norm_path("/ticket/") == "/ticket"
    assert mod._visitor_norm_path("/operations") == "/operations"


# --------------------------------------------------------------- row capture
def test_page_get_logs_full_row(vapp):
    with _client(vapp) as client:
        resp = client.get("/threat-map", headers={
            "CF-Connecting-IP": "203.0.113.7",
            "CF-IPCountry": "US",
            "Referer": "https://www.google.com/",
            "User-Agent": BROWSER_UA})
    assert resp.status_code == 200
    sc = resp.headers.get("set-cookie", "")
    assert "HttpOnly" in sc and "Secure" in sc and "SameSite=Lax" in sc
    assert "Max-Age=1800" in sc
    svid = _svid_from(resp)
    assert svid
    rows = _wait_rows(vapp.DB_PATH, 1)
    assert len(rows) == 1
    r = rows[0]
    assert r["ip"] == "203.0.113.7"          # CF-resolved, not the peer
    assert r["country"] == "US"
    assert r["referrer"] == "https://www.google.com/"
    assert r["ua"] == BROWSER_UA
    assert r["path"] == "/threat-map"
    assert r["visit_id"] == svid
    assert r["bot"] == 0
    assert abs(r["ts"] - int(time.time())) < 120


def test_static_mount_pages_log_normalized(vapp):
    before = len(_rows(vapp.DB_PATH))
    with _client(vapp) as client:
        assert client.get("/report-issue").status_code in (200, 307)
        r1 = client.get("/report-issue/")
        r2 = client.get("/index.html")
    assert r1.status_code == 200 and r2.status_code == 200
    rows = _wait_rows(vapp.DB_PATH, before + 3)
    new = rows[before:]
    # /report-issue (no slash) 307-redirects to the slash form; the
    # redirect itself is not a 200 and logs nothing, the followed
    # slash-form GET logs once — labeled identically to a direct
    # slash-form visit. /index.html is labeled as the homepage.
    assert [r["path"] for r in new] == ["/report-issue",
                                        "/report-issue", "/"]


def test_exclusions_write_nothing(vapp):
    before = len(_rows(vapp.DB_PATH))
    with _client(vapp) as client:
        assert client.get("/api/threat-data").status_code == 200
        assert client.get("/static/style.css").status_code == 200
        assert client.get("/admin").status_code == 403
        assert client.get("/health").status_code == 403
        assert client.get("/no-such-page").status_code == 404
        client.head("/threat-map")  # non-GET: must not log
        assert client.post("/api/contact", json={
            "name": "Pat", "email": "pat@example.co",
            "message": "hi"}).status_code == 200
    time.sleep(0.8)  # any stray async insert would have landed
    assert len(_rows(vapp.DB_PATH)) == before


def test_visit_grouping_and_cookie_replacement(vapp):
    with _client(vapp) as client:
        r1 = client.get("/threat-map", headers={"User-Agent": BROWSER_UA})
        svid = _svid_from(r1)
        assert svid
        r2 = client.get("/geopolitical", headers={
            "User-Agent": BROWSER_UA, "Cookie": f"svid={svid}"})
        # Rolling refresh: same value re-issued, not a new visit.
        assert _svid_from(r2) == svid
        r3 = client.get("/flights", headers={
            "User-Agent": BROWSER_UA, "Cookie": "svid=NOT-A-REAL-COOKIE"})
        forged = _svid_from(r3)
        assert forged and forged != "NOT-A-REAL-COOKIE"
    rows = _wait_rows(vapp.DB_PATH, 3)
    mine = [r for r in rows if r["visit_id"] == svid]
    assert {r["path"] for r in mine} >= {"/threat-map", "/geopolitical"}
    assert all(r["visit_id"] != "NOT-A-REAL-COOKIE" for r in rows)


def test_bot_uas_flagged_not_hidden(vapp):
    before = len(_rows(vapp.DB_PATH))
    with _client(vapp) as client:
        client.get("/", headers={"User-Agent": "curl/8.5.0"})
        client.get("/", headers={
            "User-Agent": "Mozilla/5.0 (compatible; UptimeRobot/2.0)"})
    rows = _wait_rows(vapp.DB_PATH, before + 2)[before:]
    assert len(rows) == 2 and all(r["bot"] == 1 for r in rows)


# --------------------------------------------------------------- internal gate
@pytest.fixture()
def token_env(vapp, tmp_path, monkeypatch):
    tok = tmp_path / "internal_token.txt"
    tok.write_text("test-internal-token\n", encoding="utf-8")
    monkeypatch.setenv("SENTINEL_LIVE_INTERNAL_TOKEN_PATH", str(tok))
    return "test-internal-token"


def test_internal_endpoint_gates(vapp, token_env):
    with _client(vapp) as client:
        assert client.get("/internal/visitors").status_code == 404
        assert client.get("/internal/visitors", headers={
            "X-Internal-Token": "wrong"}).status_code == 404
        # Tunnel evidence refuses even with the right token: a real
        # caller on the box never carries CF-Connecting-IP.
        assert client.get("/internal/visitors", headers={
            "X-Internal-Token": token_env,
            "CF-Connecting-IP": "203.0.113.9"}).status_code == 404
        ok = client.get("/internal/visitors", headers={
            "X-Internal-Token": token_env})
    assert ok.status_code == 200
    body = ok.json()
    assert set(body) == {"summary", "feed"}
    assert set(body["summary"]) == {"viewsToday", "uniqueIpsToday",
                                    "visitsToday", "topPages",
                                    "topReferrers", "topCountries"}
    assert isinstance(body["feed"], list)


def test_internal_endpoint_off_without_token_file(vapp, tmp_path,
                                                   monkeypatch):
    monkeypatch.setenv("SENTINEL_LIVE_INTERNAL_TOKEN_PATH",
                       str(tmp_path / "absent.txt"))
    with _client(vapp) as client:
        assert client.get("/internal/visitors", headers={
            "X-Internal-Token": "anything"}).status_code == 404


# --------------------------------------------------------------- summary math
def test_summary_math_and_feed(vapp, token_env):
    today0 = vapp._chicago_day_start_epoch(0)
    yday0 = vapp._chicago_day_start_epoch(1)
    seed = [
        # ts, ip, ua, path, referrer, country, visit_id, bot
        (today0 + 3600, "198.51.100.1", BROWSER_UA, "/",
         "https://www.google.com/", "US", "a" * 32, 0),
        (today0 + 3700, "198.51.100.1", BROWSER_UA, "/flights",
         "https://www.google.com/", "US", "a" * 32, 0),
        (today0 + 3800, "198.51.100.2", BROWSER_UA, "/",
         "", "CA", "b" * 32, 0),
        (yday0 + 3600, "198.51.100.3", BROWSER_UA, "/flights",
         "", "US", "c" * 32, 0),
        (yday0 + 3700, "198.51.100.3", BROWSER_UA, "/flights",
         "", "US", "c" * 32, 0),
    ]
    conn = sqlite3.connect(vapp.DB_PATH, timeout=5)
    try:
        conn.execute(vapp._VISITOR_TABLE_SQL)
        conn.executemany(
            "INSERT INTO visitor_log(ts,ip,ua,path,referrer,country,"
            "visit_id,bot) VALUES(?,?,?,?,?,?,?,?)", seed)
        conn.commit()
    finally:
        conn.close()
    with _client(vapp) as client:
        body = client.get("/internal/visitors?days=2&limit=200",
                          headers={"X-Internal-Token": token_env}).json()
    s = body["summary"]
    # Today's numbers count ONLY the three seeded today rows, plus
    # whatever this module's live-capture tests already logged today
    # (from the loopback test peer / CF header 203.0.113.7) — so the
    # seeded contributions are asserted as minimums + exact deltas
    # where the seed is unambiguous.
    assert s["viewsToday"] >= 3
    pages = {r["path"]: r["views"] for r in s["topPages"]}
    assert pages["/flights"] >= 3          # 1 today + 2 yesterday
    refs = {r["referrer"]: r["views"] for r in s["topReferrers"]}
    assert refs["https://www.google.com/"] >= 2
    assert refs.get("direct", 0) >= 3      # '' referrers named direct
    countries = {r["country"]: r["views"] for r in s["topCountries"]}
    assert countries["US"] >= 4 and countries["CA"] >= 1
    feed = body["feed"]
    assert feed and all(
        set(item) == {"ts", "ip", "ua", "path", "referrer", "country",
                      "visitId", "bot"} for item in feed)
    tstamps = [item["ts"] for item in feed]
    assert tstamps == sorted(tstamps, reverse=True)  # newest first
    seeded_feed = [i for i in feed if i["ip"].startswith("198.51.100.")]
    assert len(seeded_feed) == 5           # 3 today + 2 within days=2


# --------------------------------------------------------------- retention
def test_prune_removes_only_old_rows(papp):
    now = int(time.time())
    conn = sqlite3.connect(papp.DB_PATH, timeout=5)
    try:
        conn.execute(papp._VISITOR_TABLE_SQL)
        conn.executemany(
            "INSERT INTO visitor_log(ts,ip,ua,path,referrer,country,"
            "visit_id,bot) VALUES(?,?,?,?,?,?,?,?)",
            [(now - 91 * 86400, "192.0.2.1", "ua", "/", "", "",
              "d" * 32, 0),
             (now - 89 * 86400, "192.0.2.2", "ua", "/", "", "",
              "e" * 32, 0),
             (now, "192.0.2.3", "ua", "/", "", "", "f" * 32, 0)])
        conn.commit()
    finally:
        conn.close()
    assert papp._prune_visitor_log_sync() == 1
    rows = _rows(papp.DB_PATH)
    assert [r["ip"] for r in rows] == ["192.0.2.2", "192.0.2.3"]
