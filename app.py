#!/usr/bin/env python3
"""Sentinel Live Server — Sentinel Safeguard LLC.

Single-file Windows service (built with PyInstaller --onefile --noconsole).
Serves:
  * the public website frontend (from ./site/ when present)
  * 4 live pages: /threat-map  /geopolitical  /flights  /news
  * website backend APIs: contact form, Get Help tickets, newsletter signup
  * admin API + page (localhost-only, or X-Admin-Key)
All persistent storage is an embedded SQLite file next to the exe.
Logs go to ./logs/server.log (there is no console in the .exe build).
"""
import asyncio
import hmac
import csv
import io
import json
import logging
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

import aiosqlite
import yaml
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import feeds

# ------------------------------------------------------------------ paths
FROZEN = getattr(sys, "frozen", False)


def app_dir() -> Path:
    """Writable dir: next to the .exe when frozen, else next to source."""
    if FROZEN:
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def res_dir(name: str) -> Path:
    """Bundled read-only resources (templates/static inside the exe)."""
    if FROZEN:
        return Path(sys._MEIPASS) / name  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent / name


APP_DIR = app_dir()
DATA_DIR = APP_DIR / "data"
LOG_DIR = APP_DIR / "logs"
DB_PATH = DATA_DIR / "sentinel-live.db"
CONFIG_PATH = APP_DIR / "config.yaml"
BRIEFING_PATH = DATA_DIR / "briefing.json"
for _d in (DATA_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------------ config
DEFAULT_CONFIG = {
    "server": {"host": "127.0.0.1", "port": 8443},
    "feeds": {"threat_refresh_minutes": 5, "geo_refresh_minutes": 15,
              "news_refresh_minutes": 30, "request_timeout_seconds": 20},
    "flight_api": {"provider": "aviationstack", "api_key": ""},
    "threat_feeds": {"abuse_ch_auth_key": ""},  # optional free key from https://auth.abuse.ch/
    "tunnel": {"enabled": False,
               "cloudflared_path": "C:\\Program Files\\cloudflared\\cloudflared.exe",
               "args": "tunnel --url http://127.0.0.1:8443"},
    "briefing_token": "",
    "admin_key": "",
    # SL6-1: default is NO cross-origin access. The old default of ["*"]
    # combined with the localhost admin bypass let any website the owner
    # visited on aroura read /api/admin/* responses out of the local
    # server (the request genuinely comes from 127.0.0.1, and "*" let the
    # attacker's page read the reply). Same-origin pages served by this
    # server never need CORS; an externally hosted frontend must be
    # listed explicitly in config.yaml (cors_origins).
    "cors_origins": [],
    "rss": {
        "geopolitical": [
            "https://www.aljazeera.com/xml/rss/all.xml",
            "https://feeds.bbci.co.uk/news/world/rss.xml",
            "https://rss.dw.com/xml/rss-en-world",
        ],
        "news_sections": {
            "National": ["https://feeds.npr.org/1001/rss.xml",
                         "https://www.pbs.org/newshour/feeds/rss/headlines"],
            "Missouri": ["https://fox4kc.com/feed/",
                         "https://www.ozarksfirst.com/feed/",
                         "https://www.stltoday.com/search/?l=10&sd=desc&s=start_time&f=rss"],
            "Kansas City": ["https://www.kcur.org/term/news/rss.xml",
                            "https://www.kmbc.com/topstories-rss"],
            "Geopolitical": ["https://www.aljazeera.com/xml/rss/all.xml",
                             "https://feeds.bbci.co.uk/news/world/rss.xml"],
            "Cyber": ["https://krebsonsecurity.com/feed/",
                      "https://www.bleepingcomputer.com/feed/",
                      "https://feeds.feedburner.com/TheHackersNews"],
            "Political": ["https://thehill.com/feed/"],
            "Markets": ["https://www.cnbc.com/id/100003114/device/rss/rss.html",
                        "https://feeds.marketwatch.com/marketwatch/topstories/"],
        },
    },
    "logging": {"file": "logs/server.log", "level": "INFO"},
}


# Warnings collected while merging config (the logger doesn't exist yet
# at this point, so load_config can't log directly).
_config_warnings = []


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump(DEFAULT_CONFIG, f, sort_keys=False,
                           default_flow_style=False, allow_unicode=True)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception:
        cfg = {}
    if not isinstance(cfg, dict):
        # BH2-1: a config whose top level isn't a mapping (a stray note,
        # a bare list/number) crashed _merge with AttributeError and
        # bricked startup. Ignore the file, keep the defaults.
        _config_warnings.append(
            f"config top level is {type(cfg).__name__}, not a mapping; "
            "ignoring the file and using defaults")
        cfg = {}
    # deep-merge defaults so missing keys never crash the app
    merged = json.loads(json.dumps(DEFAULT_CONFIG))

    def _merge(dst, src, path=""):
        for k, v in src.items():
            cur = dst.get(k)
            here = f"{path}.{k}" if path else str(k)
            if isinstance(v, dict) and isinstance(cur, dict):
                _merge(cur, v, here)
            elif k in dst and isinstance(v, dict) != isinstance(cur, dict):
                # SL2-1: a wrong-typed value must never replace a default
                # subtree (e.g. `server: "oops"` bricking startup) — keep
                # the default and warn instead.
                _config_warnings.append(
                    f"config key '{here}' has wrong type "
                    f"({type(v).__name__}); keeping default")
            else:
                dst[k] = v

    _merge(merged, cfg)
    return merged


config = load_config()

# ------------------------------------------------------------------ logging (file only)
log = logging.getLogger("sentinel-live")
log.setLevel(getattr(logging, str(config["logging"]["level"]).upper(), logging.INFO))
_fh = RotatingFileHandler(LOG_DIR / "server.log", maxBytes=2_000_000,
                          backupCount=5, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
log.addHandler(_fh)
log.propagate = False
for _n in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    _l = logging.getLogger(_n)
    _l.handlers = [_fh]
    _l.propagate = False

# flush config-merge warnings now that the logger exists
for _w in _config_warnings:
    log.warning("config: %s", _w)
_config_warnings.clear()


def _validate_config_schema():
    """SL2-1: critical numeric settings with wrong types get their default
    back instead of crashing the server or the refresh loops."""
    srv = config.get("server")
    if isinstance(srv, dict):
        port = srv.get("port")
        if isinstance(port, bool) or not isinstance(port, int):
            log.warning("config: server.port invalid (%r); using default %r",
                        port, DEFAULT_CONFIG["server"]["port"])
            srv["port"] = DEFAULT_CONFIG["server"]["port"]
    fcfg = config.get("feeds")
    if isinstance(fcfg, dict):
        for _key in ("threat_refresh_minutes", "geo_refresh_minutes",
                     "news_refresh_minutes", "request_timeout_seconds"):
            _v = fcfg.get(_key)
            if isinstance(_v, bool) or not isinstance(_v, int):
                log.warning("config: feeds.%s invalid (%r); using default %r",
                            _key, _v, DEFAULT_CONFIG["feeds"][_key])
                fcfg[_key] = DEFAULT_CONFIG["feeds"][_key]


_validate_config_schema()

class _BodySizeLimitMiddleware:
    """Pure-ASGI request body size cap (SL2-3).

    Reads Content-Length first for an early 413, then caps bytes while
    streaming so a missing/lying header can't OOM the process. Limits the
    body endpoints to 2MB (contact/ticket/newsletter/admin) and the
    briefing ingest (which is written to disk) to 5MB.
    """
    LIMIT_DEFAULT = 2 * 1024 * 1024
    LIMITS = {"/api/briefing": 5 * 1024 * 1024}

    def __init__(self, app):
        self.app = app

    def _limit_for(self, path: str) -> int:
        for prefix, lim in self.LIMITS.items():
            if path == prefix or path.startswith(prefix + "/"):
                return lim
        return self.LIMIT_DEFAULT

    async def _respond_413(self, send):
        body = b'{"detail":"Request body too large."}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body,
                    "more_body": False})

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # SL6-6: nosniff on every response — cheap insurance against
            # MIME-sniffing a stored/uploaded body into active content.
            # (Deliberately NOT a full CSP or frame policy here: the
            # pages load Leaflet + map tiles from CDNs and the owner may
            # embed the live pages in the main site; those policies
            # need their own deliberate pass, not a drive-by header.)
            _orig_send = send

            async def send(message):
                if message["type"] == "http.response.start":
                    hdrs = [(k, v) for k, v in message.get("headers", [])
                            if k.lower() != b"x-content-type-options"]
                    hdrs.append((b"x-content-type-options", b"nosniff"))
                    message = dict(message, headers=hdrs)
                await _orig_send(message)

        if scope["type"] != "http" or scope.get("method") not in ("POST", "PATCH", "PUT"):
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        limit = self._limit_for(path)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        try:
            content_length = int(headers.get("content-length") or 0)
        except (TypeError, ValueError):
            content_length = 0
        if content_length > limit:
            log.warning("body cap 413: path=%s content-length=%d > %d",
                        path, content_length, limit)
            await self._respond_413(send)
            return
        # cap while reading (covers missing/lying Content-Length)
        chunks, total, more_body = [], 0, True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > limit:
                    log.warning("body cap 413: path=%s streamed %d > %d",
                                path, total, limit)
                    await self._respond_413(send)
                    return
                chunks.append(chunk)
                more_body = message.get("more_body", False)
        body = b"".join(chunks)

        sent = False

        async def receive_replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body,
                        "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, receive_replay, send)


# ------------------------------------------------------------------ app
app = FastAPI(title="Sentinel Live Server", docs_url=None, redoc_url=None,
              openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get("cors_origins") or [],
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)
# outermost: reject oversized bodies before anything else touches them
app.add_middleware(_BodySizeLimitMiddleware)
app.mount("/static", StaticFiles(directory=res_dir("static")), name="static")
templates = Jinja2Templates(directory=str(res_dir("templates")))

# in-memory live-data store (SQLite holds the persistent stuff)
STARTED_AT = None
store = {
    "threat": {"updated": None, "status": "starting", "attacks_today": 0,
               "sources_today": 0, "families": [], "countries": [],
               "attack_types": [], "markers": [], "arcs": [], "feed": [],
               "error": None},
    "geo": {"updated": None, "status": "starting", "items": [], "hotspots": [], "error": None},
    "news": {"updated": None, "status": "starting", "sections": {}, "error": None},
    "briefing": None,
}

# ------------------------------------------------------------------ sqlite
SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL,
  subject TEXT DEFAULT '', message TEXT NOT NULL, ip TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS tickets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL,
  phone TEXT DEFAULT '', category TEXT DEFAULT '', priority TEXT DEFAULT 'Normal',
  subject TEXT NOT NULL, message TEXT NOT NULL,
  status TEXT DEFAULT 'new', admin_notes TEXT DEFAULT '', ip TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS newsletter(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  name TEXT DEFAULT '', ip TEXT DEFAULT '');
"""


async def _db():
    # SL5-1: do NOT await the connect here. aiosqlite's __await__ starts
    # the connection's worker thread, and every caller uses
    # `async with await _db()` — the context manager awaits the
    # connection again, and a thread can only be started once, so the
    # old shape died at startup with "threads can only be started once".
    # Returning the unstarted connection lets __aenter__ start it once.
    # WAL mode is asserted in init_db (it persists on the database file).
    return aiosqlite.connect(DB_PATH, timeout=30)


async def init_db():
    try:
        async with await _db() as db:
            await db.executescript(SCHEMA)
            await db.execute("PRAGMA journal_mode=WAL")  # SL5-1: see _db()
            await db.commit()
    except sqlite3.DatabaseError:
        # SL4-1: a corrupt database must never brick startup — quarantine
        # the file aside and re-initialize fresh so the server can boot.
        # The re-init uses stdlib sqlite3 directly to keep the recovery
        # path independent of the async wrapper.
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        bad = DB_PATH.with_name(f"sentinel-live.db.corrupt-{ts}")
        try:
            if DB_PATH.exists():
                DB_PATH.rename(bad)
        except Exception:
            pass  # keep going either way — the log line says where it went
        log.critical("SQLite database corrupt — quarantined to %s; "
                     "re-initializing fresh", bad)
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()
    log.info("SQLite ready at %s", DB_PATH)


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ guards
_hits = defaultdict(list)
_admin_fails = defaultdict(list)


def _real_ip(request: Request):
    # Behind the Cloudflare Tunnel every connection looks like localhost —
    # use the real client IP Cloudflare reports instead.
    # SL2-2: when tunneled, trust ONLY CF-Connecting-IP. X-Forwarded-For is
    # attacker-controlled and must never be a fallback (rate-limit bypass);
    # without the Cloudflare header, use the TCP peer.
    if config.get("tunnel", {}).get("enabled"):
        return (request.headers.get("CF-Connecting-IP")
                or (request.client.host if request.client else "?"))
    return request.client.host if request.client else "?"


def rate_limit(request: Request, max_hits: int = 20, window: int = 600):
    ip = _real_ip(request)
    now = time.time()
    # SL5-7: prune IPs whose hits have all expired, so this table can't
    # grow by one permanent entry per unique visitor on a long-lived
    # server. Only swept once the table is actually large.
    if len(_hits) > 4096:
        for _k in [k for k, v in _hits.items()
                   if not v or now - max(v) >= window]:
            _hits.pop(_k, None)
    keep = [t for t in _hits[ip] if now - t < window]
    if len(keep) >= max_hits:
        # SL4-2: log rejections with real IP + path
        log.warning("rate-limit 429: ip=%s path=%s", ip, request.url.path)
        raise HTTPException(429, "Too many requests — please slow down and retry.")
    keep.append(now)
    _hits[ip] = keep


def require_admin(request: Request):
    # When the Cloudflare Tunnel is on, all public traffic arrives as
    # localhost — so the localhost bypass must NOT apply then.
    tunneled = bool(config.get("tunnel", {}).get("enabled"))
    host = request.client.host if request.client else ""
    if not tunneled and host in ("127.0.0.1", "::1", "localhost"):
        return True
    key = request.headers.get("X-Admin-Key", "")
    expected = config.get("admin_key") or ""
    ok = False
    if expected and key:
        # SL6-2: compare_digest raises TypeError on non-ASCII str input
        # (a latin-1-decoded header byte >= 0x80) — that escaped as a
        # 500. The briefing-token check already guards this; mirror it.
        try:
            ok = hmac.compare_digest(key, expected)
        except TypeError:
            ok = False
    if ok:
        return True
    # SL6-3: throttle FAILED admin attempts per IP. Successful admin
    # use is never counted (the console legitimately makes many calls);
    # guessing the key is capped at 20 failures per 10 minutes per IP.
    ip = _real_ip(request)
    now = time.time()
    fails = [t for t in _admin_fails[ip] if now - t < 600]
    fails.append(now)
    _admin_fails[ip] = fails
    if len(fails) > 20:
        log.warning("admin 429 throttled: ip=%s path=%s", ip, request.url.path)
        raise HTTPException(429, "Too many failed admin attempts.")
    # SL4-2: log denied admin attempts with real IP + path
    log.warning("admin 403 denied: ip=%s path=%s", _real_ip(request),
                request.url.path)
    raise HTTPException(403, "Admin access denied.")


# ------------------------------------------------------------------ background refresh
async def _refresh_loop(name, minutes, coro, *args):
    await asyncio.sleep(7)  # stagger startup
    t = max(1, int(minutes))
    while True:
        try:
            store[name] = await coro(*args)
            log.info("refreshed %s (%s)", name, store[name].get("status"))
        except Exception as e:  # never kill the loop
            log.exception("refresh %s failed", name)
            store[name]["status"] = "error"
            store[name]["error"] = f"{type(e).__name__}: {e}"
        await asyncio.sleep(t * 60)


def _load_briefing():
    try:
        if BRIEFING_PATH.exists():
            data = json.loads(BRIEFING_PATH.read_text(encoding="utf-8"))
            # SL6-4: only a JSON object is a briefing. A hand-edited or
            # truncated file holding a list/scalar used to be stored
            # as-is and then 500'd /news (no .sections on a list).
            # Ingest already enforces this shape; enforce it on load.
            if not isinstance(data, dict):
                log.warning("briefing file is %s, not an object; ignoring it",
                            type(data).__name__)
                return
            store["briefing"] = data
            log.info("loaded briefing for %s", store["briefing"].get("date"))
    except Exception as e:
        log.warning("briefing load failed: %s", e)


@app.on_event("startup")
async def _startup():
    global STARTED_AT
    STARTED_AT = datetime.now(timezone.utc)
    await init_db()
    _load_briefing()
    fcfg, to = config["feeds"], config["feeds"]["request_timeout_seconds"]
    asyncio.create_task(_refresh_loop("threat", fcfg["threat_refresh_minutes"],
                                      feeds.fetch_threat, to,
                                      config["threat_feeds"]["abuse_ch_auth_key"]))
    asyncio.create_task(_refresh_loop("geo", fcfg["geo_refresh_minutes"],
                                      feeds.fetch_geopolitical,
                                      config["rss"]["geopolitical"], to))
    asyncio.create_task(_refresh_loop("news", fcfg["news_refresh_minutes"],
                                      feeds.fetch_news_sections,
                                      config["rss"]["news_sections"], to))
    log.info("Sentinel Live Server started (frozen=%s)", FROZEN)


# ------------------------------------------------------------------ pages
def _ctx(request: Request, **kw):
    base = {"request": request, "now": _utcnow()}
    base.update(kw)
    return base


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", _ctx(
        request, threat=store["threat"], geo=store["geo"], news=store["news"]))


@app.get("/threat-map", response_class=HTMLResponse)
async def threat_map(request: Request):
    return templates.TemplateResponse(request, "threat_map.html", _ctx(request))


@app.get("/geopolitical", response_class=HTMLResponse)
async def geopolitical(request: Request):
    return templates.TemplateResponse(request, "geopolitical.html", _ctx(request))


@app.get("/flights", response_class=HTMLResponse)
async def flights_page(request: Request, q: str = ""):
    result, error, key_missing = None, None, False
    if q.strip():
        api_key = (config["flight_api"].get("api_key") or "").strip()
        if not api_key:
            key_missing = True
        else:
            # SL5-6: each lookup spends paid flight-API quota — cap
            # per-IP lookups like the other public endpoints.
            rate_limit(request)
            result, error = await feeds.lookup_flight(
                q.strip(), api_key, config["feeds"]["request_timeout_seconds"])
    return templates.TemplateResponse(request, "flights.html", _ctx(
        request, q=q, result=result, error=error, key_missing=key_missing,
        airport_coords=feeds.AIRPORT_COORDS))


@app.get("/news", response_class=HTMLResponse)
async def news_page(request: Request):
    return templates.TemplateResponse(request, "news.html", _ctx(
        request, news=store["news"], briefing=store["briefing"]))


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    require_admin(request)
    return templates.TemplateResponse(request, "admin.html", _ctx(request))


@app.get("/health")
async def health():
    now = datetime.now(timezone.utc)
    return {"ok": True, "time": now.isoformat(timespec="seconds"), "frozen": FROZEN,
            "uptime_seconds": int((now - STARTED_AT).total_seconds()) if STARTED_AT else None,
            "feeds": {k: {"updated": v.get("updated"), "status": v.get("status")}
                      for k, v in store.items() if k != "briefing"}}


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request):
    now = datetime.now(timezone.utc)
    uptime = int((now - STARTED_AT).total_seconds()) if STARTED_AT else 0
    feeds = []
    for k, v in store.items():
        if k == "briefing":
            continue
        feeds.append({"name": k, "updated": v.get("updated"),
                      "status": v.get("status", "unknown")})
    return templates.TemplateResponse(request, "status.html", _ctx(
        request, uptime=uptime,
        started=STARTED_AT.isoformat(timespec="seconds") if STARTED_AT else None,
        feeds=feeds))


# ------------------------------------------------------------------ live-data JSON
@app.get("/api/threat-data")
async def api_threat():
    return JSONResponse(store["threat"])


@app.get("/api/geo-data")
async def api_geo():
    return JSONResponse(store["geo"])


@app.get("/api/news-data")
async def api_news():
    return JSONResponse({"news": store["news"], "briefing": store["briefing"]})


# ------------------------------------------------------------------ website backend APIs
def _client_ip(request: Request):
    # BH2-6: store the same client IP the rate limiter and the admin
    # logs already use. The raw TCP peer is always 127.0.0.1 behind the
    # Cloudflare Tunnel, so the stored column was localhost for every
    # public submission — useless for the abuse tracking it's kept for.
    return _real_ip(request)


def _s(body, key):
    """SL5-3: a JSON field as a string. A non-string value (number, list,
    object) becomes "" instead of crashing .strip()/slicing into a 500;
    paired with an isinstance(body, dict) check in each handler."""
    v = body.get(key)
    return v if isinstance(v, str) else ""


async def _json_body(request: Request):
    """Parse a request body that must be a JSON object (SL5-3).

    Factored out of the form handlers, which each repeated this exact
    parse + type check; raises the same 400 "Invalid JSON." they did,
    for both an unparseable body and a non-dict one."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    if not isinstance(body, dict):
        raise HTTPException(400, "Invalid JSON.")
    return body


@app.post("/api/contact")
async def api_contact(request: Request):
    rate_limit(request)
    body = await _json_body(request)
    name, email, message = _s(body, "name").strip(), _s(body, "email").strip(), \
                          _s(body, "message").strip()
    if not name or not email or not message or "@" not in email:
        raise HTTPException(400, "Name, a valid email, and a message are required.")
    if len(message) > 5000:
        raise HTTPException(400, "Message is too long (5000 chars max).")
    async with await _db() as db:
        await db.execute(
            "INSERT INTO contacts(created_at,name,email,subject,message,ip) VALUES(?,?,?,?,?,?)",
            (_utcnow(), name[:120], email[:160], _s(body, "subject")[:160],
             message, _client_ip(request)))
        await db.commit()
    log.info("contact submission from %s", email)
    return {"ok": True}


@app.post("/api/ticket")
async def api_ticket(request: Request):
    """Get Help ticket intake — stores a ticket, no login required."""
    rate_limit(request, max_hits=10)
    body = await _json_body(request)
    name, email, subject, message = (_s(body, k).strip()
                                    for k in ("name", "email", "subject", "message"))
    if not name or not email or "@" not in email or not subject or not message:
        raise HTTPException(400, "Name, valid email, subject, and message are required.")
    if len(message) > 8000:
        raise HTTPException(400, "Message is too long (8000 chars max).")
    prio = (_s(body, "priority") or "Normal").strip().capitalize()
    if prio not in ("Low", "Normal", "High"):
        prio = "Normal"  # public can never file Critical
    async with await _db() as db:
        cur = await db.execute(
            "INSERT INTO tickets(created_at,name,email,phone,category,priority,subject,message,ip)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (_utcnow(), name[:120], email[:160], _s(body, "phone")[:40],
             _s(body, "category")[:80], prio, subject[:200], message,
             _client_ip(request)))
        await db.commit()
        tid = cur.lastrowid
    log.info("ticket #%s opened by %s", tid, email)
    return {"ok": True, "ticket_id": tid}


@app.post("/api/newsletter")
async def api_newsletter(request: Request):
    rate_limit(request)
    body = await _json_body(request)
    email = _s(body, "email").strip()
    if not email or "@" not in email:
        raise HTTPException(400, "A valid email is required.")
    async with await _db() as db:
        try:
            await db.execute(
                "INSERT INTO newsletter(created_at,email,name,ip) VALUES(?,?,?,?)",
                (_utcnow(), email[:160], _s(body, "name")[:120], _client_ip(request)))
            await db.commit()
        except aiosqlite.IntegrityError:
            # duplicate email — still report success (no enumeration).
            # BH2-7: only the UNIQUE violation is swallowed; any other
            # DB failure must surface as an error, not a fake success.
            pass
    return {"ok": True}


# ------------------------------------------------------------------ briefing ingest
@app.post("/api/briefing")
async def api_briefing(request: Request):
    # SL6-3: a daily briefing is one post a day; the shared form limiter
    # (20/10min/IP) still caps token guessing and write spam.
    rate_limit(request)
    token = config.get("briefing_token") or ""
    if not token and config.get("tunnel", {}).get("enabled"):
        # SL5-5: no token configured + the public tunnel on = anyone on
        # the internet could inject briefing content onto /news. Fail
        # closed in exactly that configuration; the tokenless setup
        # keeps working when the server is localhost-only (same trust
        # level as the admin localhost bypass).
        raise HTTPException(403, "Briefing token is not configured.")
    if token:
        # SL3-1: token is header-only now — ?token= in the query string is
        # no longer accepted (it leaks into logs, proxies, and history).
        got = request.headers.get("X-Briefing-Token", "")
        # SL3-2: constant-time comparison (hmac already imported).
        try:
            ok = hmac.compare_digest(got, token)
        except TypeError:
            ok = False
        if not ok:
            raise HTTPException(403, "Bad briefing token.")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    # SL2-4: sections must be a dict — anything else used to 500 below.
    if not isinstance(body, dict) or not isinstance(body.get("sections"), dict):
        raise HTTPException(400, 'Body must be {"date": "...", "sections": {...}}.')
    # sanitize briefing URLs (defense against javascript: scheme XSS)
    try:
        from feeds import _safe_url
        for sec_items in body["sections"].values():
            if isinstance(sec_items, list):
                for it in sec_items:
                    if not isinstance(it, dict) or "url" not in it:
                        continue
                    # BH2-2: _safe_url assumes a string. A non-string
                    # url (number/object) used to raise here, and the
                    # blanket except below then skipped sanitizing the
                    # REST of the payload — javascript: URLs included.
                    # Blank non-strings instead, and never let one bad
                    # item disarm the pass for the others.
                    if isinstance(it["url"], str):
                        it["url"] = _safe_url(it["url"])
                    elif it["url"]:
                        it["url"] = ""
    except Exception:
        pass
    body["ingested_at"] = _utcnow()
    BRIEFING_PATH.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    store["briefing"] = body
    log.info("briefing ingested for %s", body.get("date"))
    return {"ok": True, "date": body.get("date")}


# ------------------------------------------------------------------ admin API
_TABLES = {"contacts": "contacts", "tickets": "tickets", "newsletter": "newsletter"}


def _admin_table(type: str) -> str:
    """Whitelist-resolve an admin `type` parameter to a table name —
    the one validation the admin read endpoints share."""
    table = _TABLES.get(type)
    if not table:
        raise HTTPException(400, "type must be contacts, tickets, or newsletter")
    return table


@app.get("/api/admin/submissions")
async def admin_submissions(request: Request, type: str = "tickets",
                            limit: int = 100, offset: int = 0):
    require_admin(request)
    table = _admin_table(type)
    limit = max(1, min(limit, 500))
    async with await _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
                f"SELECT * FROM {table} ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
        async with db.execute(f"SELECT COUNT(*) FROM {table}") as cur:
            total = (await cur.fetchone())[0]
    return {"ok": True, "type": type, "total": total, "rows": rows}


@app.get("/api/admin/export")
async def admin_export(request: Request, type: str = "tickets", format: str = "csv"):
    require_admin(request)
    table = _admin_table(type)
    async with await _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(f"SELECT * FROM {table} ORDER BY id DESC") as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    if format == "json":
        return JSONResponse({"ok": True, "type": type, "rows": rows})
    buf = io.StringIO()
    if rows:
        fields = list(rows[0].keys())
        w = csv.writer(buf)
        w.writerow(fields)
        # SL5-4: spreadsheet formula injection — a stored submission
        # whose cell starts with =, +, -, @ (or tab/CR) is executed as a
        # formula when the export is opened in Excel/Sheets. Prefix
        # those cells with a quote so they stay inert text.
        # SL6-5: also catch the formula char hidden behind leading
        # spaces/tabs ("  =..."), which Sheets/Excel still evaluate.
        def _csv_safe(v):
            if not isinstance(v, str) or not v:
                return v
            if v[:1] in ("=", "+", "-", "@", "\t", "\r") or \
                    v.lstrip(" \t")[:1] in ("=", "+", "-", "@"):
                return "'" + v
            return v

        w.writerows([_csv_safe(r[k]) for k in fields] for r in rows)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinel-{type}.csv"})


@app.patch("/api/admin/tickets/{ticket_id}")
async def admin_ticket_update(request: Request, ticket_id: int):
    require_admin(request)
    body = await _json_body(request)
    status = _s(body, "status").strip().lower()
    if status not in ("new", "open", "in_progress", "resolved", "closed"):
        raise HTTPException(400, "Invalid status.")
    async with await _db() as db:
        cur = await db.execute(
            "UPDATE tickets SET status=?, admin_notes=? WHERE id=?",
            (status, _s(body, "admin_notes")[:2000], ticket_id))
        await db.commit()
        changed = cur.rowcount
    if not changed:
        # BH2-3: the update matched no ticket — say so instead of
        # reporting (and logging) a success that never happened.
        raise HTTPException(404, "Ticket not found.")
    log.info("ticket #%s -> %s (admin)", ticket_id, status)
    return {"ok": True, "id": ticket_id, "status": status}


# ------------------------------------------------------------------ optional static site
_SITE_DIR = APP_DIR / "site"
if _SITE_DIR.is_dir():
    # Mounted LAST so /api/*, /threat-map, etc. keep priority.
    app.mount("/", StaticFiles(directory=_SITE_DIR, html=True), name="site")
    log.info("serving static site from %s", _SITE_DIR)


# ------------------------------------------------------------------ entry
if __name__ == "__main__":
    import uvicorn
    srv = config["server"]
    log.info("starting uvicorn on %s:%s", srv["host"], srv["port"])
    uvicorn.run(app, host=srv["host"], port=int(srv["port"]), log_level="warning")
