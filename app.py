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
    "cors_origins": ["*"],
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
    # deep-merge defaults so missing keys never crash the app
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    def _merge(dst, src):
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                _merge(dst[k], v)
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

# ------------------------------------------------------------------ app
app = FastAPI(title="Sentinel Live Server", docs_url=None, redoc_url=None,
              openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get("cors_origins") or [],
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)
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
    db = await aiosqlite.connect(DB_PATH, timeout=30)
    await db.execute("PRAGMA journal_mode=WAL")
    return db


async def init_db():
    async with await _db() as db:
        await db.executescript(SCHEMA)
        await db.commit()
    log.info("SQLite ready at %s", DB_PATH)


def _utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ guards
_hits = defaultdict(list)


def _real_ip(request: Request):
    # Behind the Cloudflare Tunnel every connection looks like localhost —
    # use the real client IP Cloudflare reports instead.
    if config.get("tunnel", {}).get("enabled"):
        return (request.headers.get("CF-Connecting-IP")
                or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or (request.client.host if request.client else "?"))
    return request.client.host if request.client else "?"


def rate_limit(request: Request, max_hits: int = 20, window: int = 600):
    ip = _real_ip(request)
    now = time.time()
    keep = [t for t in _hits[ip] if now - t < window]
    if len(keep) >= max_hits:
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
    if expected and key and hmac.compare_digest(key, expected):
        return True
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
            store["briefing"] = json.loads(BRIEFING_PATH.read_text(encoding="utf-8"))
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
    return request.client.host if request.client else ""


@app.post("/api/contact")
async def api_contact(request: Request):
    rate_limit(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    name, email, message = (body.get("name") or "").strip(), (body.get("email") or "").strip(), \
                          (body.get("message") or "").strip()
    if not name or not email or not message or "@" not in email:
        raise HTTPException(400, "Name, a valid email, and a message are required.")
    if len(message) > 5000:
        raise HTTPException(400, "Message is too long (5000 chars max).")
    async with await _db() as db:
        await db.execute(
            "INSERT INTO contacts(created_at,name,email,subject,message,ip) VALUES(?,?,?,?,?,?)",
            (_utcnow(), name[:120], email[:160], (body.get("subject") or "")[:160],
             message, _client_ip(request)))
        await db.commit()
    log.info("contact submission from %s", email)
    return {"ok": True}


@app.post("/api/ticket")
async def api_ticket(request: Request):
    """Get Help ticket intake — stores a ticket, no login required."""
    rate_limit(request, max_hits=10)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    name, email, subject, message = ((body.get(k) or "").strip()
                                    for k in ("name", "email", "subject", "message"))
    if not name or not email or "@" not in email or not subject or not message:
        raise HTTPException(400, "Name, valid email, subject, and message are required.")
    if len(message) > 8000:
        raise HTTPException(400, "Message is too long (8000 chars max).")
    prio = (body.get("priority") or "Normal").strip().capitalize()
    if prio not in ("Low", "Normal", "High"):
        prio = "Normal"  # public can never file Critical
    async with await _db() as db:
        cur = await db.execute(
            "INSERT INTO tickets(created_at,name,email,phone,category,priority,subject,message,ip)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (_utcnow(), name[:120], email[:160], (body.get("phone") or "")[:40],
             (body.get("category") or "")[:80], prio, subject[:200], message,
             _client_ip(request)))
        await db.commit()
        tid = cur.lastrowid
    log.info("ticket #%s opened by %s", tid, email)
    return {"ok": True, "ticket_id": tid}


@app.post("/api/newsletter")
async def api_newsletter(request: Request):
    rate_limit(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    email = (body.get("email") or "").strip()
    if not email or "@" not in email:
        raise HTTPException(400, "A valid email is required.")
    async with await _db() as db:
        try:
            await db.execute(
                "INSERT INTO newsletter(created_at,email,name,ip) VALUES(?,?,?,?)",
                (_utcnow(), email[:160], (body.get("name") or "")[:120], _client_ip(request)))
            await db.commit()
        except Exception:
            pass  # duplicate email — still report success (no enumeration)
    return {"ok": True}


# ------------------------------------------------------------------ briefing ingest
@app.post("/api/briefing")
async def api_briefing(request: Request):
    token = config.get("briefing_token") or ""
    if token:
        got = request.headers.get("X-Briefing-Token", "") or request.query_params.get("token", "")
        if got != token:
            raise HTTPException(403, "Bad briefing token.")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    if not isinstance(body, dict) or "sections" not in body:
        raise HTTPException(400, 'Body must be {"date": "...", "sections": {...}}.')
    # sanitize briefing URLs (defense against javascript: scheme XSS)
    try:
        from feeds import _safe_url
        for sec_items in body["sections"].values():
            if isinstance(sec_items, list):
                for it in sec_items:
                    if isinstance(it, dict) and it.get("url"):
                        it["url"] = _safe_url(it["url"])
    except Exception:
        pass
    body["ingested_at"] = _utcnow()
    BRIEFING_PATH.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    store["briefing"] = body
    log.info("briefing ingested for %s", body.get("date"))
    return {"ok": True, "date": body.get("date")}


# ------------------------------------------------------------------ admin API
_TABLES = {"contacts": "contacts", "tickets": "tickets", "newsletter": "newsletter"}


@app.get("/api/admin/submissions")
async def admin_submissions(request: Request, type: str = "tickets",
                            limit: int = 100, offset: int = 0):
    require_admin(request)
    table = _TABLES.get(type)
    if not table:
        raise HTTPException(400, "type must be contacts, tickets, or newsletter")
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
    table = _TABLES.get(type)
    if not table:
        raise HTTPException(400, "type must be contacts, tickets, or newsletter")
    async with await _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(f"SELECT * FROM {table} ORDER BY id DESC") as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    if format == "json":
        return JSONResponse({"ok": True, "type": type, "rows": rows})
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinel-{type}.csv"})


@app.patch("/api/admin/tickets/{ticket_id}")
async def admin_ticket_update(request: Request, ticket_id: int):
    require_admin(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    status = (body.get("status") or "").strip().lower()
    if status not in ("new", "open", "in_progress", "resolved", "closed"):
        raise HTTPException(400, "Invalid status.")
    async with await _db() as db:
        await db.execute("UPDATE tickets SET status=?, admin_notes=? WHERE id=?",
                         (status, (body.get("admin_notes") or "")[:2000], ticket_id))
        await db.commit()
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
