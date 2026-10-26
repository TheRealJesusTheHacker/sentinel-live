#!/usr/bin/env python3
"""Sentinel Live Server — Sentinel Safeguard LLC.

Single-file Windows service (built with PyInstaller --onefile --noconsole).
Serves:
  * the public website frontend (from ./site/ when present)
  * 4 live pages: /threat-map  /geopolitical  /flights  /news
  * website backend APIs: contact form, Get Help tickets, newsletter signup
  * admin API + page (localhost-only, or X-Admin-Key)
  * optional HackProof payments pass-through (config-gated, default off)
All persistent storage is an embedded SQLite file next to the exe.
Logs go to ./logs/server.log (there is no console in the .exe build).
"""
import asyncio
import hashlib
import hmac
import csv
import html
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover — zoneinfo is stdlib on py3.9+
    ZoneInfo = None
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import quote, urlparse
from xml.sax.saxutils import escape as _xml_escape

import aiosqlite
import httpx
import yaml
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, Response, StreamingResponse)
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
    # Optional Cloudflare Turnstile bot check on the public forms
    # (default OFF). When enabled AND a secret key is set, the three
    # public POST handlers (/api/contact, /api/ticket, /api/newsletter)
    # verify the form's cf-turnstile-response token with Cloudflare
    # server-side before anything is stored. Disabled, or enabled with
    # no secret configured, the handlers behave exactly as before.
    "turnstile": {"enabled": False, "secret_key": ""},
    "briefing_token": "",
    # REMEDIATION 5a (2026-10-26): the admin key is stored ONLY as its
    # SHA-256 hex digest in `admin_key_sha256` — a config read alone no
    # longer yields the key. `admin_key` (plaintext) is a DEPRECATED
    # transition field: it is honored only while no hash is configured,
    # so a box can deploy this code before its config is migrated, and
    # tools/hash_admin_key.py converts + removes it. Once a hash is
    # configured it takes precedence and the plaintext field is ignored
    # for authentication. New configs must use the hash form only.
    "admin_key": "",
    "admin_key_sha256": "",
    # Optional HackProof payments pass-through (default OFF): when enabled,
    # the three public payments routes are proxied to the payments service
    # running on this same machine (see the proxy section below).
    "hackproof_payments": {"enabled": False,
                           "upstream": "http://127.0.0.1:8787"},
    # SL6-1: default is NO cross-origin access. The old default of ["*"]
    # combined with the localhost admin bypass let any website the owner
    # visited on the server host read /api/admin/* responses out of the local
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
    hpcfg = config.get("hackproof_payments")
    if isinstance(hpcfg, dict):
        # Only a literal true enables the pass-through — a truthy string
        # from a hand-edited config must not silently open the routes.
        if not isinstance(hpcfg.get("enabled"), bool):
            log.warning("config: hackproof_payments.enabled invalid (%r); "
                        "using default %r",
                        hpcfg.get("enabled"),
                        DEFAULT_CONFIG["hackproof_payments"]["enabled"])
            hpcfg["enabled"] = DEFAULT_CONFIG["hackproof_payments"]["enabled"]
        _up = hpcfg.get("upstream")
        # BH2-10: the pass-through is defined as fronting a service on
        # THIS machine — so the upstream must be a bare loopback origin:
        # http(s)://127.0.0.1 | ::1 | localhost with an optional port,
        # and nothing else. The old check (any string starting with
        # http://) accepted http://169.254.169.254/..., arbitrary remote
        # hosts, userinfo that silently retargets the host
        # (http://127.0.0.1:8787@evil.example), and path prefixes that
        # reshape every proxied route — with request bodies forwarded
        # to unauthenticated public callers, a non-loopback upstream
        # turns this server into an SSRF relay for those routes.
        _up_ok = False
        if isinstance(_up, str):
            try:
                _p = urlparse(_up)
                _up_ok = (
                    _p.scheme in ("http", "https")
                    and (_p.hostname or "") in ("127.0.0.1", "::1",
                                                 "localhost")
                    and _p.username is None and _p.password is None
                    and _p.path in ("", "/")
                    and not _p.query and not _p.fragment
                    and (_p.port is None or 0 < _p.port < 65536))
            except ValueError:
                _up_ok = False
        if not _up_ok:
            log.warning("config: hackproof_payments.upstream invalid (%r); "
                        "using default %r", _up,
                        DEFAULT_CONFIG["hackproof_payments"]["upstream"])
            hpcfg["upstream"] = DEFAULT_CONFIG["hackproof_payments"]["upstream"]
    # S3-1: tunnel.enabled drives three trust decisions with plain
    # truthiness — _real_ip() trusting CF-Connecting-IP, the admin
    # localhost bypass switching off, and the briefing endpoint
    # failing closed without a token. A hand-edited `enabled: "false"`
    # (a quoted string) is truthy, so the server behaved as if the
    # tunnel were ON while the operator believed it OFF: localhost
    # admin locked out, and any direct caller could spoof
    # CF-Connecting-IP to pick their own rate-limit bucket. Same
    # type-confusion family as BH2-12 / the hackproof_payments.enabled
    # check above: only a literal bool is honored.
    tcfg = config.get("tunnel")
    if isinstance(tcfg, dict):
        if not isinstance(tcfg.get("enabled"), bool):
            log.warning("config: tunnel.enabled invalid (%r); "
                        "using default %r",
                        tcfg.get("enabled"),
                        DEFAULT_CONFIG["tunnel"]["enabled"])
            tcfg["enabled"] = DEFAULT_CONFIG["tunnel"]["enabled"]
    # Turnstile's `enabled` gates the public form handlers, and the
    # same S3-1 type confusion applies in mirror image: a quoted
    # `enabled: "false"` is truthy, so the bot check would turn ON
    # while the operator believed it OFF (every form submission
    # suddenly rejected). Only a literal bool is honored, and the
    # secret key must be a string.
    tscfg = config.get("turnstile")
    if isinstance(tscfg, dict):
        if not isinstance(tscfg.get("enabled"), bool):
            log.warning("config: turnstile.enabled invalid (%r); "
                        "using default %r",
                        tscfg.get("enabled"),
                        DEFAULT_CONFIG["turnstile"]["enabled"])
            tscfg["enabled"] = DEFAULT_CONFIG["turnstile"]["enabled"]
        if not isinstance(tscfg.get("secret_key"), str):
            # Sweep #6 (CodeQL py/clear-text-logging-sensitive-data):
            # never log the value of a secret-bearing key, even a
            # malformed one — log only its type.
            log.warning("config: turnstile.secret_key invalid "
                        "(type %s); using default ''",
                        type(tscfg.get("secret_key")).__name__)
            tscfg["secret_key"] = ""
    # S3-2: the remaining scalar keys are consumed with str-only
    # operations (.strip() on the flight key, header values, token
    # comparisons). A non-string value from a hand-edited config —
    # e.g. `api_key: 12345` — crashed the public /flights page with a
    # 500 on every lookup. Normalize them all to their (empty)
    # defaults, the same fail-safe the keys above get.
    srv2 = config.get("server")
    if isinstance(srv2, dict) and not isinstance(srv2.get("host"), str):
        log.warning("config: server.host invalid (%r); using default %r",
                    srv2.get("host"), DEFAULT_CONFIG["server"]["host"])
        srv2["host"] = DEFAULT_CONFIG["server"]["host"]
    for _sec, _key in (("flight_api", "api_key"),
                       ("threat_feeds", "abuse_ch_auth_key")):
        _sub = config.get(_sec)
        if isinstance(_sub, dict) and not isinstance(_sub.get(_key), str):
            # Same Sweep #6 rule: these are API/auth keys — type only.
            log.warning("config: %s.%s invalid (type %s); "
                        "using default ''",
                        _sec, _key, type(_sub.get(_key)).__name__)
            _sub[_key] = ""
    for _key in ("briefing_token", "admin_key", "admin_key_sha256"):
        if not isinstance(config.get(_key), str):
            # Same Sweep #6 rule: these are tokens — type only.
            log.warning("config: %s invalid (type %s); using default ''",
                        _key, type(config.get(_key)).__name__)
            config[_key] = ""
    # REMEDIATION 5a: the stored admin hash must be exactly one SHA-256
    # hex digest. Anything else (truncated, tampered with non-hex
    # characters, a pasted key instead of its hash) fails CLOSED: the
    # hash is discarded, so no presented key can authenticate against
    # it. Only the shape is logged, never the value.
    _ah = config.get("admin_key_sha256") or ""
    if _ah:
        if re.fullmatch(r"[0-9a-fA-F]{64}", _ah):
            config["admin_key_sha256"] = _ah.lower()
        else:
            log.warning("config: admin_key_sha256 invalid "
                        "(not a 64-char hex SHA-256 digest); "
                        "using default ''")
            config["admin_key_sha256"] = ""
    if config.get("admin_key_sha256") and config.get("admin_key"):
        log.warning("config: both admin_key (plaintext) and "
                    "admin_key_sha256 are set; the hash takes "
                    "precedence — remove the plaintext field "
                    "manually (the migration tool refuses "
                    "ambiguous configs rather than guess)")
    elif config.get("admin_key"):
        log.warning("config: admin_key is stored in plaintext "
                    "(deprecated); run tools/hash_admin_key.py to "
                    "migrate this config to admin_key_sha256")
    # BH2-12: CORS lockdown regression guard. Starlette treats the
    # string "*" as a wildcard allowlist (`"*" in allow_origins` is a
    # substring check on a str), so a hand-edited `cors_origins: "*"`
    # — or any non-list value — silently reopened cross-origin access
    # (the SL6-1 incident shape). Only a list of explicit origin
    # strings is honored, and a "*" entry inside a list is dropped:
    # wildcard CORS is never valid for this server (config docs and
    # README both say so) because of the localhost admin bypass.
    _cors = config.get("cors_origins")
    if not isinstance(_cors, list) or \
            any(not isinstance(_o, str) for _o in _cors):
        log.warning("config: cors_origins invalid (%r); using []", _cors)
        config["cors_origins"] = []
    elif "*" in _cors:
        log.warning("config: cors_origins contains '*'; dropping it "
                    "(wildcard CORS is never allowed on this server)")
        config["cors_origins"] = [_o for _o in _cors if _o != "*"]


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
                                (b"content-length", str(len(body)).encode()),
                                (b"x-content-type-options", b"nosniff"),
                                (b"x-frame-options", b"DENY"),
                                (b"referrer-policy", b"same-origin")]})
        await send({"type": "http.response.body", "body": body,
                    "more_body": False})

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # SL6-6: nosniff on every response — cheap insurance against
            # MIME-sniffing a stored/uploaded body into active content.
            # BH-2026-10-23 (M-3): the header set grows up. The earlier
            # "no frame policy" call assumed the owner might embed these
            # pages in the main site — nothing embeds them (the public
            # site LINKS to the live views), and the owner's OPSEC
            # order supersedes: deny framing, trim the referrer our
            # visitors leak to map/CDN third parties, pin HSTS, and
            # switch off device APIs no page uses. A full CSP remains a
            # separate deliberate pass (the map pages compose Leaflet /
            # Esri / Turnstile at runtime); frame-ancestors below only
            # stops OTHERS framing our pages and cannot break them.
            _MANAGED_HEADERS = {
                b"x-content-type-options": b"nosniff",
                b"x-frame-options": b"DENY",
                b"content-security-policy": b"frame-ancestors 'none'",
                b"referrer-policy": b"same-origin",
                b"strict-transport-security":
                    b"max-age=31536000; includeSubDomains",
                b"permissions-policy":
                    b"camera=(), microphone=(), geolocation=(), "
                    b"payment=(), usb=()",
            }
            _orig_send = send

            async def send(message):
                if message["type"] == "http.response.start":
                    hdrs = [(k, v) for k, v in message.get("headers", [])
                            if k.lower() not in _MANAGED_HEADERS]
                    hdrs.extend(_MANAGED_HEADERS.items())
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


# ------------------------------------------------------------------ visitor log
# PV-2026-10-23: public-visitor logging for the owner's Activity
# console. One row per GET of a public HTML page that answers 200 —
# the raw material for "all visitors and their activity" on the
# public side. Deliberately NOT logged: /api/*, the gated surfaces
# (/admin, /news, /status, /health), /internal/*, static assets,
# non-GET requests, and non-200 responses.
VISITOR_RETENTION_DAYS = 90  # owner-adjustable; pruned daily
_VISITOR_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS visitor_log("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " ts INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '',"
    " ua TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',"
    " referrer TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '',"
    " visit_id TEXT NOT NULL DEFAULT '', bot INTEGER NOT NULL DEFAULT 0)")
_VISITOR_PUBLIC_PATHS = {"/", "/operations", "/threat-map", "/geopolitical",
                         "/flights", "/report-issue", "/ticket", "/about",
                         "/services", "/who-we-protect", "/how-it-works", "/contact",
                         "/insights", "/privacy", "/assessment", "/tools",
                         "/training/phishing", "/faq", "/disclosure",
                         "/availability"}
_VISITOR_BOT_TOKENS = ("bot", "crawler", "spider", "curl", "wget",
                       "python-requests", "headless", "uptime")
_visitor_prune_state = {"last": 0.0}

try:
    _CHICAGO_TZ = ZoneInfo("America/Chicago") if ZoneInfo else timezone.utc
except Exception:
    _CHICAGO_TZ = timezone.utc


def _visitor_norm_path(raw: str) -> str:
    """Collapse the variants of one page to a single label: the
    homepage answers at / and /index.html, and the static pages at
    /report-issue and /report-issue/ — one row label each."""
    p = raw or "/"
    if p == "/index.html":
        return "/"
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/") or "/"
    return p


def _visitor_is_public(path: str) -> bool:
    """Public-page test for the visitor log: the fixed set above,
    plus Insights post pages — each post is logged under its own
    path so per-post reads show in the console. (The middleware
    only records 200s, so an unknown slug still logs nothing.)"""
    if path in _VISITOR_PUBLIC_PATHS:
        return True
    return bool(re.fullmatch(r"/insights/[a-z0-9][a-z0-9-]*", path))


def _chicago_day_start_epoch(days_ago: int = 0) -> int:
    """Epoch seconds of local midnight (America/Chicago) for today
    or an earlier day — "today" in the console is the owner's day,
    not UTC's. Wall-clock arithmetic keeps this DST-correct."""
    now_local = datetime.now(timezone.utc).astimezone(_CHICAGO_TZ)
    midnight = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
    return int((midnight - timedelta(days=days_ago)).timestamp())


def _visitor_insert_sync(row):
    """One visitor row, written from a daemon thread AFTER the
    response has fully left, so logging can never delay or break
    page serving. Tradeoff, stated plainly: a process crash in the
    milliseconds between serving and the thread's commit can lose
    that one row — acceptable for analytics, and the reason this is
    a fire-and-forget thread instead of a buffered queue with its
    own failure modes. Any error drops the row silently."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        try:
            conn.execute(_VISITOR_TABLE_SQL)
            conn.execute(
                "INSERT INTO visitor_log(ts,ip,ua,path,referrer,country,"
                "visit_id,bot) VALUES(?,?,?,?,?,?,?,?)", row)
            # Piggyback the retention prune at most once a day.
            now = time.monotonic()
            if now - _visitor_prune_state["last"] >= 86400:
                _visitor_prune_state["last"] = now
                cutoff = int(time.time()) - VISITOR_RETENTION_DAYS * 86400
                cur = conn.execute("DELETE FROM visitor_log WHERE ts < ?",
                                   (cutoff,))
                if cur.rowcount:
                    log.info("visitor log: pruned %d rows older than %d "
                             "days", cur.rowcount, VISITOR_RETENTION_DAYS)
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass  # a logging failure must never surface to a visitor


def _prune_visitor_log_sync() -> int:
    """Startup prune of rows past the retention window."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        try:
            conn.execute(_VISITOR_TABLE_SQL)
            cutoff = int(time.time()) - VISITOR_RETENTION_DAYS * 86400
            cur = conn.execute("DELETE FROM visitor_log WHERE ts < ?",
                               (cutoff,))
            n = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if n:
            log.info("visitor log: pruned %d rows older than %d days "
                     "at startup", n, VISITOR_RETENTION_DAYS)
        return n
    except Exception:
        return 0


class _VisitorLogMiddleware:
    """Pure-ASGI visitor logger. Lives at the ASGI layer because the
    public pages are split between explicit routes (/, /operations,
    the three live views) and the trailing StaticFiles mount
    (/report-issue, /ticket, /index.html) — this is the one hook that
    sees every public page exactly once, with its final status."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "GET":
            await self.app(scope, receive, send)
            return
        path = _visitor_norm_path(scope.get("path", ""))
        if not _visitor_is_public(path):
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        # Visit grouping: the svid first-party cookie. A valid one
        # (128-bit hex we issued) groups the visit; anything else is
        # replaced — a visitor-supplied value is never trusted into
        # the log as-is.
        visit_id = ""
        for part in headers.get("cookie", "").split(";"):
            name, _, val = part.strip().partition("=")
            if name == "svid":
                visit_id = val.strip()
        if not re.fullmatch(r"[0-9a-f]{32}", visit_id or ""):
            visit_id = secrets.token_hex(16)
        # The client IP exactly as the rest of the app resolves it
        # (_real_ip semantics): CF-Connecting-IP behind the tunnel,
        # the TCP peer otherwise.
        peer = scope.get("client")[0] if scope.get("client") else "?"
        if config.get("tunnel", {}).get("enabled"):
            ip = headers.get("cf-connecting-ip") or peer
        else:
            ip = peer
        ua = headers.get("user-agent", "")
        ua_l = ua.lower()
        row = (int(time.time()), ip[:64], ua[:512], path,
               headers.get("referer", "")[:512],
               headers.get("cf-ipcountry", "")[:8], visit_id,
               1 if any(t in ua_l for t in _VISITOR_BOT_TOKENS) else 0)
        state = {"status": None, "logged": False}

        async def send_wrap(message):
            if message["type"] == "http.response.start":
                state["status"] = message.get("status")
                if message.get("status") == 200:
                    hdrs = list(message.get("headers", []))
                    # 30-minute rolling visit window: the cookie is
                    # re-issued (same value, fresh expiry) on every
                    # logged page, so a visit is a burst of activity
                    # no more than 30 idle minutes apart.
                    hdrs.append(
                        (b"set-cookie",
                         f"svid={visit_id}; Path=/; Max-Age=1800; "
                         "HttpOnly; Secure; SameSite=Lax".encode("latin-1")))
                    message = dict(message, headers=hdrs)
            await send(message)
            if state["status"] == 200 and not state["logged"] and (
                    message["type"] == "http.response.pathsend"
                    or (message["type"] == "http.response.body"
                        and not message.get("more_body"))):
                state["logged"] = True
                threading.Thread(target=_visitor_insert_sync, args=(row,),
                                 daemon=True).start()

        await self.app(scope, receive, send_wrap)


# ------------------------------------------------------------------ app
app = FastAPI(title="Sentinel Safeguard Server", docs_url=None, redoc_url=None,
              openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get("cors_origins") or [],
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    # BH-2026-10-23 (L-3): was ["*"] — the app only ever reads these
    # three headers cross-origin; allow exactly them.
    allow_headers=["Content-Type", "X-Admin-Key", "X-Briefing-Token"],
)
# outermost: reject oversized bodies before anything else touches them
app.add_middleware(_BodySizeLimitMiddleware)
# PV-2026-10-23: visitor logging wraps everything (added last, so it
# runs outermost and sees each response's final status + headers).
app.add_middleware(_VisitorLogMiddleware)
app.mount("/static", StaticFiles(directory=res_dir("static")), name="static")
templates = Jinja2Templates(directory=str(res_dir("templates")))


# Site polish 2026-10-25: a browser that navigates to a missing page
# gets the site's own themed 404 (in the shared chrome) instead of a
# bare JSON line. The carve-out is deliberately narrow so no API or
# probing behavior can change: ONLY a 404, ONLY on a GET/HEAD, ONLY
# when the client explicitly accepts text/html (browsers navigating;
# API clients and the test suite's default */* are untouched), and
# NEVER on /api/* (JSON contract) or /internal/* (the anti-probing
# surface answers the same plain 404 to everything, browsers
# included). Every other HTTP error keeps Starlette's default JSON
# shape, headers included.
from starlette.exceptions import HTTPException as _StarletteHTTPException


@app.exception_handler(_StarletteHTTPException)
async def _http_exception_handler(request: Request, exc):
    if (exc.status_code == 404 and request.method in ("GET", "HEAD")
            and not request.url.path.startswith(("/api", "/internal"))
            and "text/html" in request.headers.get("accept", "").lower()):
        return templates.TemplateResponse(
            request, "404.html", {"request": request, "now": _utcnow()},
            status_code=404)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                        headers=getattr(exc, "headers", None))


@app.exception_handler(500)
async def _server_error_handler(request: Request, exc):
    # ESTATE-2026-10-25 (polish): the themed-404 pattern extended to
    # server errors. Same narrow carve-out as the 404 above: only a
    # browser navigation (GET/HEAD accepting text/html, never /api/*
    # or /internal/*) gets the themed page; every other caller keeps
    # the plain JSON shape. The exception itself is logged by the
    # server layer as before — this handler only shapes the reply.
    if (request.method in ("GET", "HEAD")
            and not request.url.path.startswith(("/api", "/internal"))
            and "text/html" in request.headers.get("accept", "").lower()):
        return templates.TemplateResponse(
            request, "500.html", {"request": request, "now": _utcnow()},
            status_code=500)
    return JSONResponse({"detail": "Internal Server Error"},
                        status_code=500)

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
  subject TEXT DEFAULT '', message TEXT NOT NULL, ip TEXT DEFAULT '',
  service TEXT DEFAULT '', pref_date TEXT DEFAULT '',
  pref_window TEXT DEFAULT '');
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
CREATE TABLE IF NOT EXISTS visitor_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL, ip TEXT NOT NULL DEFAULT '',
  ua TEXT NOT NULL DEFAULT '', path TEXT NOT NULL DEFAULT '',
  referrer TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '',
  visit_id TEXT NOT NULL DEFAULT '', bot INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_visitor_log_ts ON visitor_log(ts);
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
            # ESTATE-2026-10-25 (contact booking upgrade): the three
            # booking fields are additive columns on contacts. Fresh
            # databases get them from SCHEMA above; existing ones get
            # them here. SQLite has no ADD COLUMN IF NOT EXISTS, so a
            # duplicate-column error simply means "already migrated".
            for _col in ("service", "pref_date", "pref_window"):
                try:
                    await db.execute(
                        f"ALTER TABLE contacts ADD COLUMN {_col} "
                        "TEXT DEFAULT ''")
                except Exception:
                    pass
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


def _is_tunneled(request: Request) -> bool:
    # BH-2026-10-23 (H-2): the tunnel.enabled config bool used to be the
    # ONLY evidence the localhost bypass consulted — one stale bool
    # between "local exe" and "proxied production" would have silently
    # disabled admin auth for every proxied visitor. Treat the presence
    # of Cloudflare's CF-Connecting-IP header as tunnel evidence too:
    # cloudflared always sets it; a direct loopback request never
    # carries it. Fail closed on evidence, not on config alone.
    if bool(config.get("tunnel", {}).get("enabled")):
        return True
    return request.headers.get("CF-Connecting-IP") is not None


def require_admin(request: Request):
    # When the Cloudflare Tunnel is on, all public traffic arrives as
    # localhost — so the localhost bypass must NOT apply then.
    tunneled = _is_tunneled(request)
    host = request.client.host if request.client else ""
    if not tunneled and host in ("127.0.0.1", "::1", "localhost"):
        return True
    key = request.headers.get("X-Admin-Key", "")
    expected_hash = config.get("admin_key_sha256") or ""
    legacy_key = config.get("admin_key") or ""
    ok = False
    if key and (expected_hash or legacy_key):
        # REMEDIATION 5a: never compare the presented key against a
        # stored plaintext value. Hash the presented key and compare
        # HEX DIGESTS with hmac.compare_digest (constant-time). In
        # hash mode the stored value is already the digest; in the
        # deprecated transition mode the legacy plaintext is hashed
        # in memory only, so both paths compare digest-to-digest.
        # Hashing first also removes the SL6-2 hazard by construction:
        # a non-ASCII header value encodes and hashes instead of
        # raising TypeError out of compare_digest — it simply does
        # not match (same 403 as before, never a 500).
        try:
            presented = hashlib.sha256(key.encode("utf-8")).hexdigest()
            if expected_hash:
                ok = hmac.compare_digest(presented,
                                         str(expected_hash).lower())
            else:
                legacy_digest = hashlib.sha256(
                    str(legacy_key).encode("utf-8")).hexdigest()
                ok = hmac.compare_digest(presented, legacy_digest)
        except (TypeError, UnicodeError):
            ok = False
    if ok:
        return True
    # SL6-3: throttle FAILED admin attempts per IP. Successful admin
    # use is never counted (the console legitimately makes many calls);
    # guessing the key is capped at 20 failures per 10 minutes per IP.
    ip = _real_ip(request)
    now = time.time()
    # BH2-15: same unbounded-growth prune as _hits (SL5-7) — this table
    # otherwise keeps one entry per IP that ever failed an admin check.
    if len(_admin_fails) > 4096:
        for _k in [k for k, v in _admin_fails.items()
                   if not v or now - max(v) >= 600]:
            _admin_fails.pop(_k, None)
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
            # BH-2026-10-23 (M-4): the store dict is served verbatim by
            # the public data APIs — exception DETAIL (upstream URLs,
            # provider messages) is recon an attacker gets for free.
            # Class name only in public; the full exception is in the
            # log.exception line above.
            store[name]["error"] = type(e).__name__
        await asyncio.sleep(t * 60)


def _sanitize_briefing_urls(data):
    """The ingest-time _safe_url pass (BH2-2 semantics), shared.
    BH-2026-10-23 (L-4): _load_briefing used to serve a briefing file
    exactly as found on disk — a briefing written by any path other
    than the ingest endpoint skipped the scheme sanitiser entirely."""
    try:
        from feeds import _safe_url
        sections = data.get("sections") if isinstance(data, dict) else None
        if not isinstance(sections, dict):
            return
        for sec_items in sections.values():
            if isinstance(sec_items, list):
                for it in sec_items:
                    if not isinstance(it, dict) or "url" not in it:
                        continue
                    if isinstance(it["url"], str):
                        it["url"] = _safe_url(it["url"])
                    elif it["url"]:
                        it["url"] = ""
    except Exception:
        pass


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
            _sanitize_briefing_urls(data)
            store["briefing"] = data
            log.info("loaded briefing for %s", store["briefing"].get("date"))
    except Exception as e:
        log.warning("briefing load failed: %s", e)


@app.on_event("startup")
async def _startup():
    global STARTED_AT
    STARTED_AT = datetime.now(timezone.utc)
    await init_db()
    # PV-2026-10-23: visitor-log retention prune (also piggybacked
    # on writes, at most once a day — see _visitor_insert_sync).
    await asyncio.to_thread(_prune_visitor_log_sync)
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
    # BH-2026-10-23 (L-1): turnstile enabled with no secret configured
    # silently no-ops the form bot check — say so loudly at startup
    # instead of letting the site look protected when it is not.
    _tscfg = config.get("turnstile") or {}
    if _tscfg.get("enabled") and not (_tscfg.get("secret_key") or "").strip():
        log.warning("turnstile is ENABLED but no secret_key is set — "
                    "public form bot checks are NOT being enforced")
    log.info("Sentinel Live Server started (frozen=%s)", FROZEN)


# ------------------------------------------------------------------ insights
# Insights (owner order 2026-10-25): the site's public notebook.
# Posts are DATA, not hand-built pages: one Markdown file per post
# in the insights/ directory — YAML front matter (slug, date,
# title, dek, optional weight) over a body in a small Markdown
# subset (## / ### headings, "- " list items, **bold**, links).
# The index generates from the files, newest first; a post page
# renders from its file. Publishing is "add one file and deploy" —
# no template surgery — and nothing auto-publishes: a file only
# exists once the owner has approved the post in the content
# cadence. Sources are the daily briefings (distilled,
# outsider-safe) and the owner's story posts (2x/day cadence);
# the gated /news briefing is a different, private layer and is
# never linked or referenced from here.
_INSIGHTS_DIR = res_dir("insights")
_insights_cache = {"key": None, "posts": []}


def _insight_inline(text: str) -> str:
    """Inline subset on ALREADY-escaped text: links, then bold.
    A link renders only for a site-relative or https target, so a
    post file can never smuggle a javascript: href into the page."""
    text = re.sub(r"\[([^\]]+)\]\((https://[^)\s]+|/[^)\s]*)\)",
                  r'<a href="\2">\1</a>', text)
    return re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)


def _insight_body_html(body: str) -> str:
    """Render the body subset to HTML. Every line is HTML-escaped
    first, so the only markup in the output is the markup this
    function itself emits."""
    out, para, items = [], [], []

    def flush_para():
        if para:
            out.append("<p>" + _insight_inline(" ".join(para)) + "</p>")
            para.clear()

    def flush_items():
        if items:
            out.append("<ul>" + "".join(
                "<li>" + _insight_inline(i) + "</li>"
                for i in items) + "</ul>")
            items.clear()

    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            flush_para()
            flush_items()
            continue
        esc = html.escape(line)
        if esc.startswith("### "):
            flush_para()
            flush_items()
            out.append("<h3>" + _insight_inline(esc[4:]) + "</h3>")
        elif esc.startswith("## "):
            flush_para()
            flush_items()
            out.append("<h2>" + _insight_inline(esc[3:]) + "</h2>")
        elif esc.startswith("- "):
            flush_para()
            items.append(esc[2:])
        else:
            flush_items()
            para.append(esc)
    flush_para()
    flush_items()
    return "\n".join(out)


def _load_insights():
    """Parse every insights/*.md into a post dict, newest first
    (same-day posts order by weight, higher first, then slug).
    Cached on the (name, mtime) fingerprint of the directory —
    deploys restart the process, and the cache keeps repeat reads
    free. A malformed file is logged and skipped: one bad post
    can never take the notebook down."""
    if not _INSIGHTS_DIR.is_dir():
        return []
    files = sorted(_INSIGHTS_DIR.glob("*.md"))
    key = tuple((p.name, p.stat().st_mtime_ns) for p in files)
    if _insights_cache["key"] == key:
        return _insights_cache["posts"]
    posts = []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8")
            if not text.startswith("---"):
                raise ValueError("missing front matter")
            _, fm, body = text.split("---", 2)
            meta = yaml.safe_load(fm) or {}
            slug = str(meta["slug"]).strip()
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug):
                raise ValueError("bad slug: %r" % slug)
            date = str(meta["date"])
            day = datetime.strptime(date, "%Y-%m-%d").date()
            posts.append({
                "slug": slug,
                "date": date,
                "date_long": "%s %d, %d" % (
                    day.strftime("%B"), day.day, day.year),
                "title": str(meta["title"]).strip(),
                "dek": str(meta["dek"]).strip(),
                "weight": int(meta.get("weight") or 0),
                "html": _insight_body_html(body),
                "url": "/insights/" + slug,
            })
        except Exception:
            log.warning("insights: skipping malformed post file %s",
                        p.name)
    posts.sort(key=lambda x: (x["date"], x["weight"], x["slug"]),
               reverse=True)
    _insights_cache["key"] = key
    _insights_cache["posts"] = posts
    return posts


# ------------------------------------------------------------------ pages
def _ctx(request: Request, **kw):
    base = {"request": request, "now": _utcnow()}
    base.update(kw)
    return base


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # Front door = the public marketing homepage (owner order
    # 2026-10-23: "Homepage should be front door"). When the static
    # site is present, its index.html IS the homepage — serve the
    # exact bytes /index.html serves. Without a site dir (e.g. the
    # packaged server build), fall back to the operations landing
    # so / still works.
    home = _SITE_DIR / "index.html"
    if home.is_file():
        return FileResponse(home, media_type="text/html")
    return _operations_page(request)


@app.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    # About the Company (owner order 2026-10-25): a static-content
    # page in the shared chrome — who the company is, who leads it,
    # what it does, and the proof that is already public. Content is
    # factual-only by the owner's accuracy rules (no client history,
    # no testimonials, future services marked planned).
    return templates.TemplateResponse(request, "about.html", _ctx(request))


@app.get("/services", response_class=HTMLResponse)
async def services(request: Request):
    # Services (owner order 2026-10-25): the five lines of work in
    # full — what each is, who it is for, what the client walks away
    # with — in the shared chrome. Same factual-only discipline as
    # /about (no prices, no client history, no planned services
    # listed); penetration testing is framed authorized-only, and
    # the custom websites & software section is the owner's
    # developer tribute, every claim linked to its public proof.
    return templates.TemplateResponse(request, "services.html", _ctx(request))


@app.get("/who-we-protect", response_class=HTMLResponse)
async def who_we_protect(request: Request):
    # Who We Protect (owner order 2026-10-25): the named industries
    # are a focus, never a fence — the page is an INVITATION, framed
    # "built for / common calls", never a client résumé (no client
    # base is implied in any vertical; the first booking is still
    # ahead). Residential and the open-door block are the owner's
    # explicit additions: businesses AND homes, and anyone whose
    # world is not named still reads "this means you". Same
    # factual-only discipline as /about and /services.
    return templates.TemplateResponse(request, "who_we_protect.html", _ctx(request))


@app.get("/how-it-works", response_class=HTMLResponse)
async def how_it_works(request: Request):
    # How It Works (owner order 2026-10-25): the engagement process
    # stated plainly for a first-time buyer — reach out, talk and
    # look, in writing and signed before work, the work, report &
    # walkthrough, after — plus the emergencies shortcut and what
    # Sentinel asks of the client. The paperwork named is real: the
    # Engagement Letter, Scope of Work, Penetration Testing
    # Authorization, and Chain of Custody are the company's final
    # approved forms. Same factual-only discipline as /about,
    # /services, and /who-we-protect: no prices, no invented
    # response times or SLAs, no client history.
    return templates.TemplateResponse(request, "how_it_works.html", _ctx(request))


@app.get("/contact", response_class=HTMLResponse)
async def contact(request: Request):
    # Contact (owner order 2026-10-25): the dedicated contact page
    # — the homepage contact form's contract replicated exactly
    # (same fields, same Turnstile widget, same /api/contact
    # payload and success/error handling), the direct phone/email
    # block, what-to-include guidance, and the emergencies strip
    # pointing at /report-issue so the form never reads as the
    # emergency channel. No response-time promises anywhere: the
    # site states none, and this page invents none.
    return templates.TemplateResponse(request, "contact.html", _ctx(request))


@app.get("/insights/feed.xml")
async def insights_feed(request: Request):
    # ESTATE-2026-10-25 (item 7): the Insights RSS feed, built from
    # the same _load_insights() data the pages render — one source,
    # so the feed can never drift from the notebook. Registered
    # BEFORE /insights/{slug} so "feed.xml" is never read as a slug.
    from email.utils import format_datetime as _fmt_dt
    posts = _load_insights()
    items = []
    for post in posts:
        day = datetime.strptime(post["date"], "%Y-%m-%d").replace(
            tzinfo=timezone.utc)
        items.append(
            "<item><title>%s</title><link>%s%s</link>"
            "<guid isPermaLink=\"true\">%s%s</guid>"
            "<pubDate>%s</pubDate><description>%s</description></item>"
            % (_xml_escape(post["title"]), _SITE_BASE, post["url"],
               _SITE_BASE, post["url"], _fmt_dt(day),
               _xml_escape(post["dek"])))
    if posts:
        latest = datetime.strptime(posts[0]["date"], "%Y-%m-%d").replace(
            tzinfo=timezone.utc)
        built = "<lastBuildDate>%s</lastBuildDate>" % _fmt_dt(latest)
    else:
        built = ""
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<rss version="2.0"><channel>'
           "<title>Sentinel Safeguard \u2014 Insights</title>"
           "<link>%s/insights</link>"
           "<description>Plain-language security notes for Kansas "
           "City metro businesses and homes, from Sentinel "
           "Safeguard's daily watch.</description>"
           "<language>en-us</language>%s%s</channel></rss>"
           % (_SITE_BASE, built, "".join(items)))
    return Response(content=xml, media_type="application/rss+xml")


@app.get("/insights", response_class=HTMLResponse)
async def insights(request: Request):
    # Insights (owner order 2026-10-25): the public notebook —
    # outsider-safe notes distilled from the daily briefings and
    # the owner's story posts, rendered from data files in the
    # insights/ directory (see _load_insights). The gated /news
    # briefing is never linked or referenced here: this is the
    # curated public layer, and every post on it passed the
    # owner's approval before its file existed.
    return templates.TemplateResponse(
        request, "insights.html", _ctx(request, posts=_load_insights()))


@app.get("/insights/{slug}", response_class=HTMLResponse)
async def insight_post(request: Request, slug: str):
    for post in _load_insights():
        if post["slug"] == slug:
            return templates.TemplateResponse(
                request, "insight_post.html", _ctx(request, post=post))
    # The app's plain 404, same shape as its other 404s — an
    # unknown note is a real 404, never a redirect or a soft 200.
    raise HTTPException(404, "Not found.")


@app.get("/privacy", response_class=HTMLResponse)
async def privacy(request: Request):
    # Privacy (owner order 2026-10-25): the site's data handling
    # stated plainly — what the forms collect, the visitor log and
    # its 90-day retention, the one cookie (svid), the named third
    # parties, and the never list. Every sentence traces to the
    # verified data-flow inventory in PRIVACY-PAGE-2026-10-25:
    # the page discloses the collection that exists and claims no
    # absence that the inventory contradicts (it never says "we
    # collect nothing", "no cookies", or "anonymous").
    return templates.TemplateResponse(request, "privacy.html", _ctx(request))


@app.get("/assessment", response_class=HTMLResponse)
async def assessment(request: Request):
    # ESTATE-2026-10-25 (item 1): the security self-assessment —
    # ten plain-language questions, scored entirely client-side.
    # NOTHING is transmitted or stored: there is no POST endpoint
    # behind this page, and the privacy page needs no new entry
    # for it (it already states the visitor log covers page views).
    return templates.TemplateResponse(request, "assessment.html",
                                      _ctx(request))


@app.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request):
    # ESTATE-2026-10-25 (item 2): the passphrase generator + the
    # transparent strength checker. Both run client-side only —
    # crypto.getRandomValues on the device, nothing sent anywhere.
    return templates.TemplateResponse(request, "tools.html",
                                      _ctx(request))


@app.get("/training/phishing", response_class=HTMLResponse)
async def training_phishing(request: Request):
    # ESTATE-2026-10-25 (item 3): spot-the-phish training. IA call
    # (recorded in the lane record): a standalone path under
    # /training/ rather than a /tools section — training is a
    # different job from the utilities, the URL reads as a course
    # address a business can be sent to directly, and /training/
    # leaves room for future rounds without crowding /tools.
    # Samples are inert mock UI rendered from text only.
    return templates.TemplateResponse(request, "training_phishing.html",
                                      _ctx(request))


@app.get("/faq", response_class=HTMLResponse)
async def faq(request: Request):
    # ESTATE-2026-10-25 (item 6): only facts already true elsewhere
    # on the site — appointment-only, authorization-first testing,
    # KC metro, the /how-it-works flow, and cost framed as what
    # drives it (scope, size, systems) with no numbers anywhere.
    return templates.TemplateResponse(request, "faq.html", _ctx(request))


@app.get("/disclosure", response_class=HTMLResponse)
async def disclosure(request: Request):
    # ESTATE-2026-10-25 (item 4): the responsible-disclosure page —
    # the human-readable companion to /.well-known/security.txt.
    return templates.TemplateResponse(request, "disclosure.html",
                                      _ctx(request))


# ------------------------------------------------------- availability
# ESTATE-2026-10-25 (item 10, built LAST per the sweep order): the
# public availability page reads the server lane's monitor log
# (contract B in estate-sweep-sections/server.md — path, JSONL
# format, and target list are FIXED there; this code consumes, it
# does not redefine). The path is overridable by environment for
# staging/tests; production uses the contract path.
AVAILABILITY_LOG_PATH = Path(
    os.environ.get("SENTINEL_AVAILABILITY_LOG")
    or "/var/lib/sentinel-status/availability.jsonl")
_AVAIL_TARGETS = [
    ("public_site", "Public website"),
    ("live_loopback", "Website server"),
    ("command_gate", "Sentinel Command gate"),
    ("command_loopback", "Command server"),
    ("mail_imap_993", "Mail \u2014 receiving"),
    ("mail_submit_587", "Mail \u2014 sending"),
    ("mail_smtp_25", "Mail \u2014 delivery"),
    ("tunnel_public_dns", "Domain name resolution"),
]
_AVAIL_WINDOW_MS = 30 * 24 * 3600 * 1000
_AVAIL_STALE_MS = 15 * 60 * 1000


def _avail_fmt_ms(ms):
    d = datetime.fromtimestamp(ms / 1000, timezone.utc).astimezone(
        _CHICAGO_TZ)
    return "%s %d, %d" % (d.strftime("%B"), d.day, d.year)


def _avail_fmt_ms_time(ms):
    d = datetime.fromtimestamp(ms / 1000, timezone.utc).astimezone(
        _CHICAGO_TZ)
    return "%s %d, %d, %s CT" % (
        d.strftime("%B"), d.day, d.year,
        d.strftime("%I:%M %p").lstrip("0"))


_availability_cache = {"key": None, "summary": None}


def _availability_summary():
    """SECAUDIT-2026-10-25: cached front for the compute below.
    /availability is a public, unauthenticated page and the raw
    compute re-reads and re-parses the whole 35-day monitor log on
    every hit — free CPU amplification for anyone who cares to
    refresh hard. Cache on the log's (path, mtime, size) plus a
    one-minute time bucket: an unchanged log is re-parsed at most
    once a minute no matter the request rate, a fresh monitor
    append invalidates immediately, and the bucket keeps the
    "stale" flag honest (it is recomputed at least once a minute
    even when the log has stopped moving)."""
    try:
        st = AVAILABILITY_LOG_PATH.stat()
        key = (str(AVAILABILITY_LOG_PATH), st.st_mtime_ns, st.st_size,
               int(time.time()) // 60)
    except Exception:
        return _availability_summary_compute()
    if _availability_cache["key"] == key:
        return _availability_cache["summary"]
    summary = _availability_summary_compute()
    _availability_cache["key"] = key
    _availability_cache["summary"] = summary
    return summary


def _availability_summary_compute():
    """Compute the availability page's data from the monitor log.

    Honesty rules (coordinator contract): "checking since" is the
    FIRST entry's date — no backfill; current state is the latest
    entry per target; uptime is ok/total over the logged window,
    capped at 30 days; a log whose newest entry is older than the
    stale threshold is flagged, never silently presented as live.
    A missing/unreadable/empty log is "not available yet", not an
    error and never faked numbers."""
    try:
        lines = AVAILABILITY_LOG_PATH.read_text(
            encoding="utf-8").splitlines()
    except Exception:
        return {"available": False}
    entries = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            entries.append((int(e["ts"]), str(e["target"]),
                            bool(e["ok"]), int(e.get("ms") or 0)))
        except Exception:
            continue  # a torn final line must never break the page
    if not entries:
        return {"available": False}
    entries.sort(key=lambda x: x[0])
    first_ts = entries[0][0]
    last_ts = entries[-1][0]
    cutoff = last_ts - _AVAIL_WINDOW_MS
    window = [e for e in entries if e[0] >= cutoff]
    rows = []
    for target, label in _AVAIL_TARGETS:
        mine = [e for e in window if e[1] == target]
        if not mine:
            continue
        latest = mine[-1]
        ok_count = sum(1 for e in mine if e[2])
        uptime = 100.0 * ok_count / len(mine)
        uptime_txt = ("%d" % uptime) if uptime == int(uptime) else (
            "%.2f" % uptime).rstrip("0").rstrip(".")
        rows.append({"target": target, "label": label,
                     "ok": latest[2], "ms": latest[3],
                     "total": len(mine), "uptime": uptime_txt})
    if not rows:
        return {"available": False}
    import time as _time
    now_ms = int(_time.time() * 1000)
    return {"available": True, "rows": rows,
            "all_ok": all(r["ok"] for r in rows),
            "since_long": _avail_fmt_ms(first_ts),
            "last_long": _avail_fmt_ms_time(last_ts),
            "stale": (now_ms - last_ts) > _AVAIL_STALE_MS}


@app.get("/availability", response_class=HTMLResponse)
async def availability(request: Request):
    return templates.TemplateResponse(
        request, "availability.html",
        _ctx(request, avail=_availability_summary()))


# ------------------------------------------------------- insights plumbing
_SITE_BASE = "https://sentinelsafeguard.net"
_SITEMAP_PATHS = ["/", "/about", "/services", "/who-we-protect",
                  "/how-it-works", "/insights", "/privacy",
                  "/operations", "/threat-map", "/geopolitical",
                  "/flights", "/contact", "/report-issue",
                  "/assessment", "/tools", "/training/phishing",
                  "/faq", "/disclosure", "/availability"]


@app.get("/sitemap.xml")
async def sitemap(request: Request):
    # ESTATE-2026-10-25 (item 7): every public page + every Insights
    # post (with its real date as lastmod). Gated surfaces are not
    # listed — a sitemap names what the public may read.
    urls = []
    for path in _SITEMAP_PATHS:
        urls.append("<url><loc>%s%s</loc></url>" % (_SITE_BASE, path))
    for post in _load_insights():
        urls.append("<url><loc>%s%s</loc><lastmod>%s</lastmod></url>"
                    % (_SITE_BASE, post["url"], post["date"]))
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/'
           '0.9">%s</urlset>' % "".join(urls))
    return Response(content=xml, media_type="application/xml")


@app.get("/robots.txt")
async def robots(request: Request):
    # Points crawlers at the sitemap. NOTE (recorded in the lane
    # record): the app pages currently carry a noindex meta from an
    # earlier era while the static homepage does not — resolving
    # that indexing question is the owner's call, not this sweep's;
    # this file only makes the public set discoverable and named.
    return PlainTextResponse(
        "User-agent: *\nAllow: /\n\nSitemap: %s/sitemap.xml\n"
        % _SITE_BASE)


# ESTATE-2026-10-25 (item 4): RFC 9116 security.txt, served by the
# app AND committed identically under site/.well-known/ (the static
# copy covers any deployment shape that serves the tree without the
# app route; the two are pinned byte-identical by test). Contact is
# the report page first (the monitored intake) and the sentinel@
# mailbox second — a real mailbox since the 2026-10-25 mail cutover.
SECURITY_TXT = (
    "Contact: https://sentinelsafeguard.net/report-issue\n"
    "Contact: mailto:sentinel@sentinelsafeguard.net\n"
    "Expires: 2027-10-25T17:00:00-05:00\n"
    "Preferred-Languages: en\n"
    "Canonical: https://sentinelsafeguard.net/.well-known/security.txt\n"
    "Policy: https://sentinelsafeguard.net/disclosure\n")


@app.get("/.well-known/security.txt")
async def security_txt(request: Request):
    return PlainTextResponse(SECURITY_TXT)


@app.get("/operations", response_class=HTMLResponse)
async def operations(request: Request):
    # The Live Operations landing (aggregates the live data views)
    # keeps its own home here after the homepage took over /.
    return _operations_page(request)


def _operations_page(request: Request):
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
    # BH-2026-10-23 (H-1): the news hub + daily briefing are owner
    # surfaces. This gate used to exist ONLY as a Cloudflare Access
    # rule at the edge — the app itself served the page to anyone who
    # reached it. Enforce in-app, same key as /admin; the edge rule
    # stays as a second layer, not the only one.
    require_admin(request)
    return templates.TemplateResponse(request, "news.html", _ctx(
        request, news=store["news"], briefing=store["briefing"]))


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    require_admin(request)
    return templates.TemplateResponse(request, "admin.html", _ctx(request))


@app.get("/health")
async def health(request: Request):
    # BH-2026-10-23 (H-1): feed states + precise uptime are operational
    # detail, not public information — same in-app gate as /admin.
    # Loopback callers (on-box checks) still pass via the localhost
    # rule inside require_admin.
    require_admin(request)
    now = datetime.now(timezone.utc)
    return {"ok": True, "time": now.isoformat(timespec="seconds"), "frozen": FROZEN,
            "uptime_seconds": int((now - STARTED_AT).total_seconds()) if STARTED_AT else None,
            "feeds": {k: {"updated": v.get("updated"), "status": v.get("status")}
                      for k, v in store.items() if k != "briefing"}}


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request):
    # BH-2026-10-23 (H-1): exact start time + uptime + feed states are
    # operational detail — in-app gate, as with /news and /health.
    require_admin(request)
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


_LIVE_DEFAULT_CENTER = (39.1, -94.6)  # Kansas City — the tracker's home view


@app.get("/api/live-flights")
async def api_live_flights(request: Request, lat: float = None,
                           lon: float = None, dist: int = None):
    # LF-2026-10-25: live aircraft positions (community ADS-B via
    # adsb.lol, ODbL) for the Flight Tracker map. Public like the
    # other read APIs, but capped harder than the form endpoints:
    # the frontend polls every 15s per open tab, so the per-IP bucket
    # allows a few concurrent tabs plus pan/zoom refetches — while
    # feeds.fetch_live_flights guarantees visitor count can never
    # multiply upstream calls (server cache + one global upstream
    # gate), so this endpoint is cheap to serve at any audience.
    rate_limit(request, max_hits=300, window=600)
    if lat is None:
        lat = _LIVE_DEFAULT_CENTER[0]
    if lon is None:
        lon = _LIVE_DEFAULT_CENTER[1]
    if dist is None:
        dist = feeds.LIVE_DEFAULT_DIST
    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        raise HTTPException(400, "lat/lon out of range.")
    dist = max(1, min(int(dist), feeds.LIVE_MAX_DIST))
    timeout = config["feeds"]["request_timeout_seconds"]
    payload, _attempted = await feeds.fetch_live_flights(
        lat, lon, dist, timeout=min(timeout, feeds.LIVE_UPSTREAM_TIMEOUT))
    return JSONResponse(payload)


@app.get("/api/news-data")
async def api_news(request: Request):
    # BH-2026-10-23 (H-1): this endpoint returns the FULL briefing
    # object — it was the one gated dataset reachable with no in-app
    # authentication at all. Same gate as /news.
    require_admin(request)
    return JSONResponse({"news": store["news"], "briefing": store["briefing"]})


# ------------------------------------------------------------------ internal visitors
# PV-2026-10-23: the visitor feed for the Sentinel Command Activity
# console. This endpoint does not exist as far as the public internet
# is concerned: three independent gates, and EVERY failure is the
# same plain 404, so nothing about it can be probed from outside.
_INTERNAL_TOKEN_DEFAULT_PATH = "/opt/sentinel-live/internal_token.txt"


def _internal_token() -> str:
    """The shared token for the /internal/* endpoints (visitors and
    the ITEM6 ticket bridge), read from a box-local
    file on every call (rotation needs no restart). The path comes
    from SENTINEL_LIVE_INTERNAL_TOKEN_PATH or the production
    default; a missing/unreadable file means the feature is OFF and
    the endpoint answers 404 to everything, the app unaffected."""
    path = os.environ.get("SENTINEL_LIVE_INTERNAL_TOKEN_PATH") \
        or _INTERNAL_TOKEN_DEFAULT_PATH
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _visitors_gate(request: Request):
    def _nope():
        # SECAUDIT-2026-10-25: the detail must byte-match the
        # framework's own 404 ("Not Found") for an unmatched path.
        # The app's raised-404 style ("Not found.") is fine on
        # public routes, but here it told an outside prober exactly
        # which paths are real-but-gated and which do not exist —
        # an existence oracle against the stealth contract above.
        raise HTTPException(404, "Not Found")
    # (a) The TCP peer must be loopback — the console calls over SSH
    # or from the same box; tunnel traffic arrives AS loopback too,
    # which is what gate (b) exists for.
    host = request.client.host if request.client else ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        _nope()
    # (b) Cloudflare Tunnel traffic ALWAYS carries CF-Connecting-IP
    # (cloudflared sets it); a genuine box-local call never does.
    # Its presence means the request came in from the internet.
    if request.headers.get("CF-Connecting-IP") is not None:
        _nope()
    # (c) The token itself, constant-time compared.
    expected = _internal_token()
    if not expected:
        _nope()
    got = request.headers.get("X-Internal-Token", "")
    try:
        ok = hmac.compare_digest(got, expected)
    except TypeError:
        ok = False
    if not ok:
        _nope()


@app.get("/internal/visitors")
async def internal_visitors(request: Request, days: str = "2",
                            limit: str = "200"):
    # SWEEP5-2026-10-24: days/limit arrive as raw strings and are
    # parsed only AFTER the gate. As typed int parameters, FastAPI
    # validated them before this handler ran, so a malformed value
    # (days=abc) answered 422 while every gate failure answers the
    # same plain 404 — an oracle that distinguished this endpoint
    # from a nonexistent path, against the stealth design above.
    # Gate first: outsiders get 404 for every malformed request;
    # a gated caller with a bad value still gets a plain 400.
    _visitors_gate(request)
    try:
        days = int(days)
        limit = int(limit)
    except (TypeError, ValueError):
        raise HTTPException(400, "days and limit must be integers.")
    days = max(1, min(days, 90))
    limit = max(1, min(limit, 1000))
    today_start = _chicago_day_start_epoch(0)
    window_start = _chicago_day_start_epoch(days - 1)
    async with await _db() as db:
        await db.execute(_VISITOR_TABLE_SQL)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_visitor_log_ts "
            "ON visitor_log(ts)")
        async with db.execute(
                "SELECT COUNT(*), COUNT(DISTINCT ip), "
                "COUNT(DISTINCT visit_id) FROM visitor_log "
                "WHERE ts >= ?", (today_start,)) as cur:
            views_today, ips_today, visits_today = await cur.fetchone()

        async def _top(sql, key):
            async with db.execute(sql, (window_start,)) as cur:
                return [{key: r[0], "views": r[1]}
                        for r in await cur.fetchall()]

        top_pages = await _top(
            "SELECT path, COUNT(*) AS v FROM visitor_log "
            "WHERE ts >= ? GROUP BY path ORDER BY v DESC, path ASC "
            "LIMIT 10", "path")
        top_refs = await _top(
            "SELECT referrer, COUNT(*) AS v FROM visitor_log "
            "WHERE ts >= ? GROUP BY referrer ORDER BY v DESC, "
            "referrer ASC LIMIT 10", "referrer")
        # An empty referrer IS a direct visit — name it in the
        # summary (the feed keeps the raw stored value).
        for r in top_refs:
            if not r["referrer"]:
                r["referrer"] = "direct"
        top_countries = await _top(
            "SELECT country, COUNT(*) AS v FROM visitor_log "
            "WHERE ts >= ? AND country != '' GROUP BY country "
            "ORDER BY v DESC, country ASC LIMIT 10", "country")
        db.row_factory = aiosqlite.Row
        async with db.execute(
                "SELECT ts, ip, ua, path, referrer, country, visit_id, "
                "bot FROM visitor_log WHERE ts >= ? "
                "ORDER BY ts DESC, id DESC LIMIT ?",
                (window_start, limit)) as cur:
            feed = [{
                "ts": datetime.fromtimestamp(
                    r["ts"], timezone.utc).isoformat(timespec="seconds"),
                "ip": r["ip"], "ua": r["ua"], "path": r["path"],
                "referrer": r["referrer"], "country": r["country"],
                "visitId": r["visit_id"], "bot": bool(r["bot"]),
            } for r in await cur.fetchall()]
    return {"summary": {"viewsToday": views_today,
                        "uniqueIpsToday": ips_today,
                        "visitsToday": visits_today,
                        "topPages": top_pages,
                        "topReferrers": top_refs,
                        "topCountries": top_countries},
            "feed": feed}


@app.get("/internal/tickets")
async def internal_tickets(request: Request, after: str = "0",
                           limit: str = "200"):
    # ITEM6-2026-10-25: the public-ticket bridge feed for Sentinel
    # Command. Same three gates as /internal/visitors (the shared
    # _visitors_gate: loopback peer, no CF-Connecting-IP, box token
    # file) and the same stealth contract — every gate failure is
    # the same plain 404. after/limit are raw strings parsed only
    # AFTER the gate, for the SWEEP5 reason recorded on
    # /internal/visitors: typed int params would be validated by
    # FastAPI before the handler runs and a 422 would oracle this
    # endpoint apart from a nonexistent path.
    #
    # Contract: tickets with id > after, oldest first, so the
    # caller can keep a durable cursor (the highest id it has seen)
    # and never re-fetch history. The response carries maxId — the
    # highest ticket id in the whole table, or 0 when empty — so a
    # caller can distinguish "caught up" from "empty". Reporter IP
    # and admin_notes deliberately do NOT ride this feed: Command
    # needs the ticket, not the abuse-tracking metadata.
    _visitors_gate(request)
    try:
        after = int(after)
        limit = int(limit)
    except (TypeError, ValueError):
        raise HTTPException(400, "after and limit must be integers.")
    after = max(0, after)
    limit = max(1, min(limit, 500))
    async with await _db() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
                "SELECT COALESCE(MAX(id), 0) FROM tickets") as cur:
            max_id = (await cur.fetchone())[0]
        async with db.execute(
                "SELECT id, created_at, name, email, phone, category,"
                " priority, subject, message, status FROM tickets"
                " WHERE id > ? ORDER BY id ASC LIMIT ?",
                (after, limit)) as cur:
            rows = await cur.fetchall()
    return {"tickets": [{
                "id": r["id"], "createdAt": r["created_at"],
                "name": r["name"], "email": r["email"],
                "phone": r["phone"], "category": r["category"],
                "priority": r["priority"], "subject": r["subject"],
                "message": r["message"], "status": r["status"]}
            for r in rows],
            "maxId": max_id}


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
    for both an unparseable body and a non-dict one.

    SECAUDIT-2026-10-25: the media type must be application/json.
    request.json() parses the body whatever Content-Type arrived,
    so a cross-site page could store a form submission with a
    CORS-safelisted text/plain POST (no preflight, no Turnstile
    token of its own — the victim's browser supplies the request).
    Every real caller (the site's forms, the admin API's clients)
    already sends application/json; anything else is a 415 before
    the body is even parsed."""
    _ctype = (request.headers.get("content-type") or "") \
        .split(";")[0].strip().lower()
    if _ctype != "application/json":
        raise HTTPException(415, "Content-Type must be application/json.")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON.")
    if not isinstance(body, dict):
        raise HTTPException(400, "Invalid JSON.")
    return body


# ------------------------------------------------------------------ turnstile
TURNSTILE_SITEVERIFY_URL = \
    "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def _turnstile_siteverify(secret: str, token: str, remoteip: str) -> dict:
    """One call to Cloudflare's siteverify endpoint; returns the parsed
    JSON body. Isolated into its own function so the handlers never
    touch the network directly (and tests can stub exactly this seam).
    Raises on any transport or parse failure — the caller fails closed.
    The secret and token travel in the POST body only; neither is ever
    logged."""
    data = {"secret": secret, "response": token}
    if remoteip and remoteip != "?":
        data["remoteip"] = remoteip
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(TURNSTILE_SITEVERIFY_URL, data=data)
    result = resp.json()
    if not isinstance(result, dict):
        raise ValueError("siteverify returned a non-object body")
    return result


async def _verify_turnstile(request: Request, body: dict):
    """Cloudflare Turnstile gate shared by the public form handlers.

    A no-op unless turnstile.enabled is true AND a secret key is
    configured — in every other configuration the forms behave exactly
    as they did before this check existed (local/staging unaffected).
    When active, the payload's cf-turnstile-response token is verified
    with Cloudflare server-side BEFORE anything is stored: a missing
    or rejected token is a plain 400 in the API's usual style, and if
    siteverify itself can't be reached the submission fails CLOSED
    with a 503 pointing at the email/phone fallback — an outage never
    silently waves a submission through."""
    tscfg = config.get("turnstile") or {}
    if not tscfg.get("enabled"):
        return
    secret = (tscfg.get("secret_key") or "").strip()
    if not secret:
        return
    token = _s(body, "cf-turnstile-response").strip()
    if not token:
        raise HTTPException(400, "Please complete the bot check and try again.")
    try:
        result = await _turnstile_siteverify(secret, token, _client_ip(request))
    except Exception:
        log.warning("turnstile siteverify unreachable (path=%s)",
                    request.url.path)
        raise HTTPException(
            503, "Bot check is unavailable right now — please contact us "
                 "by email or phone instead.")
    if result.get("success") is not True:
        # Cloudflare's error-codes are safe to log (they name the
        # failure class, never the secret or the token).
        log.info("turnstile rejected a submission (path=%s codes=%s)",
                 request.url.path, result.get("error-codes"))
        raise HTTPException(
            400, "Bot check failed — please try again, or contact us "
                 "by email or phone.")
    # BH-2026-10-23 (L-1): a token minted for a DIFFERENT site's widget
    # must not pass here — when Cloudflare reports the hostname the
    # challenge was solved on, assert it is one of ours (production
    # domains, or loopback for local installs).
    _solved_on = result.get("hostname")
    if isinstance(_solved_on, str) and _solved_on and _solved_on not in (
            "sentinelsafeguard.net", "www.sentinelsafeguard.net",
            "localhost", "127.0.0.1"):
        log.info("turnstile hostname mismatch (path=%s host=%s)",
                 request.url.path, _solved_on)
        raise HTTPException(
            400, "Bot check failed — please try again, or contact us "
                 "by email or phone.")


# ESTATE-2026-10-25: the booking-upgrade vocabularies for
# /api/contact — mirrored by the /contact form's <select> options and
# pinned by tests/test_estate_sweep_2026_10_25.py. The service list is
# the five lines of work /services names, plus the honest "not sure".
CONTACT_SERVICES = ("Penetration testing", "Cybersecurity & IT",
                    "Security installs", "Incident response",
                    "Custom websites & software", "Not sure yet")
CONTACT_TIME_WINDOWS = ("Morning", "Afternoon", "Evening")


@app.post("/api/contact")
async def api_contact(request: Request):
    rate_limit(request)
    body = await _json_body(request)
    await _verify_turnstile(request, body)
    name, email, message = _s(body, "name").strip(), _s(body, "email").strip(), \
                          _s(body, "message").strip()
    if not name or not email or not message or "@" not in email:
        raise HTTPException(400, "Name, a valid email, and a message are required.")
    if len(message) > 5000:
        raise HTTPException(400, "Message is too long (5000 chars max).")
    # ESTATE-2026-10-25 (booking upgrade): three OPTIONAL fields —
    # the service the message is about, a preferred date, and a
    # preferred time window. All validated server-side against the
    # exact sets the form offers; anything outside them is a plain
    # 400, and an absent field stores "" exactly as before, so the
    # homepage form's original payload keeps working unchanged.
    service = _s(body, "service").strip()
    if service and service not in CONTACT_SERVICES:
        raise HTTPException(400, "Please pick a service from the list.")
    pref_date = _s(body, "pref_date").strip()
    if pref_date:
        try:
            datetime.strptime(pref_date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(400, "Preferred date must be a date.")
        if len(pref_date) != 10:
            raise HTTPException(400, "Preferred date must be a date.")
    pref_window = _s(body, "pref_window").strip()
    if pref_window and pref_window not in CONTACT_TIME_WINDOWS:
        raise HTTPException(400, "Please pick a time window from the list.")
    async with await _db() as db:
        await db.execute(
            "INSERT INTO contacts(created_at,name,email,subject,message,ip,"
            "service,pref_date,pref_window) VALUES(?,?,?,?,?,?,?,?,?)",
            (_utcnow(), name[:120], email[:160], _s(body, "subject")[:160],
             message, _client_ip(request), service, pref_date, pref_window))
        await db.commit()
    log.info("contact submission from %s", email)
    return {"ok": True}


@app.post("/api/ticket")
async def api_ticket(request: Request):
    """Get Help ticket intake — stores a ticket, no login required."""
    rate_limit(request, max_hits=10)
    body = await _json_body(request)
    await _verify_turnstile(request, body)
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
    await _verify_turnstile(request, body)
    email = _s(body, "email").strip()
    if not email or "@" not in email:
        raise HTTPException(400, "A valid email is required.")
    async with await _db() as db:
        try:
            await db.execute(
                "INSERT INTO newsletter(created_at,email,name,ip) VALUES(?,?,?,?)",
                (_utcnow(), email[:160], _s(body, "name")[:120], _client_ip(request)))
            await db.commit()
        except aiosqlite.IntegrityError as e:
            # duplicate email — still report success (no enumeration).
            # BH2-7/BH2-13: only the UNIQUE violation is swallowed;
            # any other integrity failure must surface as an error,
            # not a fake success (the blanket except used to hide it).
            if "UNIQUE constraint failed" not in str(e):
                raise
    return {"ok": True}


# ------------------------------------------------------------------ briefing ingest
@app.post("/api/briefing")
async def api_briefing(request: Request):
    # SL6-3: a daily briefing is one post a day; the shared form limiter
    # (20/10min/IP) still caps token guessing and write spam.
    rate_limit(request)
    token = config.get("briefing_token") or ""
    if not token and _is_tunneled(request):
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
    _sanitize_briefing_urls(body)
    body["ingested_at"] = _utcnow()
    # Write via a temp file + atomic replace: a crash or a concurrent
    # ingest mid-write must never leave a torn briefing.json behind
    # (the loader ignores a corrupt file, which would silently drop
    # the day's briefing from /news).
    _brief_tmp = BRIEFING_PATH.with_name(BRIEFING_PATH.name + ".tmp")
    _brief_tmp.write_text(json.dumps(body, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    _brief_tmp.replace(BRIEFING_PATH)
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
    # SWEEP5-2026-10-24: offset was bound raw while limit was
    # clamped — an offset past SQLite's INTEGER range (2**63-1)
    # raised OverflowError on binding and surfaced as a 500.
    # Clamp into the bindable range; any offset past the row
    # count still returns an empty page, exactly as before, and
    # a negative offset keeps SQLite's treated-as-zero result.
    offset = max(0, min(offset, 9223372036854775807))
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
    # SWEEP5-2026-10-24: an invalid `type` is a 400 (above), but an
    # invalid `format` silently fell back to a CSV download — a
    # caller asking for format=xml got CSV bytes under a .csv name
    # with no signal anything was wrong. Validate the documented
    # pair (case-insensitively, so CSV/JSON keep working) instead.
    format = format.lower()
    if format not in ("csv", "json"):
        raise HTTPException(400, "format must be csv or json")
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
            # BH2-14: a leading newline hid the formula char from both
            # checks ("<LF>=..." with no space/tab to strip) — include
            # \n in the first-char set and in the stripped prefix.
            if v[:1] in ("=", "+", "-", "@", "\t", "\r", "\n") or \
                    v.lstrip(" \t\r\n")[:1] in ("=", "+", "-", "@"):
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
    # SWEEP5-2026-10-24: this is a PATCH — the field a caller omits
    # must keep its stored value. The old handler required status
    # on every call and rewrote admin_notes from the body
    # unconditionally, so a status-only update silently erased the
    # ticket's admin notes (verified: notes set, status-only PATCH,
    # notes read back empty), and a notes-only update was a 400.
    if not 0 <= ticket_id <= 9223372036854775807:
        # Past SQLite's INTEGER range no ticket can exist; binding
        # the raw value raised OverflowError and surfaced as a 500.
        raise HTTPException(404, "Ticket not found.")
    has_status = "status" in body
    has_notes = "admin_notes" in body
    if not has_status and not has_notes:
        raise HTTPException(
            400, "Nothing to update: provide status and/or admin_notes.")
    status = None
    if has_status:
        status = _s(body, "status").strip().lower()
        if status not in ("new", "open", "in_progress", "resolved", "closed"):
            raise HTTPException(400, "Invalid status.")
    notes = None
    if has_notes:
        if not isinstance(body.get("admin_notes"), str):
            raise HTTPException(400, "admin_notes must be a string.")
        notes = body["admin_notes"][:2000]
    async with await _db() as db:
        async with db.execute(
                "SELECT status, admin_notes FROM tickets WHERE id=?",
                (ticket_id,)) as cur:
            row = await cur.fetchone()
        if row is None:
            # BH2-3: the update matched no ticket — say so instead of
            # reporting (and logging) a success that never happened.
            raise HTTPException(404, "Ticket not found.")
        new_status = status if has_status else row[0]
        new_notes = notes if has_notes else (row[1] or "")
        await db.execute(
            "UPDATE tickets SET status=?, admin_notes=? WHERE id=?",
            (new_status, new_notes, ticket_id))
        await db.commit()
    log.info("ticket #%s -> %s (admin)", ticket_id, new_status)
    return {"ok": True, "id": ticket_id, "status": new_status}


# ------------------------------------------------------- HackProof payments
# Optional pass-through to the HackProof payments service (payments/** in
# the HackProof repo), which runs on this same machine bound to loopback.
# Config: hackproof_payments.enabled (default OFF — the routes below do
# not exist at all while it is off). When enabled, Sentinel Live fronts
# the service so one server faces the world and the payments service
# never needs a port of its own exposed.
#
# ONLY the three public payments routes are proxied. /api/admin/* is
# NEVER proxied: the payments review queue stays reachable only directly
# on loopback, behind its own admin token.
_hp_cfg = config.get("hackproof_payments") or {}
HP_PAYMENTS_ENABLED = bool(_hp_cfg.get("enabled"))
HP_PAYMENTS_UPSTREAM = str(
    _hp_cfg.get("upstream") or "http://127.0.0.1:8787").rstrip("/")

_payments_client = None

# BH2-11: cap on the upstream reply body. Payments replies are small
# JSON documents; the old code buffered resp.content with no limit, so
# a hung/buggy/compromised upstream could OOM this server with one
# endless response. Anything past the cap is a clean 502, same shape
# as an unreachable upstream.
HP_PROXY_MAX_RESPONSE_BYTES = 5 * 1024 * 1024

_hp_hits = defaultdict(list)


def _hp_rate_limit(request: Request, category: str, max_hits: int):
    """BH2-8: throttle for the proxied routes, with its OWN buckets.

    The three routes shipped with no throttling at all: order creation
    makes the upstream lock BTC prices and store orders, certificate
    submission can trigger email, and order-status reads enumerate
    payment state (a paid reply carries the license key). This cannot
    share rate_limit()'s per-IP bucket, though: a buyer legitimately
    polls order status for minutes, and in a shared bucket those polls
    would eat the small POST allowance and then 429 the certificate
    submission the whole flow exists for. Buckets are per category.
    """
    ip = _real_ip(request)
    now = time.time()
    if len(_hp_hits) > 4096:
        for _k in [k for k, v in _hp_hits.items()
                   if not v or now - max(v) >= 600]:
            _hp_hits.pop(_k, None)
    key = (category, ip)
    keep = [t for t in _hp_hits[key] if now - t < 600]
    if len(keep) >= max_hits:
        log.warning("hackproof proxy rate-limit 429: ip=%s route=%s",
                    ip, category)
        raise HTTPException(429, "Too many requests — please slow down "
                                 "and retry.")
    keep.append(now)
    _hp_hits[key] = keep


def _get_payments_client():
    global _payments_client
    if _payments_client is None:
        # Order creation asks the upstream to lock a live BTC price and
        # certificate issuance sends email, so reads may take a while;
        # the connect timeout stays short so a dead upstream fails fast.
        _payments_client = httpx.AsyncClient(
            timeout=httpx.Timeout(65.0, connect=5.0))
    return _payments_client


async def _proxy_payments(request: Request, upstream_path: str):
    """Forward one request to the payments service and return its reply
    untouched: same status, same body bytes. The certificate flow depends
    on the exact 200/201/202/400 semantics, so nothing is re-shaped.

    Only Content-Type/Accept are forwarded (BH2 sweep: the admin key,
    cookies and any Authorization header a client sends this server
    must never leak upstream), and only Content-Type is returned, so
    no hop-by-hop or upstream session headers pass through either.
    The reply is streamed under HP_PROXY_MAX_RESPONSE_BYTES (BH2-11).
    """
    headers = {}
    for _h in ("content-type", "accept"):
        _v = request.headers.get(_h)
        if _v:
            headers[_h] = _v
    try:
        async with _get_payments_client().stream(
                request.method, HP_PAYMENTS_UPSTREAM + upstream_path,
                content=await request.body(), headers=headers) as resp:
            chunks, total = [], 0
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > HP_PROXY_MAX_RESPONSE_BYTES:
                    log.warning("hackproof payments upstream response "
                                "too large: %s %s", request.method,
                                upstream_path)
                    raise HTTPException(
                        502, "The HackProof payment service returned "
                             "an oversized response — please try again "
                             "later.")
                chunks.append(chunk)
            status = resp.status_code
            ctype = resp.headers.get("content-type", "application/json")
    except httpx.HTTPError:
        log.warning("hackproof payments upstream unreachable: %s %s",
                    request.method, upstream_path)
        raise HTTPException(
            502, "The HackProof payment service is unavailable right now "
                 "— please try again in a few minutes.")
    return Response(content=b"".join(chunks), status_code=status,
                    headers={"Content-Type": ctype})


if HP_PAYMENTS_ENABLED:
    @app.post("/api/orders")
    async def hp_create_order(request: Request):
        _hp_rate_limit(request, "orders-create", 10)
        return await _proxy_payments(request, "/api/orders")

    @app.get("/api/orders/{order_id}")
    async def hp_order_status(request: Request, order_id: str):
        # Generous cap: a checkout page polls this while a BTC payment
        # confirms; the cap's job is stopping id enumeration/abuse,
        # not breaking a waiting buyer (see _hp_rate_limit).
        _hp_rate_limit(request, "order-status", 300)
        # BH2-9: order ids are machine-issued tokens. Anything outside
        # a plain token charset is rejected here instead of being
        # quoted and forwarded: quoting alone left ".." to be
        # normalized by the HTTP client into a different upstream path
        # and left %2F-style smuggling to whatever decoding the
        # upstream happens to do — either could reshape the fixed
        # /api/orders/{id} path toward routes that must never be
        # proxied (e.g. the payments service's /api/admin/*).
        if ".." in order_id or \
                not re.fullmatch(r"[A-Za-z0-9._-]+", order_id):
            raise HTTPException(400, "Invalid order id.")
        return await _proxy_payments(
            request, "/api/orders/" + quote(order_id, safe=""))

    @app.post("/api/certificates")
    async def hp_submit_certificate(request: Request):
        _hp_rate_limit(request, "certificates", 10)
        return await _proxy_payments(request, "/api/certificates")

    log.info("HackProof payments pass-through enabled (upstream %s)",
             HP_PAYMENTS_UPSTREAM)


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
    # BH-2026-10-23 (L-5): don't volunteer the framework banner —
    # server_header=False drops uvicorn's "Server: uvicorn" line.
    uvicorn.run(app, host=srv["host"], port=int(srv["port"]), log_level="warning",
                server_header=False)
