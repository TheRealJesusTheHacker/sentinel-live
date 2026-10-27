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
              "news_refresh_minutes": 30, "request_timeout_seconds": 20,
              # Internet Weather 2026-10-27: IODA + RIPEstat refresh.
              "weather_refresh_minutes": 15},
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
    # SENTINEL-NEWS-2026-10-26: the News Desk push key, stored the
    # same way as the admin key — ONLY its SHA-256 hex digest in
    # `news_push_key_sha256`. Sentinel Command presents the key in
    # the X-News-Key header when it publishes/unpublishes/deletes a
    # news item at POST /internal/news(-delete); the app hashes the
    # presented value and constant-time compares digests, so a
    # config read alone never yields the key. Empty = the push
    # endpoint is OFF (404 to everything), exactly like a missing
    # internal token file.
    "news_push_key_sha256": "",
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
                     "news_refresh_minutes", "request_timeout_seconds",
                     # Internet Weather 2026-10-27: same validation.
                     "weather_refresh_minutes"):
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
                                (b"cache-control", b"no-store"),
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
            # switch off device APIs no page uses.
            # CSP PASS 2026-10-27: the full Content-Security-Policy
            # that BH-2026-10-23 deferred is now designed and staged.
            # It is only possible because the site was rebuilt for it:
            # every inline script/style was externalized to same-origin
            # files, Leaflet 1.9.4 and both typefaces are self-hosted,
            # and the last style attributes became classes/CSSOM — so
            # the policy needs no 'unsafe-inline' or 'unsafe-eval'
            # anywhere. The only third parties left are Esri map tiles
            # (img-src) and Cloudflare Turnstile (script/frame/connect
            # on the form pages). STAGE 1 shipped it Report-Only
            # (2026-10-27) and a real-browser sweep exercised every
            # page type: the only findings were Leaflet's data: empty-
            # tile placeholder (img-src gains data: — images only,
            # never scripts) and Cloudflare's edge-injected Web
            # Analytics beacon, which is deliberately NOT allowlisted
            # (the privacy page promises no third-party analytics;
            # the beacon stays blocked). STAGE 2 (this commit) flips
            # the header to enforcing.
            _MANAGED_HEADERS = {
                b"x-content-type-options": b"nosniff",
                b"x-frame-options": b"DENY",
                b"content-security-policy":
                    b"default-src 'none'; "
                    b"script-src 'self' https://challenges.cloudflare.com; "
                    b"style-src 'self'; "
                    b"img-src 'self' data: https://server.arcgisonline.com; "
                    b"font-src 'self'; "
                    b"connect-src 'self' https://challenges.cloudflare.com; "
                    b"frame-src https://challenges.cloudflare.com; "
                    b"frame-ancestors 'none'; "
                    b"object-src 'none'; "
                    b"base-uri 'self'; "
                    b"form-action 'self'; "
                    b"worker-src 'self'; "
                    b"manifest-src 'self'; "
                    b"media-src 'self'",
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
                    # AUDIT-MAX 2026-10-27 (Lane 1 F3): this app's
                    # JSON is live data — feeds, admin, errors. No
                    # downstream cache should retain a JSON body;
                    # say so explicitly, as mail and Command do.
                    ctype = next((v for k, v in hdrs
                                  if k.lower() == b"content-type"), b"")
                    if ctype.startswith(b"application/json"):
                        hdrs = [(k, v) for k, v in hdrs
                                if k.lower() != b"cache-control"]
                        hdrs.append((b"cache-control", b"no-store"))
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
                         "/services", "/services/cybersecurity-kansas-city",
                         "/services/it-support-kansas-city",
                         "/services/network-security-installs-kansas-city",
                         "/who-we-protect", "/how-it-works", "/contact",
                         "/insights", "/privacy", "/assessment", "/tools",
                         "/training/phishing", "/faq", "/disclosure",
                         "/availability", "/sentinel-news",
                         # New pages 2026-10-27 (owner order).
                         "/kc-scam-alerts", "/internet-weather",
                         # DEFCON-RESHAPE-2026-10-27: the two DEFCON pages.
                         "/cyber-defcon", "/geopolitical-defcon",
                         # BREACH-CHECK-2026-10-27: the Breach Check page.
                         "/breach-check"}
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
    if re.fullmatch(r"/insights/[a-z0-9][a-z0-9-]*", path):
        return True
    # SENTINEL-NEWS-2026-10-26: published news items log under
    # their own paths, same as Insights posts.
    return bool(re.fullmatch(r"/sentinel-news/[a-z0-9][a-z0-9-]*", path))


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
    # Internet Weather 2026-10-27: IODA + RIPEstat store.
    "weather": {"updated": None, "status": "starting",
                "window_hours": 24,
                "sources": {"ioda": "starting", "ripestat": "starting"},
                "totals": {"countries_affected": 0, "outage_events": 0,
                           "alerts_24h": 0},
                "countries": [], "events": [], "error": None},
    # Sentinel Cyber DEFCON 2026-10-27 (DEFCON-RESHAPE-2026-10-27):
    # CISA KEV counts + the computed levels (dicts) or None until
    # the first computes land.
    "kev": {"updated": None, "status": "starting", "total": 0,
            "added_7d": 0, "added_today": 0, "added_dates": []},
    "cyber_defcon": None,
    "geo_defcon": None,
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
    # Internet Weather + KEV + DEFCON engines 2026-10-27
    # (DEFCON-RESHAPE-2026-10-27).
    asyncio.create_task(_refresh_loop("weather",
                                      fcfg["weather_refresh_minutes"],
                                      feeds.fetch_internet_weather, to))
    asyncio.create_task(_refresh_loop("kev", 60, feeds.fetch_kev, to))
    asyncio.create_task(_cyber_defcon_loop())
    asyncio.create_task(_geo_defcon_loop())
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


# ------------------------------------------------------------------ sentinel news
# SENTINEL-NEWS-2026-10-26 (owner order 2026-10-26 07:26): Sentinel
# News — the site's news page, fed from the News Desk in Sentinel
# Command. Items are DATA, not repo files and not pages: one JSON
# file per item under data/news/ on the box (SENTINEL_LIVE_NEWS_DIR
# overrides for tests/rehearsal), written ONLY by the key-gated
# loopback push endpoint below when the desk publishes. The repo
# stays a clean pull-only clone; data/news/ rides the nightly
# backup with the rest of data/. An item carries a state —
# "draft" or "published" — and ONLY published items render, feed,
# or sitemap here. Bodies are Markdown in the Insights subset and
# render through _insight_body_html, so the escaping standard is
# identical: every line is HTML-escaped first and the only markup
# emitted is the renderer's own.
_NEWS_DIR = Path(os.environ.get("SENTINEL_LIVE_NEWS_DIR")
                 or DATA_DIR / "news")
_NEWS_TAGS = ("Announcement", "Threat Watch", "Patch Alert",
              "From the House")
_NEWS_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
_news_cache = {"key": None, "items": []}


def _news_parse_item(raw):
    """One news file's JSON -> a render dict, or None when the
    shape is off. Strict on every field the renderer trusts:
    a sloppy file is skipped (and logged by the caller), never
    half-rendered."""
    if not isinstance(raw, dict):
        return None
    slug = str(raw.get("slug") or "").strip()
    if not _NEWS_SLUG_RE.fullmatch(slug) or len(slug) > 80:
        return None
    date = str(raw.get("date") or "")
    try:
        day = datetime.strptime(date, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None
    tag = str(raw.get("tag") or "").strip()
    if tag not in _NEWS_TAGS:
        return None
    title = str(raw.get("title") or "").strip()
    summary = str(raw.get("summary") or "").strip()
    body = str(raw.get("body") or "")
    if not title or not summary:
        return None
    source_url = str(raw.get("sourceUrl") or "").strip()
    if source_url and not source_url.startswith("https://"):
        source_url = ""
    return {
        "slug": slug, "date": date,
        "date_long": "%s %d, %d" % (day.strftime("%B"), day.day,
                                    day.year),
        "tag": tag, "title": title, "summary": summary,
        "html": _insight_body_html(body),
        # KC Scam Alerts 2026-10-27: geographic scope of the item.
        "scope": str(raw.get("scope") or "").strip(),
        "source_name": str(raw.get("sourceName") or "").strip(),
        "source_url": source_url,
        "state": str(raw.get("state") or ""),
        "updated_at": str(raw.get("updatedAt") or ""),
        "url": "/sentinel-news/" + slug,
    }


def _load_news():
    """Every PUBLISHED news item, newest first (same-day items by
    most recently pushed, then slug). Cached on the directory's
    (name, mtime) fingerprint, the Insights pattern; a malformed
    file is logged and skipped — one bad item can never take the
    page down, and a draft can never leak onto it."""
    if not _NEWS_DIR.is_dir():
        return []
    files = sorted(_NEWS_DIR.glob("*.json"))
    key = tuple((p.name, p.stat().st_mtime_ns) for p in files)
    if _news_cache["key"] == key:
        return _news_cache["items"]
    items = []
    for p in files:
        try:
            item = _news_parse_item(
                json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            item = None
        if item is None:
            log.warning("news: skipping malformed item file %s",
                        p.name)
            continue
        if item["state"] != "published":
            continue
        items.append(item)
    items.sort(key=lambda x: (x["date"], x["updated_at"], x["slug"]),
               reverse=True)
    _news_cache["key"] = key
    _news_cache["items"] = items
    return items


# ------------------------------------------------------- news push gate
def _news_push_gate(request: Request):
    """The /internal/news* gate — the ticket-bridge discipline
    with the key discipline of REMEDIATION 5a: (a) the TCP peer
    must be loopback, (b) CF-Connecting-IP must be absent (tunnel
    traffic always carries it; a genuine box-local call never
    does), (c) the X-News-Key header's SHA-256 must match the
    digest configured in news_push_key_sha256, constant-time
    compared. EVERY failure is the same plain 404 whose detail
    byte-matches the framework's own, so the endpoint cannot be
    probed apart from a nonexistent path. An unconfigured digest
    means the feature is OFF — 404 to everything."""
    def _nope():
        raise HTTPException(404, "Not Found")
    host = request.client.host if request.client else ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        _nope()
    if request.headers.get("CF-Connecting-IP") is not None:
        _nope()
    expected = str(config.get("news_push_key_sha256") or "").strip().lower()
    if not expected:
        _nope()
    got = request.headers.get("X-News-Key", "")
    digest = hashlib.sha256(got.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, expected):
        _nope()


async def _news_push_payload(request: Request):
    """Body parsed only AFTER the gate (the SWEEP5 rule: a
    malformed request from outside must meet the same 404 as
    every other gate failure, never a distinguishing 4xx)."""
    try:
        raw = json.loads((await request.body()).decode("utf-8"))
    except Exception:
        raise HTTPException(400, "A JSON item is required.")
    if not isinstance(raw, dict):
        raise HTTPException(400, "A JSON item is required.")
    slug = str(raw.get("slug") or "").strip()
    if not _NEWS_SLUG_RE.fullmatch(slug) or len(slug) > 80:
        raise HTTPException(400, "A valid slug is required.")
    item = {"slug": slug}
    if "date" in raw:
        date = str(raw.get("date") or "")
        try:
            datetime.strptime(date, "%Y-%m-%d")
        except (TypeError, ValueError):
            raise HTTPException(400, "date must be YYYY-MM-DD.")
        item["date"] = date
    # Only keys the caller actually sent ride the item — the
    # upsert merges over the stored file, and an absent key must
    # mean "unchanged", never "blanked".
    for key, cap in (("tag", 40), ("title", 200), ("summary", 400),
                     ("sourceName", 120), ("sourceUrl", 500)):
        if key not in raw:
            continue
        v = str(raw.get(key) or "").strip()
        if len(v) > cap:
            raise HTTPException(400, "%s is too long." % key)
        item[key] = v
    if "body" in raw:
        body = raw.get("body")
        item["body"] = body if isinstance(body, str) else ""
        if len(item["body"]) > 60000:
            raise HTTPException(400, "body is too long.")
    # KC Scam Alerts 2026-10-27: scope, when sent, must be one of
    # the three geographic scopes.
    if "scope" in raw:
        scope = str(raw.get("scope") or "").strip()
        if scope not in ("World", "National", "Kansas City"):
            raise HTTPException(
                400, "scope must be World, National, or Kansas City.")
        item["scope"] = scope
    state = str(raw.get("state") or "").strip()
    if state not in ("draft", "published"):
        raise HTTPException(400, "state must be draft or published.")
    item["state"] = state
    return item


def _news_item_path(slug):
    """The one place a slug becomes a filesystem path. Callers
    already gate the slug charset ([a-z0-9-], fullmatch, <=80 —
    no separators, no dots); this adds a containment proof on
    top: the resolved target must sit directly inside the news
    store, so no slug, however produced, can address a file
    outside it. (AUDIT-MAX 2026-10-27, CodeQL py/path-injection
    alert #3 — defense-in-depth over the charset gate.)"""
    base = _NEWS_DIR.resolve()
    target = (base / (slug + ".json")).resolve()
    if target.parent != base:
        raise HTTPException(400, "A valid slug is required.")
    return target


def _news_write_item(item):
    """Atomic write: temp file in the same directory, then
    os.replace — a reader mid-publish sees the old file or the
    new one, never a torn write."""
    _NEWS_DIR.mkdir(parents=True, exist_ok=True)
    item = dict(item)
    # Millisecond resolution: the index orders by (date,
    # updatedAt), and two publishes in the same second must
    # still order by publish order, not by slug accident.
    item["updatedAt"] = datetime.now(timezone.utc).isoformat(
        timespec="milliseconds")
    target = _news_item_path(item["slug"])
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_text(json.dumps(item, indent=1, sort_keys=True),
                   encoding="utf-8")
    os.replace(tmp, target)
    return item


@app.post("/internal/news")
async def internal_news_upsert(request: Request):
    # SENTINEL-NEWS-2026-10-26: the News Desk publish path. The
    # desk calls this when an item is saved, published, or
    # unpublished; the file it writes IS the item's live state.
    # Upsert semantics: a save for a slug the directory already
    # holds keeps the fields the desk did not send (a state-only
    # publish never wipes a body written by an earlier save).
    _news_push_gate(request)
    item = await _news_push_payload(request)
    existing = None
    path = _news_item_path(item["slug"])
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = None
    if isinstance(existing, dict):
        merged = dict(existing)
        merged.update(item)
        item = merged
    # Validation runs on the MERGED item: a state-only push (the
    # desk's publish/unpublish) sends slug + state, and the fields
    # it omits are the ones already on file.
    if "date" not in item:
        raise HTTPException(400, "date is required.")
    if item.get("tag") not in _NEWS_TAGS:
        raise HTTPException(400, "tag is not a Sentinel News tag.")
    # KC Scam Alerts 2026-10-27: a stored scope must stay valid.
    if item.get("scope") and item.get("scope") not in (
            "World", "National", "Kansas City"):
        raise HTTPException(
            400, "scope must be World, National, or Kansas City.")
    if not item.get("title") or not item.get("summary"):
        raise HTTPException(400, "title and summary are required.")
    src = str(item.get("sourceUrl") or "")
    if src and not src.startswith("https://"):
        raise HTTPException(400, "sourceUrl must be https.")
    _news_write_item(item)
    return {"ok": True, "slug": item["slug"], "state": item["state"]}


@app.post("/internal/news-delete")
async def internal_news_delete(request: Request):
    # Same gate; removes the item file outright (the desk's
    # delete). An absent slug is a successful no-op — the desk's
    # state and the directory converge either way.
    _news_push_gate(request)
    try:
        raw = json.loads((await request.body()).decode("utf-8"))
    except Exception:
        raise HTTPException(400, "A JSON body is required.")
    slug = str((raw or {}).get("slug") or "").strip()
    if not _NEWS_SLUG_RE.fullmatch(slug) or len(slug) > 80:
        raise HTTPException(400, "A valid slug is required.")
    try:
        _news_item_path(slug).unlink()
        deleted = True
    except FileNotFoundError:
        deleted = False
    return {"ok": True, "slug": slug, "deleted": deleted}



# ------------------------------------------------------- cyber defcon
# Sentinel Cyber DEFCON 2026-10-27 (DEFCON-RESHAPE-2026-10-27,
# owner order): the former "Sentinel Threat Level", reshaped to
# the 5->1 DEFCON convention. The MATH IS IDENTICAL — same three
# public inputs, same point bands, same score 0-7:
#   KEV points:  CISA KEV additions in the trailing 7 days —
#                >=18 -> 3, 10-17 -> 2, 4-9 -> 1, else 0.
#   News points: Sentinel News Threat Watch + Patch Alert items in
#                the trailing 7 days — >=45 -> 2, 25-44 -> 1, else 0.
#   Feed points: DShield attacking sources today —
#                >=260000 -> 2, >=180000 -> 1, else 0.
# Only the scale direction changed: score 0-1 -> DEFCON 5,
# 2-3 -> 4, 4-5 -> 3, 6 -> 2, 7 -> 1.
_CYBER_DEFCON_NAMES = {5: "ROUTINE", 4: "GUARDED", 3: "ELEVATED",
                       2: "HIGH", 1: "SEVERE"}
# The geopolitical estimate uses the same DEFCON names.
_GEO_DEFCON_NAMES = dict(_CYBER_DEFCON_NAMES)


def _cyber_defcon_path():
    """The persistence file, resolved from DATA_DIR at call time
    so tests can point DATA_DIR at a scratch directory."""
    return DATA_DIR / "cyber_defcon.json"


def _cyber_defcon_score(kev7, tw7, pa7, sources_today):
    """Pure scoring — the formula above, nothing else. Returns
    (score, parts) where parts carries each input's points."""
    try:
        kev7 = int(kev7 or 0)
    except (TypeError, ValueError):
        kev7 = 0
    try:
        news_total = int(tw7 or 0) + int(pa7 or 0)
    except (TypeError, ValueError):
        news_total = 0
    try:
        sources_today = int(sources_today or 0)
    except (TypeError, ValueError):
        sources_today = 0
    kev_points = 3 if kev7 >= 18 else 2 if kev7 >= 10 else \
        1 if kev7 >= 4 else 0
    news_points = 2 if news_total >= 45 else 1 if news_total >= 25 else 0
    feed_points = 2 if sources_today >= 260000 else \
        1 if sources_today >= 180000 else 0
    parts = {"kev_points": kev_points, "news_points": news_points,
             "feed_points": feed_points}
    return kev_points + news_points + feed_points, parts


# Back-compat alias: the scoring bands are unchanged by the reshape.
_threat_level_score = _cyber_defcon_score


def _cyber_defcon_for_score(score):
    """Score -> DEFCON (inverted direction vs the old level)."""
    if score <= 1:
        return 5
    if score <= 3:
        return 4
    if score <= 5:
        return 3
    if score == 6:
        return 2
    return 1


def _convert_legacy_threat_level(data):
    """HISTORY MIGRATION (DEFCON-RESHAPE-2026-10-27): convert a
    legacy threat_level.json payload ({current, history} with
    level 1-5) to the cyber_defcon shape (defcon = 6 - level,
    keeping score/inputs/dates). Returns the converted dict."""
    def conv_current(old):
        if not isinstance(old, dict):
            return None
        try:
            level = int(old.get("level") or 0)
        except (TypeError, ValueError):
            return None
        if level < 1 or level > 5:
            return None
        defcon = 6 - level
        return {"defcon": defcon, "name": _CYBER_DEFCON_NAMES[defcon],
                "score": old.get("score"),
                "parts": old.get("parts") if isinstance(
                    old.get("parts"), dict) else {},
                "inputs": old.get("inputs") if isinstance(
                    old.get("inputs"), dict) else {},
                "computed_at": old.get("computed_at")}
    history = []
    raw_hist = data.get("history") if isinstance(data, dict) else None
    for entry in (raw_hist if isinstance(raw_hist, list) else []):
        if not isinstance(entry, dict):
            continue
        try:
            level = int(entry.get("level") or 0)
        except (TypeError, ValueError):
            continue
        if level < 1 or level > 5 or not entry.get("date"):
            continue
        history.append({"date": entry.get("date"),
                        "defcon": 6 - level,
                        "score": entry.get("score"),
                        "inputs": entry.get("inputs") if isinstance(
                            entry.get("inputs"), dict) else {}})
    current = conv_current(data.get("current")) if isinstance(
        data, dict) else None
    return {"current": current, "history": history}


def _load_cyber_defcon_file(path=None):
    """The persisted {current, history} dict, or an empty shape.
    Never raises — a missing or malformed file is 'no level yet'.
    If cyber_defcon.json is absent but a legacy threat_level.json
    sits beside it, the legacy state is converted and persisted
    as the new file's seed (the old file is left untouched)."""
    path = Path(path) if path else _cyber_defcon_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            current = data.get("current")
            history = data.get("history")
            return {"current": current if isinstance(current, dict)
                    else None,
                    "history": history if isinstance(history, list)
                    else []}
    except Exception:
        pass
    # Migration seed: only when the cyber file itself is absent.
    if not path.exists():
        legacy = path.with_name("threat_level.json")
        try:
            if legacy.is_file():
                data = json.loads(legacy.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    converted = _convert_legacy_threat_level(data)
                    try:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        tmp = path.with_name(path.name + ".tmp")
                        tmp.write_text(json.dumps(
                            converted, indent=1, sort_keys=True),
                            encoding="utf-8")
                        os.replace(tmp, path)
                    except Exception:
                        pass  # the in-memory conversion still holds
                    return converted
        except Exception:
            pass
    return {"current": None, "history": []}


def _get_cyber_defcon():
    """Cheap, never-raising getter for templates: the in-memory
    current level, else the file-loaded current, else None."""
    try:
        cur = store.get("cyber_defcon")
        if isinstance(cur, dict) and cur.get("defcon"):
            return cur
        return _load_cyber_defcon_file()["current"]
    except Exception:
        return None


def _get_cyber_history():
    try:
        return _load_cyber_defcon_file()["history"]
    except Exception:
        return []


def _chicago_today():
    return datetime.now(timezone.utc).astimezone(_CHICAGO_TZ).date()


def _compute_cyber_defcon(path=None):
    """Compute the current Cyber DEFCON from the live stores,
    persist it (atomic tmp+rename, today's snapshot upserted into
    a history trimmed to the last 30 days), and set
    store["cyber_defcon"]. When KEV has not landed (status not
    ok) an existing current level is kept unchanged; with none,
    returns None — the badge shows 'being computed' honestly
    until the first compute."""
    path = Path(path) if path else _cyber_defcon_path()
    existing = _load_cyber_defcon_file(path)
    previous = store.get("cyber_defcon")
    if not (isinstance(previous, dict) and previous.get("defcon")):
        previous = existing["current"]
    kev = store.get("kev") or {}
    if not isinstance(kev, dict) or kev.get("status") != "ok":
        if previous:
            store["cyber_defcon"] = previous
            return previous
        return None
    today = _chicago_today()
    start_ord = today.toordinal() - 6
    tw7 = pa7 = 0
    for item in _load_news():
        try:
            day = datetime.strptime(
                str(item.get("date") or ""), "%Y-%m-%d").date()
        except (TypeError, ValueError):
            continue
        if not (start_ord <= day.toordinal() <= today.toordinal()):
            continue
        if item.get("tag") == "Threat Watch":
            tw7 += 1
        elif item.get("tag") == "Patch Alert":
            pa7 += 1
    try:
        sources_today = int(
            (store.get("threat") or {}).get("sources_today") or 0)
    except (TypeError, ValueError):
        sources_today = 0
    try:
        kev7 = int(kev.get("added_7d") or 0)
    except (TypeError, ValueError):
        kev7 = 0
    score, parts = _cyber_defcon_score(kev7, tw7, pa7, sources_today)
    defcon = _cyber_defcon_for_score(score)
    inputs = {"kev_added_7d": kev7, "news_threat_watch_7d": tw7,
              "news_patch_alert_7d": pa7,
              "dshield_sources_today": sources_today}
    current = {"defcon": defcon, "name": _CYBER_DEFCON_NAMES[defcon],
               "score": score, "parts": parts, "inputs": inputs,
               "computed_at": _utcnow()}
    date_str = today.isoformat()
    cutoff_ord = today.toordinal() - 29
    history = []
    for entry in existing["history"]:
        if not isinstance(entry, dict):
            continue
        try:
            d_ord = datetime.strptime(
                str(entry.get("date") or ""), "%Y-%m-%d").date().toordinal()
        except (TypeError, ValueError):
            continue
        if d_ord >= cutoff_ord and entry.get("date") != date_str:
            history.append(entry)
    history.append({"date": date_str, "defcon": defcon, "score": score,
                    "inputs": inputs})
    history.sort(key=lambda e: str(e.get("date") or ""))
    history = history[-30:]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps({"current": current,
                                   "history": history},
                                  indent=1, sort_keys=True),
                       encoding="utf-8")
        os.replace(tmp, path)
    except Exception as e:
        log.warning("cyber defcon persist failed: %s",
                    type(e).__name__)
    store["cyber_defcon"] = current
    return current


async def _cyber_defcon_loop():
    """Hourly Cyber DEFCON compute. The first run waits ~25s so
    the KEV/threat feeds have a chance to land; after that the
    loop recomputes every 60 minutes. _compute_cyber_defcon keeps
    the previous level when KEV is unavailable, so an early run
    with no KEV yet costs nothing."""
    await asyncio.sleep(25)
    while True:
        try:
            _compute_cyber_defcon()
        except Exception:
            log.exception("cyber defcon compute failed")
        await asyncio.sleep(60 * 60)


# ------------------------------------------- geopolitical defcon
# Geopolitical DEFCON estimate 2026-10-27 (DEFCON-RESHAPE-
# 2026-10-27, owner order): an OPEN-SOURCE ESTIMATE of the
# United States geopolitical DEFCON level — the actual level is
# classified. Five signal families feed a pressure score; a
# candidate level is only ever produced by multi-signal
# triangulation (no single feed can move this level alone), and
# inertia (consecutive-evaluation confirmation) keeps the level
# from jittering on one-off spikes.
WAR_CLASS = ("war", "airstrike", "air strike", "missile strike",
             "offensive", "invasion", "ceasefire", "front line",
             "frontline", "shelling", "bombardment", "drone strike",
             "military operation", "armed conflict", "warzone",
             "war zone",
             # DEFCON-CALIBRATION-2026-10-27: the first live
             # evaluation undercounted this era's headline vocabulary
             # (a US "strike on" a vessel, a named "conflict", a
             # "bombing" campaign read as zero). Era-realistic terms
             # added; every backtest anchor re-verified after.
             "strike on", "strikes on", "struck", "conflict",
             "bombing", "missile", "drone attack", "warfare",
             "hostilities")
POSTURE_CLASS = ("u.s. strike", "us strike", "u.s. troops",
                 "us troops", "u.s. military", "us military",
                 "pentagon", "nato", "carrier strike",
                 "carrier group", "troop deployment",
                 "deployment of u.s", "deployment of us",
                 "u.s. base", "us base", "u.s. forces", "us forces",
                 "american forces", "u.s. warship", "us warship",
                 "military aid", "weapons package")
NUCLEAR_CLASS = ("nuclear", "warhead", "icbm", "atomic weapon",
                 "ballistic missile", "nuclear threat",
                 "nuclear deterrent", "strategic forces")
CONFRONTATION_CLASS = ("naval blockade", "blockade of",
                       "quarantine", "shot down a u.s",
                       "shot down a us", "shot down an american",
                       "airborne alert", "strategic bombers",
                       "nuclear forces on alert",
                       "forces on high alert", "direct clash",
                       "clash between u.s. and",
                       "clash between us and", "exchange of fire")
IMMINENT_CLASS = ("nuclear strike launched",
                  "nuclear attack underway", "nuclear detonation",
                  "nuclear exchange", "missiles launched at",
                  "first nuclear strike", "nuclear weapon used",
                  "nuclear weapons used")

_DOOMSDAY_CLOCK_URL = "https://thebulletin.org/doomsday-clock/"
# Cold seed for the Doomsday Clock: 85 seconds — fetched live
# from the Bulletin on 2026-10-27 during design of this engine.
_DOOMSDAY_COLD_SEED = 85
_GDELT_URL = ("https://api.gdeltproject.org/api/v2/doc/doc?"
              "query=%28war%20OR%20missile%20OR%20airstrike%20OR"
              "%20offensive%29&mode=timelinevolinfo&timespan=7d"
              "&format=json")


def _geo_defcon_path():
    return DATA_DIR / "geo_defcon.json"


def _count_class(texts, keywords):
    """Distinct items with at least one keyword hit (lowercase
    substring scan)."""
    n = 0
    for text in texts:
        low = str(text or "").lower()
        if any(kw in low for kw in keywords):
            n += 1
    return n


def _has_class(texts, keywords):
    return any(any(kw in str(t or "").lower() for kw in keywords)
               for t in texts)


def _band_a(count):
    return 3 if count >= 5 else 2 if count >= 3 else \
        1 if count >= 1 else 0


def _band_b(count):
    return 3 if count >= 6 else 2 if count >= 3 else \
        1 if count >= 1 else 0


def _band_c(count):
    return 3 if count >= 4 else 2 if count >= 2 else \
        1 if count >= 1 else 0


def _doomsday_score(seconds):
    """Doomsday Clock band: <=90s -> 2, 91-120s -> 1, >120s -> 0.
    Family D counts as an ELEVATED family iff its score == 2:
    at its closest-ever settings the Bulletin board is itself an
    elevated civil-advisory signal."""
    if seconds is None:
        return 0
    return 2 if seconds <= 90 else 1 if seconds <= 120 else 0


def _parse_doomsday_clock(text):
    """First 'NN seconds to midnight' match in Bulletin page
    text, or None."""
    if not text:
        return None
    m = re.search(r"(\d+)\s*seconds to midnight", str(text))
    if not m:
        return None
    try:
        return int(m.group(1))
    except (TypeError, ValueError):
        return None


def _gdelt_score_from_ratio(ratio):
    if ratio is None:
        return None
    return 2 if ratio >= 1.5 else 1 if ratio >= 1.2 else 0


def _gdelt_parse(payload):
    """GDELT timelinevolinfo payload -> (score, ratio). Any
    malformed shape is (None, None): E is opportunistic only."""
    try:
        points = payload.get("timeline") if isinstance(
            payload, dict) else None
        values = []
        for point in (points or []):
            if isinstance(point, dict):
                values.append(float(point.get("value") or 0))
        if not values:
            return None, None
        mean = sum(values) / len(values)
        if mean <= 0:
            return None, None
        ratio = values[-1] / mean
        return _gdelt_score_from_ratio(ratio), ratio
    except (TypeError, ValueError):
        return None, None


def _geo_pressure(families):
    total = 0
    for key in ("A", "B", "C", "D"):
        try:
            total += int(families.get(key) or 0)
        except (TypeError, ValueError):
            pass
    # E is opportunistic: a single-source volume metric informs
    # pressure but can never concur in a triangulation, so it is
    # excluded from the elevated set (see _geo_elevated) even
    # though its points count toward pressure when available.
    try:
        total += int(families.get("E") or 0)
    except (TypeError, ValueError):
        pass
    return total


def _geo_elevated(families):
    out = []
    for key in ("A", "B", "C"):
        try:
            if int(families.get(key) or 0) >= 2:
                out.append(key)
        except (TypeError, ValueError):
            pass
    try:
        if int(families.get("D") or 0) == 2:
            out.append("D")
    except (TypeError, ValueError):
        pass
    return out


def _geo_candidate(families, confrontation=False, imminent=False):
    """Pure candidate rule — tests drive this with synthetic
    family scores + flags. families: {A,B,C,D,E} scores (E may
    be None). Triangulation: the severe levels require BOTH high
    pressure AND at least three elevated families AND a flag;
    DEFCON 3 requires pressure >= 4 AND at least two elevated
    families, so no single family can move the level alone.
    DEFCON-CALIBRATION-2026-10-27: the bar was >= 5 at first
    ship; the first LIVE evaluation (real corpus: A2 B0 C0 D2,
    pressure 4, families {A, D} concurring) landed 4, while the
    owner's calibration anchor for exactly this era profile is 3
    (major ongoing war, nuclear-armed power, closest-ever Clock).
    The >= 5 bar double-charged the anchor family: D's 2 points
    are already the price of elevation. Bar set to >= 4; ALL
    backtest anchors re-verified against the new bar in tests
    (1962->2, 1973->3, 9/11->3, today->3, peacetime->5,
    single-family A3 still caps at 4)."""
    pressure = _geo_pressure(families)
    elevated = _geo_elevated(families)
    if imminent and pressure >= 9 and len(elevated) >= 3:
        return 1
    if confrontation and pressure >= 7 and len(elevated) >= 3:
        return 2
    if pressure >= 4 and len(elevated) >= 2:
        return 3
    if pressure >= 3:
        return 4
    return 5


def _geo_required_confirmations(candidate):
    """Inertia: moves to DEFCON 2 or 1 need 3 consecutive
    evaluations; any other move needs 2."""
    return 3 if candidate <= 2 else 2


def _load_geo_defcon_file(path=None):
    """The persisted geo state {current, pending, history,
    changes, clock_seconds}, or an empty shape. Never raises."""
    path = Path(path) if path else _geo_defcon_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            def _dict_or_none(v):
                return v if isinstance(v, dict) else None
            def _list_or_empty(v):
                return v if isinstance(v, list) else []
            clock = data.get("clock_seconds")
            try:
                clock = int(clock) if clock is not None else None
            except (TypeError, ValueError):
                clock = None
            return {"current": _dict_or_none(data.get("current")),
                    "pending": _dict_or_none(data.get("pending")),
                    "history": _list_or_empty(data.get("history")),
                    "changes": _list_or_empty(data.get("changes")),
                    "clock_seconds": clock}
    except Exception:
        pass
    return {"current": None, "pending": None, "history": [],
            "changes": [], "clock_seconds": None}


def _get_geo_defcon():
    try:
        cur = store.get("geo_defcon")
        if isinstance(cur, dict) and cur.get("defcon"):
            return cur
        return _load_geo_defcon_file()["current"]
    except Exception:
        return None


def _get_geo_history():
    try:
        return _load_geo_defcon_file()["history"]
    except Exception:
        return []


def _get_geo_changes():
    try:
        return _load_geo_defcon_file()["changes"]
    except Exception:
        return []


def _get_geo_pending():
    try:
        return _load_geo_defcon_file()["pending"]
    except Exception:
        return None


def _geo_corpora():
    """(geo_titles, news_texts) for one evaluation. Geo items are
    store["geo"]["items"] titles; the news corpus is published
    Sentinel News items dated in the trailing 7 days, as
    title + summary text (one item = one counting unit)."""
    geo_titles = []
    geo = store.get("geo") or {}
    if isinstance(geo, dict):
        for item in (geo.get("items") or []):
            if isinstance(item, dict):
                geo_titles.append(str(item.get("title") or ""))
    today = _chicago_today()
    start_ord = today.toordinal() - 6
    news_texts = []
    for item in _load_news():
        try:
            day = datetime.strptime(
                str(item.get("date") or ""), "%Y-%m-%d").date()
        except (TypeError, ValueError):
            continue
        if not (start_ord <= day.toordinal() <= today.toordinal()):
            continue
        news_texts.append(str(item.get("title") or "") + " " +
                          str(item.get("summary") or ""))
    return geo_titles, news_texts


def _compute_geo_defcon(path=None, clock_seconds=None,
                        clock_source=None, gdelt_score=None,
                        gdelt_ratio=None, gdelt_status=None):
    """One geopolitical evaluation (sync core; the live wrapper
    fetches the clock + GDELT first and passes them in).

    clock_seconds=None means 'no live clock this run': the last
    good persisted seconds are used, or the cold seed when no
    state file exists yet — the source is then 'last-known'.
    gdelt_status defaults to 'unavailable' with score None: E
    contributes 0 and never counts as an elevated family.

    Empty corpora: with no current, returns None (pending — no
    invented level); with a current, keeps it and its timestamp.
    """
    path = Path(path) if path else _geo_defcon_path()
    state = _load_geo_defcon_file(path)
    previous = store.get("geo_defcon")
    if not (isinstance(previous, dict) and previous.get("defcon")):
        previous = state["current"]
    geo_titles, news_texts = _geo_corpora()
    if not geo_titles and not news_texts:
        if previous:
            store["geo_defcon"] = previous
            return previous
        return None
    # Clock: live value persists as the new last-good.
    if clock_seconds is not None:
        try:
            clock_seconds = int(clock_seconds)
        except (TypeError, ValueError):
            clock_seconds = None
    if clock_seconds is not None:
        clock_source = clock_source or "live"
        last_clock = clock_seconds
    else:
        last_clock = state["clock_seconds"]
        if last_clock is None:
            last_clock = _DOOMSDAY_COLD_SEED
        clock_seconds = last_clock
        clock_source = "last-known"
    if gdelt_status is None:
        gdelt_status = "ok" if gdelt_score is not None \
            else "unavailable"
    if gdelt_status != "ok":
        gdelt_score = None
        gdelt_ratio = None
    combined = list(geo_titles) + list(news_texts)
    counts = {"A": _count_class(geo_titles, WAR_CLASS),
              "B": _count_class(combined, POSTURE_CLASS),
              "C": _count_class(combined, NUCLEAR_CLASS)}
    families = {"A": _band_a(counts["A"]),
                "B": _band_b(counts["B"]),
                "C": _band_c(counts["C"]),
                "D": _doomsday_score(clock_seconds),
                "E": gdelt_score}
    flags = {"confrontation": _has_class(combined,
                                         CONFRONTATION_CLASS),
             "imminent": _has_class(combined, IMMINENT_CLASS)}
    pressure = _geo_pressure(families)
    elevated = _geo_elevated(families)
    candidate = _geo_candidate(families, flags["confrontation"],
                               flags["imminent"])
    inputs = {"geo_items": len(geo_titles),
              "news_items_7d": len(news_texts),
              "counts": counts,
              "clock_seconds": clock_seconds,
              "clock_source": clock_source,
              "gdelt": gdelt_status,
              "gdelt_ratio": gdelt_ratio,
              "gdelt_score": gdelt_score}
    now_str = _utcnow()
    changes = list(state["changes"])
    pending = state["pending"]
    applied = False
    if previous is None:
        # First-ever compute applies immediately — no dwell.
        current_defcon = candidate
        pending = None
        applied = True
    elif candidate == previous.get("defcon"):
        current_defcon = candidate
        pending = None
    else:
        if isinstance(pending, dict) and \
                pending.get("defcon") == candidate:
            try:
                count = int(pending.get("count") or 0) + 1
            except (TypeError, ValueError):
                count = 1
        else:
            count = 1
        pending = {"defcon": candidate, "count": count}
        if count >= _geo_required_confirmations(candidate):
            changes.append({
                "ts": now_str, "from": previous.get("defcon"),
                "to": candidate, "pressure": pressure,
                "families": families, "elevated": elevated,
                "flags": flags, "inputs": inputs})
            current_defcon = candidate
            pending = None
            applied = True
        else:
            current_defcon = previous.get("defcon")
    if previous is not None and not applied and \
            current_defcon == previous.get("defcon") and \
            pending is not None:
        # A pending move does not move the level: the standing
        # current (and its supporting inputs) stays exactly as
        # last applied/computed until the move confirms.
        current = previous
    else:
        current = {"defcon": current_defcon,
                   "name": _GEO_DEFCON_NAMES[current_defcon],
                   "pressure": pressure, "families": families,
                   "elevated": elevated, "flags": flags,
                   "inputs": inputs,
                   "clock_seconds": clock_seconds,
                   "clock_source": clock_source,
                   "gdelt": gdelt_status,
                   "computed_at": now_str}
    today = _chicago_today()
    date_str = today.isoformat()
    cutoff_ord = today.toordinal() - 29
    history = []
    for entry in state["history"]:
        if not isinstance(entry, dict):
            continue
        try:
            d_ord = datetime.strptime(
                str(entry.get("date") or ""), "%Y-%m-%d").date().toordinal()
        except (TypeError, ValueError):
            continue
        if d_ord >= cutoff_ord and entry.get("date") != date_str:
            history.append(entry)
    history.append({"date": date_str, "defcon": current["defcon"],
                    "pressure": current.get("pressure"),
                    "inputs": current.get("inputs") or {}})
    history.sort(key=lambda e: str(e.get("date") or ""))
    history = history[-30:]
    new_state = {"current": current, "pending": pending,
                 "history": history, "changes": changes,
                 "clock_seconds": last_clock}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(new_state, indent=1,
                                  sort_keys=True),
                       encoding="utf-8")
        os.replace(tmp, path)
    except Exception as e:
        log.warning("geo defcon persist failed: %s",
                    type(e).__name__)
    store["geo_defcon"] = current
    return current


async def _fetch_doomsday_seconds():
    """Live Doomsday Clock seconds, or None on any failure (the
    caller falls back to the last-known persisted value)."""
    try:
        timeout = config["feeds"]["request_timeout_seconds"]
    except Exception:
        timeout = 20
    try:
        async with httpx.AsyncClient(timeout=min(timeout, 15)) \
                as client:
            resp = await client.get(_DOOMSDAY_CLOCK_URL)
            resp.raise_for_status()
            return _parse_doomsday_clock(resp.text)
    except Exception:
        return None


async def _fetch_gdelt():
    """One GDELT timeline call -> (score, ratio, status). ANY
    failure is 'unavailable': E is opportunistic, and this
    estate's IP currently sits in GDELT's rate-limit pool, so
    unavailability is the expected steady state, not an error
    worth surfacing as one."""
    try:
        timeout = config["feeds"]["request_timeout_seconds"]
    except Exception:
        timeout = 20
    try:
        async with httpx.AsyncClient(timeout=min(timeout, 15)) \
                as client:
            resp = await client.get(_GDELT_URL)
            resp.raise_for_status()
            score, ratio = _gdelt_parse(resp.json())
            if score is None:
                return None, None, "unavailable"
            return score, ratio, "ok"
    except Exception:
        return None, None, "unavailable"


async def _compute_geo_defcon_live():
    clock = await _fetch_doomsday_seconds()
    g_score, g_ratio, g_status = await _fetch_gdelt()
    if clock is not None:
        return _compute_geo_defcon(
            clock_seconds=clock, clock_source="live",
            gdelt_score=g_score, gdelt_ratio=g_ratio,
            gdelt_status=g_status)
    return _compute_geo_defcon(
        gdelt_score=g_score, gdelt_ratio=g_ratio,
        gdelt_status=g_status)


async def _geo_defcon_loop():
    """Hourly geopolitical evaluation. The first run waits ~35s
    (staggered after the Cyber DEFCON loop's ~25s) so the geo
    feed has a chance to land; after that, hourly."""
    await asyncio.sleep(35)
    while True:
        try:
            await _compute_geo_defcon_live()
        except Exception:
            log.exception("geo defcon compute failed")
        await asyncio.sleep(60 * 60)


# ------------------------------------------------------- kc scam alerts
def _kc_scam_alerts():
    """KC Scam Alerts 2026-10-27: published Sentinel News items
    scoped to Kansas City with the Threat Watch tag — nothing
    else. Drafts never reach _load_news, so they can never leak
    here; a KC Patch Alert and a National Threat Watch are both
    deliberately excluded."""
    return [i for i in _load_news()
            if i.get("scope") == "Kansas City"
            and i.get("tag") == "Threat Watch"]


# ------------------------------------------------------------------ pages
def _ctx(request: Request, **kw):
    base = {"request": request, "now": _utcnow(),
            # DEFCON-RESHAPE-2026-10-27: every app page carries
            # the dual badge band (base.html) and the Operations
            # board reads both levels + histories; all getters are
            # cheap and never raise.
            "cyber_defcon": _get_cyber_defcon(),
            "cyber_history": _get_cyber_history(),
            "geo_defcon": _get_geo_defcon(),
            "geo_history": _get_geo_history()}
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


@app.get("/services/cybersecurity-kansas-city", response_class=HTMLResponse)
async def kc_cybersecurity(request: Request):
    # CONVERSION-2026-10-26: Kansas City service landing pages —
    # focused doorways into the /services lines of work for local
    # search intent, one per topic, linked from /services and in
    # the sitemap. Same factual-only discipline as /services (no
    # prices, no client history, no invented response times);
    # Liberty is never named — Kansas City / KC metro only.
    return templates.TemplateResponse(
        request, "kc_cybersecurity.html", _ctx(request))


@app.get("/services/it-support-kansas-city", response_class=HTMLResponse)
async def kc_it_support(request: Request):
    # CONVERSION-2026-10-26: see kc_cybersecurity above.
    return templates.TemplateResponse(
        request, "kc_it_support.html", _ctx(request))


@app.get("/services/network-security-installs-kansas-city",
         response_class=HTMLResponse)
async def kc_network_installs(request: Request):
    # CONVERSION-2026-10-26: see kc_cybersecurity above.
    return templates.TemplateResponse(
        request, "kc_network_installs.html", _ctx(request))


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


@app.get("/sentinel-news/feed.xml")
async def sentinel_news_feed(request: Request):
    # SENTINEL-NEWS-2026-10-26: the Sentinel News RSS feed, built
    # from the same _load_news() data the pages render (published
    # items only) — one source, so the feed can never drift from
    # the page or leak a draft. Registered BEFORE
    # /sentinel-news/{slug} so "feed.xml" is never read as a slug.
    from email.utils import format_datetime as _fmt_dt
    published = _load_news()
    items = []
    for item in published:
        day = datetime.strptime(item["date"], "%Y-%m-%d").replace(
            tzinfo=timezone.utc)
        items.append(
            "<item><title>%s</title><link>%s%s</link>"
            "<guid isPermaLink=\"true\">%s%s</guid>"
            "<pubDate>%s</pubDate><category>%s</category>"
            "<description>%s</description></item>"
            % (_xml_escape(item["title"]), _SITE_BASE, item["url"],
               _SITE_BASE, item["url"], _fmt_dt(day),
               _xml_escape(item["tag"]),
               _xml_escape(item["summary"])))
    if published:
        latest = datetime.strptime(published[0]["date"],
                                   "%Y-%m-%d").replace(
            tzinfo=timezone.utc)
        built = "<lastBuildDate>%s</lastBuildDate>" % _fmt_dt(latest)
    else:
        built = ""
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<rss version="2.0"><channel>'
           "<title>Sentinel Safeguard \u2014 Sentinel News</title>"
           "<link>%s/sentinel-news</link>"
           "<description>Announcements, threat watches, and patch "
           "alerts from Sentinel Safeguard, Kansas City metro."
           "</description>"
           "<language>en-us</language>%s%s</channel></rss>"
           % (_SITE_BASE, built, "".join(items)))
    return Response(content=xml, media_type="application/rss+xml")


@app.get("/sentinel-news", response_class=HTMLResponse)
async def sentinel_news(request: Request):
    # SENTINEL-NEWS-2026-10-26: the public news page — published
    # items from the News Desk, newest first. Drafts never reach
    # this handler's data (see _load_news), so nothing the desk
    # has not published can render here.
    return templates.TemplateResponse(
        request, "sentinel_news.html", _ctx(request, items=_load_news()))


@app.get("/sentinel-news/{slug}", response_class=HTMLResponse)
async def sentinel_news_item(request: Request, slug: str):
    for item in _load_news():
        if item["slug"] == slug:
            return templates.TemplateResponse(
                request, "sentinel_news_item.html",
                _ctx(request, item=item))
    # A draft's permalink and an unknown slug are the same plain
    # 404 — the page neither confirms nor denies a draft exists.
    raise HTTPException(404, "Not found.")


@app.get("/kc-scam-alerts/feed.xml")
async def kc_scam_alerts_feed(request: Request):
    # KC Scam Alerts 2026-10-27: the KC feed, built from the same
    # _kc_scam_alerts() data the page renders — one source, so the
    # feed can never drift from the page. Registered before the
    # page route for symmetry with the Sentinel News feed.
    from email.utils import format_datetime as _fmt_dt
    published = _kc_scam_alerts()
    items = []
    for item in published:
        day = datetime.strptime(item["date"], "%Y-%m-%d").replace(
            tzinfo=timezone.utc)
        items.append(
            "<item><title>%s</title><link>%s%s</link>"
            "<guid isPermaLink=\"true\">%s%s</guid>"
            "<pubDate>%s</pubDate><category>%s</category>"
            "<description>%s</description></item>"
            % (_xml_escape(item["title"]), _SITE_BASE, item["url"],
               _SITE_BASE, item["url"], _fmt_dt(day),
               _xml_escape(item["tag"]),
               _xml_escape(item["summary"])))
    if published:
        latest = datetime.strptime(published[0]["date"],
                                   "%Y-%m-%d").replace(
            tzinfo=timezone.utc)
        built = "<lastBuildDate>%s</lastBuildDate>" % _fmt_dt(latest)
    else:
        built = ""
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<rss version="2.0"><channel>'
           "<title>Sentinel Safeguard \u2014 KC Scam Alerts</title>"
           "<link>%s/kc-scam-alerts</link>"
           "<description>Kansas City metro scam and fraud alerts "
           "from Sentinel Safeguard.</description>"
           "<language>en-us</language>%s%s</channel></rss>"
           % (_SITE_BASE, built, "".join(items)))
    return Response(content=xml, media_type="application/rss+xml")


@app.get("/kc-scam-alerts", response_class=HTMLResponse)
async def kc_scam_alerts(request: Request):
    # KC Scam Alerts 2026-10-27: Kansas City metro scam/fraud
    # alerts — the Kansas City-scoped Threat Watch items from
    # Sentinel News, on their own page.
    return templates.TemplateResponse(
        request, "kc_scam_alerts.html",
        _ctx(request, items=_kc_scam_alerts()))


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
_SITEMAP_PATHS = ["/", "/about", "/services",
                  "/services/cybersecurity-kansas-city",
                  "/services/it-support-kansas-city",
                  "/services/network-security-installs-kansas-city",
                  "/who-we-protect",
                  "/how-it-works", "/insights", "/privacy",
                  "/operations", "/threat-map", "/geopolitical",
                  "/flights", "/internet-weather",
                  "/contact", "/report-issue",
                  "/assessment", "/tools", "/training/phishing",
                  "/faq", "/disclosure", "/availability",
                  "/sentinel-news", "/kc-scam-alerts",
                  # DEFCON-RESHAPE-2026-10-27: the two DEFCON pages.
                  "/cyber-defcon", "/geopolitical-defcon",
                  # BREACH-CHECK-2026-10-27: the Breach Check page.
                  "/breach-check"]


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
    # SENTINEL-NEWS-2026-10-26: published news items join the
    # sitemap with their dates; drafts are not public and are
    # never listed.
    for item in _load_news():
        urls.append("<url><loc>%s%s</loc><lastmod>%s</lastmod></url>"
                    % (_SITE_BASE, item["url"], item["date"]))
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


@app.get("/internet-weather", response_class=HTMLResponse)
async def internet_weather(request: Request):
    # Internet Weather 2026-10-27: country-level outage picture
    # from IODA + RIPEstat (see feeds.fetch_internet_weather);
    # the page's script reads /api/internet-weather.
    return templates.TemplateResponse(
        request, "internet_weather.html", _ctx(request))


@app.get("/cyber-defcon", response_class=HTMLResponse)
async def cyber_defcon_page(request: Request):
    # DEFCON-RESHAPE-2026-10-27: the Cyber DEFCON's own page —
    # hero level, score breakdown, methodology, history.
    return templates.TemplateResponse(
        request, "cyber_defcon.html", _ctx(request))


@app.get("/geopolitical-defcon", response_class=HTMLResponse)
async def geopolitical_defcon_page(request: Request):
    # DEFCON-RESHAPE-2026-10-27: the geopolitical estimate's own
    # page — hero (estimate-labeled), drivers, methodology,
    # backtest anchors, the self-scoring change log, history.
    return templates.TemplateResponse(
        request, "geopolitical_defcon.html", _ctx(
            request, geo_pending=_get_geo_pending(),
            geo_changes=_get_geo_changes()))


@app.get("/breach-check", response_class=HTMLResponse)
async def breach_check_page(request: Request):
    # BREACH-CHECK-2026-10-27 (owner order 2026-10-27): Sentinel's
    # own public breach-check page — an email breach lookup
    # (XposedOrNot, proxied by the POST endpoints below) and a
    # password exposure check (Have I Been Pwned's Pwned Passwords
    # k-anonymity range API; the hashing happens in the visitor's
    # browser). The page is Sentinel's own name and branding —
    # "Breach Check" — never the upstream services' page names.
    return templates.TemplateResponse(
        request, "breach_check.html", _ctx(request))


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
            # cyber_defcon / geo_defcon are dict-or-None store
            # entries (DEFCON-RESHAPE-2026-10-27), not feed dicts —
            # only dict stores report here.
            "feeds": {k: {"updated": v.get("updated"), "status": v.get("status")}
                      for k, v in store.items()
                      if k != "briefing" and isinstance(v, dict)}}


@app.get("/status", response_class=HTMLResponse)
async def status_page(request: Request):
    # BH-2026-10-23 (H-1): exact start time + uptime + feed states are
    # operational detail — in-app gate, as with /news and /health.
    require_admin(request)
    now = datetime.now(timezone.utc)
    uptime = int((now - STARTED_AT).total_seconds()) if STARTED_AT else 0
    feeds = []
    for k, v in store.items():
        if k == "briefing" or not isinstance(v, dict):
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


@app.get("/api/internet-weather")
async def api_internet_weather():
    return JSONResponse(store["weather"])


@app.get("/api/cyber-defcon")
async def api_cyber_defcon():
    # DEFCON-RESHAPE-2026-10-27: the current Cyber DEFCON plus
    # its history; until the first compute lands, an honest
    # pending shape (defcon null) instead of a fabricated level.
    # (The old /api/threat-level route is removed by this reshape.)
    current = _get_cyber_defcon()
    history = _get_cyber_history()
    if not current:
        return JSONResponse({"defcon": None, "pending": True,
                             "history": history})
    out = dict(current)
    out["history"] = history
    out["pending"] = False
    return JSONResponse(out)


@app.get("/api/geo-defcon")
async def api_geo_defcon():
    # DEFCON-RESHAPE-2026-10-27: the geopolitical DEFCON estimate
    # — current (with pressure, families, elevated set, flags,
    # inputs incl. per-family raw counts, clock + GDELT status),
    # the pending (inertia) state, history, and the change log.
    # Until the first compute lands, defcon is null — no invented
    # estimate.
    current = _get_geo_defcon()
    history = _get_geo_history()
    changes = _get_geo_changes()
    pending = _get_geo_pending()
    if not current:
        return JSONResponse({"defcon": None, "pending": pending,
                             "awaiting_first": True,
                             "history": history,
                             "changes": changes})
    out = dict(current)
    out["history"] = history
    out["changes"] = changes
    out["pending"] = pending
    return JSONResponse(out)


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


# ------------------------------------------------------------------ breach check
# BREACH-CHECK-2026-10-27 (owner order 2026-10-27): the two
# same-origin proxy endpoints behind /breach-check. Both are POST
# only, so a searched value never rides a URL.
#
# Email leg: the address goes to XposedOrNot's keyless check-email
# API (that IS the lookup — the page discloses it plainly), and the
# breach names it returns are joined against a cached copy of
# XposedOrNot's /v1/breaches metadata corpus (refreshed at most
# every 6 hours) for the card details.
#
# Password leg: the visitor's browser SHA-1 hashes the password
# locally and sends ONLY the first 5 hex characters (the prefix).
# This endpoint validates that shape, asks Have I Been Pwned's
# Pwned Passwords range API for that prefix, and returns the
# suffix:count list — the browser finds its own suffix locally.
# The full password and the full hash never reach this server.
#
# PRIVACY (pinned by tests/test_breach_check_2026_10_27.py):
# searched emails, passwords, and prefixes are never stored,
# logged, or written anywhere. In particular the error paths log
# only the event and the exception's CLASS NAME — an httpx error
# string can embed the request URL, and the email leg's URL
# carries the searched address.
XPOSED_CHECK_EMAIL_URL = "https://api.xposedornot.com/v1/check-email/"
XPOSED_BREACHES_URL = "https://api.xposedornot.com/v1/breaches"
PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/"
_BREACH_CORPUS_TTL = 6 * 3600  # seconds; metadata corpus refresh cap
_BREACH_RANGE_TTL = 3600  # range replies are cacheable public data
_BREACH_RANGE_MAX_BYTES = 256 * 1024  # a range reply is ~30KB
_BREACH_MAX_NAMES = 200  # defensive cap on cards per lookup

_breach_corpus_cache = {"at": 0.0, "ok": False, "by_name": {}}
_breach_range_cache = {}


def _breach_email_shape(email: str) -> bool:
    """Server-side email shape check (the browser's type=email is
    a hint, never the validation): one @, a dotted domain, no
    whitespace, bounded lengths."""
    if not email or len(email) > 254:
        return False
    return bool(re.fullmatch(
        r"[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}", email))


def _breach_check_names(payload):
    """XposedOrNot check-email payload -> the flat breach-name
    list, or None when the payload is not the documented shape.
    A found address returns {"breaches": [[name, ...]], ...}
    (note the double-nested list); a clean one returns
    {"Error": "Not found", "email": null}, which parses to []."""
    if not isinstance(payload, dict):
        return None
    if "breaches" not in payload:
        if "Error" in payload:
            return []
        return None
    raw = payload.get("breaches")
    if not isinstance(raw, list):
        return None
    names = []
    for item in raw:
        if isinstance(item, list):
            names.extend(x for x in item if isinstance(x, str))
        elif isinstance(item, str):
            names.append(item)
    out, seen = [], set()
    for name in names:
        name = name.strip()[:120]
        if name and name not in seen:
            seen.add(name)
            out.append(name)
        if len(out) >= _BREACH_MAX_NAMES:
            break
    return out


def _breach_corpus_parse(payload):
    """XposedOrNot /v1/breaches payload -> {breachID: card fields},
    or None when the payload is not the documented shape. Field
    names are the corpus's REAL ones (verified live 2026-10-27):
    breachID, breachedDate, domain, exposedData (a list of data
    type strings), passwordRisk, exposedRecords,
    exposureDescription. Only the card fields ride onward."""
    if not isinstance(payload, dict):
        return None
    rows = payload.get("exposedBreaches")
    if not isinstance(rows, list):
        return None
    by_name = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("breachID")
        if not isinstance(name, str) or not name.strip():
            continue
        exposed = row.get("exposedData")
        if isinstance(exposed, list):
            exposed = [str(x).strip()[:80] for x in exposed
                       if isinstance(x, str) and x.strip()][:40]
        else:
            exposed = []
        date = row.get("breachedDate")
        date = date.strip()[:10] if isinstance(date, str) else ""
        domain = row.get("domain")
        domain = domain.strip()[:120] if isinstance(domain, str) else ""
        risk = row.get("passwordRisk")
        risk = risk.strip()[:40] if isinstance(risk, str) else ""
        records = row.get("exposedRecords")
        if isinstance(records, bool) or not isinstance(records, int):
            records = None
        by_name[name.strip()] = {
            "name": name.strip(), "date": date, "domain": domain,
            "exposed_data": exposed, "password_risk": risk,
            "exposed_records": records}
    return by_name


def _breach_card(name: str, meta):
    """One result card. meta=None (the breach is missing from the
    metadata corpus, or the corpus itself is unavailable) is the
    honest name-only fallback — the card says so via
    metadata=False and invents no date, domain, or data types."""
    if not isinstance(meta, dict):
        return {"name": name, "date": "", "domain": "",
                "exposed_data": [], "password_risk": "",
                "exposed_records": None, "metadata": False}
    card = dict(meta)
    card["name"] = name
    card["metadata"] = True
    return card


async def _breach_upstream_check_email(email: str):
    """One XposedOrNot check-email call; returns the parsed JSON.
    Isolated as its own seam (like _turnstile_siteverify) so tests
    stub exactly this function and never touch the network."""
    async with feeds._make_client(timeout=15.0) as client:
        resp = await client.get(
            XPOSED_CHECK_EMAIL_URL + quote(email, safe=""),
            headers={"User-Agent": "SentinelLive/1.0 "
                                   "(Sentinel Safeguard LLC)"})
    resp.raise_for_status()
    return resp.json()


async def _breach_upstream_breaches():
    """One XposedOrNot /v1/breaches corpus call (see the seam
    note on _breach_upstream_check_email)."""
    async with feeds._make_client(timeout=20.0) as client:
        resp = await client.get(
            XPOSED_BREACHES_URL,
            headers={"User-Agent": "SentinelLive/1.0 "
                                   "(Sentinel Safeguard LLC)"})
    resp.raise_for_status()
    return resp.json()


async def _breach_upstream_range(prefix: str) -> str:
    """One Pwned Passwords range call; returns the raw
    suffix:count text (see the seam note above)."""
    async with feeds._make_client(timeout=15.0) as client:
        resp = await client.get(
            PWNED_RANGE_URL + prefix,
            headers={"User-Agent": "SentinelLive/1.0 "
                                   "(Sentinel Safeguard LLC)"})
    resp.raise_for_status()
    return resp.text


async def _breach_corpus():
    """The metadata corpus as (by_name, available). A fresh cache
    is served as-is; past the TTL one refresh is attempted, and a
    failed refresh falls back to the stale cache. available=False
    means no corpus at all — cards degrade to name-only."""
    now = time.time()
    cache = _breach_corpus_cache
    if cache.get("ok") and now - float(cache.get("at") or 0) \
            < _BREACH_CORPUS_TTL:
        return cache["by_name"], True
    try:
        by_name = _breach_corpus_parse(await _breach_upstream_breaches())
        if by_name is None:
            raise ValueError("breaches corpus: unexpected shape")
    except Exception as e:
        # Class name only — see the PRIVACY note at this section's
        # head (this call carries no searched value, but the
        # discipline is uniform).
        log.warning("breach-check metadata corpus unavailable (%s)",
                    type(e).__name__)
        if cache.get("ok"):
            return cache["by_name"], True
        return {}, False
    _breach_corpus_cache.update(
        {"at": now, "ok": True, "by_name": by_name})
    return by_name, True


def _breach_range_parse(text):
    """Pwned Passwords range text -> ["SUFFIX:count", ...], or
    None when nothing in the body parses. Defensive: malformed
    lines are skipped, suffixes must be 35 uppercase hex chars,
    counts must be plain integers, and an oversized body is
    refused outright rather than parsed."""
    if not isinstance(text, str) or len(text.encode("utf-8", "ignore")) \
            > _BREACH_RANGE_MAX_BYTES:
        return None
    out = []
    for line in text.splitlines():
        suffix, sep, count = line.strip().partition(":")
        if not sep:
            continue
        suffix = suffix.strip().upper()
        count = count.strip()
        if re.fullmatch(r"[0-9A-F]{35}", suffix) and \
                re.fullmatch(r"[0-9]+", count):
            out.append(f"{suffix}:{int(count)}")
        if len(out) >= 2000:
            break
    return out or None


# BREACH-CHECK-2026-10-27: the two API routes are POST only, and
# say so — without these, a GET falls through to the static mount
# at "/" and answers a plain 404, blurring the contract (a GET
# also has no business carrying a searched value in its URL).
@app.get("/api/breach-check/email")
@app.get("/api/breach-check/password")
async def api_breach_check_post_only(request: Request):
    raise HTTPException(405, "Method not allowed — POST only.")


@app.post("/api/breach-check/email")
async def api_breach_check_email(request: Request):
    rate_limit(request)
    body = await _json_body(request)
    await _verify_turnstile(request, body)
    email = _s(body, "email").strip()
    if not _breach_email_shape(email):
        raise HTTPException(400, "Enter a valid email address.")
    try:
        payload = await _breach_upstream_check_email(email)
    except Exception as e:
        log.warning("breach-check email lookup unavailable (%s)",
                    type(e).__name__)
        raise HTTPException(
            503, "Breach lookup is unavailable right now — please "
                 "try again later.")
    names = _breach_check_names(payload)
    if names is None:
        log.warning("breach-check email lookup: unexpected "
                    "upstream shape")
        raise HTTPException(
            503, "Breach lookup is unavailable right now — please "
                 "try again later.")
    if not names:
        return {"ok": True, "found": False, "breaches": [],
                "metadata_available": True}
    by_name, available = await _breach_corpus()
    cards = [_breach_card(name, by_name.get(name)) for name in names]
    return {"ok": True, "found": True, "breaches": cards,
            "metadata_available": available}


@app.post("/api/breach-check/password")
async def api_breach_check_password(request: Request):
    # The password leg gets the same rate limit AND the same
    # Turnstile gate as the email leg (the _verify_turnstile call
    # is one line — prefix calls are cheap to abuse for dictionary
    # grinding, so there is no reason to leave this endpoint
    # ungated where the site has the gate switched on).
    rate_limit(request)
    body = await _json_body(request)
    await _verify_turnstile(request, body)
    prefix = _s(body, "prefix")
    if not re.fullmatch(r"[0-9A-F]{5}", prefix or ""):
        raise HTTPException(
            400, "Password check needs exactly the first 5 "
                 "characters of the hash — reload the page and "
                 "try again.")
    now = time.time()
    hit = _breach_range_cache.get(prefix)
    if hit and now - hit[0] < _BREACH_RANGE_TTL:
        return {"ok": True, "prefix": prefix, "suffixes": hit[1]}
    try:
        suffixes = _breach_range_parse(
            await _breach_upstream_range(prefix))
        if suffixes is None:
            raise ValueError("range reply: unexpected shape")
    except Exception as e:
        log.warning("breach-check password lookup unavailable (%s)",
                    type(e).__name__)
        raise HTTPException(
            503, "Password check is unavailable right now — please "
                 "try again later.")
    if len(_breach_range_cache) > 512:
        _breach_range_cache.clear()
    _breach_range_cache[prefix] = (now, suffixes)
    return {"ok": True, "prefix": prefix, "suffixes": suffixes}


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
