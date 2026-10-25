# Sentinel Live Server

[![Release](https://img.shields.io/badge/release-v1.0.3-blue?style=flat-square)](https://github.com/TheRealJesusTheHacker/sentinel-live/releases/tag/v1.0.3)
[![Build Windows EXE](https://github.com/TheRealJesusTheHacker/sentinel-live/actions/workflows/build-exe.yml/badge.svg?style=flat-square)](https://github.com/TheRealJesusTheHacker/sentinel-live/actions/workflows/build-exe.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=flat-square)](requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.143.0-009688?style=flat-square)](requirements.txt)
[![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square)](install.ps1)
[![License](https://img.shields.io/badge/license-Proprietary-red?style=flat-square)](LICENSE)

The server side of the Sentinel Safeguard website: a FastAPI application that
serves the public website's front door, live threat, geopolitical, flight,
and news pages, plus the contact, ticket, and newsletter APIs behind the
public site — packaged as a single Windows executable (`SentinelLive.exe`).

It is built to run silently on an always-on host: as a packaged Windows
install it is one `.exe`, no Python install, no console window, started
automatically at every boot by the installer described below. The current
production deployment runs this same code from source on the owner's Linux
server — see [Status](#status).

## Overview

Sentinel Live does three jobs in one process:

1. **Live pages.** Four server-rendered pages present data that refreshes in
   the background on timers: a cyber threat map, a geopolitical feed with a
   hotspot map, a flight lookup, and a news hub with a daily briefing. The
   public front door and the `/operations` page carry live-preview sections
   fed by the same data — the homepage's "Live intel, always on." cards and
   the operations page's "Live right now" panels refresh on a timer and
   click through to the full pages.
2. **Website backend.** The public website is a static frontend; its forms
   `fetch()` this server's JSON APIs. Contact messages, Get Help tickets, and
   newsletter signups are validated, rate-limited, and stored in an embedded
   SQLite database — there is no external database to run.
3. **Optional HackProof payments pass-through.** Config-gated and off by
   default, it fronts exactly three public routes of a HackProof payments
   service that stays bound to loopback on the same machine. Details in
   [HackProof payments pass-through](#hackproof-payments-pass-through-optional-off-by-default).

By default the server binds only to `127.0.0.1:8443`. Public exposure, when
wanted, is via an optional Cloudflare Tunnel — the server itself does not need
a public port.

## Who it is for

- Visitors to the Sentinel Safeguard website, who use the public pages and
  forms listed below.
- The site owner, who reviews stored submissions through the admin console
  and admin APIs.

## Features

- **Live threat map** from the SANS DShield sensor network (keyless),
  refreshed every 5 minutes by default, with optional ThreatFox
  malware-family enrichment when a free abuse.ch Auth-Key is configured.
- **Geopolitical feed and hotspot map** built from RSS, refreshed every
  15 minutes by default, with a per-story impact note generated for each item.
- **News hub** with seven configured sections — National, Missouri,
  Kansas City, Geopolitical, Cyber, Political, and Markets — refreshed every
  30 minutes by default, plus a daily briefing shown at the top of the page.
- **Flight lookup** by flight number through AviationStack, when the owner
  has put an AviationStack API key in `config.yaml`.
- **Live previews on the front door:** the homepage and `/operations` show
  always-on preview cards for the threat, geopolitical, and flight data,
  fed by the public read APIs below and auto-refreshing, with click-through
  to the full tracker pages. The flight preview reuses the tracker's own
  cached search, so it spends no additional provider quota.
- **Report an Issue page:** a public, no-login ticket form (`/report-issue`,
  also linked as `/ticket`) whose submissions land in the same ticket store
  as the ticket API.
- **Form intake with no accounts:** contact messages, Get Help tickets (the
  API returns the new `ticket_id`), and newsletter signups (duplicate emails
  still return success, so the endpoint does not reveal who is subscribed).
- **Cloudflare Turnstile bot check (optional, config-gated):** when enabled
  with a secret key configured, the three public form endpoints
  (`/api/contact`, `/api/ticket`, `/api/newsletter`) verify the submission's
  Turnstile token with Cloudflare server-side before anything is stored,
  and fail closed when verification is unreachable.
- **Admin console and admin APIs** for listing submissions, exporting them as
  CSV or JSON, and updating a ticket's status and admin notes.
- **Single-file Windows build:** PyInstaller `--onefile --noconsole`, with
  templates and static assets bundled; configuration, the SQLite database,
  logs, and an optional static `site/` folder all live next to the exe.
- **Hardened defaults:** no CORS by default, per-IP rate limits, request-body
  size caps, `X-Content-Type-Options: nosniff` on responses, and file-only
  rotating logs (2 MB per file, 5 backups) — see [Security notes](#security-notes).

## What it serves

| Path | What it is |
|---|---|
| `/` | The public front door. With the static `site/` folder present (the production deployment) this is the Sentinel Safeguard homepage, including the "Live intel, always on." preview section |
| `/operations` | Live operations page — the threat, geopolitical, and news panels, plus "Live right now" previews of the three trackers |
| `/about` | About the Company — who the company is, who leads it, what it does, and the proof that is already public |
| `/services` | Services — the five lines of work in full (penetration testing, cybersecurity & IT, security installs, incident response & forensics, custom websites & software), each with who it is for and what the client walks away with |
| `/who-we-protect` | Who We Protect — who the work is built for: apartment complexes & property management, senior centers & care facilities, churches & nonprofits, local service companies & trades, and residential homes & families — framed as a focus, never a fence, with an open door to every other industry |
| `/how-it-works` | How It Works — the engagement process in six steps for a first-time buyer (reach out → talk and look → written scope signed before work → the work → report & walkthrough → after), the real paperwork named (Engagement Letter, Scope of Work, Penetration Testing Authorization, Chain of Custody), an emergencies shortcut, and what Sentinel asks of the client; no prices and no invented response times or SLAs |
| `/contact` | Contact — the dedicated contact page: the homepage contact form replicated exactly (same fields, Turnstile widget, and `/api/contact` payload), the direct phone/email block, what-to-include guidance, an emergencies strip to `/report-issue`, and pointers to `/how-it-works` and `/who-we-protect`; by appointment only, and no response-time promises anywhere |
| `/report-issue` | Public Report an Issue page — no-login ticket intake form (`/ticket` serves the identical page) |
| `/threat-map` | Live cyber threat map — attacks observed by the SANS DShield sensor network, refreshed every 5 min by default (keyless). Optional free abuse.ch key adds ThreatFox malware-family enrichment |
| `/geopolitical` | Geopolitical news feed + hotspot map with per-story impact notes (refreshed every 15 min by default) |
| `/flights` | Flight tracker — search any flight number (needs an AviationStack API key in `config.yaml`) |
| `/news` | News hub: National, Missouri, Kansas City, Geopolitical, Cyber, Political, Markets + the daily briefing |
| `/health` | Health check JSON — `ok`, current time, frozen/exe flag, uptime, and per-feed refresh status |
| `/status` | Status page — start time, uptime, and per-feed refresh status |
| `/admin` | Admin console — view stored form submissions (admin rules below) |
| `/static/*` | The bundled stylesheet and other static assets |

If a `site/` folder exists next to the exe, it is also mounted at `/` as a
static site (`html=True`) after the routes above are registered — that is how
the pure-frontend public website is served when it is deployed alongside the
server.

### Access split (the rule whenever this server is publicly exposed)

Public means public, and the rest is gated — this split is the owner's
standing order for any public deployment of this code:

- **Public:** `/`, `/operations`, `/about`, `/services`, `/who-we-protect`, `/how-it-works`, `/contact`, `/report-issue`,
  `/ticket`, `/flights`, `/geopolitical`, `/threat-map` and their read
  APIs (`/api/threat-data`, `/api/geo-data`), plus the public form
  endpoints (`POST /api/contact`, `/api/ticket`, `/api/newsletter`),
  which are rate-limited and Turnstile-gated as described above.
- **Gated:** `/admin` and `/api/admin/*` (the app's own admin rules
  below), `/news` and the briefing (including `/api/news-data`, which
  carries the briefing), `/status`, and `/health`. Stored ticket and
  contact data is reachable only through the gated admin surfaces.
- This app deliberately does **not** serve Sentinel Command in any form.
  The site's header links out to the public library hosted on Command's
  own host; the library is served there, not here. Sentinel Safeguard's
  mail (Sentinel Mail) likewise runs as a separate service — this
  application neither serves nor proxies it.

The app itself enforces the gated side in code — gated routes check
the same admin rule as `/admin` before serving anything — and the
production deployment adds an edge access layer on top. The layering
is deliberate: no single control is the only thing standing between
the internet and the gated surfaces.

Live-data JSON endpoints backing those pages:

| Endpoint | Purpose |
|---|---|
| `GET /api/threat-data` | Current threat-map data (the in-memory threat store) |
| `GET /api/geo-data` | Current geopolitical data |
| `GET /api/news-data` | Current news sections and the daily briefing (admin-gated — it carries the briefing) |

## Website backend APIs (JSON, stored in embedded SQLite)

| Endpoint | Purpose |
|---|---|
| `POST /api/contact` | Contact form → stored in the `contacts` table. Requires a name, an email containing `@`, and a message (5,000 characters max) |
| `POST /api/ticket` | Get Help ticket intake (no login) → `tickets` table, status `new`; returns `{"ok": true, "ticket_id": …}`. Priority is `Low`/`Normal`/`High` — anything else is stored as `Normal` |
| `POST /api/newsletter` | Newsletter/alerts signup → `newsletter` table (email is unique; duplicates are deduped) |
| `POST /api/briefing` | Daily briefing ingest → saved to `data/briefing.json` and rendered at the top of `/news` |
| `GET /api/admin/submissions?type=tickets\|contacts\|newsletter` | View stored rows (admin; `limit` is clamped to 1–500, with `offset`) |
| `GET /api/admin/export?type=tickets&format=csv\|json` | Download an export (admin) |
| `PATCH /api/admin/tickets/{id}` | Update ticket status / admin notes (admin) |

Invalid JSON, a non-object body, or a missing required field on the form
endpoints returns `400`, not a stored row.

## Architecture

```
Visitor ──https──▶ Cloudflare Tunnel ──▶ 127.0.0.1:8443 ──▶ SentinelLive.exe
                                                              ├─ static site  (./site/, when present)
                                                              ├─ 4 live pages  (feeds refresh on a timer)
                                                              ├─ form APIs ──▶ SQLite (./data/sentinel-live.db)
                                                              └─ admin API    (localhost or X-Admin-Key)
host boots ──▶ Task Scheduler ──▶ SentinelLive.exe (auto-start)
                              └─▶ cloudflared tunnel (if enabled in config.yaml)
```

How it works, in the order a request and a refresh travel:

- **Startup** (`app.py`): configuration is loaded and validated, the SQLite
  schema is created if needed, any stored briefing is loaded, and three
  background refresh loops start — threat, geopolitical, and news. A loop
  failure is logged and recorded as that feed's status; it does not kill the
  loop or the server. A corrupt SQLite file is quarantined aside with a
  timestamped `.corrupt-…` name and a fresh database is initialized, so a bad
  database does not brick startup.
- **Feeds** (`feeds.py`): the threat fetcher reads the SANS DShield threat
  feeds, geolocates the observed source IPs, and optionally merges ThreatFox
  malware families; the RSS fetchers parse the configured feeds per section
  (failures are tolerated per feed), derive geopolitical hotspots and impact
  notes, and the flight lookup calls AviationStack's `/v1/flights`.
- **In-memory live data, persistent form data:** refreshed page data lives in
  an in-memory store served by the `/api/*-data` endpoints; only form
  submissions and the briefing are persisted (SQLite and
  `data/briefing.json` respectively).
- **Frozen-path rules:** bundled resources (templates, static) resolve via
  `sys._MEIPASS` inside the exe; writable state — `config.yaml`, `data/`,
  `logs/`, and `site/` — resolves next to the exe, never inside it.
- No external database. The SQLite file is created automatically on first
  run, next to the exe (`data/sentinel-live.db`, WAL mode).
- All logging goes to `logs/server.log` — the exe has no console.
- `config.yaml` lives next to the exe and is written with defaults on first
  run if it is missing. Keys are never hardcoded in the source.

## Install

### From a release (the normal path)

Current release: **v1.0.3**, providing `SentinelLive.exe` and
`SHA256SUMS.txt`.

1. **Download** `SentinelLive.exe` (and `SHA256SUMS.txt`, to verify it) from
   the [v1.0.3 release](https://github.com/TheRealJesusTheHacker/sentinel-live/releases/tag/v1.0.3)
   and put the exe in an administrator-protected folder, e.g.
   `C:\SentinelLive\`. Copy `install.ps1` / `uninstall.ps1` from this
   repository next to it. Do not use a folder inside a user profile — see
   the installer warning below.
2. **Right-click `install.ps1` → "Run with PowerShell"** (as Administrator;
   the script requires it). It:
   - errors out if `SentinelLive.exe` is not next to the script;
   - warns loudly if the install folder is inside a user-writable profile
     folder (`%USERPROFILE%\…` or `C:\Users\Public\…`);
   - reads host/port and the tunnel setting from `config.yaml` when present
     (defaults `127.0.0.1:8443`, tunnel off);
   - registers a `SentinelLiveServer` scheduled task — AtStartup trigger,
     SYSTEM principal at the highest run level, hidden, restart on failure
     (3 restarts, 1 minute apart) — replacing any older task of that name;
   - registers a `SentinelLiveTunnel` task as well, but only when the tunnel
     is enabled in `config.yaml`, `cloudflared` is found, and `-NoTunnel`
     was not passed;
   - starts the server immediately (no reboot needed) and verifies it by
     calling `/health`, printing the returned JSON or pointing at
     `logs\server.log` if it does not answer within 10 seconds.

Optional: set `tunnel.enabled: true` in `config.yaml` before installing to
also run the Cloudflare Tunnel at boot.

To remove: right-click `uninstall.ps1` → "Run with PowerShell" (as
Administrator). It stops and removes both scheduled tasks; your `data/` and
`logs/` folders are kept and can be deleted by hand.

### From source

See [Development](#development). `run.bat` runs the app in the foreground
with uvicorn on `127.0.0.1:8443`; it is for testing, not the installed
service.

## Configuration (`config.yaml`)

Edit the file next to the exe, then restart the server. Missing keys fall
back to the defaults in `app.py`, wrong-typed subtrees are ignored with a
logged warning instead of crashing startup, and invalid values for the
guarded keys below are replaced with their safe defaults. **Never put a real
secret value in git** — the file in this repository carries empty keys and
defaults only.

| Key | Default | Purpose |
|---|---|---|
| `server.host` | `"127.0.0.1"` | Bind address. Localhost by design; a tunnel exposes it publicly |
| `server.port` | `8443` | Bind port |
| `feeds.threat_refresh_minutes` | `5` | Threat-map refresh interval |
| `feeds.geo_refresh_minutes` | `15` | Geopolitical refresh interval |
| `feeds.news_refresh_minutes` | `30` | News refresh interval |
| `feeds.request_timeout_seconds` | `20` | Timeout for outbound feed / flight requests |
| `threat_feeds.abuse_ch_auth_key` | `""` | Optional free abuse.ch Auth-Key; adds ThreatFox enrichment. The map works fully without it |
| `flight_api.provider` | `"aviationstack"` | Flight data provider |
| `flight_api.api_key` | `""` | AviationStack key that enables `/flights`. Free signup: https://aviationstack.com/ (the config file notes the free tier as 100 requests/month) |
| `tunnel.enabled` | `false` | Run the Cloudflare Tunnel alongside the server |
| `tunnel.cloudflared_path` | `C:\Program Files\cloudflared\cloudflared.exe` | Where `cloudflared` is installed |
| `tunnel.args` | `tunnel --url http://127.0.0.1:8443` | Arguments passed to `cloudflared` (quick tunnel by default; a named tunnel is shown as a commented example in the file) |
| `turnstile.enabled` | `false` | Turn the Cloudflare Turnstile bot check for the three public form endpoints on or off |
| `turnstile.secret_key` | `""` | Turnstile secret key (server-side only; the matching site key is public in the web pages). With `enabled` on but no secret set, the check stays off and a warning is logged at startup |
| `briefing_token` | `""` | Shared secret for `POST /api/briefing`, sent as the `X-Briefing-Token` header |
| `admin_key` | `""` | When set, allows admin access via the `X-Admin-Key` header. See the admin rules under [Security notes](#security-notes) |
| `cors_origins` | `[]` | Exact cross-origin allowlist. Empty = no cross-origin access. Never `"*"` — a `"*"` entry is dropped at startup (see Security notes) |
| `hackproof_payments.enabled` | `false` | Turn the HackProof payments pass-through on or off |
| `hackproof_payments.upstream` | `"http://127.0.0.1:8787"` | Payments service address. Must be a bare loopback origin; anything else falls back to this default |
| `rss.geopolitical` | Al Jazeera, BBC World, DW (see file) | RSS sources for the geopolitical page |
| `rss.news_sections` | National / Missouri / Kansas City / Geopolitical / Cyber / Political / Markets (see file) | RSS sources per news section. Add or remove freely; failures are tolerated per feed |
| `logging.file` | `"logs/server.log"` | Log location (relative to the install folder) |
| `logging.level` | `"INFO"` | Log level |

## Usage

### Checking it is alive

```powershell
Invoke-RestMethod http://127.0.0.1:8443/health
```

returns JSON with `ok`, `time`, `frozen`, `uptime_seconds`, and a `feeds`
object giving each feed's last `updated` time and `status`. The same
information in a page is at `http://127.0.0.1:8443/status`. Both are
admin-gated (see the access split): from the machine itself they open
directly; from anywhere else they need the admin key.

### Admin

Open `http://127.0.0.1:8443/admin` on the machine itself, or call the admin
APIs with the configured key:

```powershell
Invoke-RestMethod "http://127.0.0.1:8443/api/admin/submissions?type=tickets" `
  -Headers @{"X-Admin-Key"="<admin_key from config.yaml>"}
```

The console and the APIs under `/api/admin/` share one rule (`require_admin`
in `app.py`): a request is allowed from localhost **only while the tunnel is
disabled**, or from anywhere with an `X-Admin-Key` header matching
`admin_key`. Failed attempts are throttled — see Security notes.

### Daily briefing ingest

```powershell
$body = @{ date = "2026-10-11"; sections = @{
  "National" = @(@{ title = "..."; summary = "..."; url = "https://..." })
}} | ConvertTo-Json -Depth 6
Invoke-RestMethod -Uri "http://127.0.0.1:8443/api/briefing" -Method Post `
  -Body $body -ContentType "application/json" -Headers @{"X-Briefing-Token"="<token>"}
```

The body must be a JSON object whose `sections` is an object; anything else
returns `400`. Story URLs are sanitized on ingest (non-`http(s)` schemes are
blanked), and a stored briefing that is not a JSON object is ignored on load
instead of breaking `/news`.

## HackProof payments pass-through (optional, off by default)

Sentinel Live can also front the **HackProof payments service** (the
`payments/` program in the HackProof repo — automated Bitcoin checkout
and certificate delivery), so one server faces the world and the
payments service never needs a public port of its own. While it is off
(the default), nothing changes: the payments routes do not exist on
this server, and a request to them is a plain `404`.

To turn it on:

1. **Set the payments service up on the same machine first**, following
   its own README ("Host setup" in the HackProof repo's
   `payments/README.md`) — its configuration, key store, and startup
   recipe live there, not here. It listens on loopback only — leave
   it that way.
2. **Flip one switch** in this server's `config.yaml`:
   `hackproof_payments.enabled: true` (the `upstream` next to it is
   already the right address). If your buy page is hosted on a
   different origin, also add that exact origin to `cors_origins` —
   never `*`.
3. **Restart Sentinel Live.** Exactly these three routes now work at this
   server's address, answered by the payments service:

   | Proxied route | Notes |
   |---|---|
   | `POST /api/orders` | Rate-limited per IP |
   | `GET /api/orders/{id}` | Generous limit (a checkout page polls this while a payment confirms) |
   | `POST /api/certificates` | Rate-limited per IP |

4. **Point the storefront at this server**: the site's
   `PAYMENTS_API_BASE` and the app's `HACKPROOF_SERVICE_BASE_URL` both
   become this server's public base URL.

How the proxy behaves, as implemented in `app.py`:

- **Byte-faithful:** the upstream reply is returned with the same status and
  the same body bytes — the certificate flow depends on the exact
  `200`/`201`/`202`/`400` semantics, so nothing is re-shaped.
- **Header hygiene:** only `Content-Type` and `Accept` are forwarded, and
  only `Content-Type` is returned. The admin key, cookies, and any
  `Authorization` header a client sends this server never leak upstream.
- **Fixed paths only:** the order id must match a plain token pattern
  (`[A-Za-z0-9._-]+`, with `..` rejected) before it is quoted and forwarded,
  so it cannot be reshaped toward another upstream route.
- **Loopback-only upstream:** at startup the configured `upstream` must be a
  bare loopback origin (`http://127.0.0.1:8787`, `http://localhost:8787`, or
  the IPv6 loopback equivalent, with no credentials, path, query, or
  fragment). Anything else is logged and replaced with the default.
- **Failure shape:** an unreachable upstream — or an upstream reply larger
  than 5 MB — is a clean `502` with a short explanation, never a hang or a
  partial response. The client timeout is 65 seconds overall with a
  5-second connect timeout, so a dead upstream fails fast.

One safety line that does not move: the payments **admin/review
endpoints (`/api/admin/*` on the payments service) are never forwarded**.
The review queue stays reachable only directly on the machine itself,
exactly as the payments service intends.

## Security notes

* **CORS lockdown by default.** `cors_origins` defaults to `[]` — no
  cross-origin access at all. Pages served by this server are same-origin
  and need no CORS. Only list an exact origin when a frontend hosted
  elsewhere must fetch these endpoints. `"*"` is refused twice over: a
  string `"*"` value is replaced with `[]` at startup, and a `"*"` entry
  inside a list is dropped. The reason is the localhost admin bypass: with
  `"*"`, any website the owner visited on the server machine could read
  `/api/admin/*` responses out of the local server.
* **Admin rules.** The admin page and admin APIs allow a request from
  localhost only while the request shows no sign of having been
  proxied — proxied traffic also arrives as localhost, so the bypass
  is switched off then — or the `X-Admin-Key` header matching
  `admin_key` in `config.yaml`, compared in constant time. Failed
  admin attempts are counted per IP, throttled, and logged with the
  real client IP and path.
* **Rate limits:** the public form endpoints, flight lookups, and the
  proxied payments routes are rate-limited per client IP and return
  `429` on excess. Behind the tunnel, the client IP is taken only from
  Cloudflare's `CF-Connecting-IP` header — `X-Forwarded-For` is never
  trusted as a fallback, because it is attacker-controlled.
* **Briefing ingest** (`POST /api/briefing`): when `briefing_token` is set,
  the request must carry it in the `X-Briefing-Token` header (a `?token=`
  query value is not accepted). With no token configured and the tunnel
  enabled, ingest fails closed (`403`) instead of accepting public posts.
* **Turnstile bot check:** with `turnstile.enabled` on and a secret key
  set, `/api/contact`, `/api/ticket`, and `/api/newsletter` verify the
  `cf-turnstile-response` token with Cloudflare's siteverify endpoint
  server-side, before anything is stored. A missing or rejected token is
  a `400`; if siteverify cannot be reached the submission fails closed
  with a `503` — an outage never silently waves a submission through.
  The secret and tokens are never logged. Enabled with no secret
  configured (or disabled) is a no-op, so local installs behave exactly
  as before.
* **Body size caps:** POST/PATCH/PUT bodies are capped per endpoint,
  checked from `Content-Length` first and again while streaming, so a
  missing or lying header cannot bypass the cap; oversized requests
  get `413`.
* **OpenAPI surface is off:** the FastAPI app is created with `docs_url`,
  `redoc_url`, and `openapi_url` all disabled.
* API keys are read from `config.yaml` next to the exe; no keys are
  hardcoded in the source, and no real key belongs in this repository.
* **Install location matters:** `install.ps1` registers the exe to run as
  SYSTEM at boot, and it warns if the install folder is inside a
  user-writable profile folder — whoever can write to that folder controls
  a SYSTEM binary at the next boot. Use an administrator-protected folder
  such as `C:\SentinelLive\`.

## Development

* Source layout: `app.py` (FastAPI application — pages, APIs, admin, SQLite
  storage, feed refresh loops, the payments proxy), `feeds.py` (threat /
  RSS / flight fetchers), `templates/`, `static/`, `tests/`.
* Stack: FastAPI and uvicorn, with httpx, Jinja2, PyYAML, feedparser, and
  aiosqlite — pinned versions are in `requirements.txt` (FastAPI 0.143.0,
  uvicorn 0.54.0, httpx 0.28.1 at the time of writing). The release workflow
  builds with Python 3.12; `build-exe.bat` states Python 3.11+.
* Manual test run: `run.bat` (needs Python +
  `pip install --require-hashes -r requirements.lock`); it runs uvicorn
  in the foreground on `127.0.0.1:8443`.
* Local exe build: `build-exe.bat` — installs the hash-locked build set
  (`requirements-build.lock.txt`: the production closure plus
  PyInstaller 6.22.3) and builds into `dist\SentinelLive.exe`.
* Releases: publishing a GitHub **release** triggers
  `.github/workflows/build-exe.yml` (windows-latest), which builds
  `SentinelLive.exe` with PyInstaller (`--onefile --noconsole`, templates
  and static bundled, `aiosqlite` as a hidden import), generates
  `SHA256SUMS.txt`, and attaches both files to that release.

### Dependencies — hash-verified installs

Every Python install for this project goes through a committed,
hash-verified lock (`pip install --require-hashes …`); a mismatch fails
the install loudly. `requirements.txt` stays the human-edited source of
exact pins — never install from it directly.

* **Production / source installs:** `requirements.lock` — the full
  production closure (23 packages, direct + transitive) with sha256
  hashes. Install: `pip install --require-hashes -r requirements.lock`.
  **Deploy-side step:** the Linux production host still installs from
  `requirements.txt`; on the next deploy, refresh its virtualenv with
  `pip install --require-hashes -r requirements.lock` (from the repo
  root, in the service's virtualenv, before restarting the service) so
  production runs exactly the locked closure.
* **EXE build:** `requirements-build.lock.txt` (source:
  `requirements-build.txt` = `requirements.txt` + PyInstaller 6.22.3),
  used by `.github/workflows/build-exe.yml` and `build-exe.bat`. It is
  compiled with `requirements.lock` as a constraint, so its shared
  packages are the production closure versions exactly.
* **Tests:** `requirements-test.lock.txt` (source:
  `requirements-test.txt` = `requirements.txt` + pytest), same
  constraint rule.
* **Updating:** a version bump is not landed until its lock is
  regenerated (commands are in each lock's header) and committed in the
  same change-set.

### Testing

```
python -m pip install --require-hashes -r requirements-test.lock.txt
python -m pytest tests/ --collect-only
python -m pytest tests/
```

The suite is nine files — `tests/test_hackproof_proxy.py` (22 tests),
`tests/test_turnstile.py` (7 tests), `tests/test_front_door.py`
(4 tests), `tests/test_bughunt_2026_10_23.py`,
`tests/test_visitors_2026_10_23.py` (public visitor logging),
`tests/test_sweep5_2026_10_24.py`, `tests/test_phase_two_a.py`
(the Phase Two pins), `tests/test_design_pass.py` (the design-pass,
About, Services, Who We Protect, How It Works, and Contact pins), and
`tests/test_live_flights.py` — with
**138 tests** in total, verified by a full run on 2026-10-25
(`138 passed`).
It builds the app against fake payments upstreams and covers, among other
things:

- the payments routes not existing while the pass-through is disabled, and
  existing behavior staying intact;
- byte-for-byte proxying of order creation (`201`) and order status
  (`200`), and certificate results (`201` issued, `202` held, `400`
  forged);
- `/api/admin/*` never being proxied, and order-id traversal being
  rejected;
- an unreachable or oversized upstream reply becoming a clean `502`;
- sensitive headers not leaking upstream;
- the proxied POST routes being rate-limited;
- a non-loopback upstream falling back to the default; and
- a `"*"` CORS value — as a string or as a list entry — not acting as a
  wildcard; and
- Cloudflare Turnstile verification on the public form endpoints:
  disabled (or enabled with no secret) is a no-op, a missing or invalid
  token is rejected when enabled, a valid token is accepted, and a
  siteverify outage fails closed.
- The 2026-10-23 bug-hunt pins: the gated surfaces (`/news`, `/status`,
  `/health`, `/api/news-data`) require the admin rule in-app while the
  public surfaces stay public; a `CF-Connecting-IP` header defeats the
  localhost bypass; the baseline security headers ride on pages and
  APIs; feed refresh errors surface as a class name only; flight
  numbers are shape-validated and cached before any provider call;
  and a Turnstile token solved on another site's widget is rejected.
- The Phase Two pins: the homepage and `/operations` live previews
  render from the public read APIs, the flight preview spends no
  provider quota, and the shared navigation carries the Operations
  and Library links on every page.

Page coverage is partial: routing, the in-app gates, response
headers, and flight-number validation are pinned by the tests above;
rendered-page behavior (layouts, maps, previews) is exercised by
periodic headless-browser censuses — most recently the Phase Two
census on 2026-10-25 — rather than by pytest. The
form APIs are covered only where the tests above touch them
(Turnstile gating, CSV export, newsletter handling, admin
throttling).

## Status

- **Phase Two (2026-10-25)** shipped on the production deployment:
  live previews on the homepage and `/operations`, tracker-page
  consistency polish, and a full public-page functionality pass. On
  the separate Sentinel Command service, new Live Intel views
  (Threat Map, Geopolitics, Flights) read this app's public data
  APIs — Command remains a separate gated service, and this app
  still does not serve it.
- **Current release: v1.0.3** (GitHub Releases), providing
  `SentinelLive.exe` and `SHA256SUMS.txt`. Publishing a GitHub release
  triggers the build workflow (`.github/workflows/build-exe.yml`), which
  builds the exe with PyInstaller and attaches it to that release.
- This README describes what the code in this repository does. The
  code is deployed in production behind the Cloudflare edge, with the
  access split above in force. A GitHub release of this repository
  does **not** update that deployment — the packaged Windows install
  described above remains a separate, owner-run install form.

## License

Proprietary. See [LICENSE](LICENSE) in this repository.

Copyright (c) 2026 JesusTheHacker / Sentinel Safeguard LLC. All rights
reserved. No copying, redistribution, resale, republication, or derivative
works are permitted without prior written permission from
JesusTheHacker / Sentinel Safeguard LLC.

## Contact

Sentinel Live Server is a Sentinel Safeguard LLC project, maintained in
this repository by TheRealJesusTheHacker. The repository itself carries no
separate contact address; website inquiries go through the site's own
contact form, which is one of the APIs this server provides
(`POST /api/contact`).
