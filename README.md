# Sentinel Live Server

The server side of the Sentinel Safeguard website: a FastAPI application that
serves live threat, geopolitical, flight, and news pages, plus the contact,
ticket, and newsletter APIs behind the public site — packaged as a single
Windows executable.

It is built to run silently on aroura (Windows 11, always-on): one `.exe`, no
Python install, no console window, started automatically on every boot by the
installer described below.

## Status

- Released through GitHub Releases: the v1.0.0 release provides
  `SentinelLive.exe`. Publishing a GitHub release triggers the build workflow
  (`.github/workflows/build-exe.yml`), which builds the exe with PyInstaller
  and attaches it to that release.
- This README describes what the code in this repository does. It does not
  claim a field-verified deployment state for any particular machine.

## Who it is for

- Visitors to the Sentinel Safeguard website, who use the public pages and
  forms listed below.
- The site owner, who reviews stored submissions through the admin console
  and admin APIs.

## What it serves

| Path | What it is |
|---|---|
| `/` | Server-rendered home page drawing on the live threat, geopolitical, and news data; the app also serves a public website frontend from the `site/` folder next to the exe, when present |
| `/threat-map` | Live cyber threat map — attacks observed by the SANS DShield sensor network, refreshed every 5 min (keyless). Optional free abuse.ch key adds ThreatFox malware-family enrichment |
| `/geopolitical` | Geopolitical news feed + hotspot map with per-story impact notes (refreshed every 15 min) |
| `/flights` | Flight tracker — search any flight number (needs a free AviationStack API key in `config.yaml`) |
| `/news` | News hub: National, Missouri, Kansas City, Geopolitical, Cyber, Political, Markets + the daily briefing |
| `/health` | Health check JSON — uptime and per-feed refresh status |
| `/status` | Status page — start time, uptime, and per-feed refresh status |
| `/admin` | Admin console — view stored form submissions (localhost-only, or `X-Admin-Key`) |

Live-data JSON endpoints backing those pages:

| Endpoint | Purpose |
|---|---|
| `GET /api/threat-data` | Current threat-map data |
| `GET /api/geo-data` | Current geopolitical data |
| `GET /api/news-data` | Current news sections and the daily briefing |

## Website backend APIs (JSON, stored in embedded SQLite)

| Endpoint | Purpose |
|---|---|
| `POST /api/contact` | Contact form → stored in `contacts` table |
| `POST /api/ticket` | Get Help ticket intake (no login) → `tickets` table, status `new` |
| `POST /api/newsletter` | Newsletter/alerts signup → `newsletter` table (deduped) |
| `POST /api/briefing` | Daily briefing ingest → rendered at the top of `/news` |
| `GET /api/admin/submissions?type=tickets\|contacts\|newsletter` | View stored rows (admin) |
| `GET /api/admin/export?type=tickets&format=csv\|json` | Download export (admin) |
| `PATCH /api/admin/tickets/{id}` | Update ticket status / admin notes (admin) |

The static public website is a **pure frontend** — its forms just `fetch()` these
endpoints. Point the site's JS at the tunnel's public URL (CORS is configurable
in `config.yaml`).

## Architecture

```
Visitor ──https──▶ Cloudflare Tunnel ──▶ 127.0.0.1:8443 ──▶ SentinelLive.exe
                                                              ├─ static site  (./site/)
                                                              ├─ 4 live pages  (feeds refresh on a timer)
                                                              ├─ form APIs ──▶ SQLite (./data/sentinel-live.db)
                                                              └─ admin API    (localhost or X-Admin-Key)
aroura boots ──▶ Task Scheduler ──▶ SentinelLive.exe (SYSTEM, hidden, auto-restart)
                              └─▶ cloudflared tunnel (if enabled in config.yaml)
```

* No external database. The SQLite file is created automatically on first run,
  next to the exe (`data/sentinel-live.db`).
* All logging goes to `logs/server.log` — the exe has no console.
* `config.yaml` lives next to the exe and is created with sane defaults on
  first run. Keys are never hardcoded.

## Install (2 steps)

1. **Download** `SentinelLive.exe` from the GitHub release page and put it in a
   folder, e.g. `C:\SentinelLive\`. Copy `install.ps1` / `uninstall.ps1` next to it.
2. **Right-click `install.ps1` → "Run with PowerShell"** (as Administrator).
   It creates the startup task, starts the server immediately, and verifies
   `/health`. Optional: set `tunnel.enabled: true` in `config.yaml` first to
   also run Cloudflare Tunnel at boot.

To remove: right-click `uninstall.ps1` → "Run with PowerShell" (as Administrator).
Your `data/` and `logs/` folders are kept.

## Configuration (`config.yaml`)

* `flight_api.api_key` — paste a free AviationStack key to enable `/flights`.
  Free signup: https://aviationstack.com/ (100 lookups/month).
* `threat_feeds.abuse_ch_auth_key` — optional free key from https://auth.abuse.ch/
  that adds ThreatFox malware-family enrichment to the threat map. The map
  works fully without it (SANS DShield feed is keyless).
* `tunnel.enabled` / `tunnel.args` — Cloudflare Tunnel settings.
* `admin_key` — set a secret to allow remote admin access via the
  `X-Admin-Key` header. Empty = localhost only.
* `briefing_token` — shared secret for `POST /api/briefing`.
* `rss.*` — feed URLs per section; failures are tolerated per-feed.
* `cors_origins` — cross-origin allowlist, **empty by default** (pages
  served by this server are same-origin and need no CORS). Only set it
  when a frontend hosted on another origin must fetch these endpoints,
  and only to that exact origin — never `*`: combined with the localhost
  admin bypass, `*` would let any website visited on aroura read admin
  data out of the local server.

## Daily briefing ingest

```powershell
$body = @{ date = "2026-10-11"; sections = @{
  "National" = @(@{ title = "..."; summary = "..."; url = "https://..." })
}} | ConvertTo-Json -Depth 6
Invoke-RestMethod -Uri "http://127.0.0.1:8443/api/briefing" -Method Post `
  -Body $body -ContentType "application/json" -Headers @{"X-Briefing-Token"="<token>"}
```

## Safety notes

* Admin access is restricted: the admin page and admin APIs allow a request
  from localhost (only while the Cloudflare Tunnel is disabled — tunneled
  traffic also arrives as localhost, so the bypass is switched off then), or
  the `X-Admin-Key` header matching `admin_key` in `config.yaml`. Failed
  admin attempts are throttled per IP.
* CORS is empty by default — see the warning under Configuration. Do not set
  `cors_origins` to `*`.
* Briefing ingest (`POST /api/briefing`): when `briefing_token` is set in
  `config.yaml`, the request must carry it in the `X-Briefing-Token` header.
  With no token configured and the Cloudflare Tunnel enabled, ingest fails
  closed instead of accepting public posts.
* Public form and flight-lookup endpoints are rate-limited per client IP in
  `app.py`.
* API keys are read from `config.yaml` next to the exe; no keys are hardcoded
  in the source.
* Install location matters: `install.ps1` registers the exe to run as SYSTEM
  at boot, and it warns if the install folder is inside a user-writable
  profile folder. Use an administrator-protected folder such as
  `C:\SentinelLive\`.

## For developers

* Source layout: `app.py` (FastAPI application — pages, APIs, admin, SQLite
  storage, feed refresh loops), `feeds.py` (threat/RSS/flight fetchers),
  `templates/`, `static/`.
* Stack: FastAPI and uvicorn, with httpx, Jinja2, PyYAML, feedparser, and
  aiosqlite — pinned versions are in `requirements.txt`.
* Manual test run: `run.bat` (needs Python + `pip install -r requirements.txt`).
* Local exe build: `build-exe.bat`.
* Releases: pushing a GitHub **release** triggers `.github/workflows/build-exe.yml`
  (windows-latest), which builds `SentinelLive.exe` with PyInstaller
  (`--onefile --noconsole`, templates/static bundled) and attaches it to the release.
* Frozen-path rules: bundled resources resolve via `sys._MEIPASS`; the config,
  SQLite DB, logs, `data/`, and `site/` all live **next to the exe** (writable).

## License

Proprietary. See `LICENSE` in this repository.

Copyright (c) 2026 JesusTheHacker / Sentinel Safeguard LLC. All rights
reserved. No copying, redistribution, resale, republication, or derivative
works are permitted without prior written permission from
JesusTheHacker / Sentinel Safeguard LLC.
