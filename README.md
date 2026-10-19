# Sentinel Live Server

The **entire server side** of the Sentinel Safeguard website, running silently on
aroura (Windows 11, always-on). One `.exe`, no Python install, no console window,
starts automatically on every boot.

## What it serves

| Path | What it is |
|---|---|
| `/` | Public website frontend (served from the `site/` folder next to the exe, when present) |
| `/threat-map` | Live cyber threat map — attacks observed by the SANS DShield sensor network, refreshed every 5 min (keyless). Optional free abuse.ch key adds ThreatFox malware-family enrichment |
| `/geopolitical` | Geopolitical news feed + hotspot map with per-story impact notes (refreshed every 15 min) |
| `/flights` | Flight tracker — search any flight number (needs a free AviationStack API key in `config.yaml`) |
| `/news` | News hub: National, Missouri, Kansas City, Geopolitical, Cyber, Political, Markets + the daily briefing |
| `/health` | Health check JSON |
| `/admin` | Admin console — view stored form submissions (localhost-only, or `X-Admin-Key`) |

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

## For developers

* Source layout: `app.py` (FastAPI), `feeds.py` (threat/RSS/flight fetchers),
  `templates/`, `static/`.
* Manual test run: `run.bat` (needs Python + `pip install -r requirements.txt`).
* Local exe build: `build-exe.bat`.
* Releases: pushing a GitHub **release** triggers `.github/workflows/build-exe.yml`
  (windows-latest), which builds `SentinelLive.exe` with PyInstaller
  (`--onefile --noconsole`, templates/static bundled) and attaches it to the release.
* Frozen-path rules: bundled resources resolve via `sys._MEIPASS`; the config,
  SQLite DB, logs, `data/`, and `site/` all live **next to the exe** (writable).
