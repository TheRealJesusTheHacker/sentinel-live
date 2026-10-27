"""Feed fetchers for Sentinel Live Server.

All functions are async, tolerate failures, and never invent data:
on failure they return an error status the pages render honestly.
"""
import asyncio
import ipaddress
import math
import time
import logging
import re
from collections import Counter
from datetime import datetime, timezone

import feedparser
import httpx

UA = {"User-Agent": "SentinelLive/1.0 (Sentinel Safeguard LLC)"}
# app.py configures this logger with the server.log file handler, so
# feed problems land in the same log as everything else.
log = logging.getLogger("sentinel-live")

# ---------------------------------------------------------------- countries
# Compact lat/lon table for the threat map (centroids, good enough for arcs).
COUNTRY_COORDS = {
    "US": (39.8, -98.5), "CA": (56.1, -106.3), "MX": (23.6, -102.5),
    "BR": (-14.2, -51.9), "AR": (-38.4, -63.6), "CL": (-35.6, -71.5),
    "GB": (54.0, -2.0), "IE": (53.1, -8.2), "FR": (46.2, 2.2),
    "DE": (51.1, 10.4), "NL": (52.1, 5.3), "BE": (50.6, 4.6),
    "ES": (40.4, -3.7), "PT": (39.5, -8.0), "IT": (41.8, 12.5),
    "CH": (46.8, 8.2), "AT": (47.5, 14.5), "SE": (60.1, 18.6),
    "NO": (64.4, 11.5), "FI": (61.9, 25.7), "DK": (56.2, 10.0),
    "PL": (51.9, 19.1), "CZ": (49.8, 15.4), "SK": (48.6, 19.7),
    "HU": (47.1, 19.5), "RO": (45.9, 25.0), "BG": (42.7, 25.4),
    "GR": (39.0, 22.0), "HR": (45.1, 15.2), "RS": (44.0, 20.8),
    "UA": (48.3, 31.1), "BY": (53.7, 27.9), "MD": (47.4, 28.3),
    "RU": (61.5, 90.0), "KZ": (48.0, 66.9), "TR": (38.9, 35.2),
    "IL": (31.0, 34.8), "AE": (24.0, 54.0), "SA": (24.6, 46.6),
    "IR": (32.4, 53.6), "IQ": (33.0, 43.6), "EG": (26.8, 30.8),
    "ZA": (-30.5, 22.9), "NG": (9.0, 8.6), "KE": (0.0, 37.8),
    "IN": (21.0, 78.0), "PK": (30.3, 69.3), "BD": (23.6, 90.3),
    "CN": (35.8, 104.1), "HK": (22.3, 114.1), "TW": (23.6, 121.0),
    "JP": (36.2, 138.2), "KR": (35.9, 127.7), "KP": (40.3, 127.5),
    "MN": (46.8, 103.8), "TH": (15.8, 101.0), "VN": (14.0, 108.2),
    "MY": (4.2, 102.2), "SG": (1.3, 103.8), "ID": (-2.5, 118.0),
    "PH": (12.8, 121.7), "AU": (-25.2, 133.7), "NZ": (-40.9, 174.8),
    "PA": (8.5, -80.7), "VG": (18.4, -64.6), "SC": (-4.6, 55.4),
    "MU": (-20.3, 57.5), "IS": (64.9, -19.0), "EE": (58.5, 25.0),
    "LV": (56.9, 25.0), "LT": (55.1, 23.9), "GE": (42.3, 43.7),
    "AM": (40.0, 45.0), "AZ": (40.1, 47.5), "KZ2": (48.0, 66.9),
    # Internet Weather 2026-10-27: IODA reporters missing from the
    # threat-map table above (owner-ordered additions CK, NF, SS,
    # GU, BO) plus other plausible country reporters, placed at
    # country centroids confidently.
    "CK": (-21.2, -159.8), "NF": (-29.0, 168.0), "SS": (7.9, 29.7),
    "GU": (13.4, 144.8), "BO": (-17.1, -65.0),
    "AF": (33.9, 67.7), "AL": (41.2, 20.2), "DZ": (28.0, 1.7),
    "AO": (-12.5, 17.5), "AS": (-14.3, -170.1), "AW": (12.5, -70.0),
    "BH": (26.1, 50.6), "BB": (13.2, -59.5), "BZ": (17.2, -88.7),
    "BJ": (9.3, 2.6), "BT": (27.5, 90.4), "BW": (-22.3, 24.7),
    "BF": (12.2, -1.7), "BI": (-3.4, 29.9), "CV": (16.0, -24.0),
    "KH": (12.7, 105.0), "CM": (7.4, 12.4), "CF": (6.6, 20.9),
    "TD": (15.5, 18.7), "KM": (-11.6, 43.7), "CG": (-0.2, 15.8),
    "CD": (-4.0, 21.8), "CR": (9.7, -83.8), "CI": (7.5, -5.5),
    "CU": (21.5, -77.8), "CY": (35.1, 33.4), "DJ": (11.8, 42.6),
    "DM": (15.4, -61.4), "DO": (18.7, -70.2), "EC": (-1.8, -78.2),
    "SV": (13.8, -88.9), "GQ": (1.5, 10.3), "ER": (15.2, 39.8),
    "SZ": (-26.5, 31.5), "ET": (9.1, 40.5), "FJ": (-17.7, 178.1),
    "GA": (-0.8, 11.6), "GM": (13.4, -16.3), "GD": (12.1, -61.7),
    "GT": (15.5, -90.3), "GN": (10.0, -12.7), "GW": (11.8, -15.2),
    "GY": (4.9, -58.9), "HT": (19.1, -72.4), "HN": (15.2, -86.2),
    "JM": (18.1, -77.3), "JO": (30.6, 36.2), "KW": (29.3, 47.5),
    "KG": (41.2, 74.8), "LA": (19.9, 102.5), "LB": (33.9, 35.9),
    "LS": (-29.6, 28.2), "LR": (6.4, -9.4), "LY": (26.3, 17.2),
    "LU": (49.8, 6.1), "MG": (-18.8, 47.0), "MW": (-13.3, 34.3),
    "MV": (3.2, 73.2), "ML": (17.6, -4.0), "MT": (35.9, 14.4),
    "MR": (21.0, -10.9), "MZ": (-17.3, 35.5), "MM": (21.9, 96.0),
    "NA": (-22.6, 17.1), "NP": (28.4, 84.1), "NI": (13.0, -85.0),
    "NE": (17.6, 8.1), "MK": (41.6, 21.7), "OM": (21.5, 56.0),
    "PS": (31.9, 35.2), "PG": (-6.3, 147.0), "PY": (-23.4, -58.4),
    "PE": (-9.2, -75.0), "QA": (25.3, 51.2), "RW": (-2.0, 30.0),
    "WS": (-13.8, -172.1), "SN": (14.4, -14.5), "SL": (8.5, -11.8),
    "SO": (5.2, 46.2), "LK": (7.9, 80.8), "SD": (12.9, 30.2),
    "SR": (3.9, -56.0), "SY": (35.0, 38.0), "TJ": (38.9, 71.3),
    "TZ": (-6.4, 34.9), "TG": (8.6, 0.8), "TO": (-20.3, -175.2),
    "TT": (10.7, -61.4), "TN": (33.9, 9.6), "TM": (39.1, 59.7),
    "UG": (1.4, 32.4), "UY": (-32.5, -55.8), "UZ": (41.4, 64.6),
    "VU": (-15.4, 166.9), "VE": (6.4, -66.6), "YE": (15.6, 47.6),
    "ZM": (-13.1, 27.8), "ZW": (-19.0, 29.9), "ME": (42.7, 19.4),
    "XK": (42.6, 21.0), "BN": (4.7, 115.0),
}

# --------------------------------------------------------------- helpers
def _make_client(**kw):
    """httpx client that survives unparseable NO_PROXY entries (bracketed IPv6)."""
    kw.setdefault("headers", UA)
    try:
        return httpx.AsyncClient(**kw)
    except Exception:
        kw["trust_env"] = False
        return httpx.AsyncClient(**kw)


async def _get(client, url, timeout, **kw):
    r = await client.get(url, timeout=timeout, **kw)
    r.raise_for_status()
    return r


async def _post(client, url, payload, timeout, **kw):
    r = await client.post(url, json=payload, timeout=timeout, **kw)
    r.raise_for_status()
    return r.json()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ threat
DSHIELD = "https://isc.sans.edu/api"

# DShield "threatfeeds" keys -> human attack-type labels
ATTACK_TYPES = {
    "blocklistde443": "HTTPS attacks", "blocklistde80": "HTTP attacks",
    "blocklistdeapache": "Web-app attacks", "blocklistdeasterisk": "VoIP/SIP attacks",
    "blocklistdessh": "SSH brute force", "blocklistdemail": "Mail abuse",
    "blocklistdeftp": "FTP attacks", "blocklistdeimap": "IMAP attacks",
    "ciarmy": "Multi-vector", "qrator": "Qrator radar",
    "emergingthreats": "EmergingThreats hits", "feodotracker": "Botnet C2",
}


async def _geolocate_ips(client, ips, timeout):
    """ip-api batch geolocation -> {ip: (lat, lon, country, cc)}."""
    out = {}
    batch = [{"query": ip, "fields": "status,country,countryCode,lat,lon,query"}
             for ip in ips[:90]]
    if not batch:
        return out
    try:
        # Plain HTTP is a documented free-tier constraint: ip-api
        # serves HTTPS only on its Pro plan (BH-2026-10-23, M-2). The
        # batch contains only third-party attacker IPs already public
        # via DShield — no key and no visitor data crosses this call.
        data = await _post(client, "http://ip-api.com/batch", batch, timeout)
        for g in data or []:
            if isinstance(g, dict) and g.get("status") == "success" \
                    and g.get("lat") is not None:
                out[g["query"]] = (g["lat"], g["lon"],
                                   g.get("country") or "", (g.get("countryCode") or "").upper())
    except Exception:
        pass
    return out


async def _threatfox_families(client, auth_key, timeout):
    """Optional enrichment: top malware families (needs free abuse.ch Auth-Key)."""
    try:
        r = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            headers={"Auth-Key": auth_key}, timeout=timeout)
        r.raise_for_status()
        fams = Counter()
        for it in (r.json().get("data") or [])[:400]:
            fam = (it.get("malware_printable") or "unknown").strip() or "unknown"
            fams[fam] += 1
        return [{"name": k, "count": v} for k, v in fams.most_common(8)]
    except Exception:
        return []


async def fetch_threat(timeout=20, abuse_ch_key=""):
    """Live attack data from the SANS DShield sensor network (keyless).

    sources/attacks -> top attacking IPs with counts;
    dailysummary    -> today's totals;
    ip/{ip}         -> attacker country + attack types (threatfeeds).
    Optional: abuse.ch Auth-Key enriches with ThreatFox malware families.
    """
    out = {"updated": _now(), "status": "starting", "attacks_today": 0,
           "sources_today": 0, "families": [], "countries": [],
           "attack_types": [], "markers": [], "arcs": [], "feed": [],
           "error": None}
    errors = []
    try:
        async with _make_client() as client:
            # Stage 1: today's totals (independent)
            try:
                summ = await _get(client, f"{DSHIELD}/dailysummary?json", timeout)
                today = (summ.json() or [{}])[0]
                out["attacks_today"] = today.get("records") or 0
                out["sources_today"] = today.get("sources") or 0
            except Exception as e:
                errors.append(f"summary: {type(e).__name__}")

            # Stage 2: top attacking sources (independent)
            sources = []
            try:
                r = await _get(client, f"{DSHIELD}/sources/attacks/150?json", timeout)
                sources = r.json() or []
                if not isinstance(sources, list):
                    # BH2-5: an error object instead of the list used
                    # to explode later at sources[:40] (KeyError) and
                    # take the whole fetch down.
                    errors.append("sources: unexpected shape")
                    sources = []
            except Exception as e:
                errors.append(f"sources: {type(e).__name__}")

            # Stage 3: per-IP detail + geolocation (per-item failures tolerated)
            if sources:
                async def _detail(ip):
                    try:
                        rr = await _get(client, f"{DSHIELD}/ip/{ip}?json", timeout)
                        payload = rr.json()
                        d = payload.get("ip") if isinstance(payload, dict) else None
                        return d if isinstance(d, dict) else {}
                    except Exception:
                        return {}

                # BH2-5: tolerate malformed entries — one bad source
                # (not an object, no ip) must not take the whole map
                # down; the healthy entries still render.
                # SL6-7: the ip string is interpolated into the DShield
                # detail URL and the geolocation payload below, so
                # require it to actually parse as an IP address — a
                # compromised/mangled upstream entry must not get to
                # reshape the request path ("../../", "?x=" etc.).
                def _is_ip(v):
                    if not isinstance(v, str):
                        return False
                    try:
                        ipaddress.ip_address(v)
                        return True
                    except ValueError:
                        return False

                clean = [s for s in sources
                         if isinstance(s, dict) and _is_ip(s.get("ip"))]
                top = clean[:40]
                details = await asyncio.gather(*(_detail(s["ip"]) for s in top))
                geo = await _geolocate_ips(client, [s["ip"] for s in clean[:60]], timeout)

                by_country = Counter()
                by_type = Counter()
                markers, feed = [], []
                for s, d in zip(top, details):
                    ip = s["ip"]
                    try:
                        attacks = int(s.get("attacks") or 0)
                    except (TypeError, ValueError):
                        # BH2-5: a non-numeric count from upstream is
                        # a 0, not a reason to fail the whole fetch.
                        attacks = 0
                    feeds_seen = d.get("threatfeeds")
                    if not isinstance(feeds_seen, dict):
                        feeds_seen = {}
                    types = [ATTACK_TYPES.get(k, k) for k in feeds_seen]
                    for t in types:
                        by_type[t] += attacks
                    _cc = d.get("ascountry")
                    cc = _cc.upper() if isinstance(_cc, str) else ""
                    g = geo.get(ip)
                    if g:
                        lat, lon, country, cc2 = g
                        cc = cc or cc2
                    elif cc in COUNTRY_COORDS:
                        lat, lon = COUNTRY_COORDS[cc]
                        country = cc
                    else:
                        continue
                    by_country[cc or "?"] += attacks
                    markers.append({"lat": lat, "lon": lon, "country": country,
                                    "ip": ip, "attacks": attacks,
                                    "asname": d.get("asname") or "",
                                    "types": types[:4]})
                    feed.append({"ip": ip, "attacks": attacks, "country": cc,
                                 "asname": d.get("asname") or "",
                                 "types": ", ".join(types[:3])})

                out["markers"] = markers
                out["countries"] = [{"code": k, "count": v}
                                    for k, v in by_country.most_common(8)]
                out["attack_types"] = [{"name": k, "count": v}
                                       for k, v in by_type.most_common(8)]
                out["feed"] = sorted(feed, key=lambda f: -f["attacks"])[:60]

                # Arcs: top attacking countries -> sensor network (US-heavy).
                hub = COUNTRY_COORDS["US"]
                arcs = []
                for c in out["countries"][:8]:
                    cc = c["code"]
                    if cc in COUNTRY_COORDS and cc != "US":
                        arcs.append({"from": COUNTRY_COORDS[cc], "to": hub,
                                     "from_cc": cc, "to_cc": "US",
                                     "label": f"{c['count']:,} attacks"})
                out["arcs"] = arcs

            # Stage 4: optional ThreatFox enrichment (independent)
            if abuse_ch_key:
                out["families"] = await _threatfox_families(client, abuse_ch_key, timeout)

            if out["markers"]:
                out["status"] = "ok"
            elif out["attacks_today"]:
                out["status"] = "partial"
                out["error"] = ("Attacker map temporarily unavailable; "
                                "totals are live. (" + "; ".join(errors) + ")")
            else:
                out["status"] = "error"
                out["error"] = "Threat feed unavailable (" + "; ".join(errors) + ")"
    except Exception as e:  # honest failure state
        # SL5-2: the detail goes to the log, not the public page —
        # exception strings can carry request URLs and other internals.
        log.warning("fetch_threat failed: %r", e)
        out["status"] = "error"
        out["error"] = f"Threat feed unavailable ({type(e).__name__})"
    return out


# --------------------------------------------------------------------- rss
def _safe_url(url):
    u = (url or "").strip()
    if u.lower().startswith(("http://", "https://")):
        return u
    return ""


def _parse_rss(content, limit=8):
    items = []
    try:
        parsed = feedparser.parse(content)
        for e in (parsed.entries or [])[:limit]:
            title = (e.get("title") or "").strip()
            if not title:
                continue
            items.append({
                "title": title,
                "link": _safe_url(e.get("link")),
                "published": e.get("published") or e.get("updated") or "",
                "source": (parsed.feed.get("title") or "").strip()[:40],
            })
    except Exception:
        pass
    return items


# Max bytes accepted for a single RSS response (SL3-3).
RSS_MAX_BYTES = 5 * 1024 * 1024


async def fetch_rss_items(urls, timeout=20, limit_per_feed=6):
    items = []
    async with _make_client(follow_redirects=True) as client:
        async def one(url):
            try:
                # SL3-3: cap the response size — Content-Length first, then a
                # byte cap while streaming, so a hostile feed can't OOM us.
                async with client.stream("GET", url, timeout=timeout) as r:
                    r.raise_for_status()
                    try:
                        cl = int(r.headers.get("content-length") or 0)
                    except (TypeError, ValueError):
                        cl = 0
                    if cl > RSS_MAX_BYTES:
                        return []
                    chunks, total = [], 0
                    async for chunk in r.aiter_bytes(65536):
                        total += len(chunk)
                        if total > RSS_MAX_BYTES:
                            return []
                        chunks.append(chunk)
                # feedparser is CPU-bound and parses the whole document
                # even for a small limit — run it off the event loop so a
                # refresh can't stall request handling while it chews.
                return await asyncio.to_thread(
                    _parse_rss, b"".join(chunks), limit_per_feed)
            except Exception:
                return []
        for chunk in [urls[i:i + 4] for i in range(0, len(urls), 4)]:
            results = await asyncio.gather(*(one(u) for u in chunk))
            for r in results:
                items.extend(r)
    # de-dupe by title
    seen, uniq = set(), []
    for it in items:
        k = it["title"].lower()
        if k not in seen:
            seen.add(k)
            uniq.append(it)
    return uniq


# ------------------------------------------------------------- geopolitical
GEO_KEYWORDS = [
    ("ukraine", 48.3, 31.1, "Ukraine"), ("kyiv", 50.4, 30.5, "Kyiv"),
    ("russia", 61.5, 90.0, "Russia"), ("moscow", 55.7, 37.6, "Moscow"),
    ("kremlin", 55.7, 37.6, "Moscow"),
    ("gaza", 31.5, 34.4, "Gaza"), ("israel", 31.0, 34.8, "Israel"),
    ("tel aviv", 32.0, 34.7, "Tel Aviv"), ("palestine", 31.9, 35.2, "West Bank"),
    ("lebanon", 33.8, 35.8, "Lebanon"), ("beirut", 33.8, 35.5, "Beirut"),
    ("iran", 32.4, 53.6, "Iran"), ("tehran", 35.6, 51.4, "Tehran"),
    ("syria", 34.8, 38.0, "Syria"), ("damascus", 33.5, 36.2, "Damascus"),
    ("yemen", 15.5, 48.5, "Yemen"), ("red sea", 20.0, 38.5, "Red Sea"),
    ("taiwan", 23.6, 121.0, "Taiwan"), ("taipei", 25.0, 121.5, "Taipei"),
    ("beijing", 39.9, 116.4, "Beijing"), ("south china sea", 12.0, 114.0, "South China Sea"),
    ("north korea", 40.3, 127.5, "North Korea"), ("pyongyang", 39.0, 125.7, "Pyongyang"),
    ("seoul", 37.5, 127.0, "Seoul"),
    ("sudan", 12.8, 30.2, "Sudan"), ("khartoum", 15.5, 32.5, "Khartoum"),
    ("myanmar", 21.9, 95.9, "Myanmar"), ("sahel", 15.0, 0.0, "Sahel"),
    ("niger", 17.6, 8.0, "Niger"), ("afghanistan", 33.9, 67.7, "Afghanistan"),
    ("kabul", 34.5, 69.1, "Kabul"), ("pakistan", 30.3, 69.3, "Pakistan"),
    ("kashmir", 34.0, 74.8, "Kashmir"), ("libya", 28.0, 17.0, "Libya"),
    ("somalia", 5.1, 46.1, "Somalia"), ("ethiopia", 9.1, 40.4, "Ethiopia"),
    ("venezuela", 6.4, -66.5, "Venezuela"), ("cuba", 21.5, -79.5, "Cuba"),
    ("belarus", 53.7, 27.9, "Belarus"), ("moldova", 47.4, 28.3, "Moldova"),
    ("armenia", 40.0, 45.0, "Armenia"), ("azerbaijan", 40.1, 47.5, "Azerbaijan"),
    ("kosovo", 42.6, 21.0, "Kosovo"), ("serbia", 44.0, 20.8, "Serbia"),
    ("nato", 50.8, 4.4, "Brussels (NATO)"), ("brussels", 50.8, 4.4, "Brussels"),
    ("white house", 38.9, -77.0, "Washington, D.C."), ("pentagon", 38.8, -77.0, "Pentagon"),
    ("united nations", 40.7, -74.0, "United Nations"), ("gaza", 31.5, 34.4, "Gaza"),
    ("horn of africa", 5.0, 46.0, "Horn of Africa"), ("arctic", 75.0, -40.0, "Arctic"),
    ("brics", 55.7, 37.6, "BRICS"), ("g7", 50.8, 4.4, "G7"), ("g20", 28.6, 77.2, "G20"),
    # Maps fix 2026-10-23: gazetteer expansion. Matching is a plain
    # substring scan of the headline (heuristic — the longest matching
    # keyword wins in geo_hotspots, so specific places beat generic ones,
    # e.g. "nigeria" over "niger", "south china sea" over "china").
    # Positions are country/region level, not exact story locations.
    ("kenya", -1.29, 36.82, "Kenya"), ("nairobi", -1.29, 36.82, "Nairobi"),
    ("nigeria", 9.08, 8.68, "Nigeria"), ("lagos", 6.52, 3.37, "Lagos"),
    ("south africa", -29.0, 24.7, "South Africa"),
    ("johannesburg", -26.2, 28.0, "Johannesburg"),
    ("egypt", 26.8, 30.8, "Egypt"), ("cairo", 30.0, 31.2, "Cairo"),
    ("morocco", 31.8, -6.0, "Morocco"), ("algeria", 28.0, 1.66, "Algeria"),
    ("tunisia", 33.9, 9.6, "Tunisia"),
    ("tanzania", -6.4, 34.9, "Tanzania"), ("uganda", 1.4, 32.4, "Uganda"),
    ("angola", -12.5, 17.5, "Angola"), ("mozambique", -17.8, 35.5, "Mozambique"),
    ("ghana", 7.9, -1.2, "Ghana"), ("cameroon", 5.7, 12.7, "Cameroon"),
    ("mali", 17.6, -3.99, "Mali"), ("chad", 15.45, 18.73, "Chad"),
    ("congo", -0.7, 23.5, "Congo Basin"),
    ("india", 21.1, 78.4, "India"), ("delhi", 28.6, 77.2, "Delhi"),
    ("mumbai", 19.1, 72.9, "Mumbai"), ("bangladesh", 23.7, 90.4, "Bangladesh"),
    ("sri lanka", 7.9, 80.8, "Sri Lanka"),
    ("nepal", 28.4, 84.1, "Nepal"),
    ("thailand", 15.9, 100.99, "Thailand"), ("bangkok", 13.75, 100.5, "Bangkok"),
    ("vietnam", 14.1, 108.3, "Vietnam"), ("hanoi", 21.0, 105.8, "Hanoi"),
    ("indonesia", -2.2, 118.0, "Indonesia"), ("jakarta", -6.2, 106.8, "Jakarta"),
    ("philippines", 12.9, 121.8, "Philippines"), ("manila", 14.6, 121.0, "Manila"),
    ("malaysia", 4.2, 102.0, "Malaysia"), ("singapore", 1.35, 103.8, "Singapore"),
    ("cambodia", 12.6, 105.0, "Cambodia"), ("mongolia", 46.9, 103.8, "Mongolia"),
    ("kazakhstan", 48.0, 66.9, "Kazakhstan"),
    ("japan", 36.2, 138.3, "Japan"), ("tokyo", 35.7, 139.7, "Tokyo"),
    ("china", 35.0, 104.9, "China"), ("shanghai", 31.2, 121.5, "Shanghai"),
    ("hong kong", 22.3, 114.2, "Hong Kong"),
    ("australia", -25.3, 133.8, "Australia"), ("sydney", -33.9, 151.2, "Sydney"),
    ("new zealand", -41.8, 172.8, "New Zealand"),
    ("turkey", 38.96, 35.2, "Turkey"), ("ankara", 39.9, 32.9, "Ankara"),
    ("istanbul", 41.0, 28.97, "Istanbul"),
    ("saudi arabia", 23.9, 45.1, "Saudi Arabia"), ("riyadh", 24.7, 46.7, "Riyadh"),
    ("united arab emirates", 24.2, 54.4, "UAE"), ("dubai", 25.2, 55.3, "Dubai"),
    ("qatar", 25.3, 51.2, "Qatar"), ("doha", 25.3, 51.5, "Doha"),
    ("iraq", 33.2, 43.7, "Iraq"), ("baghdad", 33.3, 44.4, "Baghdad"),
    ("jordan", 31.2, 36.6, "Jordan"), ("amman", 31.9, 35.9, "Amman"),
    ("jerusalem", 31.78, 35.21, "Jerusalem"),
    ("black sea", 43.4, 34.0, "Black Sea"), ("baltic", 58.5, 20.5, "Baltic Sea"),
    ("united kingdom", 54.0, -2.5, "United Kingdom"), ("london", 51.5, -0.12, "London"),
    ("britain", 54.0, -2.5, "United Kingdom"),
    ("france", 46.6, 2.5, "France"), ("paris", 48.85, 2.35, "Paris"),
    ("germany", 51.1, 10.4, "Germany"), ("berlin", 52.5, 13.4, "Berlin"),
    ("italy", 42.8, 12.8, "Italy"), ("rome", 41.9, 12.5, "Rome"),
    ("spain", 40.2, -3.6, "Spain"), ("madrid", 40.4, -3.7, "Madrid"),
    ("portugal", 39.6, -8.0, "Portugal"), ("lisbon", 38.7, -9.1, "Lisbon"),
    ("greece", 39.1, 21.8, "Greece"), ("athens", 38.0, 23.7, "Athens"),
    ("poland", 51.9, 19.1, "Poland"), ("warsaw", 52.2, 21.0, "Warsaw"),
    ("romania", 45.9, 24.97, "Romania"), ("bucharest", 44.4, 26.1, "Bucharest"),
    ("bulgaria", 42.8, 25.5, "Bulgaria"), ("hungary", 47.2, 19.5, "Hungary"),
    ("czech", 49.8, 15.5, "Czechia"), ("prague", 50.1, 14.4, "Prague"),
    ("austria", 47.6, 14.1, "Austria"), ("vienna", 48.2, 16.4, "Vienna"),
    ("switzerland", 46.8, 8.2, "Switzerland"), ("netherlands", 52.1, 5.3, "Netherlands"),
    ("amsterdam", 52.4, 4.9, "Amsterdam"), ("ireland", 53.4, -8.2, "Ireland"),
    ("dublin", 53.3, -6.3, "Dublin"), ("iceland", 65.0, -18.7, "Iceland"),
    ("sweden", 60.1, 18.6, "Sweden"), ("stockholm", 59.3, 18.1, "Stockholm"),
    ("norway", 60.5, 8.5, "Norway"), ("oslo", 59.9, 10.7, "Oslo"),
    ("denmark", 56.3, 9.5, "Denmark"), ("copenhagen", 55.7, 12.6, "Copenhagen"),
    ("finland", 61.9, 25.7, "Finland"), ("helsinki", 60.2, 25.0, "Helsinki"),
    ("estonia", 58.6, 25.0, "Estonia"), ("latvia", 56.9, 24.6, "Latvia"),
    ("lithuania", 56.0, 24.0, "Lithuania"), ("croatia", 45.1, 16.4, "Croatia"),
    ("tbilisi", 41.7, 44.8, "Tbilisi"),
    ("cyprus", 35.0, 33.0, "Cyprus"),
    ("canada", 57.0, -102.0, "Canada"), ("ottawa", 45.4, -75.7, "Ottawa"),
    ("toronto", 43.7, -79.4, "Toronto"),
    ("mexico", 23.6, -101.9, "Mexico"), ("mexico city", 19.4, -99.1, "Mexico City"),
    ("brazil", -14.2, -51.9, "Brazil"), ("brasilia", -15.8, -47.9, "Brasilia"),
    ("argentina", -38.4, -63.6, "Argentina"), ("buenos aires", -34.6, -58.4, "Buenos Aires"),
    ("chile", -31.8, -70.7, "Chile"), ("santiago", -33.4, -70.7, "Santiago"),
    ("peru", -9.2, -75.0, "Peru"), ("lima", -12.0, -77.0, "Lima"),
    ("colombia", 3.9, -73.1, "Colombia"), ("bogota", 4.7, -74.1, "Bogota"),
    ("washington", 38.9, -77.0, "Washington, D.C."),
    ("new york", 40.7, -74.0, "New York"),
]


def impact_note(text):
    t = (text or "").lower()
    notes = []
    if any(k in t for k in ("cyber", "ransomware", "hack", "malware", "apt ",
                            "breach", "ddos", "phishing", "spyware", "zero-day")):
        notes.append("Cyber relevance: check client exposure to the named actors, "
                     "vendors, and regions; review monitoring rules.")
    if any(k in t for k in ("oil", "gas", "energy", "pipeline", "power grid",
                            "shipping", "supply chain", "semiconductor", "chip")):
        notes.append("Business impact: energy/logistics exposure — review client "
                     "continuity plans and vendor dependencies.")
    if any(k in t for k in ("sanction", "tariff", "embargo", "trade deal")):
        notes.append("Compliance watch: trade/sanctions shifts can affect client "
                     "contracts and supply chains.")
    if not notes:
        notes.append("Monitoring: no direct cyber/business trigger — track for escalation.")
    return " ".join(notes)


def geo_hotspots(items):
    """Group stories per hotspot (maps fix 2026-10-23).

    Previously only the FIRST story per place was kept (one title per
    hotspot, no count). Now every matching story is grouped under its
    label (capped at 8 stored stories per hotspot) with a total count,
    so the map can show clusters and multi-story popups. Matching stays
    a headline substring heuristic; when several keywords match, the
    LONGEST keyword wins (specific beats generic), ties keep list order.
    "title" is retained (first story) for backward compatibility.
    """
    groups, order = {}, []
    for it in items:
        t = (it.get("title") or "").lower()
        best = None
        for kw, lat, lon, label in GEO_KEYWORDS:
            if kw in t and (best is None or len(kw) > len(best[0])):
                best = (kw, lat, lon, label)
        if best is None:
            continue
        _, lat, lon, label = best
        g = groups.get(label)
        if g is None:
            g = groups[label] = {"lat": lat, "lon": lon, "label": label,
                                 "title": it.get("title"), "count": 0,
                                 "stories": []}
            order.append(label)
        g["count"] += 1
        if len(g["stories"]) < 8:
            g["stories"].append({
                "title": it.get("title"), "source": it.get("source"),
                "published": it.get("published"), "link": it.get("link")})
    return [groups[k] for k in order[:25]]


async def fetch_geopolitical(urls, timeout=20):
    items = await fetch_rss_items(urls, timeout, limit_per_feed=8)
    for it in items:
        it["impact"] = impact_note(it["title"])
    return {"updated": _now(), "status": "ok" if items else "empty",
            "items": items[:40], "hotspots": geo_hotspots(items),
            "error": None if items else "All geopolitical feeds unreachable right now."}


async def fetch_news_sections(sections, timeout=20):
    out = {"updated": _now(), "status": "ok", "sections": {}, "error": None}

    async def _section(urls):
        items = await fetch_rss_items(urls, timeout, limit_per_feed=6)
        return items[:12]

    # Sections are independent: fetch them concurrently so a refresh
    # costs the slowest section's time, not the sum of all of them.
    # gather preserves the config's section order, and each section's
    # items are produced by the same fetch as before.
    names = list(sections)
    results = await asyncio.gather(
        *(_section(sections[name]) for name in names))
    for name, items in zip(names, results):
        out["sections"][name] = items
    if not any(out["sections"].values()):
        out["status"] = "empty"
        out["error"] = "News feeds unreachable right now."
    return out


# ------------------------------------------------------------------ flights
# BH-2026-10-23 (M-1): flight-number shape + a short result cache.
# Every uncached lookup spends from the free plan's 100 requests/month;
# before this, ANY alphanumeric string a visitor typed was forwarded
# to the provider, so junk queries burned real quota.
_FLIGHT_NUMBER_RE = re.compile(r"^[A-Z][A-Z0-9]{1,2}\d{1,4}[A-Z]?$")
_FLIGHT_CACHE = {}
_FLIGHT_CACHE_TTL = 600  # seconds


async def lookup_flight(number, api_key, timeout=20):
    """AviationStack lookup. Returns (result_dict, error_str)."""
    num = re.sub(r"[^A-Za-z0-9]", "", number or "").upper()
    if not num or len(num) > 10 or not _FLIGHT_NUMBER_RE.fullmatch(num):
        return None, "Enter a flight number (e.g. AA100, UAL512, SWA204)."
    now = time.time()
    hit = _FLIGHT_CACHE.get(num)
    if hit and now - hit[0] < _FLIGHT_CACHE_TTL:
        return hit[1], hit[2]
    result, error = await _lookup_flight_provider(num, api_key, timeout)
    if len(_FLIGHT_CACHE) > 512:
        _FLIGHT_CACHE.clear()
    _FLIGHT_CACHE[num] = (now, result, error)
    return result, error


async def _lookup_flight_provider(num, api_key, timeout=20):
    """One uncached AviationStack call for an already-validated
    designator. Returns (result_dict, error_str)."""
    # HTTPS: APILayer's current docs offer HTTPS on every plan. If a
    # plan ever rejects it, the provider error surfaces below as a
    # generic "no live data" and this URL goes back to http:// with the
    # constraint noted — the key is free-tier, quota-capped, rotatable.
    url = "https://api.aviationstack.com/v1/flights"
    try:
        async with _make_client() as client:
            r = await client.get(url, params={"access_key": api_key,
                                              "flight_iata": num}, timeout=timeout)
            r.raise_for_status()
            payload = r.json()
    except httpx.HTTPStatusError as e:
        # SL5-2: NEVER surface str(e) here — httpx includes the full
        # request URL in it, and the API key travels in that URL's
        # query string. The old message pasted the live key onto the
        # public /flights page for anyone who triggered an error.
        log.warning("flight lookup for %s: HTTP %s",
                    num, e.response.status_code)
        return None, f"Flight API request failed (HTTP {e.response.status_code})."
    except Exception as e:
        log.warning("flight lookup for %s failed: %r", num, e)
        return None, f"Flight API request failed ({type(e).__name__})."
    # BH2-4: the provider's JSON shape was trusted below — a list
    # payload, a dict "data", a string "error", or a null first entry
    # raised out of this function and became a 500 on /flights.
    # Validate the shape; anything unexpected is just "no live data".
    if not isinstance(payload, dict):
        return None, f"No live data for {num} right now."
    flights = payload.get("data") or []
    if not isinstance(flights, list):
        flights = []
    if not flights:
        # BH-2026-10-23: never render the provider's own error text on
        # the public page — it is an upstream-controlled string. Log it
        # server-side; the visitor gets a fixed message.
        err = payload.get("error")
        if isinstance(err, dict):
            log.warning("flight lookup for %s: provider error %s: %s",
                        num, err.get("code"), err.get("message"))
        return None, f"No live data for {num} right now."
    f = flights[0]
    if not isinstance(f, dict):
        return None, f"No live data for {num} right now."

    def _sub(d, key):
        v = d.get(key)
        return v if isinstance(v, dict) else {}

    dep, arr = _sub(f, "departure"), _sub(f, "arrival")
    # Maps fix 2026-10-23: pass the provider's live aircraft position
    # through (numbers only) so the flight page can plot it when present.
    live_raw = _sub(f, "live")

    def _num(v):
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None

    live = None
    if _num(live_raw.get("latitude")) is not None and _num(live_raw.get("longitude")) is not None:
        live = {"latitude": _num(live_raw.get("latitude")),
                "longitude": _num(live_raw.get("longitude")),
                "altitude": _num(live_raw.get("altitude")),
                "direction": _num(live_raw.get("direction")),
                "speed_horizontal": _num(live_raw.get("speed_horizontal")),
                "is_ground": bool(live_raw.get("is_ground"))}
    return {
        "number": _sub(f, "flight").get("iata") or num,
        "airline": _sub(f, "airline").get("name") or "",
        "status": f.get("flight_status") or "unknown",
        "date": f.get("flight_date") or "",
        "departure": {k: dep.get(k) for k in
                      ("airport", "iata", "terminal", "gate", "scheduled", "estimated", "actual", "delay")},
        "arrival": {k: arr.get(k) for k in
                    ("airport", "iata", "terminal", "gate", "scheduled", "estimated", "actual", "delay")},
        "aircraft": _sub(f, "aircraft").get("registration") or "",
        "live": live,
    }, None


# Small hub coordinate table so the flight page can draw the route line
# when both airports are known majors.
AIRPORT_COORDS = {
    "MCI": (39.2976, -94.7139), "STL": (38.7487, -90.3700),
    "DFW": (32.8998, -97.0403), "DEN": (39.8561, -104.6737),
    "ORD": (41.9742, -87.9073), "ATL": (33.6407, -84.4277),
    "LAX": (33.9416, -118.4085), "JFK": (40.6413, -73.7781),
    "EWR": (40.6895, -74.1745), "SFO": (37.6213, -122.3790),
    "SEA": (47.4502, -122.3088), "MIA": (25.7959, -80.2870),
    "BOS": (42.3656, -71.0096), "DCA": (38.8512, -77.0402),
    "IAD": (38.9531, -77.4565), "PHX": (33.4373, -112.0078),
    "LAS": (36.0840, -115.1537), "MSP": (44.8848, -93.2223),
    "DTW": (42.2124, -83.3534), "CLT": (35.2144, -80.9431),
    "IAH": (29.9844, -95.3414), "AUS": (30.1945, -97.6699),
    "BNA": (36.1263, -86.6774), "MDW": (41.7868, -87.7522),
    "LHR": (51.4700, -0.4543), "CDG": (49.0097, 2.5479),
    "FRA": (50.0379, 8.5622), "AMS": (52.3105, 4.7683),
    "NRT": (35.7720, 140.3929), "ICN": (37.4602, 126.4407),
    # Maps fix 2026-10-23: expanded from 28 to ~140 airports (major US
    # hubs + world gateways) so most looked-up routes can be plotted.
    "PDX": (45.5898, -122.5951), "SLC": (40.7899, -111.9791),
    "OKC": (35.3931, -97.6007), "TUL": (36.1984, -95.8881),
    "ICT": (37.6499, -97.4331), "OMA": (41.3032, -95.8941),
    "DSM": (41.5340, -93.6631), "MSY": (29.9934, -90.2580),
    "MEM": (35.0424, -89.9767), "LIT": (34.7294, -92.2243),
    "HOU": (29.6454, -95.2789), "DAL": (32.8471, -96.8518),
    "SAT": (29.5337, -98.4697), "ELP": (31.8072, -106.3776),
    "ABQ": (35.0402, -106.6090), "TUS": (32.1161, -110.9410),
    "SAN": (32.7338, -117.1933), "SNA": (33.6757, -117.8682),
    "ONT": (34.0560, -117.6012), "SMF": (38.6954, -121.5908),
    "SJC": (37.3639, -121.9289), "OAK": (37.7126, -122.2197),
    "RNO": (39.4986, -119.7681), "BOI": (43.5644, -116.2228),
    "ANC": (61.1743, -149.9962), "HNL": (21.3245, -157.9251),
    "IND": (39.7173, -86.2944), "CMH": (39.9980, -82.8919),
    "CLE": (41.4117, -81.8498), "PIT": (40.4915, -80.2329),
    "BWI": (39.1754, -76.6684), "PHL": (39.8744, -75.2424),
    "RDU": (35.8801, -78.7880), "JAX": (30.4941, -81.6879),
    "MCO": (28.5455, -81.2578), "TPA": (27.9755, -82.5332),
    "FLL": (26.0726, -80.1527), "PBI": (26.6832, -80.0956),
    "CHS": (32.8986, -80.0405), "BHM": (33.5629, -86.7535),
    "XNA": (36.2819, -94.3068), "SGF": (37.2457, -93.3886),
    "YYZ": (43.6777, -79.6248), "YVR": (49.1967, -123.1815),
    "YYC": (51.1315, -114.0103), "YUL": (45.4706, -73.7408),
    "MEX": (19.4363, -99.0721), "CUN": (21.0365, -86.8771),
    "PTY": (9.0714, -79.3835), "SJU": (18.4394, -66.0018),
    "GRU": (-23.4356, -46.4731), "GIG": (-22.8099, -43.2505),
    "EZE": (-34.8222, -58.5358), "SCL": (-33.3930, -70.7858),
    "LIM": (-12.0219, -77.1143), "BOG": (4.7016, -74.1469),
    "LGW": (51.1537, -0.1821), "MAN": (53.3493, -2.2796),
    "DUB": (53.4213, -6.2701), "MAD": (40.4983, -3.5676),
    "BCN": (41.2974, 2.0833), "LIS": (38.7742, -9.1342),
    "FCO": (41.8003, 12.2500), "MXP": (45.6306, 8.7231),
    "ZRH": (47.4647, 8.5492), "VIE": (48.1103, 16.5697),
    "BRU": (50.9010, 4.4844), "CPH": (55.6180, 12.6560),
    "ARN": (59.6519, 17.9186), "OSL": (60.1939, 11.1004),
    "HEL": (60.3172, 24.9633), "KEF": (63.9850, -22.6056),
    "WAW": (52.1657, 20.9671), "PRG": (50.1008, 14.2632),
    "BUD": (47.4369, 19.2556), "ATH": (37.9364, 23.9445),
    "IST": (41.2753, 28.7519), "DXB": (25.2532, 55.3657),
    "DOH": (25.2731, 51.6081), "AUH": (24.4330, 54.6511),
    "RUH": (24.9576, 46.6989), "KWI": (29.2266, 47.9689),
    "BOM": (19.0896, 72.8656), "DEL": (28.5562, 77.1000),
    "BLR": (13.1986, 77.7066), "MAA": (13.0600, 80.2718),
    "HYD": (17.2403, 78.4294), "CCU": (22.6547, 88.4467),
    "SIN": (1.3644, 103.9915), "KUL": (2.7456, 101.7072),
    "BKK": (13.6900, 100.7501), "HKG": (22.3080, 113.9185),
    "TPE": (25.0797, 121.2342), "MNL": (14.5086, 121.0194),
    "CGK": (-6.1256, 106.6559), "HAN": (21.2142, 105.8028),
    "SGN": (10.8188, 106.6520), "PEK": (40.0799, 116.6031),
    "PVG": (31.1443, 121.8083), "CAN": (23.3924, 113.2988),
    "SZX": (22.6393, 113.8107), "HND": (35.5494, 139.7798),
    "KIX": (34.4347, 135.2441), "NGO": (34.8584, 136.8054),
    "SYD": (-33.9399, 151.1753), "MEL": (-37.6690, 144.8410),
    "BNE": (-27.3842, 153.1175), "PER": (-31.9403, 115.9672),
    "AKL": (-37.0082, 174.7850), "JNB": (-26.1367, 28.2411),
    "CPT": (-33.9715, 18.6021), "NBO": (-1.3192, 36.9278),
    "ADD": (8.9779, 38.7993), "CAI": (30.1219, 31.4056),
    "LOS": (6.5774, 3.3212), "ACC": (5.6052, -0.1667),
}



# ---------------------------------------------------------- internet weather
# Internet Weather 2026-10-27: country-level internet outage picture
# from IODA (Georgia Tech Internet Intelligence Lab, keyless) with
# RIPEstat routing-stats enrichment for the worst-affected countries.
# NEVER invents data: a failed source flips its flag in the output
# and the page says so; if IODA fails entirely the store is an honest
# error with empty lists.

def _wx_num(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def _wx_signals(scores):
    """Signal names present in an IODA scores object. IODA has used
    both nested keys ("bgp": {...}) and flat dotted keys
    ("bgp.median"); accept either shape."""
    keys = list(scores.keys()) if isinstance(scores, dict) else []
    out = []
    for sig, prefixes in (("bgp", ("bgp",)), ("ping", ("ping",)),
                          ("gtr", ("gtr",))):
        if any(k == pre or k.startswith(pre + ".") or k.startswith(pre + "-")
               for k in keys for pre in prefixes):
            out.append(sig)
    return out


def _wx_entity(raw):
    """An IODA entity: {'code','name'} dict, or a bare code string."""
    if isinstance(raw, dict):
        return (str(raw.get("code") or "").strip().upper(),
                str(raw.get("name") or "").strip())
    if isinstance(raw, str):
        return raw.strip().upper(), ""
    return "", ""


def _wx_ts(v):
    n = _wx_num(v)
    if n is not None and n > 0:
        try:
            return datetime.fromtimestamp(n, timezone.utc).isoformat(
                timespec="seconds")
        except (OverflowError, OSError, ValueError):
            return ""
    return str(v or "").strip()


def _weather_parse(summary_json, alerts_json, ripe_map):
    """Pure parsing: IODA summary + alerts payloads and a RIPEstat
    map {code: {"v4_prefixes_ris": n, "v6_prefixes_ris": n}} -> the
    {totals, countries, events} core of the weather store. No I/O,
    no clock — unit-tested directly."""
    ripe_map = ripe_map if isinstance(ripe_map, dict) else {}
    rows = []
    if isinstance(summary_json, dict) and isinstance(
            summary_json.get("data"), list):
        rows = summary_json["data"]
    parsed = []
    max_overall = 0.0
    for row in rows:
        if not isinstance(row, dict):
            continue
        code, name = _wx_entity(row.get("entity"))
        if not code:
            continue
        scores = row.get("scores") if isinstance(
            row.get("scores"), dict) else {}
        overall = _wx_num(scores.get("overall"))
        overall = overall if overall is not None else 0.0
        max_overall = max(max_overall, overall)
        try:
            events = int(row.get("event_cnt") or 0)
        except (TypeError, ValueError):
            events = 0
        parsed.append((code, name or code, scores, overall, events))
    countries = []
    for code, name, scores, overall, events in parsed:
        if max_overall > 0:
            intensity = round(100 * math.log10(overall + 1)
                              / math.log10(max_overall + 1))
        else:
            intensity = 0
        lat, lon = COUNTRY_COORDS.get(code, (None, None))
        ripe = ripe_map.get(code) or {}
        countries.append({
            "code": code, "name": name, "lat": lat, "lon": lon,
            "events": events, "signals": _wx_signals(scores),
            # "score" is the raw IODA overall score, unmodified.
            "score": overall, "intensity": intensity,
            "ripe_v4": ripe.get("v4_prefixes_ris"),
            "ripe_v6": ripe.get("v6_prefixes_ris"),
        })
    alert_rows = []
    if isinstance(alerts_json, dict) and isinstance(
            alerts_json.get("data"), list):
        alert_rows = [a for a in alerts_json["data"]
                      if isinstance(a, dict)]
    alerts = []
    for a in alert_rows:
        code, name = _wx_entity(a.get("entity"))
        alerts.append({
            "ts": _wx_ts(a.get("time")), "code": code,
            "name": name or code,
            "datasource": str(a.get("datasource") or ""),
            "level": str(a.get("level") or ""),
            "condition": str(a.get("condition") or ""),
        })
    # Notable first: every non-"normal" alert (input is newest-first),
    # then the most recent remaining alerts, at most 12 total.
    notable = [a for a in alerts
               if a["level"].strip().lower() != "normal"]
    rest = [a for a in alerts if a["level"].strip().lower() == "normal"]
    events_list = (notable + rest)[:12]
    totals = {
        "countries_affected": len(countries),
        "outage_events": sum(c["events"] for c in countries),
        "alerts_24h": len(alerts),
    }
    return {"totals": totals, "countries": countries,
            "events": events_list}


def _ripe_parse(payload):
    """One RIPEstat country-routing-stats payload -> the prefix
    counts at the last timeline point, or None. Defensive about the
    real shape: data.stats may be a list whose first entry carries a
    timeline list; key spellings are probed, never assumed."""
    try:
        if not isinstance(payload, dict):
            return None
        data = payload.get("data")
        if not isinstance(data, dict):
            return None
        stats = data.get("stats")
        if isinstance(stats, list):
            stats = stats[0] if stats else {}
        if not isinstance(stats, dict):
            return None
        timeline = stats.get("timeline")
        if isinstance(timeline, list):
            point = timeline[-1] if timeline else {}
        elif isinstance(timeline, dict):
            point = timeline
        else:
            point = stats

        def _pick(*keys):
            for k in keys:
                v = _wx_num(point.get(k)) if isinstance(point, dict) else None
                if v is not None:
                    return int(v)
            return None

        v4 = _pick("v4_prefixes_ris", "v4_prefixes", "ipv4_prefixes_ris")
        v6 = _pick("v6_prefixes_ris", "v6_prefixes", "ipv6_prefixes_ris")
        if v4 is None and v6 is None:
            return None
        return {"v4_prefixes_ris": v4, "v6_prefixes_ris": v6}
    except Exception:
        return None


async def fetch_internet_weather(timeout=20):
    """IODA outage summary + alerts for the trailing 24h, enriched
    with RIPEstat routing stats for the top 6 countries by score."""
    out = {"updated": _now(), "status": "error", "window_hours": 24,
           "sources": {"ioda": "error", "ripestat": "error"},
           "totals": {"countries_affected": 0, "outage_events": 0,
                      "alerts_24h": 0},
           "countries": [], "events": [], "error": None}
    now = int(time.time())
    frm, until = now - 86400, now
    base = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages"
    summary_url = (f"{base}/summary?from={frm}&until={until}"
                   "&entityType=country&limit=60&orderBy=score/desc")
    alerts_url = (f"{base}/alerts?from={frm}&until={until}"
                  "&entityType=country&limit=40&orderBy=time/desc")
    try:
        async with _make_client() as client:
            summary_json = alerts_json = None
            ok_count = 0
            err_names = []
            try:
                r = await _get(client, summary_url, timeout)
                summary_json = r.json()
                ok_count += 1
            except Exception as e:
                log.warning("internet weather summary failed: %r", e)
                err_names.append(type(e).__name__)
            try:
                r = await _get(client, alerts_url, timeout)
                alerts_json = r.json()
                ok_count += 1
            except Exception as e:
                log.warning("internet weather alerts failed: %r", e)
                err_names.append(type(e).__name__)
            if ok_count == 0:
                # IODA failed entirely: honest error, empty lists,
                # class name only (the store error discipline).
                out["error"] = ("IODA unavailable ("
                                + ", ".join(err_names) + ")")
                return out
            # RIPEstat enrichment for the top 6 by IODA score.
            prelim = _weather_parse(summary_json, alerts_json, {})
            top = sorted(prelim["countries"],
                         key=lambda c: -(c["score"] or 0))[:6]
            ripe_map = {}
            ripe_ok = 0
            if top:
                async def _ripe(cc):
                    try:
                        r = await _get(
                            client,
                            "https://stat.ripe.net/data/"
                            "country-routing-stats/data.json"
                            f"?resource={cc}", timeout)
                        parsed = _ripe_parse(r.json())
                        return cc, parsed
                    except Exception:
                        return cc, None

                for cc, parsed in await asyncio.gather(
                        *(_ripe(c["code"]) for c in top)):
                    if parsed is not None:
                        ripe_map[cc] = parsed
                        ripe_ok += 1
                if ripe_ok == len(top):
                    ripe_status = "ok"
                elif ripe_ok:
                    ripe_status = "partial"
                else:
                    ripe_status = "error"
            else:
                ripe_status = "ok"
            core = _weather_parse(summary_json, alerts_json, ripe_map)
            out.update(core)
            out["sources"] = {
                "ioda": "ok" if ok_count == 2 else "error",
                "ripestat": ripe_status}
            if ok_count == 2 and ripe_status == "ok":
                out["status"] = "ok"
            else:
                out["status"] = "degraded"
                out["error"] = (
                    "One or more sources unavailable "
                    f"(ioda={out['sources']['ioda']}, "
                    f"ripestat={ripe_status})")
            return out
    except Exception as e:
        log.warning("fetch_internet_weather failed: %r", e)
        out["status"] = "error"
        out["error"] = f"Internet weather unavailable ({type(e).__name__})"
        return out


# ------------------------------------------------------------------- kev
# Sentinel Threat Level input 2026-10-27: CISA's Known Exploited
# Vulnerabilities catalog (keyless JSON feed).

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def _kev_parse(payload, today=None):
    """Pure parsing of the KEV catalog: totals over UTC dates.
    The trailing-7-days window includes today (today-6 .. today).
    added_dates is the sorted list of distinct in-window dates."""
    if today is None:
        today = datetime.now(timezone.utc).date()
    vulns = []
    if isinstance(payload, dict) and isinstance(
            payload.get("vulnerabilities"), list):
        vulns = payload["vulnerabilities"]
    start = today.toordinal() - 6
    added_7d = added_today = 0
    dates = set()
    for v in vulns:
        if not isinstance(v, dict):
            continue
        raw = str(v.get("dateAdded") or "").strip()
        try:
            day = datetime.strptime(raw, "%Y-%m-%d").date()
        except (TypeError, ValueError):
            continue
        if start <= day.toordinal() <= today.toordinal():
            added_7d += 1
            dates.add(raw)
            if day == today:
                added_today += 1
    return {"total": len(vulns), "added_7d": added_7d,
            "added_today": added_today,
            "added_dates": sorted(dates)}


async def fetch_kev(timeout=20):
    """Fetch + count the CISA KEV catalog. On any failure an honest
    error dict with zero counts — never invented numbers."""
    out = {"updated": _now(), "status": "error", "total": 0,
           "added_7d": 0, "added_today": 0, "added_dates": []}
    try:
        async with _make_client(follow_redirects=True) as client:
            r = await _get(client, KEV_URL, timeout)
            parsed = _kev_parse(r.json())
        out.update(parsed)
        out["status"] = "ok"
    except Exception as e:
        log.warning("fetch_kev failed: %r", e)
    return out


# --------------------------------------------------------------- live traffic
# LF-2026-10-25: live aircraft positions for the Flight Tracker, from
# adsb.lol — a community ADS-B aggregator (keyless, ODbL data; the API
# answers {ac: [...], total, now}). Probed from the production box
# before this was designed around it: HTTP 200 in ~0.4s. Two upstream
# disciplines shape everything below:
#   * adsb.lol advertises a tight request budget (~4/s, 60/min,
#     500/day per IP via x-ratelimit-*), so ALL upstream fetches go
#     through one lock + one global min-interval gate, and every area
#     answer is cached well past the page's poll interval — visitor
#     count can never multiply upstream calls.
#   * The upstream uses cache-control: no-store and community
#     receivers, so a fetch can fail or arrive thin at any time: on
#     ANY failure the caller gets the last good answer for the area
#     flagged stale, never a raw upstream error.
LIVE_ADSB_BASE = "https://api.adsb.lol/v2"
LIVE_CACHE_TTL = 20.0        # s an area answer stays fresh
LIVE_STALE_TTL = 600.0       # s a last-good answer may be served stale
LIVE_MIN_UPSTREAM_GAP = 16.0  # s between upstream fetches, any area
LIVE_MAX_DIST = 250          # nm — the upstream's own radius ceiling
LIVE_DEFAULT_DIST = 100      # nm — covers the full opening KC view
LIVE_UPSTREAM_TIMEOUT = 12.0  # s — upstream answers in <1s when healthy
LIVE_RESPONSE_NOTE = (
    "Live positions from community ADS-B receivers via adsb.lol "
    "(ODbL). Coverage varies by area and positions can lag — not an "
    "official navigation or safety source.")

_live_cache = {}             # key -> {"fetched": float, "payload": dict}
_live_lock = None            # asyncio.Lock, created lazily inside a loop
_live_last_fetch = 0.0       # epoch of the last upstream fetch attempt

_EMERGENCY_SQUAWKS = {"7500", "7600", "7700"}


def _live_num(v):
    """Feed numbers arrive as numbers, numeric strings, the literal
    'ground' (alt_baro on the surface), or missing — normalize to a
    float or None without ever raising."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def _live_key(lat, lon, dist):
    """Cache/coalescing key: area centers rounded to ~11 km cells so
    nearby viewports share one answer (and one upstream budget)."""
    return (round(float(lat) * 10) / 10, round(float(lon) * 10) / 10,
            int(dist))


def normalize_aircraft(ac):
    """One raw adsb.lol record -> the clean shape the page consumes,
    or None when the record has no usable position. Feed values only:
    registration/type are included because the feed carries them,
    never derived or invented here."""
    if not isinstance(ac, dict):
        return None
    lat, lon = _live_num(ac.get("lat")), _live_num(ac.get("lon"))
    if lat is None or lon is None:
        return None
    callsign = str(ac.get("flight") or "").strip()
    squawk = str(ac.get("squawk") or "").strip() or None
    alt = ac.get("alt_baro")
    on_ground = isinstance(alt, str) and alt.strip().lower() == "ground"
    alt_ft = None if on_ground else _live_num(alt)
    if alt_ft is None and not on_ground:
        alt_ft = _live_num(ac.get("alt_geom"))
    vr = _live_num(ac.get("baro_rate"))
    if vr is None:
        vr = _live_num(ac.get("geom_rate"))
    heading = _live_num(ac.get("track"))
    if heading is None:
        heading = _live_num(ac.get("true_heading"))
    return {
        "hex": str(ac.get("hex") or ""),
        "callsign": callsign or None,
        "registration": (str(ac.get("r")).strip() or None)
                        if ac.get("r") else None,
        "type": (str(ac.get("t")).strip() or None) if ac.get("t") else None,
        "lat": round(lat, 5),
        "lon": round(lon, 5),
        "altitude_ft": int(round(alt_ft)) if alt_ft is not None else None,
        "on_ground": bool(on_ground),
        "speed_kt": _live_num(ac.get("gs")),
        "heading": heading,
        "vertical_rate_fpm": int(round(vr)) if vr is not None else None,
        "squawk": squawk,
        "emergency": squawk in _EMERGENCY_SQUAWKS,
        "category": (str(ac.get("category")).strip() or None)
                    if ac.get("category") else None,
        "seen_s": _live_num(ac.get("seen_pos")),
    }


def normalize_live_payload(raw):
    """Whole upstream body -> clean aircraft list + upstream total.
    Non-dict bodies and junk records degrade to an empty list, never
    an exception (the caller treats 'no aircraft' as 'no data' and
    falls back to last-good)."""
    if not isinstance(raw, dict):
        return [], 0
    out = []
    for ac in raw.get("ac") or []:
        n = normalize_aircraft(ac)
        if n is not None:
            out.append(n)
    total = raw.get("total")
    if not isinstance(total, int) or total < len(out):
        total = len(out)
    return out, total


async def _fetch_live_upstream(lat, lon, dist, timeout):
    url = "%s/lat/%s/lon/%s/dist/%d" % (
        LIVE_ADSB_BASE, round(float(lat), 4), round(float(lon), 4),
        int(dist))
    async with _make_client(follow_redirects=True) as client:
        r = await _get(client, url, timeout)
        return r.json()


async def fetch_live_flights(lat, lon, dist, timeout=LIVE_UPSTREAM_TIMEOUT):
    """Live aircraft around (lat, lon) within dist nm.

    Returns (payload, upstream_attempted). Payload shape:
    {aircraft: [...], total, center: {lat, lon}, dist, fetched_at,
     age_s, stale, source, note}. On upstream failure (or while the
    global upstream gate is closed) the last good answer for the area
    is returned with stale=True; with no history at all, an empty
    stale payload. NEVER raises and never leaks upstream error text —
    the same contract the Command Live Intel feeds use."""
    global _live_lock, _live_last_fetch
    lat, lon, dist = float(lat), float(lon), int(dist)
    now = time.time()
    key = _live_key(lat, lon, dist)
    hit = _live_cache.get(key)
    if hit and now - hit["fetched"] < LIVE_CACHE_TTL:
        return dict(hit["payload"],
                    age_s=round(now - hit["fetched"], 1), stale=False), False
    if _live_lock is None:
        _live_lock = asyncio.Lock()
    attempted = False
    fresh = None
    async with _live_lock:
        # Re-check under the lock: a concurrent request for this area
        # may have just refreshed it while we waited.
        now = time.time()
        hit = _live_cache.get(key)
        if hit and now - hit["fetched"] < LIVE_CACHE_TTL:
            return dict(hit["payload"],
                        age_s=round(now - hit["fetched"], 1),
                        stale=False), False
        if now - _live_last_fetch >= LIVE_MIN_UPSTREAM_GAP:
            attempted = True
            _live_last_fetch = now
            try:
                raw = await _fetch_live_upstream(lat, lon, dist, timeout)
                aircraft, total = normalize_live_payload(raw)
            except Exception:
                aircraft, total = [], 0
            if aircraft:
                fresh = {
                    "aircraft": aircraft, "total": total,
                    "center": {"lat": round(lat, 4), "lon": round(lon, 4)},
                    "dist": dist,
                    "fetched_at": datetime.fromtimestamp(
                        now, timezone.utc).isoformat(timespec="seconds"),
                    "source": "adsb.lol", "note": LIVE_RESPONSE_NOTE,
                }
                if len(_live_cache) > 64:
                    _live_cache.clear()
                _live_cache[key] = {"fetched": now, "payload": fresh}
    if fresh is not None:
        return dict(fresh, age_s=0.0, stale=False), attempted
    if hit and now - hit["fetched"] < LIVE_STALE_TTL:
        return dict(hit["payload"],
                    age_s=round(now - hit["fetched"], 1),
                    stale=True), attempted
    return {
        "aircraft": [], "total": 0,
        "center": {"lat": round(lat, 4), "lon": round(lon, 4)},
        "dist": dist, "fetched_at": None, "age_s": None, "stale": True,
        "source": "adsb.lol", "note": LIVE_RESPONSE_NOTE,
    }, attempted
