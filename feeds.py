"""Feed fetchers for Sentinel Live Server.

All functions are async, tolerate failures, and never invent data:
on failure they return an error status the pages render honestly.
"""
import asyncio
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

import feedparser
import httpx

UA = {"User-Agent": "SentinelLive/1.0 (Sentinel Safeguard LLC)"}

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
            except Exception as e:
                errors.append(f"sources: {type(e).__name__}")

            # Stage 3: per-IP detail + geolocation (per-item failures tolerated)
            if sources:
                async def _detail(ip):
                    try:
                        rr = await _get(client, f"{DSHIELD}/ip/{ip}?json", timeout)
                        return (rr.json() or {}).get("ip") or {}
                    except Exception:
                        return {}

                top = sources[:40]
                details = await asyncio.gather(*(_detail(s["ip"]) for s in top))
                geo = await _geolocate_ips(client, [s["ip"] for s in sources[:60]], timeout)

                by_country = Counter()
                by_type = Counter()
                markers, feed = [], []
                for s, d in zip(top, details):
                    ip = s["ip"]
                    attacks = s.get("attacks") or 0
                    feeds_seen = (d.get("threatfeeds") or {})
                    types = [ATTACK_TYPES.get(k, k) for k in feeds_seen]
                    for t in types:
                        by_type[t] += attacks
                    cc = (d.get("ascountry") or "").upper()
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
        out["status"] = "error"
        out["error"] = f"Threat feed unavailable ({type(e).__name__}): {e}"
    return out


# --------------------------------------------------------------------- rss
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
                "link": e.get("link") or "",
                "published": e.get("published") or e.get("updated") or "",
                "source": (parsed.feed.get("title") or "").strip()[:40],
            })
    except Exception:
        pass
    return items


async def fetch_rss_items(urls, timeout=20, limit_per_feed=6):
    items = []
    async with _make_client(follow_redirects=True) as client:
        async def one(url):
            try:
                r = await client.get(url, timeout=timeout)
                r.raise_for_status()
                return _parse_rss(r.content, limit_per_feed)
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
    spots, seen = [], set()
    for it in items:
        t = (it["title"] or "").lower()
        for kw, lat, lon, label in GEO_KEYWORDS:
            if kw in t and label not in seen:
                seen.add(label)
                spots.append({"lat": lat, "lon": lon, "label": label,
                              "title": it["title"]})
                break
    return spots[:25]


async def fetch_geopolitical(urls, timeout=20):
    items = await fetch_rss_items(urls, timeout, limit_per_feed=8)
    for it in items:
        it["impact"] = impact_note(it["title"])
    return {"updated": _now(), "status": "ok" if items else "empty",
            "items": items[:40], "hotspots": geo_hotspots(items),
            "error": None if items else "All geopolitical feeds unreachable right now."}


async def fetch_news_sections(sections, timeout=20):
    out = {"updated": _now(), "status": "ok", "sections": {}, "error": None}
    for name, urls in sections.items():
        items = await fetch_rss_items(urls, timeout, limit_per_feed=6)
        out["sections"][name] = items[:12]
    if not any(out["sections"].values()):
        out["status"] = "empty"
        out["error"] = "News feeds unreachable right now."
    return out


# ------------------------------------------------------------------ flights
async def lookup_flight(number, api_key, timeout=20):
    """AviationStack lookup. Returns (result_dict, error_str)."""
    num = re.sub(r"[^A-Za-z0-9]", "", number or "").upper()
    if not num:
        return None, "Enter a flight number (e.g. AA100, UAL512, SWA204)."
    url = "http://api.aviationstack.com/v1/flights"
    try:
        async with _make_client() as client:
            r = await client.get(url, params={"access_key": api_key,
                                              "flight_iata": num}, timeout=timeout)
            r.raise_for_status()
            payload = r.json()
    except Exception as e:
        return None, f"Flight API request failed ({type(e).__name__}): {e}"
    flights = (payload or {}).get("data") or []
    if not flights:
        err = (payload or {}).get("error", {})
        return None, err.get("message") or f"No live data for {num} right now."
    f = flights[0]
    dep, arr = f.get("departure") or {}, f.get("arrival") or {}
    return {
        "number": (f.get("flight") or {}).get("iata") or num,
        "airline": (f.get("airline") or {}).get("name") or "",
        "status": f.get("flight_status") or "unknown",
        "date": f.get("flight_date") or "",
        "departure": {k: dep.get(k) for k in
                      ("airport", "iata", "terminal", "gate", "scheduled", "estimated", "actual", "delay")},
        "arrival": {k: arr.get(k) for k in
                    ("airport", "iata", "terminal", "gate", "scheduled", "estimated", "actual", "delay")},
        "aircraft": (f.get("aircraft") or {}).get("registration") or "",
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
}
