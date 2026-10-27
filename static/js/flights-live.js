// LF-2026-10-25: the live traffic layer. The map above starts on the
// world view; this module takes it home to Kansas City (unless a
// searched route already framed the view), then polls
// /api/live-flights for the CURRENT viewport every 15s and renders
// real aircraft from the community ADS-B feed (adsb.lol). Markers
// glide between polls on dead reckoning — ground speed + heading
// from each aircraft's own last report — and snap to truth on the
// next poll; rotation turns the short way round. Nothing here calls
// the flight-status provider: map traffic spends zero search quota.
(function liveTraffic() {
  const KC = [39.1, -94.6], POLL_MS = 15000, CAP = 600;
  const PLANE = 'M12 1.8l1.7 1.1v6.2l7.8 4.4v2.3l-9.5-2.4v5l3 2v1.7l-3-1-3 1v-1.7l3-2v-5l-9.5 2.4v-2.3l7.8-4.4V2.9z';
  const noteEl = document.getElementById('fmap-note');
  const statusEl = document.getElementById('live-status');
  const panel = document.getElementById('flight-panel');
  const entries = new Map();   // hex -> {marker, data, rot, curLat, curLon}
  let selectedHex = null, pendingTrack = null;
  let meta = {shown: 0, total: 0, ageBase: null, respLocal: 0, stale: true, ok: false};

  if (!window.__routePlotted) fmap.setView(KC, 9);
  if (!RESULT) noteEl.textContent = 'Live traffic over Kansas City — drag or zoom and the view refreshes itself. Click any aircraft for its details.';

  function havNm(a, b) {
    const R = 3440.065, rad = Math.PI / 180;
    const dLa = (b[0] - a[0]) * rad;
    let dLo = (b[1] - a[1]) * rad;
    const s = Math.sin(dLa / 2) ** 2 + Math.cos(a[0] * rad) * Math.cos(b[0] * rad) * Math.sin(dLo / 2) ** 2;
    return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
  }
  function fmtInt(n) { return Math.round(n).toLocaleString('en-US'); }
  function acStyle(a) {
    if (a.on_ground) return {fill: '#ffffff'};
    const f = a.altitude_ft;
    if (f != null && f < 10000) return {fill: '#ffd9d9'};
    if (f != null && f >= 30000) return {fill: '#ff8a3c'};
    return {fill: '#ffe9c9'};
  }
  function showLabels() { return selectedHex != null || fmap.getZoom() >= 9; }
  function acIcon(e) {
    const a = e.data, sel = e.hex === selectedHex;
    const lab = (sel || fmap.getZoom() >= 9) && a.callsign
      ? '<div class="aclab">' + esc(a.callsign) + '</div>' : '';
    return L.divIcon({
      className: 'acicon' + (a.emergency ? ' acalert' : ''),
      iconSize: [30, 30], iconAnchor: [15, 15],
      html: '<div class="acwrap' + (sel ? ' sel' : '') + '"><div class="achalo"></div>' +
        '<div class="acrot">' +
        '<svg viewBox="0 0 24 24" width="30" height="30" aria-hidden="true"><path d="' + PLANE + '" fill="' + acStyle(a).fill + '"/></svg></div>' +
        lab + '</div>'
    });
  }
  function posAt(e, now) {
    // Dead reckoning from the last report: fast + high = bigger steps.
    const dt = Math.min(20, Math.max(0, (now - e.t0) / 1000));
    if (!e.data || e.data.on_ground || e.data.speed_kt == null || e.data.heading == null) {
      return [e.lat, e.lon];
    }
    const dNm = e.data.speed_kt * dt / 3600, rad = Math.PI / 180;
    const brg = e.data.heading * rad, la = e.lat * rad, lo = e.lon * rad;
    const nLa = la + (dNm / 3440.065) * Math.cos(brg);
    const nLo = lo + (dNm / 3440.065) * Math.sin(brg) / Math.max(0.2, Math.cos(la));
    // nLa/nLo are RADIANS here — convert BOTH back to degrees.
    // (A radians longitude fed to the marker wrapped ~57x around
    // the world: positions landed thousands of degrees west.)
    return [nLa / rad, nLo / rad];
  }
  function setRot(e, hdg) {
    if (hdg == null) return;
    let t = hdg;
    while (t - e.rot > 180) t -= 360;
    while (e.rot - t > 180) t += 360;
    e.rot = t;
    const el = e.marker.getElement();
    if (el) { const r = el.querySelector('.acrot'); if (r) r.style.transform = 'rotate(' + t + 'deg)'; }
  }
  function refreshIcon(e) { e.marker.setIcon(acIcon(e)); setRot(e, e.data ? e.data.heading : null); }

  function statusRender() {
    const age = meta.ageBase == null ? null : Math.max(0, Math.round(meta.ageBase + (Date.now() - meta.respLocal) / 1000));
    let txt;
    if (!meta.ok) txt = 'Live feed unreachable — retrying automatically.';
    else if (!meta.total) txt = 'Live — no aircraft inside this view right now.';
    else {
      txt = (meta.stale ? 'Feed delayed — last good data · ' : 'Live · ') +
        meta.total.toLocaleString('en-US') + ' aircraft in range' +
        (meta.shown < meta.total ? ' · showing nearest ' + meta.shown : '') +
        (age != null ? ' · data ' + age + 's old' : '');
    }
    statusEl.textContent = txt;
    const fu = document.getElementById('fp-updated');
    if (!panel.hidden && age != null) {
      fu.textContent = 'Updated ' + age + 's ago' + (meta.stale ? ' · feed delayed, showing last good data' : '') + ' · positions advance between updates on each aircraft\u2019s last reported speed and heading.';
    }
  }

  function renderPanel(a) {
    // Display coordinates are always the true -180..180 values, even
    // when the marker rides a wrapped world copy.
    const dLat = Math.max(-90, Math.min(90, a.lat));
    const dLon = ((a.lon + 540) % 360) - 180;
    document.getElementById('fp-title').textContent = a.callsign || a.registration || (a.hex || '').toUpperCase() || 'Aircraft';
    const sub = [];
    if (a.type) sub.push('Type ' + a.type);
    if (a.registration) sub.push(a.registration);
    if (!a.callsign && a.hex) sub.push('ICAO ' + a.hex.toUpperCase());
    document.getElementById('fp-sub').textContent = sub.join(' · ');
    document.getElementById('fp-alt').textContent = a.on_ground ? 'On the ground'
      : (a.altitude_ft != null ? fmtInt(a.altitude_ft) + ' ft' : '—');
    document.getElementById('fp-spd').textContent = a.speed_kt != null ? fmtInt(a.speed_kt) + ' kt' : '—';
    document.getElementById('fp-hdg').textContent = a.heading != null ? Math.round(a.heading) + '°' : '—';
    document.getElementById('fp-vr').textContent = a.vertical_rate_fpm == null ? '—'
      : (a.vertical_rate_fpm === 0 ? 'Level' : (a.vertical_rate_fpm > 0 ? '+' : '-') + fmtInt(Math.abs(a.vertical_rate_fpm)) + ' fpm');
    document.getElementById('fp-sqk').innerHTML = a.squawk
      ? esc(a.squawk) + (a.emergency ? ' <span class="fp-emg">EMERGENCY</span>' : '') : '—';
    document.getElementById('fp-pos').textContent = dLat.toFixed(4) + ', ' + dLon.toFixed(4);
    document.getElementById('fp-cat').textContent = a.category || '—';
    panel.hidden = false;
    statusRender();
  }
  function deselect() {
    if (selectedHex && entries.has(selectedHex)) refreshIcon(entries.get(selectedHex));
    selectedHex = null;
    panel.hidden = true;
  }
  function selectAircraft(hex, pan) {
    const e = entries.get(hex);
    if (!e) return;
    const prev = selectedHex;
    selectedHex = hex;
    if (prev && prev !== hex && entries.has(prev)) refreshIcon(entries.get(prev));
    refreshIcon(e);
    if (pan) fmap.panTo([e.data.lat, e.data.lon]);
    renderPanel(e.data);
  }
  document.getElementById('fp-close').addEventListener('click', deselect);
  // Clicking empty map clears the selection — but only on a true
  // background click: a drag-pan that starts on an aircraft also
  // fires the map's click (the press began on the marker), and that
  // must not deselect what the visitor is following. 250ms separates
  // a click from a drag's release.
  let pressAt = 0;
  fmap.on('mousedown', () => { pressAt = Date.now(); });
  fmap.on('click', () => { if (Date.now() - pressAt < 250) deselect(); });

  function applyData(data) {
    if (!data || !Array.isArray(data.aircraft)) { meta.ok = false; statusRender(); return; }
    meta = {shown: 0, total: data.total || 0, ageBase: (typeof data.age_s === 'number' ? data.age_s : 0),
            respLocal: Date.now(), stale: !!data.stale, ok: true};
    const c = fmap.getCenter();
    let list = data.aircraft.slice();
    if (list.length > CAP) {
      list.sort((x, y) => havNm([c.lat, c.lng], [x.lat, x.lon]) - havNm([c.lat, c.lng], [y.lat, y.lon]));
      list = list.slice(0, CAP);
    }
    meta.shown = list.length;
    const seen = new Set(), now = performance.now();
    list.forEach(a => {
      const key = a.hex || (a.callsign || '') + '@' + a.lat + ',' + a.lon;
      seen.add(key);
      // World-copy discipline: the map runs with worldCopyJump, so a
      // marker's stored longitude can drift a full world (360°) from
      // the feed's — comparing raw longitudes then reads as a
      // trans-world jump, and any position derived from the drifted
      // copy (the panel's readout) would print impossible coordinates.
      // Normalize every incoming position to the copy nearest the
      // current view center; stored entries keep their own copy.
      const clng = c.lng;
      while (a.lon - clng > 180) a.lon -= 360;
      while (clng - a.lon > 180) a.lon += 360;
      const e = entries.get(key);
      if (e) {
        while (a.lon - e.lon > 180) a.lon -= 360;
        while (e.lon - a.lon > 180) a.lon += 360;
        const p = posAt(e, now);
        e.lat = a.lat; e.lon = a.lon; e.t0 = now; e.data = a;
        e.marker.setLatLng(p);
        setRot(e, a.heading);
        refreshIcon(e);
      } else {
        const ne = {hex: key, data: a, rot: a.heading || 0, lat: a.lat, lon: a.lon, t0: now, marker: null};
        ne.marker = L.marker([a.lat, a.lon], {icon: acIcon(ne), keyboard: false})
          .addTo(fmap).on('click', () => selectAircraft(key, false));
        entries.set(key, ne);
        setRot(ne, a.heading);
      }
    });
    entries.forEach((e, key) => {
      if (!seen.has(key)) {
        fmap.removeLayer(e.marker);
        entries.delete(key);
        if (selectedHex === key) { selectedHex = null; panel.hidden = true; }
      }
    });
    if (selectedHex && entries.has(selectedHex)) renderPanel(entries.get(selectedHex).data);
    if (pendingTrack) {
      const hit = findByCallsign(pendingTrack);
      if (hit) {
        selectAircraft(hit, true);
        trackMsg('Now tracking ' + pendingTrack + ' live.');
        pendingTrack = null;
      }
    }
    statusRender();
  }
  function findByCallsign(cs) {
    let found = null;
    entries.forEach((e, key) => {
      if (!found && e.data.callsign && e.data.callsign.replace(/\s+/g, '').toUpperCase() === cs) found = key;
    });
    return found;
  }
  async function pollLive() {
    const c = fmap.getCenter(), b = fmap.getBounds();
    const dist = Math.min(250, Math.max(10, Math.ceil(havNm([c.lat, c.lng], [b.getNorth(), b.getEast()]) * 1.05)));
    let data = null;
    try {
      const r = await fetch('/api/live-flights?lat=' + c.lat.toFixed(4) + '&lon=' + c.lng.toFixed(4) + '&dist=' + dist,
        {headers: {'Accept': 'application/json'}});
      if (r.ok) data = await r.json();
    } catch (err) { /* keep last frame; status shows the retry */ }
    applyData(data);
  }

  // Glide: a 100ms ticker advances every marker on dead reckoning
  // (see posAt) — deterministic, monotonic, never jittery.
  let lastTick = 0;
  function tick(ts) {
    requestAnimationFrame(tick);
    if (ts - lastTick < 100) return;
    lastTick = ts;
    const now = performance.now();
    entries.forEach(e => e.marker.setLatLng(posAt(e, now)));
  }
  requestAnimationFrame(tick);
  setInterval(pollLive, POLL_MS);
  setInterval(statusRender, 1000);
  let moveTimer = null;
  fmap.on('moveend', () => { clearTimeout(moveTimer); moveTimer = setTimeout(pollLive, 700); });
  fmap.on('zoomend', () => entries.forEach(refreshIcon));
  pollLive();

  // ---- search bridge: "Track live" on a searched flight number.
  const trackBtn = document.getElementById('track-live');
  const trackMsgEl = document.getElementById('track-live-msg');
  function trackMsg(t) { if (trackMsgEl) trackMsgEl.textContent = t; }
  if (trackBtn && RESULT && RESULT.number) {
    trackBtn.addEventListener('click', () => {
      const cs = String(RESULT.number).replace(/\s+/g, '').toUpperCase();
      const hit = findByCallsign(cs);
      if (hit) {
        selectAircraft(hit, true);
        trackMsg('Now tracking ' + cs + ' live on the map.');
        document.getElementById('fmap').scrollIntoView({behavior: 'smooth', block: 'center'});
        return;
      }
      pendingTrack = cs;
      if (window.__searchedPos) {
        fmap.setView(window.__searchedPos, 9);
        trackMsg('Moving to ' + cs + '\u2019s reported position and watching for it in live coverage\u2026');
      } else {
        trackMsg(cs + ' is not inside the current live view — watching for it here. Pan the map toward its route and it will be picked up.');
      }
      document.getElementById('fmap').scrollIntoView({behavior: 'smooth', block: 'center'});
    });
  }
})();
