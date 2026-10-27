const map = L.map('map', {worldCopyJump: true}).setView([28, 8], 2);
// Basemap block copied from threat-map.js (same Esri layers).
(function basemaps(m) {
  const ESRI = 'https://server.arcgisonline.com/ArcGIS/rest/services';
  const OPTS = {maxZoom: 19, maxNativeZoom: 18};
  const streets = L.tileLayer(ESRI + '/World_Street_Map/MapServer/tile/{z}/{y}/{x}',
    Object.assign({attribution: 'Esri, HERE, Garmin, OpenStreetMap contributors, and the GIS User Community'}, OPTS));
  const satellite = L.layerGroup([
    L.tileLayer(ESRI + '/World_Imagery/MapServer/tile/{z}/{y}/{x}',
      Object.assign({attribution: 'Esri, Maxar, Earthstar Geographics'}, OPTS)),
    L.tileLayer(ESRI + '/Reference/World_Transportation/MapServer/tile/{z}/{y}/{x}', OPTS),
    L.tileLayer(ESRI + '/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}',
      Object.assign({attribution: 'Esri'}, OPTS))
  ]);
  const dark = L.layerGroup([
    L.tileLayer(ESRI + '/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}',
      Object.assign({attribution: 'Esri, HERE, Garmin, OpenStreetMap contributors, and the GIS User Community'}, OPTS)),
    L.tileLayer(ESRI + '/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}', OPTS)
  ]);
  streets.addTo(m);
  m.on('load', () => m.getContainer().classList.add('tiles-in'));
  L.control.layers({'Streets': streets, 'Satellite': satellite, 'Dark': dark}, null, {collapsed: true}).addTo(m);
  L.control.scale({imperial: true}).addTo(m);
})(map);

let layers = [];
let cuFirst = true;

function wxColor(v) { return v > 66 ? '#ff4444' : v >= 34 ? '#ff7b33' : v >= 1 ? '#ffb300' : '#00e676'; }

function ageText(updated) {
  if (!updated) return 'never';
  const t = Date.parse(updated);
  if (isNaN(t)) return String(updated);
  const mins = Math.max(0, Math.round((Date.now() - t) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return mins + ' min ago';
  const hrs = Math.floor(mins / 60);
  return hrs + (hrs === 1 ? ' hour ago' : ' hours ago');
}

async function load() {
  try {
    const r = await fetch('/api/internet-weather');
    const d = await r.json();
    const totals = d.totals || {};
    document.getElementById('upd').textContent =
      'Last updated ' + fmtCT(d.updated) + ' (' + ageText(d.updated) + ')' +
      (d.status === 'ok' ? '' : ' — ' + (d.error || d.status) + ' — retrying automatically.');
    const note = document.getElementById('wx-note');
    const src = d.sources || {};
    const gripes = [];
    if (src.ioda && src.ioda !== 'ok') gripes.push('IODA is unavailable right now, so the outage picture may be incomplete.');
    if (src.ripestat && src.ripestat !== 'ok') gripes.push('RIPEstat routing data is ' + (src.ripestat === 'partial' ? 'partially available' : 'unavailable') + ' — prefix counts may be missing.');
    if (d.status === 'error') gripes.push('Internet weather data is unavailable right now. Nothing below is estimated or filled in — the page updates automatically when the sources answer again.');
    if (gripes.length) {
      note.hidden = false;
      note.textContent = gripes.join(' ') + ' Data age: ' + ageText(d.updated) + '.';
    } else {
      note.hidden = true;
      note.textContent = '';
    }
    document.getElementById('counters').innerHTML =
      '<div class="counter"><b data-cu="' + (totals.countries_affected || 0) + '">0</b><span>countries affected</span></div>' +
      '<div class="counter"><b data-cu="' + (totals.outage_events || 0) + '">0</b><span>outage events</span></div>' +
      '<div class="counter"><b data-cu="' + (totals.alerts_24h || 0) + '">0</b><span>alerts in window</span></div>' +
      '<div class="counter"><b>' + esc(ageText(d.updated)) + '</b><span>data age</span></div>';
    document.querySelectorAll('#counters [data-cu]').forEach(function (el) {
      var v = Number(el.getAttribute('data-cu'));
      if (window.SSG && cuFirst) SSG.countUp(el, v, fmt); else el.textContent = fmt(v);
    });
    cuFirst = false;
    layers.forEach(l => map.removeLayer(l)); layers = [];
    (d.countries || []).forEach(c => {
      if (c.lat == null || c.lon == null) return;
      const circ = L.circleMarker([c.lat, c.lon], {
          radius: Math.max(7, Math.min(24, 5 + (c.intensity || 0) / 5)),
          color: wxColor(c.intensity || 0), weight: 2,
          fillColor: wxColor(c.intensity || 0), fillOpacity: 0.35})
        .bindPopup('<b>' + esc(c.name) + '</b> (' + esc(c.code) + ')<br>' +
          fmt(c.events) + ' outage events in the last 24 hours<br>' +
          'Intensity: ' + (c.intensity || 0) + ' of 100' +
          (c.signals && c.signals.length ? '<br>Signals: ' + esc(c.signals.join(', ')) : '') +
          (c.ripe_v4 != null || c.ripe_v6 != null
            ? '<br><span class="popmeta">RIPEstat prefixes seen: ' +
              (c.ripe_v4 != null ? fmt(c.ripe_v4) + ' IPv4' : '') +
              (c.ripe_v4 != null && c.ripe_v6 != null ? ' · ' : '') +
              (c.ripe_v6 != null ? fmt(c.ripe_v6) + ' IPv6' : '') + '</span>' : ''));
      circ.addTo(map); layers.push(circ);
    });
    document.getElementById('wx-countries').innerHTML = (d.countries || []).map(c =>
      '<li><span>' + esc(c.name) + '</span><div class="bar"><i data-w="' +
      Math.max(0, Math.min(100, c.intensity || 0)) + '"></i></div><b>' + fmt(c.events) + '</b>' +
      (c.signals && c.signals.length ? '<em>' + esc(c.signals.join(', ')) + '</em>' : '') + '</li>').join('')
      || '<li class="dim">No affected countries in the current window.</li>';
    setBars(document.getElementById('wx-countries'));
    document.getElementById('wx-events').innerHTML = (d.events || []).map(e =>
      '<div class="tick"><code>' + esc(e.ts || '') + '</code><span>' + esc(e.name || e.code || '') + '</span><em>' +
      esc(e.datasource || '') + (e.level ? ' · ' + esc(e.level) : '') +
      (e.condition ? ' · ' + esc(e.condition) : '') + '</em></div>').join('')
      || '<p class="dim">No notable events in the current window.</p>';
  } catch (e) {
    document.getElementById('upd').textContent = 'Could not reach the server — retrying.';
    const note = document.getElementById('wx-note');
    note.hidden = false;
    note.textContent = 'Internet weather data is unavailable right now — the server could not be reached.';
  }
}

function setBars(el) { el.querySelectorAll('i[data-w]').forEach(function (i) { i.style.width = i.dataset.w + '%'; }); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function fmt(n) { return Number(n || 0).toLocaleString('en-US'); }
load();
setInterval(load, 60000);

/* POLISH-LANE-A-2026-10-27: house timestamp format — America/Chicago,
   long date + 12-hour clock + CT, matching the server ct_time filter. */
function fmtCT(iso) {
  if (!iso) return 'never';
  var t = Date.parse(iso);
  if (isNaN(t)) return String(iso);
  try {
    return new Intl.DateTimeFormat('en-US', {timeZone: 'America/Chicago', month: 'long', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true}).format(new Date(t)) + ' CT';
  } catch (e) { return String(iso); }
}
