const map = L.map('map', {worldCopyJump: true}).setView([28, 8], 2);
// Basemap standard shared by all three maps — Esri public ArcGIS services
// (keyless, no watermark). Basemap swap 2026-10-23: CARTO's free endpoints
// began serving "API KEY REQUIRED" watermark tiles, so every CARTO layer
// was replaced. "Streets" (default) is the detailed layer — borders,
// labels, roads; "Satellite" is world imagery with transport + place
// label overlays; "Dark" is the dark gray canvas with its reference
// overlay. Esri tiles are ordered {z}/{y}/{x} and native to zoom 18; the
// maps zoom to 19 and upscale the last level instead of erroring.
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

const pulseIcon = L.divIcon({className: 'pulse', iconSize: [14, 14]});
let layers = [];
let cuFirst = true;

// Aggregate the per-IP markers into one volume point per source country:
// centroid of that country's mapped IPs, summed attacks, top attack types.
// The API's countries[] totals (all sources, not just the mapped top-40)
// are merged in by region-name match when available.
function countryPoints(d) {
  const byName = {};
  (d.markers || []).forEach(m => {
    const k = m.country || 'Unknown';
    const g = byName[k] || (byName[k] = {name: k, lat: 0, lon: 0, n: 0, attacks: 0, types: {}});
    g.lat += m.lat; g.lon += m.lon; g.n++; g.attacks += (m.attacks || 0);
    (m.types || []).forEach(t => { g.types[t] = (g.types[t] || 0) + (m.attacks || 0); });
  });
  const totals = {};
  try {
    const dn = new Intl.DisplayNames(['en'], {type: 'region'});
    (d.countries || []).forEach(c => { try { totals[dn.of(c.code).toLowerCase()] = c.count; } catch (e) {} });
  } catch (e) {}
  return Object.values(byName).map(g => ({
    name: g.name, lat: g.lat / g.n, lon: g.lon / g.n, ips: g.n, attacks: g.attacks,
    total: (totals[g.name.toLowerCase()] != null ? totals[g.name.toLowerCase()] : null),
    topTypes: Object.entries(g.types).sort((a, b) => b[1] - a[1]).slice(0, 3).map(x => x[0])
  }));
}
function volColor(v) { return v > 50000 ? '#ff4444' : v > 10000 ? '#ff7b33' : v > 2000 ? '#ffb300' : '#00e676'; }

async function load() {
  try {
    const r = await fetch('/api/threat-data');
    const d = await r.json();
    document.getElementById('upd').textContent =
      'Last updated ' + (d.updated || 'never') +
      (d.status === 'ok' ? '' : ' — ' + (d.error || d.status) + ' — retrying automatically.');
    document.getElementById('counters').innerHTML =
      '<div class="counter"><b data-cu="' + (d.attacks_today || 0) + '">0</b><span>attacks logged today</span></div>' +
      '<div class="counter"><b data-cu="' + (d.sources_today || 0) + '">0</b><span>attacking sources today</span></div>' +
      '<div class="counter"><b data-cu="' + d.markers.length + '">0</b><span>top attackers mapped</span></div>' +
      '<div class="counter"><b data-cu="' + d.arcs.length + '">0</b><span>attack paths</span></div>';
    // Design pass: on first load the counters count up to their live
    // values (SSG.countUp sets them instantly under reduced motion);
    // on the 60s refreshes they update in place — a live instrument,
    // not a looping animation.
    document.querySelectorAll('#counters [data-cu]').forEach(function (el) {
      var v = Number(el.getAttribute('data-cu'));
      if (window.SSG && cuFirst) SSG.countUp(el, v, fmt); else el.textContent = fmt(v);
    });
    cuFirst = false;
    layers.forEach(l => map.removeLayer(l)); layers = [];
    countryPoints(d).forEach(g => {
      const vol = g.total != null ? g.total : g.attacks;
      const circ = L.circleMarker([g.lat, g.lon], {
          radius: Math.max(8, Math.min(26, 4 + Math.log10(vol + 1) * 4.2)),
          color: volColor(vol), weight: 2, fillColor: volColor(vol), fillOpacity: 0.35})
        .bindPopup('<b>' + esc(g.name) + '</b><br>' +
          fmt(vol) + ' attacks logged today' + (g.total != null ? ' (all sources)' : ' (mapped sources)') + '<br>' +
          '<span class="popmeta">from ' + g.ips + ' mapped attacking IP' + (g.ips === 1 ? '' : 's') + '</span>' +
          (g.topTypes.length ? '<br>Top types: ' + esc(g.topTypes.join(', ')) : '') +
          (d.families && d.families.length ? '<br><span class="popmeta">Top malware families today (global): ' +
            esc(d.families.slice(0, 3).map(f => f.name).join(', ')) + '</span>' : ''));
      circ.addTo(map); layers.push(circ);
    });
    (d.markers || []).forEach(m => {
      const mk = L.marker([m.lat, m.lon], {icon: pulseIcon})
        .bindPopup('<b>' + esc(m.ip) + '</b> (' + fmt(m.attacks) + ' attacks)<br>' +
                   esc(m.country) + (m.asname ? ' &middot; ' + esc(m.asname) : '') +
                   (m.types && m.types.length ? '<br><span class="dim">' + esc(m.types.join(', ')) + '</span>' : ''));
      mk.addTo(map); layers.push(mk);
    });
    (d.arcs || []).forEach(a => {
      const line = L.polyline([a.from, a.to], {color: '#ff4444', weight: 1.5, opacity: 0.75, dashArray: '6 8', className: 'arc'})
        .bindPopup('<b>' + esc(a.from_cc) + ' &rarr; sensor network</b><br>' + esc(a.label));
      line.addTo(map); layers.push(line);
    });
    document.getElementById('ctrs').innerHTML = (d.countries || []).map(c =>
      '<li><span>' + esc(c.code) + '</span><div class="bar"><i data-w="' +
      Math.min(100, Math.log10(c.count + 1) * 28) + '"></i></div><b>' + fmt(c.count) + '</b></li>').join('') || '<li class="dim">No data yet</li>';
    document.getElementById('types').innerHTML = (d.attack_types || []).map(t =>
      '<li><span>' + esc(t.name) + '</span><div class="bar"><i data-w="' +
      Math.min(100, Math.log10(t.count + 1) * 28) + '"></i></div><b>' + fmt(t.count) + '</b></li>').join('') || '<li class="dim">No data yet</li>';
    if (d.families && d.families.length) {
      document.getElementById('famsec').hidden = false;
      document.getElementById('fams').innerHTML = d.families.map(f =>
        '<li><span>' + esc(f.name) + '</span><div class="bar"><i data-w="' +
        Math.min(100, f.count * 4) + '"></i></div><b>' + f.count + '</b></li>').join('');
    }
    setBars(document.getElementById('ctrs')); setBars(document.getElementById('types')); setBars(document.getElementById('fams'));
    document.getElementById('ticker').innerHTML = (d.feed || []).map(f =>
      '<div class="tick"><code>' + esc(f.ip) + '</code><span>' + fmt(f.attacks) + ' attacks</span><em>' +
      esc(f.country) + (f.asname ? ' · ' + esc(f.asname) : '') + (f.types ? ' · ' + esc(f.types) : '') + '</em></div>').join('')
      || '<p class="dim">No attackers in the current window.</p>';
  } catch (e) {
    document.getElementById('upd').textContent = 'Could not reach the server — retrying.';
  }
}

function setBars(el) { el.querySelectorAll('i[data-w]').forEach(function (i) { i.style.width = i.dataset.w + '%'; }); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function fmt(n) { return Number(n || 0).toLocaleString('en-US'); }
load();
setInterval(load, 60000);
