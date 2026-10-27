// Maps fix 2026-10-23: the flight map is now ALWAYS rendered (previously it
// existed only inside the result block, so with no live result — e.g. while
// the AviationStack key is missing — the page had no map at all). Basemap
// standard shared with the threat and geopolitical maps: Esri public
// ArcGIS services (keyless, no watermark) — CARTO's free endpoints began
// serving "API KEY REQUIRED" watermark tiles (basemap swap 2026-10-23).
// "Streets" (default) is the detailed layer; "Satellite" is world imagery
// with label overlays; "Dark" is the dark gray canvas + reference overlay.
// Esri tiles are ordered {z}/{y}/{x}, native to zoom 18; maps zoom to 19.
const fmap = L.map('fmap', {worldCopyJump: true}).setView([30, -40], 2);
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
})(fmap);

const _FD = JSON.parse(document.getElementById('flight-data').textContent);
const COORDS = _FD.coords;
const RESULT = _FD.result;
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function gcPoints(a, b, n) {
  // Great-circle interpolation (slerp between unit vectors).
  const rad = Math.PI / 180;
  const v = p => [Math.cos(p[0] * rad) * Math.cos(p[1] * rad), Math.cos(p[0] * rad) * Math.sin(p[1] * rad), Math.sin(p[0] * rad)];
  const A = v(a), B = v(b);
  const dot = Math.max(-1, Math.min(1, A[0] * B[0] + A[1] * B[1] + A[2] * B[2]));
  const om = Math.acos(dot), so = Math.sin(om);
  const pts = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    const k0 = so < 1e-6 ? 1 - t : Math.sin((1 - t) * om) / so;
    const k1 = so < 1e-6 ? t : Math.sin(t * om) / so;
    const x = k0 * A[0] + k1 * B[0], y = k0 * A[1] + k1 * B[1], z = k0 * A[2] + k1 * B[2];
    pts.push([Math.atan2(z, Math.hypot(x, y)) / rad, Math.atan2(y, x) / rad]);
  }
  return pts;
}
function aptPopup(title, apt, code, when) {
  return '<b>' + esc(title) + '</b><br>' + esc(apt.airport || '') + (code ? ' (' + esc(code) + ')' : '') +
    '<br><span class="popmeta">Flight ' + esc(RESULT.number || '') + (RESULT.airline ? ' &middot; ' + esc(RESULT.airline) : '') +
    ' &middot; ' + esc(String(RESULT.status || '').replace(/_/g, ' ')) + '</span>' +
    '<br>Scheduled: ' + esc(apt.scheduled || '—') +
    (apt.estimated ? '<br>Estimated: ' + esc(apt.estimated) : '') +
    (apt.actual ? '<br>' + esc(when) + ': ' + esc(apt.actual) : '') +
    (apt.terminal ? '<br><span class="popmeta">Terminal ' + esc(apt.terminal) + (apt.gate ? ' &middot; Gate ' + esc(apt.gate) : '') + '</span>' : '');
}
(function plot() {
  const note = document.getElementById('fmap-note');
  if (!RESULT) return;
  const depC = RESULT.departure && RESULT.departure.iata, arrC = RESULT.arrival && RESULT.arrival.iata;
  const a = depC && COORDS[depC], b = arrC && COORDS[arrC];
  const bounds = [];
  if (a) { L.marker(a).bindPopup(aptPopup('Departure', RESULT.departure, depC, 'Departed')).addTo(fmap); bounds.push(a); }
  if (b) { L.marker(b).bindPopup(aptPopup('Arrival', RESULT.arrival, arrC, 'Arrived')).addTo(fmap); bounds.push(b); }
  if (a && b) {
    const pts = gcPoints(a, b, 80);
    L.polyline(pts, {color: '#003d1f', weight: 5, opacity: 0.55}).addTo(fmap);
    L.polyline(pts, {color: '#00e676', weight: 2, dashArray: '6 8', className: 'arc'}).addTo(fmap);
    note.textContent = 'Route ' + depC + ' → ' + arrC + ' plotted as a great-circle path — live traffic continues around it.';
  } else if (a || b) {
    note.textContent = 'One airport of this route is not in the coordinate table yet — showing the known end only.';
  } else {
    note.textContent = 'Route map unavailable: these airports are not in the coordinate table yet.';
  }
  if (RESULT.live && typeof RESULT.live.latitude === 'number' && typeof RESULT.live.longitude === 'number') {
    const lp = [RESULT.live.latitude, RESULT.live.longitude];
    window.__searchedPos = lp;
    L.marker(lp, {icon: L.divIcon({className: 'plane', html: '&#9992;', iconSize: [24, 24]})})
      .bindPopup('<b>' + esc(RESULT.number || 'Flight') + ' — live position</b>' +
        (RESULT.live.altitude != null ? '<br>Altitude: ' + esc(Math.round(RESULT.live.altitude)) + ' m' : '') +
        (RESULT.live.speed_horizontal != null ? '<br>Ground speed: ' + esc(Math.round(RESULT.live.speed_horizontal)) + ' km/h' : '') +
        (RESULT.live.direction != null ? '<br>Heading: ' + esc(Math.round(RESULT.live.direction)) + '&deg;' : ''))
      .addTo(fmap).openPopup();
    bounds.push(lp);
  }
  if (bounds.length) { fmap.fitBounds(bounds, {padding: [45, 45], maxZoom: 6}); window.__routePlotted = true; }
})();
