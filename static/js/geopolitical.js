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
let layers = [];
async function load() {
  try {
    const r = await fetch('/api/geo-data');
    const d = await r.json();
    document.getElementById('upd').textContent =
      'Last updated ' + fmtCT(d.updated) + (d.error ? ' — ' + d.error : '');
    layers.forEach(l => map.removeLayer(l)); layers = [];
    (d.hotspots || []).forEach(h => {
      // Server groups stories per hotspot (h.stories[], h.count); older
      // payloads carried a single h.title — synthesize a one-story list.
      const stories = (h.stories && h.stories.length) ? h.stories : [{title: h.title}];
      const count = h.count || stories.length;
      const icon = count > 1
        ? L.divIcon({className: 'hotbadge', html: String(count), iconSize: [22, 22]})
        : L.divIcon({className: 'hot', iconSize: [12, 12]});
      const list = stories.slice(0, 5).map(s =>
        '<li>' + (s.link ? '<a href="' + esc(s.link) + '" target="_blank" rel="noopener">' + esc(s.title) + '</a>' : esc(s.title)) +
        '<br><span class="popmeta">' + esc(s.source || '') + (s.published ? ' &middot; ' + esc(s.published) : '') + '</span></li>').join('');
      const m = L.marker([h.lat, h.lon], {icon: icon})
        .bindPopup('<b>' + esc(h.label) + '</b> <span class="popmeta">' + count + (count === 1 ? ' story' : ' stories') + '</span>' +
          '<ul>' + list + '</ul>' + (count > 5 ? '<span class="popmeta">+ ' + (count - 5) + ' more in the feed below</span>' : ''), {maxWidth: 340});
      m.addTo(map); layers.push(m);
    });
    document.getElementById('stories').innerHTML = (d.items || []).map(s =>
      '<article class="story"><h3>' + (s.link ? '<a href="' + esc(s.link) + '" target="_blank" rel="noopener">' + esc(s.title) + '</a>' : esc(s.title)) + '</h3>' +
      '<p class="meta">' + esc(s.source || '') + (s.published ? ' &middot; ' + esc(s.published) : '') + '</p>' +
      '<p class="impact"><b>Potential impact:</b> ' + esc(s.impact || '') + '</p></article>').join('')
      || '<p class="dim">No stories right now.</p>';
  } catch (e) {
    document.getElementById('upd').textContent = 'Could not reach the server — retrying.';
  }
}
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
load();
setInterval(load, 120000);

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
