// Phase Two A (2026-10-25): the operations landing now SAYS what is
// live instead of only linking to it — top threat sources and the
// latest geopolitical headlines, from the same public read APIs the
// tracker pages use. The flight card spends no provider quota: it is
// the tracker search itself, carried to the full page on submit.
function pvEsc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function pvFmt(n) { return Number(n || 0).toLocaleString('en-US'); }
async function pvLoad() {
  try {
    const d = await (await fetch('/api/threat-data')).json();
    document.getElementById('pv-threat-stat').textContent =
      pvFmt(d.attacks_today) + ' attacks today · ' + pvFmt(d.sources_today) + ' sources';
    document.getElementById('pv-threat-list').innerHTML =
      (d.countries || []).slice(0, 3).map(c =>
        '<li><span>' + pvEsc(c.code) + '</span><b>' + pvFmt(c.count) + ' attacks</b></li>').join('')
      || '<li class="dim">No data yet — retrying automatically.</li>';
  } catch (e) {
    document.getElementById('pv-threat-stat').textContent = 'Live data unreachable — retrying.';
  }
  try {
    const g = await (await fetch('/api/geo-data')).json();
    document.getElementById('pv-geo-stat').textContent =
      (g.items || []).length + ' stories · ' + (g.hotspots || []).length + ' hotspots mapped';
    document.getElementById('pv-geo-list').innerHTML =
      (g.items || []).slice(0, 3).map(s =>
        '<li>' + (s.link ? '<a href="' + pvEsc(s.link) + '" target="_blank" rel="noopener">' : '') +
        pvEsc(s.title) + (s.link ? '</a>' : '') + '</li>').join('')
      || '<li class="dim">No stories right now.</li>';
  } catch (e) {
    document.getElementById('pv-geo-stat').textContent = 'Live data unreachable — retrying.';
  }
}
pvLoad();
setInterval(pvLoad, 60000);
