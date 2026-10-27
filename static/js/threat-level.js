/* Sentinel Threat Level 2026-10-27: fills the site-wide badge
   band (#tl-band, server/static-rendered with a pending state)
   and, on pages that carry it, the methodology panel
   (#tl-panel-level / #tl-inputs / #tl-history) from
   /api/threat-level. No level is ever invented here: a pending
   or unreachable API leaves the honest "being computed" copy. */
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
  function fmt(n) { return Number(n || 0).toLocaleString('en-US'); }
  function relTime(iso) {
    if (!iso) return '';
    var t = Date.parse(iso);
    if (isNaN(t)) return String(iso);
    var mins = Math.max(0, Math.round((Date.now() - t) / 60000));
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + ' min ago';
    var hrs = Math.floor(mins / 60);
    if (hrs < 24) return hrs + (hrs === 1 ? ' hour ago' : ' hours ago');
    var days = Math.floor(hrs / 24);
    return days + (days === 1 ? ' day ago' : ' days ago');
  }
  function chip(level, name) {
    return '<strong class="tl-lvl tl-lvl-' + level + '">' + level + ' &mdash; ' + esc(name || '') + '</strong>';
  }
  fetch('/api/threat-level').then(function (r) { return r.json(); }).then(function (d) {
    var band = document.getElementById('tl-band');
    var panelLevel = document.getElementById('tl-panel-level');
    var inputsEl = document.getElementById('tl-inputs');
    var historyEl = document.getElementById('tl-history');
    if (!d || !d.level) {
      if (band) band.innerHTML = 'Sentinel Threat Level &mdash; being computed &middot; <a href="/operations#threat-level">How this is set</a>';
      return;
    }
    if (band) {
      band.innerHTML = 'Sentinel Threat Level ' + chip(d.level, d.name) +
        ' &middot; updated ' + esc(relTime(d.computed_at)) +
        ' &middot; <a href="/operations#threat-level">How this is set</a>';
    }
    if (panelLevel) {
      panelLevel.innerHTML = 'Level ' + chip(d.level, d.name) +
        ' &middot; score ' + (d.score != null ? d.score : '') + ' of 7' +
        ' &middot; updated ' + esc(relTime(d.computed_at));
    }
    if (inputsEl && d.inputs) {
      var p = d.parts || {};
      inputsEl.innerHTML = '<ul class="tl-input-list">' +
        '<li>Known exploited vulnerabilities added in the last 7 days (CISA KEV): <b>' + fmt(d.inputs.kev_added_7d) + '</b> &middot; ' + (p.kev_points || 0) + ' points</li>' +
        '<li>Sentinel News Threat Watch items in the last 7 days: <b>' + fmt(d.inputs.news_threat_watch_7d) + '</b></li>' +
        '<li>Sentinel News Patch Alert items in the last 7 days: <b>' + fmt(d.inputs.news_patch_alert_7d) + '</b> &middot; news total ' + (p.news_points || 0) + ' points</li>' +
        '<li>Attacking sources today (DShield): <b>' + fmt(d.inputs.dshield_sources_today) + '</b> &middot; ' + (p.feed_points || 0) + ' points</li>' +
        '</ul>';
    }
    if (historyEl) {
      var hist = (d.history || []).slice(-14);
      historyEl.innerHTML = hist.map(function (h) {
        return '<li>' + esc(h.date) + ' <span class="tl-lvl tl-lvl-' + h.level + '">' + h.level + '</span></li>';
      }).join('') || '<li class="dim">No history yet.</li>';
    }
  }).catch(function () { /* server-rendered copy stays as-is */ });
})();
