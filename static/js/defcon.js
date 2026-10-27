/* DEFCON badges + board 2026-10-27 (DEFCON-RESHAPE-2026-10-27):
   fills the site-wide dual badge band (#tl-band, server/static-
   rendered with a pending state), the dual DEFCON board on the
   home/operations pages (#dc-cyber-* / #dc-geo-*), and the
   dedicated pages' detail blocks when present, from
   /api/cyber-defcon and /api/geo-defcon. No level is ever
   invented here: a pending or unreachable API leaves the honest
   "being computed" copy. Chip class is tl-lvl-(6-defcon): the
   severity palette is the old rising scale, inverted on purpose. */
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
  function chip(defcon, name) {
    return '<strong class="tl-lvl tl-lvl-' + (6 - defcon) + '">' + defcon + (name ? ' &mdash; ' + esc(name) : '') + '</strong>';
  }
  function getJson(url) {
    return fetch(url).then(function (r) { return r.json(); });
  }
  var cyber = null, geo = null;
  function renderBand() {
    var band = document.getElementById('tl-band');
    if (!band) return;
    var c = cyber && cyber.defcon ?
      '<a href="/cyber-defcon">' + chip(cyber.defcon, cyber.name) + '</a>' :
      '<a href="/cyber-defcon">being computed</a>';
    var g = geo && geo.defcon ?
      '<a href="/geopolitical-defcon">' + chip(geo.defcon, '') + '</a>' :
      '<a href="/geopolitical-defcon">being computed</a>';
    var stamp = (cyber && cyber.computed_at) || (geo && geo.computed_at);
    band.innerHTML = 'Cyber DEFCON ' + c +
      ' &middot; Geopolitical DEFCON (est.) ' + g +
      (stamp ? ' &middot; updated ' + esc(relTime(stamp)) : '');
  }
  function renderCyber() {
    if (!cyber || !cyber.defcon) return;
    var boardLevel = document.getElementById('dc-cyber-level');
    if (boardLevel) {
      boardLevel.innerHTML = '<a href="/cyber-defcon">Cyber DEFCON</a> ' +
        chip(cyber.defcon, cyber.name) +
        ' &middot; updated ' + esc(relTime(cyber.computed_at));
    }
    var boardDriver = document.getElementById('dc-cyber-driver');
    if (boardDriver && cyber.parts) {
      boardDriver.textContent = 'Score ' + cyber.score + ' of 7 — KEV ' +
        (cyber.parts.kev_points || 0) + ' pts, news ' +
        (cyber.parts.news_points || 0) + ' pts, DShield ' +
        (cyber.parts.feed_points || 0) + ' pts.';
    }
    var panelLevel = document.getElementById('cyber-panel-level');
    if (panelLevel) {
      panelLevel.innerHTML = 'DEFCON ' + chip(cyber.defcon, cyber.name) +
        ' &middot; score ' + cyber.score + ' of 7' +
        ' &middot; updated ' + esc(relTime(cyber.computed_at));
    }
    var inputsEl = document.getElementById('cyber-inputs');
    if (inputsEl && cyber.inputs) {
      var p = cyber.parts || {};
      inputsEl.innerHTML = '<ul class="tl-input-list">' +
        '<li>Known exploited vulnerabilities added in the last 7 days (CISA KEV): <b>' + fmt(cyber.inputs.kev_added_7d) + '</b> &middot; ' + (p.kev_points || 0) + ' points</li>' +
        '<li>Sentinel News Threat Watch items in the last 7 days: <b>' + fmt(cyber.inputs.news_threat_watch_7d) + '</b></li>' +
        '<li>Sentinel News Patch Alert items in the last 7 days: <b>' + fmt(cyber.inputs.news_patch_alert_7d) + '</b> &middot; news total ' + (p.news_points || 0) + ' points</li>' +
        '<li>Attacking sources today (DShield): <b>' + fmt(cyber.inputs.dshield_sources_today) + '</b> &middot; ' + (p.feed_points || 0) + ' points</li>' +
        '</ul>';
    }
    var historyEl = document.getElementById('cyber-history');
    if (historyEl) {
      var hist = (cyber.history || []).slice(-14);
      historyEl.innerHTML = hist.map(function (h) {
        return '<li>' + esc(h.date) + ' <span class="tl-lvl tl-lvl-' + (6 - h.defcon) + '">' + h.defcon + '</span></li>';
      }).join('') || '<li class="dim">No history yet.</li>';
    }
  }
  function renderGeo() {
    if (!geo || !geo.defcon) return;
    var boardLevel = document.getElementById('dc-geo-level');
    if (boardLevel) {
      boardLevel.innerHTML = '<a href="/geopolitical-defcon">Geopolitical DEFCON (open-source estimate)</a> ' +
        chip(geo.defcon, geo.name) +
        ' &middot; updated ' + esc(relTime(geo.computed_at));
    }
    var boardDriver = document.getElementById('dc-geo-driver');
    if (boardDriver) {
      boardDriver.textContent = 'Pressure ' + geo.pressure +
        ' — elevated families: ' +
        ((geo.elevated && geo.elevated.length) ? geo.elevated.join(', ') : 'none') + '.';
    }
    var panelLevel = document.getElementById('geo-panel-level');
    if (panelLevel) {
      panelLevel.innerHTML = 'Estimated DEFCON ' + chip(geo.defcon, geo.name) +
        ' &middot; pressure ' + geo.pressure +
        ' &middot; updated ' + esc(relTime(geo.computed_at));
    }
    var driversEl = document.getElementById('geo-drivers');
    if (driversEl && geo.inputs && geo.families) {
      var counts = geo.inputs.counts || {};
      driversEl.innerHTML = '<ul class="tl-input-list">' +
        '<li>Family A — conflict intensity: <b>' + fmt(counts.A) + '</b> stories &middot; score ' + (geo.families.A || 0) + ' of 3</li>' +
        '<li>Family B — U.S. involvement and force posture: <b>' + fmt(counts.B) + '</b> stories &middot; score ' + (geo.families.B || 0) + ' of 3</li>' +
        '<li>Family C — nuclear rhetoric and doctrine: <b>' + fmt(counts.C) + '</b> stories &middot; score ' + (geo.families.C || 0) + ' of 3</li>' +
        '<li>Family D — Doomsday Clock: <b>' + fmt(geo.clock_seconds != null ? geo.clock_seconds : geo.inputs.clock_seconds) + ' seconds to midnight</b> (' + esc(geo.clock_source || geo.inputs.clock_source || '') + ') &middot; score ' + (geo.families.D || 0) + ' of 2</li>' +
        '<li>Family E — GDELT conflict-volume trend: <b>' + esc(geo.gdelt || geo.inputs.gdelt || '') + '</b>' + (geo.families.E != null ? ' &middot; score ' + geo.families.E + ' of 2' : '') + '</li>' +
        '<li>Elevated families right now: <b>' + esc((geo.elevated || []).join(', ') || 'none') + '</b> &middot; total pressure <b>' + geo.pressure + '</b></li>' +
        '</ul>';
    }
    var changesEl = document.getElementById('geo-changes');
    if (changesEl && geo.changes) {
      if (geo.changes.length) {
        changesEl.innerHTML = '<ul class="tl-input-list">' + geo.changes.slice().reverse().map(function (c) {
          var f = c.families || {};
          return '<li>' + esc(c.ts) + ' &middot; DEFCON ' + esc(c.from) + ' &rarr; <b>' + esc(c.to) + '</b> &middot; pressure ' + esc(c.pressure) + ' &middot; elevated: ' + esc((c.elevated || []).join(', ')) + '</li>';
        }).join('') + '</ul>';
      }
    }
    var historyEl = document.getElementById('geo-history');
    if (historyEl) {
      var hist = (geo.history || []).slice(-14);
      historyEl.innerHTML = hist.map(function (h) {
        return '<li>' + esc(h.date) + ' <span class="tl-lvl tl-lvl-' + (6 - h.defcon) + '">' + h.defcon + '</span></li>';
      }).join('') || '<li class="dim">No history yet.</li>';
    }
  }
  getJson('/api/cyber-defcon').then(function (d) {
    cyber = d; renderBand(); renderCyber();
  }).catch(function () { /* server-rendered copy stays as-is */ });
  getJson('/api/geo-defcon').then(function (d) {
    geo = d; renderBand(); renderGeo();
  }).catch(function () { /* server-rendered copy stays as-is */ });
})();
