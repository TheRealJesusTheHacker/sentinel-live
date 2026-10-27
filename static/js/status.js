const t0 = Number(document.getElementById('uptime').dataset.t0 || 0);
const el = document.getElementById('uptime');
const start = Date.now();
setInterval(() => {
  const s = t0 + Math.floor((Date.now() - start) / 1000);
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60);
  el.textContent = (h ? h + 'h ' : '') + (m ? m + 'm ' : '') + (s % 60) + 's';
}, 1000);
