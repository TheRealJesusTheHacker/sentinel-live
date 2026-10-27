async function load() {
  const t = document.getElementById('ds').value;
  const r = await fetch('/api/admin/submissions?type=' + t + '&limit=200');
  if (!r.ok) { document.getElementById('rows').innerHTML = '<p class="warn">Access denied.</p>'; return; }
  const d = await r.json();
  document.getElementById('total').textContent = d.total + ' records';
  document.getElementById('csv').href = '/api/admin/export?type=' + t + '&format=csv';
  if (!d.rows.length) { document.getElementById('rows').innerHTML = '<p class="dim">No records yet.</p>'; return; }
  const cols = Object.keys(d.rows[0]);
  let h = '<table><tr>' + cols.map(c => '<th>' + esc(c) + '</th>').join('') + '</tr>';
  d.rows.forEach(row => { h += '<tr>' + cols.map(c => '<td>' + esc(row[c]) + '</td>').join('') + '</tr>'; });
  document.getElementById('rows').innerHTML = h + '</table>';
}
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
document.getElementById('load').onclick = load;
