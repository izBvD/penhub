// ── Notifications: two header bells (pwn3d + domain admin) ──────────────────
// Server journal is append-only; "unread" is computed here from localStorage
// (single shared access key → per-browser seen-state). Polls independently of LIVE.
const Notif = (() => {
  const POLL_MS = 15000;
  const TYPES = {
    pwn3d:        { seenKey: 'notif_seen_pwn3d',        label: 'PWN3D' },
    domain_admin: { seenKey: 'notif_seen_domain_admin', label: 'DOMAIN ADMIN' },
  };

  let _ws = null, _timer = null, _rows = [], _openType = null;

  const _seen    = t => parseInt(localStorage.getItem(TYPES[t].seenKey) || '0', 10) || 0;
  const _setSeen = (t, id) => localStorage.setItem(TYPES[t].seenKey, String(id));
  const _ofType  = t => _rows.filter(r => r.type === t);
  const _unread  = t => { const s = _seen(t); return _ofType(t).filter(r => r.id > s).length; };
  const _maxId   = t => _ofType(t).reduce((m, r) => Math.max(m, r.id), 0);

  function _ago(iso) {
    const then = Date.parse((iso || '').replace(' ', 'T'));
    if (isNaN(then)) return '';
    const s = Math.max(0, (Date.now() - then) / 1000);
    if (s < 60)    return Math.floor(s) + 's';
    if (s < 3600)  return Math.floor(s / 60) + 'm';
    if (s < 86400) return Math.floor(s / 3600) + 'h';
    return Math.floor(s / 86400) + 'd';
  }

  async function _poll() {
    if (!_ws) return;
    try {
      const r = await apiFetch(`/api/notifications?workspace_id=${_ws.id}`);
      if (!r.ok) return;
      _rows = (await r.json()).rows || [];
      _render();
    } catch (e) { /* offline / transient — keep last state */ }
  }

  function _render() {
    for (const t of Object.keys(TYPES)) {
      const badge = document.getElementById('notifBadge_' + t);
      if (!badge) continue;
      const n = _unread(t);
      badge.textContent = n > 99 ? '99+' : n;
      badge.style.display = n > 0 ? '' : 'none';
    }
    // Mirror total unread into the browser tab title (messenger-style "(3) PenHub").
    const total = Object.keys(TYPES).reduce((s, t) => s + _unread(t), 0);
    document.title = total ? `(${total}) PenHub` : 'PenHub';
    if (_openType) _renderDropdown(_openType);
  }

  function _renderDropdown(t) {
    const d = document.getElementById('notifDrop');
    if (!d) return;
    const rows = _ofType(t).slice(0, 50);
    let h = `<div class="notif-drop-hd">${TYPES[t].label}</div>`;
    h += rows.length
      ? rows.map(r =>
          `<div class="notif-item" onclick="Notif.go(${r.id})">` +
          `<span class="notif-dot ${r.type}"></span>` +
          `<span class="notif-title">${esc(r.title)}</span>` +
          `<span class="notif-time">${_ago(r.created_at)}</span></div>`
        ).join('')
      : `<div class="notif-empty">No events</div>`;
    d.innerHTML = h;
    d.style.display = '';
    const bell = document.getElementById('notifBell_' + t);
    if (bell) {
      const rect = bell.getBoundingClientRect();
      d.style.top   = (rect.bottom + 6) + 'px';
      d.style.right = Math.max(8, window.innerWidth - rect.right) + 'px';
    }
  }

  function toggle(t) {
    if (_openType === t) { _close(); return; }
    _openType = t;
    const mx = _maxId(t);
    if (mx) _setSeen(t, mx);   // opening = mark this type seen
    _renderDropdown(t);
    _render();                 // badge clears immediately
    setTimeout(() => document.addEventListener('click', _outside, true), 0);
  }
  function _close() {
    _openType = null;
    const d = document.getElementById('notifDrop');
    if (d) d.style.display = 'none';
    document.removeEventListener('click', _outside, true);
  }
  function _outside(e) {
    const wrap = document.getElementById('notifBells');
    const drop = document.getElementById('notifDrop');
    if (wrap && wrap.contains(e.target)) return;
    if (drop && drop.contains(e.target)) return;
    _close();
  }

  // Click a record → jump to the object via the existing global search.
  function go(id) {
    const r = _rows.find(x => x.id === id);
    _close();
    if (!r) return;
    const term = r.type === 'pwn3d'
      ? (r.title || '').split(' (')[0]          // hostname (drop the "(domain)" suffix)
      : (r.ref_username || r.title || '');       // domain admin username
    const gi = document.getElementById('globalSearchIn');
    if (gi && term) { gi.value = term; if (typeof onGlobalSearch === 'function') onGlobalSearch(); }
  }

  function _show(on) {
    const w = document.getElementById('notifBells');
    if (w) w.style.display = on ? 'flex' : 'none';
  }
  function start(workspace) {
    _ws = workspace;
    _show(true);
    _poll();
    if (_timer) clearInterval(_timer);
    _timer = setInterval(_poll, POLL_MS);
  }
  function stop() {
    if (_timer) { clearInterval(_timer); _timer = null; }
    _ws = null; _rows = []; _close(); _show(false);
    document.title = 'PenHub';   // leaving the project clears the tab badge
  }

  return { start, stop, toggle, go };
})();
