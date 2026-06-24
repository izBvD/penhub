function toggleManageMod() {
  if (manageMod) {
    manageMod = false;
    if (proto === 'HIDDEN' || proto === 'HIDDEN_HOSTS') {
      proto = _preManageProto; sub = 'all';
    }
    page = 1; syncProtoUI(); updateSubRow(); loadData();
  } else {
    manageMod = true;
    if (proto !== 'HIDDEN' && proto !== 'HIDDEN_HOSTS') _preManageProto = proto;
    syncProtoUI(); updateSubRow(); loadData();
  }
}

async function hideCredential(btn) {
  const wsId     = parseInt(btn.dataset.ws);
  const username = btn.dataset.user;
  const domain   = btn.dataset.domain;
  const password = btn.dataset.pass;
  try {
    const r = await apiFetch('/api/credentials/set_hidden', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id:wsId, domain, username, password, hidden:1}),
    });
    if (r.ok) {
      _flashManage(btn, 'hide');
      const row = btn.closest('tr');
      if (row) {
        _flashRow(row, 'hide');
        setTimeout(() => {
          row.style.transition = 'opacity .25s';
          row.style.opacity = '0';
          setTimeout(() => row.remove(), 260);
        }, 160);
      }
    }
  } catch(e) {}
}

async function restoreCredential(btn) {
  const wsId     = parseInt(btn.dataset.ws);
  const username = btn.dataset.user;
  const domain   = btn.dataset.domain;
  const password = btn.dataset.pass;
  try {
    const r = await apiFetch('/api/credentials/set_hidden', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id:wsId, domain, username, password, hidden:0}),
    });
    if (r.ok) {
      _flashManage(btn, 'restore');
      const row = btn.closest('tr');
      if (row) {
        _flashRow(row, 'restore');
        setTimeout(() => {
          row.style.transition = 'opacity .25s';
          row.style.opacity = '0';
          setTimeout(() => row.remove(), 260);
        }, 160);
      }
    }
  } catch(e) {}
}

async function hideDpapi(btn) {
  const wsId   = parseInt(btn.dataset.ws);
  const dpapiId = parseInt(btn.dataset.id);
  try {
    const r = await apiFetch('/api/dpapi/set_hidden', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id:wsId, dpapi_id:dpapiId, hidden:1}),
    });
    if (r.ok) {
      _flashManage(btn, 'hide');
      const row = btn.closest('tr');
      if (row) { _flashRow(row, 'hide'); setTimeout(() => { row.style.transition='opacity .25s'; row.style.opacity='0'; setTimeout(()=>row.remove(),260); }, 160); }
    }
  } catch(e) {}
}

async function restoreDpapi(btn) {
  const wsId   = parseInt(btn.dataset.ws);
  const dpapiId = parseInt(btn.dataset.id);
  try {
    const r = await apiFetch('/api/dpapi/set_hidden', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id:wsId, dpapi_id:dpapiId, hidden:0}),
    });
    if (r.ok) {
      _flashManage(btn, 'restore');
      const row = btn.closest('tr');
      if (row) { _flashRow(row, 'restore'); setTimeout(() => { row.style.transition='opacity .25s'; row.style.opacity='0'; setTimeout(()=>row.remove(),260); }, 160); }
    }
  } catch(e) {}
}

async function hideHost(btn) {
  const wsId   = parseInt(btn.dataset.ws);
  const hostId = parseInt(btn.dataset.id);
  try {
    const r = await apiFetch('/api/hosts/set_hidden', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id:wsId, host_id:hostId, hidden:1}),
    });
    if (r.ok) {
      _flashManage(btn, 'hide');
      const row = btn.closest('tr');
      if (row) { _flashRow(row, 'hide'); setTimeout(() => { row.style.transition='opacity .25s'; row.style.opacity='0'; setTimeout(()=>row.remove(),260); }, 160); }
    }
  } catch(e) {}
}

async function restoreHost(btn) {
  const wsId = parseInt(btn.dataset.ws);
  const ip   = btn.dataset.ip;
  if (!ip) return;
  try {
    const r = await apiFetch('/api/hosts/restore_strike', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id: wsId, host_ip: ip}),
    });
    if (r.ok) {
      _flashManage(btn, 'restore');
      const row = btn.closest('tr');
      if (row) { _flashRow(row, 'restore'); setTimeout(() => { row.style.transition='opacity .25s'; row.style.opacity='0'; setTimeout(()=>row.remove(),260); }, 160); }
    }
  } catch(e) {}
}

async function strikeIp(td) {
  const ip = td.dataset.ip;
  if (!ip || !ws) return;
  try {
    const r = await apiFetch('/api/hosts/strike', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id: ws.id, host_ip: ip}),
    });
    if (r.ok) {
      _flashRow(td.closest('tr'), 'hide');
      setTimeout(() => loadData(), 320);
    }
  } catch(e) {}
}

async function restoreIp(td) {
  const ip = td.dataset.ip;
  if (!ip || !ws) return;
  try {
    const r = await apiFetch('/api/hosts/restore_strike', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({workspace_id: ws.id, host_ip: ip}),
    });
    if (r.ok) {
      _flashRow(td.closest('tr'), 'restore');
      setTimeout(() => loadData(), 320);
    }
  } catch(e) {}
}

async function loadDpapi() {
  const lim = pageSize || 999999;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim});
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/dpapi?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total; renderDpapi(_sortRows(d.rows)); renderPager();
}

async function loadVulns() {
  const lim = pageSize || 200;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim});
  if (srch) p.set('search', srch);
  if (andMode && andVulns.size > 0) {
    p.set('vulns', Array.from(andVulns).join(','));
  } else if (vulnFilter && vulnFilter !== 'all') {
    p.set('vuln', vulnFilter);
  }
  if (manageMod) p.set('show_all', '1');
  const r = await apiFetch('/api/vulns?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total; renderVulns(d.rows); renderPager();
}

async function loadStats() {
  if (!ws) return;
  const r = await apiFetch('/api/stats?workspace_id=' + ws.id);
  if (r.status === 404) { _handleWorkspaceGone(); return; }
  if (!r.ok) return;
  const s = await r.json();
  document.getElementById('sHosts').textContent   = s.hosts;
  document.getElementById('sCreds').textContent   = s.creds;
  document.getElementById('sAdmin').textContent   = s.admin;
}

function _handleWorkspaceGone() {
  stopLive();
  ws = null;  // prevent re-entry; stops any further ws-scoped calls
  document.getElementById('tableWrap').innerHTML =
    '<div class="empty" style="color:var(--a4)"><div class="icon">&#9888;</div>' +
    'This project was deleted or moved. Returning to projects…</div>';
  setTimeout(showProjectsPage, 2500);
}

// ── Render ─────────────────────────────────────────────────────────────────
const esc     = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const escAttr = s => String(s ?? '').replace(/&/g,'&amp;').replace(/"/g,'&quot;');
const pClass  = p => 'proto proto-' + (p||'').toLowerCase();

// ── Admin credential + copy helpers ───────────────────────────────────────
async function toggleAdminCred(btn) {
  const wsId     = parseInt(btn.dataset.ws);
  const username = btn.dataset.user;
  const domain   = btn.dataset.domain;
  const password = btn.dataset.pass;
  const newVal   = btn.classList.contains('marked') ? 0 : 1;
  try {
    const r = await apiFetch('/api/credentials/set_admin_cred', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({workspace_id: wsId, domain, username, password, admin_cred: newVal})
    });
    if (r.ok) {
      const isMarked = newVal === 1;
      document.querySelectorAll('.skull-btn').forEach(b => {
        if (b.dataset.user === username && b.dataset.domain === domain && parseInt(b.dataset.ws) === wsId) {
          b.classList.toggle('marked', isMarked);
          const row = b.closest('tr');
          if (row) {
            row.classList.toggle('row-acred', isMarked);
            if (!isMarked && acredMode && row) row.remove();
            // Mutual exclusion: mute local-admin-btn on same row when domain admin is set
            const lapBtn = row.querySelector('.local-admin-btn');
            if (lapBtn) lapBtn.classList.toggle('lap-muted', isMarked);
          }
        }
      });
    }
  } catch(e) {}
}

async function toggleLocalAdminCred(btn) {
  const wsId    = parseInt(btn.dataset.ws);
  const username = btn.dataset.user;
  const password = btn.dataset.pass;
  const newVal  = btn.classList.contains('marked') ? 0 : 1;
  try {
    const r = await apiFetch('/api/credentials/set_local_admin_cred', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({workspace_id: wsId, username, password, local_admin_cred: newVal})
    });
    if (r.ok) {
      const isMarked = newVal === 1;
      document.querySelectorAll('.local-admin-btn').forEach(b => {
        if (b.dataset.user === username && b.dataset.pass === password && parseInt(b.dataset.ws) === wsId) {
          b.classList.toggle('marked', isMarked);
          const row = b.closest('tr');
          if (row) {
            if (!isMarked && acredMode && acredSub === 'local') row.remove();
            // Mutual exclusion: mute skull-btn on same row when local admin is set
            const skullBtn = row.querySelector('.skull-btn');
            if (skullBtn) skullBtn.classList.toggle('skull-muted', isMarked);
          }
        }
      });
    }
  } catch(e) {}
}

