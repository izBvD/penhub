function empty(msg) {
  document.getElementById('tableWrap').innerHTML =
    `<div class="empty"><div class="icon">&#9676;</div>${msg}</div>`;
}
function clearTable() {
  document.getElementById('tableWrap').innerHTML =
    '<div class="empty"><div class="icon">&#9676;</div>Select a workspace</div>';
  document.getElementById('pager').style.display = 'none';
}
function clearStats() {
  ['sHosts','sCreds','sAdmin'].forEach(id =>
    document.getElementById(id).textContent = '—'
  );
}

// ── Pagination ─────────────────────────────────────────────────────────────
let _keepScroll = false;
function renderPager() {
  const tw = document.getElementById('tableWrap');
  if (tw && !_keepScroll) tw.scrollTop = 0;
  _keepScroll = false;
  const pager  = document.getElementById('pager');
  const pgPrev = document.getElementById('pgPrev');
  const pgNext = document.getElementById('pgNext');
  const pgInfo = document.getElementById('pgInfo');
  pager.style.display = 'flex';
  const lim = pageSize || total;
  if (pageSize === 0 || total <= lim) {
    pgPrev.style.visibility = 'hidden';
    pgNext.style.visibility = 'hidden';
    pgInfo.textContent = total > 0 ? `${total} records` : '';
  } else {
    pgPrev.style.visibility = '';
    pgNext.style.visibility = '';
    const pages = Math.ceil(total / lim);
    const from  = Math.min((page-1)*lim+1, total);
    const to    = Math.min(page*lim, total);
    pgInfo.textContent = `${from}–${to} of ${total}  (page ${page}/${pages})`;
    pgPrev.disabled = page <= 1;
    pgNext.disabled = page >= pages;
  }
}

function goPage(delta) {
  page = Math.max(1, page + delta);
  loadData();
}

// ── Exports ────────────────────────────────────────────────────────────────
function _qp() {
  const p = new URLSearchParams({workspace_id:ws.id, hide_guest:hideGuest});

  // Global search mode — export exactly what /api/search returns
  // GUARD: view=search maps to the search export handler in export.py.
  // When changing global_search query logic in data.py, sync export.py view=search handler too.
  if (globalSearchMode) {
    if (globalSearchQ) p.set('q', globalSearchQ);
    p.set('view', 'search');
    return p;
  }

  if (proto !== 'ALL') p.set('proto', proto);
  if (srch) p.set('search', srch);

  // GUARD: CUSTOM tab has its own export handler — must not fall through to viewMap.
  if (proto === 'CUSTOM') { p.set('view', 'custom'); return p; }

  if (acredMode) {
    if (acredSub === 'local') {
      p.set('view', 'local_admin');
    } else {
      p.delete('proto'); // domain admin creds are protocol-agnostic
      p.set('admin_cred', 'true');
      p.set('view', 'creds');
    }
  } else {
    if (sub === 'admin' || sub === 'loggedin') p.set('relation', sub);
    if (sub === 'sam') p.set('credtype', 'hash');
    if (sub === 'lsa') p.set('credtype', 'plaintext');
    if (andMode && andVulns.size > 0) p.set('vulns', Array.from(andVulns).join(','));
    else if (sub === 'vulns' && vulnFilter !== 'all') p.set('vuln', vulnFilter);
    const viewMap = {vulns:'vulns', dpapi:'dpapi', sam:'creds', lsa:'creds', samlsa:'creds', creds:'creds', all:'all', shares:'shares', hosts:'hosts', conf_checks:'conf_checks'};
    p.set('view', viewMap[sub] || 'results');
  }
  return p;
}

function exportXlsx() {
  if (!ws) return;
  const p = _qp();
  if (hkBrutedMode) p.set('hk', '1');
  window.open('/api/export/xlsx?' + p, '_blank');
}
function exportAllCred() { if (ws) window.open('/api/export/allcred?workspace_id=' + ws.id, '_blank'); }

// ── Sidebar ────────────────────────────────────────────────────────────────
function _sbIsActive(id) {
  const inNxc = Shell.isActive('nxc-collector');
  switch(id) {
    case 'loggedin': return inNxc && !acredMode && sub !== 'vulns' && sub === 'loggedin';
    case 'admin':    return inNxc && !acredMode && sub === 'admin' && sub !== 'vulns';
    case 'sam':      return inNxc && sub === 'sam';
    case 'lsa':      return inNxc && sub === 'lsa';
    case 'dpapi':    return inNxc && sub === 'dpapi';
    case 'acred':    return inNxc && acredMode;
    case 'vulns':    return inNxc && sub === 'vulns';
    case 'nxc-collector': return Shell.isActive('nxc-collector');
    case 'hashkiller':    return Shell.isActive('hashkiller');
    case 'toolbox':       return Shell.isActive('toolbox');
    default:              return false;
  }
}

// ── Domain Admin Watchlist: clear ghost (unmatched) entries ──────────────────
async function clearAdmGhosts() {
  if (!ws) return;
  if (!confirm('Remove all unmatched domain admin entries (no credentials found yet)?')) return;
  try {
    const r = await apiFetch('/api/domain_admin_list/clear_ghosts', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({workspace_id: ws.id}),
    });
    if (r.ok && acredMode) loadData();
  } catch(e) {}
}

// ── VULNS manage mode: clear all overrides for this workspace ────────────────
async function clearVulnOverrides() {
  if (!ws) return;
  if (!confirm('Reset ALL manual VULNS overrides in this workspace? Sync values will be restored.')) return;
  try {
    const r = await apiFetch(`/api/vulns/overrides?workspace_id=${ws.id}`, {method: 'DELETE'});
    if (r.ok && sub === 'vulns') loadData();
  } catch(e) {}
}

// ── VULNS manage mode: manual tri-state override (YES→NO→—→YES) ──────────────
async function _setVulnOverride(ip, slug, nextVal) {
  if (!ws) return;
  const tw = document.getElementById('tableWrap');
  const savedTop = tw ? tw.scrollTop : 0;
  await apiFetch('/api/vulns/set_override', {
    method:  'POST',
    headers: {'Content-Type': 'application/json'},
    body:    JSON.stringify({workspace_id: ws.id, ip, vuln_name: slug, is_vulnerable: nextVal}),
  });
  _keepScroll = true;
  await loadData();
  if (tw) tw.scrollTop = savedTop;
}

// ── Domain Admin Watchlist: per-row entry deletion ───────────────────────────
async function _deleteDalEntry(domain, username) {
  if (!ws) return;
  const p = new URLSearchParams({workspace_id: ws.id, domain, username});
  await apiFetch('/api/domain_admin_list/entry?' + p, {method: 'DELETE'});
  loadData();
}

// ── Manage-mod: delete all custom credentials in the workspace ───────────────
async function deleteAllCustom() {
  if (!ws) return;
  if (!confirm('Delete ALL custom credential rows in this workspace? This cannot be undone.')) return;
  try {
    const r = await apiFetch(`/api/custom_creds?workspace_id=${ws.id}`, {method: 'DELETE'});
    if (r.ok && proto === 'CUSTOM') loadData();
  } catch(e) {}
}

function sbNavigate(id) {
  switch(id) {
    case 'loggedin':
      if (!Shell.isActive('nxc-collector')) { Shell.activate('nxc-collector').then(() => setSub('loggedin')); return; }
      if (acredMode) { acredMode = false; acredSub = 'creds'; }
      if (sub === 'vulns') { sub = 'loggedin'; vulnFilter = 'all'; }
      setSub('loggedin'); break;
    case 'admin':
      if (!Shell.isActive('nxc-collector')) { Shell.activate('nxc-collector').then(() => setSub('admin')); return; }
      if (acredMode) { acredMode = false; acredSub = 'creds'; }
      if (sub === 'vulns') { sub = 'admin'; vulnFilter = 'all'; }
      setSub('admin'); break;
    case 'sam':
      if (!Shell.isActive('nxc-collector')) { Shell.activate('nxc-collector').then(() => setSub('sam')); return; }
      setSub('sam'); break;
    case 'lsa':
      if (!Shell.isActive('nxc-collector')) { Shell.activate('nxc-collector').then(() => setSub('lsa')); return; }
      setSub('lsa'); break;
    case 'dpapi':
      if (!Shell.isActive('nxc-collector')) { Shell.activate('nxc-collector').then(() => setSub('dpapi')); return; }
      setSub('dpapi'); break;
    case 'acred':
      if (!Shell.isActive('nxc-collector')) { Shell.activate('nxc-collector').then(() => setAcred()); return; }
      setAcred(); break;
    case 'vulns':
      if (!Shell.isActive('nxc-collector')) { Shell.activate('nxc-collector').then(() => setVulns()); return; }
      setVulns(); break;
    case 'nxc-collector': Shell.activate('nxc-collector'); break;
    case 'hashkiller':    Shell.activate('hashkiller'); break;
    case 'toolbox':       Shell.activate('toolbox'); break;
    default: {
      const m = ModuleRegistry._modules.find(m => m.id === id);
      if (m && m.route && m.route !== '#') window.location.href = m.route;
    }
  }
}

function toggleSidebar() {
  _sidebarCollapsed = !_sidebarCollapsed;
  const sidebar = document.getElementById('sidebar');
  if (sidebar) sidebar.classList.toggle('collapsed', _sidebarCollapsed);
  const btn = sidebar && sidebar.querySelector('.sb-collapse-btn');
  if (btn) btn.textContent = _sidebarCollapsed ? '›' : '‹';
  if (typeof SbAnim !== 'undefined') {
    if (_sidebarCollapsed) SbAnim.onCollapse(); else SbAnim.onExpand();
  }
}

function renderSidebar() {
  const nav = document.getElementById('sidebarNav');
  if (!nav) return;
  const groups = ModuleRegistry.getByGroup();
  let html = '';
  if (ws) html += `<div class="sb-ws-name" title="${escAttr(ws.name)}">${esc(ws.name)}</div>`;
  html += '<div class="sb-sections-wrap">';
  for (const [group, mods] of Object.entries(groups)) {
    html += `<div class="sb-section"><div class="sb-label">${esc(group)}</div>`;
    for (const m of mods) {
      const active = _sbIsActive(m.id);
      const clsCols = m.colorCls ? ' ' + m.colorCls : '';
      html += `<div class="sb-item${clsCols}${active ? ' active' : ''}" onclick="sbNavigate('${m.id}')" title="${escAttr(m.name)}">`;
      html += `<span class="sb-item-icon">${m.icon}</span>`;
      html += `<span class="sb-item-name">${esc(m.name)}</span>`;
      html += `</div>`;
    }
    html += '</div>';
  }
  html += '</div>';
  nav.innerHTML = html;
}
