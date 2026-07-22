// ── Protocol / sub-filter ──────────────────────────────────────────────────
function setProto(p) {
  proto = p;
  andMode = false; andVulns.clear();
  globalSearchMode = false; globalSearchQ = '';
  const gsi = document.getElementById('globalSearchIn'); if (gsi) gsi.value = '';
  if (acredMode) { acredMode = false; acredSub = 'creds'; }
  if (sub === 'vulns') { sub = 'admin'; vulnFilter = 'all'; }
  const available = PROTO_SUBS[proto] || [];
  if (!available.length) {
    sub = 'admin';
  } else if (!available.includes(sub)) {
    sub = available[0];
  }
  page = 1; syncProtoUI(); updateSubRow(); loadData();
}

function setSub(s) {
  andMode = false; andVulns.clear();
  sub = s;
  page = 1; updateSubRow(); loadData();
}

function setVulnFilter(vf) {
  if (andMode) {
    if (vf === 'all') { andVulns.clear(); vulnFilter = 'all'; }
    else {
      if (andVulns.has(vf)) andVulns.delete(vf);
      else andVulns.add(vf);
      vulnFilter = vf;
    }
  } else {
    vulnFilter = vf;
  }
  page = 1; updateSubRow(); loadData();
}

function setVulns() {
  globalSearchMode = false; globalSearchQ = '';
  const _gsiV = document.getElementById('globalSearchIn'); if (_gsiV) _gsiV.value = '';
  acredMode = false; acredSub = 'creds';
  andMode = false; andVulns.clear();
  // GUARD: virtual protos are not real NXC protocols — loadData() checks proto before sub==='vulns',
  // so proto must be reset to 'ALL' here to reach loadVulns().
  if (proto === 'CUSTOM' || proto === 'HIDDEN' || proto === 'HIDDEN_HOSTS') proto = 'ALL';
  if (sub === 'vulns') {
    sub = 'admin'; vulnFilter = 'all';
  } else {
    sub = 'vulns'; vulnFilter = 'all';
  }
  page = 1; syncProtoUI(); updateSubRow(); loadData();
}

function setAcred() {
  globalSearchMode = false; globalSearchQ = '';
  const _gsiA = document.getElementById('globalSearchIn'); if (_gsiA) _gsiA.value = '';
  if (acredMode) {
    acredMode = false; acredSub = 'creds';
  } else {
    acredMode = true; acredSub = 'creds';
    andMode = false; andVulns.clear();
    if (sub === 'vulns') { sub = 'admin'; vulnFilter = 'all'; }
    // GUARD: loadData() checks HIDDEN/HIDDEN_HOSTS before acredMode, so proto must be reset
    // to reach loadAcredCreds(). CUSTOM is handled in loadAcredCreds() itself via _VIRTUAL_PROTOS.
    if (proto === 'HIDDEN' || proto === 'HIDDEN_HOSTS') proto = 'ALL';
  }
  page = 1; syncProtoUI(); updateSubRow(); loadData();
}

function setAcredSub(s) {
  acredSub = s;
  page = 1; updateSubRow(); loadData();
}

function setPageSize(n) {
  pageSize = n;
  document.querySelectorAll('.size-pill').forEach(b => b.classList.remove('active'));
  const ids = {100:'sz100', 500:'sz500', 1000:'sz1000', 0:'szAll'};
  const btn = document.getElementById(ids[n]);
  if (btn) btn.classList.add('active');
  page = 1; loadData();
}

function toggleHkBruted() {
  hkBrutedMode = !hkBrutedMode;
  document.getElementById('hkBtn').classList.toggle('on', hkBrutedMode);
  _keepScroll = true;
  loadData();
}

function toggleUniq() {
  uniqMode = !uniqMode;
  document.getElementById('uniqBtn').classList.toggle('on', uniqMode);
  page = 1; loadData();
}

function toggleAnd() {
  if (sub !== 'vulns') return;  // AND only for VULNS
  andMode = !andMode;
  if (!andMode) {
    andVulns.clear();
    vulnFilter = 'all';
  } else if (vulnFilter !== 'all') {
    andVulns.add(vulnFilter);
  }
  page = 1; updateSubRow(); loadData();
}

function resetFilters() {
  proto = 'ALL'; sub = 'all'; vulnFilter = 'all';
  srch = ''; document.getElementById('searchIn').value = '';
  globalSearchQ = ''; globalSearchMode = false;
  const gsi = document.getElementById('globalSearchIn');
  if (gsi) gsi.value = '';
  andMode = false; andVulns.clear();
  acredMode = false; acredSub = 'creds';
  manageMod = false; _preManageProto = 'ALL';
  sortBy = 'username'; sortDir = 'asc';
  page = 1; syncProtoUI(); updateSubRow(); if (ws) loadData();
}

function deduplicateRows(rows) {
  // TZ key: domain + login + password + host ip (per-host).
  // Auth-relation rows keep one row per credential x host; same-host dups from
  // other protocols/operators collapse. Rows without ip dedup by the triple.
  // Priority: plaintext > hash; admin > loggedin; more fields (SMB preferred).
  // GUARD: Server mirror — data_service.dedup_results(). Keep ranking logic in sync.
  const protoRank = p => p === 'SMB' ? 2 : p === 'LDAP' ? 1 : 0;
  const rank = r => (r.credtype === 'plaintext' ? 4 : 0)
    + (r.relation_type === 'admin' ? 2 : 0)
    + (r.ip ? 1 : 0)
    + protoRank(r.proto || '');
  const byKey  = new Map();
  const acredK = new Set();
  for (const r of rows) {
    const k = `${(r.cred_domain||r.domain||'').toLowerCase()}|${(r.username||'').toLowerCase()}|${(r.password||'')}|${(r.ip||'')}`;
    if (r.admin_cred == 1) acredK.add(k);
    const ex = byKey.get(k);
    if (!ex || rank(r) > rank(ex)) byKey.set(k, r);
  }
  return Array.from(byKey.entries()).map(([k, r]) =>
    acredK.has(k) ? Object.assign({}, r, {admin_cred: 1}) : r
  );
}

// ── Sorting ────────────────────────────────────────────────────────────────
function _sortVal(r, col) {
  switch(col) {
    case 'proto':        return (r.proto       || '').toLowerCase();
    case 'ip': {
      const ip = r.ip || r.host_ip || r.pillaged_from_ip || '';
      const parts = ip.split('.');
      if (parts.length === 4 && parts.every(p => /^\d+$/.test(p)))
        return parts.map(p => parseInt(p).toString().padStart(3,'0')).join('.');
      return ip.toLowerCase();
    }
    case 'hostname':     return (r.hostname     || '').toLowerCase();
    case 'domain':       return (r.cred_domain  || r.domain || r.host_domain || '').toLowerCase();
    case 'os':           return (r.os           || '').toLowerCase();
    case 'username':     return (r.username     || '').toLowerCase();
    case 'password':     return (_dispPass(r)   || '').toLowerCase();
    case 'type':         return (_dispCredtype(r)|| '').toLowerCase();
    case 'rel':          return (r.relation_type|| '').toLowerCase();
    case 'op':           return (r.operator     || '').toLowerCase();
    case 'dpapi_type':   return (r.dpapi_type   || '').toLowerCase();
    case 'windows_user': return (r.windows_user || '').toLowerCase();
    case 'url':          return (r.url          || '').toLowerCase();
    case 'port':         return r.port != null ? String(r.port).padStart(6,'0') : '';
    case 'source':       return (r.source       || '').toLowerCase();
    case 'share':        return (r.name         || '').toLowerCase();
    case 'read':         return r.read  ? '1' : '0';
    case 'write':        return r.write ? '1' : '0';
    default:
      // VULNS matrix columns: tri-state (1 YES / 0 no / null|undefined —). Rank so that
      // ascending is — < no < YES (mirrors read/write, where the "present" state sorts last).
      if (_VULN_SLUGS.has(col)) { const v = r[col]; return v === 1 ? 2 : v === 0 ? 1 : 0; }
      return '';
  }
}

function _sortRows(rows) {
  if (!sortBy || !rows.length) return rows;
  return [...rows].sort((a, b) => {
    const av = _sortVal(a, sortBy), bv = _sortVal(b, sortBy);
    const cmp = av < bv ? -1 : av > bv ? 1 : 0;
    return sortDir === 'asc' ? cmp : -cmp;
  });
}

function setSortBy(col) {
  if (sortBy === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
  else { sortBy = col; sortDir = 'asc'; }
  page = 1; loadData();
}

// GUARD: global display/output helpers — must be checked in EVERY render* and export function.
// Checklist for any new render* function:
//   _thSort       → all sortable column headers
//   _ipTd         → every IP cell (copy + manage strike/restore)
//   _skullTd      → every row with username+domain (mark as domain admin)
//   _copyTd       → every credential row (nxc/dup copy + manage hide/restore button)
//   _hostActionTd → every host row (manage hide/restore button)
//   _rowClass     → every credential row (admin/acred highlight)
//   _sortPaginate → server-fetched loaders: fetch ALL rows (limit _ALL_LIMIT) then
//                   _sortPaginate(d.rows) so sorting spans every page, not just the current one
//                   (_paginate for pre-arranged lists like ACRED ghosts; _sortRows = sort only)
//   _dispPass()   → use instead of r.password directly (HK-bruted display)
//   copyable      → every text cell with a value worth copying
// Checklist for any new export path (view=X in export.py / _qp() in shell.js):
//   - Export view must mirror what the user SEES in the browser (same data, same filters)
//   - hk flag → apply_brutforced() in export handler
//   - If a new view=X is added in export.py, add corresponding case in _qp() in shell.js
// If a new global feature is added here, audit ALL render* and export functions, notify the user.
function _thSort(label, key) {
  if (!key) return `<th>${label}</th>`;
  let cls = 'sortable';
  let ind = '';
  if (sortBy === key) { cls += sortDir === 'asc' ? ' sort-asc' : ' sort-desc'; ind = sortDir === 'asc' ? ' ↑' : ' ↓'; }
  if (manageMod && key === 'ip') {
    cls += (proto === 'HIDDEN' || proto === 'HIDDEN_HOSTS') ? ' th-ip-restore' : ' th-ip-strike';
  }
  return `<th class="${cls}" onclick="setSortBy('${key}')">${label}${ind}</th>`;
}

function toggleGuest() {
  hideGuest = !hideGuest;
  document.getElementById('guestBtn').classList.toggle('on', hideGuest);
  page = 1; loadData();
}

function onSearch() {
  clearTimeout(debTimer);
  debTimer = setTimeout(() => {
    srch = document.getElementById('searchIn').value.trim();
    page = 1; loadData();
  }, 280);
}

function syncProtoUI() {
  document.querySelectorAll('#protoRow .pill[data-proto]').forEach(b =>
    b.classList.toggle('active', b.dataset.proto === proto)
  );
  document.getElementById('vulnsBtn').classList.toggle('active', sub === 'vulns');
  document.getElementById('acredBtn').classList.toggle('active', acredMode);
  const mb = document.getElementById('manageBtn');
  if (mb) mb.classList.toggle('active', manageMod);
  const brand = document.querySelector('.brand');
  if (brand) brand.classList.toggle('manage-active', manageMod);
  const mr = document.getElementById('manageRow');
  if (mr) {
    mr.classList.toggle('visible', manageMod);
    const bc = document.getElementById('hiddenCredsBtn');
    const bh = document.getElementById('hiddenHostsBtn');
    if (bc) bc.classList.toggle('active', proto === 'HIDDEN');
    if (bh) bh.classList.toggle('active', proto === 'HIDDEN_HOSTS');
  }
}

function updateSubRow() {
  renderSidebar();
  const container = document.getElementById('subPills');
  document.getElementById('vulnsBtn').classList.toggle('active', sub === 'vulns');
  document.getElementById('acredBtn').classList.toggle('active', acredMode);
  document.getElementById('protoRow').classList.toggle('gsearch-active', globalSearchMode);

  // HIDDEN / HIDDEN_HOSTS: no regular sub-pills
  if (proto === 'HIDDEN' || proto === 'HIDDEN_HOSTS') {
    container.innerHTML = '';
    return;
  }

  // ACRED mode: CREDS + LOCAL ADMIN sub-pills
  if (acredMode) {
    document.getElementById('uniqBtn').style.display = 'none';
    const isCreds = acredSub === 'creds';
    container.innerHTML =
      `<button class="pill s-acred${isCreds ? ' active' : ''}" onclick="setAcredSub('creds')">CREDS</button>` +
      `<button class="pill s-acred${!isCreds ? ' active' : ''}" onclick="setAcredSub('local')">LOCAL ADMIN</button>`;
    return;
  }

  // UNIQ only makes sense for auth_relations views
  const noUniqSubs = ['vulns','dpapi','sam','lsa','samlsa','creds','hosts','shares','dirs','conf_checks'];
  const showUniq = !noUniqSubs.includes(sub);
  document.getElementById('uniqBtn').style.display = showUniq ? '' : 'none';

  if (sub === 'vulns') {
    const andActive = andMode;
    const andBtn = `<button class="and-btn-inline${andActive?' active':''}" onclick="toggleAnd()" title="AND: combine multiple vuln filters">AND</button>`;
    const pill = vf => {
      const isActive = andMode ? andVulns.has(vf.id) : (vulnFilter === vf.id);
      return `<button class="pill vf vf-${vf.id}${isActive?' active':''}" onclick="setVulnFilter('${vf.id}')">${vf.label}</button>`;
    };
    // ALL + AND on the first row, then one labelled row per group (REMOTE / COERCE / ADMIN-ONLY).
    // Wrapped in a column container so each group starts on its own line (#subPills is a flex row).
    const allPill = VULN_FILTERS.find(vf => vf.id === 'all');
    let html = `<div class="vf-row">${pill(allPill)}${andBtn}</div>`;
    for (const g of VULN_GROUPS) {
      const groupPills = VULN_FILTERS.filter(vf => vf.group === g.id).map(pill).join('');
      html += `<div class="vf-row"><span class="vf-group-label">${g.label}</span>${groupPills}</div>`;
    }
    container.innerHTML = `<div class="vf-groups">${html}</div>`;
    return;
  }

  const available = PROTO_SUBS[proto] || [];
  if (!available.length) {
    container.innerHTML = '<span style="color:var(--fg2);font-size:11px;font-style:italic">hosts only — no credentials</span>';
    return;
  }
  container.innerHTML = available.map(s => {
    const isActive = sub === s;
    return `<button class="pill s-${s}${isActive?' active':''}" data-sub="${s}" onclick="setSub('${s}')">${SUB_LABELS[s]}</button>`;
  }).join('');
}

