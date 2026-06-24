// ── Data loading ───────────────────────────────────────────────────────────
async function loadData() {
  if (!ws) return;
  if (globalSearchMode) return loadGlobalSearch();
  if (proto === 'HIDDEN')       return loadHidden();
  if (proto === 'HIDDEN_HOSTS') return loadHiddenHosts();
  if (acredMode) return loadAcredCreds();
  if (proto === 'CUSTOM')   return loadCustomCreds();
  if (sub === 'all')        return loadAll();
  if (sub === 'vulns')      return loadVulns();
  if (sub === 'dpapi')      return loadDpapi();
  if (sub === 'samlsa')     return loadSamLsa();
  if (sub === 'sam' || sub === 'lsa') return loadSamLsa();
  if (sub === 'creds')      return loadProtoCreds();
  if (sub === 'hosts')      return loadProtoHosts();
  if (sub === 'shares')     return loadShares();
  if (sub === 'dirs')       return loadDirectoryListings('FTP');
  if (sub === 'conf_checks') return loadConfChecks();
  return loadResults();
}

async function loadAll() {
  // Merge auth_relations (all) + DPAPI + SAM/LSA + custom_credentials into one sortable, paginated view.
  const pr = new URLSearchParams({workspace_id:ws.id, hide_guest:hideGuest, page:1, limit:999999});
  if (srch) pr.set('search', srch);
  const pd = new URLSearchParams({workspace_id:ws.id, page:1, limit:999999});
  if (srch) pd.set('search', srch);
  const ps = new URLSearchParams({workspace_id:ws.id, hide_guest:hideGuest, page:1, limit:999999, samlsa:'true', proto:'SMB'});
  if (srch) ps.set('search', srch);
  const pcc = new URLSearchParams({workspace_id:ws.id, page:1, limit:999999});
  if (srch) pcc.set('search', srch);

  const [rr, rd, rs, rcc] = await Promise.all([
    apiFetch('/api/results?'      + pr).then(r => r.ok ? r.json() : {rows:[],total:0}),
    apiFetch('/api/dpapi?'        + pd).then(r => r.ok ? r.json() : {rows:[],total:0}),
    apiFetch('/api/credentials?'  + ps).then(r => r.ok ? r.json() : {rows:[],total:0}),
    apiFetch('/api/custom_creds?' + pcc).then(r => r.ok ? r.json() : {rows:[],total:0}),
  ]);

  // Normalise DPAPI rows to match the shared _sortVal keys
  const dpapiNorm = rd.rows.map(d => ({
    _src: 'dpapi',
    proto: d.dpapi_type || '',
    ip: d.host_ip || '',
    hostname: '',
    domain: '',
    os: '',
    username: d.username || '',
    password: d.password || '',
    credtype: 'plaintext',
    brutforced: null,
    relation_type: null,
    url: d.url || '',
    operator: d.operator || '',
    // keep originals for display
    host_ip: d.host_ip, dpapi_type: d.dpapi_type, windows_user: d.windows_user,
  }));

  // Normalise SAM/LSA rows — credentials with no auth_relation or with pillaged_from_ip
  const samLsaNorm = rs.rows.map(c => ({
    _src: 'samlsa',
    proto: c.proto || '',
    ip: c.pillaged_from_ip || '',
    hostname: c.pillaged_from_hostname || '',
    domain: c.domain || '',
    os: '',
    username: c.username || '',
    password: c.password || '',
    credtype: c.credtype || '',
    brutforced: c.brutforced || null,
    admin_cred: c.admin_cred,
    relation_type: null,
    url: '',
    operator: c.operator || '',
  }));

  // Normalise custom_credentials rows
  const customNorm = rcc.rows.map(c => ({
    _src: 'custom',
    id: c.id,
    proto: c.proto || '',
    ip: c.ip || '',
    hostname: '',
    domain: c.domain || '',
    os: '',
    username: c.username || '',  // login aliased as username by /api/custom_creds
    password: c.password || '',
    credtype: c.credtype || 'plaintext',
    brutforced: c.brutforced || null,
    relation_type: null,
    admin_cred: null,
    url: c.url || '',
  }));

  const raw = [
    ...rr.rows.map(r => Object.assign({}, r, {_src:'result', url: r.url || ''})),
    ...dpapiNorm,
    ...samLsaNorm,
    ...customNorm,
  ];
  const merged = _sortRows(uniqMode ? deduplicateRows(raw) : raw);
  total = merged.length;
  const pageRows = pageSize > 0
    ? merged.slice((page - 1) * pageSize, page * pageSize)
    : merged;
  renderAll(pageRows);
  renderPager();
}

function renderAll(rows) {
  if (!rows.length) { empty('No data for current filter'); return; }
  const hdr = [
    ['',''], ['Proto','proto'], ['IP','ip'], ['Hostname','hostname'], ['Domain','domain'],
    ['OS','os'], ['Username','username'], ['Password','password'],
    ['Type','type'], ['Rel','rel'], ['',''],
  ];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw    = _dispPass(r);
    const dispBadge = _dispBadge(r);
    const dispCtype = _dispCredtype(r);
    const domain    = r.cred_domain || r.domain || '';
    const isCustom  = r._src === 'custom';
    const isDpapi   = r._src === 'dpapi';
    const rowCls    = isCustom ? ' class="row-custom"'
                    : isDpapi  ? ' class="row-dpapi"'
                    : _rowClass(r);
    const protoCell = r.proto
      ? `<td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>`
      : '<td></td>';
    if (isCustom) {
      const delCell = manageMod
        ? `<td class="skull-col"><button class="del-custom-btn" onclick="_deleteCustomCred(${r.id})" title="Delete">✕</button></td>`
        : '<td class="skull-col"></td>';
      h += `<tr${rowCls}>
        ${delCell}
        ${protoCell}
        <td class="copyable" onclick="copyField(this)">${esc(r.ip || '')}</td>
        <td></td>
        <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
        <td></td>
        <td class="copyable" onclick="copyField(this)"><b>${esc(r.username || '')}</b></td>
        <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
        <td>${dispBadge}</td>
        <td></td>
        ${_copyTd(r, domain, dispPw, dispCtype, false)}
      </tr>`;
    } else {
      const os = r.os || '';
      h += `<tr${rowCls}>
        ${_skullTd(r, domain)}
        ${protoCell}
        ${_ipTd(r.ip)}
        <td class="copyable" onclick="copyField(this)">${esc(r.hostname || '')}</td>
        <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
        <td title="${esc(os)}">${esc(os.substring(0,28))}</td>
        <td class="copyable" onclick="copyField(this)"><b>${esc(r.username || '')}</b></td>
        <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
        <td>${dispBadge}</td>
        <td>${r.relation_type ? relBadge(r.relation_type) : ''}</td>
        ${_copyTd(r, domain, dispPw, dispCtype)}
      </tr>`;
    }
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function onGlobalSearch() {
  clearTimeout(debTimer);
  debTimer = setTimeout(() => {
    const val = (document.getElementById('globalSearchIn').value || '').trim();
    if (val.length >= 2) {
      globalSearchQ = val;
      globalSearchMode = true;
      srch = ''; document.getElementById('searchIn').value = '';
      proto = 'ALL'; sub = 'all'; acredMode = false;
      syncProtoUI(); updateSubRow();
    } else {
      globalSearchMode = false;
      globalSearchQ = '';
      if (!val) updateSubRow();
    }
    page = 1;
    if (ws) loadData();
  }, 350);
}

async function _deleteCustomCred(id) {
  if (!ws) return;
  await apiFetch(`/api/custom_creds/${id}?workspace_id=${ws.id}`, {method: 'DELETE'});
  loadData();
}

async function loadCustomCreds() {
  const lim = pageSize || 999999;
  const p = new URLSearchParams({workspace_id: ws.id, page, limit: lim});
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/custom_creds?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total;
  _renderCustomCreds(_sortRows(d.rows));
  renderPager();
}

async function loadGlobalSearch() {
  if (!globalSearchQ || globalSearchQ.length < 2) { empty('Enter at least 2 characters to search'); return; }
  const lim = pageSize === 0 ? 0 : (pageSize || 100);
  const p = new URLSearchParams({workspace_id:ws.id, q:globalSearchQ, page, limit:lim, hide_guest:hideGuest});
  const r = await apiFetch('/api/search?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total;
  renderGlobalSearch(_sortRows(d.rows));
  renderPager();
}

function renderGlobalSearch(rows) {
  if (!rows.length) { empty(`No results for "${globalSearchQ}"`); return; }
  // GUARD: custom render path — must use all global display helpers just like other render* functions.
  // When adding a new global display feature (_thSort / _ipTd / _skullTd / _copyTd / _hostActionTd /
  // _rowClass / copyable), update this function too and notify the user of the gap.
  const hdr = [
    ['',''],           // skull slot
    ['Protocol',''],   // mixed types — not sortable
    ['',''],           // type label — internal metadata
    ['IP','ip'],
    ['Login','username'],
    ['Password','password'],
    ['Matched in',''],
    ['Details',''],
    ['',''],           // act-col
  ];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw    = _dispPass(r);
    const dispCtype = _dispCredtype(r);
    const domain    = r.cred_domain || r.domain || '';
    const matched   = (r.matched_in || []).join(', ');
    const details   = [];
    if (r.hostname)      details.push(`hostname: ${r.hostname}`);
    if (r.os)            details.push(`os: ${r.os}`);
    if (r.banner)        details.push(`banner: ${r.banner}`);
    if (r.url)           details.push(`url: ${r.url}`);
    if (r.relation_type) details.push(`rel: ${r.relation_type}`);
    if (r.credtype)      details.push(`type: ${r.credtype}`);
    const hasCred  = r._type === 'auth' || r._type === 'cred';
    const isCustom = r._type === 'custom';
    const isHost   = r._type === 'host';
    if (r.source) details.push(`source: ${r.source}`);
    h += `<tr${hasCred ? _rowClass(r) : (isCustom ? ' class="row-custom"' : '')}>
      ${hasCred ? _skullTd(r, domain) : '<td class="skull-col"></td>'}
      <td><span class="${pClass(r.proto)}">${esc(r.proto||'—')}</span></td>
      <td style="color:var(--fg2);font-size:10px">${esc(r._type||'')}</td>
      ${isCustom ? `<td class="copyable" onclick="copyField(this)">${esc(r.ip||'')}</td>` : _ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username||'')}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td style="color:var(--a3);font-size:10px">${esc(matched)}</td>
      <td style="color:var(--fg2);font-size:10px" title="${escAttr(details.join(' · '))}">${esc(details.slice(0,3).join(' · '))}</td>
      ${(hasCred || isCustom) ? _copyTd(r, domain, dispPw, dispCtype, !isCustom) : isHost ? _hostActionTd(r) : '<td class="act-col"></td>'}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

async function loadResults() {
  const p = new URLSearchParams({workspace_id:ws.id, hide_guest:hideGuest});
  if (proto !== 'ALL') p.set('proto', proto);
  if (sub === 'admin' || sub === 'loggedin') {
    p.set('relation', sub);
  }
  if (srch) p.set('search', srch);

  if (uniqMode) {
    // Server-side dedup: all matching rows are deduplicated, then paginated.
    p.set('dedup', 'true');
    p.set('page', page);
    p.set('limit', pageSize || 100);
    const r = await apiFetch('/api/results?' + p);
    if (!r.ok) return;
    const d = await r.json();
    total = d.total;
    renderResults(_sortRows(d.rows)); renderPager();
  } else {
    p.set('page', page);
    p.set('limit', pageSize || 999999);
    const r = await apiFetch('/api/results?' + p);
    if (!r.ok) return;
    const d = await r.json();
    total = d.total;
    renderResults(_sortRows(d.rows)); renderPager();
  }
}

async function loadSamLsa() {
  const lim = pageSize || 999999;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim, hide_guest:hideGuest});
  p.set('proto', proto !== 'ALL' ? proto : 'SMB');
  // pillaged_from_ip IS NOT NULL  OR  not linked to any auth_relation
  p.set('samlsa', 'true');
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/credentials?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total; renderCreds(_sortRows(d.rows)); renderPager();
}

async function loadProtoCreds() {
  const lim = pageSize || 999999;
  // VNC/WMI need host IP — fetch from auth_relations
  if (proto === 'VNC' || proto === 'WMI') {
    const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim, hide_guest:hideGuest, proto});
    if (srch) p.set('search', srch);
    const r = await apiFetch('/api/results?' + p);
    if (!r.ok) return;
    const d = await r.json();
    total = d.total; renderCreds(_sortRows(d.rows)); renderPager();
    return;
  }
  // LDAP CREDS uses credentials table (no host IP needed)
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim, hide_guest:hideGuest});
  if (proto !== 'ALL') p.set('proto', proto);
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/credentials?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total; renderCreds(_sortRows(d.rows)); renderPager();
}

async function loadProtoHosts() {
  // For protocols with "hosts" sub (RDP, LDAP HOSTS)
  const lim = pageSize || 2000;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim});
  if (proto) p.set('proto', proto);
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/hosts?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total;
  if (proto === 'RDP') renderRdpHosts(d.rows);
  else if (proto === 'LDAP') renderLdapHosts(d.rows);
  else renderProtoHosts(d.rows);
  renderPager();
}

async function loadShares() {
  const lim = pageSize || 999999;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim});
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/shares?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total;
  if (proto === 'NFS') renderNfsShares(_sortRows(d.rows));
  else renderSmbShares(_sortRows(d.rows));
  renderPager();
}

async function loadDirectoryListings(protoFilter) {
  const lim = pageSize || 999999;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim, proto:protoFilter});
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/directory_listings?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total; renderDirectoryListings(d.rows, protoFilter); renderPager();
}

async function loadConfChecks() {
  const lim = pageSize || 999999;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim});
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/conf_checks?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total; renderConfChecks(d.rows); renderPager();
}

async function loadAcredCreds() {
  const lim = pageSize || 999999;

  if (acredSub === 'local') {
    // LOCAL ADMIN tab: use results endpoint (has ip + cred_domain per host).
    // proto forced to SMB — local admin only applies to SMB admin relations.
    const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim, hide_guest:hideGuest});
    p.set('local_admin_cred', 'true');
    p.set('relation', 'admin');
    p.set('proto', 'SMB');
    if (srch) p.set('search', srch);
    const r = await apiFetch('/api/results?' + p);
    if (!r.ok) return;
    const d = await r.json();
    total = d.total;
    renderCreds(_sortRows(d.rows));
    renderPager();
    return;
  }

  // CREDS tab: domain admin credentials (admin_cred=1) + pending ghost rows
  // Domain admin creds are protocol-agnostic — proto filter must not apply here.
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim, hide_guest:hideGuest});
  p.set('admin_cred', 'true');
  if (srch) p.set('search', srch);
  const [r, rp] = await Promise.all([
    apiFetch('/api/credentials?' + p),
    apiFetch(`/api/domain_admin_list/pending?workspace_id=${ws.id}`),
  ]);
  if (!r.ok) return;
  const d = await r.json();
  const pending = rp.ok ? (await rp.json()).rows : [];
  // Pending rows: synthetic fields for rendering; placed after real sorted creds
  const pendingRows = pending.map(pr => ({
    ...pr, _pending: true, proto: '', password: '', credtype: '',
    admin_cred: 1, brutforced: null, pkey: null, operator: null,
  }));
  total = d.total + pendingRows.length;
  renderCreds([..._sortRows(d.rows), ...pendingRows]);
  renderPager();
}

// ── Manage-mod: hidden credentials + DPAPI view ────────────────────────────
async function loadHidden() {
  const lim = pageSize || 999999;
  const pc = new URLSearchParams({workspace_id:ws.id, page:1, limit:lim, hide_guest:'false', hidden:'true'});
  if (srch) pc.set('search', srch);
  const pd = new URLSearchParams({workspace_id:ws.id, page:1, limit:lim, hidden:'true'});
  if (srch) pd.set('search', srch);
  const [rc, rd] = await Promise.all([
    apiFetch('/api/credentials?' + pc).then(r => r.ok ? r.json() : {rows:[],total:0}),
    apiFetch('/api/dpapi?'       + pd).then(r => r.ok ? r.json() : {rows:[],total:0}),
  ]);
  const credRows  = rc.rows.map(r => ({...r, _src:'cred'}));
  const dpapiRows = rd.rows.map(d => ({...d, _src:'dpapi', proto:'DPAPI',
    username:d.username||'', password:d.password||'', domain:'', credtype:'plaintext', brutforced:null}));
  const merged = _sortRows([...credRows, ...dpapiRows]);
  total = merged.length;
  renderHiddenItems(merged);
  renderPager();
}

async function loadHiddenHosts() {
  const lim = pageSize || 999999;
  const p = new URLSearchParams({workspace_id:ws.id, page, limit:lim, hidden:'true'});
  if (srch) p.set('search', srch);
  const r = await apiFetch('/api/hosts?' + p);
  if (!r.ok) return;
  const d = await r.json();
  total = d.total; renderHiddenHosts(_sortRows(d.rows)); renderPager();
}

