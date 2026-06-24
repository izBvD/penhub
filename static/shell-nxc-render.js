function renderResults(rows) {
  if (!rows.length) { empty('No results for current filter'); return; }
  if (proto === 'FTP')                       return _renderFtpResults(rows);
  if (proto === 'SSH' && sub === 'admin')    return _renderSshAdmin(rows);
  if (proto === 'SSH')                       return _renderSshLoggedin(rows);
  if (proto === 'WINRM')                     return _renderWinrmResults(rows);
  if (proto === 'NFS' && sub === 'loggedin') return _renderNfsLoggedin(rows);
  _renderResultsStd(rows);
}

// FTP [+]: proto, IP, port, banner, login, password, operator
function _renderFtpResults(rows) {
  const hdr = [['Proto','proto'],['IP','ip'],['Port',''],['Banner',''],['Login','username'],['Password','password'],['Op','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw = _dispPass(r); const dispCtype = _dispCredtype(r);
    h += `<tr>
      <td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>
      ${_ipTd(r.ip)}
      <td style="color:var(--fg2)">${esc(r.host_port||'')}</td>
      <td style="color:var(--fg2);font-size:10px" title="${escAttr(r.host_banner||'')}">${esc((r.host_banner||'').substring(0,40))}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator)}</td>
      <td class="act-col">
        <button class="copy-btn" onclick="copyUpd(this)"
          data-user="${escAttr(r.username)}" data-pass="${escAttr(dispPw)}"
          data-domain="" data-credtype="${escAttr(dispCtype)}">&#10063;</button>
        <button class="copy-btn" onclick="copyDup(this)"
          data-user="${escAttr(r.username)}" data-pass="${escAttr(dispPw)}" data-domain="">&#10064;</button>
      </td>
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// SSH [+]: proto, IP, port, banner, OS, login, password, type, shell, rel, operator
function _renderSshLoggedin(rows) {
  const hdr = [['',''],['Proto','proto'],['IP','ip'],['Port',''],['Banner',''],['OS','os'],['Login','username'],['Password','password'],['Type','type'],['Shell',''],['Rel','rel'],['Op','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw=_dispPass(r); const dispBadge=_dispBadge(r); const dispCtype=_dispCredtype(r);
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, r.cred_domain||'')}
      <td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>
      ${_ipTd(r.ip)}
      <td style="color:var(--fg2)">${esc(r.host_port||'')}</td>
      <td style="color:var(--fg2);font-size:10px" title="${escAttr(r.host_banner||'')}">${esc((r.host_banner||'').substring(0,30))}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,28))}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td>${dispBadge}</td>
      <td>${r.shell ? '<span class="badge safe">yes</span>' : '<span class="badge na">no</span>'}</td>
      <td>${relBadge(r.relation_type)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator)}</td>
      ${_copyTd(r, r.cred_domain||'', dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// SSH PWN3D!: proto, IP, port, OS, login, password, rel, operator
function _renderSshAdmin(rows) {
  const hdr = [['',''],['Proto','proto'],['IP','ip'],['Port',''],['OS','os'],['Login','username'],['Password','password'],['Rel','rel'],['Op','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw=_dispPass(r); const dispCtype=_dispCredtype(r);
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, r.cred_domain||'')}
      <td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>
      ${_ipTd(r.ip)}
      <td style="color:var(--fg2)">${esc(r.host_port||'')}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,28))}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td>${relBadge(r.relation_type)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator)}</td>
      ${_copyTd(r, '', dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// WinRM [+]/PWN3D!: proto, IP, port, hostname, domain, OS, login, password, type, rel, operator
function _renderWinrmResults(rows) {
  const hdr = [['',''],['Proto','proto'],['IP','ip'],['Port',''],['Hostname','hostname'],['Domain','domain'],['OS','os'],['Login','username'],['Password','password'],['Type','type'],['Rel','rel'],['Op','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const domain=r.cred_domain||r.host_domain||'';
    const dispPw=_dispPass(r); const dispBadge=_dispBadge(r); const dispCtype=_dispCredtype(r);
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, domain)}
      <td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>
      ${_ipTd(r.ip)}
      <td style="color:var(--fg2)">${esc(r.host_port||'')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,28))}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td>${dispBadge}</td>
      <td>${relBadge(r.relation_type)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator)}</td>
      ${_copyTd(r, domain, dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// NFS [+]: proto, IP, hostname, port, login, password, operator
function _renderNfsLoggedin(rows) {
  const hdr = [['',''],['Proto','proto'],['IP','ip'],['Hostname','hostname'],['Port',''],['Login','username'],['Password','password'],['Op','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw=_dispPass(r); const dispCtype=_dispCredtype(r);
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, '')}
      <td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}</td>
      <td style="color:var(--fg2)">${esc(r.host_port||'')}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator)}</td>
      ${_copyTd(r, '', dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// CUSTOM ALL: all rows from custom_credentials — manual import via Toolbox
function _renderCustomCreds(rows) {
  if (!rows.length) { empty('No custom credentials found'); return; }
  const hdr = [
    ['',''],
    ['Proto','proto'], ['IP','ip'], ['Port','port'], ['Domain','domain'],
    ['Login','username'], ['Password','password'], ['Type','type'],
    ['URL','url'], ['Source','source'], ['Comment',''], ['',''],
  ];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw    = _dispPass(r);
    const dispBadge = _dispBadge(r);
    const dispCtype = _dispCredtype(r);
    const domain    = r.domain || '';
    const protoCell = r.proto
      ? `<td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>`
      : '<td style="color:var(--fg2)">—</td>';
    const urlText   = r.url || '';
    const urlDisp   = urlText.length > 45 ? urlText.substring(0, 42) + '…' : urlText;
    const commentDisp = (r.comment || '').substring(0, 30);
    const delCell = manageMod
      ? `<td class="skull-col"><button class="del-custom-btn" onclick="_deleteCustomCred(${r.id})" title="Delete">✕</button></td>`
      : '<td class="skull-col"></td>';
    h += `<tr>
      ${delCell}
      ${protoCell}
      <td class="copyable" onclick="copyField(this)">${esc(r.ip || '')}</td>
      <td style="color:var(--fg2)">${esc(r.port != null ? String(r.port) : '')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username || '')}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td>${dispBadge}</td>
      <td class="copyable" onclick="copyField(this)" title="${escAttr(urlText)}">${esc(urlDisp)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.source || '')}</td>
      <td style="color:var(--fg2);font-size:10px" title="${escAttr(r.comment || '')}">${esc(commentDisp)}</td>
      ${_copyTd(r, domain, dispPw, dispCtype, false)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// Default: SMB, MSSQL, LDAP loggedin, others
function _renderResultsStd(rows) {
  const showInstances = proto === 'MSSQL' && rows.some(r => r.instances != null);
  let h = '<table><thead><tr>' +
    _thSort('','') + _thSort('Proto','proto') + _thSort('IP','ip') +
    _thSort('Hostname','hostname') + _thSort('Domain','domain') + _thSort('OS','os') +
    (showInstances ? '<th>Inst</th>' : '') +
    _thSort('Username','username') + _thSort('Password','password') +
    _thSort('Type','type') + _thSort('Rel','rel') + _thSort('Op','op') + _thSort('','') +
    '</tr></thead><tbody>';
  for (const r of rows) {
    const domain = r.cred_domain || r.host_domain || '';
    const dispPw = _dispPass(r); const dispBadge = _dispBadge(r); const dispCtype = _dispCredtype(r);
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, domain)}
      <td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,28))}</td>
      ${showInstances ? `<td style="color:var(--fg2);font-size:10px">${esc(r.instances??'')}</td>` : ''}
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td>${dispBadge}</td>
      <td>${relBadge(r.relation_type)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator)}</td>
      ${_copyTd(r, domain, dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderDpapi(rows) {
  if (!rows.length) { empty('No DPAPI secrets found'); return; }
  const hdr = [
    ['Host IP','ip'], ['Type','dpapi_type'], ['Windows User','windows_user'],
    ['Username','username'], ['Password','password'], ['URL','url'], ['Operator','op'], ['',''],
  ];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    h += `<tr class="row-dpapi">
      ${_ipTd(r.host_ip)}
      <td style="color:var(--a5)">${esc(r.dpapi_type)}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.windows_user)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(r.password)}</td>
      <td class="copyable" onclick="copyField(this)" style="color:var(--a1);font-size:10px"
        title="${esc(r.url)}">${esc((r.url||'').substring(0,55))}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator)}</td>
      ${_dpapiCopyTd(r, r.password)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderHiddenItems(rows) {
  if (!rows.length) { empty('No hidden items found'); return; }
  const hdr = [['Type',''],['Domain / Source','domain'],['Username','username'],['Password','password'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw = _dispPass(r);
    const src = r._src || 'cred';
    const typeLabel = src === 'dpapi'
      ? `<span class="badge" style="background:var(--a5);color:#fff">${esc(r.dpapi_type||'DPAPI')}</span>`
      : typeBadge(r.credtype || 'plaintext');
    const domainOrSrc = src === 'dpapi' ? (r.dpapi_type || '—') : (r.domain || '—');
    let restoreBtn;
    if (src === 'dpapi') {
      restoreBtn = `<button class="copy-btn restore-cred-btn" onclick="restoreDpapi(this)"
        data-ws="${ws.id}" data-id="${r.id}" title="Restore DPAPI secret">&#43;</button>`;
    } else {
      restoreBtn = `<button class="copy-btn restore-cred-btn" onclick="restoreCredential(this)"
        data-ws="${ws.id}" data-domain="${escAttr(r.domain||'')}"
        data-user="${escAttr(r.username||'')}" data-pass="${escAttr(dispPw)}"
        title="Restore credential">&#43;</button>`;
    }
    h += `<tr>
      <td>${typeLabel}</td>
      <td class="copyable" onclick="copyField(this)">${esc(domainOrSrc)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username||'')}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td class="act-col">${restoreBtn}</td>
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderHiddenHosts(rows) {
  if (!rows.length) { empty('No hidden hosts found'); return; }
  const hdr = [['IP','ip'],['Hostname','hostname'],['Domain','domain'],['OS','os'],['Operator','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    h += `<tr>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.domain||'')}</td>
      <td title="${esc(r.os||'')}">${esc((r.os||'').substring(0,35))}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator||'')}</td>
      ${_hostActionTd(r)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderCreds(rows) {
  if (!rows.length) { empty('No credentials found'); return; }
  if (acredMode && acredSub === 'local') return _renderLocalAdminCreds(rows);
  if (acredMode)         return _renderAcredCreds(rows);
  if (proto === 'VNC')   return _renderVncCreds(rows);
  if (proto === 'WMI')   return _renderWmiCreds(rows);
  if (proto === 'LDAP')  return _renderLdapCreds(rows);
  _renderCredsDefault(rows);
}

// ACRED: domain, login, password only (deduplicated, prefer SMB) + pending ghost rows
function _renderAcredCreds(rows) {
  // Split real vs pending (ghost) rows — pending come from domain_admin_list with no matching cred
  const realRows    = rows.filter(r => !r._pending);
  const pendingRows = rows.filter(r =>  r._pending);

  // Deduplicate real rows by domain+login+password, prefer SMB
  const best = new Map();
  for (const r of realRows) {
    const k = `${(r.domain||'').toLowerCase()}|${(r.username||'').toLowerCase()}|${r.password||''}`;
    if (!best.has(k) || (r.proto||'').toUpperCase() === 'SMB') best.set(k, r);
  }
  // Pending rows already deduplicated by UNIQUE constraint + NOT EXISTS in API
  const deduped = [...Array.from(best.values()), ...pendingRows];
  if (!deduped.length) { empty('No admin credentials'); return; }

  const dalDelHdr = manageMod ? [['','']] : [];
  const hdr = [...dalDelHdr,['',''],['Domain','domain'],['Login','username'],['Password','password'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of deduped) {
    if (r._pending) {
      // Ghost row: grayed out, no skull button, no copy buttons, no password
      // Delete button only on ghosts — real rows keep their existing manage controls
      const dalDel = manageMod
        ? `<td class="skull-col"><button class="del-custom-btn" onclick="_deleteDalEntry('${esc(r.domain||'')}','${esc(r.username||'')}')" title="Remove from watchlist">✕</button></td>`
        : '';
      h += `<tr class="row-acred-pending">
        ${dalDel}
        <td class="skull-col"></td>
        <td class="copyable" onclick="copyField(this)">${esc(r.domain||'')}</td>
        <td class="copyable" onclick="copyField(this)">${esc(r.username||'')}</td>
        <td style="color:var(--fg2)">&#8212;</td>
        <td class="act-col"></td>
      </tr>`;
      continue;
    }
    const dispPw=_dispPass(r); const dispCtype=_dispCredtype(r);
    const domain = r.domain || '';
    // Real matched rows: empty filler cell in manage mode to keep column count consistent
    const dalFiller = manageMod ? '<td class="skull-col"></td>' : '';
    h += `<tr class="row-acred">
      ${dalFiller}
      ${_skullTd(r, domain)}
      <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      ${_copyTd(r, domain, dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// LOCAL ADMIN: IP (machine) | Machine (cred_domain) | Login | Password
// Data comes from get_results() — each row is one (credential, host) auth_relation.
// Dedup by ip+username+password to collapse repeated auth_relations on the same host.
function _renderLocalAdminCreds(rows) {
  if (!rows.length) { empty('No local admin credentials'); return; }
  const seen = new Set();
  const deduped = [];
  for (const r of rows) {
    const k = `${r.ip||''}|${(r.username||'').toLowerCase()}|${r.password||''}`;
    if (!seen.has(k)) { seen.add(k); deduped.push(r); }
  }
  const hdr = [['',''],['IP','ip'],['Machine','cred_domain'],['Login','username'],['Password','password'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of deduped) {
    const dispPw=_dispPass(r); const dispCtype=_dispCredtype(r);
    const machine = r.cred_domain || '';
    h += `<tr class="row-acred">
      ${_skullTd(r, machine)}
      ${_ipTd(r.ip || '')}
      <td class="copyable" onclick="copyField(this)">${esc(machine)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      ${_copyTd(r, machine, dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// VNC CREDS: IP (prefer r.ip from auth_relations), login, password, pkey, operator
function _renderVncCreds(rows) {
  const hasPkey = rows.some(r => r.pkey);
  const hdr = [['',''],['IP','ip'],['Login','username'],['Password','password']]
    .concat(hasPkey ? [['PKey','']] : []).concat([['Op','op'],['','']]);
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw=_dispPass(r); const dispCtype=_dispCredtype(r);
    const ip = r.ip || r.pillaged_from_ip || '';
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, '')}
      ${_ipTd(ip)}
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      ${hasPkey ? `<td class="copyable" onclick="copyField(this)" style="font-size:9px;color:var(--a5)" title="${escAttr(r.pkey||'')}">${r.pkey?'🔑':'—'}</td>` : ''}
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator||'')}</td>
      ${_copyTd(r, '', dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// WMI CREDS: IP, login, password, operator
function _renderWmiCreds(rows) {
  const hdr = [['',''],['IP','ip'],['Login','username'],['Password','password'],['Op','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const dispPw=_dispPass(r); const dispCtype=_dispCredtype(r);
    const ip = r.ip || r.pillaged_from_ip || '';
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, '')}
      ${_ipTd(ip)}
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator||'')}</td>
      ${_copyTd(r, '', dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// LDAP CREDS: domain, login, password, type, operator
function _renderLdapCreds(rows) {
  const hdr = [['',''],['Domain','domain'],['Login','username'],['Password','password'],['Type','type'],['Op','op'],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k])=>_thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const domain=r.domain||''; const dispPw=_dispPass(r); const dispBadge=_dispBadge(r); const dispCtype=_dispCredtype(r);
    h += `<tr${_rowClass(r)}>
      ${_skullTd(r, domain)}
      <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td>${dispBadge}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator||'')}</td>
      ${_copyTd(r, domain, dispPw, dispCtype)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

// Default creds (samlsa / LSA+SAM)
function _renderCredsDefault(rows) {
  const hasIp  = rows.some(r => r.pillaged_from_ip);
  const hasPkey = rows.some(r => r.pkey);
  const hdrBase = hasIp
    ? [['',''],['Host IP','ip'],['Hostname','hostname'],['Proto','proto'],['Domain','domain'],['Username','username'],['Password','password'],['Type','type'],['Op','op']]
    : [['',''],['Proto','proto'],['Domain','domain'],['Username','username'],['Password','password'],['Type','type'],['Op','op']];
  const hdr = hasPkey ? [...hdrBase, ['PKey',''], ['','']] : [...hdrBase, ['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const domain = r.domain || ''; const dispPw = _dispPass(r);
    const dispBadge = _dispBadge(r); const dispCtype = _dispCredtype(r);
    h += `<tr${_rowClass(r)}>`;
    h += _skullTd(r, domain);
    if (hasIp) h += _ipTd(r.pillaged_from_ip)
                 + `<td class="copyable" onclick="copyField(this)">${esc(r.pillaged_from_hostname||'')}</td>`;
    h += `<td><span class="${pClass(r.proto)}">${esc(r.proto)}</span></td>
      <td class="copyable" onclick="copyField(this)">${esc(domain)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.username)}</b></td>
      <td class="copyable" onclick="copyField(this)">${esc(dispPw)}</td>
      <td>${dispBadge}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator||'')}</td>
      ${hasPkey ? `<td class="copyable" onclick="copyField(this)" style="font-size:9px;color:var(--a5)" title="${escAttr(r.pkey||'')}">${r.pkey ? '🔑' : '—'}</td>` : ''}`;
    h += _copyTd(r, domain, dispPw, dispCtype);
    h += '</tr>';
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderVulns(rows) {
  if (!rows.length) { empty('No vulnerabilities found for current filter'); return; }
  // Columns: IP/Hostname/Domain/OS + one per VULN_COLUMNS (mirrors server). Scrolls right.
  const hdr = [['IP','ip'],['Hostname','hostname'],['Domain','domain'],['OS','os']]
    .concat(VULN_COLUMNS.map(c => [c.label, c.slug]))
    .concat([['','']]);
  let h = '<table class="vulns-table"><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  // Cycle: 1(YES) → 0(NO) → null(—) → 1(YES)
  const _nextVuln = v => v === 1 ? 0 : v === 0 ? null : 1;
  for (const r of rows) {
    const vulnCells = VULN_COLUMNS.map(c => {
      const v = r[c.slug];
      if (manageMod) {
        const nv = _nextVuln(v);
        const nvStr = nv === null ? 'null' : nv;
        return `<td class="vuln-cycle-td" onclick="_setVulnOverride('${esc(r.ip)}','${c.slug}',${nvStr})" title="Click to cycle: YES→NO→—">${vtri(v)}</td>`;
      }
      return `<td>${vtri(v)}</td>`;
    }).join('');
    h += `<tr>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname)}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.domain)}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,35))}</td>
      ${vulnCells}
      ${_hostActionTd(r)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function _dupBadge(r) {
  return manageMod && r._dup_hostname
    ? ' <span class="badge dup" title="Same hostname on multiple IPs — possible DHCP reassignment">⚠ DUP</span>'
    : '';
}

function renderRdpHosts(rows) {
  if (!rows.length) { empty('No RDP hosts found'); return; }
  const hdr = [['IP','ip'],['Port',''],['Hostname','hostname'],['Domain','domain'],['OS','os'],['NLA',''],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    h += `<tr>
      ${_ipTd(r.ip)}
      <td>${esc(r.port||'')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}${_dupBadge(r)}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.domain||'')}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,35))}</td>
      <td>${r.nla ? '<span class="badge vuln">NLA</span>' : '<span class="badge safe">no</span>'}</td>
      ${_hostActionTd(r)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderLdapHosts(rows) {
  if (!rows.length) { empty('No LDAP hosts found'); return; }
  const hdr = [['IP','ip'],['Hostname','hostname'],['Domain','domain'],['OS','os'],['Signing',''],['Channel Binding',''],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const signing = r.signing_required != null
      ? (r.signing_required ? '<span class="badge safe">Required</span>' : '<span class="badge vuln">Off</span>')
      : '<span class="badge na">—</span>';
    h += `<tr>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}${_dupBadge(r)}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.domain||'')}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,28))}</td>
      <td>${signing}</td>
      <td class="copyable" onclick="copyField(this)" style="font-size:10px;color:var(--fg2)">${esc(r.channel_binding||'')}</td>
      ${_hostActionTd(r)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderProtoHosts(rows) {
  if (!rows.length) { empty('No hosts found'); return; }
  const hdr = [['IP','ip'],['Hostname','hostname'],['Domain','domain'],['OS','os'],['Port',''],['Banner',''],['','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    h += `<tr>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}${_dupBadge(r)}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.domain||'')}</td>
      <td title="${esc(r.os)}">${esc((r.os||'').substring(0,28))}</td>
      <td>${esc(r.port||'')}</td>
      <td class="copyable" onclick="copyField(this)" style="font-size:10px;color:var(--fg2)">${esc((r.banner||'').substring(0,40))}</td>
      ${_hostActionTd(r)}
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderSmbShares(rows) {
  if (!rows.length) { empty('No SMB shares found'); return; }
  const hdr = [['IP','ip'],['Username','username'],['Password','password'],['Share','share'],['Remark',''],['Read','read'],['Write','write'],['Op','op']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const rd  = r.read  ? '<span class="badge safe">R</span>'  : '<span class="badge na">—</span>';
    const wr  = r.write ? '<span class="badge vuln">W</span>' : '<span class="badge na">—</span>';
    const pwd = r.brutforced || r.password || '';
    const pwdCls = r.brutforced ? ' class="copyable sv-cracked"' : ' class="copyable"';
    h += `<tr>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.username||'')}</td>
      <td${pwdCls} onclick="copyField(this)">${esc(pwd)}</td>
      <td class="copyable" onclick="copyField(this)"><b>${esc(r.name||'')}</b></td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.remark||'')}</td>
      <td>${rd}</td>
      <td>${wr}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.operator||'')}</td>
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderNfsShares(rows) {
  if (!rows.length) { empty('No NFS shares found'); return; }
  const hdr = [['IP','ip'],['Login','username'],['Data','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const data = r.data || '';
    const label = data.length === 0 ? '—' : data.length > 30 ? '>30' : '<30';
    h += `<tr>
      <td class="copyable" onclick="copyField(this)">${esc(r.ip||r.host_ip||'')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.username||'')}</td>
      <td class="copyable" onclick="copyField(this)" title="${esc(data)}">${esc(label)}</td>
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderDirectoryListings(rows, protoFilter) {
  if (!rows.length) { empty('No directory listings found'); return; }
  const threshold = protoFilter === 'FTP' ? 50 : 30;
  const hdr = [['IP','ip'],['Login','username'],['Data','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const data = r.data || '';
    const label = data.length === 0 ? '—' : data.length > threshold ? `>${threshold}` : `<${threshold}`;
    h += `<tr>
      <td class="copyable" onclick="copyField(this)">${esc(r.host_ip||'')}</td>
      <td class="copyable" onclick="copyField(this)">${esc(r.username||'')}</td>
      <td class="copyable" onclick="copyField(this)" title="${esc(data)}">${esc(label)}</td>
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

function renderConfChecks(rows) {
  if (!rows.length) { empty('No conf check results found'); return; }
  const hdr = [['IP','ip'],['Hostname','hostname'],['Check',''],['Secure',''],['Reasons','']];
  let h = '<table><thead><tr>' + hdr.map(([l,k]) => _thSort(l,k)).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    const sec = r.secure
      ? '<span class="badge safe">yes</span>'
      : '<span class="badge vuln">DANGER</span>';
    h += `<tr>
      ${_ipTd(r.ip)}
      <td class="copyable" onclick="copyField(this)">${esc(r.hostname||'')}</td>
      <td><b>${esc(r.check_name||'')}</b></td>
      <td>${sec}</td>
      <td style="color:var(--fg2);font-size:10px">${esc(r.reasons||'')}</td>
    </tr>`;
  }
  h += '</tbody></table>';
  document.getElementById('tableWrap').innerHTML = h;
}

