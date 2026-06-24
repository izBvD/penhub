function copyUpd(btn) {
  const u = btn.dataset.user || '', p = btn.dataset.pass || '', d = btn.dataset.domain || '';
  const flag = btn.dataset.credtype === 'hash' ? '-H' : '-p';
  _copyText(d ? `-u ${u} ${flag} ${p} -d ${d}` : `-u ${u} ${flag} ${p}`);
  _flashCopy(btn);
}

function copyDup(btn) {
  const u = btn.dataset.user || '', p = btn.dataset.pass || '', d = btn.dataset.domain || '';
  _copyText(d ? `${d}\\${u}:${p}` : `\\${u}:${p}`);
  _flashCopy(btn);
}

function copyField(el) {
  _copyText(el.textContent || '');
  const orig = el.style.color;
  el.style.color = 'var(--a2)';
  setTimeout(() => { el.style.color = orig; }, 500);
  _showToast();
}

function relBadge(r) {
  if (r === 'admin')    return '<span class="badge admin">PWN3D!</span>';
  if (r === 'loggedin') return '<span class="badge loggedin">[+]</span>';
  return '';
}
function typeBadge(t) {
  return t === 'hash'
    ? '<span class="badge hash">HASH</span>'
    : '<span class="badge plain">plain</span>';
}
function vflag(v, dangerOnZero) {
  if (v === null || v === undefined) return '<span class="badge na">—</span>';
  const bad = dangerOnZero ? v === 0 : v === 1;
  return bad ? '<span class="badge vuln">YES</span>' : '<span class="badge safe">no</span>';
}
// Tri-state vuln cell: 1=vulnerable, 0=checked-clean, null/undefined=could-not-check / no data.
// GUARD: null is NOT "safe" — render it as — (na), never as "no".
function vtri(v) {
  if (v === 1) return '<span class="badge vuln">YES</span>';
  if (v === 0) return '<span class="badge safe">no</span>';
  return '<span class="badge na">—</span>';
}

function _dispPass(r) {
  return (hkBrutedMode && r.brutforced) ? r.brutforced : r.password;
}
function _dispBadge(r) {
  return typeBadge((hkBrutedMode && r.brutforced) ? 'plaintext' : r.credtype);
}
function _dispCredtype(r) {
  return (hkBrutedMode && r.brutforced) ? 'plaintext' : r.credtype;
}

// ── Common row action cells (skull + 2 copy buttons) ──────────────────────
// Single source for all table renders — change here, applies everywhere.
// Skull button: requires non-empty domain. Local admin button: only on SMB admin relation
// rows with non-empty password. Both are mutually exclusive (muted via CSS when opposite is set).
function _skullTd(r, domain) {
  if (!(r.username || '').trim()) return '<td class="skull-col"></td>';
  const dom = domain !== undefined ? domain : (r.cred_domain || r.domain || '');
  const pw  = r.password || '';

  const isAcred      = r.admin_cred == 1;
  const isLocalAdmin = r.local_admin_cred == 1;

  // Laptop button: only in PWN3D SMB rows (auth_relations with relation_type=admin)
  const canLap = r.relation_type === 'admin'
    && (r.proto || '').toUpperCase() === 'SMB'
    && pw && pw !== '<empty_password>';

  const canSkull = !!dom.trim();

  if (!canSkull && !canLap) return '<td class="skull-col"></td>';

  const skullBtn = canSkull
    ? `<button class="skull-btn${isAcred ? ' marked' : ''}${isLocalAdmin ? ' skull-muted' : ''}"
        onclick="toggleAdminCred(this)"
        data-ws="${ws.id}" data-domain="${escAttr(dom)}"
        data-user="${escAttr(r.username)}" data-pass="${escAttr(pw)}"
        title="Mark as domain admin">&#9760;</button>`
    : '';

  const lapBtn = canLap
    ? `<button class="local-admin-btn${isLocalAdmin ? ' marked' : ''}${isAcred ? ' lap-muted' : ''}"
        onclick="toggleLocalAdminCred(this)"
        data-ws="${ws.id}" data-user="${escAttr(r.username)}" data-pass="${escAttr(pw)}"
        title="Mark as local admin">&#x1F4BB;</button>`
    : '';

  return `<td class="skull-col">${skullBtn}${lapBtn}</td>`;
}
function _copyTd(r, domain, dispPw, dispCtype, allowManage = true) {
  const u = r.username || '', d = domain !== undefined ? domain : (r.cred_domain || r.domain || '');
  let manageBtn = '';
  if (manageMod && u && allowManage) {
    if (proto === 'HIDDEN') {
      manageBtn = `<button class="copy-btn restore-cred-btn" onclick="restoreCredential(this)"
        data-ws="${ws.id}" data-domain="${escAttr(d)}"
        data-user="${escAttr(u)}" data-pass="${escAttr(dispPw)}"
        title="Restore — make credential visible again">&#43;</button>`;
    } else {
      manageBtn = `<button class="copy-btn hide-cred-btn" onclick="hideCredential(this)"
        data-ws="${ws.id}" data-domain="${escAttr(d)}"
        data-user="${escAttr(u)}" data-pass="${escAttr(dispPw)}"
        title="Hide credential from all views">&#10006;</button>`;
    }
  }
  return `<td class="act-col">
    <button class="copy-btn" onclick="copyUpd(this)"
      data-user="${escAttr(u)}" data-pass="${escAttr(dispPw)}"
      data-domain="${escAttr(d)}" data-credtype="${escAttr(dispCtype)}"
      title="${dispCtype === 'hash' ? 'Copy: -u user -H hash -d domain' : 'Copy: -u user -p pass -d domain'}">&#10063;</button>
    <button class="copy-btn" onclick="copyDup(this)"
      data-user="${escAttr(u)}" data-pass="${escAttr(dispPw)}"
      data-domain="${escAttr(d)}"
      title="Copy: domain\\user:pass">&#10064;</button>
    ${manageBtn}
  </td>`;
}
function _dpapiCopyTd(r, dispPw) {
  const u = r.username || '';
  let manageBtn = '';
  if (manageMod) {
    manageBtn = `<button class="copy-btn hide-cred-btn" onclick="hideDpapi(this)"
      data-ws="${ws.id}" data-id="${r.id}"
      title="Hide DPAPI secret from all views">&#10006;</button>`;
  }
  return `<td class="act-col">
    <button class="copy-btn" onclick="copyUpd(this)"
      data-user="${escAttr(u)}" data-pass="${escAttr(dispPw)}"
      data-domain="" data-credtype="plaintext"
      title="Copy: -u user -p pass">&#10063;</button>
    <button class="copy-btn" onclick="copyDup(this)"
      data-user="${escAttr(u)}" data-pass="${escAttr(dispPw)}"
      data-domain=""
      title="Copy: user:pass">&#10064;</button>
    ${manageBtn}
  </td>`;
}
function _ipTd(ip) {
  const v = esc(ip || '');
  const a = escAttr(ip || '');
  if (!manageMod) return `<td class="copyable" onclick="copyField(this)">${v}</td>`;
  if (proto === 'HIDDEN' || proto === 'HIDDEN_HOSTS')
    return `<td class="ip-restore" data-ip="${a}" onclick="restoreIp(this)" title="Restore all records for ${a}">${v}</td>`;
  return `<td class="ip-strike" data-ip="${a}" onclick="strikeIp(this)" title="Strike: hide host and auth records for ${a}">${v}</td>`;
}
function _hostActionTd(r) {
  if (!manageMod) return '<td class="act-col"></td>';
  if (proto === 'HIDDEN_HOSTS') {
    return `<td class="act-col"><button class="copy-btn restore-cred-btn" onclick="restoreHost(this)"
      data-ws="${ws.id}" data-ip="${escAttr(r.ip||'')}" title="Restore host to all views">&#43;</button></td>`;
  }
  return `<td class="act-col"><button class="copy-btn hide-cred-btn" onclick="hideHost(this)"
    data-ws="${ws.id}" data-id="${r.id}" title="Hide host from all views">&#10006;</button></td>`;
}
function _rowClass(r, extra) {
  let c = r.relation_type === 'admin' ? 'row-admin' : '';
  if (r.admin_cred == 1) c = (c + ' row-acred').trim();
  if (extra) c = (c + ' ' + extra).trim();
  return c ? ` class="${c}"` : '';
}

