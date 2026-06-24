// ── Projects page credential rain (vanilla port of auth-app Rain component) ─
const WsRain = (() => {
  const HEX = "0123456789abcdef";
  const USERS = ["administrator","admin","svc_sql","backup","root","jsmith","dwilson","sa","helpdesk","krbtgt","operator","webadmin","sshd","ftpuser","ldap_bind","mgomez","aturner","guest"];
  const WORDS = ["P@ssw0rd!","Summer2025","Welcome1","Spring#26","Qwerty123","Companynet1","Hunter2!","Letmein99","Dragon#7","Passw0rd1","Tr0ub4dor","Winter2024","Changeme1","Football!","ZxCvBn123","Pa$$w0rd","Admin@123","S3cur3!t"];
  const PROTOS = ["SMB","LDAP","MSSQL","WINRM","SSH","RDP","FTP","VNC"];
  const rnd = a => a[Math.floor(Math.random() * a.length)];
  const hex = n => Array.from({length:n}, () => rnd(HEX)).join('');
  const ip = () => rnd(["10.10","192.168","172.16","10.0"]) + "." + (~~(Math.random()*254)+1) + "." + (~~(Math.random()*254)+1);
  function credPair() {
    const r = Math.random();
    if (r < .30) return {t:rnd(USERS)+":"+rnd(WORDS), c:"cyan"};
    if (r < .52) return {t:(hex(32)+":"+hex(32)).slice(0,33)+"…", c:"purple"};
    if (r < .70) return {t:ip()+" "+rnd(PROTOS), c:"green"};
    if (r < .82) return {t:rnd(USERS)+"$:"+hex(16), c:"amber"};
    if (r < .90) return {t:"aad3b…:"+hex(24), c:"k"};
    if (r < .96) return {t:rnd(USERS)+":"+rnd(WORDS), c:"red"};
    return {t:hex(20), c:"k"};
  }
  function credToken() { const t = credPair(); t.gap = 70 + ~~(Math.random()*220); return t; }
  const SCRAMBLE = "ABCDEFGHJKLMNPQRSTUVWXYZabcdef0123456789!@#$%&*";
  const scrCh = () => SCRAMBLE[~~(Math.random()*SCRAMBLE.length)];
  const keepCh = ch => !/[A-Za-z0-9]/.test(ch);

  let _timer = null, _cells = [], _onResize = null;

  function _build() {
    const el = document.getElementById('wsRain');
    if (!el) return [];
    el.innerHTML = '';
    const count = Math.max(4, ~~(window.innerWidth / 240));
    const cells = [];
    for (let ci = 0; ci < count; ci++) {
      const toks = Array.from({length:9}, credToken);
      const col = document.createElement('div');
      col.className = 'at-col';
      col.style.cssText = `left:${ci/count*100+(Math.random()*4-2)}%;animation-duration:${13+Math.random()*12}s;animation-delay:${-Math.random()*22}s`;
      const byK = Array.from({length:9}, () => []);
      [...toks, ...toks].forEach((tok, j) => {
        const sp = document.createElement('span');
        sp.className = 'at-tok scan';
        sp.style.marginBottom = tok.gap + 'px';
        sp.textContent = tok.t;
        col.appendChild(sp);
        byK[j % 9].push(sp);
      });
      el.appendChild(col);
      toks.forEach((tok, k) => cells.push({spans:byK[k], base:tok.t, color:tok.c, rev:0, hold:0, speed:0.16+Math.random()*0.32}));
    }
    return cells;
  }

  function start() {
    stop();
    _cells = _build();
    _timer = setInterval(() => {
      for (const c of _cells) {
        let txt, cls;
        if (c.hold > 0) {
          c.hold--; txt = c.base; cls = 'at-tok '+c.color+' lock';
          if (c.hold === 0) { c.rev = 0; const np = credPair(); c.base = np.t; c.color = np.c; }
        } else if (c.rev >= c.base.length) {
          c.hold = 6 + ~~(Math.random()*16); txt = c.base; cls = 'at-tok '+c.color+' lock';
        } else {
          if (Math.random() < c.speed) c.rev++;
          let s = c.base.slice(0, c.rev);
          for (let i = c.rev; i < c.base.length; i++) s += keepCh(c.base[i]) ? c.base[i] : scrCh();
          txt = s; cls = 'at-tok scan';
        }
        for (const sp of c.spans) { sp.textContent = txt; sp.className = cls; }
      }
    }, 65);
    _onResize = () => { stop(); start(); };
    window.addEventListener('resize', _onResize);
  }

  function stop() {
    if (_timer) { clearInterval(_timer); _timer = null; }
    if (_onResize) { window.removeEventListener('resize', _onResize); _onResize = null; }
    _cells = [];
    const el = document.getElementById('wsRain');
    if (el) el.innerHTML = '';
  }

  return {start, stop};
})();

// ── Top bar (shared component across all post-login pages) ────────────────
function _setTopBar(mode) {
  // mode: 'projects' | 'app'
  const isApp    = mode === 'app';
  const bar      = document.getElementById('topBar');
  const backBtn  = document.getElementById('backBtn');
  const tbPage   = document.getElementById('tbPage');
  const tbStats  = document.getElementById('tbStats');
  const newProj  = document.getElementById('newProjBtn');
  const liveBtn  = document.getElementById('liveBtn');
  const exitBtn  = document.getElementById('exitBtn');

  if (bar)     bar.style.display    = 'flex';
  if (backBtn) backBtn.style.display = isApp ? '' : 'none';
  if (tbPage)  tbPage.textContent   = isApp ? (ws ? ws.name : '') : 'PROJECTS';
  if (tbStats) tbStats.style.display = isApp ? 'flex' : 'none';
  if (newProj) newProj.style.display = 'none';
  if (liveBtn) liveBtn.style.display = isApp ? '' : 'none';
  if (exitBtn) exitBtn.style.display = isApp ? '' : 'none';
}

// ── Auth ───────────────────────────────────────────────────────────────────
async function doLogin() {
  const pwd = document.getElementById('pwdInput').value;
  const err = document.getElementById('loginErr');
  err.textContent = '';
  try {
    const r = await fetch('/api/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({password:pwd})
    });
    if (!r.ok) { err.textContent = 'Access denied'; return; }
    await initApp();
  } catch(e) { err.textContent = 'Connection error'; }
}

async function doLogout() {
  stopLive();
  await fetch('/api/logout', {method:'POST'});
  const bar = document.getElementById('topBar');
  if (bar) bar.style.display = 'none';
  location.reload();
}


// ── Live refresh ───────────────────────────────────────────────────────────
function toggleLive() {
  liveOn = !liveOn;
  document.getElementById('liveBtn').classList.toggle('on', liveOn);
  if (liveOn) startLive(); else stopLive();
}
function startLive() {
  if (liveTimer) clearInterval(liveTimer);
  liveTimer = setInterval(() => { if (ws) { _keepScroll = true; loadData(); loadStats(); } }, LIVE_MS);
}
function stopLive() {
  if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
}
function reloadData() {
  if (ws) { loadData(); loadStats(); }
}

// ── Workspace rename (inline edit) ─────────────────────────────────────────
let _renameBusy = false;

function _renameStart(e, wsId, btn) {
  e.stopPropagation();
  if (_renameBusy) return;
  const nameDiv = btn.closest('.ws-card-name');
  const origName = nameDiv.querySelector('.ws-name-text').textContent;
  nameDiv.innerHTML =
    `<input class="ws-name-input" value="${esc(origName)}" maxlength="120">` +
    `<span class="ws-rename-err"></span>`;
  const inp = nameDiv.querySelector('.ws-name-input');
  const err = nameDiv.querySelector('.ws-rename-err');
  inp.focus(); inp.select();
  inp.addEventListener('click', ev => ev.stopPropagation());
  inp.addEventListener('keydown', async ev => {
    if (ev.key === 'Enter') {
      ev.preventDefault();
      if (_renameBusy) return;
      const newName = inp.value.trim();
      if (!newName) { err.textContent = 'Name cannot be empty'; return; }
      _renameBusy = true;
      const r = await apiFetch(`/api/workspaces/${wsId}`, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: newName}),
      });
      _renameBusy = false;
      if (r.ok) {
        await renderProjectList();
      } else if (r.status === 409) {
        err.textContent = 'Name already taken';
        inp.focus();
      } else {
        err.textContent = 'Error saving';
        inp.focus();
      }
    } else if (ev.key === 'Escape') {
      ev.preventDefault();
      _renameCancel(nameDiv, origName);
    }
  });
  inp.addEventListener('blur', () => {
    if (!_renameBusy) _renameCancel(nameDiv, origName);
  });
}

function _renameCancel(nameDiv, origName) {
  nameDiv.innerHTML =
    `<span class="ws-name-text">${esc(origName)}</span>` +
    `<button class="ws-rename-btn" title="Rename">` +
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>` +
    `</button>`;
  const btn = nameDiv.querySelector('.ws-rename-btn');
  btn.addEventListener('click', ev => _renameStart(ev, nameDiv.dataset.wsId, btn));
}

// ── Workspaces ─────────────────────────────────────────────────────────────
async function loadWorkspaces() {
  const r = await apiFetch('/api/workspaces');
  if (!r.ok) throw new Error('error');
  return await r.json();
}

// ── Project selection page ─────────────────────────────────────────────────
let _projectTab = 'active';  // 'active' | 'archive'

async function showProjectsPage() {
  stopLive();
  if (typeof Notif !== 'undefined') Notif.stop();
  ws = null;
  manageMod = false;
  document.getElementById('appView').style.display = 'none';
  document.getElementById('wsView').style.display  = 'flex';
  _restartNeonSign();
  WsRain.start();
  _setTopBar('projects');
  clearTable(); clearStats();
  syncProtoUI();
  await renderProjectList();
}

function _restartNeonSign() {
  const sign = document.querySelector('.neon-sign');
  if (!sign) return;
  const flicker = sign.querySelector('.nl.flicker');
  sign.style.animation = 'none';
  if (flicker) flicker.style.animation = 'none';
  void sign.offsetWidth; // force reflow — restarts CSS animations
  sign.style.animation = '';
  if (flicker) flicker.style.animation = '';
}

function setProjectTab(tab) {
  _projectTab = tab;
  document.querySelectorAll('.ws-tab').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === tab)
  );
  renderProjectList();
}

async function renderProjectList() {
  const container = document.getElementById('wsList');
  try {
    const r = await apiFetch('/api/workspaces');
    if (!r.ok) throw new Error();
    const list = await r.json();

    let filtered;
    if (_projectTab === 'recycle') {
      filtered = list.filter(w => !!w.recycled_at);
    } else if (_projectTab === 'active') {
      filtered = list.filter(w => !w.archived_at && !w.recycled_at);
    } else {
      filtered = list.filter(w => !!w.archived_at && !w.recycled_at);
    }

    const emptyHints = {
      active:  'No active projects — create one with + NEW',
      archive: 'No archived projects',
      recycle: 'Recycle bin is empty',
    };
    if (!filtered.length) {
      container.innerHTML = `<div class="ws-empty-hint">${emptyHints[_projectTab]}</div>`;
      return;
    }

    if (_projectTab === 'recycle') {
      container.innerHTML = filtered.map(w => {
        const dt       = formatDate(w.created_at);
        const rcDt     = formatDate(w.recycled_at);
        const safeName = esc(w.name).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"');
        return `<div class="ws-card ws-card--recycle">
    <div class="ws-card-info">
      <div class="ws-card-name">${esc(w.name)}</div>
      <div class="ws-card-date">${dt} &middot; deleted ${rcDt}</div>
    </div>
    <div class="ws-card-stats">
      <div class="ws-stat-blk">
        <div class="ws-stat-val">${w.hosts ?? 0}</div>
        <div class="ws-stat-lbl">HOSTS</div>
      </div>
      <div class="ws-stat-blk">
        <div class="ws-stat-val">${w.creds ?? 0}</div>
        <div class="ws-stat-lbl">CREDS</div>
      </div>
      <div class="ws-stat-blk">
        <div class="ws-stat-val sv-admin">${w.admin ?? 0}</div>
        <div class="ws-stat-lbl">PWN3D!</div>
      </div>
    </div>
    <div class="ws-card-actions" onclick="event.stopPropagation()">
      <button class="btn btn--ghost" onclick="restoreProject(event,${w.id},'active')" title="Restore to Active">&#8635; Active</button>
      <button class="btn btn--warn"  onclick="restoreProject(event,${w.id},'archive')" title="Restore to Archive">&#8964; Archive</button>
      <button class="ws-del ws-del--perm" onclick="permanentDeleteProject(event,${w.id},'${safeName}')" title="Delete permanently">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/><path d="M10 11v5M14 11v5"/></svg>
      </button>
    </div>
  </div>`;
      }).join('');
      return;
    }

    container.innerHTML = filtered.map(w => {
      const dt       = formatDate(w.created_at);
      const archDt   = formatDate(w.archived_at);
      const safeName = esc(w.name).replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/"/g,'\\"');
      const isArch   = !!w.archived_at;
      return `<div class="ws-card" onclick="openProject(${w.id})">
    <div class="ws-card-info">
      <div class="ws-card-name" data-ws-id="${w.id}">
        <span class="ws-name-text">${esc(w.name)}</span>
        <button class="ws-rename-btn" onclick="_renameStart(event,${w.id},this)" title="Rename"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
      </div>
      <div class="ws-card-date">${dt}${isArch ? ` &middot; archived ${archDt}` : ''}</div>
    </div>
    <div class="ws-card-stats">
      <div class="ws-stat-blk">
        <div class="ws-stat-val">${w.hosts ?? 0}</div>
        <div class="ws-stat-lbl">HOSTS</div>
      </div>
      <div class="ws-stat-blk">
        <div class="ws-stat-val">${w.creds ?? 0}</div>
        <div class="ws-stat-lbl">CREDS</div>
      </div>
      <div class="ws-stat-blk">
        <div class="ws-stat-val sv-admin">${w.admin ?? 0}</div>
        <div class="ws-stat-lbl">PWN3D!</div>
      </div>
    </div>
    <div class="ws-card-actions" onclick="event.stopPropagation()">
      ${isArch
        ? `<button class="btn btn--ghost" onclick="unarchiveProject(event,${w.id})" title="Activate"><span class="gi">&#8635;</span>ACTIVATE</button>`
        : `<button class="btn btn--warn" onclick="archiveProject(event,${w.id},'${safeName}')" title="Archive"><span class="gi">&#8964;</span>ARCHIVE</button>`
      }
      <button class="ws-del" onclick="deleteProject(event,${w.id},'${safeName}')" title="Move to Recycle"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 14h10l1-14"/><path d="M10 11v5M14 11v5"/></svg></button>
    </div>
  </div>`;
    }).join('');
  } catch(e) {
    container.innerHTML = '<div style="color:var(--a4);padding:24px 0">Error loading projects</div>';
  }
}

async function archiveProject(e, id, name) {
  e.stopPropagation();
  if (!confirm(`Archive project "${name}"?\n\nSMART Enrich will run in background.`)) return;
  const btn = e.currentTarget;
  const origHtml = btn.innerHTML;
  btn.innerHTML = '&#8987;'; btn.disabled = true;
  const r = await apiFetch(`/api/workspaces/${id}/archive`, {method:'POST'});
  if (r.ok) {
    await renderProjectList();
  } else {
    btn.innerHTML = origHtml; btn.disabled = false;
    alert('Error archiving project');
  }
}

async function unarchiveProject(e, id) {
  e.stopPropagation();
  const r = await apiFetch(`/api/workspaces/${id}/unarchive`, {method:'POST'});
  if (r.ok) await renderProjectList();
  else alert('Error activating project');
}

async function openProject(id) {
  const list = await loadWorkspaces();
  const found = list.find(w => w.id === id);
  if (!found) return;
  ws = found;

  WsRain.stop();
  document.getElementById('wsView').style.display  = 'none';
  document.getElementById('appView').style.display = 'flex';
  _setTopBar('app');
  if (typeof Notif !== 'undefined') Notif.start(ws);
  renderSidebar();
  if (typeof SbAnim !== 'undefined') SbAnim.init();
  page = 1; proto = 'ALL'; sub = 'all'; vulnFilter = 'all';
  srch = ''; document.getElementById('searchIn').value = '';
  globalSearchQ = ''; globalSearchMode = false;
  const gsi0 = document.getElementById('globalSearchIn'); if (gsi0) gsi0.value = '';
  andMode = false; andVulns.clear();
  acredMode = false; acredSub = 'creds';
  syncProtoUI(); updateSubRow();
  document.getElementById('pager').style.display = 'flex';
  await loadData();
  await loadStats();
  startLive();
  // Notify non-NXC modules about workspace change if they're currently active.
  // REMINDER: when adding a new lazy module, add a line here AND in Shell.activate() above (show/hide + onActivate call).
  // Also add a container div in collector/_frontend/_html.py. See penhub/app.py for the full checklist.
  if (Shell.isActive('toolbox'))    TBModule.onActivate(ws);
  if (Shell.isActive('hashkiller')) HKModule.onActivate(ws);
}

async function createProjectFromPage() {
  const name = prompt('New project name:');
  if (!name || !name.trim()) return;
  const r = await apiFetch('/api/workspaces', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:name.trim()})
  });
  if (r.status === 409) { alert(`Project "${name.trim()}" already exists.`); return; }
  if (!r.ok) { alert('Error creating project'); return; }
  await renderProjectList();
}

async function deleteProject(e, id, name) {
  e.stopPropagation();
  if (!confirm(`Move project "${name}" to Recycle Bin?\n\nData is preserved. You can restore or permanently delete it from the Recycle tab.`)) return;
  const btn = e.currentTarget;
  const origHtml = btn.innerHTML;
  btn.innerHTML = '&#8987;';
  btn.disabled = true;
  const r = await apiFetch(`/api/workspaces/${id}`, {method:'DELETE'});
  if (r.ok) {
    await renderProjectList();
  } else {
    btn.innerHTML = origHtml;
    btn.disabled = false;
    alert('Error moving project to recycle');
  }
}

async function restoreProject(e, id, target) {
  e.stopPropagation();
  const endpoint = target === 'active' ? 'restore_active' : 'restore_archive';
  const r = await apiFetch(`/api/workspaces/${id}/${endpoint}`, {method:'POST'});
  if (r.ok) await renderProjectList();
  else alert('Error restoring project');
}

async function permanentDeleteProject(e, id, name) {
  e.stopPropagation();
  if (!confirm(`PERMANENTLY delete "${name}"?\n\nAll data will be irreversibly removed: hosts, credentials, auth relations.\nThis cannot be undone.\n\nNote: if a new project is created with the same name, operator syncs will re-populate it — unless operators manually delete ~/.nxc/workspaces/${name}/ on their machines.`)) return;
  const btn = e.currentTarget;
  btn.disabled = true;
  const r = await apiFetch(`/api/workspaces/${id}/permanent`, {method:'DELETE'});
  if (r.ok) {
    await renderProjectList();
  } else {
    btn.disabled = false;
    alert('Error permanently deleting project');
  }
}

// ── Init ───────────────────────────────────────────────────────────────────
async function initApp() {
  if (window.__phAuthRoot) { window.__phAuthRoot.unmount(); window.__phAuthRoot = null; }
  document.getElementById('loginView').style.display = 'none';
  syncProtoUI(); updateSubRow();
  _setTopBar('projects');
  await showProjectsPage();
}
window.__phInitApp = initApp;

window.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadWorkspaces();
    const params   = new URLSearchParams(window.location.search);
    const wsParam  = params.get('ws');
    const modParam = params.get('module');
    if (wsParam) {
      const wsId = parseInt(wsParam);
      if (wsId) {
        document.getElementById('loginView').style.display = 'none';
        syncProtoUI(); updateSubRow();
        _setTopBar('projects');
        await openProject(wsId);
        if (ws) {
          // Activate requested module after project is open
          if      (modParam === 'hashkiller') { await Shell.activate('hashkiller'); }
          else if (modParam === 'toolbox')    { await Shell.activate('toolbox'); }
          return;
        }
      }
    }
    await initApp();
    // If ?module= was passed without ?ws=, activate after login+project selection
    if      (modParam === 'hashkiller' && ws) { await Shell.activate('hashkiller'); }
    else if (modParam === 'toolbox'    && ws) { await Shell.activate('toolbox'); }
  } catch(e) { /* not logged in */ }
});
