// ── Shell ─────────────────────────────────────────────────────────────────
// Shell manages module activation and lazy loading.
// NXC Collector (#appContent) is the primary module (always loaded).
// Other modules (HashKiller) are fetched once on first activation.
const Shell = {
  _active:  'nxc-collector',
  _loaded:  {'nxc-collector': true},

  async activate(moduleId) {
    // Show/hide module containers
    const nxcDiv = document.getElementById('appContent');
    const hkDiv  = document.getElementById('mod-hashkiller');
    const tbDiv  = document.getElementById('mod-toolbox');
    if (nxcDiv) nxcDiv.style.display = moduleId === 'nxc-collector' ? 'flex' : 'none';
    if (hkDiv)  hkDiv.style.display  = moduleId === 'hashkiller'    ? 'flex' : 'none';
    if (tbDiv)  tbDiv.style.display  = moduleId === 'toolbox'       ? 'flex' : 'none';

    // Lazy-load fragment if this is the first activation
    if (!this._loaded[moduleId]) {
      await this._loadFragment(moduleId);
    }
    this._active = moduleId;

    // If sidebar is collapsed and has an expanded active tile, animate it
    // collapsing before we rebuild the DOM (otherwise it would be instant).
    const sidebar = document.getElementById('sidebar');
    const nav     = document.getElementById('sidebarNav');
    if (sidebar && sidebar.classList.contains('collapsed') && nav) {
      const el = nav.querySelector('.sb-item.sb-nxc.active,.sb-item.sb-hk.active,.sb-item.sb-tb.active');
      if (el) {
        el.classList.remove('active');
        el.classList.add('sb-collapsing');
        await new Promise(r => setTimeout(r, 240));
      }
    }

    renderSidebar();

    // In collapsed mode, animate the new active tile expanding from cube size.
    // renderSidebar() inserts it already with .active (128px), so we briefly
    // strip the class, force a reflow, then restore it to trigger the transition.
    if (sidebar && sidebar.classList.contains('collapsed') && nav) {
      const newEl = nav.querySelector('.sb-item.sb-nxc.active,.sb-item.sb-hk.active,.sb-item.sb-tb.active');
      if (newEl) {
        newEl.classList.remove('active');
        void newEl.offsetHeight; // force paint at 34px
        newEl.classList.add('active'); // triggers height 34px → 128px transition
      }
    }

    // Per-module activation hooks
    if (moduleId === 'hashkiller') {
      HKModule.onActivate(ws);
    } else if (moduleId === 'toolbox') {
      TBModule.onActivate(ws);
    }
  },

  async _loadFragment(moduleId) {
    const container = document.getElementById('mod-' + moduleId);
    if (!container) return;
    container.innerHTML = '<div style="padding:24px;color:var(--fg2);font-size:11px;letter-spacing:1px">Loading...</div>';
    try {
      const r = await apiFetch('/api/shell/module/' + moduleId + '/ui');
      if (!r.ok) throw new Error('HTTP ' + r.status);
      container.innerHTML = await r.text();
      this._loaded[moduleId] = true;
    } catch(e) {
      container.innerHTML = '<div style="padding:24px;color:var(--a4)">Failed to load module: ' + e.message + '</div>';
    }
  },

  isActive(moduleId) { return this._active === moduleId; }
};

// ── Module Registry ────────────────────────────────────────────────────────
const ModuleRegistry = {
  _modules: [],
  register(mod) { this._modules.push({enabled:true, order:100, group:'General', colorCls:'', ...mod}); },
  disable(id)   { const m=this._modules.find(m=>m.id===id); if(m) m.enabled=false; },
  enable(id)    { const m=this._modules.find(m=>m.id===id); if(m) m.enabled=true; },
  getEnabled()  { return [...this._modules].filter(m=>m.enabled).sort((a,b)=>a.order-b.order); },
  getByGroup()  {
    const g={};
    for(const m of this.getEnabled()){if(!g[m.group])g[m.group]=[];g[m.group].push(m);}
    return g;
  }
};

// Platform modules — sidebar shows only top-level modules.
// Internal NXC views (Logged In, PWN3D!, SAM, etc.) are accessible via toolbar pills.
// To add a new module: see penhub/app.py for the full checklist.
ModuleRegistry.register({id:'nxc-collector',name:'NXC Collector',icon:'📡',group:'Modules',order:10,colorCls:'sb-nxc'});
ModuleRegistry.register({id:'hashkiller',   name:'HashKiller',   icon:'🗡',group:'Modules',order:20,colorCls:'sb-hk' });
ModuleRegistry.register({id:'toolbox',      name:'Toolbox',      icon:'⚙', group:'Modules',order:30,colorCls:'sb-tb' });

// ── Constants ──────────────────────────────────────────────────────────────
const LIVE_MS      = 5000;

// Sub-filters available per protocol
const PROTO_SUBS = {
  ALL:    ['all'],
  SMB:    ['loggedin','admin','dpapi','shares','samlsa','conf_checks'],
  LDAP:   ['hosts','creds'],
  WINRM:  ['loggedin','admin'],
  MSSQL:  ['loggedin','admin'],
  SSH:    ['loggedin','admin'],
  FTP:    ['loggedin','dirs'],
  RDP:    ['hosts'],
  VNC:    ['creds'],
  WMI:    ['creds'],
  NFS:    ['loggedin','shares'],
  CUSTOM: ['all'],
  HIDDEN: ['all'],  // visible only when manageMod=true
};
const SUB_LABELS = {
  all:'ALL', loggedin:'[+]', admin:'PWN3D!', dpapi:'DPAPI',
  sam:'SAM', lsa:'LSA', samlsa:'LSA+SAM',
  acred:'ACRED', creds:'CREDS', hosts:'HOSTS',
  shares:'SHARES', dirs:'DIRS', conf_checks:'CONF CHECKS',
};

// VULNS columns — MIRRORS collector/core/constants.py VULN_COLUMNS (slug + label + group).
// GUARD: keep this list and its order identical to the server's VULN_COLUMNS.
const VULN_COLUMNS = [
  {slug:'smbv1',          label:'SMBv1',          group:'remote'},
  {slug:'signing',        label:'Signing OFF',    group:'remote'},
  {slug:'spooler',        label:'Spooler',        group:'remote'},
  {slug:'ms17_010',       label:'MS17-010',       group:'remote'},
  {slug:'smbghost',       label:'SMBGhost',       group:'remote'},
  {slug:'printnightmare', label:'PrintNightmare', group:'remote'},
  {slug:'webdav',         label:'WebDAV',         group:'remote'},
  {slug:'nopac',          label:'noPac',          group:'remote'},
  {slug:'zerologon',      label:'Zerologon',      group:'remote'},
  {slug:'petitpotam',     label:'PetitPotam',     group:'coerce'},
  {slug:'printerbug',     label:'PrinterBug',     group:'coerce'},
  {slug:'dfscoerce',      label:'DFSCoerce',      group:'coerce'},
  {slug:'shadowcoerce',   label:'ShadowCoerce',   group:'coerce'},
  {slug:'wdigest',        label:'WDigest',        group:'admin'},
  {slug:'ntlmv1',         label:'NTLMv1',         group:'admin'},
  {slug:'runasppl',       label:'RunAsPPL',       group:'admin'},
  {slug:'uac',            label:'UAC',            group:'admin'},
];
const VULN_GROUPS = [
  {id:'remote', label:'REMOTE'},
  {id:'coerce', label:'COERCE'},
  {id:'admin',  label:'ADMIN-ONLY'},
];
const VULN_FILTERS = [
  {id:'all', label:'ALL'},
  ...VULN_COLUMNS.map(c => ({id:c.slug, label:c.label, group:c.group})),
];

// ── State ──────────────────────────────────────────────────────────────────
let ws              = null;
let proto           = 'ALL';
let sub             = 'all';
let vulnFilter      = 'all';
let srch            = '';
let hideGuest       = true;
let uniqMode        = true;
let hkBrutedMode    = true;
let andMode         = false;
let andVulns        = new Set();
let sortBy          = 'username';
let sortDir         = 'asc';
let acredMode       = false;
let acredSub        = 'creds';
let manageMod       = false;
let _preManageProto = 'ALL';   // restore point when manage-mod is toggled off
let page            = 1;
let pageSize        = 100;
let total           = 0;
let debTimer        = null;
let liveOn          = true;
let liveTimer       = null;
let globalSearchQ   = '';
let globalSearchMode = false;
let _sidebarCollapsed = false;

// dd.mm.yyyy hh:mm from ISO string
function formatDate(iso) {
  if (!iso) return '';
  const s = iso.replace('T', ' ').replace('Z', '').substring(0, 16);
  const [d, t] = s.split(' ');
  if (!d) return s;
  const [y, mo, day] = d.split('-');
  return `${day}.${mo}.${y} ${t||''}`;
}

// ── API fetch wrapper ──────────────────────────────────────────────────────
// All authenticated API calls go through apiFetch. A 401 shows the login view.
// We do NOT reload on 401 — that would cause an infinite loop on initial page
// load (DOMContentLoaded calls loadWorkspaces before any session exists).
async function apiFetch(url, opts) {
  const r = await fetch(url, opts);
  if (r.status === 401) {
    document.getElementById('loginView').style.display = 'flex';
    const bar = document.getElementById('topBar');
    if (bar) bar.style.display = 'none';
    throw new Error('401');
  }
  return r;
}

// ── Toast / copy utilities ─────────────────────────────────────────────────
let _toastTimer = null;
function _showToast() {
  const t = document.getElementById('copyToast');
  t.classList.add('show');
  if (_toastTimer) clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => t.classList.remove('show'), 900);
}

function _flashCopy(el) {
  el.classList.add('flash');
  setTimeout(() => el.classList.remove('flash'), 500);
  _showToast();
}

function _flashManage(el, type) {
  const cls = type === 'hide' ? 'flash-hide' : 'flash-restore';
  el.classList.add(cls);
  setTimeout(() => el.classList.remove(cls), 320);
}

function _flashRow(row, type) {
  if (!row) return;
  const cls = type === 'hide' ? 'row-strike-flash' : 'row-restore-flash';
  row.classList.add(cls);
}

function _copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => _copyFallback(text));
  } else {
    _copyFallback(text);
  }
}
function _copyFallback(text) {
  const el = document.createElement('textarea');
  el.value = text;
  el.style.cssText = 'position:fixed;opacity:0;top:0;left:0;width:1px;height:1px';
  document.body.appendChild(el);
  el.focus(); el.select();
  try { document.execCommand('copy'); } catch(e) {}
  document.body.removeChild(el);
}
