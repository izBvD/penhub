// ── Toolbox Module ────────────────────────────────────────────────────────────
const TBModule = {
  _wsId:       null,
  _serverInfo: null,  // cached from /api/toolbox/server-info

  _g(id) { return document.getElementById(id); },

  // ── Lifecycle ────────────────────────────────────────────────────────────
  async onActivate(currentWs) {
    this._wsId = currentWs ? currentWs.id : null;
    // Load server info every activation (workspace name can change)
    await this._fetchServerInfo();
    if (this._wsId) {
      await this._loadWsConfig();
      // Reset DAL fields on every workspace activation — domain context is workspace-specific
      const dalDom = this._g('dalDomain');
      if (dalDom) dalDom.value = '';
      const dalRes = this._g('dalResult');
      if (dalRes) dalRes.textContent = '';
      await this.dalLoadPlaceholder();
    }
    this._setupBhListeners();
  },

  // ── Server info ──────────────────────────────────────────────────────────
  async _fetchServerInfo() {
    try {
      const q = this._wsId ? `?workspace_id=${this._wsId}` : '';
      const r = await apiFetch(`/api/toolbox/server-info${q}`);
      if (r.ok) this._serverInfo = await r.json();
    } catch(e) {}
  },

  // ── BH workspace config ──────────────────────────────────────────────────
  async _loadWsConfig() {
    if (!this._wsId) return;
    try {
      const r = await apiFetch(`/api/toolbox/ws-config/${this._wsId}`);
      if (!r.ok) return;
      const cfg = await r.json();
      const s = (id, v) => { const el = this._g(id); if (el && v) el.value = v; };
      s('tbBhIp',    cfg.bh_ip);
      s('tbBhLogin', cfg.bh_login);
      s('tbBhPass',  cfg.bh_pass);
      s('tbBhPort',  cfg.bh_port);
      const sel = this._g('tbBhEnable');
      if (sel && cfg.bh_enable != null) sel.value = cfg.bh_enable;
    } catch(e) {}
  },

  _setupBhListeners() {
    // Auto-save BH config on any field change
    ['tbBhIp','tbBhLogin','tbBhPass','tbBhPort','tbBhEnable'].forEach(id => {
      const el = this._g(id);
      if (el && !el._tbListener) {
        el._tbListener = true;
        el.addEventListener('change', () => this._saveBhConfig());
      }
    });
  },

  async _saveBhConfig() {
    if (!this._wsId) return;
    const v = id => this._g(id)?.value ?? '';
    const body = {
      bh_ip:     v('tbBhIp'),
      bh_login:  v('tbBhLogin'),
      bh_pass:   v('tbBhPass'),
      bh_port:   v('tbBhPort'),
      bh_enable: v('tbBhEnable'),
    };
    try {
      await apiFetch(`/api/toolbox/ws-config/${this._wsId}`, {
        method:  'PUT',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify(body),
      });
    } catch(e) {}
  },

  // ── Block 1: Custom import ────────────────────────────────────────────────
  downloadCustomImportTemplate() { window.open('/api/toolbox/custom-import/template', '_blank'); },

  importCustomFile() {
    if (!this._wsId) { this._setMsg('customImportResult', 'Select a workspace first.', 'err'); return; }
    const fi = this._g('customImportFile');
    if (!fi) return;
    fi.value = '';
    fi.onchange = () => this._doCustomImport(fi.files[0]);
    fi.click();
  },

  async _doCustomImport(file) {
    if (!file || !this._wsId) return;
    this._setMsg('customImportResult', 'Uploading…', 'info');
    const fd = new FormData();
    fd.append('workspace_id', String(this._wsId));
    fd.append('file', file);
    try {
      const r = await apiFetch('/api/toolbox/custom-import/upload', { method: 'POST', body: fd });
      const d = await r.json();
      if (!r.ok) { this._setMsg('customImportResult', d.detail || 'Error ' + r.status, 'err'); return; }
      const parts = [];
      if (d.added)           parts.push(`Added: ${d.added}`);
      if (d.enriched)        parts.push(`Enriched: ${d.enriched}`);
      if (d.already_existed) parts.push(`Already existed: ${d.already_existed}`);
      if (d.skipped)         parts.push(`Skipped: ${d.skipped}`);
      let msg = parts.length ? parts.join(' · ') : 'No changes';
      let cls = (d.added || d.enriched) ? 'ok' : 'info';
      // Header mismatch feedback
      const mh = d.matched_headers || [], uh = d.unrecognized_headers || [];
      if (mh.length === 0 && uh.length > 0) {
        msg += ` — no columns matched. Found: [${uh.join(', ')}]. Expected: Login, Password, Proto…`;
        cls = 'err';
      } else if (uh.length > 0) {
        msg += ` — unrecognized columns ignored: ${uh.join(', ')}`;
      }
      this._setMsg('customImportResult', msg, cls);
    } catch(e) { this._setMsg('customImportResult', 'Error: ' + e.message, 'err'); }
  },

  // ── Block 2: NXCExtractor downloads ─────────────────────────────────────
  downloadLogins()       { if (this._wsId) window.open(`/api/toolbox/logins?workspace_id=${this._wsId}`,        '_blank'); },
  downloadPasswords()    { if (this._wsId) window.open(`/api/toolbox/passwords?workspace_id=${this._wsId}`,     '_blank'); },
  downloadHashes()       { if (this._wsId) window.open(`/api/toolbox/hashes?workspace_id=${this._wsId}`,        '_blank'); },
  downloadIPs()          { if (this._wsId) window.open(`/api/toolbox/ips?workspace_id=${this._wsId}`,           '_blank'); },
  downloadSprayArchive() { if (this._wsId) window.open(`/api/toolbox/spray-archive?workspace_id=${this._wsId}`, '_blank'); },
  downloadNotPwndIps()   { if (this._wsId) window.open(`/api/toolbox/not-pwnd-ips?workspace_id=${this._wsId}`,  '_blank'); },

  // ── Block 3: Scripts download ────────────────────────────────────────────
  downloadScripts() { window.open('/api/toolbox/scripts', '_blank'); },

  // ── Block 3: Copy config strings ─────────────────────────────────────────
  copyConfig() {
    const op = (this._g('tbOperator')?.value || '').trim();
    if (!op) { this._setMsg('copyConfigResult', 'Enter operator name first.', 'err'); return; }
    const si = this._serverInfo;
    if (!si) { this._setMsg('copyConfigResult', 'Server info not available.', 'err'); return; }
    const ws   = si.ws_name || 'WORKSPACE';
    const pass = (si.password || '').replace(/!/g, '\\!');
    const str = `nxc_collector -ws --server ${si.server_url} --port ${si.port} --pass "${pass}" --workspace ${ws} --operator ${op}`;
    _copyText(str);
    this._setMsg('copyConfigResult', 'Copied to clipboard.', 'ok');
  },

  copyBhConfig() {
    const ip = (this._g('tbBhIp')?.value || '').trim();
    if (!ip) { this._setMsg('copyBhConfigResult', 'Enter BloodHound IP first.', 'err'); return; }
    const login  = this._g('tbBhLogin')?.value  || 'neo4j';
    const pass   = (this._g('tbBhPass')?.value   || 'bloodhoundcommunityedition').replace(/!/g, '\\!');
    const port   = this._g('tbBhPort')?.value   || '7687';
    const enable = this._g('tbBhEnable')?.value || 'true';
    const str = `nxc_collector --bh-setup --bh-ip ${ip} --bh-login ${login} --bh-pass "${pass}" --bh-port ${port} --bh-enable ${enable}`;
    _copyText(str);
    this._saveBhConfig();
    this._setMsg('copyBhConfigResult', 'Copied to clipboard.', 'ok');
  },

  // ── Block 2: Domain Admin Watchlist ─────────────────────────────────────
  async dalLoadPlaceholder() {
    if (!this._wsId) return;
    try {
      const r = await apiFetch(`/api/domain_admin_list/top_domain?workspace_id=${this._wsId}`);
      if (!r.ok) return;
      const d = await r.json();
      const el = this._g('dalDomain');
      // GUARD: threshold is enforced server-side (data.py get_top_domain); d.domain is null when not met — don't re-add count check here
      if (el) el.value = d.domain || 'domain.local.ru';
    } catch(e) {}
  },

  dalUpload() {
    const fi = this._g('dalFileInput');
    if (!fi) return;
    fi.value = '';
    fi.onchange = () => this._dalProcessFile(fi.files[0]);
    fi.click();
  },

  async dalAddOne() {
    if (!this._wsId) return;
    const domain   = (this._g('dalDomain')?.value   || '').trim();
    const username = (this._g('dalUsername')?.value || '').trim();
    if (!username) { this._setMsg('dalResult', 'Enter username first.', 'err'); return; }
    if (!domain)   { this._setMsg('dalResult', 'Enter domain first.', 'err');   return; }
    try {
      const r = await apiFetch('/api/domain_admin_list/upload', {
        method:  'POST',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify({workspace_id: this._wsId, domain, usernames: [username]}),
      });
      if (!r.ok) { this._setMsg('dalResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      if (d.added > 0) {
        this._setMsg('dalResult', `Added: ${username}`, 'ok');
        this._g('dalUsername').value = '';
      } else {
        this._setMsg('dalResult', `${username} already in watchlist.`, 'warn');
      }
    } catch(e) { this._setMsg('dalResult', 'Error: ' + e.message, 'err'); }
  },

  async _dalProcessFile(file) {
    if (!file || !this._wsId) return;
    const domain = (this._g('dalDomain')?.value || '').trim();
    if (!domain) { this._setMsg('dalResult', 'Enter domain name first.', 'err'); return; }
    const text = await file.text();
    const lines = text.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    const usernames = lines.filter(l => l.length <= 50);
    const skippedLen = lines.length - usernames.length;
    if (!usernames.length) {
      this._setMsg('dalResult', 'No valid usernames found in file.', 'err');
      return;
    }
    try {
      const r = await apiFetch('/api/domain_admin_list/upload', {
        method:  'POST',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify({workspace_id: this._wsId, domain, usernames}),
      });
      if (!r.ok) { this._setMsg('dalResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      const alreadyExisted = usernames.length - d.added;
      let msg = d.added > 0 ? `Added: ${d.added}` : 'All already in watchlist';
      if (d.added > 0 && alreadyExisted > 0) msg += `, already existed: ${alreadyExisted}`;
      if (skippedLen > 0) msg += `, skipped (>50 chars): ${skippedLen}`;
      const cls = d.added > 0 ? 'ok' : 'warn';
      this._setMsg('dalResult', msg, cls);
    } catch(e) { this._setMsg('dalResult', 'Error: ' + e.message, 'err'); }
  },

  // ── How-to toggle (suffix '1' = custom import block, '2' = nxcextractor block) ──
  toggleHowTo(suffix) {
    const body  = this._g('tbHowToBody' + suffix);
    const arrow = this._g('tbHowArrow'  + suffix);
    if (!body) return;
    body.hidden = !body.hidden;
    if (arrow) arrow.style.transform = body.hidden ? '' : 'rotate(90deg)';
  },

  // ── Message helper (mirrors hashkiller pattern) ──────────────────────────
  _setMsg(id, msg, cls) {
    const el = this._g(id);
    if (el) { el.textContent = msg; el.className = 'result-msg' + (cls ? ' ' + cls : ''); }
  },

  // ── Error toast ──────────────────────────────────────────────────────────
  _showErr() {
    const t = this._g('tbErrToast');
    if (!t) return;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 1200);
  },
};
