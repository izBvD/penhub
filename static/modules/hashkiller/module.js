// ── HashKiller Module ─────────────────────────────────────────────────────────
const _HK_TASK_KEY = 'hk_active_task_id';

const HKModule = {
  _wsId:              null,
  _pollTimer:         null,
  _activeTaskId:      null,
  _pendingDelete:     null,  // value to delete after confirmation
  _importStatsBefore: null,  // pairs total before a server-file import task starts

  _g(id) { return document.getElementById(id); },
  _esc(s) { return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); },

  // ── Lifecycle ────────────────────────────────────────────────────────────
  async onActivate(currentWs) {
    this._wsId = currentWs ? currentWs.id : null;
    this._setBusy(!!this._activeTaskId);
    this.loadStats();
    if (!this._activeTaskId) {
      const saved = localStorage.getItem(_HK_TASK_KEY);
      if (saved) await this._tryReconnect(saved);
    }
  },

  async _tryReconnect(taskId) {
    try {
      const r = await fetch(`/api/hk/task/${taskId}`);
      if (!r.ok) { localStorage.removeItem(_HK_TASK_KEY); return; }
      const d = await r.json();
      if (d.status !== 'running') { localStorage.removeItem(_HK_TASK_KEY); return; }
      this._activeTaskId = taskId;
      this._setBusy(true);
      this._setMsg('killResult', 'Reconnected to running task…', 'info');
      if (this._pollTimer) clearInterval(this._pollTimer);
      this._pollTimer = setInterval(() => this._pollTask(taskId), 1200);
    } catch(e) { localStorage.removeItem(_HK_TASK_KEY); }
  },

  // ── Stats ────────────────────────────────────────────────────────────────
  async loadStats() {
    try {
      const r = await fetch('/api/hk/stats');
      if (!r.ok) return;
      const d = await r.json();
      const set = (id, v) => { const el = this._g(id); if (el) el.textContent = Number(v).toLocaleString(); };
      set('statTotal', d.total);
      set('statSmart', d.smart);
      // warning is expensive (full-table GROUP BY on 120M rows) — fetch lazily
      // without blocking the fast stats above; shows '…' until ready
      const warnEl = this._g('statWarn');
      if (warnEl) warnEl.textContent = '…';
      fetch('/api/hk/stats/warning')
        .then(r => r.ok ? r.json() : null)
        .then(d => { if (d != null && warnEl) warnEl.textContent = Number(d.warning).toLocaleString(); })
        .catch(() => { if (warnEl) warnEl.textContent = '?'; });
    } catch(e) {}
  },

  _saveStatsBefore() {
    const el = this._g('statTotal');
    const n = parseInt((el?.textContent || '').replace(/[^0-9]/g, ''), 10);
    this._importStatsBefore = isNaN(n) ? null : n;
  },

  _deltaMsg() {
    if (this._importStatsBefore === null) return '';
    const el = this._g('statTotal');
    const n = parseInt((el?.textContent || '').replace(/[^0-9]/g, ''), 10);
    if (isNaN(n)) return '';
    const delta = n - this._importStatsBefore;
    if (delta === 0) return '';
    return `  |  total: ${this._importStatsBefore.toLocaleString()} → ${n.toLocaleString()} (+${delta.toLocaleString()})`;
  },

  // ── File label helper ────────────────────────────────────────────────────
  onFileSelected(input, labelId) {
    const fn  = input.files[0]?.name || '';
    const el  = this._g(labelId);
    if (el) el.textContent = fn ? ('&#128196; ' + fn) : '';
  },

  // ── Import ───────────────────────────────────────────────────────────────
  async doImport() {
    const text = (this._g('importText')?.value || '').trim();
    const fi   = this._g('importFile');
    const file = fi?.files[0];
    if (!text && !file) { this._setMsg('importResult', 'Paste text or select a file first', 'err'); return; }
    const btn = this._g('importBtn');
    if (btn) btn.disabled = true;
    this._setMsg('importResult', 'Importing…', 'info');
    try {
      const fd = new FormData();
      if (text) fd.append('text', text);
      if (file) fd.append('file', file);
      const r = await fetch('/api/hk/import', {method:'POST', body:fd});
      if (!r.ok) { this._setMsg('importResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      if (d.total_lines === 0) {
        this._setMsg('importResult', 'Nothing to import — paste text or upload a potfile', 'err');
        return;
      }
      const parts = [`added: ${d.added}`, `skipped: ${d.skipped}`];
      if (d.warned   > 0) parts.push(`⚠ conflicts (warning): ${d.warned}`);
      if (d.invalid  > 0) parts.push(`invalid lines: ${d.invalid} — expected: hash:plain or LM:NT:user:plain`);
      const cls = d.warned > 0 ? 'warn' : d.added > 0 ? 'ok' : 'info';
      this._setMsg('importResult', parts.join('  |  '), cls);
      if (d.added > 0 || d.warned > 0) this.loadStats();
    } catch(e) {
      this._setMsg('importResult', 'Error: ' + e.message, 'err');
    } finally {
      if (btn) btn.disabled = false;
    }
  },

  // ── Import server-side file (hk_inbox/large.potfile) ──────────────────────
  async importServerFile(ramKiller = false) {
    let st;
    try {
      const r = await fetch('/api/hk/import-file/check');
      if (!r.ok) { this._setMsg('importResult', 'Server error: ' + r.status, 'err'); return; }
      st = await r.json();
    } catch(e) { this._setMsg('importResult', 'Error: ' + e.message, 'err'); return; }
    if (!st.exists) {
      this._setMsg('importResult', 'No server file found at hk_inbox/large.potfile', 'err');
      return;
    }
    const mb = (st.size / (1024 * 1024)).toFixed(1);
    const extra = ramKiller
      ? '\n\n💥 RAM-KILLER: uses most of the free RAM during import for max speed (kept safe — leaves headroom).'
      : '';
    if (!confirm(`Found ${st.name} (${mb} MB) on the server.\n\nImport it into the HashKiller DB?${extra}`)) return;
    this._setMsg('importResult',
      (ramKiller ? 'Importing (RAM-killer)…' : 'Importing server file…') + ' progress shown in ACTIONS below.', 'info');
    this._saveStatsBefore();
    this._startTask('/api/hk/import-file/run' + (ramKiller ? '?ram=1' : ''), 'POST');
  },

  // ── Upload DB ────────────────────────────────────────────────────────────
  async doUploadDb() {
    const fi   = this._g('uploadDbFile');
    const file = fi?.files[0];
    if (!file) return;
    this._setMsg('uploadResult', 'Uploading…', 'info');
    try {
      const fd = new FormData();
      fd.append('file', file);
      const r = await fetch('/api/hk/upload-db', {method:'POST', body:fd});
      if (r.status === 422) {
        const e = await r.json();
        this._setMsg('uploadResult', '⚠ ' + (e.detail || 'Invalid format'), 'err');
        return;
      }
      if (!r.ok) { this._setMsg('uploadResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      const parts = [`added: ${d.added}`, `skipped: ${d.skipped}`];
      if (d.warned > 0) parts.push(`⚠ conflicts (warning): ${d.warned}`);
      const cls = d.warned > 0 ? 'warn' : d.added > 0 ? 'ok' : 'info';
      this._setMsg('uploadResult', parts.join('  |  '), cls);
      if (d.added > 0 || d.warned > 0) this.loadStats();
    } catch(e) {
      this._setMsg('uploadResult', 'Error: ' + e.message, 'err');
    }
  },

  // ── Task buttons ─────────────────────────────────────────────────────────
  async doKill() {
    if (!this._wsId) return;
    this._startTask(`/api/hk/kill/${this._wsId}`, 'POST');
  },

  async syncBrutforced() {
    if (!this._wsId) return;
    const btn = this._g('syncBfBtn');
    if (btn) btn.disabled = true;
    this._setMsg('killResult', 'Checking…', 'info');
    try {
      const r = await fetch(`/api/hk/sync-brutforced/${this._wsId}`, {method: 'POST'});
      if (!r.ok) { this._setMsg('killResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      const msg = d.cleared > 0
        ? `Cleared ${d.cleared} stale Brutforced entries`
        : 'All Brutforced entries are valid — nothing to clear';
      this._setMsg('killResult', msg, d.cleared > 0 ? 'ok' : 'info');
    } catch(e) {
      this._setMsg('killResult', 'Error: ' + e.message, 'err');
    } finally {
      if (btn) btn.disabled = !this._wsId;
    }
  },

  async doSmartEnrich() {
    if (!this._wsId) return;
    this._startTask(`/api/hk/smart-enrich/${this._wsId}`, 'POST');
  },

  async doKillAll() {
    if (!confirm('Run “Kill Them All” for ALL workspaces?\n\nThis fills the Brutforced column across every workspace using the current HK database.')) return;
    this._startTask('/api/hk/kill-all', 'POST');
  },

  async _startTask(url, method) {
    this._setBusy(true);
    this._setMsg('killResult', '', '');
    try {
      const r = await fetch(url, {method});
      if (!r.ok) { this._setBusy(false); this._setMsg('killResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      this._activeTaskId = d.task_id;
      localStorage.setItem(_HK_TASK_KEY, d.task_id);
      if (this._pollTimer) clearInterval(this._pollTimer);
      this._pollTimer = setInterval(() => this._pollTask(d.task_id), 1200);
    } catch(e) {
      this._setBusy(false);
      this._setMsg('killResult', 'Error: ' + e.message, 'err');
    }
  },

  // ── Task polling ──────────────────────────────────────────────────────────
  async _pollTask(taskId) {
    if (taskId !== this._activeTaskId) { clearInterval(this._pollTimer); return; }
    try {
      const r = await fetch(`/api/hk/task/${taskId}`);
      if (!r.ok) {
        if (r.status === 404) {
          clearInterval(this._pollTimer);
          this._activeTaskId = null;
          localStorage.removeItem(_HK_TASK_KEY);
          this._setBusy(false);
          this._setMsg('killResult', 'Connection lost — server restarted', 'err');
        }
        return;
      }
      const d = await r.json();

      // Update progress bar
      if (d.progress && d.progress.total > 0) {
        const pct = Math.round(d.progress.current / d.progress.total * 100);
        this._setProgress(d.progress.current, d.progress.total, pct);
      }

      if (d.status === 'done' || d.status === 'cancelled') {
        clearInterval(this._pollTimer);
        this._activeTaskId = null;
        this._setBusy(false);
        const res = d.result;
        let msg = '';
        if (d.status === 'cancelled')              msg = 'Cancelled.';
        else if (res && 'matched' in res)          msg = `matched: ${res.matched}  →  updated: ${res.updated}${res.cancelled ? ' (cancelled)' : ''}`;
        else if (res && 'added' in res)          { msg = `added to HK DB: ${res.added}  |  already existed: ${res.skipped}`;
                                                   if (res.warned)  msg += `  |  ⚠ conflicts: ${res.warned}`;
                                                   if (res.invalid) msg += `  |  invalid: ${res.invalid}`;
                                                   if (res.seconds != null) msg += `  |  ${res.seconds}s` + (res.rate ? ` (${res.rate.toLocaleString()}/s)` : '');
                                                   if (res.ram_mb)  msg += `  |  cache ${res.ram_mb}MB`; }
        else if (res && 'total_matched' in res)    msg = `total matched: ${res.total_matched}  →  total updated: ${res.total_updated}`;
        else                                       msg = JSON.stringify(res);
        localStorage.removeItem(_HK_TASK_KEY);
        this._setMsg('killResult', msg, d.status === 'cancelled' ? 'info' : 'ok');
        await this.loadStats();
        const delta = this._deltaMsg();
        if (delta) { const el = this._g('killResult'); if (el) el.textContent += delta; }
        this._importStatsBefore = null;
      } else if (d.status === 'error') {
        clearInterval(this._pollTimer);
        this._activeTaskId = null;
        localStorage.removeItem(_HK_TASK_KEY);
        this._setBusy(false);
        this._setMsg('killResult', 'Error: ' + (d.error || 'unknown'), 'err');
      }
    } catch(e) {}
  },

  cancelTask() {
    if (!this._activeTaskId) return;
    fetch(`/api/hk/task/${this._activeTaskId}`, {method:'DELETE'}).catch(() => {});
    this._setMsg('killResult', 'Cancelling…', 'info');
  },

  // ── Busy state ────────────────────────────────────────────────────────────
  _setBusy(busy) {
    ['killBtn','enrichBtn','killAllBtn'].forEach(id => {
      const b = this._g(id); if (b) b.disabled = busy || (id !== 'killAllBtn' && !this._wsId);
    });
    this._g('exportBtn')  && (this._g('exportBtn').disabled  = busy || !this._wsId);
    this._g('syncBfBtn')  && (this._g('syncBfBtn').disabled  = busy || !this._wsId);
    const prog = this._g('taskProgress');
    if (prog) prog.hidden = !busy;
    if (!busy) {
      const bar = this._g('progressBar');
      if (bar) { bar.style.width = '0%'; }
      const txt = this._g('progressText');
      if (txt) txt.textContent = 'Processing…';
    }
  },

  _setProgress(current, total, pct) {
    const bar = this._g('progressBar');
    if (bar) bar.style.width = pct + '%';
    const txt = this._g('progressText');
    if (txt) txt.textContent = `Processing: ${current} / ${total}`;
  },

  // ── Exports ───────────────────────────────────────────────────────────────
  exportHashes()  { if (this._wsId) window.open(`/api/hk/export-hashes/${this._wsId}`, '_blank'); },
  exportSmart()   { window.open('/api/hk/export-smart',   '_blank'); },
  exportWarning() { window.open('/api/hk/export-warning', '_blank'); },
  dumpDb()        { window.open('/api/hk/dump-db',        '_blank'); },

  // ── Delete pair ───────────────────────────────────────────────────────────
  async deleteByValue() {
    const input = this._g('deleteInput');
    const val   = (input?.value || '').trim();
    if (!val) { this._setMsg('deleteResult', 'Enter a hash, plaintext, or hash:plain value', 'err'); return; }

    this._setMsg('deleteResult', 'Searching…', 'info');
    this._hideDeleteConfirm();

    try {
      const p = new URLSearchParams({value: val});
      const r = await fetch('/api/hk/find?' + p);
      if (!r.ok) { this._setMsg('deleteResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();

      const byHash  = d.by_hash  || [];
      const byPlain = d.by_plain || [];

      if (!byHash.length && !byPlain.length) {
        this._setMsg('deleteResult', 'Not found in HK database', 'info');
        return;
      }

      this._setMsg('deleteResult', '', '');
      this._pendingDelete = val;
      this._showDeleteConfirm(byHash, byPlain);
    } catch(e) {
      this._setMsg('deleteResult', 'Error: ' + e.message, 'err');
    }
  },

  _showDeleteConfirm(byHash, byPlain) {
    const list = this._g('deleteConfirmList');
    if (!list) return;
    let html = '';
    const row = r => {
      const flags = [];
      if (r.smart)   flags.push('<span class="tag-smart">SMART</span>');
      if (r.warning) flags.push('<span class="tag-warn">⚠</span>');
      return `<div class="confirm-row">${this._esc(r.nt_hash)}<span class="confirm-sep">:</span>${this._esc(r.plaintext)} ${flags.join(' ')}</div>`;
    };
    if (byHash.length) {
      html += '<div class="confirm-group-label">By hash:</div>';
      byHash.forEach(r => { html += row(r); });
    }
    if (byPlain.length) {
      html += '<div class="confirm-group-label" style="margin-top:6px">By plaintext:</div>';
      byPlain.forEach(r => { html += row(r); });
    }
    list.innerHTML = html;
    const box = this._g('deleteConfirm');
    if (box) box.hidden = false;
  },

  async confirmDelete() {
    if (!this._pendingDelete) return;
    const val = this._pendingDelete;
    this._pendingDelete = null;
    this._hideDeleteConfirm();
    try {
      const p = new URLSearchParams({value: val});
      const r = await fetch('/api/hk/pair?' + p, {method:'DELETE'});
      if (!r.ok) { this._setMsg('deleteResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      if (d.deleted > 0) {
        this._setMsg('deleteResult', `Deleted ${d.deleted} pair(s)`, 'ok');
        const inp = this._g('deleteInput'); if (inp) inp.value = '';
        this.loadStats();
      } else {
        this._setMsg('deleteResult', 'Not found (already deleted?)', 'info');
      }
    } catch(e) { this._setMsg('deleteResult', 'Error: ' + e.message, 'err'); }
  },

  cancelDelete() {
    this._pendingDelete = null;
    this._hideDeleteConfirm();
    this._setMsg('deleteResult', 'Cancelled', 'info');
  },

  // ── Bulk delete from file (e.g. the EXPORT WARNING file) ──────────────────
  async deleteFromFile(input) {
    const file = input.files[0];
    if (!file) return;
    const kb = (file.size / 1024).toFixed(0);
    if (!confirm(`Delete every hash / pair listed in "${file.name}" (${kb} KB) from the HashKiller DB?\n\nThis cannot be undone.`)) {
      input.value = '';
      return;
    }
    this._setMsg('deleteResult', 'Deleting from file…', 'info');
    try {
      const fd = new FormData();
      fd.append('file', file);
      const r = await fetch('/api/hk/delete-file', {method:'POST', body:fd});
      if (r.status === 413) { this._setMsg('deleteResult', 'File too large — max 50 MB', 'err'); return; }
      if (!r.ok) { this._setMsg('deleteResult', 'Server error: ' + r.status, 'err'); return; }
      const d = await r.json();
      this._setMsg('deleteResult', `Deleted ${d.deleted} record(s) from ${d.lines} line(s)`, 'ok');
      this.loadStats();
    } catch(e) {
      this._setMsg('deleteResult', 'Error: ' + e.message, 'err');
    } finally {
      input.value = '';
    }
  },

  _hideDeleteConfirm() {
    const box = this._g('deleteConfirm');
    if (box) { box.hidden = true; }
    const list = this._g('deleteConfirmList');
    if (list) list.innerHTML = '';
  },

  // ── How-to toggle ─────────────────────────────────────────────────────────
  toggleHowTo() {
    const body  = this._g('howToBody');
    const arrow = this._g('howArrow');
    if (!body) return;
    body.hidden = !body.hidden;
    if (arrow) arrow.style.transform = body.hidden ? '' : 'rotate(90deg)';
  },

  // ── Generic message helper ────────────────────────────────────────────────
  _setMsg(id, msg, cls) {
    const el = this._g(id);
    if (el) { el.textContent = msg; el.className = 'result-msg' + (cls ? ' ' + cls : ''); }
  },
};
