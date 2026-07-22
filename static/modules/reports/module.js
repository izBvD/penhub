// ── Reports Module ────────────────────────────────────────────────────────────
const RPModule = {
  _wsId: null,
  _nodes: [],     // last-rendered active nodes (for edit prefill)
  _modal: null,   // {mode, kind?, id?, labelRequired}
  _escHandler: null,

  onActivate(currentWs) {
    this._wsId = currentWs ? currentWs.id : null;
    this.loadTimeline();
  },

  _g(id) { return document.getElementById(id); },

  // ── Exports (block 2) ──────────────────────────────────────────────────────
  exportAllCreds() {
    if (this._wsId) window.open(`/api/export/allcred?workspace_id=${this._wsId}`, '_blank');
  },
  exportAllVulns() {
    if (this._wsId) window.open(`/api/export/xlsx?view=vulns&workspace_id=${this._wsId}`, '_blank');
  },
  exportLocalAdmins() {
    if (this._wsId) window.open(`/api/reports/local-admins/export?workspace_id=${this._wsId}`, '_blank');
  },

  // ── Timeline (block 1) ─────────────────────────────────────────────────────
  _CANON: {
    'First sync': 'first_sync',
    'First captured account': 'first_account',
    'First PWNED': 'first_pwned',
    'First Domain Admin': 'first_da',
  },
  _CANON_LABEL: {
    first_sync: 'First sync',
    first_account: 'First captured account',
    first_pwned: 'First PWNED',
    first_da: 'First Domain Admin',
  },

  _tsForInput(ts) { return ts ? ts.replace('Z', '') : ''; },
  _nowInput() {
    const d = new Date(), p = n => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`
         + `T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  },
  _clip(s, max) { s = s || ''; return s.length > max ? s.slice(0, max - 1) + '…' : s; },

  async loadTimeline() {
    if (!this._wsId) return;
    try {
      const r = await apiFetch(`/api/timeline?workspace_id=${this._wsId}`);
      if (r.ok) this.renderTimeline(await r.json());
    } catch (e) {}
  },

  renderTimeline(tl) {
    this._nodes = tl.nodes || [];
    const wrap = this._g('rpTimeline');
    if (!wrap) return;
    wrap.innerHTML = this._nodes.length
      ? this._svgMap(this._nodes)
      : '<div class="rp-tl-empty">No milestones yet — sync data or add a node.</div>';

    const pend = this._g('rpTimelinePending');
    pend.innerHTML = (tl.pending && tl.pending.length)
      ? `<div class="rp-tl-pending-hdr">Not reached:</div>`
        + tl.pending.map(p => `<div class="rp-pend-item" onclick="RPModule.setPending('${esc(p)}')">— ${esc(p)}</div>`).join('')
      : '';

    this._g('rpTimelineTotal').textContent = tl.total_str ? `Total: ${tl.total_str}` : '';
  },

  // ── "Treasure map" SVG render ──────────────────────────────────────────────
  _svgMap(nodes) {
    const W = 820, rowH = 96, top = 42, xL = 60, xR = 430;
    const pos = nodes.map((n, i) => ({ x: (i % 2 === 0) ? xL : xR, y: top + i * rowH + 18, n, i }));
    const H = top + nodes.length * rowH;

    let conn = '', bullets = '', elapsed = '', interact = '';
    for (let i = 1; i < pos.length; i++) {
      const a = pos[i - 1], b = pos[i];
      conn += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="rp-map-conn"/>`;
      if (b.n.elapsed_str) {
        const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        elapsed += `<text x="${mx + 8}" y="${my - 4}" class="rp-map-elapsed">${esc(b.n.elapsed_str)}</text>`;
      }
    }
    pos.forEach(p => {
      bullets += this._bulletHole(p.x, p.y, p.i);
      const click = p.n.kind === 'custom'
        ? `RPModule.editCustomNode(${p.n.id})`
        : `RPModule.editCanonical('${p.n.kind}')`;
      interact += `<g class="rp-map-node" onclick="${click}">`
        + `<circle cx="${p.x}" cy="${p.y}" r="17" fill="transparent"/>`
        + this._nodeText(p.x + 24, p.y, p.n)
        + `</g>`;
    });

    return `<svg viewBox="0 0 ${W} ${H}" class="rp-map" preserveAspectRatio="xMinYMin meet">`
      + `<defs>${this._roughFilter()}</defs>`
      + `<g filter="url(#rpRough)" class="rp-map-ink">${conn}${bullets}</g>`
      + `${elapsed}${interact}</svg>`;
  },

  _bulletHole(x, y, seed) {
    // deterministic pseudo-random cracks (stable per node index)
    const rnd = k => { const s = Math.sin((seed + 1) * 97.13 + k * 12.9898) * 43758.5453; return s - Math.floor(s); };
    let cracks = '';
    const n = 7;
    for (let k = 0; k < n; k++) {
      const ang = (k / n) * Math.PI * 2 + rnd(k) * 0.7;
      const r1 = 6, r2 = 11 + rnd(k + 10) * 8;
      const x1 = (x + Math.cos(ang) * r1).toFixed(1), y1 = (y + Math.sin(ang) * r1).toFixed(1);
      const x2 = (x + Math.cos(ang) * r2).toFixed(1), y2 = (y + Math.sin(ang) * r2).toFixed(1);
      cracks += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="rp-hole-crack"/>`;
    }
    return `<circle cx="${x}" cy="${y}" r="12" class="rp-hole-ring"/>`
      + cracks
      + `<circle cx="${x}" cy="${y}" r="5.5" class="rp-hole-core"/>`;
  },

  _nodeText(x, y, n) {
    const dt = n.ts ? formatDate(n.ts) : '';
    let t = `<text x="${x}" y="${y - 5}" class="rp-map-label">${esc(this._clip(n.label, 34))}</text>`
          + `<text x="${x}" y="${y + 9}" class="rp-map-time">${esc(dt)} UTC</text>`;
    if (n.detail) t += `<text x="${x}" y="${y + 22}" class="rp-map-detail">${esc(this._clip(n.detail, 42))}</text>`;
    return t;
  },

  _roughFilter() {
    return '<filter id="rpRough">'
      + '<feTurbulence type="turbulence" baseFrequency="0.02" numOctaves="2" seed="7" result="t"/>'
      + '<feDisplacementMap in="SourceGraphic" in2="t" scale="2.2" xChannelSelector="R" yChannelSelector="G"/>'
      + '</filter>';
  },

  downloadTimeline() {
    if (this._wsId) window.open(`/api/timeline/download?workspace_id=${this._wsId}`, '_blank');
  },

  // ── Modal editor ───────────────────────────────────────────────────────────
  _openModal(o) {
    this._modal = o;
    this._g('rpModalTitle').textContent = o.title;
    const lab = this._g('rpModalLabel');
    lab.value = o.label || '';
    lab.placeholder = o.labelPlaceholder || '';
    this._g('rpModalTime').value = o.time || this._nowInput();
    this._g('rpModalDetail').value = o.detail || '';
    this._setModalErr('');
    this._g('rpModalDel').style.display = (o.mode === 'custom-edit') ? '' : 'none';
    this._g('rpModalReset').style.display = (o.mode === 'canonical' && o.isOverride) ? '' : 'none';
    this._g('rpNodeModal').style.display = 'flex';
    lab.focus();
    if (!this._escHandler) {
      this._escHandler = (e) => { if (e.key === 'Escape') this.closeModal(); };
      document.addEventListener('keydown', this._escHandler);
    }
  },
  closeModal() {
    const m = this._g('rpNodeModal');
    if (m) m.style.display = 'none';
    this._modal = null;
    if (this._escHandler) { document.removeEventListener('keydown', this._escHandler); this._escHandler = null; }
  },
  onModalBackdrop(e) { if (e.target === this._g('rpNodeModal')) this.closeModal(); },
  _setModalErr(msg) { const el = this._g('rpModalErr'); if (el) el.textContent = msg || ''; },

  addCustomNode() {
    if (!this._wsId) return;
    this._openModal({ mode: 'custom-add', labelRequired: true, title: 'Add node',
                      label: '', time: this._nowInput(), detail: '' });
  },
  editCustomNode(id) {
    const n = this._nodes.find(x => x.id === id) || {};
    this._openModal({ mode: 'custom-edit', id, labelRequired: true, title: 'Edit node',
                      label: n.label || '', time: this._tsForInput(n.ts), detail: n.detail || '' });
  },
  editCanonical(kind) {
    const n = this._nodes.find(x => x.kind === kind) || {};
    const def = this._CANON_LABEL[kind] || '';
    this._openModal({ mode: 'canonical', kind, labelRequired: false, title: `Set: ${def}`,
                      isOverride: !!n.is_override,
                      label: (n.label && n.label !== def) ? n.label : '',
                      labelPlaceholder: `${def} (default)`,
                      time: this._tsForInput(n.ts), detail: n.detail || '' });
  },
  setPending(label) {
    const kind = this._CANON[label];
    if (kind) this.editCanonical(kind);
  },

  async saveModal() {
    const m = this._modal;
    if (!m) return;
    const label = this._g('rpModalLabel').value.trim();
    const ts = this._g('rpModalTime').value.trim();
    const detail = this._g('rpModalDetail').value.trim();
    if (!ts) { this._setModalErr('Please pick a date and time.'); return; }
    if (m.labelRequired && !label) { this._setModalErr('Name is required.'); return; }

    let url, method, payload;
    if (m.mode === 'custom-add') {
      url = '/api/timeline/custom'; method = 'POST';
      payload = { workspace_id: this._wsId, label, ts, detail };
    } else if (m.mode === 'custom-edit') {
      url = `/api/timeline/custom/${m.id}`; method = 'PUT';
      payload = { label, ts, detail };
    } else {
      url = '/api/timeline/canonical'; method = 'PUT';
      payload = { workspace_id: this._wsId, kind: m.kind, label: label || null, ts, detail };
    }

    try {
      const r = await apiFetch(url, { method,
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      if (!r.ok) {
        let msg = `Save failed (HTTP ${r.status}).`;
        try { const j = await r.json(); if (j && j.detail) msg = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail); } catch (e) {}
        this._setModalErr(msg);
        return;
      }
    } catch (e) {
      this._setModalErr('Network error — please try again.');
      return;
    }
    this.closeModal();
    this.loadTimeline();
  },

  async deleteFromModal() {
    if (!this._modal || this._modal.mode !== 'custom-edit') return;
    if (!confirm('Delete this custom node?')) return;
    await apiFetch(`/api/timeline/custom/${this._modal.id}`, { method: 'DELETE' });
    this.closeModal();
    this.loadTimeline();
  },
  async resetFromModal() {
    if (!this._modal || this._modal.mode !== 'canonical') return;
    if (!confirm('Reset this milestone to the auto-detected value?')) return;
    await apiFetch(`/api/timeline/canonical?workspace_id=${this._wsId}&kind=${this._modal.kind}`, { method: 'DELETE' });
    this.closeModal();
    this.loadTimeline();
  },
};
window.RPModule = RPModule;
