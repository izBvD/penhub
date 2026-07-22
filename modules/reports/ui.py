"""Reports UI fragment — lazy-loaded HTML injected by Shell on first activation."""

_RP_FRAGMENT = r"""
<div style="display:flex;flex-direction:column;width:100%;height:100%;overflow:hidden">

  <!-- Header -->
  <div class="toolbar row0" style="flex-shrink:0;gap:10px;flex-wrap:wrap">
    <span style="color:var(--a1);font-weight:700;font-size:13px;letter-spacing:2px">&#128196; REPORTS</span>
  </div>

  <!-- Scrollable body -->
  <div class="tb-content">

    <!-- BLOCK 1: TIMELINE -->
    <div class="card">
      <div class="tb-block-hdr hdr-green">&#128197; TIMELINE</div>
      <div class="tb-hint" style="margin-bottom:10px">
        Engagement route &mdash; canonical milestones auto-detected where possible,
        editable, plus your own custom nodes. Times are UTC.
      </div>
      <div class="rp-tl-actions">
        <button class="btn tb-dl-btn" onclick="RPModule.addCustomNode()"
                title="Add a custom timeline node">&#43; ADD NODE</button>
      </div>
      <div id="rpTimeline" class="rp-timeline"></div>
      <div id="rpTimelinePending" class="rp-tl-pending"></div>
      <div id="rpTimelineTotal" class="rp-tl-total"></div>
    </div>

    <!-- BLOCK: LOCAL ADMIN FOUNDER -->
    <div class="card">
      <div class="tb-block-hdr hdr-cyan">&#128187; LOCAL ADMIN FOUNDER</div>
      <div class="tb-hint" style="margin-bottom:8px">
        Auto-detects <strong style="color:var(--fg0)">local admins</strong>
        (operator-marked + admin-proven on SMB). A second section below lists
        <strong style="color:var(--fg0)">local credentials whose secret repeats
        across &ge;2 machines</strong> (lateral-movement candidates). XLSX, two sections.
      </div>
      <div class="actions-row">
        <button class="btn tb-dl-btn" onclick="RPModule.exportLocalAdmins()"
                title="Detect and download local admin accounts as XLSX">
          &#128187; LOCAL ADMINS&#8595;</button>
      </div>
    </div>

    <!-- BLOCK 2: EXPORTS -->
    <div class="card">
      <div class="tb-block-hdr hdr-orange">&#8595; EXPORTS</div>

      <div class="tb-hint" style="margin-bottom:8px">
        Full workspace credentials &mdash; plaintext, hashes (brutforced
        substituted), DPAPI, custom import and local-admin rows &mdash; as XLSX.
      </div>
      <div class="actions-row">
        <button class="btn tb-dl-btn" onclick="RPModule.exportAllCreds()"
                title="Export all workspace credentials as XLSX">
          &#128081; ALL CREDS&#8595;</button>
      </div>

      <div class="tb-hint" style="margin-top:16px;margin-bottom:8px">
        Per-host vulnerability pivot &mdash; the default VULNS &mdash; ALL view &mdash; as XLSX.
      </div>
      <div class="actions-row">
        <button class="btn tb-dl-btn" onclick="RPModule.exportAllVulns()"
                title="Export the VULNS — ALL view as XLSX">
          &#9889; ALL VULNS&#8595;</button>
      </div>

      <div class="tb-hint" style="margin-top:16px;margin-bottom:8px">
        Engagement timeline &mdash; milestones with elapsed times &mdash; as TXT.
      </div>
      <div class="actions-row">
        <button class="btn tb-dl-btn" onclick="RPModule.downloadTimeline()"
                title="Download the timeline as TXT">
          &#128197; DOWNLOAD TIMELINE&#8595;</button>
      </div>

    </div>

  </div>

  <!-- Timeline node editor modal (sibling of .tb-content → not clipped by scroll) -->
  <div id="rpNodeModal" class="rp-modal" style="display:none" onclick="RPModule.onModalBackdrop(event)">
    <div class="rp-modal-box">
      <div class="rp-modal-title" id="rpModalTitle">Node</div>

      <label class="rp-modal-lbl" id="rpModalLabelRow">Label</label>
      <input type="text" id="rpModalLabel" class="rp-modal-input" autocomplete="off" spellcheck="false">

      <label class="rp-modal-lbl">Time (UTC)</label>
      <input type="datetime-local" step="1" id="rpModalTime" class="rp-modal-input">

      <label class="rp-modal-lbl">Detail <span class="rp-modal-opt">(optional)</span></label>
      <input type="text" id="rpModalDetail" class="rp-modal-input" autocomplete="off"
             spellcheck="false" placeholder="DOMAIN\user / host / note">

      <div id="rpModalErr" class="rp-modal-err"></div>
      <div class="rp-modal-actions">
        <button class="btn rp-modal-danger" id="rpModalDel" style="display:none"
                onclick="RPModule.deleteFromModal()">Delete</button>
        <button class="btn" id="rpModalReset" style="display:none"
                onclick="RPModule.resetFromModal()">&#8635; Reset to auto</button>
        <span class="rp-modal-spacer"></span>
        <button class="btn" onclick="RPModule.closeModal()">Cancel</button>
        <button class="btn tb-dl-btn" onclick="RPModule.saveModal()">Save</button>
      </div>
    </div>
  </div>
</div>
"""


def get_ui_fragment() -> str:
    return _RP_FRAGMENT
