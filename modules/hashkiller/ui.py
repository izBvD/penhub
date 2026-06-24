"""HashKiller UI fragment — lazy-loaded HTML injected by Shell on first activation."""

_HK_FRAGMENT = r"""
<div style="display:flex;flex-direction:column;width:100%;height:100%;overflow:hidden">

  <!-- Header: title + stats -->
  <div class="toolbar row0" style="flex-shrink:0;gap:10px;flex-wrap:wrap">
    <span style="color:var(--a1);font-weight:700;font-size:13px;letter-spacing:2px">&#9760; HASHKILLER</span>
    <div class="stat-chips">
      <span class="stat-chip s-total">pairs: <b id="statTotal">&#8212;</b></span>
      <span class="stat-chip s-smart">smart: <b id="statSmart">&#8212;</b></span>
      <span class="stat-chip s-warn">&#9888; warning: <b id="statWarn">&#8212;</b></span>
    </div>
  </div>

  <!-- Scrollable body -->
  <div class="hk-content">

    <!-- ═══ BLOCK 1: IMPORT ═══════════════════════════════════════════════ -->
    <div class="card">
      <div class="hk-block-hdr hdr-green">&#9654; IMPORT &mdash; paste or upload hash:plain pairs</div>
      <textarea class="import-area" id="importText" placeholder="Supported formats:
HASH:PLAIN                     8846f7eaee8fb117ad06bdd830b7586c:Password1
LM:NT:PLAIN                    aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:Password1
$NT$HASH:PLAIN                 $NT$8846f7eaee8fb117ad06bdd830b7586c:Password1
Empty password hash            31d6cfe0d16ae931b73c59d7e0c089c0:&lt;empty_password&gt;

Unknown hash types are skipped. Multiple lines accepted. Paste .potfile contents directly."></textarea>
      <div class="import-row">
        <label class="file-label" title="Upload .potfile or .txt">
          &#128196; Upload .potfile / .txt
          <input type="file" id="importFile" accept=".potfile,.pot,.txt,text/*"
                 hidden onchange="HKModule.onFileSelected(this,'fileName')">
        </label>
        <span id="fileName" class="file-name"></span>
        <button class="btn action-btn" id="importBtn" onclick="HKModule.doImport()">&#9654; IMPORT</button>
        <div class="spacer"></div>
        <button class="btn action-btn" id="importServerBtn" onclick="HKModule.importServerFile()"
                title="Import a large .potfile placed on the server at hk_inbox/large.potfile">
          &#128193; SERVER FILE</button>
        <button class="btn action-btn" id="importRamBtn" onclick="HKModule.importServerFile(true)"
                title="Same as SERVER FILE but uses most of the free RAM for max speed (safe — leaves headroom)">
          &#128165; RAM-KILLER</button>
      </div>
      <div id="importResult" class="result-msg"></div>
    </div>

    <!-- ═══ BLOCK 2: ACTIONS ══════════════════════════════════════════════ -->
    <div class="card">
      <div class="hk-block-hdr hdr-purple">&#9889; ACTIONS</div>

      <!-- Primary actions -->
      <div class="actions-row">
        <button class="btn enrich-btn" id="enrichBtn" onclick="HKModule.doSmartEnrich()" disabled
                title="Infer hash&#8594;plain pairs from this workspace&#39;s auth data">
          &#9889; SMART ENRICH</button>
        <button class="btn kill-btn" id="killBtn" onclick="HKModule.doKill()" disabled
                title="Look up all uncracked hashes in HK DB and fill Brutforced column">
          &#128477; KILL THEM ALL</button>
        <button class="btn export-btn" id="exportBtn" onclick="HKModule.exportHashes()" disabled
                title="Download all uncracked NT hashes for hashcat -m 1000">
          &#8595; HASHES.TXT</button>
        <button class="btn sync-bf-btn" id="syncBfBtn" onclick="HKModule.syncBrutforced()" disabled
                title="Clear Brutforced entries whose source pair was deleted from HK DB">
          &#8635;</button>
      </div>

      <!-- Progress area (hidden when idle) -->
      <div id="taskProgress" class="task-progress" hidden>
        <div class="progress-bar-wrap"><div class="progress-bar" id="progressBar"></div></div>
        <div class="progress-info">
          <span id="progressText" class="progress-text">Processing&#8230;</span>
          <button class="btn cancel-btn" id="cancelBtn" onclick="HKModule.cancelTask()">&#10005; Cancel</button>
        </div>
      </div>
      <div id="killResult" class="result-msg"></div>

      <!-- Dangerous zone: ALL WORKSPACES -->
      <div class="danger-zone">
        <button class="btn killall-btn" id="killAllBtn" onclick="HKModule.doKillAll()"
                title="Run Kill Them All for EVERY workspace including archived">
          &#9762; ALL WORKSPACES</button>
        <span class="danger-hint">applies to all projects incl. archived</span>
      </div>
    </div>

    <!-- ═══ BLOCK 3: DB WORK ══════════════════════════════════════════════ -->
    <div class="card">
      <div class="hk-block-hdr hdr-orange">&#128190; DB WORK</div>

      <!-- Row 1: download / upload -->
      <div class="actions-row" style="margin-bottom:10px">
        <button class="btn dump-btn" onclick="HKModule.dumpDb()"
                title="Download full hashkiller.db file">
          &#8659; DOWNLOAD DB</button>

        <label class="file-label upload-label" title="Upload another hashkiller.db to merge (non-destructive)">
          &#8657; UPLOAD DB
          <input type="file" id="uploadDbFile" accept=".db,application/octet-stream"
                 hidden onchange="HKModule.onFileSelected(this,'uploadFileName');HKModule.doUploadDb()">
        </label>
        <span id="uploadFileName" class="file-name"></span>
      </div>
      <div id="uploadResult" class="result-msg" style="margin-bottom:10px"></div>

      <!-- Row 2: exports -->
      <div class="actions-row" style="margin-bottom:10px">
        <button class="btn smart-export-btn" onclick="HKModule.exportSmart()"
                title="Export all SMART-inferred pairs as hash:plain text">
          &#8659; EXPORT SMART</button>
        <button class="btn warn-export-btn" onclick="HKModule.exportWarning()"
                title="Export all conflicting pairs (warning=true) for review">
          &#9888;&#8659; EXPORT WARNING</button>
      </div>

      <!-- Row 3: delete pair -->
      <div class="card-title" style="margin-top:4px;margin-bottom:6px">
        DELETE PAIR — by hash or plaintext
      </div>
      <div class="delete-wrap">
        <input type="text" id="deleteInput"
               placeholder="hash (32-hex), plaintext, or hash:plain — confirmed before delete">
        <div class="delete-btn-row">
          <button class="btn delete-btn" onclick="HKModule.deleteByValue()">&#10005; DELETE</button>
          <div class="spacer"></div>
          <span id="deleteFileName" class="file-name"></span>
          <label class="file-label" title="Bulk delete: upload a txt of hash:plain or hash lines (e.g. the EXPORT WARNING file) — deletes all matches, no per-pair confirm">
            &#128196; DELETE FROM FILE
            <input type="file" id="deleteFile" accept=".txt,.potfile,.pot,text/*" hidden
                   onchange="HKModule.onFileSelected(this,'deleteFileName');HKModule.deleteFromFile(this)">
          </label>
        </div>
      </div>
      <div id="deleteResult" class="result-msg"></div>
      <!-- Confirmation area (hidden until matches found) -->
      <div id="deleteConfirm" class="delete-confirm" hidden>
        <div class="delete-confirm-list" id="deleteConfirmList"></div>
        <div class="delete-confirm-btns">
          <button class="btn delete-btn" id="deleteConfirmOk"   onclick="HKModule.confirmDelete()">&#10005; Confirm Delete</button>
          <button class="btn"            id="deleteConfirmCancel" onclick="HKModule.cancelDelete()">Cancel</button>
        </div>
      </div>
    </div>

    <!-- ═══ BLOCK 4: HOW TO USE ═══════════════════════════════════════════ -->
    <div class="card how-to">
      <div class="hk-block-hdr hdr-dim how-to-toggle" onclick="HKModule.toggleHowTo()">
        <span class="how-to-arrow" id="howArrow">&#9654;</span> HOW TO USE
      </div>
      <div id="howToBody" class="how-to-body" hidden>
        <pre>
IMPORT (Block 1)
  Paste hash:plain pairs or upload a .potfile directly from hashcat.
  Supported formats:
    HASH:PLAIN          — 8846f7eaee8fb117ad06bdd830b7586c:Password1
    LM:NT:PLAIN         — aad3b435...:8846f7...:Password1
    $NT$HASH:PLAIN      — $NT$8846f7...:Password1
  Unknown hash types are silently skipped.
  The empty NT hash (31d6...) is always stored as &lt;empty_password&gt;.

  SERVER FILE — for very large potfiles (multi-GB) that are impractical to
    upload through the browser. Place the file on the server at
    hk_inbox/large.potfile (via scp / rsync / direct disk), then click
    SERVER FILE: it confirms the file size, then streams it into the DB in
    the background (progress shown in ACTIONS). Same formats and rules as
    above. The file is never auto-deleted — remove it manually when done.
    If the import is cancelled or the server restarts mid-run, it is safe to
    re-import the same file: duplicate pairs are skipped automatically.

  RAM-KILLER — same as SERVER FILE but devotes most of the free RAM to the
    DB cache for maximum speed on a large disk-bound database. Safe: it always
    leaves headroom so the host stays alive. Use it for the heaviest imports.

ACTIONS (Block 2)
  ① SMART ENRICH — analyses the selected workspace and infers hash↔plain pairs:
      If on the same host the same login authenticated with EXACTLY one plaintext
      AND EXACTLY one hash, those are assumed to match.
      Ambiguous cases (multiple plaintexts or multiple hashes) are skipped.
      Cross-operator matches on the same host count as a valid match.
      Found pairs are added to HK DB with smart=true.

  ② KILL THEM ALL — for the selected workspace: looks up every uncracked hash in
      HK DB and writes the cracked password into the Brutforced column.
      Run after SMART ENRICH and/or after importing a .potfile.

  ③ HASHES.TXT — downloads all uncracked NT hashes from the workspace in plain
      text, ready for hashcat:  hashcat -m 1000 hashes.txt wordlist.txt -O

  ALL WORKSPACES — runs Kill Them All across ALL projects (including archived).

DB WORK (Block 3)
  DOWNLOAD DB     — export the full hashkiller.db file (backup / share).
  UPLOAD DB       — merge another operator's hashkiller.db (non-destructive).
                    Conflicting pairs (same hash, different plaintext) get
                    warning=true — both values are kept for review.
  EXPORT SMART    — download all smart=true pairs (hash:plain, one per line).
  EXPORT WARNING  — download all warning=true pairs for manual review.
  DELETE PAIR     — remove a wrong / false-positive pair.
                    Enter a hash, plaintext, or hash:plain pair.
                    A preview is shown before deletion — confirm to proceed.
                    If the value matches entries in both the hash and plaintext
                    columns of different records, a list is shown for review.
  DELETE FROM FILE — bulk delete. Upload a txt with one hash:plain or hash per
                    line (e.g. the EXPORT WARNING file): every match is removed
                    at once, with a single confirm instead of one per pair.
                    Handy to clear many conflicts in one go.

Typical workflow:
  1. Select workspace → SMART ENRICH  (free pairs from existing data)
  2. HASHES.TXT → crack with hashcat → upload .potfile via IMPORT
  3. KILL THEM ALL → hashes resolved in Brutforced column
  4. Enable &#128275; HK toggle in NXC view to show cracked passwords
        </pre>
      </div>
    </div>

  </div><!-- /hk-content -->
</div>
"""


def get_ui_fragment() -> str:
    return _HK_FRAGMENT
