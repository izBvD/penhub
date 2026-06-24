"""Toolbox UI fragment — lazy-loaded HTML injected by Shell on first activation."""

_TB_FRAGMENT = r"""
<div style="display:flex;flex-direction:column;width:100%;height:100%;overflow:hidden">

  <!-- Header -->
  <div class="toolbar row0" style="flex-shrink:0;gap:10px;flex-wrap:wrap">
    <span style="color:var(--a1);font-weight:700;font-size:13px;letter-spacing:2px">&#9881; TOOLBOX</span>
  </div>

  <!-- Scrollable body -->
  <div class="tb-content">

    <!-- ═══ BLOCK 1: CUSTOM IMPORT ══════════════════════════════════════════ -->
    <div class="card">
      <div class="tb-block-hdr hdr-green">&#8679; CUSTOM IMPORT</div>
      <div class="tb-hint" style="margin-bottom:12px">
        Download the XLSX template, fill in your credentials, then upload to a workspace.<br>
        Columns: Proto &middot; IP &middot; Port &middot; Domain &middot;
        <strong style="color:var(--fg0)">Login</strong> &middot;
        <strong style="color:var(--fg0)">Password</strong> &middot;
        Type &middot; URL &middot; Source &middot; Comment.<br>
        <span style="color:var(--a3)">&bull;</span>
        Login <em>or</em> Password required (at least one per row).
      </div>
      <div class="actions-row">
        <button class="btn tb-dl-btn" onclick="TBModule.downloadCustomImportTemplate()"
                title="Download XLSX template — fill it in, then upload">
          &#8595; DOWNLOAD TEMPLATE</button>
        <button class="btn tb-spray-btn" onclick="TBModule.importCustomFile()"
                title="Upload filled XLSX — imports into the current workspace">
          &#8679; IMPORT XLSX</button>
      </div>
      <input type="file" id="customImportFile"
             accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
             style="display:none">
      <div id="customImportResult" class="result-msg"></div>

      <!-- Domain Admin Watchlist — separated like spray section in NXCEXTRACTOR -->
      <div class="tb-spray-section">
        <div class="tb-section-label">DOMAIN ADMIN WATCHLIST</div>
        <div style="color:var(--fg1);font-size:10px;margin-bottom:8px;line-height:1.6">
          Upload a list of known domain admin usernames.
          PenHub will track them in ADM CREDS &mdash; gray until found, auto-marked when synced.
        </div>
        <div class="tb-input-row" style="margin-bottom:5px">
          <input type="text" id="dalDomain" class="tb-input tb-input-fixed"
                 autocomplete="off" spellcheck="false">
          <button class="btn tb-spray-btn" onclick="TBModule.dalUpload()"
                  title="Upload TXT file: one username per line, lines &gt; 50 chars skipped">
            &#8679; ADD USER LIST</button>
        </div>
        <div class="tb-or-sep">OR</div>
        <div class="tb-input-row" style="margin-bottom:5px">
          <input type="text" id="dalUsername" class="tb-input tb-input-fixed"
                 placeholder="administrator" autocomplete="off" spellcheck="false">
          <button class="btn tb-spray-btn" onclick="TBModule.dalAddOne()"
                  title="Add a single domain admin username">
            &#43; ADD ONE ADM USER</button>
        </div>
        <input type="file" id="dalFileInput" accept=".txt,text/plain" style="display:none">
        <div id="dalResult" class="result-msg"></div>
      </div>

      <!-- How to use (collapsible) -->
      <div class="tb-spray-section">
        <div class="tb-spray-label how-to-toggle" onclick="TBModule.toggleHowTo('1')">
          <span class="how-to-arrow" id="tbHowArrow1">&#9654;</span> HOW TO USE
        </div>
        <div id="tbHowToBody1" class="how-to-body" hidden>
          <pre>
CUSTOM IMPORT
  Download the XLSX template, fill in credentials, then upload to the current workspace.
  Login or Password required per row — all other columns are optional.

DOMAIN ADMIN WATCHLIST
  Upload a TXT file with one domain admin username per line (lines &gt; 50 chars are skipped).
  Enter the domain exactly as shown in the Domain column of ADM CREDS.
  Uploaded usernames appear grayed out in ADM CREDS until their credentials are found via sync.
  When a matching credential is synced, it is automatically marked as an ADM CRED.
  Use CLEAR ADM GHOSTS (in manage mode) to remove unmatched entries.
          </pre>
        </div>
      </div>
    </div>

    <!-- ═══ BLOCK 2: NXCEXTRACTOR LISTS ════════════════════════════════════ -->
    <div class="card">
      <div class="tb-block-hdr hdr-cyan">&#8595; NXCEXTRACTOR LISTS</div>

      <!-- Primary export buttons -->
      <div class="actions-row" style="margin-bottom:14px">
        <button class="btn tb-dl-btn" onclick="TBModule.downloadLogins()"
                title="Unique usernames (credentials + DPAPI SMB), lowercased — GUEST excluded">
          &#8595; ALL UNIQ LOGINS</button>
        <button class="btn tb-dl-btn" onclick="TBModule.downloadPasswords()"
                title="Unique plaintext passwords (credentials + DPAPI SMB) — HK-Brute applied">
          &#8595; ALL UNIQ PASS</button>
        <button class="btn tb-dl-btn" onclick="TBModule.downloadHashes()"
                title="Unique uncracked NT hashes (Brutforced column empty)">
          &#8595; ALL UNIQ HASHES</button>
        <button class="btn tb-dl-btn" onclick="TBModule.downloadIPs()"
                title="Unique IP addresses of all discovered hosts">
          &#8595; ALL UNIQ IP</button>
      </div>

      <!-- Spray archive — separated visually -->
      <div class="tb-spray-section">
        <div class="tb-spray-label">nxc &ndash;&ndash;no-bruteforce &ndash;&ndash;continue-on-success lists</div>
        <div class="actions-row" style="margin-bottom:6px">
          <button class="btn tb-spray-btn" onclick="TBModule.downloadSprayArchive()"
                  title="ZIP: not_pwn3d_ip.txt + plaintext_logins/passes.txt + hashes_logins/passes.txt (line-paired)">
            &#8595; DOWNLOAD ARCHIVE</button>
          <button class="btn tb-spray-btn" onclick="TBModule.downloadNotPwndIps()"
                  title="Hosts with no admin access (not_pwn3d_ip.txt)">
            &#8595; NOT PWN3D IPs</button>
        </div>
        <div class="tb-hint">
          archive: not_pwn3d_ip.txt &mdash; plaintext_logins/passes.txt &mdash; hashes_logins/passes.txt
          &mdash; line-paired, ready for nxc spray
        </div>
      </div>

      <!-- How to use (collapsible) -->
      <div class="tb-spray-section">
        <div class="tb-spray-label how-to-toggle" onclick="TBModule.toggleHowTo('2')">
          <span class="how-to-arrow" id="tbHowArrow2">&#9654;</span> HOW TO USE
        </div>
        <div id="tbHowToBody2" class="how-to-body" hidden>
          <pre>
ALL UNIQ LOGINS  — unique usernames (credentials + DPAPI SMB), lowercased, GUEST excluded.
ALL UNIQ PASS    — unique plaintext passwords (credentials + DPAPI SMB). HK-Brute applied: cracked hashes count as plaintext.
ALL UNIQ HASHES  — unique NT hashes with no cracked plaintext (Brutforced column empty).
ALL UNIQ IP      — unique IP addresses of all discovered hosts.

SPRAY ARCHIVE (--no-bruteforce)
  Downloads a ZIP with 5 files for nxc credential spray against non-owned hosts:
    not_pwn3d_ip.txt                             — target hosts with no admin access yet
    plaintext_logins.txt / plaintext_passes.txt  — login per line, matching password per line
    hashes_logins.txt    / hashes_passes.txt      — login per line, matching NT hash per line
  Line counts are guaranteed equal within each pair (one credential per line).

  Typical use:
    nxc smb not_pwn3d_ip.txt -u plaintext_logins.txt -p plaintext_passes.txt --no-bruteforce --continue-on-success
    nxc smb not_pwn3d_ip.txt -u hashes_logins.txt -H hashes_passes.txt --no-bruteforce --continue-on-success

NOT PWN3D IPs — downloads not_pwn3d_ip.txt separately (all hosts with no admin access).
          </pre>
        </div>
      </div>
    </div>

    <!-- ═══ BLOCK 3: OPERATOR ENVIRONMENT ═══════════════════════════════════ -->
    <div class="card">
      <div class="tb-block-hdr hdr-orange">&#128295; OPERATOR ENVIRONMENT CONFIG</div>

      <!-- Group 1: Download scripts -->
      <div class="tb-env-group">
        <div class="actions-row">
          <button class="btn tb-dl-btn" onclick="TBModule.downloadScripts()"
                  title="Download nxc_collector, nxce.py, nxc_updater.py as ZIP">
            &#8595; DOWNLOAD SCRIPTS</button>
          <span class="tb-hint" style="margin-left:4px">
            Install or Update: <code>./nxc_collector --install</code> &mdash; then reopen terminal
          </span>
        </div>
      </div>

      <!-- Group 2: Copy workspace config string -->
      <div class="tb-env-group">
        <div class="tb-env-label">COPY CONFIG STRING</div>
        <div class="tb-input-row">
          <input type="text" id="tbOperator" class="tb-input tb-input-fixed"
                 placeholder="OPERATOR (required)" autocomplete="off" spellcheck="false">
          <button class="btn tb-copy-btn" onclick="TBModule.copyConfig()"
                  title="Copy nxc_collector -ws config string to clipboard">
            &#10021; COPY CONFIG</button>
        </div>
        <div id="copyConfigResult" class="result-msg"></div>
      </div>

      <!-- Group 3: BloodHound config string -->
      <div class="tb-env-group">
        <div class="tb-env-label">COPY BLOODHOUND CONFIG STRING</div>
        <div class="tb-bh-grid">
          <span class="tb-field-label">--bh-ip</span>
          <input type="text" id="tbBhIp" class="tb-input" placeholder="BloodHound IP (required)"
                 autocomplete="off" spellcheck="false">
          <span class="tb-field-label">--bh-login</span>
          <input type="text" id="tbBhLogin" class="tb-input" value="neo4j"
                 autocomplete="off" spellcheck="false">
          <span class="tb-field-label">--bh-pass</span>
          <input type="text" id="tbBhPass" class="tb-input" value="bloodhoundcommunityedition"
                 autocomplete="off" spellcheck="false">
          <span class="tb-field-label">--bh-port</span>
          <input type="text" id="tbBhPort" class="tb-input tb-input-sm" value="7687"
                 autocomplete="off" spellcheck="false">
          <span class="tb-field-label">--bh-enable</span>
          <select id="tbBhEnable" class="tb-select">
            <option value="true" selected>true</option>
            <option value="false">false</option>
          </select>
        </div>
        <div class="actions-row" style="margin-top:8px">
          <button class="btn tb-copy-btn" onclick="TBModule.copyBhConfig()"
                  title="Copy nxc_collector --bh-setup config string to clipboard">
            &#10021; COPY BH CONFIG</button>
        </div>
        <div id="copyBhConfigResult" class="result-msg"></div>
      </div>

    </div><!-- /card operator env -->

  </div><!-- /tb-content -->
</div>
"""


def get_ui_fragment() -> str:
    return _TB_FRAGMENT
