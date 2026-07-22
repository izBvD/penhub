"""HTML layout — body markup (from <body> through end of body, without inline CSS/JS)."""

HTML_LAYOUT = r"""<body>

<!-- ─────────────── LOGIN ─────────────────────────────────────────────────── -->
<div id="loginView"><div id="app"></div></div>
<!-- DS bundle mounts its demo kit here; hidden so it doesn't interfere -->
<div id="root" style="display:none"></div>

<!-- ─────────────── SHARED TOP BAR ───────────────────────────────────────── -->
<!-- Single header used by all post-login pages. JS updates it per mode.     -->
<div id="topBar">
  <span class="brand">PenHub</span>
  <span class="tb-page" id="tbPage">Projects</span>
  <div id="tbStats" class="stats">
    <span class="stat">Hosts: <b id="sHosts">&#8212;</b></span>
    <span class="stat">Creds: <b id="sCreds">&#8212;</b></span>
    <span class="stat s-admin">PWN3D!: <b id="sAdmin">&#8212;</b></span>
  </div>
  <div class="spacer"></div>
  <div id="notifBells" style="display:none">
    <button id="notifBell_pwn3d" class="notif-bell" onclick="Notif.toggle('pwn3d')" title="New PWN3D hosts">
      &#127942;<span id="notifBadge_pwn3d" class="notif-badge" style="display:none">0</span>
    </button>
    <button id="notifBell_domain_admin" class="notif-bell" onclick="Notif.toggle('domain_admin')" title="New domain admin credentials">
      &#9760;<span id="notifBadge_domain_admin" class="notif-badge" style="display:none">0</span>
    </button>
  </div>
  <div id="notifDrop" class="notif-drop" style="display:none"></div>
  <button id="newProjBtn" class="btn new-ws" onclick="createProjectFromPage()" title="Create new project">+ NEW</button>
  <button class="btn live-btn on" id="liveBtn" onclick="toggleLive()" title="Auto-refresh every 5s">LIVE &#9679;</button>
  <button id="backBtn" class="btn tb-back" onclick="showProjectsPage()" title="Back to projects">&#9664; PROJECTS</button>
  <button id="exitBtn" class="btn exit" onclick="doLogout()">EXIT</button>
</div>

<!-- ─────────────── PROJECTS PAGE ────────────────────────────────────────── -->
<div id="wsView">

  <div id="wsRain" class="at-rain" aria-hidden="true"></div>

  <div class="neon-sign" aria-hidden="true">
    <span class="nl">P</span><span class="nl">R</span><span class="nl flicker">O</span><span class="nl">J</span><span class="nl">E</span><span class="nl">C</span><span class="nl">T</span><span class="nl">S</span>
  </div>

  <div class="ws-window">
    <div class="ws-titlebar">
      <div class="ws-tabs">
        <button class="ws-tab active" data-tab="active" onclick="setProjectTab('active')"><span class="dot"></span>Active</button>
        <button class="ws-tab" data-tab="archive" onclick="setProjectTab('archive')"><span class="dot"></span>Archive</button>
        <button class="ws-tab" data-tab="recycle" onclick="setProjectTab('recycle')"><span class="dot"></span>Recycle</button>
      </div>
      <div class="ws-tb-spacer"></div>
      <div class="ws-tb-actions">
        <button class="btn btn--ghost" onclick="window.open('/api/download/db','_blank')" title="Download database"><span class="gi">&#8659;</span>DB</button>
        <button class="btn btn--primary" onclick="createProjectFromPage()" title="Create new project"><span class="gi">+</span>NEW PROJECT</button>
      </div>
      <button class="ws-close" title="Exit" onclick="doLogout()">&#10005;</button>
    </div>

    <div class="ws-list-wrap">
      <div class="ws-list" id="wsList">
        <div class="ws-empty-hint">Loading...</div>
      </div>
    </div>
  </div>

</div>

<!-- ─────────────── APP (project view) ───────────────────────────────────── -->
<div id="appView">
  <!-- Sidebar navigation -->
  <nav id="sidebar" class="sidebar">
    <canvas id="sbCanvas"></canvas>
    <div id="sidebarNav"></div>
    <button class="sb-collapse-btn" onclick="toggleSidebar()" title="Collapse / expand sidebar">&#8249;</button>
  </nav>
  <!-- Main content area -->
  <div id="appContent">

  <!-- Row 1: protocol pills + global search + VULNS + ACRED -->
  <div class="toolbar row1" id="protoRow">
    <button class="pill p-all active" data-proto="ALL"   onclick="setProto('ALL')">ALL</button>
    <button class="pill p-smb"        data-proto="SMB"   onclick="setProto('SMB')">SMB</button>
    <button class="pill p-ldap"       data-proto="LDAP"  onclick="setProto('LDAP')">LDAP</button>
    <button class="pill p-mssql"      data-proto="MSSQL" onclick="setProto('MSSQL')">MSSQL</button>
    <button class="pill p-ftp"        data-proto="FTP"   onclick="setProto('FTP')">FTP</button>
    <button class="pill p-ssh"        data-proto="SSH"   onclick="setProto('SSH')">SSH</button>
    <button class="pill p-winrm"      data-proto="WINRM" onclick="setProto('WINRM')">WINRM</button>
    <button class="pill p-rdp"        data-proto="RDP"   onclick="setProto('RDP')">RDP</button>
    <button class="pill p-vnc"        data-proto="VNC"   onclick="setProto('VNC')">VNC</button>
    <button class="pill p-wmi"        data-proto="WMI"   onclick="setProto('WMI')">WMI</button>
    <button class="pill p-nfs"        data-proto="NFS"   onclick="setProto('NFS')">NFS</button>
    <button class="pill p-custom"     data-proto="CUSTOM" onclick="setProto('CUSTOM')">CUSTOM</button>
    <div class="spacer"></div>
    <button class="btn reset-btn" onclick="resetFilters()" title="Reset all filters">&#10005;</button>
    <div class="gsearch-wrap">
      <input id="globalSearchIn" type="text" placeholder="&#128269; global search..."
             oninput="onGlobalSearch()" autocomplete="off">
    </div>
    <button class="pill s-vulns" id="vulnsBtn" onclick="setVulns()">&#9889; VULNS</button>
    <button class="pill s-acred" id="acredBtn" onclick="setAcred()">&#9760; ADM CREDS</button>
    <button class="btn manage-btn" id="manageBtn" onclick="toggleManageMod()" title="Manage mode — show/hide credentials">&#9998;</button>
  </div>

  <!-- Row 2: dynamic sub-filters + local search + guest + exports -->
  <div class="toolbar row2">
    <div id="subPills"></div>
    <div class="search-wrap">
      <input id="searchIn" type="text" placeholder="filter table..." oninput="onSearch()">
    </div>
    <button class="btn reset-btn" onclick="resetFilters()" title="Reset all filters">&#10005;</button>
    <div class="spacer"></div>
    <button class="pill hk-btn on" id="hkBtn" onclick="toggleHkBruted()"
            title="HK-bruted: show hashkiller-cracked passwords">&#128275; HK</button>
    <button class="pill uniq on" id="uniqBtn" onclick="toggleUniq()"
            title="Show unique credentials only (prefer plaintext over hash)">UNIQ</button>
    <button class="pill guest on" id="guestBtn" onclick="toggleGuest()"
            title="Hide guest / гость / DefaultAccount / WDAGUtilityAccount entries">&#128683; GUEST</button>
    <button class="btn xlsx"    onclick="exportXlsx()"   title="Export current view as XLSX">XLSX&#8595;</button>
  </div>

  <!-- Row 3: manage-mod hidden items (visible only when manage mode is active) -->
  <div class="toolbar row3" id="manageRow">
    <span style="color:var(--a4);font-size:10px;font-weight:600;letter-spacing:.06em;opacity:.7;margin-right:2px">MANAGE</span>
    <button class="pill p-hidden" id="hiddenCredsBtn" onclick="setProto('HIDDEN')"
            title="Hidden credentials + DPAPI">&#128683; HIDDEN CREDS</button>
    <button class="pill p-hidden-hosts" id="hiddenHostsBtn" onclick="setProto('HIDDEN_HOSTS')"
            title="Hidden hosts">&#128683; HIDDEN HOSTS</button>
    <button class="pill p-clear-ghosts" id="clearGhostsBtn" onclick="clearAdmGhosts()"
            title="Remove unmatched domain admin entries (not yet found in any sync)">&#128123; CLEAR ADM GHOSTS</button>
    <button class="pill p-del-custom" id="delAllCustomBtn" onclick="deleteAllCustom()"
            title="Delete all custom credential rows (Toolbox import) in this workspace">&#128465; DELETE ALL CUSTOM</button>
    <button class="pill p-clear-vuln-overrides" id="clearVulnOverridesBtn" onclick="clearVulnOverrides()"
            title="Reset all manual VULNS overrides — restores sync values">&#8635; CLEAR OVERRIDES VULNS</button>
  </div>

  <!-- Table -->
  <div class="table-wrap" id="tableWrap">
    <div class="empty"><div class="icon">&#9676;</div>Select a workspace</div>
  </div>

  <!-- Footer / Pagination -->
  <div class="pager" id="pager" style="display:none">
    <span style="color:var(--fg2)">Rows:</span>
    <button class="pill size-pill active" id="sz100"  onclick="setPageSize(100)">100</button>
    <button class="pill size-pill"        id="sz500"  onclick="setPageSize(500)">500</button>
    <button class="pill size-pill"        id="sz1000" onclick="setPageSize(1000)">1000</button>
    <button class="pill size-pill"        id="szAll"  onclick="setPageSize(0)">ALL</button>
    <div style="width:4px"></div>
    <button class="pg-btn" id="pgPrev" onclick="goPage(-1)" style="visibility:hidden">&#8592;</button>
    <span class="info" id="pgInfo"></span>
    <button class="pg-btn" id="pgNext" onclick="goPage(1)"  style="visibility:hidden">&#8594;</button>
    <div class="spacer"></div>
    <button class="btn reload" onclick="reloadData()" title="Reload now">&#8635; RELOAD</button>
  </div>

  </div><!-- /appContent -->

  <!-- HashKiller module view (lazy-loaded on first activation) -->
  <div id="mod-hashkiller" style="display:none;flex:1;overflow:hidden"></div>

  <!-- Toolbox module view (lazy-loaded on first activation) -->
  <div id="mod-toolbox" style="display:none;flex:1;overflow:hidden"></div>

  <!-- Reports module view (lazy-loaded on first activation) -->
  <div id="mod-reports" style="display:none;flex:1;overflow:hidden"></div>

  <!-- REMINDER: add <div id="mod-<moduleId>"> here for each new lazy module. -->

</div><!-- /appView -->

<div id="copyToast">COPIED</div>
<div id="tbErrToast">ERROR</div>
"""
