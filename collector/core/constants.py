"""
Shared constants used across API and service layers.
"""

_LM_EMPTY   = "aad3b435b51404eeaad3b435b51404ee:"
_NT_EMPTY   = "31d6cfe0d16ae931b73c59d7e0c089c0"
_XLSX_MIME  = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

# Built-in Windows accounts hidden by the GUEST filter.
# GUARD: embedded verbatim into SQL in data.py, export.py, workspaces.py,
# toolbox_exports.py — rendered SQL must stay identical across all of them.
_GUEST_NAMES_SQL = "('guest','гость','defaultaccount','wdagutilityaccount')"

# ── VULNS single source of truth ────────────────────────────────────────────
# One ordered entry per vulnerability column. Read by:
#   - data.py get_vulns (pivot aggregate-per-host)
#   - export.py view=vulns (headers/rows — must equal the view 1:1)
#   - frontend (mirrored into VULN_FILTERS + column headers; keep in sync)
# GUARD: this is the ONLY place columns are defined. Add a vuln here, and the
#   slug must match the operator's slug map (nxc_updater._VULN_SLUG).
# Fields:
#   slug   — stable key (matches vuln_findings.vuln_name); never tied to CVE text
#   label  — display header / filter label
#   source — "host"   : read hosts.<col> (vuln when value == vuln_value)
#            "finding": read vuln_findings(ip, slug).is_vulnerable (tri-state)
#            "merge"  : vulnerable if hosts.<col>==vuln_value OR finding is_vulnerable==1
#   col / vuln_value — host column + the value that means "vulnerable" (host/merge only)
#   group  — filter grouping: remote | coerce | admin
VULN_COLUMNS = [
    {"slug": "smbv1",          "label": "SMBv1",          "source": "host",    "col": "smbv1",      "vuln_value": 1, "group": "remote"},
    {"slug": "signing",        "label": "Signing OFF",    "source": "host",    "col": "signing",    "vuln_value": 0, "group": "remote"},
    {"slug": "spooler",        "label": "Spooler",        "source": "host",    "col": "spooler",    "vuln_value": 1, "group": "remote"},
    {"slug": "ms17_010",       "label": "MS17-010",       "source": "finding",                                       "group": "remote"},
    {"slug": "smbghost",       "label": "SMBGhost",       "source": "finding",                                       "group": "remote"},
    {"slug": "printnightmare", "label": "PrintNightmare", "source": "finding",                                       "group": "remote"},
    {"slug": "webdav",         "label": "WebDAV",         "source": "finding",                                       "group": "remote"},
    {"slug": "nopac",          "label": "noPac",          "source": "finding",                                       "group": "remote"},
    {"slug": "zerologon",      "label": "Zerologon",      "source": "merge",   "col": "zerologon",  "vuln_value": 1, "group": "remote"},
    {"slug": "petitpotam",     "label": "PetitPotam",     "source": "merge",   "col": "petitpotam", "vuln_value": 1, "group": "coerce"},
    {"slug": "printerbug",     "label": "PrinterBug",     "source": "finding",                                       "group": "coerce"},
    {"slug": "dfscoerce",      "label": "DFSCoerce",      "source": "finding",                                       "group": "coerce"},
    {"slug": "shadowcoerce",   "label": "ShadowCoerce",   "source": "finding",                                       "group": "coerce"},
    {"slug": "wdigest",        "label": "WDigest",        "source": "finding",                                       "group": "admin"},
    {"slug": "ntlmv1",         "label": "NTLMv1",         "source": "finding",                                       "group": "admin"},
    {"slug": "runasppl",       "label": "RunAsPPL",       "source": "finding",                                       "group": "admin"},
    {"slug": "uac",            "label": "UAC",            "source": "finding",                                       "group": "admin"},
]

VULN_SLUGS = [c["slug"] for c in VULN_COLUMNS]
