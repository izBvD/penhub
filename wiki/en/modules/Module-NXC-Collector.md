# Module — NXC Collector 📡

The main module of the system. Displays, sorts, filters, and manages everything accumulated within a project.

![](../../images/nxc-overview-annotated.png)

---

## Module navigation

### Row 1 — protocols and global actions

Select a protocol (or a special view).

| Button          | Shows                                                                                        |
| --------------- | -------------------------------------------------------------------------------------------- |
| **ALL**         | Everything in the project: credentials from all protocols + DPAPI + custom                   |
| **SMB**         | Hosts (with vulnerability flags), credentials, shares, DPAPI, LSA/SAM, config checks         |
| **LDAP**        | Hosts, credentials                                                                           |
| **MSSQL**       | Hosts, credentials, sysadmin flag                                                            |
| **FTP**         | Hosts, credentials, directory listings                                                       |
| **SSH**         | Hosts, credentials, SSH keys                                                                 |
| **WinRM**       | Hosts, credentials                                                                           |
| **RDP**         | Hosts only (NLA flag; no credentials)                                                        |
| **VNC**         | Credentials + private key                                                                    |
| **WMI**         | Credentials                                                                                  |
| **NFS**         | Credentials, NFS shares                                                                      |
| **☠ ADM CREDS** | Special view: domain admin (CREDS) + local admin (LOCAL ADMIN)                               |
| **⚡ VULNS**     | Special view: vulnerability matrix by host                                                   |

Also in row 1:
- **✏ MANAGE** — switches the module to Manage Mode (see below).
- **Global search** — contains-search across the *entire* project database (all fields in all tables except numeric IDs and boolean flags). Activating it resets the selected protocol and filters. Result columns: *(type)* · Protocol · IP · Login · Password · Matched in · Details. Next to it is a reset button for protocol, filters, and search (GUEST / UNIQ / HK-bruted toggles are *not* reset).
- **CUSTOM** — displays credentials added via the Toolbox module, see [Module — Toolbox](Module-Toolbox.md).

![](../../images/nxc-filters.png)

### Row 2 — filters (dynamic)

Filter buttons change according to the selected protocol.

Standalone controls not related to protocol filters:

| Control          | What it does                                                                                                                                      |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ALL CREDS ↓**  | Export *all unique* project credentials to XLSX.                                                                                                  |
| **XLSX ↓**       | Export the *current* table view to XLSX respecting active filters.                                                                                |
| **GUEST**        | On by default. Hides Guest / DefaultAccount / WDAGUtilityAccount accounts (case-insensitive).                                                     |
| **UNIQ**         | Unique credentials by domain+login+password; on collision prefers plaintext over hash, admin over loggedin, SMB > LDAP > others.                  |
| **HK-bruted 🔓** | On by default. If a known plaintext exists for a hash in HashKiller — shows the password instead of the hash.                                     |

Also in row 2: **local search**. Searches within the current table.

---

## Table interactions

- **Click a cell** → copies its value.
- **Copy buttons** — 2 square buttons on the right side of each row, when both login and password are present:
  1. nxc format: `-u user -p password -d domain` (or `-H hash`, dynamically based on data type).
  2. Format: `domain\user:password`.
- **Sorting** — click a column header (A→Z / Z→A).
- **Reload** — force-refresh table data (useful when LIVE auto-update is off).

![](../../images/nxc-copy.png)

---

## Admin tracking

Two independent flags, toggled by buttons on the left side of each row:

- **Mark as domain admin** — marks credentials as domain-administrative. Specifically toggles `admin_cred` for the entire `domain+login+password` set; all matching rows across all protocols are highlighted.
- **Mark as local admin** (💻) — marks local admin credentials. Toggles `local_admin_cred` by `username+password` (without domain). Only on SMB PWN3D rows. Mutually exclusive with the domain admin mark.

The **☠ ADM CREDS** view shows them in one place:
- **CREDS** = domain admins (`admin_cred=1`), deduplicated by domain+login+password. Watchlist names without a password appear as grey **ghost rows** — they disappear after the first sync that brings their password.
- **LOCAL ADMIN** = list of all hosts for which local admin credentials are available (`local_admin_cred=1`), one row per host.

The domain admin watchlist is loaded in **[Module — Toolbox](Module-Toolbox.md)** (Domain Admin Watchlist).

![](../../images/nxc-mark-as-domain-adm.png)

---

## Vulnerabilities (⚡ VULNS)

Vulnerability matrix by host. Each row is a host; each column is a vulnerability; each cell is a **tri-state badge**: **YES** (vulnerable) / **no** (clean) / **—** (no data). **`—` does not mean "safe".**

Filters are grouped: **REMOTE** (SMBv1, Signing OFF, Spooler, MS17-010, SMBGhost, PrintNightmare, WebDAV, noPac, Zerologon), **COERCE** (PetitPotam, PrinterBug, DFSCoerce, ShadowCoerce), and **ADMIN-ONLY** config issues (WDigest, NTLMv1, RunAsPPL, UAC). The **AND** button, when active, combines selected filters with AND logic (adds results to the view).

What each vulnerability means and how to remediate — see **[Vulnerability Reference](../vulns/Vulnerability-Reference.md)** and **[Vulnerability Details and Remediation](../vulns/Vulnerability-Details.md)**.

Example — building a relay target list:

*SMBv1* **AND** *Signing OFF* **AND** *SPOOLER*:
![](../../images/nxc-vulns-matrix.png)

---

## Manage Mode ✏

Enables an extra action row and changes table behavior.

Extra row buttons:

| Button               | Action                                                                                |
| -------------------- | ------------------------------------------------------------------------------------- |
| 🚫 HIDDEN CREDS      | Show hidden credentials (hidden credentials + hidden DPAPI)                           |
| 🚫 HIDDEN HOSTS      | Show hidden hosts                                                                     |
| 👻 CLEAR ADM GHOSTS  | Remove watchlist entries awaiting a successful authentication                         |
| 🗑 DELETE ALL CUSTOM | Delete **all** custom (Toolbox-imported) credentials — irreversible, requires confirm |

In table view with Manage Mode enabled:
- **Click on IP → STRIKE function**: hide the host and all its credentials (honeypot=1).
- **× on a row** (right side) → hide only that row.

In the HIDDEN views you can restore items (**+** on a row), and clicking a hidden host IP (highlighted **green**) performs **RESTORE STRIKE** — restores the host and all its associated credentials.

> Honeypot logic: after a strike, new credentials associated with the hidden host during future syncs are automatically hidden. Credentials individually restored with **+** are not touched.

![](../../images/nxc-manage-mode.png)

![](../../images/nxc-manage-mode2.png)

---

## On "deletion"

Hard-deleting synced data (credentials, hosts, DPAPI) on an active project is largely pointless: the next sync from the operator reinserts them. That's why the tools **hide** rather than delete. Only custom (Toolbox) credentials and archived projects are truly deleted. For noise you want to suppress during work, use **hide / strike** rather than deletion.
