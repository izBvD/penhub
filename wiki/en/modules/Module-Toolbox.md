# Module — Toolbox ⚙

A set of utilities that interact with other modules: manual credential import, domain admin watchlist, export lists for credential sprays, and operator environment configuration.

![](../../images/toolbox-overview1.png)
![](../../images/toolbox-overview2.png)

---

## Block 1 — CUSTOM IMPORT

### Custom Import (XLSX)

Add credentials to NXC Collector using an XLSX template.

- **↓ DOWNLOAD TEMPLATE** — download the XLSX template with hints.
- **↑ IMPORT XLSX** — parses, enriches, and adds to the database.

Template fields: Proto · IP · Port · Domain · **Login** · **Password** · Type · URL · Source · Comment.
**Login OR Password is required** (at least one); all other fields are optional.

![](../../images/toolbox-custom-template.png)

> Use this to add credentials obtained outside nxc (web apps, bruteforce, etc.). For NT hashes, apply HashKiller logic by setting `hash` in the Type field of the import template.

These credentials appear in the **ALL CREDS** export as a separate block.

### Domain Admin Watchlist

Prepare and import the names that are domain admins. PenHub watches every sync: as soon as a password or hash appears for a name from the watchlist, that account is automatically marked `admin_cred=1`.

- **Domain** field — auto-filled with the most common domain in the project; required on import.
- **↑ ADD USER LIST** — TXT file, one username per line (lines longer than 50 characters are skipped).
- **+ ADD ONE ADM USER** — add a single username (domain + username required).

While no password has been found for a watchlist name, it appears as a grey **ghost row** in the ADM CREDS view in NXC Collector. The **👻 CLEAR ADM GHOSTS** button (in NXC Collector Manage Mode) removes ghost entries from the watchlist.

![](../../images/toolbox-watchlist.png)

---

## Block 2 — NXCEXTRACTOR LISTS

Prepare lists for credential spray runs.

| Button                 | Downloads                                                                                                                                                      |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **↓ ALL UNIQ LOGINS**  | Unique logins (credentials + DPAPI SMB), lowercase, no Guest. TXT.                                                                                             |
| **↓ ALL UNIQ PASS**    | Unique plaintext passwords after HK-brute (cracked hashes count as plaintext). TXT.                                                                            |
| **↓ ALL UNIQ HASHES**  | Unique uncracked NT hashes. TXT.                                                                                                                               |
| **↓ ALL UNIQ IP**      | Unique IPs of all discovered hosts. TXT.                                                                                                                       |
| **↓ DOWNLOAD ARCHIVE** | ZIP of **5 files** for nxc spray: `not_pwnd_ip.txt` + `plaintext_logins.txt` + `plaintext_passes.txt` + `hashes_logins.txt` + `hashes_passes.txt`. 1:1 lines. |
| **↓ NOT PWN3D IPs**    | Just `not_pwnd_ip.txt` — hosts with no successful admin authentication.                                                                                        |

**HOW TO USE** contains instructions and typical commands.

> 1:1 pairing matters: line N in `plaintext_logins.txt` pairs with line N in `plaintext_passes.txt`, so nxc with `--no-bruteforce` tries each prepared pair for authentication. The same files can be generated offline with `nxce --brute`.

---

## Block 3 — OPERATOR ENVIRONMENT CONFIG

Everything needed to prepare an operator's environment (see **[Installation — Operator Client](../install/Installation-Operator-Client.md)**).

- **↓ DOWNLOAD SCRIPTS** — ZIP with `nxc_collector`, `nxce.py`, `nxc_updater.py`, `collector_dc.py`, `collector_hosts.py`.
  Install: `./nxc_collector --install`, then restart the terminal.
  The installer places the three scripts in `/usr/local/bin` (or `~/bin`) and the two `.py` NXC modules in `~/.nxc/modules/`.
- **COPY CONFIG STRING** — builds and copies the ready-to-use command:
  ```
  nxc_collector -ws --server http://<IP> --port <PORT> --pass "<password>" --workspace <project> --operator <you>
  ```
  The **OPERATOR** field is required; IP, port, password, and workspace are auto-filled from the server.
- **COPY BLOODHOUND CONFIG STRING** — builds the `--bh-setup` command for BloodHound (bh-ip required; bh-login defaults to `neo4j`, bh-pass to `bloodhoundcommunityedition`, bh-port to `7687`, bh-enable to `true`). BloodHound settings are stored on the server.

![](../../images/toolbox-config-string.png)
