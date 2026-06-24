# Installation — Operator Client

Every operator running NetExec installs three small scripts and two custom NXC modules on their working machine. The scripts push nxc data to your server and pull back the unified database (merged with other operators). Everything uses **stdlib Python + bash only** — no pip packages required on the operator side.

Three scripts:

| Script                 | Role                                                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `nxc_collector` (bash) | Installer and configurator. Places the other scripts, writes config, sets up cron. Does not manipulate data itself.                                    |
| `nxc_updater.py`       | Sync engine. Runs from cron every 10 minutes: reads nxc databases, pushes to server, pulls the merged workspace back.                                  |
| `nxce.py`              | Offline extractor ("PWN3D Extractor"). Reads the local merged database to build target lists and spray files. Does not contact the server. (see --help) |

Two custom NXC modules (installed automatically to `~/.nxc/modules/` by `--install`):

| Module               | What it checks                                                                                                                                                                                                                                 |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `collector_dc.py`    | DC-specific checks: **noPac** (CVE-2021-42278/42287) and **Zerologon** (CVE-2020-1472). Run with `nxc ... -M collector_dc` against DC targets.                                                                                                 |
| `collector_hosts.py` | General host checks: **MS17-010/EternalBlue**, **SMBGhost**, **Coerce** (DFSCoerce/ShadowCoerce/PrinterBug/PetitPotam), **WebDAV**, **PrintNightmare**, **WDigest**, **NTLMv1**, **RunAsPPL**, **UAC**. Run with `nxc ... -M collector_hosts`. |

These modules are re-implementations of existing nxc modules. The problem with the stock modules is that they do **not** write results to nxcdb. To collect results in NXC Collector we rewrote these checks and added writing to `nxc-vulns.db`.

Results from both modules are saved to `nxc-vulns.db` in a separate workspace and sent to the server on the next `nxc_updater` run — they appear in the **VULNS** view in NXC Collector.

> All flags for all three scripts are in **[Operator Scripts Reference](../reference/Operator-Scripts-Reference.md)**.

---

## Requirements

- A Linux machine with **[NetExec](https://github.com/Pennyw0rth/NetExec)** already installed and working.
- Python 3 (stdlib) and `cron`.
- Network access to the PenHub server at host:port.

---

## Easiest path: grab scripts from the server

The server serves a ready-made package and a config string. Just copy and paste.

1. Log in to PenHub in your browser, open the project, go to **Toolbox** → **Operator Environment Config** block.
2. Click **↓ DOWNLOAD SCRIPTS** — downloads a ZIP with `nxc_collector`, `nxc_updater.py`, `nxce.py`, `collector_dc.py`, `collector_hosts.py`.
3. Unzip on the operator's machine and install:

```bash
unzip penhub-scripts.zip -d penhub-scripts
cd penhub-scripts
chmod +x nxc_collector
./nxc_collector --install
```

`--install` copies the three scripts to `/usr/local/bin` (or `~/bin` if no write access there), makes them executable, sets up cron (`*/10` + `@reboot`), and **copies `collector_dc.py` and `collector_hosts.py` to `~/.nxc/modules/`** — NetExec will pick them up automatically. After that — **restart your terminal**.

![](../../images/toolbox-block3-config.png)

---

## Configuring the connection

In the same block, fill in the **OPERATOR** field (your nickname — it tags every row you contribute) and click **COPY CONFIG STRING**. You get a string like:

```bash
nxc_collector -ws --server http://10.10.10.5 --port 322 --pass "StrongPasswordHere!" --workspace organisationX --operator alice
```

Run it on the operator's machine. This creates `~/.nxc-collector.conf` and, if needed, creates the nxc workspace locally.

Connection check:

```bash
nxc_collector --connection-test
# 200 = OK · 401/403 = wrong password · no output = server unreachable

nxc_collector --show-options
# prints the active config (password masked), workspace, BloodHound section
```

> ⚠️ The project (`--workspace`) **must already exist on the server**, otherwise sync does nothing. If it doesn't exist, `nxc_updater` silently skips (exit 0) and pushes nothing — this is intentional so a typo doesn't create garbage projects. Create the project on the Projects page in PenHub first.

---

## Using the custom NXC modules

After install the modules are in `~/.nxc/modules/`. Add `-M collector_hosts` or `-M collector_dc` to your nxc commands:

```bash
# Check all hosts for MS17-010, coerce, PrintNightmare, WDigest, etc.
nxc smb 10.10.10.0/24 -u alex -p Password1 -M collector_hosts

# Check domain controllers for noPac and Zerologon
nxc smb dc01.corp.local -u alex -p Password1 -M collector_dc
```

Results land in `~/.nxc/workspaces/<ws>/nxc-vulns.db` and are sent to the server on the next sync. View them in **⚡ VULNS** in NXC Collector.

---

## What happens next

Once set up, cron runs `nxc_updater.py` every 10 minutes. Each run:

1. **Push** — reads all `~/.nxc/workspaces/<ws>/{proto}.db` plus `nxc-vulns.db`, normalizes, and `POST`s to `/api/sync`.
2. **Pull** — `GET`s the merged workspace from the server and overwrites the local merged database `~/.nxc/workspaces/<ws>/nxc-collector.db`.

Nothing needs to be triggered manually during work — just use nxc as usual. To sync immediately:

```bash
nxc_collector -upd
```

To export various target/password/login lists offline at any point (no server needed):

```bash
nxce all --nxc          # ready-to-run nxc commands for each PWN3D host
nxce smb -u admin       # SMB admin credentials for user 'admin'
nxce --brute ./spray    # write paired login/password/hash files for spray

# and much more...
```

See: **[Operator Workflow](../usage/Operator-Workflow.md)**, all flags in **[Operator Scripts Reference](../reference/Operator-Scripts-Reference.md)**.

---

## Optional: BloodHound config

If you use BloodHound in your work, Toolbox also generates a `--bh-setup` string to save BloodHound connection settings to `~/.nxc/nxc.conf`. These settings are stored on the server. See **[Module — Toolbox](../modules/Module-Toolbox.md)** for details.

---

## Uninstall

```bash
nxc_collector --install -rm
```

Removes binaries and cron entries. Your config, log, and local database **are preserved**.
