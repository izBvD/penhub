# Operator Scripts Reference

Reference for the three operator scripts.
Installation — **[Installation — Operator Client](../install/Installation-Operator-Client.md)**; usage scenarios — **[Operator Workflow](../usage/Operator-Workflow.md)**.

```
nxc_collector   →  installer and configurator
nxc_updater.py  →  sync engine (cron */10 + @reboot)
nxce.py         →  offline extractor
```

---

## Config files

| File                                      | Written by                             | Contains                                                   |
| ----------------------------------------- | -------------------------------------- | ---------------------------------------------------------- |
| `~/.nxc-collector.conf`                   | `nxc_collector`                        | `[collector]`: server, port, password, operator, workspace |
| `~/.nxc/nxc.conf`                         | `nxc_collector` (`-ws`, `--bh-setup`) | nxc workspace, `[BloodHound]` section                      |
| `~/.nxc/workspaces/<ws>/nxc-collector.db` | `nxc_updater` (pull)                   | local merged DB (read by `nxce`)                           |
| `~/.nxc-collector.log`                    | cron                                   | sync log                                                   |

**Auth token** (same in `nxc_collector` and `nxc_updater`): `sha256(password)` in hex, header `X-Auth-Token`.

---

## 1. `nxc_collector` (bash) — install and configure

| Command                     | Action                                                                                                                                                                                                                                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--install`                 | Copies `nxc_updater`, `nxc_collector`, `nxce` to `/usr/local/bin` (or `~/bin` if no write access) + `chmod +x`. Also copies NXC modules `collector_dc.py`, `collector_hosts.py` → `~/.nxc/modules/` (mkdir -p). Sets up cron `*/10` + `@reboot sleep 30`. Re-running updates scripts and modules, preserves config. |
| `--install -rm`             | Removes binaries, NXC modules from `~/.nxc/modules/`, and cron entries. Config, log, and local DB are preserved.                                                                                                                                                                                                    |
| `-ws` / `--workspace-setup` | Writes `~/.nxc-collector.conf`: `--server`, `--port`, `--operator`, `--pass`, `--workspace`. With `--workspace` also edits `~/.nxc/nxc.conf` and creates the nxc workspace.                                                                                                                                         |
| `--bh-setup`                | Writes BloodHound settings to `~/.nxc/nxc.conf`: `--bh-ip/-login/-pass/-port/-enable`.                                                                                                                                                                                                                             |
| `--connection-test`         | `curl` `GET /api/workspaces` with token. 200 = OK · 401/403 = wrong password · no output = server unreachable.                                                                                                                                                                                                      |
| `--show-options`            | Prints config, workspace, BloodHound section.                                                                                                                                                                                                                                                                       |
| `-upd` / `--update`         | Force sync (runs `nxc_updater.py`).                                                                                                                                                                                                                                                                                 |

---

## 2. `nxc_updater.py` — sync engine

Runs from cron. Each run: **resolve workspace → push → pull.**

**Resolve workspace.** `GET /api/workspaces`. If the workspace doesn't exist or is archived — sync is **skipped (exit 0)**, nothing is pushed.

**Phase 1 — push.** Reads all `~/.nxc/workspaces/<ws>/{proto}.db` (smb, ldap, winrm, mssql, ssh, ftp, nfs, vnc, wmi, rdp) plus `nxc-vulns.db`, normalizes, and `POST`s to `/api/sync`.

**Phase 2 — pull.** `GET`s `/api/hosts | credentials | results | dpapi | custom_creds` (paginated) and overwrites the local merged DB. **Full update**: `DELETE` + inserts everything received from the server — so anything hidden/honeypot/archived on the server disappears locally too. A network error rolls back the entire pull, so a failure never wipes the local DB. Writes `meta.last_pull`.

**What each reader extracts:**

| Reader              | Protocols          | Extracts                                                                                  |
| ------------------- | ------------------ | ----------------------------------------------------------------------------------------- |
| `_read_smb`         | smb                | hosts (+ vulnerability flags), users→creds, admin/loggedin relations, DPAPI, shares, conf checks |
| `_read_users_proto` | ldap, winrm, mssql | hosts (+ proto fields), users→creds, relations                                            |
| `_read_creds_proto` | ftp, nfs, vnc, wmi | hosts, creds (vnc: pkey), relations, directory listings (ftp/nfs)                         |
| `_read_ssh`         | ssh                | hosts, creds, SSH keys, relations                                                         |
| `_read_rdp`         | rdp                | hosts only (nla, port)                                                                    |

This configuration is primarily driven by the contents of the local databases.

Plus `_read_collector_vulns` (separate `nxc-vulns.db` written by our nxc modules `collector_dc`/`collector_hosts`) → `vuln_findings`.

**Password normalization** exactly mirrors server-side logic (LM:NT → NT; empty password hash → `<empty_password>`). For the schema safety mapping applied here — see **[Adapting to NetExec Schema Changes](Adapting-to-NetExec-Schema-Changes.md)**.

---

## 3. `nxce.py` — offline PWN3D Extractor

Reads **only** the local merged database. Workspace is selected from `~/.nxc-collector.conf`.

Can work within a specific protocol: `smb ldap winrm mssql ssh` or `all`. Queries `auth_relations WHERE relation_type='admin'` (admin/PWN3D only).

| Flag                             | Meaning                                                       |
| -------------------------------- | ------------------------------------------------------------- |
| `-u/--user`, `-d/--domain`, `-p` | Case-insensitive filters by user / domain / password          |
| `-i IP/CIDR`                     | Exact IP or subnet (CIDR filtered in Python)                  |
| `--hash` / `--plain`             | Hash-only / plaintext-only credentials                        |
| `--ip`                           | Unique IPs only                                               |
| `--nxc`                          | Ready-to-run `nxc <proto> <ip> -u … -H/-p …` commands        |
| `-c/--count`                     | Count rows                                                    |
| `-o FILE`                        | Write to file                                                 |

**`--brute DIR` — export for password spray.** Writes paired files (logins/secrets line-by-line):
- `logins_P_brut.txt` / `pass_for_brute.txt` (plaintext)
- `logins_H_brut.txt` / `hashes_for_brute.txt` (NT hashes)

Data sourced from: `credentials` + `custom_credentials`; guest users and empties are skipped. Prints the ready-to-use `nxc … --no-bruteforce --continue-on-success` command.
