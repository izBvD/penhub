# Troubleshooting and FAQ

"Everything is broken" usually comes down to a workspace name mismatch or the 10-minute cron cycle.

---

## Sync / access

**`--connection-test` returns 401/403.**
Wrong access key. The operator's `--pass` must match the server's `--password`. Try re-running the `-ws` config string from Toolbox.

**`--connection-test` returns nothing / hangs.**
Server unreachable: wrong IP/port, firewall is blocking, or the server is not running. Check whether `http://<ip>:<port>/` opens in a browser from the operator's machine.

**I ran sync but the project is empty.**
Almost always a **name mismatch**: the operator's `--workspace` doesn't match the project name on the server, *or* the project hasn't been created yet. `nxc_updater` intentionally **skips (exit 0)** when the workspace doesn't exist or is archived — it doesn't create it automatically. Create the project first with the exact name. Check `~/.nxc-collector.log`.

**Data is stale / doesn't match reality.**
Cron syncs every 10 minutes. Run manually: `nxc_collector -upd`. In the browser, enable **LIVE** (5-second refresh) or click **Reload**.

**A field stopped being collected after a NetExec update.**
nxc renamed a column or table. Look for the line `[schema] … missing column(s) …` in `~/.nxc-collector.log` and edit `nxc_schema.json`. See **[Adapting to NetExec Schema Changes](../reference/Adapting-to-NetExec-Schema-Changes.md)**.

**An archived project won't accept new data.**
By design. Archive = frozen; sync does not apply to it. Activate it on the Projects page to resume.

---

## Working with data

**I hid/deleted credentials and they came back.**
Expected. If you deleted rows from the DB they will be reinserted on the next push from an operator. During active work use **hide / strike / filters**, not deletion. Only **custom credentials** and **archived projects** are truly deleted. See **[Operator Workflow](../usage/Operator-Workflow.md)** → "Why hiding instead of deletion."

**A domain admin name shows as a grey row without a password.**
That's a **ghost row** — a Domain Admin Watchlist entry whose credentials haven't been found yet. It will fill in (or disappear) after a sync that brings the password. Incorrectly added entries are removed with **👻 CLEAR ADM GHOSTS** in Manage Mode.

**Guest / DefaultAccount credentials disappeared.**
The **GUEST** filter is on by default and hides them. Turn it off to see them. (Intentionally excluded — useless for spray and final reports.)

**Where I expected a password, a hash is shown (or vice versa).**
The **HK-bruted 🔓** filter substitutes known plaintext from HashKiller when available. Toggle it to see the hash. If the plaintext is unknown — try running **SMART ENRICH** + **KILL THEM ALL** in HashKiller to "fill in" known passwords.

**Two different passwords for the same hash in HashKiller.**
A **warning** pair — both are saved (`warning=true`). Resolve via EXPORT WARNING → review → DELETE FROM FILE. See **[Module — HashKiller](../modules/Module-HashKiller.md)**. Then add the correct `hash:plaintext` pairs if you know them.

---

## Server / operations

**What should I back up?**
Two SQLite files in the server root: `collector.db` (all projects) and `hashkiller.db` (global hashes), plus their `-wal`/`-shm` companions. Back up the full set or stop the server before copying.

**Can it run behind HTTPS?**
Yes — put nginx/caddy in front of the server and terminate TLS there. PenHub itself serves plain HTTP. In a trusted network this is unnecessary, which is why we didn't build in HTTPS by default.

**Importing a large potfile is too slow / hangs the browser.**
Don't use the browser for multi-gigabyte files. Place the file in `hk_inbox/large.potfile` on the server and use **📁 SERVER FILE** (or **💥 RAM-KILLER** for maximum speed). See **[Module — HashKiller](../modules/Module-HashKiller.md)**.

---

## FAQ

**Is there per-user authentication?**
No — one shared access key for the entire platform.

**Does PenHub exploit the vulnerabilities it shows?**
No. Detection and aggregation only.

**Can multiple operators work on the same project simultaneously?**
Yes — that's the primary use case. Independent crons, idempotent merges, WAL serialization. See **[Operator Workflow](../usage/Operator-Workflow.md)**.

**Does HashKiller reset between projects?**
No — it's global and persists across all projects and engagements. That's the point: a hash cracked once is cracked everywhere forever.

**Can a project be renamed?**
Yes — the pencil icon in the project row on the Projects page appears on hover. (After renaming, operators need to update `--workspace` in their config to the new name.)
