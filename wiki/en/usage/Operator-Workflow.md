# Operator Workflow

A detailed walkthrough of a typical operator engagement.
Use this to understand *when and which* module does its work.

---

## Big picture

- Every operator runs their own cron `nxc_updater`. Pushes are idempotent and serialized by WAL, so simultaneous syncs never overwrite or corrupt data.
- On **pull** every operator receives the **full merged workspace** — data from all operators, not just their own. Each row is tagged with the operator who found it.
- Switching workspace (`-ws`) on the operator's machine switches to a different local database; projects never mix.

```
 alice ─┐
 bob   ─┼──push──►  PenHub project "organisationX"  ──pull──►  each operator gets local DB
 carol ─┘                  (collector.db)
```

---

## Phase 1 — Start

1. **Start/verify the server** — running and reachable. (**[Installation — Server](../install/Installation-Server.md)**)
2. **Create a project** on the Projects page.
3. **Operators — download scripts (if needed) + config** from Toolbox (DOWNLOAD SCRIPTS + COPY CONFIG STRING).
4. **If applicable** — **add the Domain Admin Watchlist (from AD, for example)** using Toolbox, so PenHub marks and notifies you as soon as credentials are found.

---

## Phase 2 — Work and data accumulation

Operators use **NetExec**. `nxc_updater` automatically pushes findings and pulls the merged picture.

In the browser:
- Watch the counters in the header and **notification bells** 🏆 / ☠ for new captures and emerging domain admins. (**[Notifications](Notifications.md)**)
- Browse credentials and hosts by protocol; mark **domain/local admins**; hide unnecessary hosts in Manage Mode as needed. (**[Module — NXC Collector](../modules/Module-NXC-Collector.md)**)
- Import credentials from external sources (obtained outside nxc) via Toolbox **Custom Import**.

Force sync at any time: `nxc_collector -upd`.

---

## Phase 3 — Hash "cracking" and base enrichment

Typically done after accumulating a decent mass of hashes and passwords.

In **HashKiller**:
1. **⚡ SMART ENRICH** — collect every found plaintext password into the global hash database.
2. **🕽 KILL THEM ALL** — substitute plaintext for matching hashes in the project.
3. **↓ HASHES.TXT** → download the file of unique uncracked hashes for hashcat → after cracking, import results in HashKiller IMPORT block.

Cracked plaintext appears immediately in NXC Collector (filter **HK-bruted**) and enriches spray lists. (**[Module — HashKiller](../modules/Module-HashKiller.md)**)

---

## Phase 4 — Password spray

Grab the spray kit from **Toolbox → DOWNLOAD ARCHIVE** (or `nxce --brute ./spray` offline). It contains not-yet-captured targets plus 1:1 paired login/password and login/hash files. Run nxc spray with `--no-bruteforce --continue-on-success`, then sync new results. Repeat: new captures shrink `not_pwnd_ip.txt`, new credentials expand the spray. (**[Exports](Exports.md)**)

```
view ──► crack ──► spray ──► sync ──► view …
```

---

## Phase 5 — Report and wrap-up

- Use the XLSX export from **VULNS** and **[Vulnerability Details and Remediation](../vulns/Vulnerability-Details.md)** as a vulnerability report appendix.
- In the **[Reports](../modules/Module-Reports.md)** module: the final credentials table (**ALL CREDS ↓**), the vulnerability matrix (**ALL VULNS ↓**), local admins (**LOCAL ADMINS ↓**), and the project timeline (**DOWNLOAD TIMELINE ↓**).
- **Archive** the project when done — this freezes it (no new syncs accepted) and automatically runs a final SMART Enrich so found plaintext passwords are saved to the global hash database for future engagements.
- Projects can later be moved to **Recycle** (soft delete, name reserved) or ultimately deleted permanently.

---

## Why the UI uses hiding instead of deletion

During active work, hard-deleting synced rows is pointless — the next sync from the operator reinserts them. To reduce noise (guests, honeypots, duplicates), use **GUEST/UNIQ filters**, **hide**, and **strike**. Only **custom credentials** and **archived projects** are truly deleted. The absence of hard deletion is intentional sync logic, not a missing feature.
