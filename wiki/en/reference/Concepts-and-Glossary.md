# Concepts and Glossary

PenHub uses a small vocabulary to describe its functionality. If you're having trouble with the terminology, start here.

---

## Core entities

**Project / Workspace** — two names for the same thing, seen from different sides. In the UI it's a *project*; on the operator side and in nxc it's a *workspace*. One project = one isolated dataset. Data does not cross between projects. The project name and the nxc workspace name must match for sync to succeed (configured via `nxc_collector`).

**Operator** — a person running NetExec and performing syncs. Every row in the database is tagged with the operator who contributed it (the `Op` column). Multiple operators can sync in parallel; the server merges them.

**Access key** — a single shared password for the entire platform. There are no per-user accounts.

**Two server databases**
- **`collector.db`** — all projects: hosts, credentials, auth relations, DPAPI secrets, shares, vulnerabilities. This is your working data accumulated during engagements.
- **`hashkiller.db`** — a *global* (across all your projects) NTLM hash↔plaintext database. **Not** tied to any project — it grows over time.

**Local merged database** — `~/.nxc/workspaces/<ws>/nxc-collector.db` on the operator's machine. The merged (server-sourced) project database that `nxc_updater` keeps in sync. Read by the offline extractor `nxce`.

---

## Data in NXC Collector

**PWN3D!** — **administrative** access to a host (auth relation type `admin`). **loggedin** — credentials are valid but not admin. The **PWN3D!** counter in the header and per-protocol **PWN3D!** sub-tabs show only admin access.

**Auth relation** — the link "this credential authenticated on this host", with type `admin` or `loggedin`.

**Credential** — a tuple `(protocol, domain, login, password, credtype)`. `credtype` is either `plaintext` or `hash`. Deduplication, spray preparation, and the hash database all work on these fields.

**Domain admin (`admin_cred`)** vs **local admin (`local_admin_cred`)** — two independent flags on a credential. Domain admins are tracked across the entire project; local admins are tracked per machine. The two flags are mutually exclusive on any single row.

**Domain Admin Watchlist** — a list of names you're watching in hope of finding their credentials (loaded in Toolbox). PenHub watches every sync; as soon as a password or hash appears for a name from the watchlist, that account is automatically marked `admin_cred=1`. Until then it appears as a grey **ghost row** (no password yet).

**Honeypot / Strike** — marking a host as a honeypot ("strike", done in Manage Mode) hides it and all its associated credentials, and marks newly appearing credentials on that host as hidden during future syncs. Used to suppress false-positive authentications. Credentials individually restored with **+** are not re-hidden, allowing you to surface one valid hit among many false positives.

**Hidden** — a soft-hide flag on credentials, hosts, and DPAPI entries. Hidden items disappear from normal views (and from the operator's pull) but are not deleted; they can be un-hidden in Manage Mode.
See: **[Module — NXC Collector](../modules/Module-NXC-Collector.md)**.

---

## HashKiller

**SMART pair** — a hash↔plaintext pair that PenHub *derived itself* by hashing a plaintext password found in a project (such pairs get `SMART=true` in the database). Core principle: "seen once — cracked everywhere."

**Warning pair** — when the same hash is somehow associated with two different plaintexts, both pairs are saved with `warning=true` for you to resolve the conflict.

**Empty password hash** — NT hash `31D6CFE0D16AE931B73C59D7E0C089C0` is the hash of an empty password. PenHub stores it as the literal `<empty_password>` everywhere (both server and operator side normalize it identically).
See: **[Module — HashKiller](../modules/Module-HashKiller.md)**.

---

## Vulnerability concepts

**Tri-state finding** — each vulnerability check on a host has one of three states: **YES** (vulnerable), **no** (clean), or **—** (no data / check could not be performed). **`—` is not "safe" by definition.**
See: **[Vulnerability Reference](../vulns/Vulnerability-Reference.md)**.

---

## Sync concepts

**Push / Pull** — `nxc_updater` does both in a single run. **Push**: send the current operator's/project's nxc data. **Pull**: overwrite the local DB with the fully merged data from all operators. Pull is a **full update**: everything hidden/honeypot/archived on the server is also reflected locally.

**Schema mapping (`nxc_schema.json`)** — a safety net. NetExec sometimes renames columns or tables in its databases after updates. PenHub reads databases through a JSON map, so a rename is fixed by editing JSON, not code. See **[Adapting to NetExec Schema Changes](Adapting-to-NetExec-Schema-Changes.md)**.

**Normalization** — before saving, passwords are cleaned: LM:NT hashes are reduced to the NT part; empty password hashes become `<empty_password>`. The exact same logic lives on both server and operator sides (an intentional duplication).

---

## Three modules

| Module            | Icon | Purpose                                                                                                  |
| ----------------- | ---- | -------------------------------------------------------------------------------------------------------- |
| **NXC Collector** | 📡   | View/sort/manage synced data: hosts, credentials, vulnerabilities, admin tracking.                       |
| **HashKiller**    | 🗡   | Global NTLM hash↔plaintext database; cracking and enrichment.                                            |
| **Toolbox**       | ⚙    | Custom imports, spray export lists, operator environment configuration.                                  |

Continue reading: [Table of Contents](../Wiki%20-%20table%20of%20contents.md)
