# Module — HashKiller 🗡

**The NTLM hash database**, shared across all projects. Works with **NT hashes only**.
Every time anyone, in any project, finds a plaintext password, its NT hash becomes permanently "cracked" for the entire platform.

The empty password hash `31D6CFE0D16AE931B73C59D7E0C089C0` is stored as the literal `<empty_password>`.

**DB fields:** `hash`, `plaintext`, `SMART` (bool), `warning` (bool). The top bar shows three counters: **pairs** / **smart** / **⚠ warning**.

![](../../images/hashkiller-overview.png)

The page consists of four blocks.

---

## Block 1 — IMPORT

Paste text or upload a `.potfile` / `.txt`. Recognized formats:

- `HASH:PLAIN`
- `LM:NT:PLAIN`
- `$NT$HASH:PLAIN`

Unknown lines are skipped.

| Button             | What it does                                                                                                                                                                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **▶ IMPORT**       | Import pasted text or the selected file (up to 50 MB).                                                                                                                                                                                                        |
| **📁 SERVER FILE** | Import a large potfile pre-uploaded to the server at `hk_inbox/large.potfile`. Background task, cache limited to 256 MB. For multi-gigabyte files.                                                                                                            |
| **💥 RAM-KILLER**  | Same as SERVER FILE, but expands the cache to a large portion (60-70%) of available RAM for maximum speed on a large database. Don't be put off by the name — it's figurative. You'll have roughly 40% of RAM remaining for server operation. |

Result shows `added / already existed / time (speed) / cache MB`.

> SERVER FILE / RAM-KILLER are designed to ingest gigabytes of cracked hashes. Such lists can be produced by transforming a large wordlist into `hash:plaintext` format yourself.
>
> After a large import **always** check and clear warnings.

---

## Block 2 — ACTIONS

| Button               | What it does                                                                                                                                                                                                                                                                                                             |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **⚡ SMART ENRICH**   | Within the current project: takes every plaintext password (`credentials` + custom imports not yet marked as bruteforced), computes its NT hash locally, and adds the `nt:plaintext` pair with `SMART=true`. So a password seen once becomes a crack in every future project. Empty passwords are skipped.                |
| **🕽 KILL THEM ALL** | For every NT hash in the current project without a plaintext, looks for a match in HashKiller; if found — writes the password to the account's *Bruteforced* field.                                                                                                                                                      |
| **↓ HASHES.TXT**     | Download all uncracked NT hashes for the current project (for `hashcat -m 1000`).                                                                                                                                                                                                                                        |
| **☢ ALL WORKSPACES** | Applies KILL THEM ALL logic across *all* projects, including archived ones.                                                                                                                                                                                                                                               |

Long operations have a progress bar (`Processing: X / Y`) and a **✕ Cancel** button.

**Module workflow:** click **SMART ENRICH** to collect existing plaintext, then **KILL THEM ALL** to substitute matched hashes. Export remaining hashes with **↓ HASHES.TXT** for hashcat, then import results back in Block 1.

---

## Block 3 — DB WORK

| Button                  | What it does                                                                                                                                               |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **↓ DOWNLOAD DB**       | Download the HashKiller database (backup / transfer).                                                                                                      |
| **↑ UPLOAD DB**         | Upload a database and *enrich* (not replace) the current one. Same hash with different plaintext → both pairs are saved, `warning=true`.                   |
| **↓ EXPORT SMART**      | Export all `hash:plain` pairs with `SMART=true`.                                                                                                           |
| **⚠↓ EXPORT WARNING**   | Export all `hash:plain` pairs with `warning=true`.                                                                                                         |
| **✕ DELETE**            | Delete by hash, plaintext, or `hash:plain` pair. First searches, shows matches with SMART/warning flags, deletes only after confirmation.                  |
| **📄 DELETE FROM FILE** | Bulk delete: upload a txt with `hash:plain` or `hash` lines (e.g. an EXPORT WARNING file) → all matches are deleted.                                       |

The export/delete pair is the workflow for resolving **warning** conflicts: export warnings, decide which plaintexts are wrong, bulk-delete them from file.

---

## Block 4 — HOW TO USE

Reference block describing import formats, SMART Enrich logic, KILL THEM ALL logic, and a typical workflow.

---

## Real-world performance

Building the database and index takes a long time for large wordlists, but it only needs to be done once; everything after that runs fast.

- **Initial build — one time only:** importing a wordlist of **120 million passwords** via **💥 RAM-KILLER** and building the index took **~6 hours on 32 GB RAM**.
- **Every run after:** **🕽 KILL THEM ALL** — searching and "decrypting" against the same **120 million pairs** — runs at roughly **500 hashes per second on SSD**. Within a project you typically get a few thousand hashes from a domain or LSA/SAM dumps, and the full 120,000,000-word lookup completes in seconds.

![](../../images/hashkiller-stat.png)

---

## Connection to other modules

- **NXC Collector** uses HashKiller: the **HK-bruted 🔓** filter shows cracked plaintext instead of the hash wherever a match exists.
- **Archiving a project** automatically runs a background SMART Enrich so the project's plaintext passwords are saved to the global database.
- Since the database is global, a hash cracked while working on *clientA* is instantly "cracked" when you encounter it in *clientB*. The effect is cumulative.
