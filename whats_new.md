# What's New

## PenHub v1.1

### 🆕 New module — Reports 📄

A new reporting module (sidebar, under Toolbox) that brings project-level outputs together in one place. Three blocks:

- **TIMELINE** — an engagement route drawn as a "map": milestone nodes ("bullet holes") laid out in a zigzag and joined by dashed connectors, with the time elapsed between points shown alongside (all times UTC). Four anchor points are detected automatically — **First sync**, **First captured account**, **First PWNED**, **First Domain Admin** — each in one of three states (auto / manual override / pending). Points that carry an account also show the credential used, with its secret appended (`DOMAIN\user:secret` — the plaintext password if known, including one cracked via HashKiller, otherwise the hash). You can add your own custom nodes, edit any point through a form (native date/time picker), and download the whole timeline as a TXT report (points, intervals, total time).
- **LOCAL ADMIN FOUNDER** 💻 — one-click auto-detection of local admin accounts, exported to XLSX. Automatically separates local accounts from domain ones (auto-derived AD-domain set, handles multi-domain forests and name collisions). Two sections: **LOCAL ADMINS** (operator-marked + admin-proven on SMB) and **REUSED LOCAL CREDENTIALS** (local secrets reused across ≥2 machines — the classic shared local `Administrator`, a lateral-movement goldmine).
- **EXPORTS** — **ALL CREDS**, **ALL VULNS** (the VULNS — ALL view), **DOWNLOAD TIMELINE**, and **REUSED PASSWORDS** (every login that shares a password — one row per secret with all `domain\login` and DPAPI URLs that use it, from LSA+SAM, custom, and everywhere passwords live; cracked hashes unify with their plaintext).

### ↔ ALL CREDS moved

The **ALL CREDS ↓** export moved out of the NXC Collector toolbar into the Reports module (EXPORTS block). The export itself is unchanged.

### 🗡 HashKiller — ADD BY PASSWORD

Paste or upload a plaintext password list (one per line); each password is hashed to NT locally and stored as a `hash:plaintext` pair — a quick way to push a wordlist or a batch of known passwords straight into the global hash database without going through hashcat.

- **Fix:** passwords starting with `#` are no longer dropped as "comments" (`#` is a valid password character). Only blank lines are skipped.

### 🧰 New operator script — `dicgenerat.py`

`nxc_collector --install` now also installs **`dicgenerat.py`**, a hashcat dictionary generator for cracking the project's uncracked hashes. It pulls the workspace's credentials from the server (API) and produces two files: `<ws>_base.txt` (unique passwords + logins + domains + DPAPI creds) and `<ws>_mutated.txt` (login mutations — strip → EN↔RU transliteration → English-keyboard-layout → case variants → charset/year tails). Feed the result to hashcat together with the project's uncracked hashes:

```bash
hashcat -a 0 -m 1000 <project>_hashes.txt <project>_mutated.txt
```

It can also mutate logins from a local file instead of the API — `dicgenerat --offline-file logins.txt` (no server/config needed, same mutations).

See the [Operator Scripts Reference](wiki/en/reference/Operator-Scripts-Reference.md).

### 📦 Installation

- Added **`requirements.txt`** — install with `pip install -r requirements.txt`.
- **Fix:** added the missing **`python-multipart`** dependency, required for every file upload (HashKiller DB / potfile / password list, Toolbox XLSX import). Without it those endpoints failed.
- New **offline Windows installer** (`offline_windows_installer/`): installs Python and every dependency on an air-gapped Windows machine with no internet — `install.bat` + bundled wheels + bundled Python, with an automatic fallback if pip can't run.

### 🗂 Projects page

Projects in every tab (Active / Archive / Recycle) are now sorted by creation date, newest first.

### 🐛 Fixes

- Sidebar navigation wiring for the new module (click-to-open, active highlight, deep-link).
