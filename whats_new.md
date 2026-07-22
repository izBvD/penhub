# What's New

## PenHub v1.1

### 🆕 New module — Reports 📄

A new reporting module (sidebar, under Toolbox) that brings project-level outputs together in one place. Three blocks:

- **TIMELINE** — an engagement route drawn as a "map": milestone nodes ("bullet holes") laid out in a zigzag and joined by dashed connectors, with the time elapsed between points shown alongside (all times UTC). Four anchor points are detected automatically — **First sync**, **First captured account**, **First PWNED**, **First Domain Admin** — each in one of three states (auto / manual override / pending). Points that carry an account also show the credential used, with its secret appended (`DOMAIN\user:secret` — the plaintext password if known, including one cracked via HashKiller, otherwise the hash). You can add your own custom nodes, edit any point through a form (native date/time picker), and download the whole timeline as a TXT report (points, intervals, total time).
- **LOCAL ADMIN FOUNDER** 💻 — one-click auto-detection of local admin accounts, exported to XLSX. Automatically separates local accounts from domain ones (auto-derived AD-domain set, handles multi-domain forests and name collisions). Two sections: **LOCAL ADMINS** (operator-marked + admin-proven on SMB) and **REUSED LOCAL CREDENTIALS** (local secrets reused across ≥2 machines — the classic shared local `Administrator`, a lateral-movement goldmine).
- **EXPORTS** — **ALL CREDS**, **ALL VULNS** (the VULNS — ALL view), and **DOWNLOAD TIMELINE**.

### ↔ ALL CREDS moved

The **ALL CREDS ↓** export moved out of the NXC Collector toolbar into the Reports module (EXPORTS block). The export itself is unchanged.

### 🗡 HashKiller — ADD BY PASSWORD

Paste or upload a plaintext password list (one per line); each password is hashed to NT locally and stored as a `hash:plaintext` pair — a quick way to push a wordlist or a batch of known passwords straight into the global hash database without going through hashcat.

- **Fix:** passwords starting with `#` are no longer dropped as "comments" (`#` is a valid password character). Only blank lines are skipped.

### 📦 Installation

- Added **`requirements.txt`** — install with `pip install -r requirements.txt`.
- **Fix:** added the missing **`python-multipart`** dependency, required for every file upload (HashKiller DB / potfile / password list, Toolbox XLSX import). Without it those endpoints failed.
- New **offline Windows installer** (`offline_windows_installer/`): installs Python and every dependency on an air-gapped Windows machine with no internet — `install.bat` + bundled wheels + bundled Python, with an automatic fallback if pip can't run.

### 🗂 Projects page

Projects in every tab (Active / Archive / Recycle) are now sorted by creation date, newest first.

### 🐛 Fixes

- Sidebar navigation wiring for the new module (click-to-open, active highlight, deep-link).
