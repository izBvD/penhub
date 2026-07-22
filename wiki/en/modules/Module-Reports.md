# Module — Reports 📄

Reporting module: project timeline, automatic local-admin discovery, and final exports in one place.

---

## Block 1 — TIMELINE

A timeline of the engagement's key milestones drawn as a "map": nodes connected by dashed lines, with the time elapsed from the previous point shown beside the line. All times are UTC.

![](../../images/reports-timeline.png)

Four anchor points are detected automatically (where possible):

| Point | What it is |
| ----- | ---------- |
| **First sync** | The first sync received for the project (even an empty one) — "start of work". |
| **First captured account** | The earliest captured account with a secret. |
| **First PWNED** | The first host with admin access; the label shows the host and the account used to get it. |
| **First Domain Admin** | The first watchlist domain-admin account for which data was obtained. |

For points that carry an account, the secret is appended to the label: the plaintext password if known (including one cracked via HashKiller), otherwise the hash — `DOMAIN\user:secret`.

Any point can be **edited** (by clicking): set your own time, label, and data — for honeypots, false positives, or manual marking. An edited point can be reverted to its auto value. Points not reached yet are shown as a grey **Not reached** list below the route.

- **+ ADD NODE** — add your own node (e.g. "got VPN access").
- **↓ DOWNLOAD TIMELINE** (button in the EXPORTS block) — the timeline as a TXT report: points with times, the intervals between them, and the total time.

![](../../images/reports-timeline2.png)

---

## Block 2 — LOCAL ADMIN FOUNDER 💻

**↓ LOCAL ADMINS** — automatic discovery of local admins across the project, exported to XLSX. Among the pile of accounts from LSA+SAM (where local and domain accounts are mixed) it picks out the local accounts — mainly to surface password/hash reuse across different machines.

Domain accounts, domain-controller dumps, Guest, and empty passwords are filtered out automatically. The export has two sections:

- **LOCAL ADMINS** — local admins: marked by the operator (💻 Mark as local admin in NXC Collector) and those that gained admin access (PWN3D) over SMB.
- **REUSED LOCAL CREDENTIALS** — local accounts whose credentials repeat on ≥2 machines.

![](../../images/reports-lafounder.png)

---

## Block 3 — EXPORTS

Final project-level exports.

| Button | Downloads |
| ------ | --------- |
| **👑 ALL CREDS ↓** | All *unique* credentials in the project, split into logical blocks. XLSX. |
| **⚡ ALL VULNS ↓** | Per-host vulnerability matrix (the VULNS — ALL view). XLSX. |
| **📅 DOWNLOAD TIMELINE ↓** | The project timeline from Block 1. TXT. |
| **🔑 REUSED PASSWORDS ↓** | All logins that share a password. One row per secret (password/hash) used in ≥2 places: every `domain\login` that uses it (from LSA+SAM, custom, and all sources) + DPAPI `url;login` with the same password + a reuse count. XLSX. Can be used to find sign-ups on third-party sites that reuse a corporate password. |

> The **ALL CREDS ↓** button moved here from the NXC Collector toolbar. The export itself is unchanged.
