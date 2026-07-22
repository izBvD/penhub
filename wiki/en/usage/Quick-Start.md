# Quick Start

## 1. Start the server

On the server (details — **[Installation — Server](../install/Installation-Server.md)**):

```bash
pip install -r requirements.txt
python3 server.py --host 0.0.0.0 --port 322 --password "StrongPasswordHere!"
```

Open `http://<server-ip>:322/` in a browser and log in with the access key (--password).

---

## 2. Create a project

On the **Projects** page click **+ NEW PROJECT** and enter a name (e.g. `organisationX`). A project is an isolated workspace; data does not cross between projects.

![](../../images/projects-page.png)

---

## 3. Connect an operator

On the operator's machine, grab the scripts and config string from **Toolbox → Block 3** (see **[Installation — Operator Client](../install/Installation-Operator-Client.md)**), then:

```bash
./nxc_collector --install                 # installs scripts + cron, restart shell after

# paste COPY CONFIG STRING from Toolbox Block 3:
nxc_collector -ws --server http://<server-ip> --port 322 --pass "StrongPasswordHere!" --workspace organisationX --operator alice

nxc_collector --connection-test           # expect 200
```

---

## 4. Run nxc, then sync

Just use NetExec normally. Then either wait for cron (every 10 minutes) or push manually:

```bash
nxc_collector -upd
```

---

## 5. View in browser

The **NXC Collector** module will start filling up. Try:

- The **PWN3D!** counter in the header — hosts where you have admin access.
- Protocol row: click **SMB**, then the **PWN3D!** sub-tab to see admin sessions.
- The **Reports** module (📄, under Toolbox) → **ALL CREDS ↓** — export all unique credentials to XLSX.

![](../../images/nxc-collector-pwn3d.png)

Details: **[Module — NXC Collector](../modules/Module-NXC-Collector.md)**.

---

## 6. Hash cracking

Open **HashKiller** and click **⚡ SMART ENRICH**. Every plaintext password found in the current project is locally hashed and added to your global hash database — so when you encounter its NT hash again anywhere, it is automatically "cracked". The **🕽 KILL THEM ALL** button substitutes known plaintexts for any project hash that already has a match in the database.

Details: **[Module — HashKiller](../modules/Module-HashKiller.md)**.

---

## 7. Download spray archive

Open **Toolbox** and click **↓ DOWNLOAD ARCHIVE**. Downloads a ZIP with paired target/login/password/hash files ready for nxc credential spraying (see example commands in **Toolbox** → How to use).

Details: **[Module — Toolbox](../modules/Module-Toolbox.md)** and **[Operator Workflow](Operator-Workflow.md)**.

---

## 8. UI interactions

Column sorting, cell copy on click, smart copy, honeypot hiding, admin tracking, and more are all built in. Explore and find your own usage patterns.

[Back to contents](../Wiki%20-%20table%20of%20contents.md)
