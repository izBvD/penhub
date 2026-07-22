# Installation — Server

The PenHub server is a simple Python process. Deploy it on a machine accessible to operators on your internal/working network; all interaction happens in the browser. No separate database engine is required — SQLite files are created automatically on first run.

---

## Requirements

- **Python 3.12+**.
- Three Python packages: `fastapi`, `uvicorn`, `openpyxl`.
- A machine reachable by operators.
- An open TCP port (default **322**).

> PenHub has no external services, no Redis, no Postgres. State lives in two SQLite files next to the code (`collector.db`, `hashkiller.db`), created automatically on first start.

---

## Installation

```bash
# 1. clone the project
git clone https://github.com/izBvD/penhub.git
cd penhub

# 2. (recommended) virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. dependencies
pip install -r requirements.txt

# 4. start
python3 server.py --host 0.0.0.0 --port 322 --password "ChooseAStrongPassword"
```

That's it. On first start the server creates `collector.db`, `hashkiller.db`, and the `hk_inbox/` directory, then starts listening.

> **Windows without internet?** Install Python and the dependencies from the bundled `offline_windows_installer/` folder — see **[Installation — Windows Offline](Installation-Windows-Offline.md)**.

![](../../images/server-startup-terminal.png)

---

## Command-line options

| Flag         | Example              | Meaning                                                  |
| ------------ | -------------------- | -------------------------------------------------------- |
| `--host`     | `0.0.0.0`            | Interface to listen on.                                  |
| `--port`     | `322`                | TCP port.                                                |
| `--password` | `StrongPassword123!` | **The single access key** for the entire platform. Change it. |

The password is the only credential secret. It is hashed with `sha256` and used both for browser login and as the `X-Auth-Token` for operator clients. There are no per-user accounts — anyone with the access key can access all projects. This is intentional, for simplicity during a pentest (PenHub is designed for use inside a local network).

---

## First login

Open `http://<server-ip>:<port>/` in a browser and enter the access key.

![](../../images/login-page.png)

After login you land on the **Projects** page. Create your first project — see **[Quick Start](../usage/Quick-Start.md)**.

---

## Running as a service

Example `systemd` unit to run PenHub as a service:

```ini
# /etc/systemd/system/penhub.service
[Unit]
Description=PenHub server
After=network.target

[Service]
WorkingDirectory=/opt/penhub
ExecStart=/opt/penhub/.venv/bin/python server.py --host 0.0.0.0 --port 322 --password "StrongPasswordHere!"
Restart=on-failure
User=penhub

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now penhub
```

> The access key is stored in plaintext in the unit file — set `chmod 600` on it and restrict read access to `/etc/systemd/system/`.

---

## Backups

PenHub does not back up automatically. Manual only. The interface has buttons to download the database files.

- **`collector.db`** stores hosts and credentials for all projects. **`hashkiller.db`** stores the global hash database. Backing up both files is recommended.
- SQLite runs in **WAL mode** — you will also see accompanying `*.db-wal` / `*.db-shm` files. Back up the full set; ideally stop the server before copying.

Next: **[Installation — Operator Client](Installation-Operator-Client.md)** — set up the operator's machine.
