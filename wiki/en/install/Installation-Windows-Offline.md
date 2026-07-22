# Installation — Windows Offline

Install Python and all server dependencies on Windows **without internet** — for an isolated / air-gapped machine. Everything needed is already bundled in the [`offline_windows_installer/`](../../../offline_windows_installer) folder in the repository.

---

## What's included

- `install.bat` — the installer (run by double-click or from a console).
- `python-3.12.10-amd64.exe` — the Python installer (used only if Python isn't already on the machine).
- `packages/` — wheel files for every dependency: `fastapi`, `uvicorn`, `openpyxl`, `python-multipart`, and their transitive packages.
- `install_fallback.py` — a fallback installer in case pip fails.

---

## Installation

Copy the whole project (including the `offline_windows_installer/` folder) to the target machine and run:

```bat
cd offline_windows_installer
install.bat
```

What `install.bat` does, step by step:

1. Looks for Python on the system; if none is found, installs **Python 3.12.10** from the bundled `.exe` (a per-user install without admin rights first, falling back to a system install).
2. Installs the dependencies from the local `packages/` folder with `pip --no-index --find-links packages` — **without touching the internet**.
3. If pip fails, it extracts the wheels directly via `install_fallback.py` (wheels for a different Python version are skipped automatically).
4. Verifies that `fastapi` / `uvicorn` / `openpyxl` / `multipart` / `pydantic` import, and prints their versions.

> If Python had to be installed, **restart the terminal** (so PATH refreshes). Then start the server as usual (see **[Installation — Server](Installation-Server.md)**):
> ```
> python server.py --host 0.0.0.0 --port 322 --password "ChooseAStrongPassword"
> ```

---

## If something goes wrong

- **Python installation failed** — run `install.bat` as Administrator.
- **`python-3.12.10-amd64.exe` is missing** — download it from [python.org](https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe) on a machine with internet, place it next to `install.bat`, then move the folder over.
- **A different Python is already installed** (e.g. 3.14) — the installer picks it up; the wheels matching your version are selected automatically.
