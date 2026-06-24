#!/usr/bin/env python3
"""
NXC Collector — server entry point.

Запуск:
  python3 server.py --host 0.0.0.0 --port 322 --password "StrongPass"

Зависимости:
  pip install fastapi uvicorn openpyxl
"""

import argparse
import hashlib

import uvicorn

import collector.core.auth as _auth
from penhub.app import app  # noqa: F401 — needed for uvicorn


def main():
    parser = argparse.ArgumentParser(description="NXC Collector server")
    parser.add_argument("--host",     default="0.0.0.0")
    parser.add_argument("--port",     type=int, default=322)
    parser.add_argument("--password", default="StrongPassword123")
    args = parser.parse_args()

    # Set auth state BEFORE uvicorn starts (sync, single-threaded at this point)
    _auth.APP_PASSWORD_HASH = hashlib.sha256(args.password.encode()).hexdigest()
    _auth.APP_PASSWORD      = args.password

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
