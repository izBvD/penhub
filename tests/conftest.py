"""
pytest fixtures for NXC Collector tests.

Uses temporary SQLite files that are cleaned up after the session.
"""

import hashlib
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Point collector.db and hashkiller.db at temp files BEFORE importing the app.
_tmp_dir = tempfile.mkdtemp(prefix="nxc_test_")
os.environ["NXC_TEST_DB"]   = os.path.join(_tmp_dir, "test_collector.db")
os.environ["NXC_TEST_HKDB"] = os.path.join(_tmp_dir, "test_hashkiller.db")

import collector.db as _db_mod
import collector.hashkiller_db as _hk_mod
import collector.core.auth as _auth

_db_mod.DB_PATH      = Path(os.environ["NXC_TEST_DB"])
_hk_mod.HK_DB_PATH   = Path(os.environ["NXC_TEST_HKDB"])
# Keep the hk_inbox/ dir created at startup inside the temp dir (cleaned at session end).
_hk_mod.HK_INBOX_DIR = Path(_tmp_dir) / "hk_inbox"

# Safety: ensure we are NOT using the real production database.
assert "nxc_test_" in str(_db_mod.DB_PATH), (
    "Test DB path does not look like a temp path — refusing to run against a real DB. "
    f"DB_PATH={_db_mod.DB_PATH}"
)

from penhub.app import app  # noqa: E402

TEST_PASSWORD = "test-password-42"
TEST_HASH     = hashlib.sha256(TEST_PASSWORD.encode()).hexdigest()


@pytest.fixture(scope="session", autouse=True)
def set_auth():
    _auth.APP_PASSWORD_HASH = TEST_HASH


@pytest.fixture(scope="session", autouse=True)
def cleanup_tmp_dir():
    """Remove temp test databases after the entire test session."""
    yield
    shutil.rmtree(_tmp_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def auth_client():
    """Authenticated TestClient — independent session, never logged out by tests."""
    with TestClient(app, raise_server_exceptions=True) as c:
        r = c.post("/api/login", json={"password": TEST_PASSWORD})
        assert r.status_code == 200
        yield c


@pytest.fixture(scope="session")
def workspace_id(auth_client):
    """Create a test workspace and return its ID."""
    r = auth_client.post("/api/workspaces", json={"name": "test-ws"})
    assert r.status_code == 200
    return r.json()["id"]
