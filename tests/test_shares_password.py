"""
Shares view must expose password (and brutforced) from the linked credential.
"""
import uuid
from collector.db import db_cursor


def _setup(auth_client, password="SecretPass", brutforced=None):
    name = f"sh-{uuid.uuid4().hex[:8]}"
    wid = auth_client.post("/api/workspaces", json={"name": name}).json()["id"]
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO hosts (workspace_id, ip, hostname) VALUES (?,?,?)",
            (wid, "10.0.0.1", "DC01"),
        )
        host_id = cur.lastrowid
        cur.execute(
            "INSERT INTO credentials (workspace_id, proto, domain, username, password,"
            " credtype, brutforced) VALUES (?,?,?,?,?,?,?)",
            (wid, "SMB", "corp", "alice", password, "plaintext", brutforced),
        )
        cred_id = cur.lastrowid
        cur.execute(
            "INSERT INTO shares (workspace_id, host_id, credential_id, name, remark, read, write)"
            " VALUES (?,?,?,?,?,?,?)",
            (wid, host_id, cred_id, "SYSVOL", "Logon server share", 1, 0),
        )
    return wid


def test_shares_returns_password(auth_client):
    wid = _setup(auth_client, password="SecretPass")
    r = auth_client.get(f"/api/shares?workspace_id={wid}")
    assert r.status_code == 200
    rows = r.json()["rows"]
    assert rows, "expected at least one share row"
    assert "password" in rows[0], "password field missing from shares response"
    assert rows[0]["password"] == "SecretPass"


def test_shares_returns_domain(auth_client):
    wid = _setup(auth_client)
    r = auth_client.get(f"/api/shares?workspace_id={wid}")
    rows = r.json()["rows"]
    assert "domain" in rows[0], "domain field missing from shares response"
    assert rows[0]["domain"] == "corp"


def test_shares_returns_brutforced(auth_client):
    wid = _setup(auth_client, password="NTHash1", brutforced="CrackedPass")
    r = auth_client.get(f"/api/shares?workspace_id={wid}")
    rows = r.json()["rows"]
    assert rows[0].get("brutforced") == "CrackedPass"


def test_shares_null_password_ok(auth_client):
    """Share with no linked credential (credential_id=NULL) must not crash."""
    name = f"sh-{uuid.uuid4().hex[:8]}"
    wid = auth_client.post("/api/workspaces", json={"name": name}).json()["id"]
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO hosts (workspace_id, ip) VALUES (?,?)", (wid, "10.0.0.2")
        )
        host_id = cur.lastrowid
        cur.execute(
            "INSERT INTO shares (workspace_id, host_id, credential_id, name, read, write)"
            " VALUES (?,?,NULL,?,?,?)",
            (wid, host_id, "ADMIN$", 0, 0),
        )
    r = auth_client.get(f"/api/shares?workspace_id={wid}")
    assert r.status_code == 200
    rows = r.json()["rows"]
    assert rows[0].get("password") is None
