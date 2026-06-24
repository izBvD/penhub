"""
R15.2 — allcred dedup: SQL CTE must produce identical results to
Python smart_dedup_creds(apply_brutforced(...)). Tests describe
desired behaviour and are green with both implementations.
"""
import uuid
from io import BytesIO

import openpyxl
import pytest

from collector.db import db_cursor


@pytest.fixture
def ws(auth_client):
    name = f"ac-{uuid.uuid4().hex[:8]}"
    wid = auth_client.post("/api/workspaces", json={"name": name}).json()["id"]
    return name, wid


def _ins(workspace_id, proto, domain, username, password,
         credtype="plaintext", local_admin_cred=0, brutforced=None, hidden=0):
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR IGNORE INTO credentials"
            " (workspace_id, proto, domain, username, password,"
            "  credtype, local_admin_cred, brutforced, hidden)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (workspace_id, proto, domain, username, password,
             credtype, local_admin_cred, brutforced, hidden),
        )


def _parse(content: bytes) -> dict:
    """Parse allcred XLSX into {plain, admin, hash, dpapi, custom} section lists."""
    wb = openpyxl.load_workbook(BytesIO(content))
    ws = wb["Credentials"]
    sections: dict = {"plain": [], "admin": [], "hash": [], "dpapi": [], "custom": []}
    section = "plain"
    skip_next = False  # skip section header row after separator
    for row in list(ws.iter_rows(values_only=True))[1:]:  # skip first header
        label = row[0]
        if label == "LOCAL ADMIN": section = "admin";  skip_next = True; continue
        if label == "HASHES":      section = "hash";   skip_next = True; continue
        if label == "DPAPI":       section = "dpapi";  skip_next = True; continue
        if label == "CUSTOM":      section = "custom"; skip_next = True; continue
        if skip_next:              skip_next = False;   continue
        if any(v is not None for v in row):
            sections[section].append(row)
    return sections


def _creds(s: dict) -> list:
    """All credential rows (plain + admin + hash sections)."""
    return s["plain"] + s["admin"] + s["hash"]


def _find(rows: list, login: str, domain: str | None = None):
    """Find first row matching login (col 2) and optionally domain (col 1)."""
    for row in rows:
        if row[2] == login and (domain is None or row[1] == domain):
            return row
    return None


def _get(auth_client, workspace_id: int) -> dict:
    r = auth_client.get(f"/api/export/allcred?workspace_id={workspace_id}")
    assert r.status_code == 200
    return _parse(r.content)


# ── Basic ─────────────────────────────────────────────────────────────────────

def test_allcred_empty_workspace(auth_client, ws):
    _, wid = ws
    r = auth_client.get(f"/api/export/allcred?workspace_id={wid}")
    assert r.status_code == 200


def test_allcred_plaintext_exported(auth_client, ws):
    _, wid = ws
    _ins(wid, "SMB", "corp", "alice", "Password1")
    s = _get(auth_client, wid)
    row = _find(s["plain"], "alice", "corp")
    assert row is not None
    assert row[3] == "Password1"


# ── Dedup: plaintext wins ─────────────────────────────────────────────────────

def test_allcred_plaintext_beats_hash(auth_client, ws):
    """Same (domain, user) with hash AND plaintext → only one row, shows plaintext."""
    _, wid = ws
    _ins(wid, "SMB",  "corp", "bob", "NTHash1",   "hash")
    _ins(wid, "LDAP", "corp", "bob", "Password2",  "plaintext")
    s = _get(auth_client, wid)
    all_bob = [r for r in _creds(s) if r[2] == "bob"]
    assert len(all_bob) == 1, f"expected 1 bob row, got {len(all_bob)}: {all_bob}"
    assert all_bob[0][3] == "Password2", "plaintext must win over hash"


def test_allcred_no_duplicate_per_domain_user(auth_client, ws):
    """(domain, user) appears exactly once even with multiple proto/password combinations."""
    _, wid = ws
    _ins(wid, "SMB",  "corp", "carol", "NTHash2",   "hash")
    _ins(wid, "LDAP", "corp", "carol", "NTHash2",   "hash")       # same hash, different proto
    _ins(wid, "SMB",  "corp", "carol", "Password3",  "plaintext") # plaintext wins
    s = _get(auth_client, wid)
    all_carol = [r for r in _creds(s) if r[2] == "carol"]
    assert len(all_carol) == 1, f"expected 1 carol row, got {len(all_carol)}"
    assert all_carol[0][3] == "Password3"


def test_allcred_cross_host_plain_beats_hash(auth_client, ws):
    """Hash credential + plaintext for same user → result shows plaintext."""
    _, wid = ws
    _ins(wid, "SMB", "corp", "dave", "NTHash3",  "hash")
    _ins(wid, "SMB", "corp", "dave", "DavePass",  "plaintext")
    s = _get(auth_client, wid)
    all_dave = [r for r in _creds(s) if r[2] == "dave"]
    assert len(all_dave) == 1
    assert all_dave[0][3] == "DavePass"


# ── Brutforced ────────────────────────────────────────────────────────────────

def test_allcred_brutforced_hash_as_plain(auth_client, ws):
    """Hash with brutforced value → appears in plain section with the cracked password."""
    _, wid = ws
    _ins(wid, "SMB", "corp", "eve", "NTHash4", "hash", brutforced="EvePass")
    s = _get(auth_client, wid)
    assert _find(s["hash"], "eve") is None, "cracked hash must not appear in HASHES section"
    row = _find(s["plain"], "eve")
    assert row is not None, "cracked hash must appear in plain section"
    assert row[3] == "EvePass"


def test_allcred_uncracked_hash_stays_in_hash_section(auth_client, ws):
    _, wid = ws
    _ins(wid, "SMB", "corp", "frank", "NTHash5", "hash")
    s = _get(auth_client, wid)
    assert _find(s["plain"], "frank") is None
    assert _find(s["hash"], "frank") is not None


# ── Exclusion filters ─────────────────────────────────────────────────────────

def test_allcred_hidden_excluded(auth_client, ws):
    _, wid = ws
    _ins(wid, "SMB", "corp", "grace", "Secret", hidden=1)
    s = _get(auth_client, wid)
    assert _find(_creds(s), "grace") is None


def test_allcred_empty_username_excluded(auth_client, ws):
    _, wid = ws
    _ins(wid, "SMB", "corp", "", "Password")
    s = _get(auth_client, wid)
    assert not any(r[2] == "" or r[2] is None for r in _creds(s))


def test_allcred_guest_excluded(auth_client, ws):
    _, wid = ws
    _ins(wid, "SMB", "corp", "Guest", "Password")   # capital G — casefold catches it
    _ins(wid, "SMB", "corp", "GUEST", "Password2", "hash")
    s = _get(auth_client, wid)
    assert _find(_creds(s), "Guest") is None
    assert _find(_creds(s), "GUEST") is None


# ── Local admin ───────────────────────────────────────────────────────────────

def test_allcred_local_admin_in_section(auth_client, ws):
    _, wid = ws
    _ins(wid, "SMB", "MACHINE1", "administrator", "AdminPass", local_admin_cred=1)
    s = _get(auth_client, wid)
    assert _find(s["admin"], "administrator", "MACHINE1") is not None
    assert _find(s["plain"], "administrator", "MACHINE1") is None
