"""
Notifications journal: pwn3d + domain_admin events (append-only).

Emission rules (see docs/superpowers/specs/2026-06-16-notifications-design.md):
- pwn3d: one event per host that gains its FIRST admin relation.
- domain_admin: one event per identity (domain+user) that becomes a known admin
  for the first time via watchlist (mirrors the admin_cred UPDATE, incl. admin_cred_locked=0).
"""
import uuid
import pytest

from collector.db import db_cursor


@pytest.fixture
def ws(auth_client):
    name = f"nt-{uuid.uuid4().hex[:8]}"
    wid = auth_client.post("/api/workspaces", json={"name": name}).json()["id"]
    return name, wid


def _sync(auth_client, ws_name, hosts=None, credentials=None, auth_relations=None):
    r = auth_client.post("/api/sync", json={
        "workspace": ws_name, "operator": "tester",
        "data": {
            "hosts": hosts or [],
            "credentials": credentials or [],
            "auth_relations": auth_relations or [],
        },
    })
    assert r.status_code == 200
    return r


def _notifs(auth_client, wid, ntype=None):
    r = auth_client.get(f"/api/notifications?workspace_id={wid}")
    assert r.status_code == 200
    rows = r.json()["rows"]
    return [x for x in rows if ntype is None or x["type"] == ntype]


def _upload_watchlist(auth_client, wid, domain, usernames):
    r = auth_client.post("/api/domain_admin_list/upload", json={
        "workspace_id": wid, "domain": domain, "usernames": usernames,
    })
    assert r.status_code == 200
    return r


# ── pwn3d ───────────────────────────────────────────────────────────────────

def _admin(host_ip, user, pw="Pw1", domain="corp.local"):
    return {"proto": "SMB", "host_ip": host_ip, "relation_type": "admin",
            "cred_domain": domain, "cred_username": user, "cred_password": pw,
            "cred_credtype": "plaintext"}


def _cred(user, pw="Pw1", domain="corp.local", credtype="plaintext"):
    return {"proto": "SMB", "domain": domain, "username": user,
            "password": pw, "credtype": credtype}


def test_pwn3d_first_admin_emits_event(auth_client, ws):
    name, wid = ws
    _sync(auth_client, name,
          hosts=[{"ip": "10.0.0.1", "hostname": "DC01", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.0.0.1", "alice")])
    ev = _notifs(auth_client, wid, "pwn3d")
    assert len(ev) == 1
    assert ev[0]["ref_host_id"] is not None
    assert "DC01" in ev[0]["title"]


def test_pwn3d_second_admin_same_host_no_event(auth_client, ws):
    name, wid = ws
    _sync(auth_client, name,
          hosts=[{"ip": "10.0.0.2", "hostname": "H2", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.0.0.2", "alice")])
    _sync(auth_client, name,
          credentials=[_cred("bob")],
          auth_relations=[_admin("10.0.0.2", "bob")])
    assert len(_notifs(auth_client, wid, "pwn3d")) == 1, \
        "second admin (different cred) on an already-pwned host must not re-notify"


def test_pwn3d_same_identity_new_host_emits(auth_client, ws):
    name, wid = ws
    _sync(auth_client, name,
          hosts=[{"ip": "10.0.0.3", "hostname": "A", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.0.0.3", "alice")])
    _sync(auth_client, name,
          hosts=[{"ip": "10.0.0.4", "hostname": "B", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.0.0.4", "alice")])
    assert len(_notifs(auth_client, wid, "pwn3d")) == 2, \
        "same identity admin on a NEW host is a new pwn3d event"


def test_pwn3d_resync_no_duplicate(auth_client, ws):
    name, wid = ws
    payload = dict(
        hosts=[{"ip": "10.0.0.5", "hostname": "C", "domain": "corp.local"}],
        credentials=[_cred("alice")],
        auth_relations=[_admin("10.0.0.5", "alice")],
    )
    _sync(auth_client, name, **payload)
    _sync(auth_client, name, **payload)
    assert len(_notifs(auth_client, wid, "pwn3d")) == 1, "full resync must not duplicate"


def test_pwn3d_loggedin_only_no_event(auth_client, ws):
    """A host with only a non-admin (loggedin) relation is not pwned → no event."""
    name, wid = ws
    rel = _admin("10.0.0.6", "alice")
    rel["relation_type"] = "loggedin"
    _sync(auth_client, name,
          hosts=[{"ip": "10.0.0.6", "hostname": "D", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[rel])
    assert len(_notifs(auth_client, wid, "pwn3d")) == 0


# ── domain_admin (via sync watchlist enrichment) ──────────────────────────────

def test_domain_admin_sync_emits(auth_client, ws):
    name, wid = ws
    _upload_watchlist(auth_client, wid, "corp.local", ["admin"])
    _sync(auth_client, name, credentials=[_cred("admin")])
    ev = _notifs(auth_client, wid, "domain_admin")
    assert len(ev) == 1
    assert ev[0]["ref_username"] == "admin"
    assert "admin" in ev[0]["title"].lower()


def test_domain_admin_resync_no_duplicate(auth_client, ws):
    name, wid = ws
    _upload_watchlist(auth_client, wid, "corp.local", ["admin"])
    _sync(auth_client, name, credentials=[_cred("admin")])
    _sync(auth_client, name, credentials=[_cred("admin")])
    assert len(_notifs(auth_client, wid, "domain_admin")) == 1


def test_domain_admin_locked_identity_no_event(auth_client, ws):
    """Manually cleared admin (admin_cred=0, locked=1) matching watchlist → UPDATE skips → no event."""
    name, wid = ws
    _sync(auth_client, name, credentials=[_cred("admin")])
    # operator manually clears admin → admin_cred_locked=1
    auth_client.post("/api/credentials/set_admin_cred", json={
        "workspace_id": wid, "domain": "corp.local", "username": "admin", "admin_cred": 0,
    })
    _upload_watchlist(auth_client, wid, "corp.local", ["admin"])
    _sync(auth_client, name, credentials=[_cred("admin")])
    assert len(_notifs(auth_client, wid, "domain_admin")) == 0


def test_domain_admin_different_password_same_identity_no_second_event(auth_client, ws):
    name, wid = ws
    _upload_watchlist(auth_client, wid, "corp.local", ["admin"])
    _sync(auth_client, name, credentials=[_cred("admin", pw="Pw1")])
    # new credential row, same identity, different password — identity already a known admin
    _sync(auth_client, name, credentials=[_cred("admin", pw="Pw2")])
    assert len(_notifs(auth_client, wid, "domain_admin")) == 1


def test_domain_admin_hash_plaintext_same_sync_one_event(auth_client, ws):
    name, wid = ws
    _upload_watchlist(auth_client, wid, "corp.local", ["admin"])
    _sync(auth_client, name, credentials=[
        _cred("admin", pw="Pw1", credtype="plaintext"),
        _cred("admin", pw="abcdef0123456789abcdef0123456789", credtype="hash"),
    ])
    assert len(_notifs(auth_client, wid, "domain_admin")) == 1, \
        "hash+plaintext of one identity in a single sync = one event"


# ── domain_admin (via dal.py upload) ──────────────────────────────────────────

def test_dal_upload_marks_existing_emits(auth_client, ws):
    name, wid = ws
    _sync(auth_client, name, credentials=[_cred("svc_da")])
    _upload_watchlist(auth_client, wid, "corp.local", ["svc_da"])
    ev = _notifs(auth_client, wid, "domain_admin")
    assert len(ev) == 1
    assert ev[0]["ref_username"] == "svc_da"


def test_dal_upload_repeat_no_event(auth_client, ws):
    name, wid = ws
    _sync(auth_client, name, credentials=[_cred("svc_da")])
    _upload_watchlist(auth_client, wid, "corp.local", ["svc_da"])
    _upload_watchlist(auth_client, wid, "corp.local", ["svc_da"])
    assert len(_notifs(auth_client, wid, "domain_admin")) == 1


# ── API ───────────────────────────────────────────────────────────────────────

def test_notifications_only_current_workspace(auth_client):
    n1 = f"nt-{uuid.uuid4().hex[:8]}"
    w1 = auth_client.post("/api/workspaces", json={"name": n1}).json()["id"]
    n2 = f"nt-{uuid.uuid4().hex[:8]}"
    w2 = auth_client.post("/api/workspaces", json={"name": n2}).json()["id"]
    _sync(auth_client, n1,
          hosts=[{"ip": "10.1.0.1", "hostname": "X", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.1.0.1", "alice")])
    assert len(_notifs(auth_client, w1, "pwn3d")) == 1
    assert len(_notifs(auth_client, w2)) == 0, "events must be scoped to their workspace"


def test_notifications_newest_first(auth_client, ws):
    name, wid = ws
    _sync(auth_client, name,
          hosts=[{"ip": "10.2.0.1", "hostname": "FIRST", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.2.0.1", "alice")])
    _sync(auth_client, name,
          hosts=[{"ip": "10.2.0.2", "hostname": "SECOND", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.2.0.2", "alice")])
    ev = _notifs(auth_client, wid, "pwn3d")
    assert ev[0]["id"] > ev[1]["id"], "newest first"
    assert "SECOND" in ev[0]["title"]


def test_retention_trims_to_500(auth_client, ws):
    name, wid = ws
    # Seed 505 rows directly, then emit one more via sync → trim keeps newest 500.
    with db_cursor() as cur:
        for i in range(505):
            cur.execute(
                "INSERT INTO notifications(workspace_id, type, title, created_at)"
                " VALUES(?,?,?,?)",
                (wid, "pwn3d", f"seed-{i}", "2026-01-01T00:00:00Z"),
            )
        lowest_seed = cur.execute(
            "SELECT MIN(id) FROM notifications WHERE workspace_id=?", (wid,)
        ).fetchone()[0]
    _sync(auth_client, name,
          hosts=[{"ip": "10.3.0.1", "hostname": "NEW", "domain": "corp.local"}],
          credentials=[_cred("alice")],
          auth_relations=[_admin("10.3.0.1", "alice")])
    with db_cursor() as cur:
        total = cur.execute(
            "SELECT COUNT(*) FROM notifications WHERE workspace_id=?", (wid,)
        ).fetchone()[0]
        oldest_gone = cur.execute(
            "SELECT COUNT(*) FROM notifications WHERE workspace_id=? AND id=?",
            (wid, lowest_seed),
        ).fetchone()[0]
    assert total == 500, f"retention must cap at 500, got {total}"
    assert oldest_gone == 0, "oldest row must be trimmed"
