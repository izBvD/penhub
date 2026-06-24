"""
Workspace rename: PATCH /api/workspaces/{id}
"""
import uuid
import pytest


def _mk(auth_client, name=None):
    name = name or f"ws-{uuid.uuid4().hex[:8]}"
    r = auth_client.post("/api/workspaces", json={"name": name})
    assert r.status_code == 200
    return r.json()["id"], name


def test_rename_ok(auth_client):
    wid, _ = _mk(auth_client)
    new_name = f"renamed-{uuid.uuid4().hex[:6]}"
    r = auth_client.patch(f"/api/workspaces/{wid}", json={"name": new_name})
    assert r.status_code == 200
    assert r.json()["name"] == new_name


def test_rename_visible_in_list(auth_client):
    wid, _ = _mk(auth_client)
    new_name = f"listed-{uuid.uuid4().hex[:6]}"
    auth_client.patch(f"/api/workspaces/{wid}", json={"name": new_name})
    names = [w["name"] for w in auth_client.get("/api/workspaces").json()]
    assert new_name in names


def test_rename_conflict_409(auth_client):
    _, name_a = _mk(auth_client)
    wid_b, _ = _mk(auth_client)
    r = auth_client.patch(f"/api/workspaces/{wid_b}", json={"name": name_a})
    assert r.status_code == 409


def test_rename_conflict_case_insensitive(auth_client):
    _, name_a = _mk(auth_client)
    wid_b, _ = _mk(auth_client)
    r = auth_client.patch(f"/api/workspaces/{wid_b}", json={"name": name_a.upper()})
    assert r.status_code == 409


def test_rename_same_name_ok(auth_client):
    wid, name = _mk(auth_client)
    r = auth_client.patch(f"/api/workspaces/{wid}", json={"name": name})
    assert r.status_code == 200


def test_rename_empty_400(auth_client):
    wid, _ = _mk(auth_client)
    r = auth_client.patch(f"/api/workspaces/{wid}", json={"name": "   "})
    assert r.status_code == 400


def test_rename_not_found_404(auth_client):
    r = auth_client.patch("/api/workspaces/999999", json={"name": "whatever"})
    assert r.status_code == 404
