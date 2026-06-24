"""
Workspace management routes: /api/workspaces CRUD + archive
"""

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse

import collector.hashkiller_db as hk_db
from collector.core.auth import verify_token
from collector.core.models import WorkspaceCreate, WorkspaceRename
from collector.db import db_cursor, DB_PATH
from collector.services.stats_service import count_workspace_creds

router = APIRouter()


@router.get("/api/workspaces", dependencies=[Depends(verify_token)])
def list_workspaces():
    with db_cursor() as cur:
        rows = cur.execute("""
            SELECT w.id, w.name, w.created_at, w.archived_at, w.recycled_at,
                   (SELECT COUNT(DISTINCT ip) FROM hosts WHERE workspace_id = w.id AND hidden = 0) AS hosts,
                   (SELECT COUNT(DISTINCT ar.host_id) FROM auth_relations ar
                    JOIN hosts h ON h.id = ar.host_id AND h.hidden = 0
                    JOIN credentials c ON c.id = ar.credential_id AND c.hidden = 0
                    WHERE ar.workspace_id = w.id AND ar.relation_type = 'admin') AS admin
            FROM workspaces w
            ORDER BY w.name
        """).fetchall()

        result = []
        for row in rows:
            ws_id = row["id"]
            creds = count_workspace_creds(cur, ws_id)
            d = dict(row)
            d["creds"] = creds
            result.append(d)
    return result


@router.post("/api/workspaces", dependencies=[Depends(verify_token)])
def create_workspace(body: WorkspaceCreate):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name required")
    with db_cursor() as cur:
        existing = cur.execute(
            "SELECT id, name FROM workspaces WHERE LOWER(name) = LOWER(?)", (name,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail=f"Project '{existing['name']}' already exists")
        cur.execute("INSERT INTO workspaces(name) VALUES(?)", (name,))
        row = cur.execute(
            "SELECT id, name, created_at, archived_at FROM workspaces WHERE name=?", (name,)
        ).fetchone()
    return dict(row)


@router.patch("/api/workspaces/{ws_id}", dependencies=[Depends(verify_token)])
def rename_workspace(ws_id: int, body: WorkspaceRename):
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name required")
    with db_cursor() as cur:
        row = cur.execute("SELECT id, name FROM workspaces WHERE id=?", (ws_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        if row["name"] != name:
            conflict = cur.execute(
                "SELECT id FROM workspaces WHERE LOWER(name) = LOWER(?) AND id != ?", (name, ws_id)
            ).fetchone()
            if conflict:
                raise HTTPException(status_code=409, detail=f"Project '{name}' already exists")
            cur.execute("UPDATE workspaces SET name=? WHERE id=?", (name, ws_id))
    return {"ok": True, "name": name}


@router.post("/api/workspaces/{ws_id}/archive", dependencies=[Depends(verify_token)])
def archive_workspace(ws_id: int, background_tasks: BackgroundTasks):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db_cursor() as cur:
        row = cur.execute("SELECT id, name FROM workspaces WHERE id=?", (ws_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        cur.execute("UPDATE workspaces SET archived_at=? WHERE id=?", (now, ws_id))
    background_tasks.add_task(_bg_smart_enrich, ws_id, row["name"])
    return {"ok": True}


@router.post("/api/workspaces/{ws_id}/unarchive", dependencies=[Depends(verify_token)])
def unarchive_workspace(ws_id: int):
    with db_cursor() as cur:
        row = cur.execute("SELECT id FROM workspaces WHERE id=?", (ws_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        cur.execute("UPDATE workspaces SET archived_at=NULL WHERE id=?", (ws_id,))
    return {"ok": True}


@router.delete("/api/workspaces/{ws_id}", dependencies=[Depends(verify_token)])
def recycle_workspace(ws_id: int):
    """Move workspace to recycle bin (soft delete). Data is preserved; name stays reserved."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db_cursor() as cur:
        row = cur.execute("SELECT id FROM workspaces WHERE id=?", (ws_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        cur.execute("UPDATE workspaces SET recycled_at=? WHERE id=?", (now, ws_id))
    return {"ok": True}


@router.post("/api/workspaces/{ws_id}/restore_active", dependencies=[Depends(verify_token)])
def restore_to_active(ws_id: int):
    """Restore workspace from recycle bin to Active state (clears both recycled_at and archived_at)."""
    with db_cursor() as cur:
        row = cur.execute("SELECT id FROM workspaces WHERE id=?", (ws_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        cur.execute("UPDATE workspaces SET recycled_at=NULL, archived_at=NULL WHERE id=?", (ws_id,))
    return {"ok": True}


@router.post("/api/workspaces/{ws_id}/restore_archive", dependencies=[Depends(verify_token)])
def restore_to_archive(ws_id: int):
    """Restore workspace from recycle bin to Archive state (clears recycled_at, keeps/sets archived_at)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with db_cursor() as cur:
        row = cur.execute(
            "SELECT id, archived_at FROM workspaces WHERE id=?", (ws_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        arch = row["archived_at"] or now
        cur.execute(
            "UPDATE workspaces SET recycled_at=NULL, archived_at=? WHERE id=?", (arch, ws_id)
        )
    return {"ok": True}


@router.delete("/api/workspaces/{ws_id}/permanent", dependencies=[Depends(verify_token)])
def permanent_delete_workspace(ws_id: int, background_tasks: BackgroundTasks):
    """Permanently delete workspace (irreversible).
    SMART ENRICH runs first (credentials still present), then CASCADE delete.
    Both happen in a single background task so enrich always sees the data.
    """
    with db_cursor() as cur:
        row = cur.execute("SELECT id, name FROM workspaces WHERE id=?", (ws_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")
    background_tasks.add_task(_bg_enrich_then_delete, ws_id, row["name"])
    return {"ok": True}


def _bg_smart_enrich(ws_id: int, ws_name: str):
    try:
        hk_db.smart_enrich_workspace(ws_id, ws_name)
    except Exception:
        pass


def _bg_enrich_then_delete(ws_id: int, ws_name: str):
    """Run SMART ENRICH while credentials still exist, then hard-delete the workspace."""
    try:
        hk_db.smart_enrich_workspace(ws_id, ws_name)
    except Exception:
        pass
    try:
        with db_cursor() as cur:
            cur.execute("DELETE FROM workspaces WHERE id=?", (ws_id,))
    except Exception:
        pass


@router.get("/api/download/db", dependencies=[Depends(verify_token)])
def download_db():
    if not DB_PATH.exists():
        raise HTTPException(status_code=404, detail="Database file not found")
    return FileResponse(
        path=str(DB_PATH),
        media_type="application/octet-stream",
        filename="collector.db",
    )
