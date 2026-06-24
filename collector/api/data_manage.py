"""Visibility management routes: /api/custom_creds, /api/credentials/set_hidden, /api/dpapi/set_hidden,
/api/vulns/set_override"""

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException

from collector.core.auth import verify_token
from collector.core.constants import VULN_SLUGS
from collector.core.models import VulnOverrideBody
from collector.db import db_cursor

router = APIRouter()


@router.get("/api/custom_creds", dependencies=[Depends(verify_token)])
def get_custom_creds(
    workspace_id: int,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 100,
):
    """Return rows from custom_credentials (Toolbox Block 1 import), paginated."""
    conditions = ["workspace_id = ?"]
    params: list = [workspace_id]
    if search:
        like = f"%{search}%"
        conditions.append(
            "(login LIKE ? OR password LIKE ? OR ip LIKE ? OR domain LIKE ?"
            " OR proto LIKE ? OR url LIKE ? OR source LIKE ? OR comment LIKE ?)"
        )
        params.extend([like] * 8)
    where = " AND ".join(conditions)
    with db_cursor() as cur:
        total = cur.execute(
            f"SELECT COUNT(*) FROM custom_credentials WHERE {where}", params
        ).fetchone()[0]
        offset = (page - 1) * limit if limit > 0 else 0
        rows = cur.execute(f"""
            SELECT id, proto, ip, port, domain,
                   login AS username, password, credtype, brutforced,
                   url, source, comment
            FROM custom_credentials
            WHERE {where}
            ORDER BY id
            {"LIMIT ? OFFSET ?" if limit > 0 else ""}
        """, params + ([limit, offset] if limit > 0 else [])).fetchall()
    return {"rows": [dict(r) for r in rows], "total": total}


@router.delete("/api/custom_creds/{row_id}", dependencies=[Depends(verify_token)])
def delete_custom_cred(row_id: int, workspace_id: int):
    with db_cursor() as cur:
        cur.execute(
            "DELETE FROM custom_credentials WHERE id=? AND workspace_id=?",
            (row_id, workspace_id),
        )
    return {"ok": True}


@router.delete("/api/custom_creds", dependencies=[Depends(verify_token)])
def delete_all_custom_creds(workspace_id: int):
    """Delete every custom_credentials row for the workspace (manage-mode bulk action)."""
    with db_cursor() as cur:
        cur.execute(
            "DELETE FROM custom_credentials WHERE workspace_id=?",
            (workspace_id,),
        )
        deleted = cur.rowcount
    return {"ok": True, "deleted": deleted}


@router.post("/api/credentials/set_hidden", dependencies=[Depends(verify_token)])
def set_hidden(
    workspace_id: int = Body(...),
    domain:       str = Body(""),
    username:     str = Body(...),
    password:     str = Body(""),
    hidden:       int = Body(...),  # 1 = hide, 0 = restore
):
    """Toggle hidden flag on credential (and all credentials sharing the same username+domain)."""
    # GUARD: always reset hidden_by_strike=0 on manual hide/restore.
    # Manual actions take ownership of the hidden flag regardless of strike state.
    with db_cursor() as cur:
        cur.execute(
            "UPDATE credentials SET hidden=?, hidden_by_strike=0"
            " WHERE workspace_id=? AND LOWER(username)=LOWER(?)"
            " AND LOWER(COALESCE(domain,''))=LOWER(COALESCE(?,'')"
            ")",
            (hidden, workspace_id, username, domain),
        )
        updated = cur.rowcount
    return {"ok": True, "updated": updated}


@router.post("/api/dpapi/set_hidden", dependencies=[Depends(verify_token)])
def set_dpapi_hidden(
    workspace_id: int = Body(...),
    dpapi_id:     int = Body(...),
    hidden:       int = Body(...),
):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE dpapi_secrets SET hidden=? WHERE id=? AND workspace_id=?",
            (hidden, dpapi_id, workspace_id),
        )
    return {"ok": True}


@router.delete("/api/vulns/overrides", dependencies=[Depends(verify_token)])
def clear_vuln_overrides(workspace_id: int):
    """Delete all user-set vuln overrides for a workspace, restoring sync values."""
    with db_cursor() as cur:
        cur.execute("DELETE FROM vuln_overrides WHERE workspace_id=?", (workspace_id,))
        deleted = cur.rowcount
    return {"ok": True, "deleted": deleted}


@router.post("/api/vulns/set_override", dependencies=[Depends(verify_token)])
def set_vuln_override(body: VulnOverrideBody):
    """
    Set a manual tri-state override (1/0/null) for a specific host+vuln_name.
    User overrides take priority over sync values in the pivot (R6.1).
    GUARD: only valid vuln_name slugs accepted; sync UPSERT never touches vuln_overrides.
    """
    if body.vuln_name not in VULN_SLUGS:
        raise HTTPException(status_code=422, detail=f"Unknown vuln_name: {body.vuln_name}")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO vuln_overrides(workspace_id, ip, vuln_name, is_vulnerable)"
            " VALUES(?,?,?,?)"
            " ON CONFLICT(workspace_id, ip, vuln_name) DO UPDATE SET is_vulnerable=excluded.is_vulnerable",
            (body.workspace_id, body.ip, body.vuln_name, body.is_vulnerable),
        )
    return {"ok": True}
