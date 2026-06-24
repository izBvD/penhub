"""Domain Admin Watchlist routes: /api/domain_admin_list/*"""

from typing import List

from fastapi import APIRouter, Body, Depends, HTTPException

from datetime import datetime, timezone

from collector.core.auth import verify_token
from collector.db import db_cursor
from collector.services import notification_service

router = APIRouter()


@router.get("/api/domain_admin_list/top_domain", dependencies=[Depends(verify_token)])
def get_top_domain(workspace_id: int):
    """Return the domain with the most visible hosts for this workspace (min 1)."""
    with db_cursor() as cur:
        row = cur.execute(
            "SELECT domain, COUNT(*) AS c FROM hosts"
            " WHERE workspace_id=? AND domain!='' AND hidden=0"
            " GROUP BY domain ORDER BY c DESC LIMIT 1",
            (workspace_id,)
        ).fetchone()
    if row and row["c"] >= 1:
        return {"domain": row["domain"], "count": row["c"]}
    return {"domain": None, "count": 0}


@router.get("/api/domain_admin_list/pending", dependencies=[Depends(verify_token)])
def get_pending_dal(workspace_id: int):
    """Return domain_admin_list entries that have no matching credential yet (gray rows in ADM CREDS)."""
    with db_cursor() as cur:
        rows = cur.execute("""
            SELECT dal.domain, dal.username
            FROM domain_admin_list dal
            WHERE dal.workspace_id = ?
              AND NOT EXISTS (
                SELECT 1 FROM credentials c
                WHERE c.workspace_id = dal.workspace_id
                  AND LOWER(c.domain)   = LOWER(dal.domain)
                  AND LOWER(c.username) = LOWER(dal.username)
              )
            ORDER BY dal.domain, dal.username
        """, (workspace_id,)).fetchall()
    return {"rows": [dict(r) for r in rows]}


@router.post("/api/domain_admin_list/upload", dependencies=[Depends(verify_token)])
def upload_dal(
    workspace_id: int = Body(...),
    domain:       str = Body(...),
    usernames:    List[str] = Body(...),
):
    """
    Upload a list of domain admin usernames for a workspace.
    - Lines longer than 50 chars are skipped.
    - Domain is required. Values stored LOWER-cased; INSERT OR IGNORE deduplicates.
    - Existing credentials matching domain+username are immediately marked admin_cred=1.
    """
    domain = (domain or "").strip()
    if not domain:
        raise HTTPException(status_code=422, detail="domain is required")

    added = 0
    skipped_too_long = 0
    with db_cursor() as cur:
        for raw in usernames:
            username = (raw or "").strip()
            if not username:
                continue
            if len(username) > 50:
                skipped_too_long += 1
                continue
            cur.execute(
                "INSERT OR IGNORE INTO domain_admin_list(workspace_id, domain, username)"
                " VALUES(?, LOWER(?), LOWER(?))",
                (workspace_id, domain, username),
            )
            if cur.rowcount:
                added += 1

        # Capture identities this UPDATE will newly flip to admin (for notifications)
        # BEFORE running it — predicate mirrors the UPDATE's WHERE exactly.
        new_das = notification_service.pending_domain_admins(cur, workspace_id)
        # Auto-mark existing credentials that now match the uploaded list.
        # Skip rows where operator manually cleared admin_cred (admin_cred_locked=1).
        cur.execute("""
            UPDATE credentials SET admin_cred = 1
            WHERE workspace_id = ?
              AND admin_cred = 0
              AND admin_cred_locked = 0
              AND EXISTS (
                SELECT 1 FROM domain_admin_list dal
                WHERE dal.workspace_id = credentials.workspace_id
                  AND LOWER(dal.domain)   = LOWER(credentials.domain)
                  AND LOWER(dal.username) = LOWER(credentials.username)
              )
        """, (workspace_id,))
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        notification_service.emit_domain_admins(cur, workspace_id, new_das, now)

    return {"ok": True, "added": added, "skipped_too_long": skipped_too_long}


@router.delete("/api/domain_admin_list/entry", dependencies=[Depends(verify_token)])
def delete_dal_entry(workspace_id: int, domain: str, username: str):
    """Delete a specific domain_admin_list entry by workspace+domain+username (case-insensitive)."""
    d = (domain or "").strip().lower()
    u = (username or "").strip().lower()
    with db_cursor() as cur:
        cur.execute(
            "DELETE FROM domain_admin_list"
            " WHERE workspace_id=? AND LOWER(domain)=? AND LOWER(username)=?",
            (workspace_id, d, u),
        )
        if not cur.rowcount:
            raise HTTPException(status_code=404, detail="Entry not found")
    return {"ok": True}


@router.post("/api/domain_admin_list/clear_ghosts", dependencies=[Depends(verify_token)])
# NOTE: embed=True required because this endpoint has only one Body param.
# If a second Body param is added here later, remove embed=True — FastAPI wraps automatically with multiple params.
def clear_dal_ghosts(workspace_id: int = Body(..., embed=True)):
    """
    Delete domain_admin_list entries that have no matching credential with a real password.
    Only removes 'ghost' (pending/unmatched) entries. Does NOT touch credentials.admin_cred.
    """
    with db_cursor() as cur:
        cur.execute("""
            DELETE FROM domain_admin_list
            WHERE workspace_id = ?
              AND NOT EXISTS (
                SELECT 1 FROM credentials c
                WHERE c.workspace_id = domain_admin_list.workspace_id
                  AND LOWER(c.domain)   = LOWER(domain_admin_list.domain)
                  AND LOWER(c.username) = LOWER(domain_admin_list.username)
                  AND c.password != ''
                  AND c.password != '<empty_password>'
              )
        """, (workspace_id,))
        deleted = cur.rowcount
    return {"ok": True, "deleted": deleted}
