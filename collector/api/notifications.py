"""Notification journal read route: GET /api/notifications

Read-only. The journal is written exclusively by services/notification_service.py
(emission in sync.py / dal.py). "Unread" is computed client-side via localStorage —
the server keeps no per-user seen state (single shared access key).
"""

from fastapi import APIRouter, Depends, Query

from collector.core.auth import verify_token
from collector.db import db_cursor

router = APIRouter()

_NOTIF_PAGE = 50  # newest events returned per request


@router.get("/api/notifications", dependencies=[Depends(verify_token)])
def get_notifications(workspace_id: int = Query(...)):
    """Return the newest events for a workspace, newest first."""
    with db_cursor() as cur:
        rows = cur.execute(
            "SELECT id, type, title, ref_host_id, ref_domain, ref_username, created_at"
            " FROM notifications WHERE workspace_id=?"
            " ORDER BY id DESC LIMIT ?",
            (workspace_id, _NOTIF_PAGE),
        ).fetchall()
    return {"rows": [dict(r) for r in rows]}
