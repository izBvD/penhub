"""
Workspace name helpers shared by export routers.
"""

from collector.db import db_cursor


def ws_safe(workspace_id: int) -> str:
    """Return workspace name sanitized for use in filenames; falls back to id."""
    with db_cursor() as cur:
        row = cur.execute("SELECT name FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
    raw = (row["name"] if row else None) or ""
    safe = "".join(c if c.isascii() and (c.isalnum() or c in "-_") else "_" for c in raw).strip("_")
    return safe or str(workspace_id)
