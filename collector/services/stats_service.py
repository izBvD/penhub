"""
Workspace credential counter shared by /api/stats (topbar) and /api/workspaces (projects page).
"""

from collector.core.constants import _GUEST_NAMES_SQL
from collector.services.data_service import apply_brutforced, smart_dedup_creds


def count_workspace_creds(cur, workspace_id: int) -> int:
    """Unique creds: smart-deduped credentials + DISTINCT DPAPI secrets + custom_credentials.

    GUARD: single source of the CREDS counter — topbar stats and the projects
    page must always agree (see BACKLOG 2026-06-05 stats/allcred mismatch).
    """
    cred_rows = [dict(r) for r in cur.execute(
        "SELECT DISTINCT proto, domain, username, password, credtype, brutforced"
        " FROM credentials"
        " WHERE workspace_id=? AND username != '' AND username IS NOT NULL"
        " AND hidden = 0"
        " AND casefold(username) NOT IN"
        f" {_GUEST_NAMES_SQL}",
        (workspace_id,)
    ).fetchall()]
    creds = len(smart_dedup_creds(apply_brutforced(cred_rows)))
    creds += cur.execute(
        "SELECT COUNT(*) FROM ("
        "  SELECT DISTINCT dpapi_type, host_ip, url, username, password"
        "  FROM dpapi_secrets"
        "  WHERE workspace_id=? AND username IS NOT NULL AND username != '' AND hidden=0"
        ")",
        (workspace_id,)
    ).fetchone()[0]
    creds += cur.execute(
        "SELECT COUNT(*) FROM custom_credentials WHERE workspace_id=?",
        (workspace_id,)
    ).fetchone()[0]
    return creds
