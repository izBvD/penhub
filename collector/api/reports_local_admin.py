"""LOCAL ADMIN FOUNDER API (Reports module).

Read-only auto-detection of local admin accounts; JSON + XLSX export.
"""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from collector.core.auth import verify_token
from collector.core.workspace_utils import ws_safe
from collector.db import db_cursor
from collector.services.export_service import local_admins_xlsx
from collector.services.local_admin_service import find_local_admins

router = APIRouter()

_XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_TIER_LABEL = {"operator": "operator-marked", "admin": "admin-proven", "reuse": "reuse"}


@router.get("/api/reports/local-admins", dependencies=[Depends(verify_token)])
def local_admins(workspace_id: int = Query(...), min_hosts: int = Query(2)):
    with db_cursor() as cur:
        rows = find_local_admins(cur, workspace_id, min_hosts=max(2, min_hosts))
    return {"rows": rows, "count": len(rows)}


def _xrow(r):
    # Domain column dropped — "Machine list" already lists the machines (= hostnames).
    return [
        r["username"], r["secret"], r["credtype"], r["brutforced"] or "",
        r["machine_count"], ", ".join(r["machines"]),
        _TIER_LABEL.get(r["tier"], r["tier"]),
        "__hash__" if r["credtype"] == "hash" else None,
    ]


@router.get("/api/reports/local-admins/export", dependencies=[Depends(verify_token)])
def local_admins_export(workspace_id: int = Query(...), min_hosts: int = Query(2)):
    with db_cursor() as cur:
        rows = find_local_admins(cur, workspace_id, min_hosts=max(2, min_hosts))
    headers = ["Username", "Secret", "Type", "Cracked", "Machines", "Machine list", "Tier"]
    admins = [_xrow(r) for r in rows if r["tier"] in ("operator", "admin")]
    reused = [_xrow(r) for r in rows if r["tier"] == "reuse"]
    buf = local_admins_xlsx(admins, reused, headers)
    fn = f"{ws_safe(workspace_id)}_local_admins.xlsx"
    return StreamingResponse(
        buf, media_type=_XLSX_MIME,
        headers={"Content-Disposition": f'attachment; filename={fn}'},
    )
