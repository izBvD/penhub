"""REUSED PASSWORDS API (Reports module) — JSON + XLSX export."""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from collector.core.auth import verify_token
from collector.core.workspace_utils import ws_safe
from collector.db import db_cursor
from collector.services.export_service import xlsx_buf
from collector.services.reused_password_service import find_reused_passwords

router = APIRouter()

_XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@router.get("/api/reports/reused-passwords", dependencies=[Depends(verify_token)])
def reused_passwords(workspace_id: int = Query(...), min_count: int = Query(2)):
    with db_cursor() as cur:
        rows = find_reused_passwords(cur, workspace_id, min_count=max(2, min_count))
    return {"rows": rows, "count": len(rows)}


@router.get("/api/reports/reused-passwords/export", dependencies=[Depends(verify_token)])
def reused_passwords_export(workspace_id: int = Query(...), min_count: int = Query(2)):
    with db_cursor() as cur:
        rows = find_reused_passwords(cur, workspace_id, min_count=max(2, min_count))
    headers = ["Password / Hash", "Type", "Accounts (domain\\login)", "DPAPI (url;login)", "Count"]
    body = [[
        r["secret"], r["type"], "\n".join(r["accounts"]), "\n".join(r["dpapi"]), r["count"],
        "__hash__" if r["type"] == "hash" else None,
    ] for r in rows]
    buf = xlsx_buf(headers, body, "ReusedPasswords", wrap_cols=[2, 3])  # Accounts, DPAPI
    fn = f"{ws_safe(workspace_id)}_reused_passwords.xlsx"
    return StreamingResponse(
        buf, media_type=_XLSX_MIME,
        headers={"Content-Disposition": f'attachment; filename={fn}'},
    )
