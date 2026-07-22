"""Timeline API (Reports module). Canonical overrides + custom nodes + read model.

GUARD: `workspace_config` timeline_first_sync* keys are written only by the sync
hook (collector/api/sync.py); this router never mutates them.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from collector.core.auth import verify_token
from collector.core.workspace_utils import ws_safe
from collector.db import db_cursor
from collector.services.timeline_service import build_timeline

router = APIRouter()

_CANON_KINDS = {"first_sync", "first_account", "first_pwned", "first_da"}
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _norm_ts(ts: str) -> str:
    """Accept ISO (with Z / offset / 'T' or ' ' separator) → canonical '...Z'."""
    if not ts:
        raise HTTPException(400, "ts required")
    t = ts.strip().replace(" ", "T").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        raise HTTPException(400, f"bad ts: {ts}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(_TS_FMT)


def _now() -> str:
    return datetime.now(timezone.utc).strftime(_TS_FMT)


class CanonicalBody(BaseModel):
    workspace_id: int
    kind: str
    label: Optional[str] = None
    ts: str
    detail: Optional[str] = None


class CustomBody(BaseModel):
    workspace_id: int
    label: str
    ts: str
    detail: Optional[str] = None


class CustomEdit(BaseModel):
    label: str
    ts: str
    detail: Optional[str] = None


@router.get("/api/timeline", dependencies=[Depends(verify_token)])
def get_timeline(workspace_id: int = Query(...)):
    with db_cursor() as cur:
        return build_timeline(cur, workspace_id)


@router.put("/api/timeline/canonical", dependencies=[Depends(verify_token)])
def put_canonical(body: CanonicalBody):
    if body.kind not in _CANON_KINDS:
        raise HTTPException(400, "bad kind")
    ts = _norm_ts(body.ts)
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO timeline_nodes(workspace_id,kind,label,ts,detail,created_at)
            VALUES(?,?,?,?,?,?)
            ON CONFLICT(workspace_id,kind) WHERE kind != 'custom'
            DO UPDATE SET label=excluded.label, ts=excluded.ts, detail=excluded.detail
        """, (body.workspace_id, body.kind, body.label, ts, body.detail, _now()))
    return {"ok": True}


@router.delete("/api/timeline/canonical", dependencies=[Depends(verify_token)])
def reset_canonical(workspace_id: int = Query(...), kind: str = Query(...)):
    if kind not in _CANON_KINDS:
        raise HTTPException(400, "bad kind")
    with db_cursor() as cur:
        cur.execute("DELETE FROM timeline_nodes WHERE workspace_id=? AND kind=?",
                    (workspace_id, kind))
    return {"ok": True}


@router.post("/api/timeline/custom", dependencies=[Depends(verify_token)])
def add_custom(body: CustomBody):
    ts = _norm_ts(body.ts)
    with db_cursor() as cur:
        cur.execute("INSERT INTO timeline_nodes(workspace_id,kind,label,ts,detail,created_at)"
                    " VALUES(?,?,?,?,?,?)",
                    (body.workspace_id, "custom", body.label, ts, body.detail, _now()))
        nid = cur.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    return {"ok": True, "id": nid}


@router.put("/api/timeline/custom/{node_id}", dependencies=[Depends(verify_token)])
def edit_custom(node_id: int, body: CustomEdit):
    ts = _norm_ts(body.ts)
    with db_cursor() as cur:
        n = cur.execute("UPDATE timeline_nodes SET label=?, ts=?, detail=?"
                        " WHERE id=? AND kind='custom'",
                        (body.label, ts, body.detail, node_id)).rowcount
    if not n:
        raise HTTPException(404, "custom node not found")
    return {"ok": True}


@router.delete("/api/timeline/custom/{node_id}", dependencies=[Depends(verify_token)])
def delete_custom(node_id: int):
    with db_cursor() as cur:
        cur.execute("DELETE FROM timeline_nodes WHERE id=? AND kind='custom'", (node_id,))
    return {"ok": True}


def _fmt_abs(ts: str) -> str:
    # "2026-07-01T09:12:00Z" → "2026-07-01 09:12:00 UTC"
    return ts.replace("T", " ").replace("Z", " UTC") if ts else ""


@router.get("/api/timeline/download", dependencies=[Depends(verify_token)])
def download_timeline(workspace_id: int = Query(...)):
    with db_cursor() as cur:
        row = cur.execute("SELECT name FROM workspaces WHERE id=?", (workspace_id,)).fetchone()
        tl = build_timeline(cur, workspace_id)
    ws_name = row["name"] if row else str(workspace_id)
    lines = [f"TIMELINE — {ws_name}",
             f"Generated: {_fmt_abs(_now())}", ""]
    for i, n in enumerate(tl["nodes"], 1):
        detail = f"  ({n['detail']})" if n["detail"] else ""
        lines.append(f"{i}. {n['label']} — {_fmt_abs(n['ts'])}{detail}")
        if n["elapsed_str"]:
            lines.append(f"   Elapsed from point {i - 1}: {n['elapsed_str']}")
    if tl["total_str"]:
        lines += ["", f"Total (point 1 → {len(tl['nodes'])}): {tl['total_str']}"]
    if tl["pending"]:
        lines += ["", "Not reached:"] + [f"- {p}" for p in tl["pending"]]
    body = ("\n".join(lines) + "\n").encode("utf-8")
    fn = f"{ws_safe(workspace_id)}_timeline.txt"
    return Response(content=body, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fn}"'})
