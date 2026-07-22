"""
HashKiller API routes: /api/hk/*

_hk_tasks is intentionally in-memory — cleared on server restart by design.
"""

import functools
import os
import tempfile
import uuid

import collector.hashkiller_db as hk_db
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import FileResponse

from collector.core.auth import verify_token
from collector.db import db_cursor

router = APIRouter()

# In-memory task registry (lost on server restart — by design)
_hk_tasks: dict = {}
_HK_TASKS_MAX   = 200


def _hk_task_run(task_id: str, fn, *args):
    """Run fn(*args, progress_cb=...) in background; store result in _hk_tasks."""
    _hk_tasks[task_id]["progress"] = None

    def _cb(current: int, total: int) -> bool:
        """Report progress; return True to signal cancellation."""
        t = _hk_tasks.get(task_id, {})
        t["progress"] = {"current": current, "total": total}
        return t.get("cancelled", False)

    try:
        result = fn(*args, progress_cb=_cb)
        _hk_tasks[task_id].update({"status": "done", "result": result, "error": None})
    except Exception as exc:
        _hk_tasks[task_id].update({"status": "error", "result": None, "error": str(exc)})

    # Prune old completed tasks
    if len(_hk_tasks) > _HK_TASKS_MAX:
        done = [k for k, v in _hk_tasks.items() if v["status"] != "running"]
        for k in done[: len(_hk_tasks) - _HK_TASKS_MAX]:
            _hk_tasks.pop(k, None)


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/api/hk/stats", dependencies=[Depends(verify_token)])
def hk_stats():
    """Fast stats: {total, smart}. Served from persistent cache after first computation."""
    return hk_db.get_stats()


@router.get("/api/hk/stats/warning", dependencies=[Depends(verify_token)])
def hk_stats_warning():
    """Slow stat: {warning}. Runs a full-table GROUP BY (~4 min on 120M rows first call);
    persisted to hk_stats so subsequent calls (and restarts) return instantly."""
    return {"warning": hk_db.get_warning_count()}


# ── Import ─────────────────────────────────────────────────────────────────────

_IMPORT_MAX_BYTES = 50 * 1024 * 1024          # 50 MB (paste/small file)
_UPLOAD_MAX_BYTES = 2 * 1024 * 1024 * 1024     # 2 GB (streamed to disk; bigger → use server-file import)
_UPLOAD_CHUNK     = 8 * 1024 * 1024            # 8 MB read granularity

@router.post("/api/hk/import", dependencies=[Depends(verify_token)])
async def hk_import(
    text: str = Form(default=""),
    file: UploadFile = File(default=None),
):
    all_text = text or ""
    if file and file.filename:
        raw = await file.read(_IMPORT_MAX_BYTES + 1)
        if len(raw) > _IMPORT_MAX_BYTES:
            raise HTTPException(status_code=413, detail="File too large — max 50 MB")
        all_text += "\n" + raw.decode("utf-8", errors="replace")
    return hk_db.bulk_import(all_text)


@router.post("/api/hk/import-passwords", dependencies=[Depends(verify_token)])
async def hk_import_passwords(
    text: str = Form(default=""),
    file: UploadFile = File(default=None),
):
    """Add a plaintext password list — each line is hashed to its NT hash and stored as a pair."""
    all_text = text or ""
    if file and file.filename:
        raw = await file.read(_IMPORT_MAX_BYTES + 1)
        if len(raw) > _IMPORT_MAX_BYTES:
            raise HTTPException(status_code=413, detail="File too large — max 50 MB")
        all_text += "\n" + raw.decode("utf-8", errors="replace")
    return hk_db.import_passwords(all_text)


# ── Server-side file import (hk_inbox) ──────────────────────────────────────────

@router.get("/api/hk/import-file/check", dependencies=[Depends(verify_token)])
def hk_import_file_check():
    """Report whether the server-side inbox file is present. No path comes from the client."""
    return hk_db.inbox_file_status()


@router.post("/api/hk/import-file/run", dependencies=[Depends(verify_token)])
def hk_import_file_run(background_tasks: BackgroundTasks, ram: bool = False):
    """Stream-import the server-side inbox file as a background task (progress like KILL).
    ram=1 → RAM-killer mode (sizes the cache to most of the free RAM, with headroom)."""
    if not hk_db.inbox_file_status().get("exists"):
        raise HTTPException(status_code=404, detail="No inbox file (hk_inbox/large.potfile)")
    # Single-import guard: refuse if an import-file task is already running.
    if any(t.get("kind") == "import-file" and t["status"] == "running" for t in _hk_tasks.values()):
        raise HTTPException(status_code=409, detail="An import is already running")
    task_id = str(uuid.uuid4())
    _hk_tasks[task_id] = {"status": "running", "result": None, "error": None,
                           "progress": None, "cancelled": False, "kind": "import-file"}
    fn = functools.partial(hk_db.import_inbox_file, ram_killer=ram)
    background_tasks.add_task(_hk_task_run, task_id, fn)
    return {"task_id": task_id}


# ── Upload / merge DB ──────────────────────────────────────────────────────────

@router.post("/api/hk/upload-db", dependencies=[Depends(verify_token)])
async def hk_upload_db(file: UploadFile = File(...)):
    """Merge another hashkiller.db into current (non-destructive). Conflicts -> warning.
    Streamed to a temp file in chunks (no full read into RAM); merged via lazy cursor."""
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    try:
        written = 0
        while True:
            chunk = await file.read(_UPLOAD_CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > _UPLOAD_MAX_BYTES:
                tf.close()
                raise HTTPException(
                    status_code=413,
                    detail="File too large — use the server-file import (hk_inbox) for very large DBs",
                )
            tf.write(chunk)
        tf.close()
        try:
            return hk_db.merge_db_file(tf.name)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    finally:
        os.unlink(tf.name)


# ── Find (pre-delete lookup) ───────────────────────────────────────────────────

@router.get("/api/hk/find", dependencies=[Depends(verify_token)])
def hk_find(value: str = Query(...)):
    """Find pairs by hash or plaintext — used before delete for confirmation."""
    return hk_db.find_pairs(value)


# ── Delete ─────────────────────────────────────────────────────────────────────

@router.delete("/api/hk/pair", dependencies=[Depends(verify_token)])
def hk_delete_pair(value: str = Query(...)):
    deleted = hk_db.delete_by_value(value)
    return {"deleted": deleted}


@router.post("/api/hk/delete-file", dependencies=[Depends(verify_token)])
async def hk_delete_file(file: UploadFile = File(...)):
    """Bulk delete every hash/pair listed in an uploaded txt (e.g. an EXPORT WARNING file).
    Each line: hash:plain | bare hash | plaintext — same semantics as DELETE PAIR."""
    raw = await file.read(_IMPORT_MAX_BYTES + 1)
    if len(raw) > _IMPORT_MAX_BYTES:
        raise HTTPException(status_code=413, detail="File too large — max 50 MB")
    text = raw.decode("utf-8", errors="replace")
    return hk_db.delete_from_lines(text.splitlines())


# ── Export ─────────────────────────────────────────────────────────────────────

@router.get("/api/hk/export-smart", dependencies=[Depends(verify_token)])
def hk_export_smart():
    pairs   = hk_db.get_smart_pairs()
    content = "\n".join(f"{r['nt_hash']}:{r['plaintext']}" for r in pairs)
    if content:
        content += "\n"
    return Response(
        content=content, media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=smart_pairs.txt"},
    )


@router.get("/api/hk/export-warning", dependencies=[Depends(verify_token)])
def hk_export_warning():
    pairs   = hk_db.get_warning_pairs()
    content = "\n".join(f"{r['nt_hash']}:{r['plaintext']}" for r in pairs)
    if content:
        content += "\n"
    return Response(
        content=content, media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=warning_pairs.txt"},
    )


@router.get("/api/hk/dump-db", dependencies=[Depends(verify_token)])
def hk_dump_db():
    db_path = hk_db.HK_DB_PATH
    if not db_path.exists():
        raise HTTPException(status_code=404, detail="HashKiller DB not found")
    return FileResponse(
        path=str(db_path.resolve()),
        media_type="application/octet-stream",
        filename="hashkiller.db",
    )


@router.get("/api/hk/export-hashes/{workspace_id}", dependencies=[Depends(verify_token)])
def hk_export_hashes(workspace_id: int):
    """Export unique uncracked NT hashes for hashcat -m 1000."""
    with db_cursor() as cur:
        ws_row = cur.execute(
            "SELECT name FROM workspaces WHERE id=?", (workspace_id,)
        ).fetchone()
        if not ws_row:
            raise HTTPException(status_code=404, detail="Workspace not found")
        ws_name = ws_row["name"]
        pw_rows = cur.execute("""
            SELECT DISTINCT password FROM credentials
            WHERE workspace_id=? AND credtype='hash'
              AND brutforced IS NULL AND password != '<empty_password>'
        """, (workspace_id,)).fetchall()

    hashes: list = []
    seen:   set  = set()
    for r in pw_rows:
        nh = hk_db.extract_nt_hash(r["password"])
        if nh and nh not in seen:
            seen.add(nh)
            hashes.append(nh)

    content = "\n".join(hashes) + ("\n" if hashes else "")
    safe    = "".join(c for c in ws_name if c.isalnum() or c in "-_").lower() or "workspace"
    return Response(
        content=content, media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={safe}_hashes.txt"},
    )


# ── Background tasks ───────────────────────────────────────────────────────────

@router.post("/api/hk/sync-brutforced/{workspace_id}", dependencies=[Depends(verify_token)])
def hk_sync_brutforced(workspace_id: int):
    """Clear brutforced entries whose source plain was deleted from HK."""
    return hk_db.sync_brutforced(workspace_id)


@router.post("/api/hk/kill/{workspace_id}", dependencies=[Depends(verify_token)])
def hk_kill(workspace_id: int, background_tasks: BackgroundTasks):
    if any(t.get("kind") == "kill" and t["status"] == "running"
           and t.get("workspace_id") == workspace_id for t in _hk_tasks.values()):
        raise HTTPException(status_code=409, detail="A kill task for this workspace is already running")
    task_id = str(uuid.uuid4())
    _hk_tasks[task_id] = {"status": "running", "result": None, "error": None,
                           "progress": None, "cancelled": False,
                           "kind": "kill", "workspace_id": workspace_id}
    background_tasks.add_task(_hk_task_run, task_id, hk_db.kill_workspace, workspace_id)
    return {"task_id": task_id}


@router.post("/api/hk/smart-enrich/{workspace_id}", dependencies=[Depends(verify_token)])
def hk_smart_enrich(workspace_id: int, background_tasks: BackgroundTasks):
    if any(t.get("kind") == "smart-enrich" and t["status"] == "running"
           and t.get("workspace_id") == workspace_id for t in _hk_tasks.values()):
        raise HTTPException(status_code=409, detail="A smart-enrich task for this workspace is already running")
    with db_cursor() as cur:
        ws_row = cur.execute(
            "SELECT name FROM workspaces WHERE id=?", (workspace_id,)
        ).fetchone()
    ws_name = ws_row["name"] if ws_row else ""
    task_id = str(uuid.uuid4())
    _hk_tasks[task_id] = {"status": "running", "result": None, "error": None,
                           "progress": None, "cancelled": False,
                           "kind": "smart-enrich", "workspace_id": workspace_id}
    background_tasks.add_task(
        _hk_task_run, task_id,
        hk_db.smart_enrich_workspace, workspace_id, ws_name,
    )
    return {"task_id": task_id}


@router.post("/api/hk/kill-all", dependencies=[Depends(verify_token)])
def hk_kill_all(background_tasks: BackgroundTasks):
    if any(t.get("kind") == "kill-all" and t["status"] == "running" for t in _hk_tasks.values()):
        raise HTTPException(status_code=409, detail="A kill-all task is already running")
    task_id = str(uuid.uuid4())
    _hk_tasks[task_id] = {"status": "running", "result": None, "error": None,
                           "progress": None, "cancelled": False, "kind": "kill-all"}
    background_tasks.add_task(_hk_task_run, task_id, hk_db.kill_all_workspaces)
    return {"task_id": task_id}


@router.get("/api/hk/task/{task_id}", dependencies=[Depends(verify_token)])
def hk_task_status(task_id: str):
    task = _hk_tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found or server restarted")
    return task


@router.delete("/api/hk/task/{task_id}", dependencies=[Depends(verify_token)])
def hk_cancel_task(task_id: str):
    task = _hk_tasks.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["status"] == "running":
        task["cancelled"] = True
        return {"ok": True}
    return {"ok": False, "reason": "Task is not running"}
