"""
Shell Module API — lazy UI fragment delivery.

GET /api/shell/module/{module_id}/ui
  Returns the HTML fragment for the requested module.
  Used by Shell._loadFragment(id) in static/shell-core.js on first module activation.
  Auth-protected: same cookie as all other API endpoints.

Чтобы модуль имел UI: реализуй get_ui_fragment() → вернуть HTML-строку.
Пример: modules/hashkiller/ui.py
Чеклист для нового модуля: penhub/app.py
"""

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse

from collector.core.auth import verify_token
from penhub.shell.registry import shell_registry

router = APIRouter()


@router.get(
    "/api/shell/module/{module_id}/ui",
    response_class=HTMLResponse,
    dependencies=[Depends(verify_token)],
    include_in_schema=False,
)
async def get_module_ui(module_id: str) -> HTMLResponse:
    """Return the HTML fragment for a lazy-loaded module."""
    module = shell_registry.get_module(module_id)
    if module is None or not module.enabled:
        raise HTTPException(status_code=404, detail="Module not found")
    fragment = module.get_ui_fragment()
    if not fragment:
        raise HTTPException(status_code=404, detail="Module has no UI fragment")
    return HTMLResponse(content=fragment)
