"""
Static page routes: /, /hashkiller, /favicon.ico

/hashkiller redirects to the unified Shell SPA with the HashKiller module activated.
The Shell reads the ?module=hashkiller URL parameter on load and activates accordingly.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

import collector.frontend

router = APIRouter()

_FAVICON_PATH = Path(__file__).parent.parent.parent / "favicon" / "favicon.ico"


@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(_FAVICON_PATH, media_type="image/x-icon")


@router.get("/", response_class=HTMLResponse)
async def root():
    # Access module attribute at request time so HTML_PAGE is always current.
    return collector.frontend.HTML_PAGE


@router.get("/hashkiller", include_in_schema=False)
async def hashkiller_page():
    """
    Redirect to the unified Shell SPA with HashKiller module pre-activated.
    Old URL /hashkiller?ws=ID is preserved: /?module=hashkiller&ws=ID
    The Shell JS reads ?module= on DOMContentLoaded and calls Shell.activate().
    """
    return RedirectResponse(url="/?module=hashkiller", status_code=302)
