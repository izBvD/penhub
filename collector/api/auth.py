"""
Authentication routes: /api/login, /api/logout
"""

import hashlib

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

import collector.core.auth as _auth

router = APIRouter()


@router.post("/api/login")
async def login(request: Request):
    body = await request.json()
    h = hashlib.sha256(body.get("password", "").encode()).hexdigest()
    if h != _auth.APP_PASSWORD_HASH:
        raise HTTPException(status_code=403, detail="Wrong password")
    token = _auth.create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        "auth_token", token,
        httponly=True,
        samesite="lax",
        max_age=_auth.SESSION_SECONDS,
    )
    return resp


@router.post("/api/logout")
async def logout(request: Request):
    token = request.cookies.get("auth_token", "")
    _auth.invalidate_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("auth_token")
    return resp
