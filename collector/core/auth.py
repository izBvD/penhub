"""
Authentication state and session management.

APP_PASSWORD_HASH is set by server.py main() before uvicorn starts.

Session model:
  - Browser login → unique token via secrets.token_hex(32)
  - Token stored server-side with expiry timestamp
  - Every authenticated request renews the expiry and refreshes the cookie
  - Logout removes token from store immediately
  - Legacy API key (X-Auth-Token: sha256(password)) accepted for operator scripts
"""

import secrets
import time

from fastapi import HTTPException, Request, Response

# Set once at startup by server.py
APP_PASSWORD_HASH: str = ""
APP_PASSWORD: str = ""  # plaintext — used by Toolbox /api/toolbox/server-info

SESSION_HOURS: int = 10
SESSION_SECONDS: int = SESSION_HOURS * 3600

# token → expiry Unix timestamp
_SESSIONS: dict[str, float] = {}


def create_session() -> str:
    """Generate a new unique session token and register it."""
    token = secrets.token_hex(32)
    _SESSIONS[token] = time.time() + SESSION_SECONDS
    _cleanup_expired()
    return token


def invalidate_session(token: str) -> None:
    """Remove a session immediately (logout)."""
    _SESSIONS.pop(token, None)


def _cleanup_expired() -> None:
    """Lazily evict expired sessions to keep the store bounded."""
    now = time.time()
    expired = [k for k, v in list(_SESSIONS.items()) if v < now]
    for k in expired:
        _SESSIONS.pop(k, None)


def verify_token(request: Request, response: Response) -> bool:
    """
    FastAPI dependency injected into all protected routes.

    Accepts:
      1. Session cookie set by /api/login (renews on each call)
      2. X-Auth-Token header equal to sha256(password) — legacy, for operator scripts
    """
    token = request.cookies.get("auth_token") or request.headers.get("X-Auth-Token", "")

    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Legacy API-key mode: operator scripts send sha256(password) directly.
    # No renewal needed — it's stateless.
    if token == APP_PASSWORD_HASH:
        return True

    # Session token
    expiry = _SESSIONS.get(token)
    if expiry is None or time.time() > expiry:
        _SESSIONS.pop(token, None)
        raise HTTPException(status_code=401, detail="Session expired")

    # Renew: extend server-side expiry and refresh the client cookie
    _SESSIONS[token] = time.time() + SESSION_SECONDS
    response.set_cookie(
        "auth_token", token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_SECONDS,
    )
    return True
