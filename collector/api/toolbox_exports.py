"""NXCExtractor list export routes: /api/toolbox/logins, /passwords, /hashes, /ips, /not-pwnd-ips, /spray-archive"""

import io
import re
import zipfile

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from collector.core.auth import verify_token
from collector.core.constants import _GUEST_NAMES_SQL
from collector.core.workspace_utils import ws_safe
from collector.db import db_cursor
from collector.services.data_service import apply_brutforced

router = APIRouter()


_GUEST_FILTER = (
    "username != '' AND hidden = 0"
    f" AND casefold(username) NOT IN {_GUEST_NAMES_SQL}"
)

_HEX32    = re.compile(r'^[0-9a-fA-F]{32}$')
_NT_EMPTY = "31d6cfe0d16ae931b73c59d7e0c089c0"


def _extract_nt(pw: str) -> "str | None":
    """Extract NT hash string. Returns None for empty hash or invalid format."""
    if not pw or pw == "<empty_password>":
        return None
    pw = pw.strip().lower()
    parts = pw.split(":")
    if len(parts) == 2 and _HEX32.match(parts[0]) and _HEX32.match(parts[1]):
        nt = parts[1]
    elif _HEX32.match(pw):
        nt = pw
    else:
        return None
    return None if nt == _NT_EMPTY else nt


def _not_pwnd_ip_content(cur, workspace_id: int) -> str:
    """not_pwn3d_ip.txt content: hosts without admin auth + custom IPs not in admin hosts.

    Shared by /api/toolbox/not-pwnd-ips and the spray-archive ZIP — the standalone
    file and the one inside the archive must always be identical.
    """
    host_rows = cur.execute("""
        SELECT DISTINCT ip FROM hosts
        WHERE workspace_id=? AND hidden=0
          AND id NOT IN (
            SELECT DISTINCT host_id FROM auth_relations
            WHERE workspace_id=? AND relation_type='admin'
          )
    """, (workspace_id, workspace_id)).fetchall()
    # Custom IPs: no auth_relations → always "not pwnd" unless the same IP appears in hosts with admin
    admin_ips = {r[0] for r in cur.execute("""
        SELECT DISTINCT h.ip FROM auth_relations ar
        JOIN hosts h ON h.id = ar.host_id
        WHERE ar.workspace_id=? AND ar.relation_type='admin'
    """, (workspace_id,)).fetchall()}
    custom_ip_rows = cur.execute("""
        SELECT DISTINCT ip FROM custom_credentials
        WHERE workspace_id=? AND ip IS NOT NULL AND ip != ''
    """, (workspace_id,)).fetchall()

    seen: set = set()
    ips: list = []
    for r in host_rows:
        ip = r[0] or ""
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)
    for r in custom_ip_rows:
        ip = r[0] or ""
        if ip and ip not in seen and ip not in admin_ips:
            seen.add(ip)
            ips.append(ip)

    ips.sort()
    content = "\n".join(ips)
    if content:
        content += "\n"
    return content


@router.get("/api/toolbox/logins", dependencies=[Depends(verify_token)])
def toolbox_logins(workspace_id: int = Query(...)):
    """All unique logins (credentials + DPAPI SMB + custom_credentials), lowercased, GUEST excluded."""
    with db_cursor() as cur:
        cred_rows = cur.execute(f"""
            SELECT username FROM credentials
            WHERE workspace_id = ? AND {_GUEST_FILTER}
        """, (workspace_id,)).fetchall()
        dpapi_rows = cur.execute("""
            SELECT username FROM dpapi_secrets
            WHERE workspace_id = ? AND dpapi_type = 'SMB'
              AND hidden = 0 AND username IS NOT NULL AND username != ''
        """, (workspace_id,)).fetchall()
        custom_rows = cur.execute("""
            SELECT login FROM custom_credentials
            WHERE workspace_id = ? AND login IS NOT NULL AND login != ''
        """, (workspace_id,)).fetchall()

    seen: set = set()
    logins: list = []
    for r in [*cred_rows, *dpapi_rows, *custom_rows]:
        low = (r[0] or "").casefold()
        if low and low not in seen:
            seen.add(low)
            logins.append(low)

    logins.sort()
    content = "\n".join(logins)
    if content:
        content += "\n"
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_all_uniq_logins.txt"},
    )


@router.get("/api/toolbox/passwords", dependencies=[Depends(verify_token)])
def toolbox_passwords(workspace_id: int = Query(...)):
    """Unique plaintext passwords (credentials + DPAPI SMB + custom_credentials) after HK-brute, GUEST excluded."""
    with db_cursor() as cur:
        cred_rows = [dict(r) for r in cur.execute(f"""
            SELECT DISTINCT username, password, credtype, brutforced FROM credentials
            WHERE workspace_id = ? AND {_GUEST_FILTER}
        """, (workspace_id,)).fetchall()]
        dpapi_rows = cur.execute("""
            SELECT password FROM dpapi_secrets
            WHERE workspace_id = ? AND dpapi_type = 'SMB'
              AND hidden = 0 AND password IS NOT NULL AND password != ''
        """, (workspace_id,)).fetchall()
        custom_rows = [dict(r) for r in cur.execute("""
            SELECT DISTINCT password, credtype, brutforced FROM custom_credentials
            WHERE workspace_id = ? AND password IS NOT NULL AND password != ''
        """, (workspace_id,)).fetchall()]

    cred_rows   = apply_brutforced(cred_rows)
    custom_rows = apply_brutforced(custom_rows)  # cracked custom hashes become plaintext
    seen: set = set()
    passwords: list = []
    for r in cred_rows:
        if r.get("credtype") == "plaintext":
            pw = r.get("password") or ""
            if pw == "<empty_password>":
                pw = ""
            if pw not in seen:
                seen.add(pw)
                passwords.append(pw)

    for r in dpapi_rows:
        pw = r[0] or ""
        if pw not in seen:
            seen.add(pw)
            passwords.append(pw)

    for r in custom_rows:
        if r.get("credtype") == "plaintext":
            pw = r.get("password") or ""
            if pw == "<empty_password>":
                pw = ""
            if pw not in seen:
                seen.add(pw)
                passwords.append(pw)

    passwords.sort(key=str.casefold)
    content = "\n".join(passwords)
    if content:
        content += "\n"
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_all_uniq_pass.txt"},
    )


@router.get("/api/toolbox/hashes", dependencies=[Depends(verify_token)])
def toolbox_hashes(workspace_id: int = Query(...)):
    """Unique uncracked NT hashes (credentials + custom_credentials credtype=hash), GUEST excluded."""
    with db_cursor() as cur:
        rows = cur.execute(f"""
            SELECT DISTINCT password FROM credentials
            WHERE workspace_id = ? AND credtype = 'hash' AND brutforced IS NULL
              AND {_GUEST_FILTER}
        """, (workspace_id,)).fetchall()
        custom_hash_rows = cur.execute("""
            SELECT DISTINCT password FROM custom_credentials
            WHERE workspace_id = ? AND credtype = 'hash'
              AND password IS NOT NULL AND password != ''
        """, (workspace_id,)).fetchall()

    hashes: list = []
    seen: set = set()
    for r in [*rows, *custom_hash_rows]:
        nt = _extract_nt(r[0] or "")
        if nt and nt not in seen:
            seen.add(nt)
            hashes.append(nt)

    hashes.sort()
    content = "\n".join(hashes)
    if content:
        content += "\n"
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_all_uniq_hashes.txt"},
    )


@router.get("/api/toolbox/ips", dependencies=[Depends(verify_token)])
def toolbox_ips(workspace_id: int = Query(...)):
    """All unique IP addresses: non-hidden hosts + IPs from custom_credentials."""
    with db_cursor() as cur:
        host_rows = cur.execute("""
            SELECT DISTINCT ip FROM hosts
            WHERE workspace_id = ? AND hidden = 0
        """, (workspace_id,)).fetchall()
        custom_ip_rows = cur.execute("""
            SELECT DISTINCT ip FROM custom_credentials
            WHERE workspace_id = ? AND ip IS NOT NULL AND ip != ''
        """, (workspace_id,)).fetchall()

    seen: set = set()
    ips: list = []
    for r in [*host_rows, *custom_ip_rows]:
        ip = r[0] or ""
        if ip and ip not in seen:
            seen.add(ip)
            ips.append(ip)

    ips.sort()
    content = "\n".join(ips)
    if content:
        content += "\n"
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_all_uniq_ip.txt"},
    )


@router.get("/api/toolbox/not-pwnd-ips", dependencies=[Depends(verify_token)])
def toolbox_not_pwnd_ips(workspace_id: int = Query(...)):
    """IPs with no admin auth_relation + custom_credentials IPs not in admin hosts."""
    with db_cursor() as cur:
        content = _not_pwnd_ip_content(cur, workspace_id)
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_not_pwn3d_ip.txt"},
    )


@router.get("/api/toolbox/spray-archive", dependencies=[Depends(verify_token)])
def toolbox_spray_archive(workspace_id: int = Query(...)):
    """
    ZIP with 5 files for nxc --no-bruteforce spray against non-owned hosts.
    not_pwn3d_ip.txt — hosts with no admin access.
    4 line-paired credential files (plaintext + hash pairs).
    HK-brute applied: cracked hashes appear in plaintext pair; uncracked remain in hash pair.
    Line counts guaranteed equal within each pair.
    """
    with db_cursor() as cur:
        rows = [dict(r) for r in cur.execute(f"""
            SELECT DISTINCT username, password, credtype, brutforced FROM credentials
            WHERE workspace_id = ? AND {_GUEST_FILTER}
            ORDER BY username COLLATE NOCASE, password
        """, (workspace_id,)).fetchall()]
        dpapi_rows = cur.execute("""
            SELECT username, password FROM dpapi_secrets
            WHERE workspace_id = ? AND dpapi_type = 'SMB'
              AND hidden = 0 AND username IS NOT NULL AND username != ''
              AND password IS NOT NULL AND password != ''
        """, (workspace_id,)).fetchall()
        not_pwnd_content = _not_pwnd_ip_content(cur, workspace_id)
        custom_rows_db = [dict(r) for r in cur.execute("""
            SELECT DISTINCT login AS username, password, credtype, brutforced FROM custom_credentials
            WHERE workspace_id = ? AND login IS NOT NULL AND login != ''
              AND password IS NOT NULL AND password != ''
        """, (workspace_id,)).fetchall()]

    rows           = apply_brutforced(rows)
    custom_rows_db = apply_brutforced(custom_rows_db)  # cracked custom hashes spray as plaintext

    plain_pairs: list = []
    hash_pairs: list  = []
    seen_plain: set   = set()
    seen_hash: set    = set()

    for r in rows:
        uname    = r.get("username") or ""
        pw       = r.get("password") or ""
        credtype = r.get("credtype") or "plaintext"

        if credtype == "plaintext":
            display_pw = "" if pw == "<empty_password>" else pw
            key = (uname.casefold(), display_pw)
            if key not in seen_plain:
                seen_plain.add(key)
                plain_pairs.append((uname, display_pw))
        elif credtype == "hash":
            nt = _extract_nt(pw)
            if nt:
                key = (uname.casefold(), nt)
                if key not in seen_hash:
                    seen_hash.add(key)
                    hash_pairs.append((uname, nt))

    for r in dpapi_rows:
        uname = (r[0] or "").casefold()
        pw    = r[1] or ""
        key   = (uname, pw)
        if key not in seen_plain:
            seen_plain.add(key)
            plain_pairs.append((uname, pw))

    for r in custom_rows_db:
        uname    = (r.get("username") or "").casefold()
        pw       = r.get("password") or ""
        credtype = r.get("credtype") or "plaintext"
        if credtype == "plaintext":
            key = (uname, pw)
            if key not in seen_plain:
                seen_plain.add(key)
                plain_pairs.append((uname, pw))
        elif credtype == "hash":
            nt = _extract_nt(pw)
            if nt:
                key = (uname, nt)
                if key not in seen_hash:
                    seen_hash.add(key)
                    hash_pairs.append((uname, nt))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("not_pwn3d_ip.txt", not_pwnd_content)
        if plain_pairs:
            zf.writestr("plaintext_logins.txt", "\n".join(u for u, _ in plain_pairs) + "\n")
            zf.writestr("plaintext_passes.txt",  "\n".join(p for _, p in plain_pairs) + "\n")
        else:
            zf.writestr("plaintext_logins.txt", "")
            zf.writestr("plaintext_passes.txt",  "")
        if hash_pairs:
            zf.writestr("hashes_logins.txt", "\n".join(u for u, _ in hash_pairs) + "\n")
            zf.writestr("hashes_passes.txt",  "\n".join(h for _, h in hash_pairs) + "\n")
        else:
            zf.writestr("hashes_logins.txt", "")
            zf.writestr("hashes_passes.txt",  "")

    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_spray_lists.zip"
        },
    )
