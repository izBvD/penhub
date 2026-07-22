"""Host/network routes: /api/hosts, /api/shares, /api/conf_checks, /api/directory_listings, /api/hosts/*"""

from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException

from collector.core.auth import verify_token
from collector.db import db_cursor

router = APIRouter()


@router.get("/api/hosts", dependencies=[Depends(verify_token)])
def get_hosts(
    workspace_id: int,
    proto: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 2000,
    hidden: Optional[bool] = None,
):
    conditions = ["workspace_id = ?"]
    params: list = [workspace_id]
    conditions.append("hidden = 1" if hidden is True else "hidden = 0")

    p = (proto or "").upper()
    if p == "LDAP":
        # LDAP scanner populates signing_required; only those hosts were scanned via LDAP
        conditions.append("signing_required IS NOT NULL")
    elif p == "RDP":
        conditions.append("port = 3389")
    elif p == "SSH":
        # SSH scanner sets port; exclude RDP (3389) and FTP (21/2121) ports
        conditions.append(
            "port IS NOT NULL AND port NOT IN (3389,21,2121,5900,5901)"
            " AND signing IS NULL AND signing_required IS NULL"
        )
    elif p == "SMB":
        conditions.append("signing IS NOT NULL")

    if search:
        conditions.append(
            "(icontains(?,ip) OR icontains(?,hostname) OR icontains(?,domain)"
            " OR icontains(?,os) OR icontains(?,banner))"
        )
        params += [search] * 5

    where = " AND ".join(conditions)
    with db_cursor() as cur:
        total = cur.execute(
            f"SELECT COUNT(*) FROM hosts WHERE {where}", params
        ).fetchone()[0]
        offset = (page - 1) * limit
        rows = cur.execute(f"""
            SELECT id, ip, hostname, domain, os,
                   dc, smbv1, signing, spooler, zerologon, petitpotam,
                   nla, signing_required, channel_binding, port, banner,
                   operator, updated_at, honeypot
            FROM hosts WHERE {where}
            ORDER BY ip
            LIMIT ? OFFSET ?
        """, params + [limit, offset]).fetchall()

        # Workspace-wide duplicate hostname detection (visible hosts only).
        # Computed regardless of current search/proto filter so flag is stable when user searches.
        dup_hostnames: set = set()
        if hidden is not True:
            dup_rows = cur.execute(
                "SELECT LOWER(hostname) AS hn FROM hosts"
                " WHERE workspace_id=? AND hidden=0"
                " AND hostname IS NOT NULL AND hostname != ''"
                " GROUP BY LOWER(hostname) HAVING COUNT(*) > 1",
                (workspace_id,),
            ).fetchall()
            dup_hostnames = {r["hn"] for r in dup_rows}

    result = []
    for r in rows:
        d = dict(r)
        hn = (d.get("hostname") or "").strip().lower()
        d["_dup_hostname"] = bool(hn and hn in dup_hostnames)
        result.append(d)
    return {"rows": result, "total": total}


@router.get("/api/shares", dependencies=[Depends(verify_token)])
def get_shares(
    workspace_id: int,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 100,
):
    conditions = ["s.workspace_id = ?"]
    params: list = [workspace_id]
    if search:
        conditions.append(
            "(icontains(?,h.ip) OR icontains(?,c.username) OR icontains(?,s.name)"
            " OR icontains(?,s.remark))"
        )
        params += [search] * 4
    where = " AND ".join(conditions)
    base_q = f"""
        FROM shares s
        LEFT JOIN hosts h ON s.host_id = h.id
        LEFT JOIN credentials c ON s.credential_id = c.id
        WHERE {where}
    """
    with db_cursor() as cur:
        total = cur.execute(f"SELECT COUNT(*) {base_q}", params).fetchone()[0]
        offset = (page - 1) * limit
        rows = cur.execute(f"""
            SELECT h.ip, c.domain, c.username, c.password, c.brutforced, s.name, s.remark, s.read, s.write, s.operator
            {base_q}
            ORDER BY s.id DESC
            LIMIT ? OFFSET ?
        """, params + [limit, offset]).fetchall()
    return {"rows": [dict(r) for r in rows], "total": total}


@router.get("/api/conf_checks", dependencies=[Depends(verify_token)])
def get_conf_checks(
    workspace_id: int,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 100,
):
    conditions = ["cc.workspace_id = ?"]
    params: list = [workspace_id]
    if search:
        conditions.append(
            "(icontains(?,h.ip) OR icontains(?,h.hostname) OR icontains(?,cc.check_name)"
            " OR icontains(?,cc.reasons))"
        )
        params += [search] * 4
    where = " AND ".join(conditions)
    base_q = f"""
        FROM conf_checks_results cc
        LEFT JOIN hosts h ON cc.host_id = h.id
        WHERE {where}
    """
    with db_cursor() as cur:
        total = cur.execute(f"SELECT COUNT(*) {base_q}", params).fetchone()[0]
        offset = (page - 1) * limit
        rows = cur.execute(f"""
            SELECT h.ip, h.hostname, cc.check_name, cc.secure, cc.reasons, cc.operator
            {base_q}
            ORDER BY h.ip, cc.check_name
            LIMIT ? OFFSET ?
        """, params + [limit, offset]).fetchall()
    return {"rows": [dict(r) for r in rows], "total": total}


@router.get("/api/directory_listings", dependencies=[Depends(verify_token)])
def get_directory_listings(
    workspace_id: int,
    proto: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 100,
):
    conditions = ["workspace_id = ?"]
    params: list = [workspace_id]
    if proto:
        conditions.append("proto = ?")
        params.append(proto.upper())
    if search:
        conditions.append(
            "(icontains(?,host_ip) OR icontains(?,username) OR icontains(?,data))"
        )
        params += [search] * 3
    where = " AND ".join(conditions)
    with db_cursor() as cur:
        total = cur.execute(
            f"SELECT COUNT(*) FROM directory_listings WHERE {where}", params
        ).fetchone()[0]
        offset = (page - 1) * limit
        rows = cur.execute(f"""
            SELECT proto, host_ip, username, data, operator
            FROM directory_listings WHERE {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, params + [limit, offset]).fetchall()
    return {"rows": [dict(r) for r in rows], "total": total}


@router.post("/api/hosts/set_hidden", dependencies=[Depends(verify_token)])
def set_host_hidden(
    workspace_id: int = Body(...),
    host_id:      int = Body(...),
    hidden:       int = Body(...),
):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE hosts SET hidden=? WHERE id=? AND workspace_id=?",
            (hidden, host_id, workspace_id),
        )
    return {"ok": True}


@router.post("/api/hosts/strike", dependencies=[Depends(verify_token)])
def strike_host_ip(workspace_id: int = Body(...), host_ip: str = Body(...)):
    """Mark a host as honeypot and hide it + all credentials that authenticated on it."""
    with db_cursor() as cur:
        host = cur.execute(
            "SELECT id FROM hosts WHERE workspace_id=? AND ip=?", (workspace_id, host_ip)
        ).fetchone()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        host_id = host["id"]
        cur.execute(
            "UPDATE hosts SET honeypot=1, hidden=1 WHERE id=? AND workspace_id=?",
            (host_id, workspace_id),
        )
        cur.execute("""
            UPDATE credentials SET hidden=1, hidden_by_strike=1
            WHERE workspace_id=? AND hidden=0
              AND EXISTS (
                SELECT 1 FROM auth_relations ar
                WHERE ar.credential_id = credentials.id
                  AND ar.workspace_id  = credentials.workspace_id
                  AND ar.host_id       = ?
              )
              AND NOT EXISTS (
                SELECT 1 FROM auth_relations ar2
                WHERE ar2.credential_id = credentials.id
                  AND ar2.workspace_id  = credentials.workspace_id
                  AND ar2.host_id      != ?
              )
        """, (workspace_id, host_id, host_id))
        creds_hidden = cur.rowcount
    return {"ok": True, "host_id": host_id, "creds_hidden": creds_hidden}


@router.post("/api/hosts/restore_strike", dependencies=[Depends(verify_token)])
def restore_strike_host_ip(workspace_id: int = Body(...), host_ip: str = Body(...)):
    """Restore a struck host and all credentials that authenticated on it."""
    with db_cursor() as cur:
        host = cur.execute(
            "SELECT id FROM hosts WHERE workspace_id=? AND ip=?", (workspace_id, host_ip)
        ).fetchone()
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        host_id = host["id"]
        cur.execute(
            "UPDATE hosts SET honeypot=0, hidden=0 WHERE id=? AND workspace_id=?",
            (host_id, workspace_id),
        )
        # GUARD: restore only credentials hidden BY this strike (hidden_by_strike=1),
        # not manually-hidden credentials that happen to auth on this host.
        # hidden_by_strike is set to 1 exclusively by strike_host_ip and sync.py auto-hide;
        # manual set_hidden always resets it to 0.
        # The old NOT EXISTS filter was removed: it prevented restoring credentials that
        # gained a new auth_relation on another host between strike and restore (Bug B fix).
        cur.execute("""
            UPDATE credentials SET hidden=0, hidden_by_strike=0
            WHERE workspace_id=? AND hidden_by_strike=1
              AND EXISTS (
                SELECT 1 FROM auth_relations ar
                WHERE ar.credential_id = credentials.id
                  AND ar.workspace_id  = credentials.workspace_id
                  AND ar.host_id       = ?
              )
        """, (workspace_id, host_id))
        creds_restored = cur.rowcount
    return {"ok": True, "host_id": host_id, "creds_restored": creds_restored}
