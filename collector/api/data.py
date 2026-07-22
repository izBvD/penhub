"""
Data query routes: /api/stats, /api/hosts, /api/results,
                   /api/credentials, /api/dpapi, /api/vulns

These functions are also called directly from export.py,
so they accept all parameters as keyword arguments.

GUARD: all params use plain Python defaults (= None, = True, = 100).
No Query() wrappers anywhere in this module. FastAPI routes all params identically
for HTTP; direct Python callers (export.py) receive proper None/bool/int —
not a truthy FieldInfo object that silently corrupts SQL params (sqlite3.ProgrammingError).
Required params (workspace_id: int) have no default — FastAPI treats them
as required query params automatically; no Query() needed.
"""

from typing import Optional

from fastapi import APIRouter, Depends

from collector.core.auth import verify_token
from collector.core.constants import _GUEST_NAMES_SQL, VULN_COLUMNS
from collector.db import db_cursor
from collector.services.data_service import dedup_results
from collector.services.stats_service import count_workspace_creds

router = APIRouter()


@router.get("/api/stats", dependencies=[Depends(verify_token)])
def get_stats(workspace_id: int):
    with db_cursor() as cur:
        hosts = cur.execute(
            "SELECT COUNT(DISTINCT ip) FROM hosts WHERE workspace_id=? AND hidden = 0", (workspace_id,)
        ).fetchone()[0]
        creds = count_workspace_creds(cur, workspace_id)
        admin = cur.execute(
            "SELECT COUNT(DISTINCT ar.host_id) FROM auth_relations ar"
            " JOIN hosts h ON h.id = ar.host_id AND h.hidden = 0"
            " JOIN credentials c ON c.id = ar.credential_id AND c.hidden = 0"
            " WHERE ar.workspace_id=? AND ar.relation_type='admin'",
            (workspace_id,)
        ).fetchone()[0]
        dpapi = cur.execute(
            "SELECT COUNT(*) FROM dpapi_secrets WHERE workspace_id=? AND hidden = 0", (workspace_id,)
        ).fetchone()[0]
        domains = cur.execute(
            "SELECT COUNT(DISTINCT domain) FROM credentials"
            " WHERE workspace_id=? AND domain!='' AND hidden = 0",
            (workspace_id,)
        ).fetchone()[0]
    return {
        "hosts": hosts, "creds": creds, "admin": admin,
        "dpapi": dpapi, "domains": domains,
    }


@router.get("/api/results", dependencies=[Depends(verify_token)])
def get_results(
    workspace_id: int,
    proto: Optional[str] = None,
    relation: Optional[str] = None,
    relations: Optional[str] = None,
    credtype: Optional[str] = None,
    admin_cred: Optional[bool] = None,
    local_admin_cred: Optional[bool] = None,
    search: Optional[str] = None,
    hide_guest: bool = True,
    page: int = 1,
    limit: int = 100,
    dedup: bool = False,
):
    conditions = ["ar.workspace_id = ?", "c.hidden = 0", "h.hidden = 0"]
    params: list = [workspace_id]

    if proto and proto.upper() != "ALL":
        conditions.append("ar.proto = ?")
        params.append(proto.upper())
    if relations:
        rel_list = [r.strip() for r in relations.split(",") if r.strip() in ("admin", "loggedin")]
        if rel_list:
            ph = ",".join("?" * len(rel_list))
            conditions.append(f"ar.relation_type IN ({ph})")
            params.extend(rel_list)
    elif relation in ("admin", "loggedin"):
        conditions.append("ar.relation_type = ?")
        params.append(relation)
    if credtype:
        conditions.append("c.credtype = ?")
        params.append(credtype)
    if admin_cred is True:
        conditions.append("c.admin_cred = 1")
    if local_admin_cred is True:
        conditions.append("c.local_admin_cred = 1")
    if hide_guest:
        conditions.append(
            f"c.username != '' AND casefold(c.username) NOT IN {_GUEST_NAMES_SQL}"
        )
    if search:
        conditions.append(
            "(icontains(?,h.ip) OR icontains(?,h.hostname) OR icontains(?,c.username)"
            " OR icontains(?,c.password) OR icontains(?,c.brutforced)"
            " OR icontains(?,c.domain) OR icontains(?,c.credtype))"
        )
        params += [search] * 7

    where = " AND ".join(conditions)
    base_q = f"""
        FROM auth_relations ar
        JOIN hosts h ON ar.host_id = h.id
        JOIN credentials c ON ar.credential_id = c.id
        WHERE {where}
    """

    select_q = f"""
        SELECT
            ar.proto, ar.relation_type,
            h.ip, h.hostname, h.domain AS host_domain, h.os,
            h.smbv1, h.signing, h.spooler, h.zerologon, h.petitpotam,
            h.instances, h.port AS host_port, h.banner AS host_banner,
            c.domain AS cred_domain, c.username, c.password, c.credtype,
            c.brutforced, c.admin_cred, c.local_admin_cred, c.pkey, ar.shell, ar.operator
        {base_q}
        ORDER BY ar.id DESC
    """

    with db_cursor() as cur:
        if dedup:
            # GUARD: dedup=True loads ALL matching rows into memory before paginating.
            # For large workspaces this can be slow — used by the results views
            # ([+]/PWN3D! for every proto and the ALL tab) with the UNIQ filter on.
            # Mirrors client-side deduplicateRows() logic exactly (host-aware key).
            all_rows = [dict(r) for r in cur.execute(select_q, params).fetchall()]
            deduped = dedup_results(all_rows)
            total = len(deduped)
            if limit > 0:
                offset = (page - 1) * limit
                rows = deduped[offset:offset + limit]
            else:
                rows = deduped
        else:
            total = cur.execute(f"SELECT COUNT(*) {base_q}", params).fetchone()[0]
            offset = (page - 1) * limit
            rows = [
                dict(r) for r in cur.execute(
                    select_q + " LIMIT ? OFFSET ?", params + [limit, offset]
                ).fetchall()
            ]

    return {"rows": rows, "total": total}


@router.get("/api/credentials", dependencies=[Depends(verify_token)])
def get_credentials(
    workspace_id: int,
    proto: Optional[str] = None,
    credtype: Optional[str] = None,
    search: Optional[str] = None,
    hide_guest: bool = True,
    admin_cred: Optional[bool] = None,
    local_admin_cred: Optional[bool] = None,
    pillaged: Optional[bool] = None,
    samlsa: Optional[bool] = None,
    hidden: Optional[bool] = None,  # True = only hidden; default = only visible
    page: int = 1,
    limit: int = 100,
):
    conditions = ["c.workspace_id = ?"]
    params: list = [workspace_id]
    # hidden filter: by default show only visible (hidden=0); pass hidden=true for HIDDEN view
    if hidden is True:
        conditions.append("c.hidden = 1")
    else:
        conditions.append("c.hidden = 0")

    if proto and proto.upper() != "ALL":
        conditions.append("c.proto = ?")
        params.append(proto.upper())
    if credtype:
        conditions.append("c.credtype = ?")
        params.append(credtype)
    if admin_cred is True:
        conditions.append("c.admin_cred = 1")
    if local_admin_cred is True:
        conditions.append("c.local_admin_cred = 1")
    if pillaged is True:
        conditions.append("c.pillaged_from_ip IS NOT NULL")
    if samlsa is True:
        # Pillaged from a specific host OR has no auth_relation at all
        # (covers SAM/LSA dumps AND enumerated/dcsync accounts not tied to any host auth)
        conditions.append("""(
            c.pillaged_from_ip IS NOT NULL
            OR NOT EXISTS (
                SELECT 1 FROM auth_relations ar
                WHERE ar.credential_id = c.id AND ar.workspace_id = c.workspace_id
            )
        )""")
    if hide_guest:
        conditions.append(
            f"c.username != '' AND casefold(c.username) NOT IN {_GUEST_NAMES_SQL}"
        )
    if search:
        conditions.append(
            "(icontains(?,c.domain) OR icontains(?,c.username) OR icontains(?,c.password)"
            " OR icontains(?,c.brutforced) OR icontains(?,c.credtype)"
            " OR icontains(?,h.ip) OR icontains(?,h.hostname))"
        )
        params += [search] * 7

    where = " AND ".join(conditions)
    base_q = f"""
        FROM credentials c
        LEFT JOIN hosts h ON h.workspace_id = c.workspace_id AND h.ip = c.pillaged_from_ip
        WHERE {where}
    """

    with db_cursor() as cur:
        total = cur.execute(f"SELECT COUNT(*) {base_q}", params).fetchone()[0]
        offset = (page - 1) * limit
        rows = cur.execute(f"""
            SELECT
                c.proto, c.domain, c.username, c.password, c.credtype,
                c.brutforced, c.admin_cred, c.local_admin_cred, c.pillaged_from_ip, c.pkey,
                h.hostname AS pillaged_from_hostname,
                c.operator
            {base_q}
            ORDER BY c.id DESC
            LIMIT ? OFFSET ?
        """, params + [limit, offset]).fetchall()

    return {"rows": [dict(r) for r in rows], "total": total}


@router.get("/api/dpapi", dependencies=[Depends(verify_token)])
def get_dpapi(
    workspace_id: int,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 100,
    hidden: Optional[bool] = None,
):
    conditions = ["workspace_id = ?"]
    params: list = [workspace_id]
    conditions.append("hidden = 1" if hidden is True else "hidden = 0")

    if search:
        conditions.append(
            "(icontains(?,host_ip) OR icontains(?,windows_user) OR icontains(?,username)"
            " OR icontains(?,password) OR icontains(?,url))"
        )
        params += [search] * 5

    where = " AND ".join(conditions)
    with db_cursor() as cur:
        total = cur.execute(
            f"SELECT COUNT(*) FROM dpapi_secrets WHERE {where}", params
        ).fetchone()[0]
        offset = (page - 1) * limit
        rows = cur.execute(f"""
            SELECT id, host_ip, dpapi_type, windows_user, username, password, url, operator
            FROM dpapi_secrets WHERE {where}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, params + [limit, offset]).fetchall()

    return {"rows": [dict(r) for r in rows], "total": total}


def _host_col_status(raw, vuln_value):
    """Host-column → tri-state: None(unknown) / 1(vuln) / 0(clean)."""
    if raw is None:
        return None
    return 1 if raw == vuln_value else 0


def _merge_status(host_status, finding_status):
    """merge sources: vulnerable if either says so; clean if either says clean; else unknown."""
    if host_status == 1 or finding_status == 1:
        return 1
    if host_status == 0 or finding_status == 0:
        return 0
    return None


@router.get("/api/vulns", dependencies=[Depends(verify_token)])
def get_vulns(
    workspace_id: int,
    vuln: Optional[str] = None,
    vulns: Optional[str] = None,
    search: Optional[str] = None,
    page: int = 1,
    limit: int = 0,
    show_all: bool = False,
):
    """
    Aggregate-per-host pivot over VULN_COLUMNS. Each row carries a tri-state status
    per vuln slug: 1=vulnerable, 0=checked-clean, None=could-not-check / no data.
    Sources: host-columns (hosts table), findings (vuln_findings), merge (either).
    ALL = hosts with >=1 vulnerable slug. vuln=<slug> / vulns=<csv> filter by slug(s) (AND).
    limit=0 = no limit (export default).
    """
    _NO_OVERRIDE = object()  # sentinel: distinguishes "no row" from "row with is_vulnerable=None"

    with db_cursor() as cur:
        host_rows = cur.execute(
            "SELECT id, ip, hostname, domain, os, smbv1, signing, spooler, zerologon, petitpotam"
            " FROM hosts WHERE workspace_id=? AND hidden=0",
            (workspace_id,),
        ).fetchall()
        finding_rows = cur.execute(
            "SELECT ip, hostname, domain, vuln_name, is_vulnerable FROM vuln_findings"
            " WHERE workspace_id=?",
            (workspace_id,),
        ).fetchall()
        override_rows = cur.execute(
            "SELECT ip, vuln_name, is_vulnerable FROM vuln_overrides WHERE workspace_id=?",
            (workspace_id,),
        ).fetchall()

    # Findings indexed by ip → {slug: is_vulnerable}
    findings_by_ip: dict = {}
    finding_meta: dict = {}  # ip → (hostname, domain) for finding-only hosts
    for fr in finding_rows:
        findings_by_ip.setdefault(fr["ip"], {})[fr["vuln_name"]] = fr["is_vulnerable"]
        finding_meta.setdefault(fr["ip"], (fr["hostname"], fr["domain"]))

    # User overrides: ip → {slug: is_vulnerable}. Row existence = override active.
    overrides_by_ip: dict = {}
    for ov in override_rows:
        overrides_by_ip.setdefault(ov["ip"], {})[ov["vuln_name"]] = ov["is_vulnerable"]

    hosts_by_ip: dict = {h["ip"]: dict(h) for h in host_rows}

    # Spine = union of host IPs, finding IPs, and override IPs
    spine_set: set = set(hosts_by_ip.keys()) | set(findings_by_ip.keys()) | set(overrides_by_ip.keys())
    spine = list(spine_set)

    rows = []
    for ip in spine:
        h = hosts_by_ip.get(ip, {})
        ffinds = findings_by_ip.get(ip, {})
        ip_overrides = overrides_by_ip.get(ip, {})
        row = {
            "ip": ip,
            "hostname": h.get("hostname") or (finding_meta.get(ip) or (None, None))[0],
            "domain":   h.get("domain")   or (finding_meta.get(ip) or (None, None))[1],
            "os":       h.get("os"),
            "id":       h.get("id"),
        }
        for col in VULN_COLUMNS:
            slug = col["slug"]
            override_val = ip_overrides.get(slug, _NO_OVERRIDE)
            if override_val is not _NO_OVERRIDE:
                status = override_val  # user override wins (1, 0, or None)
            elif col["source"] == "host":
                status = _host_col_status(h.get(col["col"]), col["vuln_value"]) if h else None
            elif col["source"] == "finding":
                status = ffinds.get(slug)  # None if no finding row
            else:  # merge
                hs = _host_col_status(h.get(col["col"]), col["vuln_value"]) if h else None
                status = _merge_status(hs, ffinds.get(slug))
            row[slug] = status
        rows.append(row)

    # Filters
    if vulns:
        wanted = [v.strip() for v in vulns.split(",") if v.strip() in (c["slug"] for c in VULN_COLUMNS)]
        if wanted:
            rows = [r for r in rows if all(r.get(s) == 1 for s in wanted)]  # AND
    elif vuln and vuln in (c["slug"] for c in VULN_COLUMNS):
        rows = [r for r in rows if r.get(vuln) == 1]
    elif not show_all:
        # ALL → only hosts with at least one vulnerable slug (default behaviour)
        rows = [r for r in rows if any(r.get(c["slug"]) == 1 for c in VULN_COLUMNS)]
    # show_all=True with no slug filter → return every host in the spine (manage mode)

    if search:
        s = search.casefold()
        rows = [r for r in rows
                if any(s in str(r.get(k) or "").casefold() for k in ("ip", "hostname", "domain", "os"))]

    rows.sort(key=lambda r: r["ip"])
    total = len(rows)
    if limit > 0:
        offset = (page - 1) * limit
        rows = rows[offset:offset + limit]
    return {"rows": rows, "total": total}


_SEARCH_TABLE_LIMIT = 1000  # per-table cap — large enough for dedup before pagination


@router.get("/api/search", dependencies=[Depends(verify_token)])
def global_search(
    workspace_id: int,
    q: str = "",
    page: int = 1,
    limit: int = 100,  # 0 = all
    hide_guest: bool = True,
):
    """Cross-DB search across all tables in a workspace, with pagination."""
    q = (q or "").strip()
    if len(q) < 2:
        return {"rows": [], "total": 0}

    results: list = []

    with db_cursor() as cur:
        # auth_relations + hosts + credentials
        rows = cur.execute(f"""
            SELECT ar.proto, 'auth' AS _type,
                   h.ip, h.hostname, h.domain AS host_domain, h.os, h.banner,
                   c.domain, c.username, c.password, c.brutforced, c.credtype,
                   c.admin_cred, c.local_admin_cred,
                   ar.relation_type, ar.operator
            FROM auth_relations ar
            JOIN hosts h ON ar.host_id = h.id
            JOIN credentials c ON ar.credential_id = c.id
            WHERE ar.workspace_id = ?
              AND c.hidden = 0
              AND h.hidden = 0
              AND (NOT ? OR casefold(c.username) NOT IN {_GUEST_NAMES_SQL})
              AND (icontains(?,h.ip) OR icontains(?,h.hostname) OR icontains(?,h.os)
                   OR icontains(?,c.username) OR icontains(?,c.password)
                   OR icontains(?,c.brutforced) OR icontains(?,c.domain))
            LIMIT ?
        """, (workspace_id, hide_guest, q, q, q, q, q, q, q, _SEARCH_TABLE_LIMIT)).fetchall()
        results.extend(dict(r) for r in rows)

        # dpapi_secrets
        rows = cur.execute("""
            SELECT d.dpapi_type AS proto, 'dpapi' AS _type,
                   d.host_ip AS ip, NULL AS hostname, NULL AS host_domain,
                   NULL AS os, NULL AS banner,
                   d.host_ip AS domain, d.username, d.password,
                   'plaintext' AS credtype, NULL AS relation_type,
                   d.operator, d.url
            FROM dpapi_secrets d
            WHERE d.workspace_id = ? AND d.hidden = 0
              AND (icontains(?,host_ip) OR icontains(?,username)
                   OR icontains(?,password) OR icontains(?,windows_user) OR icontains(?,url))
            LIMIT ?
        """, (workspace_id, q, q, q, q, q, _SEARCH_TABLE_LIMIT)).fetchall()
        results.extend(dict(r) for r in rows)

        # hosts without auth
        rows = cur.execute("""
            SELECT NULL AS proto, 'host' AS _type,
                   id, ip, hostname, domain AS host_domain, os, banner,
                   domain, NULL AS username, NULL AS password,
                   NULL AS credtype, NULL AS relation_type, operator, NULL AS url
            FROM hosts
            WHERE workspace_id = ? AND hidden = 0
              AND (icontains(?,ip) OR icontains(?,hostname) OR icontains(?,domain) OR icontains(?,os))
            LIMIT ?
        """, (workspace_id, q, q, q, q, _SEARCH_TABLE_LIMIT)).fetchall()
        results.extend(dict(r) for r in rows)

        # credentials without auth_relations (LSA/SAM dumps, dcsync, enumerated accounts)
        # GUARD: first block only covers credentials WITH auth_relations — these are the rest
        # GUARD: relation_type=NULL here → canLap=false → local_admin_cred never drives 💻, but included for skull state consistency
        rows = cur.execute(f"""
            SELECT c.proto, 'cred' AS _type,
                   c.pillaged_from_ip AS ip,
                   h.hostname, h.domain AS host_domain, h.os, NULL AS banner,
                   c.domain, c.username, c.password, c.brutforced, c.credtype,
                   c.admin_cred, c.local_admin_cred,
                   NULL AS relation_type, c.operator, NULL AS url
            FROM credentials c
            LEFT JOIN hosts h ON h.workspace_id = c.workspace_id AND h.ip = c.pillaged_from_ip
            WHERE c.workspace_id = ?
              AND c.hidden = 0
              AND (NOT ? OR casefold(c.username) NOT IN {_GUEST_NAMES_SQL})
              AND NOT EXISTS (
                  SELECT 1 FROM auth_relations ar
                  WHERE ar.credential_id = c.id AND ar.workspace_id = c.workspace_id
              )
              AND (icontains(?,c.domain) OR icontains(?,c.username)
                   OR icontains(?,c.password) OR icontains(?,c.brutforced)
                   OR icontains(?,c.pillaged_from_ip))
            LIMIT ?
        """, (workspace_id, hide_guest, q, q, q, q, q, _SEARCH_TABLE_LIMIT)).fetchall()
        results.extend(dict(r) for r in rows)

        # custom_credentials (Toolbox Block 1 manual import)
        rows = cur.execute("""
            SELECT proto, 'custom' AS _type,
                   ip, NULL AS hostname, NULL AS host_domain,
                   NULL AS os, NULL AS banner,
                   domain, login AS username, password, NULL AS brutforced, credtype,
                   NULL AS relation_type, NULL AS operator, url,
                   source, comment
            FROM custom_credentials
            WHERE workspace_id = ?
              AND (icontains(?,login) OR icontains(?,password) OR icontains(?,ip)
                   OR icontains(?,domain) OR icontains(?,proto)
                   OR icontains(?,url) OR icontains(?,source) OR icontains(?,comment))
            LIMIT ?
        """, (workspace_id, q, q, q, q, q, q, q, q, _SEARCH_TABLE_LIMIT)).fetchall()
        results.extend(dict(r) for r in rows)

        # shares
        rows = cur.execute("""
            SELECT 'SMB' AS proto, 'share' AS _type,
                   h.ip, NULL AS hostname, NULL AS host_domain,
                   NULL AS os, NULL AS banner,
                   NULL AS domain, c.username, s.name AS password,
                   NULL AS credtype, NULL AS relation_type,
                   s.operator, NULL AS url
            FROM shares s
            LEFT JOIN hosts h ON s.host_id = h.id
            LEFT JOIN credentials c ON s.credential_id = c.id
            WHERE s.workspace_id = ?
              AND (icontains(?,h.ip) OR icontains(?,c.username)
                   OR icontains(?,s.name) OR icontains(?,s.remark))
            LIMIT ?
        """, (workspace_id, q, q, q, q, _SEARCH_TABLE_LIMIT)).fetchall()
        results.extend(dict(r) for r in rows)

    # Determine which fields matched
    searchable = ("ip", "hostname", "host_domain", "domain", "os", "username", "password", "brutforced", "banner")
    q_lower = q.lower()
    for r in results:
        r["matched_in"] = [
            f for f in searchable
            if r.get(f) and q_lower in str(r[f]).lower()
        ]

    # Deduplicate by (proto, _type, ip, username, password)
    seen: set = set()
    deduped: list = []
    for r in results:
        k = (r.get("proto") or "", r.get("_type") or "",
             r.get("ip") or "", r.get("username") or "", r.get("password") or "")
        if k not in seen:
            seen.add(k)
            deduped.append(r)

    total = len(deduped)
    if limit > 0:
        offset = (page - 1) * limit
        page_rows = deduped[offset: offset + limit]
    else:
        page_rows = deduped  # limit=0 → all

    return {"rows": page_rows, "total": total}



