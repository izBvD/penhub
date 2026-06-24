"""
Export routes: /api/export/xlsx, /api/export/allcred, /api/export/creds
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse

from collector.api.data import get_credentials, get_dpapi, get_results, get_vulns
from collector.api.data_hosts import get_conf_checks, get_hosts
from collector.api.data_manage import get_custom_creds
from collector.core.auth import verify_token
from collector.core.constants import _GUEST_NAMES_SQL, _XLSX_MIME, VULN_COLUMNS
from collector.core.workspace_utils import ws_safe
from collector.db import db_cursor
from collector.services.data_service import apply_brutforced, dedup_results, smart_dedup_creds
from collector.services.export_service import allcred_xlsx, cred_xlsx, xlsx_buf

logger = logging.getLogger(__name__)

_EXPORT_LIMIT = 50_000

# SQL CTE that replaces smart_dedup_creds(apply_brutforced(...)) for allcred export.
# Dedup logic (mirrors Python implementation):
#   1. Apply brutforced: hash with brutforced → treat as plaintext with cracked password.
#   2. Per (lower(domain), lower(username)): if any plaintext exists, keep it; else keep hash.
#   3. ROW_NUMBER picks one row — plaintext-type row first, then SMB > LDAP > other.
_ALLCRED_DEDUP_SQL = f"""
WITH
applied AS (
    SELECT
        proto,
        COALESCE(domain, '') AS domain,
        username,
        CASE WHEN brutforced IS NOT NULL AND credtype = 'hash'
             THEN brutforced ELSE password END  AS password,
        CASE WHEN brutforced IS NOT NULL AND credtype = 'hash'
             THEN 'plaintext' ELSE credtype END AS credtype,
        local_admin_cred
    FROM credentials
    WHERE workspace_id = ?
      AND username != ''
      AND hidden = 0
      AND casefold(username) NOT IN {_GUEST_NAMES_SQL}
),
best AS (
    SELECT
        LOWER(domain)   AS dk,
        LOWER(username) AS uk,
        MAX(CASE WHEN credtype = 'plaintext' THEN 1 ELSE 0 END) AS has_plain,
        MIN(CASE WHEN credtype = 'plaintext' THEN password END)  AS plain_pass
    FROM applied
    GROUP BY LOWER(domain), LOWER(username)
),
ranked AS (
    SELECT
        a.proto,
        a.domain,
        a.username,
        CASE WHEN b.has_plain THEN b.plain_pass ELSE a.password END AS password,
        CASE WHEN b.has_plain THEN 'plaintext'  ELSE a.credtype  END AS credtype,
        a.local_admin_cred,
        ROW_NUMBER() OVER (
            PARTITION BY LOWER(a.domain), LOWER(a.username)
            ORDER BY
                CASE WHEN b.has_plain = 1 AND a.credtype = 'plaintext' THEN 0
                     WHEN b.has_plain = 0 AND a.credtype = 'hash'      THEN 0
                     ELSE 1 END,
                CASE a.proto WHEN 'SMB' THEN 0 WHEN 'LDAP' THEN 1 ELSE 2 END
        ) AS rn
    FROM applied a
    JOIN best b ON LOWER(a.domain) = b.dk AND LOWER(a.username) = b.uk
)
SELECT proto, domain, username, password, credtype, local_admin_cred
FROM ranked
WHERE rn = 1
"""


router = APIRouter()


@router.get("/api/export/xlsx", dependencies=[Depends(verify_token)])
def export_xlsx(
    workspace_id: int = Query(...),
    view: str = Query("results"),
    proto: Optional[str] = Query(None),
    relation: Optional[str] = Query(None),
    relations: Optional[str] = Query(None),
    credtype: Optional[str] = Query(None),
    admin_cred: Optional[bool] = Query(None),
    vuln: Optional[str] = Query(None),
    vulns: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    q: Optional[str] = Query(None),       # global search term (view=search only)
    hide_guest: bool = Query(True),
    hk: bool = Query(False),
):
    if view == "shares":
        conditions = ["s.workspace_id = ?"]
        params: list = [workspace_id]
        if search:
            conditions.append(
                "(icontains(?,h.ip) OR icontains(?,c.username) OR icontains(?,s.name)"
                " OR icontains(?,s.remark))"
            )
            params += [search] * 4
        where = " AND ".join(conditions)
        with db_cursor() as cur:
            share_rows = [dict(r) for r in cur.execute(f"""
                SELECT h.ip, h.hostname, h.domain AS host_domain, h.os,
                       c.domain AS cred_domain, c.username, c.password, c.credtype,
                       s.name, s.remark, s.read, s.write, s.operator
                FROM shares s
                LEFT JOIN hosts h ON s.host_id = h.id
                LEFT JOIN credentials c ON s.credential_id = c.id
                WHERE {where}
                ORDER BY s.id DESC
                LIMIT ?
            """, params + [_EXPORT_LIMIT]).fetchall()]
        headers = ["Proto", "IP", "Hostname", "Host Domain", "OS",
                   "Cred Domain", "Username", "Password", "Type", "Relation",
                   "Operator", "Share", "Remark", "Read", "Write"]
        rows = [[
            "SMB", r["ip"], r["hostname"], r["host_domain"], r["os"],
            r["cred_domain"], r["username"], r["password"], r["credtype"], "",
            r["operator"], r["name"], r["remark"],
            "Yes" if r["read"]  else ("No" if r["read"]  is not None else ""),
            "Yes" if r["write"] else ("No" if r["write"] is not None else ""),
            None,
        ] for r in share_rows]
        buf = xlsx_buf(headers, rows, "Shares")

    elif view == "hosts":
        data = get_hosts(
            workspace_id=workspace_id, proto=proto, search=search,
            page=1, limit=_EXPORT_LIMIT,
        )
        headers = ["IP", "Hostname", "Domain", "OS", "Banner", "Operator"]
        rows = [[
            r["ip"], r["hostname"], r["domain"], r["os"], r["banner"], r["operator"],
            None,
        ] for r in data["rows"]]
        buf = xlsx_buf(headers, rows, "Hosts")

    elif view == "conf_checks":
        data = get_conf_checks(
            workspace_id=workspace_id, search=search, page=1, limit=_EXPORT_LIMIT,
        )
        headers = ["IP", "Hostname", "Check", "Secure", "Reasons"]
        rows = [[
            r["ip"], r["hostname"], r["check_name"],
            "yes" if r["secure"] else "DANGER",
            r["reasons"],
            None,
        ] for r in data["rows"]]
        buf = xlsx_buf(headers, rows, "ConfChecks")

    elif view == "vulns":
        # Columns mirror the VULNS view 1:1 (VULN_COLUMNS) so the user filters in Excel.
        data = get_vulns(workspace_id=workspace_id, vuln=vuln, vulns=vulns, search=search, page=1, limit=0)
        headers = ["IP", "Hostname", "Domain", "OS"] + [c["label"] for c in VULN_COLUMNS]
        # tri-state cell: 1→YES, 0→no, None→"" (no data / could-not-check)
        cell = lambda v: "YES" if v == 1 else ("no" if v == 0 else "")
        rows = []
        for r in data["rows"]:
            rows.append(
                [r["ip"], r["hostname"], r["domain"], r["os"]]
                + [cell(r.get(c["slug"])) for c in VULN_COLUMNS]
                + [None]
            )
        buf = xlsx_buf(headers, rows, "Vulns")

    elif view == "dpapi":
        data = get_dpapi(workspace_id=workspace_id, search=search, page=1, limit=_EXPORT_LIMIT)
        headers = ["Host IP", "Browser/Type", "Windows User", "Username", "Password", "URL", "Operator"]
        rows = [[
            r["host_ip"], r["dpapi_type"], r["windows_user"],
            r["username"], r["password"], r["url"], r["operator"],
            "__dpapi__",
        ] for r in data["rows"]]
        buf = xlsx_buf(headers, rows, "DPAPI")

    elif view == "local_admin":
        data = get_results(
            workspace_id=workspace_id, proto="SMB", relation="admin",
            local_admin_cred=True, search=search, hide_guest=hide_guest,
            page=1, limit=_EXPORT_LIMIT,
        )
        raw = [
            {"proto": r["ip"] or "", "domain": r["cred_domain"] or "",
             "username": r["username"], "password": r["password"],
             "credtype": r["credtype"], "brutforced": r.get("brutforced")}
            for r in data["rows"]
        ]
        if hk:
            raw = apply_brutforced(raw)
        seen: set = set()
        deduped_la: list = []
        for r in raw:
            k = ((r["proto"] or "").lower(), (r["username"] or "").lower(), r["password"] or "")
            if k not in seen:
                seen.add(k)
                deduped_la.append(r)
        buf = cred_xlsx(deduped_la, headers=["IP", "Machine", "Login", "Password", "Is Hash?"])

    elif view == "creds":
        data = get_credentials(
            workspace_id=workspace_id, proto=proto, credtype=credtype,
            search=search, hide_guest=hide_guest, admin_cred=admin_cred,
            page=1, limit=_EXPORT_LIMIT
        )
        cred_rows = [dict(r) for r in data["rows"]]
        if hk:
            cred_rows = apply_brutforced(cred_rows)
        headers = ["Proto", "Domain", "Username", "Password", "Type", "Pillaged From", "Operator"]
        rows = [[
            r["proto"], r["domain"], r["username"], r["password"],
            r["credtype"], r.get("pillaged_from_ip"), r["operator"],
            "__hash__" if r["credtype"] == "hash" else None,
        ] for r in cred_rows]
        buf = xlsx_buf(headers, rows, "Credentials")

    elif view == "all":
        # Merged view: auth_relations + DPAPI + SAM/LSA (mirrors ALL-ALL browser view)
        data_r = get_results(
            workspace_id=workspace_id, proto=proto, relation=None,
            relations=None, credtype=None, admin_cred=None,
            search=search, hide_guest=hide_guest, page=1, limit=_EXPORT_LIMIT,
            dedup=False,
        )
        deduped = dedup_results(data_r["rows"])
        if hk:
            deduped = apply_brutforced(deduped)
        data_d = get_dpapi(workspace_id=workspace_id, search=search, page=1, limit=_EXPORT_LIMIT)
        data_s = get_credentials(
            workspace_id=workspace_id, proto="SMB", samlsa=True,
            search=search, hide_guest=hide_guest, page=1, limit=_EXPORT_LIMIT,
        )
        headers = ["Proto", "IP", "Domain", "Username", "Password", "URL", "Relation", "Type"]
        rows = []
        for r in deduped:
            tag = "__admin__" if r["relation_type"] == "admin" else (
                "__hash__" if r["credtype"] == "hash" else None
            )
            rows.append([
                r["proto"], r["ip"], r["cred_domain"], r["username"],
                r["password"], r.get("url") or None, r["relation_type"], r["credtype"],
                tag,
            ])
        for r in data_d["rows"]:
            rows.append([
                r["dpapi_type"], r["host_ip"], None, r["username"],
                r["password"], r.get("url") or None, None, "plaintext",
                "__dpapi__",
            ])
        for r in data_s["rows"]:
            tag = "__hash__" if r["credtype"] == "hash" else None
            rows.append([
                r["proto"], r["pillaged_from_ip"], r["domain"], r["username"],
                r["password"], None, None, r["credtype"],
                tag,
            ])
        data_cc = get_custom_creds(workspace_id=workspace_id, search=search, page=1, limit=_EXPORT_LIMIT)
        cc_rows = list(data_cc["rows"])
        # GUARD: no apply_brutforced here — custom_credentials has no brutforced column.
        for r in cc_rows:
            rows.append([
                r.get("proto"), r.get("ip"), r.get("domain"),
                r.get("username"),  # login aliased
                r.get("password"), r.get("url"), None, r.get("credtype"),
                "__custom__",
            ])
        buf = xlsx_buf(headers, rows, "All")

    elif view == "custom":
        data_cc = get_custom_creds(workspace_id=workspace_id, search=search, page=1, limit=_EXPORT_LIMIT)
        custom_rows = list(data_cc["rows"])
        if hk:
            custom_rows = apply_brutforced(custom_rows)  # HK toggle: show cracked custom hashes
        headers = ["Proto", "IP", "Port", "Domain", "Login", "Password", "Type", "URL", "Source", "Comment"]
        rows = [[
            r.get("proto"), r.get("ip"), r.get("port"), r.get("domain"),
            r.get("username"),  # aliased from login in get_custom_creds
            r.get("password"), r.get("credtype"),
            r.get("url"), r.get("source"), r.get("comment"),
            "__custom__" if r.get("credtype") == "hash" else None,
        ] for r in custom_rows]
        buf = xlsx_buf(headers, rows, "CustomCreds")

    elif view == "search":
        # GUARD: mirrors global_search in data.py — keep query logic in sync when search changes.
        sq = (q or "").strip()
        results: list = []
        if sq and len(sq) >= 2:
            with db_cursor() as cur:
                rows_q = cur.execute(f"""
                    SELECT ar.proto, 'auth' AS _type,
                           h.ip, h.hostname, h.domain AS host_domain, h.os, h.banner,
                           c.domain, c.username, c.password, c.brutforced, c.credtype,
                           c.admin_cred, c.local_admin_cred,
                           ar.relation_type, ar.operator, NULL AS url
                    FROM auth_relations ar
                    JOIN hosts h ON ar.host_id = h.id
                    JOIN credentials c ON ar.credential_id = c.id
                    WHERE ar.workspace_id = ?
                      AND c.hidden = 0 AND h.hidden = 0
                      AND (NOT ? OR casefold(c.username) NOT IN {_GUEST_NAMES_SQL})
                      AND (icontains(?,h.ip) OR icontains(?,h.hostname) OR icontains(?,h.os)
                           OR icontains(?,c.username) OR icontains(?,c.password)
                           OR icontains(?,c.brutforced) OR icontains(?,c.domain))
                    LIMIT ?
                """, (workspace_id, hide_guest, sq, sq, sq, sq, sq, sq, sq, _EXPORT_LIMIT)).fetchall()
                results.extend(dict(r) for r in rows_q)

                rows_q = cur.execute("""
                    SELECT d.dpapi_type AS proto, 'dpapi' AS _type,
                           d.host_ip AS ip, NULL AS hostname, NULL AS host_domain,
                           NULL AS os, NULL AS banner,
                           d.host_ip AS domain, d.username, d.password,
                           NULL AS brutforced, 'plaintext' AS credtype,
                           NULL AS relation_type, d.operator, d.url
                    FROM dpapi_secrets d
                    WHERE d.workspace_id = ? AND d.hidden = 0
                      AND (icontains(?,host_ip) OR icontains(?,username)
                           OR icontains(?,password) OR icontains(?,windows_user) OR icontains(?,url))
                    LIMIT ?
                """, (workspace_id, sq, sq, sq, sq, sq, _EXPORT_LIMIT)).fetchall()
                results.extend(dict(r) for r in rows_q)

                rows_q = cur.execute("""
                    SELECT NULL AS proto, 'host' AS _type,
                           ip, hostname, domain AS host_domain, os, banner,
                           domain, NULL AS username, NULL AS password,
                           NULL AS brutforced, NULL AS credtype,
                           NULL AS relation_type, operator, NULL AS url
                    FROM hosts
                    WHERE workspace_id = ? AND hidden = 0
                      AND (icontains(?,ip) OR icontains(?,hostname) OR icontains(?,domain) OR icontains(?,os))
                    LIMIT ?
                """, (workspace_id, sq, sq, sq, sq, _EXPORT_LIMIT)).fetchall()
                results.extend(dict(r) for r in rows_q)

                rows_q = cur.execute(f"""
                    SELECT c.proto, 'cred' AS _type,
                           c.pillaged_from_ip AS ip,
                           h.hostname, h.domain AS host_domain, h.os, NULL AS banner,
                           c.domain, c.username, c.password, c.brutforced, c.credtype,
                           c.admin_cred, c.local_admin_cred,
                           NULL AS relation_type, c.operator, NULL AS url
                    FROM credentials c
                    LEFT JOIN hosts h ON h.workspace_id = c.workspace_id AND h.ip = c.pillaged_from_ip
                    WHERE c.workspace_id = ? AND c.hidden = 0
                      AND (NOT ? OR casefold(c.username) NOT IN {_GUEST_NAMES_SQL})
                      AND NOT EXISTS (
                          SELECT 1 FROM auth_relations ar
                          WHERE ar.credential_id = c.id AND ar.workspace_id = c.workspace_id
                      )
                      AND (icontains(?,c.domain) OR icontains(?,c.username)
                           OR icontains(?,c.password) OR icontains(?,c.brutforced)
                           OR icontains(?,c.pillaged_from_ip))
                    LIMIT ?
                """, (workspace_id, hide_guest, sq, sq, sq, sq, sq, _EXPORT_LIMIT)).fetchall()
                results.extend(dict(r) for r in rows_q)

                rows_q = cur.execute("""
                    SELECT proto, 'custom' AS _type,
                           ip, NULL AS hostname, NULL AS host_domain, NULL AS os, NULL AS banner,
                           domain, login AS username, password, NULL AS brutforced, credtype,
                           NULL AS relation_type, NULL AS operator, url,
                           source, comment
                    FROM custom_credentials
                    WHERE workspace_id = ?
                      AND (icontains(?,login) OR icontains(?,password) OR icontains(?,ip)
                           OR icontains(?,domain) OR icontains(?,proto)
                           OR icontains(?,url) OR icontains(?,source) OR icontains(?,comment))
                    LIMIT ?
                """, (workspace_id, sq, sq, sq, sq, sq, sq, sq, sq, _EXPORT_LIMIT)).fetchall()
                results.extend(dict(r) for r in rows_q)

        seen: set = set()
        deduped_s: list = []
        for r in results:
            k = (r.get("proto") or "", r.get("_type") or "",
                 r.get("ip") or "", r.get("username") or "", r.get("password") or "")
            if k not in seen:
                seen.add(k)
                deduped_s.append(r)

        if hk:
            deduped_s = apply_brutforced(deduped_s)

        headers = ["Proto", "Type", "IP", "Hostname", "Domain", "OS",
                   "Username", "Password", "Credtype", "Relation", "Operator", "URL",
                   "Source", "Comment"]
        rows = [[
            r.get("proto") or "", r.get("_type") or "", r.get("ip") or "",
            r.get("hostname") or "", r.get("domain") or r.get("host_domain") or "",
            r.get("os") or "", r.get("username") or "", r.get("password") or "",
            r.get("credtype") or "", r.get("relation_type") or "",
            r.get("operator") or "", r.get("url") or "",
            r.get("source") or "", r.get("comment") or "",
            "__admin__" if r.get("relation_type") == "admin" else (
                "__hash__" if r.get("credtype") == "hash" else None),
        ] for r in deduped_s]
        buf = xlsx_buf(headers, rows, "Search")

    else:  # results
        data = get_results(
            workspace_id=workspace_id, proto=proto, relation=relation,
            relations=relations, credtype=credtype,
            admin_cred=True if admin_cred is True else None,
            search=search, hide_guest=hide_guest, page=1, limit=_EXPORT_LIMIT,
            dedup=False,
        )
        deduped = dedup_results(data["rows"])
        if hk:
            deduped = apply_brutforced(deduped)
        headers = [
            "Proto", "IP", "Hostname", "Host Domain", "OS",
            "Cred Domain", "Username", "Password", "Type", "Relation", "Operator",
        ]
        rows = []
        for r in deduped:
            tag = "__admin__" if r["relation_type"] == "admin" else (
                "__hash__" if r["credtype"] == "hash" else None
            )
            rows.append([
                r["proto"], r["ip"], r["hostname"], r["host_domain"], r["os"],
                r["cred_domain"], r["username"], r["password"],
                r["credtype"], r["relation_type"], r["operator"],
                tag,
            ])
        buf = xlsx_buf(headers, rows, "Results")

    return StreamingResponse(
        buf, media_type=_XLSX_MIME,
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_xlsx.xlsx"},
    )


@router.get("/api/export/allcred", dependencies=[Depends(verify_token)])
def export_allcred(workspace_id: int = Query(...)):
    with db_cursor() as cur:
        # Dedup + brutforced substitution handled entirely in SQL — no Python materialisation of
        # raw rows. One pass over credentials table; SQLite window function picks winner per
        # (domain, user) the same way smart_dedup_creds(apply_brutforced(...)) does.
        processed = [dict(r) for r in cur.execute(_ALLCRED_DEDUP_SQL, (workspace_id,)).fetchall()]
        # Include a DPAPI secret if it carries a target identifier — a login OR a URL.
        # Password-only secrets with a URL (a site with a single password field, no login)
        # are valuable: the client must rotate them too. Additive vs the old login-only
        # filter — no previously-exported row is dropped.
        dpapi_rows = [dict(r) for r in cur.execute("""
            SELECT DISTINCT dpapi_type AS proto, host_ip, url,
                   username, password
            FROM dpapi_secrets
            WHERE workspace_id=? AND hidden = 0
              AND ( (username IS NOT NULL AND username != '')
                 OR (url      IS NOT NULL AND url      != '') )
        """, (workspace_id,)).fetchall()]

    data_cc = get_custom_creds(workspace_id=workspace_id, page=1, limit=_EXPORT_LIMIT)
    # allcred always substitutes brutforced (like cred_rows below) — cracked custom hashes
    # show as plaintext for the client.
    custom_rows = sorted(
        apply_brutforced(list(data_cc["rows"])),
        key=lambda r: (r.get("proto") or "").lower(),
    )

    total = len(processed) + len(dpapi_rows) + len(custom_rows)
    if total > 10_000:
        logger.warning(
            "export_allcred: workspace_id=%s — %d rows (large export)",
            workspace_id, total,
        )

    # GUARD: local_admin_cred rows are separated AFTER dedup so each machine stays as its own row.
    # Dedup key uses the real domain (machine name), not 'local admin' — see _ALLCRED_DEDUP_SQL.
    local_admin_rows = sorted(
        [r for r in processed if r.get("local_admin_cred") == 1],
        key=lambda r: ((r.get("domain") or "").lower(), (r.get("username") or "").lower()),
    )
    plain_rows = sorted(
        [r for r in processed if r.get("credtype") == "plaintext" and not r.get("local_admin_cred")],
        key=lambda r: (r.get("domain") or "").lower(),
    )
    hash_rows = sorted(
        [r for r in processed if r.get("credtype") == "hash" and not r.get("local_admin_cred")],
        key=lambda r: (r.get("domain") or "").lower(),
    )
    dpapi_rows = sorted(dpapi_rows, key=lambda r: (r.get("host_ip") or "").lower())

    buf = allcred_xlsx(plain_rows, hash_rows, dpapi_rows, custom_rows, local_admin_rows)
    return StreamingResponse(
        buf, media_type=_XLSX_MIME,
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_all_creds.xlsx"},
    )


@router.get("/api/export/creds", dependencies=[Depends(verify_token)])
def export_creds(
    workspace_id: int = Query(...),
    proto: Optional[str] = Query(None),
    relation: Optional[str] = Query(None),
    relations: Optional[str] = Query(None),
    credtype: Optional[str] = Query(None),
    admin_cred: Optional[bool] = Query(None),
    local_admin_cred: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    hide_guest: bool = Query(True),
    view: str = Query("results"),
    hk: bool = Query(False),
):
    if view == "local_admin":
        # Same source as the UI LOCAL ADMIN tab: get_results with admin relation + SMB + local_admin_cred.
        # GUARD: proto forced to SMB and relation to admin — local admin only applies to SMB PWN3D rows.
        data = get_results(
            workspace_id=workspace_id, proto="SMB", relation="admin",
            local_admin_cred=True, search=search, hide_guest=hide_guest,
            page=1, limit=_EXPORT_LIMIT,
        )
        raw = [
            {"proto": r["ip"] or "", "domain": r["cred_domain"] or "",
             "username": r["username"], "password": r["password"],
             "credtype": r["credtype"], "brutforced": r.get("brutforced")}
            for r in data["rows"]
        ]
        if hk:
            raw = apply_brutforced(raw)
        # Dedup by ip+username+password — mirrors _renderLocalAdminCreds() dedup in the UI
        seen: set = set()
        deduped_la = []
        for r in raw:
            k = ((r["proto"] or "").lower(), (r["username"] or "").lower(), r["password"] or "")
            if k not in seen:
                seen.add(k)
                deduped_la.append(r)
        buf = cred_xlsx(deduped_la, headers=["IP", "Machine", "Login", "Password", "Is Hash?"])
    elif view == "dpapi":
        data = get_dpapi(workspace_id=workspace_id, search=search, page=1, limit=_EXPORT_LIMIT)
        rows = [
            {"proto": r["dpapi_type"] or "DPAPI",
             "domain": r.get("host_ip") or "",
             "username": r["username"] or "", "password": r["password"] or "",
             "credtype": "plaintext", "brutforced": None}
            for r in data["rows"]
        ]
        buf = cred_xlsx(rows)
    elif view == "creds":
        data = get_credentials(
            workspace_id=workspace_id, proto=proto, credtype=credtype,
            search=search, hide_guest=hide_guest, page=1, limit=_EXPORT_LIMIT,
            admin_cred=True if admin_cred is True else None,
            local_admin_cred=True if local_admin_cred is True else None,
        )
        rows_raw = [
            {"proto": r["proto"], "domain": r["domain"],
             "username": r["username"], "password": r["password"],
             "credtype": r["credtype"], "brutforced": r.get("brutforced")}
            for r in data["rows"]
        ]
        if hk:
            rows_raw = apply_brutforced(rows_raw)
        seen: set = set()
        deduped_creds = []
        for r in rows_raw:
            k = (r["proto"], r["domain"].lower(), r["username"].lower(), r["password"])
            if k not in seen:
                seen.add(k)
                deduped_creds.append(r)
        buf = cred_xlsx(deduped_creds)
    else:
        data = get_results(
            workspace_id=workspace_id, proto=proto, relation=relation,
            relations=relations, credtype=None,
            admin_cred=True if admin_cred is True else None,
            search=search, hide_guest=hide_guest, page=1, limit=_EXPORT_LIMIT,
            dedup=False,
        )
        raw = [
            {"proto": r["proto"], "domain": r["cred_domain"], "username": r["username"],
             "password": r["password"], "credtype": r["credtype"],
             "brutforced": r.get("brutforced"), "_host_ip": r["ip"]}
            for r in data["rows"]
        ]
        if hk:
            raw = apply_brutforced(raw)
        deduped = smart_dedup_creds(raw)
        for r in deduped:
            r.pop("_host_ip", None)
        buf = cred_xlsx(deduped)
    return StreamingResponse(
        buf, media_type=_XLSX_MIME,
        headers={"Content-Disposition": f"attachment; filename={ws_safe(workspace_id)}_creds.xlsx"},
    )
