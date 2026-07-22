"""
Main push endpoint for nxc_updater: POST /api/sync
"""

from datetime import datetime, timezone

import collector.hashkiller_db as hk_db
from fastapi import APIRouter, BackgroundTasks, Depends

from collector.core.auth import verify_token
from collector.core.models import AdminCredBody, LocalAdminCredBody, SyncPayload, ConfCheckResultIn, DirectoryListingIn
from collector.db import db_cursor, get_or_create_workspace
from collector.services import notification_service
from collector.services.sync_service import normalize_password

router = APIRouter()


@router.post("/api/sync", dependencies=[Depends(verify_token)])
def sync_workspace(body: SyncPayload, background_tasks: BackgroundTasks):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    operator = body.operator
    data = body.data

    with db_cursor() as cur:
        wid = get_or_create_workspace(cur, body.workspace)

        # Timeline: capture the first accepted sync (even an empty one) as a one-time,
        # immutable snapshot. GUARD: workspace_config timeline_first_sync* keys are
        # written ONLY here; the timeline user API never mutates them.
        if not cur.execute(
            "SELECT 1 FROM workspace_config WHERE workspace_id=? AND key='timeline_first_sync'",
            (wid,),
        ).fetchone():
            cur.execute(
                "INSERT INTO workspace_config(workspace_id,key,value) VALUES(?,?,?)",
                (wid, "timeline_first_sync", now),
            )
            cur.execute(
                "INSERT OR REPLACE INTO workspace_config(workspace_id,key,value) VALUES(?,?,?)",
                (wid, "timeline_first_sync_op", operator or ""),
            )

        # Snapshot max credential id before this sync so post-sync honeypot enrichment
        # only auto-hides credentials that are genuinely NEW in this sync.
        # Existing credentials (including individually restored ones) are never touched.
        max_cred_id_before = cur.execute(
            "SELECT COALESCE(MAX(id), 0) FROM credentials WHERE workspace_id=?", (wid,)
        ).fetchone()[0]

        # Snapshot max auth_relation id before this sync so the pwn3d notification
        # emission fires only for hosts that gain their FIRST admin relation now.
        max_ar_before = cur.execute(
            "SELECT COALESCE(MAX(id), 0) FROM auth_relations WHERE workspace_id=?", (wid,)
        ).fetchone()[0]

        # --- Hosts ---
        host_ip_to_id: dict[str, int] = {}
        host_hostname_to_id: dict[str, int] = {}
        for h in data.hosts:
            cur.execute("""
                INSERT INTO hosts(
                    workspace_id, ip, hostname, domain, os,
                    dc, smbv1, signing, spooler, zerologon, petitpotam,
                    nla, signing_required, channel_binding, port, banner,
                    instances, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(workspace_id, ip) DO UPDATE SET
                    hostname        = COALESCE(excluded.hostname,        hostname),
                    domain          = COALESCE(excluded.domain,          domain),
                    os              = COALESCE(excluded.os,              os),
                    dc              = COALESCE(excluded.dc,              dc),
                    smbv1           = COALESCE(excluded.smbv1,           smbv1),
                    signing         = COALESCE(excluded.signing,         signing),
                    spooler         = COALESCE(excluded.spooler,         spooler),
                    zerologon       = COALESCE(excluded.zerologon,       zerologon),
                    petitpotam      = COALESCE(excluded.petitpotam,      petitpotam),
                    nla             = COALESCE(excluded.nla,             nla),
                    signing_required= COALESCE(excluded.signing_required,signing_required),
                    channel_binding = COALESCE(excluded.channel_binding, channel_binding),
                    port            = COALESCE(excluded.port,            port),
                    banner          = COALESCE(excluded.banner,          banner),
                    instances       = COALESCE(excluded.instances,       instances),
                    updated_at      = excluded.updated_at
                    -- GUARD: user-managed columns (hidden) are intentionally absent from DO UPDATE SET.
                    -- They are controlled exclusively via /api/hosts/set_hidden.
                    -- If you add a new user-managed column to hosts, do NOT include it here.
            """, (
                wid, h.ip, h.hostname, h.domain, h.os,
                h.dc, h.smbv1, h.signing, h.spooler, h.zerologon, h.petitpotam,
                h.nla, h.signing_required, h.channel_binding, h.port, h.banner,
                h.instances, operator, now,
            ))
            row = cur.execute(
                "SELECT id, hostname FROM hosts WHERE workspace_id=? AND ip=?", (wid, h.ip)
            ).fetchone()
            if row:
                host_ip_to_id[h.ip] = row["id"]
                if row["hostname"]:
                    host_hostname_to_id[row["hostname"]] = row["id"]

        # --- Credentials ---
        cred_key_to_id: dict[tuple, int] = {}
        for c in data.credentials:
            domain   = c.domain or ""
            username = c.username or ""
            credtype = c.credtype or "plaintext"
            password, credtype = normalize_password(c.password or "", credtype)
            # GUARD: user-managed columns (admin_cred, hidden) are intentionally omitted
            # from the INSERT column list — they default to 0 for new rows.
            # INSERT OR IGNORE means no UPDATE runs on conflict, so existing values
            # are preserved automatically. Do NOT move these columns into any DO UPDATE SET.
            # They are controlled exclusively via /api/credentials/set_admin_cred,
            # /api/credentials/set_hidden, the domain_admin_list post-sync enrichment,
            # and the honeypot auto-hide post-sync enrichment.
            # If you add a new user-managed column to credentials, follow the same pattern.
            cur.execute("""
                INSERT OR IGNORE INTO credentials(
                    workspace_id, proto, domain, username, password,
                    credtype, pillaged_from_ip, pkey, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """, (wid, c.proto, domain, username, password, credtype,
                  c.pillaged_from_ip, c.pkey, operator, now))
            # Update pkey if provided and credential already existed
            if c.pkey:
                cur.execute(
                    "UPDATE credentials SET pkey=? WHERE workspace_id=? AND proto=?"
                    " AND domain=? AND username=? AND password=? AND credtype=?"
                    " AND pkey IS NULL",
                    (c.pkey, wid, c.proto, domain, username, password, credtype),
                )
            row = cur.execute(
                """SELECT id FROM credentials
                   WHERE workspace_id=? AND proto=? AND domain=?
                     AND username=? AND password=? AND credtype=?""",
                (wid, c.proto, domain, username, password, credtype),
            ).fetchone()
            if row:
                cred_key_to_id[(c.proto, domain, username, password, credtype)] = row["id"]

        # --- Auth relations ---
        for ar in data.auth_relations:
            host_id = host_ip_to_id.get(ar.host_ip)
            if host_id is None:
                continue
            domain   = ar.cred_domain or ""
            password, credtype = normalize_password(
                ar.cred_password or "", ar.cred_credtype or "plaintext"
            )
            cred_id  = cred_key_to_id.get(
                (ar.proto, domain, ar.cred_username, password, credtype)
            )
            if cred_id is None:
                continue
            cur.execute("""
                INSERT INTO auth_relations(
                    workspace_id, proto, credential_id, host_id,
                    relation_type, shell, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(workspace_id, proto, credential_id, host_id, relation_type)
                DO UPDATE SET
                    shell      = COALESCE(excluded.shell, shell),
                    updated_at = excluded.updated_at
            """, (wid, ar.proto, cred_id, host_id, ar.relation_type, ar.shell, operator, now))

        # --- Honeypot auto-hide: new credentials from struck hosts ---
        # GUARD: READ-ONLY access to hosts.honeypot here.
        # honeypot is managed exclusively via:
        #   POST /api/hosts/strike
        #   POST /api/hosts/restore_strike
        # Only credentials.hidden is written — hosts is the lookup source.
        # Only NEW credentials (id > max_cred_id_before) are touched — existing rows,
        # including individually restored ones, are intentionally preserved.
        cur.execute("""
            UPDATE credentials SET hidden=1, hidden_by_strike=1
            WHERE workspace_id=? AND id > ? AND hidden=0
              AND EXISTS (
                SELECT 1 FROM auth_relations ar
                JOIN hosts h ON h.id = ar.host_id
                WHERE ar.credential_id = credentials.id
                  AND ar.workspace_id  = credentials.workspace_id
                  AND h.honeypot       = 1
              )
              AND NOT EXISTS (
                SELECT 1 FROM auth_relations ar2
                JOIN hosts h2 ON h2.id = ar2.host_id
                WHERE ar2.credential_id = credentials.id
                  AND ar2.workspace_id  = credentials.workspace_id
                  AND h2.honeypot       = 0
              )
        """, (wid, max_cred_id_before))

        # --- Notifications: pwn3d (hosts that gained their first admin relation) ---
        notification_service.emit_pwn3d(cur, wid, max_ar_before, now)

        # --- DPAPI secrets ---
        for d in data.dpapi_secrets:
            # GUARD: hidden is intentionally omitted — managed exclusively via /api/dpapi/set_hidden.
            # INSERT OR IGNORE preserves existing hidden value on conflict.
            cur.execute("""
                INSERT OR IGNORE INTO dpapi_secrets(
                    workspace_id, host_ip, dpapi_type, windows_user,
                    username, password, url, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
            """, (wid, d.host_ip, d.dpapi_type, d.windows_user,
                  d.username, d.password, d.url, operator, now))

        # --- Shares ---
        for s in data.shares:
            host_id = host_ip_to_id.get(s.host_ip or "")
            if host_id is None and s.host_hostname:
                host_id = host_hostname_to_id.get(s.host_hostname)
            if host_id is None:
                continue
            cred_id = None
            if s.cred_username is not None:
                domain   = s.cred_domain or ""
                password, credtype = normalize_password(
                    s.cred_password or "", s.cred_credtype or "plaintext"
                )
                cred_id  = cred_key_to_id.get(
                    (s.proto, domain, s.cred_username, password, credtype)
                )
            cur.execute("""
                INSERT OR IGNORE INTO shares(
                    workspace_id, host_id, credential_id, name, remark,
                    read, write, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
            """, (wid, host_id, cred_id, s.name, s.remark,
                  s.read, s.write, operator, now))

        # --- SSH keys ---
        for k in data.ssh_keys:
            domain = k.cred_domain or ""
            kpw, kct = normalize_password(k.cred_password or "", k.cred_credtype or "plaintext")
            cred_id = cred_key_to_id.get(
                ("SSH", domain, k.cred_username, kpw, kct)
            )
            if cred_id is None:
                continue
            cur.execute("""
                INSERT OR IGNORE INTO ssh_keys(
                    workspace_id, credential_id, key_data, operator, updated_at
                ) VALUES(?,?,?,?,?)
            """, (wid, cred_id, k.key_data, operator, now))

        # --- Conf checks results ---
        for cc in data.conf_checks_results:
            host_id = host_ip_to_id.get(cc.host_ip)
            if host_id is None:
                continue
            cur.execute("""
                INSERT INTO conf_checks_results(
                    workspace_id, host_id, check_name, secure, reasons, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(workspace_id, host_id, check_name) DO UPDATE SET
                    secure     = excluded.secure,
                    reasons    = excluded.reasons,
                    updated_at = excluded.updated_at
            """, (wid, host_id, cc.check_name, cc.secure, cc.reasons, operator, now))

        # --- Directory listings (FTP dirs, NFS shares) ---
        for dl in data.directory_listings:
            cur.execute("""
                INSERT OR IGNORE INTO directory_listings(
                    workspace_id, proto, host_ip, username, data, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?)
            """, (wid, dl.proto, dl.host_ip, dl.username, dl.data, operator, now))

        # --- Vuln findings (collector_dc/hosts via nxc-vulns.db) ---
        # Tri-state is_vulnerable: 1=vulnerable, 0=checked-clean, NULL=could-not-check.
        # UPSERT priority 1 > 0 > NULL (vulnerable-wins; a real clean beats a failed check).
        # rank() ranks the tri-state; >= lets an equal-rank resync refresh details/timestamp
        # (latest-timestamp tiebreak), while a strictly-lower-rank result never downgrades.
        _RANK = "CASE WHEN {x}=1 THEN 2 WHEN {x}=0 THEN 1 ELSE 0 END"
        for vf in data.vuln_findings:
            cur.execute(f"""
                INSERT INTO vuln_findings(
                    workspace_id, ip, hostname, domain, protocol, port,
                    vuln_name, is_vulnerable, details, operator, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(workspace_id, ip, vuln_name) DO UPDATE SET
                    is_vulnerable = excluded.is_vulnerable,
                    details       = excluded.details,
                    hostname      = COALESCE(excluded.hostname, hostname),
                    domain        = COALESCE(excluded.domain,   domain),
                    protocol      = COALESCE(excluded.protocol, protocol),
                    port          = COALESCE(excluded.port,     port),
                    operator      = excluded.operator,
                    updated_at    = excluded.updated_at
                WHERE ({_RANK.format(x='excluded.is_vulnerable')})
                   >= ({_RANK.format(x='vuln_findings.is_vulnerable')})
            """, (wid, vf.ip, vf.hostname, vf.domain, vf.protocol, vf.port,
                  vf.vuln_name, vf.is_vulnerable, vf.details, operator, now))

        # --- Domain Admin Watchlist: post-sync enrichment ---
        # GUARD: READ-ONLY access to domain_admin_list here.
        # This table is an API-only table — managed exclusively via:
        #   POST /api/domain_admin_list/upload
        #   POST /api/domain_admin_list/clear_ghosts
        # Do NOT add INSERT / UPDATE / DELETE for domain_admin_list in sync.py.
        # Only credentials.admin_cred is written — domain_admin_list is the lookup source.
        #
        # Capture identities that this UPDATE will newly flip to admin (for notifications)
        # BEFORE running it — the predicate mirrors the UPDATE's WHERE exactly.
        new_das = notification_service.pending_domain_admins(cur, wid)
        # Single bulk-UPDATE; fast with idx_dal_ws(workspace_id, domain, username).
        # LOWER() matching handles NXC domain format differences (CORP vs corp.local).
        cur.execute("""
            UPDATE credentials SET admin_cred = 1
            WHERE workspace_id = ?
              AND admin_cred = 0
              AND admin_cred_locked = 0
              AND EXISTS (
                  SELECT 1 FROM domain_admin_list dal
                  WHERE dal.workspace_id = credentials.workspace_id
                    AND LOWER(dal.domain)   = LOWER(credentials.domain)
                    AND LOWER(dal.username) = LOWER(credentials.username)
              )
        """, (wid,))
        # --- Notifications: domain_admin (identities newly recognised as admins) ---
        notification_service.emit_domain_admins(cur, wid, new_das, now)

    # Auto-lookup new hashes in HK DB (idempotent — only fills NULL brutforced)
    background_tasks.add_task(hk_db.auto_lookup_workspace, wid)

    return {"ok": True, "workspace": body.workspace}


@router.post("/api/credentials/set_admin_cred", dependencies=[Depends(verify_token)])
def set_admin_cred(body: AdminCredBody):
    # Match by domain+username (case-insensitive) — covers hash+plaintext variants.
    # admin_cred_locked=1 when operator manually clears (=0) to prevent watchlist from restoring.
    # admin_cred_locked=0 when operator manually sets (=1) so watchlist can manage it again.
    locked = 1 if body.admin_cred == 0 else 0
    with db_cursor() as cur:
        cur.execute(
            "UPDATE credentials SET admin_cred=?, admin_cred_locked=? "
            "WHERE workspace_id=? AND LOWER(username)=LOWER(?)"
            " AND LOWER(COALESCE(domain,''))=LOWER(COALESCE(?,  ''))",
            (body.admin_cred, locked, body.workspace_id, body.username, body.domain),
        )
    return {"ok": True}


@router.post("/api/credentials/set_local_admin_cred", dependencies=[Depends(verify_token)])
def set_local_admin_cred(body: LocalAdminCredBody):
    # Match by username+password — domain is the machine name, irrelevant for local admin identity.
    # Silent skip: rows where domain appears ≥ 10 times in workspace (= real domain, not a machine).
    # Subquery computes domain counts inline — no separate round-trip needed.
    with db_cursor() as cur:
        cur.execute(
            "UPDATE credentials SET local_admin_cred=? "
            "WHERE workspace_id=? AND LOWER(username)=LOWER(?) AND password=? "
            "AND LOWER(COALESCE(domain,'')) IN ("
            "  SELECT LOWER(COALESCE(domain,'')) FROM credentials"
            "  WHERE workspace_id=?"
            "  GROUP BY LOWER(COALESCE(domain,''))"
            "  HAVING COUNT(*) < 10"
            ")",
            (body.local_admin_cred, body.workspace_id, body.username, body.password,
             body.workspace_id),
        )
    return {"ok": True}
