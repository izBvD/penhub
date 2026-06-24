"""
Notification journal emission (pwn3d + domain_admin).

Append-only. GUARD: this is the ONLY writer of the `notifications` table; it is
called from the post-processing of sync.py and dal.py. No user-facing API mutates
the journal. See docs/superpowers/specs/2026-06-16-notifications-design.md.
"""

_NOTIF_KEEP = 500  # per-workspace retention — newest N events are kept


def _record(cur, workspace_id, ntype, title, now,
            ref_host_id=None, ref_domain=None, ref_username=None):
    cur.execute(
        "INSERT INTO notifications"
        " (workspace_id, type, ref_host_id, ref_domain, ref_username, title, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (workspace_id, ntype, ref_host_id, ref_domain, ref_username, title, now),
    )


def _trim(cur, workspace_id):
    cur.execute(
        "DELETE FROM notifications WHERE workspace_id=? AND id NOT IN ("
        "  SELECT id FROM notifications WHERE workspace_id=? ORDER BY id DESC LIMIT ?)",
        (workspace_id, workspace_id, _NOTIF_KEEP),
    )


def emit_pwn3d(cur, workspace_id, max_ar_before, now):
    """One pwn3d event per host that gained its FIRST admin relation in this sync.

    A host qualifies if it has an admin relation with id > max_ar_before (new this
    sync) and NO admin relation with id <= max_ar_before (none existed before).
    """
    rows = cur.execute("""
        SELECT h.id AS host_id, h.ip, h.hostname, h.domain
        FROM hosts h
        WHERE h.workspace_id = ?
          AND EXISTS (
            SELECT 1 FROM auth_relations ar
            WHERE ar.host_id = h.id AND ar.workspace_id = h.workspace_id
              AND ar.relation_type = 'admin' AND ar.id > ?)
          AND NOT EXISTS (
            SELECT 1 FROM auth_relations ar2
            WHERE ar2.host_id = h.id AND ar2.workspace_id = h.workspace_id
              AND ar2.relation_type = 'admin' AND ar2.id <= ?)
    """, (workspace_id, max_ar_before, max_ar_before)).fetchall()
    for r in rows:
        if r["hostname"] and r["domain"]:
            title = f"{r['hostname']} ({r['domain']})"
        else:
            title = r["hostname"] or r["ip"] or f"host {r['host_id']}"
        _record(cur, workspace_id, "pwn3d", title, now, ref_host_id=r["host_id"])
    if rows:
        _trim(cur, workspace_id)


def pending_domain_admins(cur, workspace_id):
    """Identities (domain, username) about to become known admins via watchlist.

    MUST be called BEFORE the watchlist `UPDATE credentials SET admin_cred=1` and
    mirror that UPDATE's WHERE exactly (admin_cred=0 AND admin_cred_locked=0 AND
    watchlist match) plus "not already a known admin". GROUP BY collapses
    hash+plaintext and case variants of one identity into a single event.
    """
    return cur.execute("""
        SELECT MIN(COALESCE(domain,'')) AS domain, MIN(username) AS username
        FROM credentials
        WHERE workspace_id = ?
          AND admin_cred = 0
          AND admin_cred_locked = 0
          AND EXISTS (
            SELECT 1 FROM domain_admin_list dal
            WHERE dal.workspace_id = credentials.workspace_id
              AND LOWER(dal.domain)   = LOWER(credentials.domain)
              AND LOWER(dal.username) = LOWER(credentials.username))
          AND NOT EXISTS (
            SELECT 1 FROM credentials c2
            WHERE c2.workspace_id = credentials.workspace_id
              AND LOWER(COALESCE(c2.domain,'')) = LOWER(COALESCE(credentials.domain,''))
              AND LOWER(c2.username) = LOWER(credentials.username)
              AND c2.admin_cred = 1)
        GROUP BY LOWER(COALESCE(domain,'')), LOWER(username)
    """, (workspace_id,)).fetchall()


def emit_domain_admins(cur, workspace_id, identities, now):
    """Write one domain_admin event per identity returned by pending_domain_admins()."""
    for ident in identities:
        domain = ident["domain"] or ""
        username = ident["username"]
        title = f"{domain}\\{username}" if domain else username
        _record(cur, workspace_id, "domain_admin", title, now,
                ref_domain=domain, ref_username=username)
    if identities:
        _trim(cur, workspace_id)
