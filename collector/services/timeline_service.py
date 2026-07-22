"""Timeline (Reports module) — canonical milestone resolution + elapsed formatting.

Canonical values are computed on read from the best available signal
(notifications journal + heuristics); operator overrides and custom nodes are
persisted in timeline_nodes. See docs/superpowers/specs/2026-07-21-timeline-design.md.
"""

from datetime import datetime, timezone

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

# Fixed canonical order (used for the pending list).
CANON = [
    ("first_sync",    "First sync"),
    ("first_account", "First captured account"),
    ("first_pwned",   "First PWNED"),
    ("first_da",      "First Domain Admin"),
]
_CANON_LABEL = dict(CANON)

_GUEST = ("guest", "гость", "defaultaccount", "wdagutilityaccount")


def fmt_elapsed(seconds: int) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    hms = f"{h:02d}:{m:02d}:{s:02d}"
    if days == 0:
        return hms
    return f"{days} {'day' if days == 1 else 'days'} {hms}"


def _epoch(ts: str) -> int:
    """Parse a stored UTC ISO ('...Z' or '+00:00') to epoch seconds."""
    if not ts:
        return 0
    t = ts.strip().replace("Z", "+00:00")
    return int(datetime.fromisoformat(t).replace(tzinfo=timezone.utc).timestamp())


def _cfg(cur, wid, key):
    r = cur.execute("SELECT value FROM workspace_config WHERE workspace_id=? AND key=?",
                    (wid, key)).fetchone()
    return r["value"] if r else None


def _override(cur, wid, kind):
    return cur.execute(
        "SELECT id,label,ts,detail FROM timeline_nodes WHERE workspace_id=? AND kind=?",
        (wid, kind)).fetchone()


def _host_title(cur, host_id):
    if not host_id:
        return ""
    h = cur.execute("SELECT hostname, domain, ip FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not h:
        return ""
    if h["hostname"] and h["domain"]:
        return f"{h['hostname']} ({h['domain']})"
    return h["hostname"] or h["ip"] or ""


def _secret(password, brutforced):
    """Display secret: cracked plaintext (brutforced) preferred, else the stored value
    (plaintext or hash). Empty / <empty_password> → no secret."""
    s = brutforced or password or ""
    return "" if s == "<empty_password>" else s


def _fmt_acct(domain, username, password, brutforced):
    """`DOMAIN\\user:secret` (plaintext if available, else hash); `:secret` omitted if none."""
    dom = (domain or "").strip()
    acct = f"{dom}\\{username}" if dom else (username or "")
    s = _secret(password, brutforced)
    return f"{acct}:{s}" if (acct and s) else acct


def _secret_for(cur, wid, domain, username):
    """Best secret for a (domain, username): brutforced > plaintext > hash."""
    r = cur.execute("""
        SELECT password, brutforced FROM credentials
        WHERE workspace_id=? AND LOWER(username)=LOWER(?)
          AND LOWER(COALESCE(domain,''))=LOWER(COALESCE(?,''))
          AND password<>'' AND password<>'<empty_password>'
        ORDER BY (CASE WHEN brutforced IS NOT NULL AND brutforced<>'' THEN 0
                       WHEN credtype='plaintext' THEN 1 ELSE 2 END), id ASC
        LIMIT 1
    """, (wid, username, domain or "")).fetchone()
    return _secret(r["password"], r["brutforced"]) if r else ""


def _first_admin_cred(cur, wid, host_id):
    """`DOMAIN\\user:secret` of the credential that first gained admin on this host."""
    if not host_id:
        return ""
    r = cur.execute("""
        SELECT c.domain, c.username, c.password, c.brutforced FROM auth_relations ar
        JOIN credentials c ON c.id = ar.credential_id
        WHERE ar.workspace_id=? AND ar.host_id=? AND ar.relation_type='admin'
        ORDER BY ar.id ASC LIMIT 1
    """, (wid, host_id)).fetchone()
    if not r or not r["username"]:
        return ""
    return _fmt_acct(r["domain"], r["username"], r["password"], r["brutforced"])


def _pwned_detail(cur, wid, host_title, host_id):
    """Combine the pwned host with the credential used: 'HOST · DOMAIN\\user'."""
    cred = _first_admin_cred(cur, wid, host_id)
    if host_title and cred:
        return f"{host_title} · {cred}"
    return cred or host_title


def _auto(cur, wid, kind):
    """Return (ts, detail) for a canonical kind, or None if no signal."""
    if kind == "first_sync":
        ts = _cfg(cur, wid, "timeline_first_sync")
        return (ts, _cfg(cur, wid, "timeline_first_sync_op") or "") if ts else None
    if kind == "first_account":
        placeholders = ",".join("?" * len(_GUEST))
        r = cur.execute(f"""
            SELECT domain, username, password, brutforced, updated_at FROM credentials
            WHERE workspace_id=? AND hidden=0 AND hidden_by_strike=0
              AND ((credtype='hash') OR (password <> '' AND password <> '<empty_password>'))
              AND LOWER(username) NOT IN ({placeholders})
              AND updated_at IS NOT NULL
            ORDER BY updated_at ASC LIMIT 1
        """, (wid, *_GUEST)).fetchone()
        if not r:
            return None
        return (r["updated_at"], _fmt_acct(r["domain"], r["username"], r["password"], r["brutforced"]))
    if kind == "first_pwned":
        r = cur.execute("SELECT ref_host_id, title, created_at FROM notifications"
                        " WHERE workspace_id=? AND type='pwn3d'"
                        " ORDER BY created_at ASC LIMIT 1", (wid,)).fetchone()
        if r:
            return (r["created_at"], _pwned_detail(cur, wid, r["title"] or "", r["ref_host_id"]))
        # fallback (approximate): the earliest admin relation carries the host + cred
        r = cur.execute("SELECT host_id, MIN(updated_at) AS ts FROM auth_relations"
                        " WHERE workspace_id=? AND relation_type='admin' AND updated_at IS NOT NULL",
                        (wid,)).fetchone()
        if not (r and r["ts"]):
            return None
        return (r["ts"], _pwned_detail(cur, wid, _host_title(cur, r["host_id"]), r["host_id"]))
    if kind == "first_da":
        r = cur.execute("SELECT ref_domain, ref_username, title, created_at FROM notifications"
                        " WHERE workspace_id=? AND type='domain_admin'"
                        " ORDER BY created_at ASC LIMIT 1", (wid,)).fetchone()
        if r:
            acct = r["title"] or ""
            s = _secret_for(cur, wid, r["ref_domain"], r["ref_username"])
            return (r["created_at"], f"{acct}:{s}" if (acct and s) else acct)
        r = cur.execute("SELECT domain, username, password, brutforced, MIN(updated_at) AS ts"
                        " FROM credentials"
                        " WHERE workspace_id=? AND admin_cred=1 AND updated_at IS NOT NULL",
                        (wid,)).fetchone()
        if not (r and r["ts"]):
            return None
        return (r["ts"], _fmt_acct(r["domain"], r["username"], r["password"], r["brutforced"]))
    return None


def build_timeline(cur, workspace_id):
    active, pending = [], []
    for kind, default_label in CANON:
        ov = _override(cur, workspace_id, kind)
        if ov is not None:
            active.append({"kind": kind, "label": ov["label"] or default_label,
                           "ts": ov["ts"], "detail": ov["detail"] or "", "is_override": True})
            continue
        auto = _auto(cur, workspace_id, kind)
        if auto and auto[0]:
            active.append({"kind": kind, "label": default_label,
                           "ts": auto[0], "detail": auto[1] or "", "is_override": False})
        else:
            pending.append(default_label)

    for r in cur.execute("SELECT id,label,ts,detail FROM timeline_nodes"
                         " WHERE workspace_id=? AND kind='custom'", (workspace_id,)).fetchall():
        if r["ts"]:
            active.append({"kind": "custom", "id": r["id"], "label": r["label"] or "",
                           "ts": r["ts"], "detail": r["detail"] or "", "is_override": False})

    active.sort(key=lambda n: _epoch(n["ts"]))
    for i, n in enumerate(active):
        n["elapsed_str"] = "" if i == 0 else fmt_elapsed(_epoch(n["ts"]) - _epoch(active[i - 1]["ts"]))

    total_str = ""
    if len(active) >= 2:
        total_str = fmt_elapsed(_epoch(active[-1]["ts"]) - _epoch(active[0]["ts"]))
    return {"nodes": active, "pending": pending, "total_str": total_str}
