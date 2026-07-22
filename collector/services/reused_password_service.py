"""REUSED PASSWORDS (Reports module) — find every secret used in >= min_count places.

Groups accounts (credentials + custom) and DPAPI entries by their *effective secret*:
plaintext for plaintext creds and cracked hashes (via `brutforced`), the NT hash for
uncracked hashes. Reveals all logins/URLs that share one password. Read-only.
"""

EMPTY = "<empty_password>"
_GUEST = {"guest", "гость", "defaultaccount", "wdagutilityaccount"}


def _blank(s):
    """Empty, whitespace-only, or the <empty_password> sentinel."""
    return not s or not s.strip() or s == EMPTY


def _effective(password, credtype, brutforced):
    """Return (secret, type) or (None, None) for empty/whitespace/sentinel."""
    if (credtype or "").lower() == "hash":
        if not _blank(brutforced):
            return brutforced, "plaintext"          # cracked → unify with its plaintext twin
        if not _blank(password):
            return password, "hash"                 # uncracked → the NT hash itself
        return None, None
    if not _blank(password):
        return password, "plaintext"
    return None, None


def _acct(domain, login):
    d = (domain or "").strip()
    l = (login or "").strip()
    if d and l:
        return f"{d}\\{l}"
    if l:
        return l
    if d:
        return f"{d}\\"
    return "(no login)"


def _dpapi_entry(url, login):
    u = (url or "").strip()
    l = (login or "").strip()
    if u and l:
        return f"{u};{l}"
    return u or l or "(dpapi)"


def find_reused_passwords(cur, workspace_id, min_count=2):
    groups = {}

    def _g(secret, typ):
        g = groups.get(secret)
        if g is None:
            g = groups[secret] = {"secret": secret, "type": typ,
                                  "accounts": set(), "dpapi": set()}
        return g

    # credentials (LSA+SAM + all protocols) → accounts
    for r in cur.execute(
        "SELECT domain, username AS login, password, credtype, brutforced FROM credentials "
        "WHERE workspace_id=? AND hidden=0 AND hidden_by_strike=0", (workspace_id,)).fetchall():
        secret, typ = _effective(r["password"], r["credtype"], r["brutforced"])
        if not secret:
            continue
        login = r["login"] or ""
        if login.casefold() in _GUEST:
            continue
        _g(secret, typ)["accounts"].add(_acct(r["domain"], login))

    # custom credentials (may have no login/domain) → accounts
    for r in cur.execute(
        "SELECT domain, login, password, credtype, brutforced FROM custom_credentials "
        "WHERE workspace_id=?", (workspace_id,)).fetchall():
        secret, typ = _effective(r["password"], r["credtype"], r["brutforced"])
        if not secret:
            continue
        login = r["login"] or ""
        if login and login.casefold() in _GUEST:
            continue
        _g(secret, typ)["accounts"].add(_acct(r["domain"], login))

    # DPAPI (plaintext) — joins the group whose secret == its password
    for r in cur.execute(
        "SELECT username AS login, url, password FROM dpapi_secrets "
        "WHERE workspace_id=? AND hidden=0", (workspace_id,)).fetchall():
        pw = r["password"]
        if _blank(pw):
            continue
        _g(pw, "plaintext")["dpapi"].add(_dpapi_entry(r["url"], r["login"]))

    out = []
    for g in groups.values():
        count = len(g["accounts"]) + len(g["dpapi"])
        if count < min_count:
            continue
        out.append({
            "secret": g["secret"], "type": g["type"],
            "accounts": sorted(g["accounts"]), "dpapi": sorted(g["dpapi"]),
            "count": count,
        })
    out.sort(key=lambda x: (-x["count"], x["secret"]))
    return out
