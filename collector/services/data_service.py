"""
Result deduplication and brutforced-replacement helpers.
These are pure functions with no side effects.
"""


def dedup_results(rows: list) -> list:
    """
    Per-(domain, user, password, host ip): keep the row with highest priority (TZ key).
    Host-aware so auth-relation views keep one row per credential x host; duplicates
    from different protocols / operators on the SAME host collapse (proto & operator
    are not part of the key). Rows without a host (ip empty) dedup by the triple.
    Priority: plaintext+admin > plaintext > hash+admin > hash; SMB preferred; more fields.
    admin_cred=1 is propagated from any duplicate to the winner.
    Mirrors frontend deduplicateRows().
    """
    _proto_rank = {"SMB": 2, "LDAP": 1}

    def rank(r):
        return (
            (4 if r.get("credtype") == "plaintext" else 0)
            + (2 if r.get("relation_type") == "admin" else 0)
            + (1 if r.get("ip") else 0)
            + _proto_rank.get((r.get("proto") or "").upper(), 0)
        )

    best: dict = {}
    acred_keys: set = set()
    for r in rows:
        k = (
            f"{(r.get('cred_domain') or '').lower()}"
            f"|{(r.get('username') or '').lower()}"
            f"|{r.get('password') or ''}"
            f"|{r.get('ip') or ''}"
        )
        if r.get("admin_cred") == 1:
            acred_keys.add(k)
        if k not in best or rank(r) > rank(best[k]):
            best[k] = r
    result = []
    for k, r in best.items():
        if k in acred_keys:
            r = dict(r)
            r["admin_cred"] = 1
        result.append(r)
    return result


def smart_dedup_creds(rows: list) -> list:
    """
    Smart dedup for credential export.
    Each row must have: proto, domain, username, password, credtype.
    Optional: _host_ip (for per-host plaintext-over-hash preference).

    Step 1 — per-host: if (host, domain, user) has BOTH hash and plain → keep plain.
    Step 2 — cross-host: if (domain, user) has plain on ANY host → replace hash rows with it.
    Step 3 — final dedup by (proto, domain, username, password).
    """
    # Build map of known plaintext passwords per (domain_lower, user_lower)
    plaintext_map: dict = {}
    for r in rows:
        if r.get("credtype") == "plaintext" and r.get("username"):
            key = ((r.get("domain") or "").lower(), r["username"].lower())
            if key not in plaintext_map:
                plaintext_map[key] = r["password"]

    # Per-host dedup: prefer plaintext over hash for same (host, domain, user)
    per_host: dict = {}
    for r in rows:
        host = r.get("_host_ip") or r.get("host_ip") or ""
        key = (host, (r.get("domain") or "").lower(), (r.get("username") or "").lower())
        ex = per_host.get(key)
        if ex is None:
            per_host[key] = r
        elif r["credtype"] == "plaintext" and ex["credtype"] == "hash":
            per_host[key] = r

    # Cross-host: replace remaining hash rows with known plaintext
    processed = []
    for r in per_host.values():
        row = dict(r)
        if row.get("credtype") == "hash":
            pkey = ((row.get("domain") or "").lower(), (row.get("username") or "").lower())
            if pkey in plaintext_map:
                row["password"] = plaintext_map[pkey]
                row["credtype"] = "plaintext"
        processed.append(row)

    # Final dedup by (domain, username, password) — SMB preferred over other protos
    _proto_rank = {"SMB": 2, "LDAP": 1}
    seen: dict = {}
    for r in processed:
        out_key = (
            (r.get("domain") or "").lower(),
            (r.get("username") or "").lower(),
            (r.get("password") or ""),
        )
        ex = seen.get(out_key)
        if ex is None or _proto_rank.get((r.get("proto") or "").upper(), 0) > _proto_rank.get((ex.get("proto") or "").upper(), 0):
            seen[out_key] = r
    return list(seen.values())


def apply_brutforced(rows: list) -> list:
    """Replace hash password with brutforced plaintext when available."""
    result = []
    for r in rows:
        if r.get("brutforced") and r.get("credtype") == "hash":
            r = dict(r)
            r["password"] = r["brutforced"]
            r["credtype"] = "plaintext"
        result.append(r)
    return result
