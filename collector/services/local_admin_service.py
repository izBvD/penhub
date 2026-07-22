"""LOCAL ADMIN FOUNDER — auto-detect local admin accounts (Reports module).

Local vs domain is decided by an auto-derived AD-domain set; local accounts carry
the machine hostname in credentials.domain. Three confidence tiers:
  operator (local_admin_cred=1) > admin (proven SMB admin relation) > reuse (secret
  shared across >= min_hosts machines). See spec 2026-07-21-local-admin-founder-design.
"""

from collector.core.constants import _GUEST_NAMES_SQL

_TIER_RANK = {"operator": 0, "admin": 1, "reuse": 2}


def _ad_domains(cur, wid):
    """AD domains = values on >=2 distinct hosts, or the domain of any DC host."""
    ad = set()
    for r in cur.execute(
        "SELECT LOWER(domain) AS d, COUNT(DISTINCT ip) AS n, "
        "MAX(CASE WHEN dc=1 THEN 1 ELSE 0 END) AS has_dc "
        "FROM hosts WHERE workspace_id=? AND domain IS NOT NULL AND domain<>'' "
        "GROUP BY LOWER(domain)", (wid,)
    ):
        if r["n"] >= 2 or r["has_dc"] == 1:
            ad.add(r["d"])
    return ad


def find_local_admins(cur, workspace_id, min_hosts=2):
    ad = _ad_domains(cur, workspace_id)
    rows = cur.execute(f"""
        SELECT c.id, c.domain, c.username, c.password, c.credtype, c.brutforced,
               c.local_admin_cred, c.pillaged_from_ip,
               EXISTS(SELECT 1 FROM auth_relations ar
                      WHERE ar.credential_id=c.id AND ar.relation_type='admin'
                        AND UPPER(ar.proto)='SMB') AS has_admin,
               (SELECT MAX(dc) FROM hosts h WHERE h.workspace_id=c.workspace_id
                        AND h.ip=c.pillaged_from_ip) AS src_dc
        FROM credentials c
        WHERE c.workspace_id=? AND UPPER(c.proto)='SMB'
          AND c.hidden=0 AND c.hidden_by_strike=0
          AND c.password<>'' AND c.password<>'<empty_password>'
          AND LOWER(c.username) NOT IN {_GUEST_NAMES_SQL}
    """, (workspace_id,)).fetchall()
    # NB: no pillaged/admin gate — LSA+SAM creds frequently lack pillaged_from_ip
    # (nxc didn't tag the source host) and have no auth_relation, yet are still local
    # reuse candidates. Local-vs-domain classification + the tier rules below decide
    # inclusion; machine count comes from distinct local `domain` (hostname) values.

    groups = {}
    for r in rows:
        dom = (r["domain"] or "").strip()
        is_local = dom.lower() not in ad
        from_dc = (r["src_dc"] == 1)
        key = (r["username"].lower(), r["password"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"username": r["username"], "secret": r["password"],
                               "credtype": r["credtype"], "brutforced": None,
                               "machines": set(), "operator": False, "admin": False}
        if r["brutforced"]:
            g["brutforced"] = r["brutforced"]
        if is_local and not from_dc:
            if dom:
                g["machines"].add(dom)
            if r["local_admin_cred"] == 1:
                g["operator"] = True
            if r["has_admin"]:
                g["admin"] = True

    out = []
    for g in groups.values():
        mc = len(g["machines"])
        if g["operator"]:
            tier = "operator"
        elif g["admin"] and mc >= 1:
            tier = "admin"
        elif mc >= min_hosts:
            tier = "reuse"
        else:
            continue
        out.append({
            "username": g["username"], "secret": g["secret"], "credtype": g["credtype"],
            "brutforced": g["brutforced"], "machine_count": mc,
            "machines": sorted(g["machines"]), "tier": tier,
            "domains": sorted(g["machines"]),
        })
    out.sort(key=lambda x: (_TIER_RANK[x["tier"]], -x["machine_count"], x["username"].lower()))
    return out
