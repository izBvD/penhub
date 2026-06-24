#!/usr/bin/env python3
"""
nxc_updater — читает nxc workspace SQLite БД и отправляет данные на коллектор.

Предназначен для запуска из cron каждые 10 минут. Запускается при каждом вызове.

Зависимости: только stdlib.
"""

import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from configparser import ConfigParser
from pathlib import Path

CONF_FILE  = Path.home() / ".nxc-collector.conf"
NXC_WS_DIR = Path.home() / ".nxc" / "workspaces"

DB_TIMEOUT = 5  # секунды ожидания блокировки нxc БД

_LM_EMPTY       = "aad3b435b51404eeaad3b435b51404ee:"
_NT_EMPTY       = "31d6cfe0d16ae931b73c59d7e0c089c0"
_EMPTY_PASSWORD = "<empty_password>"

# ---------------------------------------------------------------------------
# Adaptive schema mapping
# nxc_schema.json maps internal field names to actual nxc column names.
# If nxc renames a column, update nxc_schema.json only — no code changes.
# ---------------------------------------------------------------------------

_SCHEMA_FILE = Path(__file__).parent / "nxc_schema.json"
try:
    _NXC_SCHEMA: dict = json.loads(_SCHEMA_FILE.read_text(encoding="utf-8"))
except Exception:
    _NXC_SCHEMA = {}


def _col(row: dict, proto: str, table: str, key: str, default=None):
    """Resolve internal field key to actual column name via schema, then fetch from row."""
    col_name = _NXC_SCHEMA.get(proto, {}).get(table, {}).get(key, key)
    return row.get(col_name, default)


_VALID_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _table(proto: str, table: str) -> str:
    """Resolve internal table key to the actual nxc table name via the optional
    '__table__' entry in nxc_schema.json. Falls back to the internal key (stock nxc).
    A mapped name that isn't a plain SQL identifier is rejected (table names cannot be
    parameterized) and the internal key is used instead."""
    name = _NXC_SCHEMA.get(proto, {}).get(table, {}).get("__table__", table)
    if not _VALID_IDENT.match(name):
        _warn(f"[schema] {proto}.{table}: invalid __table__ {name!r} — using {table!r}")
        return table
    return name


# Identity/join columns whose silent absence means lost data. Optional fields
# (vuln flags, banner, …) are deliberately excluded to avoid false alarms on
# older nxc versions that simply don't have them. See operator-scripts.md.
_REQUIRED_COLS = {
    ("smb", "hosts"): ["ip"],
    ("smb", "users"): ["username", "password"],
    ("smb", "shares"): ["name"],
    ("smb", "conf_checks"): ["id", "name"],
    ("ldap", "hosts"): ["ip"],   ("ldap", "users"): ["username", "password"],
    ("winrm", "hosts"): ["ip"],  ("winrm", "users"): ["username", "password"],
    ("mssql", "hosts"): ["ip"],  ("mssql", "users"): ["username", "password"],
    ("ssh", "hosts"): ["host"],  ("ssh", "credentials"): ["username", "password"],
    ("ftp", "hosts"): ["host"],  ("ftp", "credentials"): ["username", "password"],
    ("nfs", "hosts"): ["ip"],    ("nfs", "credentials"): ["username", "password"],
    ("vnc", "hosts"): ["ip"],    ("vnc", "credentials"): ["username", "password"],
    ("wmi", "hosts"): ["ip"],    ("wmi", "credentials"): ["username", "password"],
    ("rdp", "hosts"): ["ip"],
}


def _audit_schema(proto: str, table: str, row_keys) -> None:
    """Warn once per table if a required, schema-mapped column is absent from the
    actual nxc table — an early signal that nxc renamed a column and nxc_schema.json
    is stale. Log-only: the sync continues with whatever columns resolved."""
    required = _REQUIRED_COLS.get((proto, table))
    if not required:
        return
    tmap = _NXC_SCHEMA.get(proto, {}).get(table, {})
    keys = set(row_keys)
    missing = [
        f"{internal}->{tmap.get(internal, internal)}"
        for internal in required
        if tmap.get(internal, internal) not in keys
    ]
    if missing:
        _warn(f"[schema] {proto}.{table}: missing column(s) {missing} "
              f"— update nxc_schema.json")


def _fetch_audited(conn, table: str, proto: str):
    """SELECT * FROM the schema-resolved nxc table, auditing the first row's columns
    against the required set. `table` is the internal key (resolved via _table)."""
    rows = conn.execute(f"SELECT * FROM {_table(proto, table)}").fetchall()
    if rows:
        _audit_schema(proto, table, dict(rows[0]).keys())
    return rows

def _normalize_password(password: str, credtype: str) -> tuple:
    """
    Normalize to canonical form (mirrors server-side sync_service.normalize_password):
    - Strip LM prefix from LM:NT hash pairs
    - Empty NT hash (31d6...) → _EMPTY_PASSWORD, plaintext
    - Empty plaintext password ("") → _EMPTY_PASSWORD, plaintext
    """
    p = password
    if p and p[:len(_LM_EMPTY)].lower() == _LM_EMPTY:
        p = p[len(_LM_EMPTY):]
    if credtype == "hash" and p.lower() == _NT_EMPTY:
        return _EMPTY_PASSWORD, "plaintext"
    if credtype == "plaintext" and p == "":
        return _EMPTY_PASSWORD, "plaintext"
    return p, credtype


# ---------------------------------------------------------------------------
# Config & state
# ---------------------------------------------------------------------------

def _local_db_path(ws_name: str) -> Path:
    """Per-workspace local collector DB: ~/.nxc/workspaces/<ws>/nxc-collector.db"""
    return NXC_WS_DIR / ws_name / "nxc-collector.db"


def load_config() -> dict:
    if not CONF_FILE.exists():
        _die(f"Config not found: {CONF_FILE}\nRun: nxc_collector --workspace-setup")
    cfg = ConfigParser()
    cfg.read(str(CONF_FILE))
    if "collector" not in cfg:
        _die(f"Missing [collector] section in {CONF_FILE}")
    c = cfg["collector"]
    server = c.get("server", "http://192.168.0.1").rstrip("/")
    if not server.startswith(("http://", "https://")):
        server = f"http://{server}"
    port   = c.get("port", "322").strip()
    # Append port if not already embedded in server URL
    import re as _re
    if port and not _re.search(r':\d+$', server):
        server = f"{server}:{port}"
    return {
        "server":    server,
        "password":  c.get("password",  "StrongPassword123"),
        "operator":  c.get("operator",  "Operator"),
        "workspace": c.get("workspace", "default"),
    }


def _die(msg: str):
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


def _warn(msg: str):
    print(f"[!] {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _open_db(path: Path) -> sqlite3.Connection | None:
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(str(path), timeout=DB_TIMEOUT)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError as e:
        _warn(f"Cannot open {path.name}: {e}")
        return None


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    r = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return bool(r)


# ---------------------------------------------------------------------------
# Protocol-specific readers
# ---------------------------------------------------------------------------

def _read_smb(db_path: Path) -> dict:
    conn = _open_db(db_path)
    if not conn:
        return {}

    out = {"hosts": [], "credentials": [], "auth_relations": [],
           "dpapi_secrets": [], "shares": [], "conf_checks_results": []}

    # hosts: build ip/hostname lookups
    host_id_to_ip: dict = {}
    host_id_to_hostname: dict = {}
    hostname_to_ip: dict = {}
    for h in _fetch_audited(conn, "hosts", "smb"):
        h = dict(h)
        ip = _col(h, "smb", "hosts", "ip") or ""
        if not ip:
            continue
        hid = h[_NXC_SCHEMA.get("smb", {}).get("hosts", {}).get("id", "id")]
        hn  = _col(h, "smb", "hosts", "hostname") or ""
        host_id_to_ip[hid] = ip
        host_id_to_hostname[hid] = hn
        if hn:
            hostname_to_ip[hn] = ip
        out["hosts"].append({
            "ip": ip, "hostname": hn,
            "domain": _col(h, "smb", "hosts", "domain"),
            "os":     _col(h, "smb", "hosts", "os"),
            "dc":     _col(h, "smb", "hosts", "dc"),
            "smbv1":  _col(h, "smb", "hosts", "smbv1"),
            "signing":     _col(h, "smb", "hosts", "signing"),
            "spooler":     _col(h, "smb", "hosts", "spooler"),
            "zerologon":   _col(h, "smb", "hosts", "zerologon"),
            "petitpotam":  _col(h, "smb", "hosts", "petitpotam"),
        })

    # users
    user_id_to_key: dict = {}
    for u in _fetch_audited(conn, "users", "smb"):
        u = dict(u)
        username = _col(u, "smb", "users", "username") or ""
        credtype = _col(u, "smb", "users", "credtype") or "plaintext"
        password, credtype = _normalize_password(_col(u, "smb", "users", "password") or "", credtype)
        if not username and not password:
            continue
        domain   = _col(u, "smb", "users", "domain") or ""
        pfh      = _col(u, "smb", "users", "pillaged_from_hostid")
        pfip     = host_id_to_ip.get(pfh) if pfh else None
        uid      = u[_NXC_SCHEMA.get("smb", {}).get("users", {}).get("id", "id")]
        key = ("SMB", domain, username, password, credtype)
        user_id_to_key[uid] = key
        out["credentials"].append({
            "proto": "SMB", "domain": domain, "username": username,
            "password": password, "credtype": credtype,
            "pillaged_from_ip": pfip,
        })

    # admin_relations
    if _table_exists(conn, _table("smb", "admin_relations")):
        for ar in _fetch_audited(conn, "admin_relations", "smb"):
            ar = dict(ar)
            key = user_id_to_key.get(_col(ar, "smb", "admin_relations", "userid"))
            hip = host_id_to_ip.get(_col(ar, "smb", "admin_relations", "hostid"))
            if key and hip:
                out["auth_relations"].append({
                    "proto": "SMB", "host_ip": hip, "relation_type": "admin",
                    "cred_domain": key[1], "cred_username": key[2],
                    "cred_password": key[3], "cred_credtype": key[4],
                })

    # loggedin_relations
    if _table_exists(conn, _table("smb", "loggedin_relations")):
        for lr in _fetch_audited(conn, "loggedin_relations", "smb"):
            lr = dict(lr)
            key = user_id_to_key.get(_col(lr, "smb", "loggedin_relations", "userid"))
            hip = host_id_to_ip.get(_col(lr, "smb", "loggedin_relations", "hostid"))
            if key and hip:
                out["auth_relations"].append({
                    "proto": "SMB", "host_ip": hip, "relation_type": "loggedin",
                    "cred_domain": key[1], "cred_username": key[2],
                    "cred_password": key[3], "cred_credtype": key[4],
                })

    # dpapi_secrets
    if _table_exists(conn, _table("smb", "dpapi_secrets")):
        for d in _fetch_audited(conn, "dpapi_secrets", "smb"):
            d = dict(d)
            out["dpapi_secrets"].append({
                "host_ip":     _col(d, "smb", "dpapi_secrets", "host"),
                "dpapi_type":  _col(d, "smb", "dpapi_secrets", "dpapi_type"),
                "windows_user": _col(d, "smb", "dpapi_secrets", "windows_user"),
                "username":    _col(d, "smb", "dpapi_secrets", "username"),
                "password":    _col(d, "smb", "dpapi_secrets", "password"),
                "url":         _col(d, "smb", "dpapi_secrets", "url"),
            })

    # shares (hostid may be hostname string in older nxc versions)
    if _table_exists(conn, _table("smb", "shares")):
        for s in _fetch_audited(conn, "shares", "smb"):
            s = dict(s)
            hostid  = _col(s, "smb", "shares", "hostid")
            host_ip = host_id_to_ip.get(hostid) or hostname_to_ip.get(str(hostid) if hostid else "")
            host_hn = host_id_to_hostname.get(hostid) or str(hostid or "")
            if not host_ip:
                continue
            userid = _col(s, "smb", "shares", "userid")
            key = user_id_to_key.get(userid)
            out["shares"].append({
                "host_ip": host_ip, "host_hostname": host_hn, "proto": "SMB",
                "cred_domain":   key[1] if key else None,
                "cred_username": key[2] if key else None,
                "cred_password": key[3] if key else None,
                "cred_credtype": key[4] if key else None,
                "name":   _col(s, "smb", "shares", "name"),
                "remark": _col(s, "smb", "shares", "remark"),
                "read":   _col(s, "smb", "shares", "read"),
                "write":  _col(s, "smb", "shares", "write"),
            })

    # conf_checks_results
    if _table_exists(conn, _table("smb", "conf_checks")) and _table_exists(conn, _table("smb", "conf_checks_results")):
        try:
            checks = {
                _col(row, "smb", "conf_checks", "id"): _col(row, "smb", "conf_checks", "name")
                for row in (dict(r) for r in _fetch_audited(conn, "conf_checks", "smb"))
            }
            for ccr in _fetch_audited(conn, "conf_checks_results", "smb"):
                ccr = dict(ccr)
                host_id = _col(ccr, "smb", "conf_checks_results", "host_id")
                check_id = _col(ccr, "smb", "conf_checks_results", "check_id")
                hip = host_id_to_ip.get(host_id)
                check_name = checks.get(check_id)
                if hip and check_name:
                    out["conf_checks_results"].append({
                        "host_ip":   hip,
                        "check_name": check_name,
                        "secure":    _col(ccr, "smb", "conf_checks_results", "secure"),
                        "reasons":   _col(ccr, "smb", "conf_checks_results", "reasons"),
                    })
        except Exception:
            pass

    conn.close()
    return out


def _read_users_proto(db_path: Path, proto: str) -> dict:
    """Generic reader for LDAP/WINRM/MSSQL — hosts + users + relations."""
    conn = _open_db(db_path)
    if not conn:
        return {}
    p = proto.lower()
    out = {"hosts": [], "credentials": [], "auth_relations": []}

    host_id_to_ip: dict = {}
    for h in _fetch_audited(conn, "hosts", p):
        h = dict(h)
        ip = _col(h, p, "hosts", "ip") or ""
        if not ip:
            continue
        hid = h[_NXC_SCHEMA.get(p, {}).get("hosts", {}).get("id", "id")]
        host_id_to_ip[hid] = ip
        entry = {
            "ip": ip,
            "hostname": _col(h, p, "hosts", "hostname"),
            "domain":   _col(h, p, "hosts", "domain"),
            "os":       _col(h, p, "hosts", "os"),
        }
        if proto == "LDAP":
            entry["signing_required"] = _col(h, p, "hosts", "signing_required")
            entry["channel_binding"]  = _col(h, p, "hosts", "channel_binding")
        if proto == "MSSQL":
            entry["instances"] = _col(h, p, "hosts", "instances")
        if proto == "WINRM":
            entry["port"] = _col(h, p, "hosts", "port")
        out["hosts"].append(entry)

    user_id_to_key: dict = {}
    if _table_exists(conn, _table(p, "users")):
        for u in _fetch_audited(conn, "users", p):
            u = dict(u)
            username = _col(u, p, "users", "username") or ""
            credtype = _col(u, p, "users", "credtype") or "plaintext"
            password, credtype = _normalize_password(_col(u, p, "users", "password") or "", credtype)
            if not username and not password:
                continue
            domain   = _col(u, p, "users", "domain") or ""
            uid      = u[_NXC_SCHEMA.get(p, {}).get("users", {}).get("id", "id")]
            key = (proto, domain, username, password, credtype)
            user_id_to_key[uid] = key
            out["credentials"].append({
                "proto": proto, "domain": domain, "username": username,
                "password": password, "credtype": credtype,
            })

    for tbl, rtype in [("admin_relations", "admin"), ("loggedin_relations", "loggedin")]:
        if _table_exists(conn, _table(p, tbl)):
            for r in _fetch_audited(conn, tbl, p):
                r = dict(r)
                key  = user_id_to_key.get(_col(r, p, tbl, "userid"))
                hip  = host_id_to_ip.get(_col(r, p, tbl, "hostid"))
                if key and hip:
                    out["auth_relations"].append({
                        "proto": proto, "host_ip": hip, "relation_type": rtype,
                        "cred_domain": key[1], "cred_username": key[2],
                        "cred_password": key[3], "cred_credtype": key[4],
                    })

    conn.close()
    return out


def _read_creds_proto(db_path: Path, proto: str) -> dict:
    """Generic reader for FTP/NFS/WMI/VNC — hosts + credentials + protocol-specific data."""
    conn = _open_db(db_path)
    if not conn:
        return {}
    p = proto.lower()
    out = {"hosts": [], "credentials": [], "auth_relations": [], "directory_listings": []}

    host_id_to_ip: dict = {}
    for h in _fetch_audited(conn, "hosts", p):
        h = dict(h)
        ip = _col(h, p, "hosts", "ip") or _col(h, p, "hosts", "host") or h.get("ip") or h.get("host") or ""
        if not ip:
            continue
        hid = h[_NXC_SCHEMA.get(p, {}).get("hosts", {}).get("id", "id")]
        host_id_to_ip[hid] = ip
        out["hosts"].append({
            "ip": ip,
            "hostname": _col(h, p, "hosts", "hostname"),
            "port":     _col(h, p, "hosts", "port"),
            "banner":   _col(h, p, "hosts", "banner") or _col(h, p, "hosts", "server_banner") or h.get("server_banner"),
        })

    cred_id_to_key: dict = {}
    lir_id_to_cred_host: dict = {}  # for FTP/NFS: lir_id → (host_ip, username)
    if _table_exists(conn, _table(p, "credentials")):
        for c in _fetch_audited(conn, "credentials", p):
            c = dict(c)
            username = _col(c, p, "credentials", "username") or ""
            credtype = _col(c, p, "credentials", "credtype") or "plaintext"
            password, credtype = _normalize_password(_col(c, p, "credentials", "password") or "", credtype)
            if not username and not password:
                continue
            cid = c[_NXC_SCHEMA.get(p, {}).get("credentials", {}).get("id", "id")]
            pkey = _col(c, p, "credentials", "pkey")  # VNC only
            key = (proto, "", username, password, credtype)
            cred_id_to_key[cid] = key
            entry = {
                "proto": proto, "domain": "", "username": username,
                "password": password, "credtype": credtype,
            }
            if pkey:
                entry["pkey"] = pkey
            out["credentials"].append(entry)

    for tbl, rtype in [("admin_relations", "admin"), ("loggedin_relations", "loggedin")]:
        if _table_exists(conn, _table(p, tbl)):
            try:
                for r in _fetch_audited(conn, tbl, p):
                    r = dict(r)
                    cid = _col(r, p, tbl, "credid") or r.get("cred_id")
                    hid = _col(r, p, tbl, "hostid") or r.get("host_id")
                    key = cred_id_to_key.get(cid)
                    hip = host_id_to_ip.get(hid)
                    if key and hip:
                        out["auth_relations"].append({
                            "proto": proto, "host_ip": hip, "relation_type": rtype,
                            "cred_domain": key[1], "cred_username": key[2],
                            "cred_password": key[3], "cred_credtype": key[4],
                        })
                    # Track lir_id → (host_ip, username) for dir/share listings
                    if rtype == "loggedin" and hip:
                        lir_id = r.get("id")
                        uname = key[2] if key else ""
                        if lir_id is not None:
                            lir_id_to_cred_host[lir_id] = (hip, uname)
            except Exception:
                pass

    # FTP: directory_listings
    if proto == "FTP" and _table_exists(conn, _table(p, "directory_listings")):
        try:
            for dl in _fetch_audited(conn, "directory_listings", p):
                dl = dict(dl)
                lir_id = _col(dl, p, "directory_listings", "lir_id")
                ch = lir_id_to_cred_host.get(lir_id)
                if ch:
                    out["directory_listings"].append({
                        "proto": "FTP",
                        "host_ip":  ch[0],
                        "username": ch[1],
                        "data":     _col(dl, p, "directory_listings", "data"),
                    })
        except Exception:
            pass

    # NFS: shares (text data, different from SMB shares)
    if proto == "NFS" and _table_exists(conn, _table(p, "shares")):
        try:
            for sh in _fetch_audited(conn, "shares", p):
                sh = dict(sh)
                lir_id = _col(sh, p, "shares", "lir_id")
                ch = lir_id_to_cred_host.get(lir_id)
                if ch:
                    out["directory_listings"].append({
                        "proto": "NFS",
                        "host_ip":  ch[0],
                        "username": ch[1],
                        "data":     _col(sh, p, "shares", "data"),
                    })
        except Exception:
            pass

    conn.close()
    return out


def _read_rdp(db_path: Path) -> dict:
    conn = _open_db(db_path)
    if not conn:
        return {}
    out = {"hosts": []}
    for h in _fetch_audited(conn, "hosts", "rdp"):
        h = dict(h)
        ip = _col(h, "rdp", "hosts", "ip") or ""
        if not ip:
            continue
        out["hosts"].append({
            "ip": ip,
            "hostname": _col(h, "rdp", "hosts", "hostname"),
            "domain":   _col(h, "rdp", "hosts", "domain"),
            "os":       _col(h, "rdp", "hosts", "os"),
            "nla":      _col(h, "rdp", "hosts", "nla"),
            "port":     _col(h, "rdp", "hosts", "port"),
        })
    conn.close()
    return out


def _read_ssh(db_path: Path) -> dict:
    conn = _open_db(db_path)
    if not conn:
        return {}
    out = {"hosts": [], "credentials": [], "auth_relations": [], "ssh_keys": []}

    host_id_to_ip: dict = {}
    for h in _fetch_audited(conn, "hosts", "ssh"):
        h = dict(h)
        ip = _col(h, "ssh", "hosts", "host") or ""
        if not ip:
            continue
        hid = h[_NXC_SCHEMA.get("ssh", {}).get("hosts", {}).get("id", "id")]
        host_id_to_ip[hid] = ip
        out["hosts"].append({
            "ip":     ip,
            "port":   _col(h, "ssh", "hosts", "port"),
            "banner": _col(h, "ssh", "hosts", "banner"),
            "os":     _col(h, "ssh", "hosts", "os"),
        })

    cred_id_to_key: dict = {}
    if _table_exists(conn, _table("ssh", "credentials")):
        for c in _fetch_audited(conn, "credentials", "ssh"):
            c = dict(c)
            username = _col(c, "ssh", "credentials", "username") or ""
            credtype = _col(c, "ssh", "credentials", "credtype") or "plaintext"
            password, credtype = _normalize_password(_col(c, "ssh", "credentials", "password") or "", credtype)
            if not username and not password:
                continue
            cid = c[_NXC_SCHEMA.get("ssh", {}).get("credentials", {}).get("id", "id")]
            key = ("SSH", "", username, password, credtype)
            cred_id_to_key[cid] = key
            out["credentials"].append({
                "proto": "SSH", "domain": "", "username": username,
                "password": password, "credtype": credtype,
            })

    if _table_exists(conn, _table("ssh", "keys")):
        for k in _fetch_audited(conn, "keys", "ssh"):
            k = dict(k)
            key = cred_id_to_key.get(_col(k, "ssh", "keys", "credid"))
            if key:
                out["ssh_keys"].append({
                    "cred_domain": key[1], "cred_username": key[2],
                    "cred_password": key[3], "cred_credtype": key[4],
                    "key_data": _col(k, "ssh", "keys", "data"),
                })

    for tbl, rtype in [("admin_relations", "admin"), ("loggedin_relations", "loggedin")]:
        if _table_exists(conn, _table("ssh", tbl)):
            for r in _fetch_audited(conn, tbl, "ssh"):
                r = dict(r)
                key = cred_id_to_key.get(_col(r, "ssh", tbl, "credid"))
                hip = host_id_to_ip.get(_col(r, "ssh", tbl, "hostid"))
                if key and hip:
                    ar = {
                        "proto": "SSH", "host_ip": hip, "relation_type": rtype,
                        "cred_domain": key[1], "cred_username": key[2],
                        "cred_password": key[3], "cred_credtype": key[4],
                    }
                    if rtype == "loggedin":
                        ar["shell"] = _col(r, "ssh", "loggedin_relations", "shell")
                    out["auth_relations"].append(ar)

    conn.close()
    return out


# ---------------------------------------------------------------------------
# Build full sync payload
# ---------------------------------------------------------------------------

PROTO_READERS = {
    "smb":   lambda p: _read_smb(p),
    "ldap":  lambda p: _read_users_proto(p, "LDAP"),
    "winrm": lambda p: _read_users_proto(p, "WINRM"),
    "mssql": lambda p: _read_users_proto(p, "MSSQL"),
    "ssh":   lambda p: _read_ssh(p),
    "ftp":   lambda p: _read_creds_proto(p, "FTP"),
    "nfs":   lambda p: _read_creds_proto(p, "NFS"),
    "vnc":   lambda p: _read_creds_proto(p, "VNC"),
    "wmi":   lambda p: _read_creds_proto(p, "WMI"),
    "rdp":   lambda p: _read_rdp(p),
}


# ---------------------------------------------------------------------------
# Vuln findings reader (collector_dc / collector_hosts → nxc-vulns.db)
# ---------------------------------------------------------------------------

# Map the modules' human-readable vuln_name (with CVE text) to a stable slug.
# The slug is the key everywhere server-side (VULN_COLUMNS); CVE display text may
# change, the slug must not. Unknown names fall back to a generic slugify.
_VULN_SLUG = {
    "Zerologon (CVE-2020-1472)":        "zerologon",
    "noPac (CVE-2021-42278/42287)":     "nopac",
    "SMBGhost (CVE-2020-0796)":         "smbghost",
    "MS17-010 EternalBlue":             "ms17_010",
    "PrintNightmare (CVE-2021-1675)":   "printnightmare",
    "WebDAV":                           "webdav",
    "Coerce/PetitPotam":                "petitpotam",
    "Coerce/PrinterBug":                "printerbug",
    "Coerce/DFSCoerce":                 "dfscoerce",
    "Coerce/ShadowCoerce":              "shadowcoerce",
    "WDigest":                          "wdigest",
    "NTLMv1":                           "ntlmv1",
    "RunAsPPL":                         "runasppl",
    "UAC":                              "uac",
}


def _vuln_slug(name: str) -> str:
    if name in _VULN_SLUG:
        return _VULN_SLUG[name]
    # Fallback: lowercase, strip CVE/pipe noise, collapse to [a-z0-9_]
    base = name.split("(")[0].split("/")[-1].strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", base).strip("_") or "unknown"


def _vuln_rank(v) -> int:
    """Tri-state rank: vulnerable(1) > checked-clean(0) > could-not-check(None)."""
    if v == 1:
        return 2
    if v == 0:
        return 1
    return 0


def _read_collector_vulns(ws_dir: Path) -> dict:
    """Read nxc-vulns.db/collector_vulns, normalize vuln_name→slug, dedup per (ip, slug)
    with tri-state priority (1>0>None) and latest-timestamp tiebreak. Push-only."""
    conn = _open_db(ws_dir / "nxc-vulns.db")
    if not conn:
        return {}
    if not _table_exists(conn, "collector_vulns"):
        return {}

    best: dict = {}  # (ip, slug) → row dict
    for r in conn.execute("SELECT * FROM collector_vulns").fetchall():
        r = dict(r)
        ip = r.get("ip") or ""
        if not ip:
            continue
        slug = _vuln_slug(r.get("vuln_name") or "")
        iv = r.get("is_vulnerable")  # int or None (NULL)
        ts = r.get("timestamp") or ""
        key = (ip, slug)
        cur = best.get(key)
        if cur is not None:
            crank, cts = _vuln_rank(cur["is_vulnerable"]), cur["_ts"]
            if (_vuln_rank(iv), ts) <= (crank, cts):
                continue  # existing wins (higher rank, or same rank & not newer)
        best[key] = {
            "ip": ip,
            "hostname": r.get("hostname"),
            "domain": r.get("domain"),
            "protocol": r.get("protocol"),
            "port": r.get("port"),
            "vuln_name": slug,
            "is_vulnerable": iv,
            "details": r.get("details"),
            "_ts": ts,
        }

    findings = [{k: v for k, v in row.items() if k != "_ts"} for row in best.values()]
    return {"vuln_findings": findings}


def build_payload(config: dict) -> dict:
    ws_dir = NXC_WS_DIR / config["workspace"]
    if not ws_dir.exists():
        _die(f"Workspace directory not found: {ws_dir}\nCreate it with: nxcdb -cw {config['workspace']}")

    merged: dict = {
        "hosts": [], "credentials": [], "auth_relations": [],
        "dpapi_secrets": [], "shares": [], "ssh_keys": [],
        "conf_checks_results": [], "directory_listings": [],
        "vuln_findings": [],
    }

    for proto, reader in PROTO_READERS.items():
        db_file = ws_dir / f"{proto}.db"
        try:
            data = reader(db_file)
        except sqlite3.OperationalError as e:
            _warn(f"Skipping {proto}.db: {e}")
            data = {}

        for key in merged:
            if key in data:
                merged[key].extend(data[key])

    # collector_vulns lives in its own file (nxc-vulns.db), not a {proto}.db — read separately.
    try:
        merged["vuln_findings"].extend(_read_collector_vulns(ws_dir).get("vuln_findings", []))
    except sqlite3.OperationalError as e:
        _warn(f"Skipping nxc-vulns.db: {e}")

    return {
        "workspace": config["workspace"],
        "operator":  config["operator"],
        "data":      merged,
    }


# ---------------------------------------------------------------------------
# Local DB — unified enriched store
# ---------------------------------------------------------------------------

def _check_ws_identity(conn: sqlite3.Connection, ws_id: int) -> None:
    """Detect workspace recreation (same name, different id) and warn the operator.

    Stores the current ws_id in meta.last_ws_id after each pull. If the id
    changes between runs it means the project was deleted and recreated with
    the same name; warns so the operator can clean up their nxc workspace if needed.
    """
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='last_ws_id'").fetchone()
        stored = int(row["value"]) if row else None
        if stored is not None and stored != ws_id:
            print(
                f"[!] Workspace was recreated (previous id={stored}, new id={ws_id}). "
                f"Local cache will be replaced. If old data re-appears, delete "
                f"~/.nxc/workspaces/<name>/ on all operator machines."
            )
        conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_ws_id', ?)", (str(ws_id),))
        conn.commit()
    except Exception as e:
        _warn(f"ws-identity check: {e}")


def _init_local_db(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS hosts (
            ip               TEXT PRIMARY KEY,
            hostname         TEXT,
            domain           TEXT,
            os               TEXT,
            dc               INTEGER,
            smbv1            INTEGER,
            signing          INTEGER,
            spooler          INTEGER,
            zerologon        INTEGER,
            petitpotam       INTEGER,
            nla              INTEGER,
            signing_required INTEGER,
            channel_binding  TEXT,
            port             INTEGER,
            banner           TEXT,
            operator         TEXT,
            updated_at       TEXT
        );

        CREATE TABLE IF NOT EXISTS credentials (
            proto            TEXT NOT NULL,
            domain           TEXT NOT NULL DEFAULT '',
            username         TEXT NOT NULL DEFAULT '',
            password         TEXT NOT NULL DEFAULT '',
            credtype         TEXT NOT NULL DEFAULT 'plaintext',
            pillaged_from_ip TEXT,
            operator         TEXT,
            PRIMARY KEY (proto, domain, username, password, credtype)
        );

        CREATE TABLE IF NOT EXISTS auth_relations (
            proto         TEXT NOT NULL,
            host_ip       TEXT NOT NULL,
            hostname      TEXT,
            host_domain   TEXT,
            cred_domain   TEXT NOT NULL DEFAULT '',
            username      TEXT NOT NULL DEFAULT '',
            password      TEXT NOT NULL DEFAULT '',
            credtype      TEXT NOT NULL DEFAULT 'plaintext',
            relation_type TEXT NOT NULL,
            operator      TEXT,
            PRIMARY KEY (proto, host_ip, cred_domain, username, password, credtype, relation_type)
        );

        CREATE TABLE IF NOT EXISTS dpapi_secrets (
            host_ip      TEXT,
            dpapi_type   TEXT,
            windows_user TEXT,
            username     TEXT,
            password     TEXT,
            url          TEXT,
            operator     TEXT
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_dpapi_local_uniq
        ON dpapi_secrets(
            COALESCE(host_ip,''), COALESCE(dpapi_type,''),
            COALESCE(windows_user,''), COALESCE(username,''),
            COALESCE(url,'')
        );

        CREATE TABLE IF NOT EXISTS custom_credentials (
            proto    TEXT,
            domain   TEXT,
            username TEXT NOT NULL DEFAULT '',
            password TEXT NOT NULL DEFAULT '',
            credtype TEXT NOT NULL DEFAULT 'plaintext',
            url      TEXT,
            source   TEXT
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_custom_local_uniq
        ON custom_credentials(
            COALESCE(proto,''), COALESCE(domain,''),
            username, COALESCE(password,'')
        );
    """)
    conn.commit()


def _api_fetch_pages(base_url: str, token: str, params: dict,
                     page_size: int = 2000) -> list:
    """Fetch all pages from a paginated API endpoint."""
    all_rows: list = []
    page = 1
    while True:
        p = {**params, "page": page, "limit": page_size}
        url = f"{base_url}?{urllib.parse.urlencode(p)}"
        req = urllib.request.Request(url, headers={"X-Auth-Token": token})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        rows = data.get("rows", [])
        all_rows.extend(rows)
        total = data.get("total", len(all_rows))
        if len(all_rows) >= total or not rows:
            break
        page += 1
    return all_rows


def pull(config: dict, ws_id: int) -> None:
    """Pull full workspace data from server into local unified DB."""
    import hashlib
    token   = hashlib.sha256(config["password"].encode()).hexdigest()
    server  = config["server"]
    ws_name = config["workspace"]

    print(f"[*] Pulling workspace '{ws_name}' (id={ws_id}) from server...")

    local_db = _local_db_path(ws_name)
    local_db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(local_db))
    _init_local_db(conn)
    _check_ws_identity(conn, ws_id)

    try:
        base = {"workspace_id": ws_id}

        # Hosts — full refresh: hidden rows are removed from local DB.
        # DELETE is unconditional: a legitimately-empty server result must clear stale
        # local rows. An API/network error raises in _api_fetch_pages → the outer
        # try/except rolls the whole pull back, so an error never wipes the local DB.
        hosts = _api_fetch_pages(f"{server}/api/hosts", token, base)
        conn.execute("DELETE FROM hosts")
        for h in hosts:
            conn.execute("""
                INSERT OR REPLACE INTO hosts(
                    ip, hostname, domain, os, dc, smbv1, signing,
                    spooler, zerologon, petitpotam, nla,
                    signing_required, channel_binding, port, banner,
                    operator, updated_at
                ) VALUES (
                    :ip, :hostname, :domain, :os, :dc, :smbv1, :signing,
                    :spooler, :zerologon, :petitpotam, :nla,
                    :signing_required, :channel_binding, :port, :banner,
                    :operator, :updated_at
                )
            """, h)

        # Credentials — full refresh: hidden rows are removed from local DB
        creds = _api_fetch_pages(
            f"{server}/api/credentials", token, {**base, "hide_guest": "false"}
        )
        conn.execute("DELETE FROM credentials")
        for c in creds:
            conn.execute("""
                INSERT OR REPLACE INTO credentials(
                    proto, domain, username, password, credtype,
                    pillaged_from_ip, operator
                ) VALUES (
                    :proto, :domain, :username, :password, :credtype,
                    :pillaged_from_ip, :operator
                )
            """, c)

        # Auth relations — full refresh: hidden rows are removed from local DB
        # /api/results returns: proto, relation_type, ip, hostname, host_domain,
        #   os, smbv1, signing, spooler, zerologon, petitpotam,
        #   cred_domain, username, password, credtype, operator
        rels = _api_fetch_pages(
            f"{server}/api/results", token, {**base, "hide_guest": "false"}
        )
        conn.execute("DELETE FROM auth_relations")
        for r in rels:
            conn.execute("""
                INSERT OR REPLACE INTO auth_relations(
                    proto, host_ip, hostname, host_domain,
                    cred_domain, username, password, credtype,
                    relation_type, operator
                ) VALUES (
                    :proto, :ip, :hostname, :host_domain,
                    :cred_domain, :username, :password, :credtype,
                    :relation_type, :operator
                )
            """, r)

        # DPAPI secrets
        dpapi = _api_fetch_pages(f"{server}/api/dpapi", token, base)
        conn.execute("DELETE FROM dpapi_secrets")
        for d in dpapi:
            conn.execute("""
                INSERT OR IGNORE INTO dpapi_secrets(
                    host_ip, dpapi_type, windows_user,
                    username, password, url, operator
                ) VALUES (
                    :host_ip, :dpapi_type, :windows_user,
                    :username, :password, :url, :operator
                )
            """, d)

        # Custom credentials (Toolbox import — login aliased as username by API)
        custom = _api_fetch_pages(f"{server}/api/custom_creds", token, base)
        conn.execute("DELETE FROM custom_credentials")
        for c in custom:
            conn.execute("""
                INSERT OR IGNORE INTO custom_credentials(
                    proto, domain, username, password, credtype, url, source
                ) VALUES (
                    :proto, :domain, :username, :password, :credtype, :url, :source
                )
            """, c)

        conn.execute(
            "INSERT OR REPLACE INTO meta VALUES ('workspace', ?)", (ws_name,)
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta VALUES ('last_pull', ?)",
            (str(int(time.time())),)
        )
        conn.commit()

        print(
            f"[+] Local DB: {len(hosts)} hosts, {len(creds)} creds, "
            f"{len(rels)} relations, {len(dpapi)} dpapi, {len(custom)} custom → {local_db}"
        )

    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP push
# ---------------------------------------------------------------------------

def push(payload: dict, config: dict) -> None:
    import hashlib
    token = hashlib.sha256(config["password"].encode()).hexdigest()
    url   = f"{config['server']}/api/sync"
    body  = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "X-Auth-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            if not result.get("ok"):
                raise RuntimeError(f"Server returned: {result}")
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body_text}")


# ---------------------------------------------------------------------------
# Workspace status check
# ---------------------------------------------------------------------------

def _resolve_workspace(config: dict) -> "int | None":
    """Fetch workspace list once; return ws_id if workspace exists and is active, else None."""
    import hashlib
    token   = hashlib.sha256(config["password"].encode()).hexdigest()
    ws_name = config["workspace"]
    try:
        req = urllib.request.Request(
            f"{config['server']}/api/workspaces",
            headers={"X-Auth-Token": token},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ws_list = json.loads(resp.read())
    except Exception as e:
        _warn(f"Cannot fetch workspace list: {e}")
        return None

    ws = next((w for w in ws_list if w["name"] == ws_name), None)
    if ws is None:
        print(f"[i] Workspace '{ws_name}' not found on server — skipping sync")
        return None
    if ws.get("archived_at"):
        print(f"[i] Workspace '{ws_name}' is archived — skipping sync")
        return None
    return ws["id"]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    config = load_config()

    ws_id = _resolve_workspace(config)
    if ws_id is None:
        sys.exit(0)

    print(f"[*] Syncing workspace '{config['workspace']}' as '{config['operator']}'...")

    try:
        payload = build_payload(config)

        total_hosts = len(payload["data"]["hosts"])
        total_creds = len(payload["data"]["credentials"])
        total_rel   = len(payload["data"]["auth_relations"])
        print(f"[*] Collected: {total_hosts} hosts, {total_creds} creds, {total_rel} relations")

        push(payload, config)
        print(f"[+] Push completed → {config['server']}")

    except Exception as e:
        _warn(f"Sync failed: {e}")
        sys.exit(1)

    # Pull: sync full workspace data from server into local DB.
    # Non-fatal — push already succeeded, local DB will be refreshed on next sync.
    try:
        pull(config, ws_id)
    except Exception as e:
        _warn(f"Pull failed (local DB not updated): {e}")


if __name__ == "__main__":
    main()
