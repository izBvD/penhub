#!/usr/bin/env python3
"""
nxce — nxc PWN3D Extractor
Queries administrative credentials and target hosts from the per-workspace local
DB (~/.nxc/workspaces/<workspace>/nxc-collector.db; workspace from
~/.nxc-collector.conf). Falls back to legacy ~/.nxc-collector-local.db if no config.
"""

import argparse
import ipaddress
import re
import sqlite3
import sys
import time
from pathlib import Path

CONF_FILE   = Path.home() / ".nxc-collector.conf"
NXC_WS_DIR  = Path.home() / ".nxc" / "workspaces"
UPDATER     = "nxc_updater"

PROTOCOLS = ["smb", "ldap", "winrm", "mssql", "ssh"]

_HEX32     = re.compile(r'^[0-9a-fA-F]{32}$')
_NT_EMPTY  = "31d6cfe0d16ae931b73c59d7e0c089c0"
_SKIP_USERS = {'guest', 'гость', 'defaultaccount', 'wdagutilityaccount', ''}

# ── ANSI ───────────────────────────────────────────────────────────────────────
_use_color = sys.stdout.isatty()

class _C:
    RST  = "\033[0m"
    BOLD = "\033[1m"
    DIM  = "\033[2m"
    RED  = "\033[91m"
    YEL  = "\033[93m"
    GRN  = "\033[92m"
    CYA  = "\033[96m"
    MAG  = "\033[95m"

def _c(text, code):
    return f"{code}{text}{_C.RST}" if _use_color else str(text)


# ── DB ─────────────────────────────────────────────────────────────────────────
def _load_conf() -> "str | None":
    """Return workspace name from config, or None if config missing/invalid."""
    if not CONF_FILE.exists():
        return None
    try:
        from configparser import ConfigParser
        cfg = ConfigParser()
        cfg.read(str(CONF_FILE))
        return cfg["collector"].get("workspace", "default") if "collector" in cfg else None
    except Exception:
        return None


def _open_db() -> "tuple[sqlite3.Connection, str]":
    """Open per-workspace local DB. Returns (conn, workspace_name)."""
    ws = _load_conf()
    if ws:
        db_path = NXC_WS_DIR / ws / "nxc-collector.db"
    else:
        # Fallback: no config — try legacy home-dir paths
        db_path = Path.home() / ".nxc-collector-local.db"
        ws = ""

    if not db_path.exists():
        print(f"[!] Local DB not found: {db_path}", file=sys.stderr)
        print(f"    Run: {UPDATER}  — push+pull workspace data from collector server",
              file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn, ws


def _sync_hint(conn: sqlite3.Connection):
    """First line shown on every run — sync reminder."""
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='last_pull'").fetchone()
        if row:
            secs = int(time.time()) - int(row[0])
            if secs < 60:
                ago = "just now"
            elif secs < 3600:
                ago = f"{secs // 60}m ago"
            elif secs < 86400:
                ago = f"{secs // 3600}h ago"
            else:
                ago = f"{secs // 86400}d ago"
            hint = f"last sync: {ago}"
        else:
            hint = "never synced"
    except Exception:
        hint = "sync status unknown"
    print(_c(f"[i] {hint} — force sync: {UPDATER}", _C.DIM), file=sys.stderr)


# ── IP / CIDR helpers ──────────────────────────────────────────────────────────
def _parse_ip_filter(val: str):
    """Parse -i value. Returns (ip_str, network) — exactly one is set."""
    try:
        if '/' in val:
            return None, ipaddress.ip_network(val, strict=False)
        return str(ipaddress.ip_address(val)), None
    except ValueError:
        print(f"[!] Invalid IP or CIDR: {val!r}", file=sys.stderr)
        sys.exit(1)


def _in_net(ip_str: str, network) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


def _filter_cidr(rows: list, network) -> list:
    return [r for r in rows if _in_net(r["host_ip"], network)]


def _extract_nt(pw: str) -> "str | None":
    """Extract NT hash from plain hash or LM:NT (SAM dump) format. Returns None for empty hash."""
    if not pw or pw == '<empty_password>':
        return None
    pw = pw.strip().lower()
    parts = pw.split(':')
    if len(parts) == 2 and _HEX32.match(parts[0]) and _HEX32.match(parts[1]):
        nt = parts[1]
    elif _HEX32.match(pw):
        nt = pw
    else:
        return None
    return None if nt == _NT_EMPTY else nt


# ── Queries ─────────────────────────────────────────────────────────────────────
def _admin_rows(conn, proto, user, domain, password, hash_only, plain_only,
                ip_exact=None):
    """Returns list of dicts from auth_relations where relation_type='admin'."""
    conds, params = ["relation_type='admin'"], []

    if proto and proto != "all":
        conds.append("UPPER(proto)=?")
        params.append(proto.upper())
    if user:
        conds.append("LOWER(username)=LOWER(?)")
        params.append(user)
    if domain:
        conds.append("LOWER(cred_domain)=LOWER(?)")
        params.append(domain)
    if password:
        conds.append("LOWER(password)=LOWER(?)")
        params.append(password)
    if hash_only:
        conds.append("credtype='hash'")
    elif plain_only:
        conds.append("credtype='plaintext'")
    if ip_exact:
        conds.append("host_ip=?")
        params.append(ip_exact)

    return [dict(r) for r in conn.execute(
        "SELECT proto, host_ip, hostname, cred_domain, username, password, credtype "
        f"FROM auth_relations WHERE {' AND '.join(conds)} "
        "ORDER BY host_ip, cred_domain, username",
        params,
    ).fetchall()]



# ── Output ─────────────────────────────────────────────────────────────────────
def _sh(s: str) -> str:
    """Shell-safe single-quote a string (handles embedded single quotes)."""
    return "'" + s.replace("'", "'\\''") + "'"


def _emit_rows(rows, ip_only, nxc_fmt, multi_proto):
    seen_ip: set = set()
    for r in rows:
        if ip_only:
            ip = r["host_ip"]
            if ip not in seen_ip:
                seen_ip.add(ip)
                yield ip
            continue

        if nxc_fmt:
            pw = r["password"]
            if pw == "<empty_password>":
                flag, pw_arg = "-p", "''"
            elif r["credtype"] == "hash":
                flag, pw_arg = "-H", _sh(pw)
            else:
                flag, pw_arg = "-p", _sh(pw)
            d_arg = f" -d {_sh(r['cred_domain'])}" if r["cred_domain"] else ""
            yield (f"nxc {r['proto'].lower()} {r['host_ip']} "
                   f"-u {_sh(r['username'])} {flag} {pw_arg}{d_arg}")
            continue

        cols: list = []
        if multi_proto:
            cols.append(r["proto"])
        cols += [r["host_ip"], r["cred_domain"] or "", r["username"], r["password"]]
        if r["credtype"] == "hash":
            cols.append("[HASH]")
        yield "\t".join(cols)


_PROTO_SET = {"SMB", "LDAP", "WINRM", "MSSQL", "SSH",
              "smb", "ldap", "winrm", "mssql", "ssh"}

def _colorize(line: str, nxc_fmt: bool, ip_only: bool) -> str:
    if not _use_color:
        return line
    if ip_only or "\t" not in line:
        return _c(line, _C.YEL)
    if nxc_fmt:
        # bold the IP (3rd token in "nxc proto IP -u ...")
        p = line.split(" ")
        if len(p) >= 3:
            p[2] = _c(p[2], _C.YEL)
        return " ".join(p)
    p = line.split("\t")
    offset = 1 if p and p[0] in _PROTO_SET else 0
    if len(p) > offset:
        p[offset] = _c(p[offset], _C.YEL)          # ip
    if len(p) > offset + 2:
        p[offset + 2] = _c(p[offset + 2], _C.CYA)  # user
    if len(p) > offset + 3:
        p[offset + 3] = _c(p[offset + 3], _C.GRN)  # pass/hash
    return "\t".join(p)


def _write(lines, outfile, nxc_fmt=False, ip_only=False):
    if outfile:
        with open(outfile, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        print(f"[+] Saved {len(lines)} lines → {outfile}")
    else:
        for line in lines:
            print(_colorize(line, nxc_fmt, ip_only))


# ── Brute-force spray export ──────────────────────────────────────────────────────

def _cmd_brute(conn: sqlite3.Connection, target: str, proto: str, out_dir_str: str):
    """
    Export 4 line-by-line credential files for nxc spray, then print ready commands.
    Line counts in each file pair are guaranteed equal (paired per row).
    """
    out_dir = Path(out_dir_str).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = conn.execute("""
        SELECT DISTINCT username, password, credtype
        FROM credentials
        WHERE username != ''
        ORDER BY username COLLATE NOCASE, password
    """).fetchall()

    plain_pairs: list = []
    hash_pairs:  list = []
    seen_plain:  set  = set()
    seen_hash:   set  = set()

    for r in rows:
        uname = r["username"] or ""
        if uname.casefold() in _SKIP_USERS:
            continue

        pw       = r["password"] or ""
        credtype = r["credtype"] or "plaintext"

        if credtype == "plaintext":
            display_pw = "" if pw == "<empty_password>" else pw
            key = (uname.casefold(), display_pw)
            if key not in seen_plain:
                seen_plain.add(key)
                plain_pairs.append((uname, display_pw))

        elif credtype == "hash":
            nt = _extract_nt(pw)
            if nt:
                key = (uname.casefold(), nt)
                if key not in seen_hash:
                    seen_hash.add(key)
                    hash_pairs.append((uname, nt))

    # Custom credentials from Toolbox import (merged into same dedup sets)
    try:
        custom_rows = conn.execute("""
            SELECT DISTINCT username, password, credtype
            FROM custom_credentials
            WHERE username != ''
            ORDER BY username COLLATE NOCASE, password
        """).fetchall()
        for r in custom_rows:
            uname    = r["username"] or ""
            if uname.casefold() in _SKIP_USERS:
                continue
            pw       = r["password"] or ""
            credtype = r["credtype"] or "plaintext"
            if credtype == "plaintext":
                display_pw = "" if pw == "<empty_password>" else pw
                key = (uname.casefold(), display_pw)
                if key not in seen_plain:
                    seen_plain.add(key)
                    plain_pairs.append((uname, display_pw))
            elif credtype == "hash":
                nt = _extract_nt(pw)
                if nt:
                    key = (uname.casefold(), nt)
                    if key not in seen_hash:
                        seen_hash.add(key)
                        hash_pairs.append((uname, nt))
    except sqlite3.OperationalError:
        pass  # table absent until first sync after update

    if not plain_pairs and not hash_pairs:
        print("[!] No usable credentials found in local DB", file=sys.stderr)
        return

    def _wpair(logins_path: Path, creds_path: Path, pairs: list, label: str):
        for p in (logins_path, creds_path):
            if p.exists():
                p.unlink()
                print(_c(f"[~] Removed existing: {p.name}", _C.DIM))
        logins_path.write_text("\n".join(u for u, _ in pairs) + "\n", encoding="utf-8")
        creds_path.write_text( "\n".join(c for _, c in pairs) + "\n", encoding="utf-8")
        print(f"[+] {len(pairs):>4} {label} pairs → "
              f"{logins_path.name}  /  {creds_path.name}")

    cmds: list = []

    if plain_pairs:
        lp = out_dir / "logins_P_brut.txt"
        pp = out_dir / "pass_for_brute.txt"
        _wpair(lp, pp, plain_pairs, "plaintext")
        cmds.append(
            f"nxc {proto} {target} "
            f"-u {lp} -p {pp} --no-bruteforce --continue-on-success"
        )

    if hash_pairs:
        lh = out_dir / "logins_H_brut.txt"
        hh = out_dir / "hashes_for_brute.txt"
        _wpair(lh, hh, hash_pairs, "hash    ")
        cmds.append(
            f"nxc {proto} {target} "
            f"-u {lh} -H {hh} --no-bruteforce --continue-on-success"
        )

    print(f"\n{_c('Next step:', _C.BOLD + _C.MAG)}\n")
    for cmd in cmds:
        print(_c(cmd, _C.GRN))
        print()


# ── Argument parser ─────────────────────────────────────────────────────────────
def _add_filters(p: argparse.ArgumentParser):
    p.add_argument("-u", "--user",   metavar="USER",   help="Username filter (case-insensitive)")
    p.add_argument("-d", "--domain", metavar="DOMAIN", help="Domain filter (case-insensitive)")
    p.add_argument("-p", metavar="PASS", dest="password",
                   help="Password / hash filter (case-insensitive)")
    p.add_argument("-i", metavar="IP/CIDR", dest="ip_filter",
                   help="Filter by target host IP or CIDR (e.g. 10.0.0.1 or 10.0.0.0/24)")
    p.add_argument("--hash",  dest="hash_only",  action="store_true",
                   help="Only hash credentials")
    p.add_argument("--plain", dest="plain_only", action="store_true",
                   help="Only plaintext credentials")
    p.add_argument("--ip", action="store_true",
                   help="Output only IP addresses (deduplicated)")
    p.add_argument("--nxc", dest="nxc_fmt", action="store_true",
                   help="Output as ready-to-run nxc commands")
    p.add_argument("-c", "--count", action="store_true",
                   help="Print result count and exit")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Save output to file (disables colours)")
    p.add_argument("--no-color", action="store_true", help="Disable coloured output")
    p.add_argument("--brute", metavar="DIR",
                   help="Export 4 credential files to DIR for nxc line-by-line spray "
                        "(logins/passes pairs for plaintext and hashes). "
                        "Use -i IP/FILE to set the spray target in printed commands "
                        "(e.g. -i not_pwn3d_ip.txt from Toolbox).")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nxce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="nxce — nxc PWN3D Extractor  (reads ~/.nxc/workspaces/<ws>/nxc-collector.db)",
        epilog="""
protocols:  smb  ldap  winrm  mssql  ssh  all

examples:
  nxce smb                                  all SMB PWN3D entries
  nxce smb -u Administrator                 hosts where Administrator is admin
  nxce smb -u "Administrator" -d corp.local filter by user + domain
  nxce smb -d corp.local --ip               only IPs for that domain
  nxce smb -i 10.10.10.15                   who is PWN3D on that specific IP
  nxce smb -i 10.10.10.0/24                 all admin entries in subnet
  nxce smb -i 10.0.0.0/8 -u Administrator  Administrator PWN3D in whole range
  nxce smb -i 172.16.0.0/16 --nxc          ready nxc commands for subnet
  nxce smb -u admin --nxc -o cmds.txt      save nxc commands to file
  nxce all -u Administrator                 admin across all protocols
""",
    )
    subs = parser.add_subparsers(dest="cmd", metavar="PROTOCOL")

    for proto in PROTOCOLS + ["all"]:
        desc = (
            f"Query PWN3D (admin) entries for {proto.upper()}"
            if proto != "all" else
            "Query admin entries across all protocols"
        )
        sub = subs.add_parser(
            proto, description=desc, help=desc,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        _add_filters(sub)

    return parser


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    global _use_color

    # No arguments → show protocol list
    if len(sys.argv) == 1:
        print(f"\n  {_c('nxce', _C.BOLD + _C.MAG)} — nxc PWN3D Extractor\n")
        print(f"  Usage: nxce {_c('PROTOCOL', _C.CYA)} [filters]\n")
        protos = "  ".join(_c(p, _C.YEL) for p in PROTOCOLS)
        print(f"  Protocols: {protos}")
        print(f"             {_c('all', _C.YEL)}  — all protocols combined\n")
        print(f"  Tip: {_c('nxce PROTOCOL -h', _C.GRN)}  for full flag list\n")
        try:
            conn, ws = _open_db()
            if ws:
                print(_c(f"[i] project: {ws}", _C.DIM), file=sys.stderr)
            _sync_hint(conn)
            conn.close()
        except SystemExit:
            pass
        return

    parser = _build_parser()
    args   = parser.parse_args()

    if args.cmd is None:
        parser.print_help()
        return

    if getattr(args, "no_color", False) or getattr(args, "output", None):
        _use_color = False

    conn, ws = _open_db()
    if ws:
        print(_c(f"[i] project: {ws}", _C.DIM), file=sys.stderr)
    _sync_hint(conn)

    # ── --brute: credential spray export ────────────────────────────────────
    if getattr(args, "brute", None):
        target = getattr(args, "ip_filter", None) or "<TARGET>"
        _cmd_brute(conn, target, args.cmd, args.brute)
        conn.close()
        return

    # ── protocol subcommand ──────────────────────────────────────────────────
    ip_exact, ip_net = None, None
    if getattr(args, "ip_filter", None):
        ip_exact, ip_net = _parse_ip_filter(args.ip_filter)

    rows = _admin_rows(
        conn,
        proto=args.cmd,
        user=args.user,
        domain=args.domain,
        password=args.password,
        hash_only=args.hash_only,
        plain_only=args.plain_only,
        ip_exact=ip_exact,
    )

    if ip_net:
        rows = _filter_cidr(rows, ip_net)

    if args.count:
        print(len(rows))
        conn.close()
        return

    multi = (args.cmd == "all")
    lines = list(_emit_rows(rows, ip_only=args.ip, nxc_fmt=args.nxc_fmt, multi_proto=multi))
    _write(lines, args.output, nxc_fmt=args.nxc_fmt, ip_only=args.ip)
    conn.close()


if __name__ == "__main__":
    main()
