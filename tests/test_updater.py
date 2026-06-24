"""
Unit tests for nxc_updater — config loading and URL normalization.
"""

import sys
import tempfile
import textwrap
from pathlib import Path

import pytest


def _write_conf(tmp_path: Path, content: str) -> Path:
    conf = tmp_path / ".nxc-collector.conf"
    conf.write_text(textwrap.dedent(content), encoding="utf-8")
    return conf


def _load_updater():
    """Import nxc_updater.py as a fresh module object for patching."""
    import importlib

    spec = importlib.util.spec_from_file_location(
        "nxc_updater_ut",
        Path(__file__).parent.parent / "nxc_updater.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_config_from(conf_path: Path) -> dict:
    """Call nxc_updater.load_config() with a patched CONF_FILE."""
    mod = _load_updater()
    # Patch AFTER exec_module so module-level init doesn't overwrite it
    mod.CONF_FILE = conf_path
    return mod.load_config()


_HOST_KEYS = (
    "ip hostname domain os dc smbv1 signing spooler zerologon petitpotam nla "
    "signing_required channel_binding port banner operator updated_at"
).split()


def _host_row(ip: str) -> dict:
    """A full host row dict with every named param pull()'s INSERT expects."""
    row = {k: None for k in _HOST_KEYS}
    row["ip"] = ip
    return row


def _seed_local_hosts(mod, ws: str, tmp_path: Path, ips):
    local_db = tmp_path / ws / "nxc-collector.db"
    local_db.parent.mkdir(parents=True, exist_ok=True)
    import sqlite3
    conn = sqlite3.connect(str(local_db))
    mod._init_local_db(conn)
    for ip in ips:
        conn.execute("INSERT INTO hosts(ip) VALUES(?)", (ip,))
    conn.commit()
    conn.close()
    return local_db


def _local_host_ips(local_db) -> set:
    import sqlite3
    conn = sqlite3.connect(str(local_db))
    ips = {r[0] for r in conn.execute("SELECT ip FROM hosts").fetchall()}
    conn.close()
    return ips


_CFG = {"server": "http://x", "password": "p", "operator": "op", "workspace": "ws"}


# ───────────────────────────────────────────────────────────────────────────
# collector_vulns reader — slug normalization + tri-state dedup
# ───────────────────────────────────────────────────────────────────────────

def _seed_vulns_db(ws_dir: Path, rows):
    """rows: list of (ip, vuln_name, is_vulnerable, details, timestamp)."""
    import sqlite3
    ws_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(ws_dir / "nxc-vulns.db"))
    conn.execute("""
        CREATE TABLE collector_vulns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT, port INTEGER, ip TEXT NOT NULL,
            hostname TEXT, domain TEXT, username TEXT, password TEXT,
            lmhash TEXT, nthash TEXT, vuln_name TEXT NOT NULL,
            is_vulnerable INTEGER, details TEXT, timestamp TEXT NOT NULL
        )
    """)
    for ip, vn, iv, det, ts in rows:
        conn.execute(
            "INSERT INTO collector_vulns(protocol, port, ip, vuln_name, is_vulnerable, details, timestamp)"
            " VALUES('smb',445,?,?,?,?,?)",
            (ip, vn, iv, det, ts),
        )
    conn.commit()
    conn.close()


def test_vuln_slug_normalization():
    mod = _load_updater()
    assert mod._vuln_slug("MS17-010 EternalBlue") == "ms17_010"
    assert mod._vuln_slug("Coerce/PetitPotam") == "petitpotam"
    assert mod._vuln_slug("Zerologon (CVE-2020-1472)") == "zerologon"
    # Unknown → slugified fallback, never crashes
    assert mod._vuln_slug("Some New Vuln (CVE-9999)") == "some_new_vuln"


def test_read_collector_vulns_missing_db(tmp_path):
    mod = _load_updater()
    assert mod._read_collector_vulns(tmp_path) == {}


def test_read_collector_vulns_slug_and_shape(tmp_path):
    mod = _load_updater()
    _seed_vulns_db(tmp_path, [("10.0.0.1", "Coerce/PrinterBug", 1, "pipe", "2026-01-01 00:00:00")])
    out = mod._read_collector_vulns(tmp_path)
    assert len(out["vuln_findings"]) == 1
    f = out["vuln_findings"][0]
    assert f["vuln_name"] == "printerbug"
    assert f["is_vulnerable"] == 1
    assert f["ip"] == "10.0.0.1"
    assert "_ts" not in f, "internal timestamp helper key must not leak into payload"


def test_read_collector_vulns_dedup_vulnerable_wins(tmp_path):
    mod = _load_updater()
    _seed_vulns_db(tmp_path, [
        ("10.0.0.2", "WebDAV", 0, "clean", "2026-01-01 00:00:00"),
        ("10.0.0.2", "WebDAV", 1, "vuln",  "2026-01-01 00:00:01"),
    ])
    out = mod._read_collector_vulns(tmp_path)
    findings = [f for f in out["vuln_findings"] if f["vuln_name"] == "webdav"]
    assert len(findings) == 1, "must dedup to one finding per (ip, slug)"
    assert findings[0]["is_vulnerable"] == 1, "vulnerable-wins over a clean scan"


def test_read_collector_vulns_clean_beats_null_and_latest_ts(tmp_path):
    mod = _load_updater()
    _seed_vulns_db(tmp_path, [
        ("10.0.0.3", "UAC", None, "error",  "2026-01-01 00:00:05"),
        ("10.0.0.3", "UAC", 0,    "clean",  "2026-01-01 00:00:01"),
    ])
    out = mod._read_collector_vulns(tmp_path)
    f = next(f for f in out["vuln_findings"] if f["vuln_name"] == "uac")
    assert f["is_vulnerable"] == 0, "checked-clean (0) must beat could-not-check (None) regardless of ts"


class TestPullFullRefresh:
    """pull() must keep the local DB's visibility in sync with the server."""

    def test_clears_stale_rows_when_server_returns_empty(self, tmp_path):
        """If everything visible got hidden/removed on the server (empty fetch), the
        local DB must be cleared — not left showing a stale snapshot."""
        mod = _load_updater()
        mod.NXC_WS_DIR = tmp_path
        local_db = _seed_local_hosts(mod, "ws", tmp_path, ["10.0.0.1"])
        mod._api_fetch_pages = lambda *a, **k: []  # server has no visible rows

        mod.pull(_CFG, ws_id=1)

        assert _local_host_ips(local_db) == set(), (
            "stale host must be removed when the server returns no visible hosts"
        )

    def test_removes_now_hidden_row_when_others_visible(self, tmp_path):
        """A row hidden on the server disappears locally while still-visible rows stay."""
        mod = _load_updater()
        mod.NXC_WS_DIR = tmp_path
        local_db = _seed_local_hosts(mod, "ws", tmp_path, ["10.0.0.1", "10.0.0.2"])

        def fake_fetch(base_url, token, params, page_size=2000):
            if base_url.endswith("/api/hosts"):
                return [_host_row("10.0.0.2")]  # 10.0.0.1 now hidden on server
            return []

        mod._api_fetch_pages = fake_fetch
        mod.pull(_CFG, ws_id=1)

        assert _local_host_ips(local_db) == {"10.0.0.2"}


class TestLoadConfigUrlNormalization:
    """load_config() must always return a server URL with http(s):// scheme."""

    def test_bare_ip_gets_http_scheme(self, tmp_path):
        conf = _write_conf(tmp_path, """
            [collector]
            server   = 192.168.0.209
            port     = 322
            password = pass
            operator = op
            workspace = ws
        """)
        cfg = _load_config_from(conf)
        assert cfg["server"].startswith("http://"), (
            f"Expected http:// prefix, got: {cfg['server']!r}"
        )
        assert "192.168.0.209" in cfg["server"]

    def test_bare_ip_with_port_suffix_gets_http_scheme(self, tmp_path):
        """server=10.0.0.1:8080 (port embedded, no scheme) → http://10.0.0.1:8080"""
        conf = _write_conf(tmp_path, """
            [collector]
            server   = 10.0.0.1:8080
            port     = 322
            password = pass
            operator = op
            workspace = ws
        """)
        cfg = _load_config_from(conf)
        assert cfg["server"].startswith("http://")
        assert "10.0.0.1:8080" in cfg["server"]

    def test_http_url_unchanged(self, tmp_path):
        conf = _write_conf(tmp_path, """
            [collector]
            server   = http://192.168.0.209
            port     = 322
            password = pass
            operator = op
            workspace = ws
        """)
        cfg = _load_config_from(conf)
        assert cfg["server"].startswith("http://192.168.0.209")
        assert cfg["server"].count("http://") == 1, "Must not double-add http://"

    def test_https_url_unchanged(self, tmp_path):
        conf = _write_conf(tmp_path, """
            [collector]
            server   = https://pentest.internal
            port     = 443
            password = pass
            operator = op
            workspace = ws
        """)
        cfg = _load_config_from(conf)
        assert cfg["server"].startswith("https://pentest.internal")
        assert cfg["server"].count("https://") == 1

    def test_port_appended_when_not_in_server(self, tmp_path):
        conf = _write_conf(tmp_path, """
            [collector]
            server   = 192.168.1.1
            port     = 9000
            password = pass
            operator = op
            workspace = ws
        """)
        cfg = _load_config_from(conf)
        assert cfg["server"].endswith(":9000"), f"Got: {cfg['server']!r}"

    def test_port_not_double_appended(self, tmp_path):
        """If port already in server string, don't append again."""
        conf = _write_conf(tmp_path, """
            [collector]
            server   = http://192.168.1.1:322
            port     = 322
            password = pass
            operator = op
            workspace = ws
        """)
        cfg = _load_config_from(conf)
        assert cfg["server"].count(":322") == 1, f"Port duplicated: {cfg['server']!r}"


# ═══════════════════════════════════════════════════════════════════════════════
# Adaptive schema mapping — readers must honor nxc_schema.json column renames
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemaMappingCoverage:
    """A column renamed in nxc + mapped in nxc_schema.json must flow through the
    reader. Guards the 'insurance' promise for RDP and SMB conf_checks."""

    def test_rdp_reader_honors_schema_column_rename(self, tmp_path):
        """nxc renames rdp.hosts.os → operating_system; schema maps it → value flows."""
        mod = _load_updater()
        import sqlite3
        db = tmp_path / "rdp.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE hosts (id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT,"
            " domain TEXT, operating_system TEXT, nla INTEGER, port INTEGER)"
        )
        conn.execute(
            "INSERT INTO hosts VALUES (1,'10.0.0.1','RDP01','corp','Windows 10',1,3389)"
        )
        conn.commit()
        conn.close()
        mod._NXC_SCHEMA.setdefault("rdp", {}).setdefault("hosts", {})["os"] = "operating_system"

        out = mod._read_rdp(db)
        assert len(out["hosts"]) == 1
        h = out["hosts"][0]
        assert h["ip"] == "10.0.0.1"
        assert h["os"] == "Windows 10", "renamed os column must resolve via schema"
        assert h["nla"] == 1 and h["port"] == 3389

    def test_rdp_reader_default_columns_still_work(self, tmp_path):
        """Regression: with stock column names (no rename), RDP host still reads."""
        mod = _load_updater()
        import sqlite3
        db = tmp_path / "rdp.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE hosts (id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT,"
            " domain TEXT, os TEXT, nla INTEGER, port INTEGER)"
        )
        conn.execute("INSERT INTO hosts VALUES (1,'10.0.0.2','RDP02','corp','Win11',0,3389)")
        conn.commit()
        conn.close()

        out = mod._read_rdp(db)
        assert out["hosts"][0]["os"] == "Win11"
        assert out["hosts"][0]["ip"] == "10.0.0.2"

    def test_smb_conf_checks_honors_schema_rename(self, tmp_path):
        """nxc renames conf_checks.name → check_label; schema maps it → check_name flows."""
        mod = _load_updater()
        import sqlite3
        db = tmp_path / "smb.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE hosts (id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT,"
            " domain TEXT, os TEXT, dc INTEGER, smbv1 INTEGER, signing INTEGER,"
            " spooler INTEGER, zerologon INTEGER, petitpotam INTEGER)"
        )
        conn.execute("INSERT INTO hosts (id, ip) VALUES (1, '10.0.0.5')")
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, domain TEXT, username TEXT,"
            " password TEXT, credtype TEXT, pillaged_from_hostid INTEGER)"
        )
        conn.execute(
            "CREATE TABLE conf_checks (id INTEGER PRIMARY KEY, check_label TEXT, description TEXT)"
        )
        conn.execute("INSERT INTO conf_checks (id, check_label) VALUES (10, 'SMB Signing')")
        conn.execute(
            "CREATE TABLE conf_checks_results (id INTEGER PRIMARY KEY, host_id INTEGER,"
            " check_id INTEGER, secure INTEGER, reasons TEXT)"
        )
        conn.execute(
            "INSERT INTO conf_checks_results (id, host_id, check_id, secure, reasons)"
            " VALUES (1, 1, 10, 0, 'weak')"
        )
        conn.commit()
        conn.close()
        mod._NXC_SCHEMA.setdefault("smb", {}).setdefault("conf_checks", {})["name"] = "check_label"

        out = mod._read_smb(db)
        ccr = out["conf_checks_results"]
        assert len(ccr) == 1, "conf_checks_result must survive a conf_checks.name rename"
        assert ccr[0]["check_name"] == "SMB Signing"
        assert ccr[0]["host_ip"] == "10.0.0.5"
        assert ccr[0]["secure"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Table-name mapping — readers honor nxc_schema.json '__table__' renames
# ═══════════════════════════════════════════════════════════════════════════════

class TestTableNameMapping:
    """nxc may rename a whole table; '__table__' in nxc_schema.json maps it without
    code changes. Falls back to the internal key for stock nxc."""

    def test_resolver_default_is_internal_key(self):
        mod = _load_updater()
        assert mod._table("smb", "hosts") == "hosts"

    def test_resolver_uses_mapped_name(self):
        mod = _load_updater()
        mod._NXC_SCHEMA.setdefault("smb", {}).setdefault("hosts", {})["__table__"] = "computers"
        assert mod._table("smb", "hosts") == "computers"

    def test_resolver_rejects_non_identifier(self, capsys):
        """A malformed __table__ (SQL-unsafe) is rejected → fall back + warn."""
        mod = _load_updater()
        mod._NXC_SCHEMA.setdefault("smb", {}).setdefault("hosts", {})["__table__"] = "hosts; DROP TABLE x"
        assert mod._table("smb", "hosts") == "hosts"
        assert "[schema]" in capsys.readouterr().err.lower()

    def test_smb_hosts_table_rename_end_to_end(self, tmp_path):
        """hosts table renamed to 'computers' in nxc; __table__ maps it → host flows."""
        mod = _load_updater()
        import sqlite3
        db = tmp_path / "smb.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE computers (id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT,"
            " domain TEXT, os TEXT, dc INTEGER, smbv1 INTEGER, signing INTEGER,"
            " spooler INTEGER, zerologon INTEGER, petitpotam INTEGER)"
        )
        conn.execute("INSERT INTO computers (id, ip, hostname) VALUES (1, '10.0.0.9', 'PC9')")
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, domain TEXT, username TEXT,"
            " password TEXT, credtype TEXT, pillaged_from_hostid INTEGER)"
        )
        conn.commit()
        conn.close()
        mod._NXC_SCHEMA.setdefault("smb", {}).setdefault("hosts", {})["__table__"] = "computers"

        out = mod._read_smb(db)
        assert len(out["hosts"]) == 1
        assert out["hosts"][0]["ip"] == "10.0.0.9"
        assert out["hosts"][0]["hostname"] == "PC9"

    def test_ssh_relations_table_rename_end_to_end(self, tmp_path):
        """admin_relations renamed → PWN3D relation still extracted via __table__."""
        mod = _load_updater()
        import sqlite3
        db = tmp_path / "ssh.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT, port INTEGER, banner TEXT, os TEXT)")
        conn.execute("INSERT INTO hosts (id, host) VALUES (1, '10.0.0.7')")
        conn.execute(
            "CREATE TABLE credentials (id INTEGER PRIMARY KEY, username TEXT, password TEXT, credtype TEXT)"
        )
        conn.execute("INSERT INTO credentials (id, username, password, credtype) VALUES (1,'root','toor','plaintext')")
        conn.execute("CREATE TABLE adminrel (id INTEGER PRIMARY KEY, credid INTEGER, hostid INTEGER)")
        conn.execute("INSERT INTO adminrel (id, credid, hostid) VALUES (1, 1, 1)")
        conn.commit()
        conn.close()
        mod._NXC_SCHEMA.setdefault("ssh", {}).setdefault("admin_relations", {})["__table__"] = "adminrel"

        out = mod._read_ssh(db)
        admin = [r for r in out["auth_relations"] if r["relation_type"] == "admin"]
        assert len(admin) == 1
        assert admin[0]["host_ip"] == "10.0.0.7"
        assert admin[0]["cred_username"] == "root"


# ═══════════════════════════════════════════════════════════════════════════════
# Schema-drift detection — _audit_schema warns when a required column is missing
# ═══════════════════════════════════════════════════════════════════════════════

def _seed_smb_min(db_path, host_cols_sql, host_insert_sql, host_values,
                  extra_setup=None):
    """Minimal smb.db: a configurable hosts table + an empty users table."""
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.execute(f"CREATE TABLE hosts ({host_cols_sql})")
    conn.execute(host_insert_sql, host_values)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, domain TEXT, username TEXT,"
        " password TEXT, credtype TEXT, pillaged_from_hostid INTEGER)"
    )
    if extra_setup:
        extra_setup(conn)
    conn.commit()
    conn.close()


class TestSchemaDriftWarning:
    """A required, schema-mapped column missing from the actual nxc table must emit a
    '[schema]' warning to stderr (early stale-nxc_schema.json signal). Log-only."""

    def test_renamed_required_column_warns(self, tmp_path, capsys):
        """hosts.ip renamed to ip_addr, schema NOT updated → warning mentions the column."""
        mod = _load_updater()
        db = tmp_path / "smb.db"
        _seed_smb_min(
            db,
            "id INTEGER PRIMARY KEY, ip_addr TEXT, hostname TEXT",
            "INSERT INTO hosts (id, ip_addr, hostname) VALUES (1, '10.0.0.1', 'H1')",
            (),
        )
        mod._read_smb(db)
        err = capsys.readouterr().err.lower()
        assert "[schema]" in err
        assert "ip" in err and "hosts" in err

    def test_stock_columns_no_warning(self, tmp_path, capsys):
        """Stock column names → no schema warning."""
        mod = _load_updater()
        db = tmp_path / "smb.db"
        _seed_smb_min(
            db,
            "id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT, domain TEXT, os TEXT,"
            " dc INTEGER, smbv1 INTEGER, signing INTEGER, spooler INTEGER,"
            " zerologon INTEGER, petitpotam INTEGER",
            "INSERT INTO hosts (id, ip) VALUES (1, '10.0.0.1')",
            (),
        )
        mod._read_smb(db)
        assert "[schema]" not in capsys.readouterr().err.lower()

    def test_optional_missing_column_no_warning(self, tmp_path, capsys):
        """Older nxc lacking optional vuln columns (dc/zerologon) must NOT warn —
        only required identity columns are audited."""
        mod = _load_updater()
        db = tmp_path / "smb.db"
        _seed_smb_min(
            db,
            "id INTEGER PRIMARY KEY, ip TEXT, hostname TEXT",  # no dc/smbv1/zerologon/...
            "INSERT INTO hosts (id, ip) VALUES (1, '10.0.0.1')",
            (),
        )
        mod._read_smb(db)
        assert "[schema]" not in capsys.readouterr().err.lower()

    def test_empty_table_no_warning(self, tmp_path, capsys):
        """An empty table reveals no columns to audit → stay silent (no false alarm)."""
        mod = _load_updater()
        db = tmp_path / "smb.db"
        _seed_smb_min(
            db,
            "id INTEGER PRIMARY KEY, ip_addr TEXT",  # renamed, but no rows
            "INSERT INTO hosts (id) VALUES (1)" if False else "INSERT INTO hosts DEFAULT VALUES",
            (),
        )
        # delete the row to make it empty
        import sqlite3
        c = sqlite3.connect(str(db)); c.execute("DELETE FROM hosts"); c.commit(); c.close()
        mod._read_smb(db)
        assert "[schema]" not in capsys.readouterr().err.lower()

    def test_conf_checks_drift_warns(self, tmp_path, capsys):
        """conf_checks.name renamed, schema stale → warning names conf_checks."""
        mod = _load_updater()
        db = tmp_path / "smb.db"

        def extra(conn):
            conn.execute(
                "CREATE TABLE conf_checks (id INTEGER PRIMARY KEY, check_label TEXT)"
            )
            conn.execute("INSERT INTO conf_checks (id, check_label) VALUES (10, 'SMB Signing')")
            conn.execute(
                "CREATE TABLE conf_checks_results (id INTEGER PRIMARY KEY, host_id INTEGER,"
                " check_id INTEGER, secure INTEGER, reasons TEXT)"
            )
            conn.execute(
                "INSERT INTO conf_checks_results (id, host_id, check_id, secure, reasons)"
                " VALUES (1, 1, 10, 0, 'weak')"
            )

        _seed_smb_min(
            db,
            "id INTEGER PRIMARY KEY, ip TEXT",
            "INSERT INTO hosts (id, ip) VALUES (1, '10.0.0.5')",
            (),
            extra_setup=extra,
        )
        mod._read_smb(db)
        err = capsys.readouterr().err.lower()
        assert "[schema]" in err and "conf_checks" in err


# ═══════════════════════════════════════════════════════════════════════════════
# R6.3 Layer 1 — _check_ws_identity: detect workspace recreation via ws_id change
# ═══════════════════════════════════════════════════════════════════════════════

import os
import sqlite3 as _sqlite3


def _make_local_db():
    """Temp local DB with full schema; returns (conn, path)."""
    tf = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tf.close()
    mod = _load_updater()
    conn = _sqlite3.connect(tf.name)
    conn.row_factory = _sqlite3.Row
    mod._init_local_db(conn)
    return mod, conn, tf.name


class TestCheckWsIdentity:
    def test_first_sync_stores_ws_id(self):
        """No previous last_ws_id → stores new ws_id in meta."""
        mod, conn, path = _make_local_db()
        try:
            mod._check_ws_identity(conn, 42)
            row = conn.execute("SELECT value FROM meta WHERE key='last_ws_id'").fetchone()
            assert row is not None and int(row["value"]) == 42
        finally:
            conn.close()
            os.unlink(path)

    def test_same_ws_id_no_warning(self, capsys):
        """Same ws_id as stored → no 'recreated' in stdout/stderr."""
        mod, conn, path = _make_local_db()
        try:
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_ws_id', '7')")
            conn.commit()
            mod._check_ws_identity(conn, 7)
            out = capsys.readouterr()
            assert "recreated" not in (out.out + out.err).lower()
        finally:
            conn.close()
            os.unlink(path)

    def test_different_ws_id_prints_warning(self, capsys):
        """Different ws_id from stored → prints warning containing 'recreated'."""
        mod, conn, path = _make_local_db()
        try:
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_ws_id', '5')")
            conn.commit()
            mod._check_ws_identity(conn, 9)
            out = capsys.readouterr()
            assert "recreated" in (out.out + out.err).lower()
        finally:
            conn.close()
            os.unlink(path)

    def test_different_ws_id_updates_meta(self):
        """After ws_id change, meta stores the new ws_id."""
        mod, conn, path = _make_local_db()
        try:
            conn.execute("INSERT OR REPLACE INTO meta VALUES ('last_ws_id', '5')")
            conn.commit()
            mod._check_ws_identity(conn, 9)
            row = conn.execute("SELECT value FROM meta WHERE key='last_ws_id'").fetchone()
            assert row is not None and int(row["value"]) == 9
        finally:
            conn.close()
            os.unlink(path)
