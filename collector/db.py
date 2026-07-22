"""
Collector database — v2.
Structured storage from nxc workspace SQLite databases.
Replaces line-based storage with normalized tables.
"""
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path("collector.db")
_local = threading.local()


def get_db() -> sqlite3.Connection:
    if not getattr(_local, "conn", None):
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-32768")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        # Unicode case-insensitive contains — handles Cyrillic and other non-ASCII
        conn.create_function("icontains", 2, lambda needle, haystack:
            bool(needle) and (needle or "").casefold() in (haystack or "").casefold()
        )
        # Unicode casefold for a single value — used for guest/DefaultAccount filtering
        conn.create_function("casefold", 1, lambda s: (s or "").casefold())
        _local.conn = conn
    return _local.conn


@contextmanager
def db_cursor():
    conn = get_db()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def init_db():
    with db_cursor() as cur:
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS workspaces (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT UNIQUE NOT NULL,
                created_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                archived_at TEXT DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS hosts (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id     INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                ip               TEXT NOT NULL,
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
                instances        INTEGER,
                operator         TEXT,
                updated_at       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(workspace_id, ip)
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id     INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                proto            TEXT NOT NULL,
                domain           TEXT NOT NULL DEFAULT '',
                username         TEXT NOT NULL DEFAULT '',
                password         TEXT NOT NULL DEFAULT '',
                credtype         TEXT NOT NULL DEFAULT 'plaintext',
                admin_cred       INTEGER DEFAULT 0,
                pillaged_from_ip TEXT,
                pkey             TEXT DEFAULT NULL,
                operator         TEXT,
                updated_at       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(workspace_id, proto, domain, username, password, credtype)
            );

            CREATE TABLE IF NOT EXISTS auth_relations (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                proto         TEXT NOT NULL,
                credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
                host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                relation_type TEXT NOT NULL,
                shell         INTEGER DEFAULT NULL,
                operator      TEXT,
                updated_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(workspace_id, proto, credential_id, host_id, relation_type)
            );

            CREATE TABLE IF NOT EXISTS dpapi_secrets (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                host_ip      TEXT,
                dpapi_type   TEXT,
                windows_user TEXT,
                username     TEXT,
                password     TEXT,
                url          TEXT,
                operator     TEXT,
                updated_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS shares (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                host_id       INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
                credential_id INTEGER REFERENCES credentials(id),
                name          TEXT,
                remark        TEXT,
                read          INTEGER,
                write         INTEGER,
                operator      TEXT,
                updated_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS ssh_keys (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                credential_id INTEGER REFERENCES credentials(id),
                key_data      TEXT,
                operator      TEXT,
                updated_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS conf_checks_results (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                host_id      INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
                check_name   TEXT,
                secure       INTEGER,
                reasons      TEXT,
                operator     TEXT,
                updated_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(workspace_id, host_id, check_name)
            );

            CREATE TABLE IF NOT EXISTS directory_listings (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                proto        TEXT NOT NULL,
                host_ip      TEXT,
                username     TEXT,
                data         TEXT,
                operator     TEXT,
                updated_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_hosts_ws      ON hosts(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_hosts_ip      ON hosts(workspace_id, ip);
            CREATE INDEX IF NOT EXISTS idx_creds_ws      ON credentials(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_creds_proto   ON credentials(workspace_id, proto);
            CREATE INDEX IF NOT EXISTS idx_creds_acred   ON credentials(workspace_id, admin_cred);
            CREATE INDEX IF NOT EXISTS idx_auth_ws       ON auth_relations(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_auth_proto_rel ON auth_relations(workspace_id, proto, relation_type);
            CREATE INDEX IF NOT EXISTS idx_auth_cred     ON auth_relations(credential_id);
            CREATE INDEX IF NOT EXISTS idx_auth_host     ON auth_relations(host_id);
            CREATE INDEX IF NOT EXISTS idx_dpapi_ws      ON dpapi_secrets(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_shares_ws     ON shares(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_confchk_ws    ON conf_checks_results(workspace_id);
            CREATE INDEX IF NOT EXISTS idx_dirlst_ws     ON directory_listings(workspace_id, proto);
        """)

        # Expression-based unique indexes (require SQLite 3.9+)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_dpapi_unique
            ON dpapi_secrets(
                workspace_id,
                COALESCE(host_ip,''),
                COALESCE(dpapi_type,''),
                COALESCE(windows_user,''),
                COALESCE(username,''),
                COALESCE(url,'')
            )
        """)
        cur.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_shares_unique
            ON shares(
                workspace_id,
                COALESCE(host_id,-1),
                COALESCE(credential_id,-1),
                COALESCE(name,'')
            )
        """)

        # Migration: add admin_cred column if not present (added in v2.2)
        try:
            cur.execute("ALTER TABLE credentials ADD COLUMN admin_cred INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        # Migration: add brutforced column for HashKiller integration (v2.3)
        try:
            cur.execute("ALTER TABLE credentials ADD COLUMN brutforced TEXT DEFAULT NULL")
        except sqlite3.OperationalError:
            pass

        # Migration: TZ-compliance v3 (2026-06-03)
        for stmt in [
            "ALTER TABLE workspaces ADD COLUMN archived_at TEXT DEFAULT NULL",
            "ALTER TABLE hosts ADD COLUMN instances INTEGER DEFAULT NULL",
            "ALTER TABLE credentials ADD COLUMN pkey TEXT DEFAULT NULL",
            "ALTER TABLE auth_relations ADD COLUMN shell INTEGER DEFAULT NULL",
        ]:
            try:
                cur.execute(stmt)
            except sqlite3.OperationalError:
                pass

        # Migration: manage-mod hidden flag (v2.4)
        try:
            cur.execute("ALTER TABLE credentials ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        try:
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_creds_hidden"
                " ON credentials(workspace_id, hidden)"
            )
        except sqlite3.OperationalError:
            pass

        # Migration: per-workspace config table (Toolbox module, v2.5)
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS workspace_config (
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                key          TEXT NOT NULL,
                value        TEXT,
                PRIMARY KEY  (workspace_id, key)
            );
        """)

        # Migration: covering index for samlsa credential lookup (v2.6)
        try:
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_auth_cred_ws"
                " ON auth_relations(credential_id, workspace_id)"
            )
        except sqlite3.OperationalError:
            pass

        # Migration: deduplicate directory_listings and add unique constraint (v2.6)
        # Plain INSERT was used previously — existing DBs may have duplicate rows.
        # Remove older duplicates first, then create the UNIQUE index.
        try:
            cur.execute("""
                DELETE FROM directory_listings
                WHERE id NOT IN (
                    SELECT MIN(id)
                    FROM directory_listings
                    GROUP BY workspace_id, proto,
                             COALESCE(host_ip,''), COALESCE(username,'')
                )
            """)
            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_dirlst_unique
                ON directory_listings(
                    workspace_id, proto,
                    COALESCE(host_ip,''), COALESCE(username,'')
                )
            """)
        except sqlite3.OperationalError:
            pass

        # Migration: manage-mod host/dpapi hiding (v2.7)
        for stmt in [
            "ALTER TABLE hosts ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE dpapi_secrets ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0",
        ]:
            try:
                cur.execute(stmt)
            except sqlite3.OperationalError:
                pass
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_hosts_hidden ON hosts(workspace_id, hidden)",
            "CREATE INDEX IF NOT EXISTS idx_dpapi_hidden ON dpapi_secrets(workspace_id, hidden)",
        ]:
            try:
                cur.execute(stmt)
            except sqlite3.OperationalError:
                pass

        # Migration: STRIKE IP — honeypot flag on hosts (v2.9)
        # API-only column: not synced from nxc_updater, not exported.
        # GUARD: do NOT add to sync.py INSERT/UPDATE — managed exclusively via
        #   POST /api/hosts/strike and POST /api/hosts/restore_strike.
        try:
            cur.execute(
                "ALTER TABLE hosts ADD COLUMN honeypot INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass

        # Migration: hidden_by_strike flag on credentials (v2.10)
        # Tracks whether a credential was hidden by strike (vs manually hidden).
        # Enables restore_strike to use hidden_by_strike=1 filter instead of NOT EXISTS,
        # fixing the bug where a credential stuck hidden after gaining a new auth_relation
        # on a non-honeypot host between strike and restore.
        # GUARD: set to 1 only by strike_host_ip and sync.py honeypot auto-hide.
        #   set_hidden (manual) always resets it to 0.
        try:
            cur.execute(
                "ALTER TABLE credentials ADD COLUMN hidden_by_strike INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass

        # Migration: Domain Admin Watchlist (v2.8)
        # Stores uploaded lists of known domain admin usernames per workspace.
        # Values are stored LOWER-cased for case-insensitive matching against credentials.
        # UNIQUE(workspace_id, domain, username) prevents duplicates on re-upload.
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS domain_admin_list (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                domain       TEXT    NOT NULL DEFAULT '',
                username     TEXT    NOT NULL DEFAULT '',
                created_at   TEXT    NOT NULL
                             DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(workspace_id, domain, username)
            );
            CREATE INDEX IF NOT EXISTS idx_dal_ws
                ON domain_admin_list(workspace_id, domain, username);
        """)

        # Migration: Custom Import (v3.0)
        # API-only table — managed exclusively via Toolbox Block 1 import endpoint.
        # GUARD: do NOT add to sync.py or models.py (custom is never synced).
        #   Import/enrichment logic lives in collector/api/toolbox.py (Block 1).
        #   No hidden/hidden_by_strike — custom rows are deleted, not hidden.
        #   brutforced IS used: KILL THEM ALL resolves custom hashes too (v3.2).
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS custom_credentials (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id     INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                proto            TEXT,
                ip               TEXT,
                port             INTEGER,
                domain           TEXT,
                login            TEXT NOT NULL DEFAULT '',
                password         TEXT NOT NULL DEFAULT '',
                credtype         TEXT NOT NULL DEFAULT 'plaintext',
                url              TEXT,
                source           TEXT,
                comment          TEXT,
                created_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                imported_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );
            CREATE INDEX IF NOT EXISTS idx_custom_creds_ws
                ON custom_credentials(workspace_id);
        """)
        # Migration v3.1: drop obsolete columns (never written to, no UI used them).
        for _col in ("hidden", "hidden_by_strike"):
            try:
                cur.execute(f"DROP INDEX IF EXISTS idx_custom_creds_hidden")
                cur.execute(f"ALTER TABLE custom_credentials DROP COLUMN {_col}")
            except Exception:
                pass
        # Migration v3.2: re-add brutforced — KILL THEM ALL now resolves custom hashes too.
        try:
            cur.execute("ALTER TABLE custom_credentials ADD COLUMN brutforced TEXT DEFAULT NULL")
        except Exception:
            pass
        # Drop and recreate: url is now part of the key (different URLs = different credentials).
        # DROP IF EXISTS is safe on fresh DBs; recreate always uses the new definition.
        try:
            cur.execute("DROP INDEX IF EXISTS idx_custom_creds_unique")
            cur.execute("""
                CREATE UNIQUE INDEX idx_custom_creds_unique
                ON custom_credentials(
                    workspace_id,
                    COALESCE(proto,   ''),
                    COALESCE(ip,      ''),
                    COALESCE(port,    -1),
                    COALESCE(domain,  ''),
                    login,
                    password,
                    credtype,
                    COALESCE(url,     '')
                )
            """)
        except sqlite3.OperationalError:
            pass

        # Migration v3.2: local_admin_cred flag — manual marking of machine-local admin pairs.
        try:
            cur.execute(
                "ALTER TABLE credentials ADD COLUMN local_admin_cred INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass

        # Migration R5.1: admin_cred_locked — prevents watchlist/sync from overwriting
        # a manually-cleared admin_cred flag. Set to 1 by set_admin_cred(admin_cred=0);
        # cleared to 0 by set_admin_cred(admin_cred=1). Checked by watchlist enrichment
        # in sync.py and dal.py before auto-setting admin_cred=1.
        # GUARD: managed exclusively via POST /api/credentials/set_admin_cred.
        try:
            cur.execute(
                "ALTER TABLE credentials ADD COLUMN admin_cred_locked INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass

        # Migration v3.4: Recycle bin — soft delete for workspaces.
        # recycled_at IS NOT NULL means workspace is in the recycle bin.
        # GUARD: managed exclusively via DELETE /api/workspaces/{id} (soft) and
        #   DELETE /api/workspaces/{id}/permanent (hard). Do NOT add recycled_at
        #   to any sync, export, or data queries — recycled workspaces are still
        #   accessible by ID but must not appear in active/archive lists.
        try:
            cur.execute("ALTER TABLE workspaces ADD COLUMN recycled_at TEXT DEFAULT NULL")
        except sqlite3.OperationalError:
            pass

        # Migration R6.1: vuln_overrides — user-set tri-state overrides (user > sync priority).
        # Row existence means override is active (is_vulnerable may be 1/0/NULL).
        # GUARD: managed exclusively via POST /api/vulns/set_override.
        # NOT written by sync — sync writes vuln_findings only.
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS vuln_overrides (
                workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                ip            TEXT NOT NULL,
                vuln_name     TEXT NOT NULL,
                is_vulnerable INTEGER,
                PRIMARY KEY (workspace_id, ip, vuln_name)
            );
        """)

        # Migration v3.3: vuln_findings — finding-centric vuln results from collector_dc/hosts
        # (nxc-vulns.db, slug-keyed). One row per (workspace, ip, vuln_name).
        # is_vulnerable is TRI-STATE and nullable: 1=vulnerable, 0=checked-clean, NULL=could-not-check.
        # GUARD: NULL is NOT "safe" — never render/treat it as clean.
        # Synced via /api/sync (data.vuln_findings) with vulnerable-wins UPSERT (1 > 0 > NULL).
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS vuln_findings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                ip            TEXT NOT NULL,
                hostname      TEXT,
                domain        TEXT,
                protocol      TEXT,
                port          INTEGER,
                vuln_name     TEXT NOT NULL,
                is_vulnerable INTEGER,
                details       TEXT,
                operator      TEXT,
                updated_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(workspace_id, ip, vuln_name)
            );
            CREATE INDEX IF NOT EXISTS idx_vuln_findings_ws
                ON vuln_findings(workspace_id, vuln_name);
        """)

        # Migration: notifications — append-only journal of pwn3d + domain_admin events.
        # AUTOINCREMENT (not rowid) so trimmed ids are never reused — clients track
        # "unread" via the monotonic id in localStorage.
        # GUARD: written ONLY by the emission helpers in services/notification_service.py
        #   (called from sync.py and dal.py). No user-facing API mutates this table;
        #   GET /api/notifications is read-only. Retention trims to newest N per workspace.
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS notifications (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                type          TEXT NOT NULL,
                ref_host_id   INTEGER,
                ref_domain    TEXT,
                ref_username  TEXT,
                title         TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_notif_ws ON notifications(workspace_id, id);
        """)

        # timeline_nodes — Reports module TIMELINE. Holds canonical milestone
        # OVERRIDES (<=1 per non-custom kind, enforced by the partial unique index)
        # and CUSTOM nodes. Auto canonical values are computed on read, not stored.
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS timeline_nodes (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id  INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                kind          TEXT NOT NULL,
                label         TEXT,
                ts            TEXT,
                detail        TEXT,
                created_at    TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_ws ON timeline_nodes(workspace_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_timeline_canonical
                ON timeline_nodes(workspace_id, kind) WHERE kind != 'custom';
        """)


def get_or_create_workspace(cur, name: str) -> int:
    # INSERT OR IGNORE handles concurrent syncs racing to create the same workspace.
    cur.execute("INSERT OR IGNORE INTO workspaces(name) VALUES(?)", (name,))
    row = cur.execute("SELECT id FROM workspaces WHERE name=?", (name,)).fetchone()
    return row["id"]
