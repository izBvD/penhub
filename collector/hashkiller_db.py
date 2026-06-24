"""
HashKiller — global hash:plain database.
Separate SQLite file (hashkiller.db), shared across all workspaces.

Schema v2: smart/warning boolean columns; UNIQUE(nt_hash, plaintext) allows
multiple plaintexts per hash with conflict detection via warning flag.
"""
import os
import re
import sqlite3
import tempfile
import threading
import time
import contextlib
from contextlib import contextmanager
from pathlib import Path

from collector.nt_hash import nt_hash

HK_DB_PATH      = Path("hashkiller.db")
_local          = threading.local()
_HEX32          = re.compile(r'^[0-9a-fA-F]{32}$')
_NT_EMPTY       = "31d6cfe0d16ae931b73c59d7e0c089c0"
_EMPTY_PASSWORD = "<empty_password>"


def _get_hk_db() -> sqlite3.Connection:
    if not getattr(_local, "hk_conn", None):
        conn = sqlite3.connect(str(HK_DB_PATH), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
        _local.hk_conn = conn
    return _local.hk_conn


@contextmanager
def _hk_cursor():
    conn = _get_hk_db()
    cur  = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


# ── Schema init & migration ────────────────────────────────────────────────────

def init_hk_db():
    conn = _get_hk_db()
    cur  = conn.cursor()
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hk_pairs'")
        table_exists = bool(cur.fetchone())

        if table_exists:
            cols = {row[1] for row in cur.execute("PRAGMA table_info(hk_pairs)").fetchall()}
            if "smart" not in cols or "warning" not in cols:
                _migrate_v1_to_v2(conn, cur, cols)
        else:
            cur.execute("""
                CREATE TABLE hk_pairs (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    nt_hash        TEXT NOT NULL,
                    plaintext      TEXT NOT NULL,
                    smart          INTEGER NOT NULL DEFAULT 0,
                    warning        INTEGER NOT NULL DEFAULT 0,
                    workspace_name TEXT,
                    added_at       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                    UNIQUE(nt_hash, plaintext)
                )
            """)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_hk_hash ON hk_pairs(nt_hash)")

        # Scaling indexes (idempotent — applied to pre-existing DBs on next startup too).
        # On a large existing DB the first CREATE INDEX runs once at startup (minutes); later no-op.
        # idx_hk_smart: partial — get_smart_pairs(WHERE smart=1) avoids a full-table scan.
        # idx_hk_plain: find/delete by plaintext avoid a full-table scan.
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hk_smart ON hk_pairs(smart) WHERE smart=1")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_hk_plain ON hk_pairs(plaintext)")

        # Persistent stats cache — survives server restarts; invalidated on any hk_pairs write.
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hk_stats (
                key        TEXT PRIMARY KEY,
                value      INTEGER NOT NULL,
                updated_at TEXT NOT NULL
                           DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            )
        """)

        # Seed empty-password canonical pair (idempotent)
        cur.execute(
            "INSERT OR IGNORE INTO hk_pairs(nt_hash, plaintext) VALUES(?,?)",
            (_NT_EMPTY, _EMPTY_PASSWORD),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


def _migrate_v1_to_v2(conn, cur, existing_cols):
    """Migrate v1 (UNIQUE nt_hash, source TEXT) -> v2 (UNIQUE nt_hash+plaintext, smart/warning)."""
    if "source" in existing_cols:
        rows = cur.execute(
            "SELECT nt_hash, plaintext,"
            " CASE WHEN source='smart' THEN 1 ELSE 0 END AS smart,"
            " workspace_name, added_at FROM hk_pairs"
        ).fetchall()
    else:
        rows = cur.execute(
            "SELECT nt_hash, plaintext, COALESCE(smart,0) AS smart,"
            " workspace_name, added_at FROM hk_pairs"
        ).fetchall()
    cur.execute("DROP TABLE IF EXISTS hk_pairs")
    cur.execute("""
        CREATE TABLE hk_pairs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            nt_hash        TEXT NOT NULL,
            plaintext      TEXT NOT NULL,
            smart          INTEGER NOT NULL DEFAULT 0,
            warning        INTEGER NOT NULL DEFAULT 0,
            workspace_name TEXT,
            added_at       TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            UNIQUE(nt_hash, plaintext)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hk_hash ON hk_pairs(nt_hash)")
    cur.executemany(
        "INSERT OR IGNORE INTO hk_pairs"
        "(nt_hash,plaintext,smart,warning,workspace_name,added_at) VALUES(?,?,?,0,?,?)",
        [(r[0], r[1], r[2], r[3], r[4]) for r in rows],
    )
    conn.commit()


# ── Normalization & parsing ────────────────────────────────────────────────────

def normalize_nt_hash(raw: str) -> "str | None":
    if not raw:
        return None
    h = raw.strip().lower()
    return h if _HEX32.match(h) else None


def extract_nt_hash(raw: str) -> "str | None":
    """
    Extract NT hash from credential password field.
    Handles plain 32-hex AND LM:NT (SAM dump) format.
    Returns None for the empty hash (those creds are normalised to plaintext already).
    """
    if not raw:
        return None
    raw   = raw.strip()
    parts = raw.split(":")
    if len(parts) == 2 and _HEX32.match(parts[0]) and _HEX32.match(parts[1]):
        nh = parts[1].lower()
    else:
        nh = normalize_nt_hash(raw)
    if nh is None or nh == _NT_EMPTY:
        return None
    return nh


def parse_line(line: str) -> "tuple | None":
    """
    Parse a hash:plain line.
    Supports: HASH:PLAIN, LM:NT:PLAIN, $NT$HASH:PLAIN
    Empty NT hash -> (nt_empty, <empty_password>).
    Returns (nt_hash_lower, plaintext) or None.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if line.upper().startswith("$NT$"):
        rest = line[4:]
        idx  = rest.find(":")
        if idx < 0:
            return None
        nh = normalize_nt_hash(rest[:idx])
        if nh is None:
            return None
        plain = rest[idx + 1:]
        return (nh, _EMPTY_PASSWORD if nh == _NT_EMPTY else plain)

    parts = line.split(":")

    def is32(s: str) -> bool:
        return bool(_HEX32.match(s))

    if not is32(parts[0]):
        return None

    if len(parts) >= 2 and is32(parts[1]):
        nh    = parts[1].lower()
        plain = ":".join(parts[2:])
    else:
        nh    = parts[0].lower()
        plain = ":".join(parts[1:])

    if not _HEX32.match(nh):
        return None
    return (nh, _EMPTY_PASSWORD if nh == _NT_EMPTY else plain)


# ── Import ─────────────────────────────────────────────────────────────────────

# Commit every N processed pairs — amortizes fsync without growing the WAL unbounded.
# Batch boundaries don't change the outcome: within one connection each SELECT still sees
# all prior inserts (committed or not), so conflict detection is identical to a single txn.
_IMPORT_BATCH = 5000


def _import_pairs(pairs_iter) -> dict:
    """
    Core import: insert (nt_hash, plaintext) pairs with conflict detection.
    Accepts any iterable/iterator (lazy generator OK — bounded memory for huge inputs).
    Conflict (same hash, different plaintext) -> both get warning=1.
    Returns {added, skipped, warned}. `invalid` (unparseable lines) is the caller's concern.
    """
    added = warned = seen = 0
    with _hk_cursor() as cur:
        for nh, plain in pairs_iter:
            seen += 1
            existing = cur.execute(
                "SELECT id, plaintext FROM hk_pairs WHERE nt_hash=?", (nh,)
            ).fetchall()
            if existing:
                if any(e["plaintext"] == plain for e in existing):
                    continue
                cur.execute("UPDATE hk_pairs SET warning=1 WHERE nt_hash=?", (nh,))
                cur.execute(
                    "INSERT OR IGNORE INTO hk_pairs(nt_hash,plaintext,warning) VALUES(?,?,1)",
                    (nh, plain),
                )
                if cur.rowcount > 0:
                    warned += 1
            else:
                cur.execute(
                    "INSERT OR IGNORE INTO hk_pairs(nt_hash,plaintext) VALUES(?,?)",
                    (nh, plain),
                )
                if cur.rowcount > 0:
                    added += 1
            if seen % _IMPORT_BATCH == 0:
                cur.connection.commit()

    _invalidate_stats()  # after commit — single chokepoint for all import/upload paths
    skipped = seen - added - warned
    return {"added": added, "skipped": max(skipped, 0), "warned": warned}


# Fast bulk insert: executemany INSERT OR IGNORE in large batches.
_BULK_BATCH = 50_000

# Bulk-load tuning applied ONLY during a bulk import, then restored. These are CAPPED
# amounts (not "all RAM"): a bigger page cache keeps more of the index hot so INSERT OR
# IGNORE re-reads fewer disk pages on a large DB. Tune here if you want a different cap.
_BULK_CACHE_KIB  = 256 * 1024          # 256 MB SQLite page cache (lazily allocated)
_BULK_MMAP_BYTES = 256 * 1024 * 1024   # 256 MB memory-mapped reads

# RAM-killer mode: size the cache to most of the FREE RAM, but always leave headroom so the
# host stays alive. Hard ceiling caps silly values on huge servers.
_RAM_KILLER_HEADROOM = 1024 * 1024 * 1024   # keep at least 1 GB free
_RAM_KILLER_FRACTION = 0.7                   # of (available - headroom)
_RAM_KILLER_CEILING_KIB = 24 * 1024 * 1024   # never exceed 24 GB cache


def _available_ram_bytes() -> "int | None":
    """Best-effort free RAM (Linux /proc/meminfo, Windows GlobalMemoryStatusEx). None if unknown."""
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    try:
        import ctypes

        class _MEMSTAT(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        m = _MEMSTAT()
        m.dwLength = ctypes.sizeof(_MEMSTAT)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
            return int(m.ullAvailPhys)
    except Exception:
        pass
    return None


def _ram_killer_cache_kib() -> int:
    """Cache size (KiB) for RAM-killer mode: a big slice of free RAM, never below the safe
    default, never above the ceiling, always leaving headroom. Falls back to the safe cap
    if free RAM can't be determined."""
    avail = _available_ram_bytes()
    if not avail:
        return _BULK_CACHE_KIB
    usable = max(avail - _RAM_KILLER_HEADROOM, 0)
    target_kib = int(usable * _RAM_KILLER_FRACTION) // 1024
    return max(_BULK_CACHE_KIB, min(target_kib, _RAM_KILLER_CEILING_KIB))


def _bulk_insert_pairs(pairs_iter, cache_kib=None, mmap_bytes=None) -> dict:
    """
    Fast path for huge potfiles: executemany INSERT OR IGNORE in big batches, with NO
    per-row SELECT. On a large existing DB the per-row conflict SELECT in _import_pairs is
    an index seek per row (disk-bound) — the dominant cost; this avoids all of them.

    Conflicting plaintexts are still stored (UNIQUE is on (nt_hash, plaintext), so a second
    plaintext for the same hash is a new row, not an ignored dup). The stored `warning` flag
    is NOT stamped, but nothing reads it: get_stats / get_warning_pairs / bulk_lookup /
    find_pairs all derive warning live via COUNT(*). So every read behaves identically to the
    precise path — only the vestigial stored flag differs.

    Returns {added, skipped}. `added` = rows actually inserted (via conn.total_changes);
    `skipped` = exact duplicates ignored.
    """
    cache_kib  = cache_kib  if cache_kib  is not None else _BULK_CACHE_KIB
    mmap_bytes = mmap_bytes if mmap_bytes is not None else _BULK_MMAP_BYTES
    conn = _get_hk_db()
    # Bulk-load tuning (restored in finally so the memory isn't held permanently).
    old_cache = conn.execute("PRAGMA cache_size").fetchone()[0]
    old_mmap  = conn.execute("PRAGMA mmap_size").fetchone()[0]
    conn.execute(f"PRAGMA cache_size = {-cache_kib}")  # negative => KiB
    conn.execute(f"PRAGMA mmap_size = {mmap_bytes}")

    before = conn.total_changes
    seen   = 0
    batch: list = []
    sql = "INSERT OR IGNORE INTO hk_pairs(nt_hash,plaintext) VALUES(?,?)"
    try:
        with _hk_cursor() as cur:
            for pair in pairs_iter:
                batch.append(pair)
                seen += 1
                if len(batch) >= _BULK_BATCH:
                    cur.executemany(sql, batch)
                    batch.clear()
                    cur.connection.commit()
            if batch:
                cur.executemany(sql, batch)
    finally:
        conn.execute(f"PRAGMA cache_size = {old_cache}")
        conn.execute(f"PRAGMA mmap_size = {old_mmap}")

    _invalidate_stats()  # after commit
    added = conn.total_changes - before
    return {"added": added, "skipped": max(seen - added, 0)}


def bulk_import(text: str) -> dict:
    """
    Import hash:plain pairs from text (pot/txt).
    Conflict (same hash, different plaintext) -> both get warning=1.
    Returns {added, skipped, warned, invalid, total_lines}.
    total_lines = non-blank, non-comment lines considered (valid + invalid).
    """
    pairs:   list = []
    invalid: int  = 0
    for line in text.splitlines():
        result = parse_line(line)
        if result is None:
            s = line.strip()
            if s and not s.startswith("#"):
                invalid += 1
        else:
            pairs.append(result)

    result = _import_pairs(pairs)
    result["invalid"] = invalid
    result["total_lines"] = len(pairs) + invalid
    return result


# ── Upload / merge another HK DB ───────────────────────────────────────────────

def merge_db_file(src_path) -> dict:
    """
    Merge hk_pairs from another hashkiller.db at `src_path` into the current DB.
    Source rows are streamed via a lazy cursor (never materialised — large-DB safe);
    insertion reuses the shared import core, so conflict/counting semantics are identical
    to bulk_import. Returns {added, skipped, warned}. Raises ValueError if hk_pairs is absent.
    """
    src = sqlite3.connect(str(src_path))
    src.row_factory = sqlite3.Row
    try:
        try:
            src.execute("SELECT 1 FROM hk_pairs LIMIT 1")
        except Exception:
            raise ValueError("Invalid hashkiller DB: hk_pairs table not found")

        def _src_pairs():
            for row in src.execute("SELECT nt_hash, plaintext FROM hk_pairs"):
                yield (row["nt_hash"], row["plaintext"])

        # _import_pairs fully consumes the generator before returning, so src stays open
        # for the whole merge and is closed in the finally below.
        return _import_pairs(_src_pairs())
    finally:
        src.close()


def upload_db(db_bytes: bytes) -> dict:
    """
    Merge another hashkiller.db from raw bytes (non-destructive enrichment).
    Conflicts -> warning=1 on both records, both kept. Returns {added, skipped, warned}.
    """
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    try:
        tf.write(db_bytes)
        tf.close()
        return merge_db_file(tf.name)
    finally:
        os.unlink(tf.name)


# ── Server-side file import (hk_inbox) ──────────────────────────────────────────
# Operators drop a large .potfile here (scp/rsync/direct disk) and trigger import from
# the UI — no 30GB HTTP upload. SECURITY: the path is hardcoded server-side; the client
# never supplies a path, which eliminates path traversal. Defense-in-depth below adds
# symlink rejection, containment and regular-file checks.

HK_INBOX_DIR  = Path("hk_inbox")
HK_INBOX_FILE = "large.potfile"


def ensure_inbox_dir():
    """Create the inbox directory if missing (idempotent). Called at startup."""
    HK_INBOX_DIR.mkdir(parents=True, exist_ok=True)


def _resolve_inbox_file() -> Path:
    """Resolve and security-check the fixed inbox file. Raises ValueError if missing/unsafe."""
    base = HK_INBOX_DIR.resolve()
    target = HK_INBOX_DIR / HK_INBOX_FILE
    if target.is_symlink():
        raise ValueError("inbox file must not be a symlink")
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise ValueError("inbox file escapes the inbox directory")
    if not resolved.is_file():
        raise ValueError("inbox file not found")
    return resolved


def inbox_file_status() -> dict:
    """Pre-import status for the UI: {exists, name, size} or {exists: False}."""
    try:
        p = _resolve_inbox_file()
    except ValueError:
        return {"exists": False}
    return {"exists": True, "name": HK_INBOX_FILE, "size": p.stat().st_size}


def import_inbox_file(progress_cb=None, ram_killer=False) -> dict:
    """
    Stream-import the fixed inbox file into hk_pairs (bounded memory — read line by line).
    Uses the fast bulk path (no per-row SELECT) — built for multi-GB potfiles.
    ram_killer=True sizes the page cache to most of the free RAM (with headroom) for max
    speed on a large disk-bound DB; otherwise a 256 MB cap is used.
    Returns {added, skipped, invalid, seconds, rate, ram_mb}. Conflicts are not counted
    per-import but are still detected live everywhere (stats / EXPORT WARNING / bulk_lookup
    derive warning via COUNT). progress_cb(bytes_done, bytes_total) -> return True to cancel.
    """
    p     = _resolve_inbox_file()
    total = p.stat().st_size
    invalid   = 0
    cancelled = False

    def _pairs():
        nonlocal invalid, cancelled
        read = 0
        with open(p, "rb") as fh:
            for i, raw in enumerate(fh, 1):
                read += len(raw)
                line   = raw.decode("utf-8", errors="replace")
                result = parse_line(line)
                if result is None:
                    s = line.strip()
                    if s and not s.startswith("#"):
                        invalid += 1
                else:
                    yield result
                if progress_cb and i % _IMPORT_BATCH == 0:
                    if progress_cb(min(read, total), total):
                        cancelled = True
                        return

    cache_kib  = _ram_killer_cache_kib() if ram_killer else _BULK_CACHE_KIB
    mmap_bytes = cache_kib * 1024

    t0 = time.perf_counter()
    result = _bulk_insert_pairs(_pairs(), cache_kib=cache_kib, mmap_bytes=mmap_bytes)
    elapsed = time.perf_counter() - t0
    result["invalid"] = invalid
    result["seconds"] = round(elapsed, 1)
    result["rate"] = round((result["added"] + result["skipped"]) / elapsed) if elapsed > 0 else 0
    result["ram_mb"] = round(cache_kib / 1024)
    if progress_cb and not cancelled:
        progress_cb(total, total)
    if cancelled:
        result["cancelled"] = True
    return result


# ── Lookup ─────────────────────────────────────────────────────────────────────

# Chunk size for IN-clause lookups: stays under the oldest SQLITE_MAX_VARIABLE_NUMBER (999),
# so the query never fails regardless of SQLite build, even for huge workspaces.
_LOOKUP_CHUNK = 900


def bulk_lookup(nt_hashes: set) -> dict:
    """Lookup hashes. Returns {nt_hash: plaintext}. Skips hashes with multiple plaintexts (conflicts)."""
    if not nt_hashes:
        return {}
    normalized = {normalize_nt_hash(h) for h in nt_hashes if h}
    normalized.discard(None)
    if not normalized:
        return {}
    norm_list = list(normalized)
    result: dict = {}
    # GUARD: HAVING COUNT(*) = 1 filters conflicting hashes from actual data —
    # the stored warning flag goes stale after deletions, so we don't read it here.
    # Chunked to stay under the SQL variable limit; each nt_hash falls in exactly one
    # chunk and its full row count is grouped there, so merging chunk results is correct.
    with _hk_cursor() as cur:
        for i in range(0, len(norm_list), _LOOKUP_CHUNK):
            chunk = norm_list[i:i + _LOOKUP_CHUNK]
            ph = ",".join("?" * len(chunk))
            rows = cur.execute(
                f"SELECT nt_hash, plaintext FROM hk_pairs"
                f" WHERE nt_hash IN ({ph}) GROUP BY nt_hash HAVING COUNT(*) = 1",
                chunk,
            ).fetchall()
            for r in rows:
                result[r["nt_hash"]] = r["plaintext"]
    return result


# ── Find (pre-delete confirmation) ────────────────────────────────────────────

_FIND_SQL = """
    SELECT p.nt_hash, p.plaintext, p.smart,
           CASE WHEN c.cnt > 1 THEN 1 ELSE 0 END AS warning
    FROM hk_pairs p
    JOIN (SELECT nt_hash, COUNT(*) AS cnt FROM hk_pairs GROUP BY nt_hash) c
      ON c.nt_hash = p.nt_hash
    WHERE p.{col} = ?
"""
# GUARD: warning is derived live (cnt > 1) — not read from the stored flag,
# which goes stale after deletions without recalculation.


def find_pairs(value: str) -> dict:
    """Find pairs by value for delete-confirmation UI."""
    value = (value or "").strip()
    if not value:
        return {"by_hash": [], "by_plain": [], "query_type": "none"}

    parsed = parse_line(value)
    if parsed:
        nh, _ = parsed
        with _hk_cursor() as cur:
            rows = cur.execute(_FIND_SQL.format(col="nt_hash"), (nh,)).fetchall()
        return {"by_hash": [dict(r) for r in rows], "by_plain": [], "query_type": "hash_plain"}

    by_hash = []
    nh = normalize_nt_hash(value)
    if nh:
        with _hk_cursor() as cur:
            rows = cur.execute(_FIND_SQL.format(col="nt_hash"), (nh,)).fetchall()
        by_hash = [dict(r) for r in rows]

    with _hk_cursor() as cur:
        rows = cur.execute(_FIND_SQL.format(col="plaintext"), (value,)).fetchall()
    by_plain = [dict(r) for r in rows]

    return {"by_hash": by_hash, "by_plain": by_plain, "query_type": "value"}


# ── Delete ─────────────────────────────────────────────────────────────────────

def _delete_one(cur, value: str) -> int:
    """Delete for a single value on an open cursor (no commit/invalidate here).
    hash:plain or bare hash -> all rows for that nt_hash; otherwise -> by plaintext."""
    value = (value or "").strip()
    if not value:
        return 0
    parsed = parse_line(value)
    if parsed:
        nh, _ = parsed
        cur.execute("DELETE FROM hk_pairs WHERE nt_hash=?", (nh,))
        return cur.rowcount
    nh = normalize_nt_hash(value)
    if nh:
        cur.execute("DELETE FROM hk_pairs WHERE nt_hash=?", (nh,))
    else:
        cur.execute("DELETE FROM hk_pairs WHERE plaintext=?", (value,))
    return cur.rowcount


def delete_by_value(value: str) -> int:
    with _hk_cursor() as cur:
        deleted = _delete_one(cur, value)
    _invalidate_stats(full=True)  # deletes can resolve conflicts — warning must be exact
    return deleted


def delete_from_lines(lines_iter) -> dict:
    """Bulk delete: apply delete_by_value semantics to each line in ONE transaction.
    Each line is `hash:plain`, a bare hash, or a plaintext. Blank/`#` lines are skipped.
    Built for re-feeding an EXPORT WARNING file to clear many conflicts at once.
    Returns {deleted, lines} (lines = non-blank/non-comment lines processed)."""
    deleted = 0
    lines = 0
    with _hk_cursor() as cur:
        for raw in lines_iter:
            s = (raw or "").strip()
            if not s or s.startswith("#"):
                continue
            lines += 1
            deleted += _delete_one(cur, s)
    _invalidate_stats(full=True)  # deletes can resolve conflicts — warning must be exact
    return {"deleted": deleted, "lines": lines}


# ── Stats & export ─────────────────────────────────────────────────────────────

# Two-level cache for HK statistics:
#   L1 — _stats_cache / _warning_cache: in-memory, lost on restart (fastest path).
#   L2 — hk_stats table: persisted to hashkiller.db, survives restarts.
# On mutation: total/smart are cleared at both levels (cheap to recompute).
# warning L1 (_warning_cache) is cleared, but L2 (hk_stats) is intentionally kept —
# its GROUP BY costs ~4 min on large DBs; stale-but-instant beats blocking on every import.
# NOTE: kill_workspace does NOT invalidate — writes to collector.db, not hk_pairs.
_stats_cache   = None   # {total, smart}
_warning_cache = None   # int


def _load_cached_stats(keys: list) -> "dict | None":
    """Read stat values from the hk_stats table. Returns None if any key is absent."""
    try:
        conn = _get_hk_db()
        ph   = ",".join("?" * len(keys))
        rows = conn.execute(
            f"SELECT key, value FROM hk_stats WHERE key IN ({ph})", keys
        ).fetchall()
        if len(rows) < len(keys):
            return None
        return {r["key"]: r["value"] for r in rows}
    except Exception:
        return None


def _save_cached_stats(values: dict):
    """Upsert stat values into the hk_stats table."""
    with contextlib.suppress(Exception):
        with _hk_cursor() as cur:
            for k, v in values.items():
                cur.execute(
                    "INSERT OR REPLACE INTO hk_stats(key, value) VALUES(?,?)",
                    (k, int(v)),
                )


def _invalidate_stats(full: bool = False):
    global _stats_cache, _warning_cache
    _stats_cache   = None
    _warning_cache = None
    with contextlib.suppress(Exception):
        with _hk_cursor() as cur:
            if full:
                # Deletes can resolve conflicts — warning count must reflect current state.
                cur.execute("DELETE FROM hk_stats")
            else:
                # Imports only add pairs — warning can only grow; stale (lower) value is safe.
                # Keep warning in hk_stats to avoid a 4-min GROUP BY on next request.
                cur.execute("DELETE FROM hk_stats WHERE key IN ('total', 'smart')")


def get_stats() -> dict:
    """Return {total, smart}. Fast — COUNT with idx_hk_smart. Persisted to hk_stats."""
    global _stats_cache
    if _stats_cache is not None:
        return dict(_stats_cache)
    cached = _load_cached_stats(["total", "smart"])
    if cached:
        _stats_cache = cached
        return dict(_stats_cache)
    conn  = _get_hk_db()
    total = conn.execute("SELECT COUNT(*) FROM hk_pairs").fetchone()[0]
    smart = conn.execute("SELECT COUNT(*) FROM hk_pairs WHERE smart=1").fetchone()[0]
    _stats_cache = {"total": total, "smart": smart}
    _save_cached_stats(_stats_cache)
    return dict(_stats_cache)


def get_warning_count() -> int:
    """Return count of rows belonging to hashes with >1 plaintext.
    Expensive (full-table GROUP BY); cached to hk_stats. Called lazily by a dedicated
    endpoint — the UI fetches it separately so fast stats appear without waiting.

    GUARD: uses live COUNT(*) GROUP BY, not the stored warning flag — the flag goes stale
    after deletions without recalculation (bulk path never stamps it either).
    """
    global _warning_cache
    if _warning_cache is not None:
        return _warning_cache
    cached = _load_cached_stats(["warning"])
    if cached:
        _warning_cache = cached["warning"]
        return _warning_cache
    conn = _get_hk_db()
    warning = conn.execute("""
        SELECT COUNT(*) FROM hk_pairs
        WHERE nt_hash IN (
            SELECT nt_hash FROM hk_pairs GROUP BY nt_hash HAVING COUNT(*) > 1
        )
    """).fetchone()[0]
    _warning_cache = warning
    _save_cached_stats({"warning": warning})
    return _warning_cache


def get_smart_pairs() -> list:
    with _hk_cursor() as cur:
        rows = cur.execute(
            "SELECT nt_hash, plaintext FROM hk_pairs WHERE smart=1 ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def get_warning_pairs() -> list:
    # GUARD: returns rows where the hash actually has >1 plaintext right now —
    # not WHERE warning=1, which goes stale after deletions without recalculation.
    with _hk_cursor() as cur:
        rows = cur.execute("""
            SELECT nt_hash, plaintext FROM hk_pairs
            WHERE nt_hash IN (
                SELECT nt_hash FROM hk_pairs GROUP BY nt_hash HAVING COUNT(*) > 1
            )
            ORDER BY nt_hash, id
        """).fetchall()
    return [dict(r) for r in rows]


# ── Kill them all ──────────────────────────────────────────────────────────────

def kill_workspace(workspace_id: int, progress_cb=None) -> dict:
    """
    Fill brutforced for uncracked hash credentials in workspace — both the synced
    `credentials` table AND `custom_credentials` (Toolbox import).
    progress_cb(current, total) -> return True to cancel.
    """
    from collector.db import db_cursor

    with db_cursor() as cur:
        cred_rows = cur.execute("""
            SELECT id, password FROM credentials
            WHERE workspace_id=? AND credtype='hash' AND brutforced IS NULL
        """, (workspace_id,)).fetchall()
        custom_rows = cur.execute("""
            SELECT id, password FROM custom_credentials
            WHERE workspace_id=? AND credtype='hash' AND brutforced IS NULL
        """, (workspace_id,)).fetchall()

    total = len(cred_rows) + len(custom_rows)
    if total == 0:
        if progress_cb:
            progress_cb(0, 0)
        return {"matched": 0, "updated": 0}

    if progress_cb:
        progress_cb(0, total)

    # hash -> ids, kept per table so each is updated in its own table.
    cred_hash_to_ids:   dict = {}
    custom_hash_to_ids: dict = {}
    for r in cred_rows:
        nh = extract_nt_hash(r["password"])
        if nh:
            cred_hash_to_ids.setdefault(nh, []).append(r["id"])
    for r in custom_rows:
        nh = extract_nt_hash(r["password"])
        if nh:
            custom_hash_to_ids.setdefault(nh, []).append(r["id"])

    all_hashes = set(cred_hash_to_ids) | set(custom_hash_to_ids)
    if not all_hashes:
        if progress_cb:
            progress_cb(total, total)
        return {"matched": 0, "updated": 0}

    found = bulk_lookup(all_hashes)
    if not found:
        if progress_cb:
            progress_cb(total, total)
        return {"matched": 0, "updated": 0}

    matched   = len(found)
    updated   = 0
    cancelled = False

    with db_cursor() as cur:
        for i, (nh, plain) in enumerate(found.items()):
            for cred_id in cred_hash_to_ids.get(nh, []):
                cur.execute("UPDATE credentials SET brutforced=? WHERE id=?", (plain, cred_id))
                updated += cur.rowcount
            for cred_id in custom_hash_to_ids.get(nh, []):
                cur.execute("UPDATE custom_credentials SET brutforced=? WHERE id=?", (plain, cred_id))
                updated += cur.rowcount
            if progress_cb and progress_cb(i + 1, matched):
                cancelled = True
                break

    result = {"matched": matched, "updated": updated}
    if cancelled:
        result["cancelled"] = True
    return result


def kill_all_workspaces(progress_cb=None) -> dict:
    """Kill them all across every workspace. progress_cb(ws_index, ws_total)."""
    from collector.db import db_cursor

    with db_cursor() as cur:
        workspaces = cur.execute("SELECT id, name FROM workspaces").fetchall()

    total = len(workspaces)
    results: dict = {}
    total_matched = total_updated = 0

    for i, ws in enumerate(workspaces):
        if progress_cb and progress_cb(i, total):
            break
        stats = kill_workspace(ws["id"])
        results[ws["name"]]  = stats
        total_matched       += stats["matched"]
        total_updated       += stats["updated"]

    if progress_cb:
        progress_cb(total, total)

    return {"workspaces": results, "total_matched": total_matched, "total_updated": total_updated}


def auto_lookup_workspace(workspace_id: int):
    try:
        kill_workspace(workspace_id)
    except Exception:
        pass


def sync_brutforced(workspace_id: int) -> dict:
    """Clear brutforced entries whose source plain was deleted from HK.

    Compares every non-NULL brutforced value in credentials/custom_credentials
    against current hk_pairs.plaintext; removes any that no longer exist.
    Returns {"cleared": N}.
    """
    from collector.db import db_cursor

    with db_cursor() as cur:
        cred_plains = {r["brutforced"] for r in cur.execute(
            "SELECT DISTINCT brutforced FROM credentials"
            " WHERE workspace_id=? AND brutforced IS NOT NULL",
            (workspace_id,),
        ).fetchall()}
        custom_plains = {r["brutforced"] for r in cur.execute(
            "SELECT DISTINCT brutforced FROM custom_credentials"
            " WHERE workspace_id=? AND brutforced IS NOT NULL",
            (workspace_id,),
        ).fetchall()}

    all_plains = cred_plains | custom_plains
    if not all_plains:
        return {"cleared": 0}

    placeholders = ",".join("?" * len(all_plains))
    with _hk_cursor() as hk_cur:
        existing = {r["plaintext"] for r in hk_cur.execute(
            f"SELECT DISTINCT plaintext FROM hk_pairs WHERE plaintext IN ({placeholders})",
            list(all_plains),
        ).fetchall()}

    stale = all_plains - existing
    if not stale:
        return {"cleared": 0}

    cleared = 0
    with db_cursor() as cur:
        for plain in stale:
            cur.execute(
                "UPDATE credentials SET brutforced=NULL WHERE workspace_id=? AND brutforced=?",
                (workspace_id, plain),
            )
            cleared += cur.rowcount
            cur.execute(
                "UPDATE custom_credentials SET brutforced=NULL WHERE workspace_id=? AND brutforced=?",
                (workspace_id, plain),
            )
            cleared += cur.rowcount

    return {"cleared": cleared}


# ── SMART enrichment ───────────────────────────────────────────────────────────

def _insert_smart_pair(cur, nh: str, plain: str, workspace_name: str) -> tuple:
    """
    Insert one verified (nt_hash, plaintext) pair as smart=1.
    Returns (added, skipped): added=1 on new row, skipped=1 if the pair already exists.
    Conflict (same hash, different plaintext) stamps warning=1 on the hash.
    """
    if cur.execute(
        "SELECT 1 FROM hk_pairs WHERE nt_hash=? AND plaintext=?", (nh, plain)
    ).fetchone():
        return 0, 1
    conflict = cur.execute(
        "SELECT 1 FROM hk_pairs WHERE nt_hash=? AND plaintext!=?", (nh, plain)
    ).fetchone()
    if conflict:
        cur.execute("UPDATE hk_pairs SET warning=1 WHERE nt_hash=?", (nh,))
        cur.execute(
            "INSERT OR IGNORE INTO hk_pairs"
            "(nt_hash,plaintext,smart,warning,workspace_name) VALUES(?,?,1,1,?)",
            (nh, plain, workspace_name),
        )
    else:
        cur.execute(
            "INSERT OR IGNORE INTO hk_pairs"
            "(nt_hash,plaintext,smart,workspace_name) VALUES(?,?,1,?)",
            (nh, plain, workspace_name),
        )
    return (cur.rowcount or 0), 0


def smart_enrich_workspace(workspace_id: int, workspace_name: str = "",
                            progress_cb=None) -> dict:
    """
    SMART ENRICH for a single workspace — plaintext enrichment.

    Every distinct non-bruteforced plaintext password in the workspace
    (credentials + custom_credentials, credtype='plaintext') is hashed to its NT
    hash locally (collector/nt_hash.py) and recorded as a smart pair. Because the
    NT hash is computed from the plaintext, every recorded pair is correct by
    construction — there is no host+login heuristic to verify or reject.
    Empty / sentinel passwords are skipped; brutforced (HK-cracked) values are NOT
    a source — only genuine plaintext.

    Returns {added, skipped}.
    """
    from collector.db import db_cursor

    if progress_cb:
        progress_cb(0, 1)

    pairs: set = set()
    with db_cursor() as cur:
        for r in cur.execute("""
            SELECT DISTINCT password AS p FROM credentials
             WHERE workspace_id=? AND credtype='plaintext'
               AND password NOT IN ('', ?)
            UNION
            SELECT DISTINCT password AS p FROM custom_credentials
             WHERE workspace_id=? AND credtype='plaintext'
               AND password NOT IN ('', ?)
        """, (workspace_id, _EMPTY_PASSWORD, workspace_id, _EMPTY_PASSWORD)).fetchall():
            plain = r["p"]
            pairs.add((nt_hash(plain), plain))

    added = skipped = 0
    with _hk_cursor() as cur:
        for nh, plain in pairs:
            a, s = _insert_smart_pair(cur, nh, plain, workspace_name)
            added += a
            skipped += s

    _invalidate_stats()  # after commit
    if progress_cb:
        progress_cb(1, 1)

    return {"added": added, "skipped": skipped}
