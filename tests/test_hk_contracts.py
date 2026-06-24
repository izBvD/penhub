"""
Characterization tests for HashKiller — Step 0 of the heavy-DB scaling plan
(hashkiller-scaling-plan.md).

These pin the CURRENT public contracts of collector.hashkiller_db so the scaling
refactor (streaming import, lookup chunking, indexes, stats cache) can be proven
not to change behaviour: each test is green on today's code and must stay green
after every refactor step.

Contracts already pinned elsewhere (not duplicated here):
  - live-warning semantics of get_stats / get_warning_pairs / bulk_lookup after
    DELETE  → tests/test_smoke.py
  - smart_enrich skip/insert semantics                → tests/test_core.py

Shared session DB: every test uses dedicated test-only hashes and removes them in
`finally`, so it leaves no lingering conflicts that could perturb other tests.
"""

import os
import sqlite3
import tempfile

import pytest

import collector.hashkiller_db as hk_db

# Dedicated 32-hex NT hashes used only by these tests.
H1 = "11111111111111111111111111111111"
H2 = "22222222222222222222222222222222"
H3 = "33333333333333333333333333333333"
H4 = "44444444444444444444444444444444"
H5 = "55555555555555555555555555555555"
H6 = "66666666666666666666666666666666"

_ALL_HASHES = (H1, H2, H3, H4, H5, H6)


@pytest.fixture(autouse=True)
def _hk_ready():
    """Ensure schema exists and our test hashes are clean before and after each test."""
    hk_db.init_hk_db()
    for h in _ALL_HASHES:
        hk_db.delete_by_value(h)
    yield
    for h in _ALL_HASHES:
        hk_db.delete_by_value(h)


def _make_source_db_bytes(rows) -> bytes:
    """Build a minimal hashkiller-shaped sqlite DB containing `rows` and return its bytes.
    upload_db only reads `SELECT nt_hash, plaintext FROM hk_pairs`, so a 2-column table suffices."""
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tf.close()
    try:
        con = sqlite3.connect(tf.name)
        con.execute("CREATE TABLE hk_pairs (nt_hash TEXT, plaintext TEXT)")
        con.executemany("INSERT INTO hk_pairs(nt_hash, plaintext) VALUES(?,?)", rows)
        con.commit()
        con.close()
        with open(tf.name, "rb") as fh:
            return fh.read()
    finally:
        os.unlink(tf.name)


# ── bulk_import contract ─────────────────────────────────────────────────────

def test_bulk_import_counts_mixed_input():
    """{added, skipped, warned, invalid} on a deterministic mixed input.

    Trace on current code (H1 clean at start):
      H1:passA  -> new hash                 -> added
      H1:passA  -> same hash + same plain   -> skipped
      H1:passB  -> same hash + diff plain   -> warned (existing row also flagged)
      nothex    -> not 32-hex, not a comment-> invalid
      #comment  -> ignored
    """
    text = "\n".join([f"{H1}:passA", f"{H1}:passA", f"{H1}:passB", "nothex", "#comment"])
    result = hk_db.bulk_import(text)
    # total_lines = 3 valid pairs + 1 invalid; comment excluded
    assert result == {"added": 1, "skipped": 1, "warned": 1, "invalid": 1, "total_lines": 4}


def test_bulk_import_is_idempotent():
    """Re-importing the exact same pair adds nothing (UNIQUE + INSERT OR IGNORE)."""
    first = hk_db.bulk_import(f"{H2}:hunter2")
    assert first["added"] == 1
    second = hk_db.bulk_import(f"{H2}:hunter2")
    assert second["added"] == 0
    assert second["skipped"] == 1


def test_import_pairs_accepts_generator_and_batches():
    """Step 3: the streaming core consumes a lazy generator (no full list in memory) and
    stays correct across the commit-batch boundary (>5000 pairs)."""
    n = 6000  # > _IMPORT_BATCH (5000) → crosses a mid-import commit
    base = 0x10000  # offset clear of every other test's hashes
    hashes = [f"{base + i:032x}" for i in range(n)]

    def gen():
        for i in range(n):
            yield (f"{base + i:032x}", f"p{i}")

    try:
        result = hk_db._import_pairs(gen())  # passing a generator proves it streams
        assert result == {"added": n, "skipped": 0, "warned": 0}
        assert hk_db.bulk_lookup({hashes[0], hashes[-1]}) == {hashes[0]: "p0", hashes[-1]: f"p{n - 1}"}
    finally:
        for h in hashes:
            hk_db.delete_by_value(h)


# ── parse_line contract (the import core reuses this verbatim) ────────────────

def test_parse_line_formats():
    """parse_line pins the three supported formats + empty-hash + bare-hash behaviour.
    The streaming import core (Step 3) feeds parse_line() output, so these must hold."""
    NT = "8846f7eaee8fb117ad06bdd830b7586c"
    LM = "aad3b435b51404eeaad3b435b51404ee"

    # HASH:PLAIN
    assert hk_db.parse_line(f"{NT}:Password1") == (NT, "Password1")
    # LM:NT:PLAIN  -> second field is the NT hash
    assert hk_db.parse_line(f"{LM}:{NT}:Password1") == (NT, "Password1")
    # $NT$HASH:PLAIN
    assert hk_db.parse_line(f"$NT${NT}:Password1") == (NT, "Password1")
    # Empty NT hash -> canonical empty-password pair regardless of supplied plaintext
    empty = hk_db._NT_EMPTY
    assert hk_db.parse_line(f"{empty}:anything") == (empty, hk_db._EMPTY_PASSWORD)
    # Bare 32-hex (no plaintext) -> (hash, "") — current behaviour, pinned as-is
    assert hk_db.parse_line(NT) == (NT, "")
    # Comments / blanks / junk -> None
    assert hk_db.parse_line("# comment") is None
    assert hk_db.parse_line("") is None
    assert hk_db.parse_line("nothex") is None


# ── bulk_lookup contract ─────────────────────────────────────────────────────

def test_bulk_lookup_returns_single_and_skips_conflict():
    """A hash with one plaintext is returned; a hash with conflicting plaintexts is skipped."""
    hk_db.bulk_import(f"{H3}:singlepass")
    hk_db.bulk_import(f"{H4}:conflA")
    hk_db.bulk_import(f"{H4}:conflB")  # H4 now has two plaintexts → conflict

    result = hk_db.bulk_lookup({H3, H4})
    assert result.get(H3) == "singlepass"
    assert H4 not in result, "conflicting hash must be skipped (HAVING COUNT(*)=1)"


def test_bulk_lookup_empty_input():
    assert hk_db.bulk_lookup(set()) == {}


def test_bulk_lookup_chunks_beyond_variable_limit():
    """Step 2: >999 hashes must not raise 'too many SQL variables', and a conflicting
    hash is still skipped across chunk boundaries (chunk size 900 → multiple chunks)."""
    n = 1000  # > 999 (old SQLite limit) and > 900 (chunk) → exercises >1 chunk
    hashes = [f"{i:032x}" for i in range(1, n + 1)]
    conflict = f"{n + 1:032x}"
    try:
        lines = [f"{h}:pw{idx}" for idx, h in enumerate(hashes)]
        lines += [f"{conflict}:ca", f"{conflict}:cb"]  # conflict → must be skipped
        hk_db.bulk_import("\n".join(lines))

        result = hk_db.bulk_lookup(set(hashes) | {conflict})
        assert len(result) == n, f"all {n} single-plaintext hashes must resolve; got {len(result)}"
        assert conflict not in result, "conflicting hash must be skipped across chunking"
        assert result[hashes[0]] == "pw0"
        assert result[hashes[-1]] == f"pw{n - 1}"
    finally:
        for h in hashes:
            hk_db.delete_by_value(h)
        hk_db.delete_by_value(conflict)


# ── upload_db contract ───────────────────────────────────────────────────────

def test_upload_db_counts():
    """{added, warned, skipped} when merging another HK DB.

    Pre-state: H5:existingZ, H6:samew.
    Source rows: H4:new (added), H5:diffY (conflict→warned), H6:samew (skipped).
    """
    hk_db.bulk_import(f"{H5}:existingZ")
    hk_db.bulk_import(f"{H6}:samew")

    src = _make_source_db_bytes([(H4, "new"), (H5, "diffY"), (H6, "samew")])
    result = hk_db.upload_db(src)
    assert result == {"added": 1, "warned": 1, "skipped": 1}


def test_upload_db_rejects_invalid_db():
    with pytest.raises(ValueError):
        hk_db.upload_db(b"this is not a sqlite database")


def test_merge_db_file_streams_large(tmp_path):
    """Step 4: merge_db_file reads the source via a lazy cursor (no fetchall) and merges
    correctly across the import batch boundary."""
    n = 6000  # > _IMPORT_BATCH (5000)
    base = 0x20000  # clear of every other test's hashes
    hashes = [f"{base + i:032x}" for i in range(n)]
    srcfile = tmp_path / "src.db"
    con = sqlite3.connect(str(srcfile))
    con.execute("CREATE TABLE hk_pairs (nt_hash TEXT, plaintext TEXT)")
    con.executemany("INSERT INTO hk_pairs(nt_hash, plaintext) VALUES(?,?)",
                    [(h, f"p{i}") for i, h in enumerate(hashes)])
    con.commit()
    con.close()
    try:
        result = hk_db.merge_db_file(str(srcfile))
        assert result == {"added": n, "skipped": 0, "warned": 0}
        assert hk_db.bulk_lookup({hashes[0], hashes[-1]}) == {hashes[0]: "p0", hashes[-1]: f"p{n - 1}"}
    finally:
        for h in hashes:
            hk_db.delete_by_value(h)


def test_merge_db_file_rejects_invalid(tmp_path):
    bad = tmp_path / "bad.db"
    con = sqlite3.connect(str(bad))
    con.execute("CREATE TABLE other (x)")
    con.commit()
    con.close()
    with pytest.raises(ValueError):
        hk_db.merge_db_file(str(bad))


def test_upload_db_endpoint_streams(auth_client, tmp_path):
    """Step 4: the upload-db endpoint streams the upload to disk in chunks and merges it."""
    H = "77777777777777777777777777777777"
    src = tmp_path / "up.db"
    con = sqlite3.connect(str(src))
    con.execute("CREATE TABLE hk_pairs (nt_hash TEXT, plaintext TEXT)")
    con.execute("INSERT INTO hk_pairs(nt_hash, plaintext) VALUES(?,?)", (H, "viaendpoint"))
    con.commit()
    con.close()
    try:
        with open(src, "rb") as fh:
            r = auth_client.post(
                "/api/hk/upload-db",
                files={"file": ("up.db", fh, "application/octet-stream")},
            )
        assert r.status_code == 200
        assert r.json()["added"] == 1
        assert hk_db.bulk_lookup({H}) == {H: "viaendpoint"}
    finally:
        hk_db.delete_by_value(H)


# ── get_stats contract (shape must survive the Step 5 cache) ──────────────────

def test_get_stats_shape():
    """get_stats returns exactly {total, smart} — warning is a separate lazy call."""
    hk_db.bulk_import(f"{H1}:pa")

    stats = hk_db.get_stats()
    assert set(stats.keys()) == {"total", "smart"}
    assert all(isinstance(v, int) for v in stats.values())


def test_get_warning_count_live():
    """get_warning_count() returns an int; hashes with >1 plaintext appear in warning export."""
    hk_db.bulk_import(f"{H1}:pa")
    hk_db.bulk_import(f"{H1}:pb")  # conflict → H1 must show up as warning

    count = hk_db.get_warning_count()
    assert isinstance(count, int)
    assert count >= 2  # H1 contributes 2 rows

    warn_hashes = {r["nt_hash"] for r in hk_db.get_warning_pairs()}
    assert H1 in warn_hashes


def test_stats_persistent_cache_survives_memory_clear():
    """Persistent cache: after in-memory wipe (simulating restart), DB values are returned."""
    hk_db.bulk_import(f"{H2}:persist")
    expected_total = hk_db.get_stats()["total"]   # computes → writes to hk_stats

    hk_db._stats_cache = None                     # simulate restart (in-memory only)
    result = hk_db.get_stats()
    assert result["total"] == expected_total, "hk_stats DB cache must serve on memory-miss"
    assert set(result.keys()) == {"total", "smart"}


def test_warning_count_persistent_cache_survives_memory_clear():
    """warning persistent cache: after in-memory wipe, DB value is returned."""
    hk_db.bulk_import(f"{H1}:wa\n{H1}:wb")       # conflict
    expected = hk_db.get_warning_count()           # computes → writes to hk_stats

    hk_db._warning_cache = None                   # simulate restart
    result = hk_db.get_warning_count()
    assert result == expected, "hk_stats DB cache must serve warning on memory-miss"


def test_persistent_cache_invalidated_on_mutation():
    """After any mutation, both memory and DB caches are cleared; next get_stats recomputes."""
    hk_db.bulk_import(f"{H1}:x")
    base = hk_db.get_stats()["total"]             # computes + stores

    hk_db.bulk_import(f"{H2}:y")                  # invalidates
    assert hk_db._stats_cache is None, "in-memory cache must be cleared after mutation"

    # Also verify DB cache is gone (simulate restart, recompute must happen)
    hk_db._stats_cache = None
    result = hk_db.get_stats()
    assert result["total"] == base + 1


def test_warning_stats_endpoint(auth_client):
    """GET /api/hk/stats/warning returns {warning: int}."""
    r = auth_client.get("/api/hk/stats/warning")
    assert r.status_code == 200
    d = r.json()
    assert set(d.keys()) == {"warning"}
    assert isinstance(d["warning"], int)


def test_get_stats_cache_and_invalidation():
    """Step 5: get_stats is cached and invalidated by each hk_pairs mutation. A raw write
    that bypasses the public API is NOT reflected until a real mutation invalidates —
    proving both that the cache serves and that mutations clear it."""
    hk_db.bulk_import(f"{H1}:a")     # invalidates
    base_total = hk_db.get_stats()["total"]  # computes + caches

    # Raw insert bypassing the mutation API → the cache must still serve the stale total.
    conn = hk_db._get_hk_db()
    conn.execute("INSERT OR IGNORE INTO hk_pairs(nt_hash, plaintext) VALUES(?,?)", (H2, "raw"))
    conn.commit()
    try:
        assert hk_db.get_stats()["total"] == base_total, "cache must serve the stale value"

        # Import invalidates → recompute sees both the raw row and the imported one.
        hk_db.bulk_import(f"{H3}:c")
        assert hk_db.get_stats()["total"] == base_total + 2

        # Delete invalidates too → count drops back.
        hk_db.delete_by_value(H3)
        assert hk_db.get_stats()["total"] == base_total + 1
    finally:
        hk_db.delete_by_value(H2)
        hk_db.delete_by_value(H3)


# ── find / delete by plaintext (the path Step-1 idx_hk_plain accelerates) ─────

def test_import_file_endpoints_wired(auth_client):
    """Step 3b: endpoints are registered + auth-gated; with an empty inbox check reports
    absence and run returns 404 (the guard)."""
    r = auth_client.get("/api/hk/import-file/check")
    assert r.status_code == 200
    assert r.json() == {"exists": False}
    r2 = auth_client.post("/api/hk/import-file/run")
    assert r2.status_code == 404


def test_inbox_status_and_import(tmp_path):
    """Step 3b: inbox status reports absence/presence; import streams the file.
    Uses the fast bulk path → {added, skipped, invalid} (no per-import warned count)."""
    orig = hk_db.HK_INBOX_DIR
    hk_db.HK_INBOX_DIR = tmp_path
    try:
        assert hk_db.inbox_file_status() == {"exists": False}

        f = tmp_path / hk_db.HK_INBOX_FILE
        f.write_text(f"{H1}:fromfile\n{H1}:fromfile\nnothex\n", encoding="utf-8")

        st = hk_db.inbox_file_status()
        assert st["exists"] is True
        assert st["name"] == hk_db.HK_INBOX_FILE
        assert st["size"] > 0

        res = hk_db.import_inbox_file()
        assert (res["added"], res["skipped"], res["invalid"]) == (1, 1, 1)
        assert "seconds" in res and "rate" in res
        assert hk_db.bulk_lookup({H1}) == {H1: "fromfile"}
    finally:
        hk_db.HK_INBOX_DIR = orig
        hk_db.delete_by_value(H1)


def test_inbox_ram_killer_import(tmp_path):
    """RAM-killer mode imports correctly and reports the cache size used."""
    orig = hk_db.HK_INBOX_DIR
    hk_db.HK_INBOX_DIR = tmp_path
    try:
        f = tmp_path / hk_db.HK_INBOX_FILE
        f.write_text(f"{H4}:rk\n", encoding="utf-8")
        res = hk_db.import_inbox_file(ram_killer=True)
        assert (res["added"], res["skipped"], res["invalid"]) == (1, 0, 0)
        assert res["ram_mb"] >= 256  # never below the safe default cap
        assert hk_db.bulk_lookup({H4}) == {H4: "rk"}
    finally:
        hk_db.HK_INBOX_DIR = orig
        hk_db.delete_by_value(H4)


def test_ram_killer_cache_never_below_default():
    """Cache sizing stays >= safe default and <= ceiling, whatever free RAM reports."""
    kib = hk_db._ram_killer_cache_kib()
    assert hk_db._BULK_CACHE_KIB <= kib <= hk_db._RAM_KILLER_CEILING_KIB
    assert hk_db._available_ram_bytes() is None or hk_db._available_ram_bytes() > 0


def test_inbox_fast_import_conflict_detected_live(tmp_path):
    """The fast bulk path does NOT stamp the stored `warning` flag, but a hash with two
    plaintexts is still reported as a conflict everywhere (warning derived live via COUNT),
    and bulk_lookup still skips it. Proves the stored flag is vestigial."""
    orig = hk_db.HK_INBOX_DIR
    hk_db.HK_INBOX_DIR = tmp_path
    try:
        f = tmp_path / hk_db.HK_INBOX_FILE
        f.write_text(f"{H1}:pa\n{H1}:pb\n", encoding="utf-8")  # same hash, two plaintexts

        res = hk_db.import_inbox_file()
        assert (res["added"], res["skipped"], res["invalid"]) == (2, 0, 0)

        # Stored flag is 0 (fast path skips stamping)...
        conn = hk_db._get_hk_db()
        stored = [r[0] for r in conn.execute(
            "SELECT warning FROM hk_pairs WHERE nt_hash=?", (H1,)).fetchall()]
        assert stored == [0, 0]
        # ...but every live consumer still treats it as a conflict.
        assert H1 in {r["nt_hash"] for r in hk_db.get_warning_pairs()}
        assert H1 not in hk_db.bulk_lookup({H1})
    finally:
        hk_db.HK_INBOX_DIR = orig
        hk_db.delete_by_value(H1)


def test_bulk_insert_pairs_counts():
    """Fast path counts: added = rows actually inserted, skipped = exact duplicates.
    A conflicting plaintext is a NEW row (counts toward added, not skipped)."""
    try:
        res = hk_db._bulk_insert_pairs(iter([(H2, "x"), (H2, "x"), (H2, "y"), (H3, "z")]))
        assert res == {"added": 3, "skipped": 1}  # x, y, z inserted; second x skipped
        assert hk_db.bulk_lookup({H3}) == {H3: "z"}
    finally:
        hk_db.delete_by_value(H2)
        hk_db.delete_by_value(H3)


def test_bulk_insert_pairs_crosses_batch(monkeypatch):
    """Multiple executemany batches (boundary) merge correctly."""
    monkeypatch.setattr(hk_db, "_BULK_BATCH", 2)
    base = 0x40000
    hashes = [f"{base + i:032x}" for i in range(5)]
    try:
        res = hk_db._bulk_insert_pairs((h, f"p{i}") for i, h in enumerate(hashes))
        assert res == {"added": 5, "skipped": 0}
        assert hk_db.bulk_lookup(set(hashes)) == {h: f"p{i}" for i, h in enumerate(hashes)}
    finally:
        for h in hashes:
            hk_db.delete_by_value(h)


def test_inbox_rejects_symlink(tmp_path):
    """Step 3b security: a symlinked inbox file (pointing outside) is rejected — defense
    against symlink-escape even though the path itself is server-hardcoded."""
    orig = hk_db.HK_INBOX_DIR
    hk_db.HK_INBOX_DIR = tmp_path
    try:
        outside = tmp_path.parent / "outside_secret.txt"
        outside.write_text(f"{H2}:secret\n", encoding="utf-8")
        link = tmp_path / hk_db.HK_INBOX_FILE
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation not permitted in this environment")

        assert hk_db.inbox_file_status() == {"exists": False}
        with pytest.raises(ValueError):
            hk_db.import_inbox_file()
    finally:
        hk_db.HK_INBOX_DIR = orig
        hk_db.delete_by_value(H2)


def test_find_and_delete_by_plaintext():
    plain = "zz_pin_unique_plain_zz"  # non-hex → treated as a plaintext query
    hk_db.bulk_import(f"{H2}:{plain}")

    found = hk_db.find_pairs(plain)
    assert found["query_type"] == "value"
    assert any(r["nt_hash"] == H2 for r in found["by_plain"])

    deleted = hk_db.delete_by_value(plain)
    assert deleted >= 1
    assert hk_db.bulk_lookup({H2}) == {}, "pair must be gone after delete-by-plaintext"


def test_delete_from_lines_mixed():
    """Bulk delete: hash:plain & bare hash delete ALL rows for that hash; plaintext deletes by
    plaintext; comments/blanks skipped — same per-line semantics as delete_by_value."""
    hk_db.bulk_import(f"{H1}:a\n{H1}:b\n{H2}:c\n{H3}:d")
    try:
        res = hk_db.delete_from_lines([
            f"{H1}:a",     # hash:plain → deletes ALL H1 rows (a and b)
            f"{H2}",       # bare hash → deletes all H2
            "# comment",   # skipped
            "",            # skipped
            "d",           # plaintext → deletes rows with plaintext 'd' (H3)
        ])
        assert res == {"deleted": 4, "lines": 3}
        assert hk_db.bulk_lookup({H1, H2, H3}) == {}
    finally:
        for h in (H1, H2, H3):
            hk_db.delete_by_value(h)


# ═══════════════════════════════════════════════════════════════════════════════
# R10.1 — single-run guard (409) for kill / smart-enrich / kill-all
# ═══════════════════════════════════════════════════════════════════════════════

def test_kill_409_if_already_running(auth_client, workspace_id):
    """kill/{ws} must return 409 if a kill task for the same workspace is already running."""
    from collector.api.hashkiller import _hk_tasks
    _hk_tasks["_r101_kill"] = {
        "status": "running", "result": None, "error": None,
        "progress": None, "cancelled": False, "kind": "kill",
        "workspace_id": workspace_id,
    }
    try:
        r = auth_client.post(f"/api/hk/kill/{workspace_id}")
        assert r.status_code == 409, f"expected 409, got {r.status_code}: {r.text}"
    finally:
        _hk_tasks.pop("_r101_kill", None)


def test_kill_409_only_for_same_workspace(auth_client, workspace_id):
    """kill/{ws} must NOT block when a running kill task is for a different workspace."""
    from collector.api.hashkiller import _hk_tasks
    other_ws_id = workspace_id + 9999
    _hk_tasks["_r101_kill_other"] = {
        "status": "running", "result": None, "error": None,
        "progress": None, "cancelled": False, "kind": "kill",
        "workspace_id": other_ws_id,
    }
    try:
        r = auth_client.post(f"/api/hk/kill/{workspace_id}")
        assert r.status_code == 200, f"must not block for different workspace: {r.text}"
    finally:
        _hk_tasks.pop("_r101_kill_other", None)


def test_smart_enrich_409_if_already_running(auth_client, workspace_id):
    """smart-enrich/{ws} must return 409 if a smart-enrich for the same workspace is running."""
    from collector.api.hashkiller import _hk_tasks
    _hk_tasks["_r101_enrich"] = {
        "status": "running", "result": None, "error": None,
        "progress": None, "cancelled": False, "kind": "smart-enrich",
        "workspace_id": workspace_id,
    }
    try:
        r = auth_client.post(f"/api/hk/smart-enrich/{workspace_id}")
        assert r.status_code == 409, f"expected 409, got {r.status_code}: {r.text}"
    finally:
        _hk_tasks.pop("_r101_enrich", None)


def test_kill_all_409_if_already_running(auth_client):
    """kill-all must return 409 if a kill-all task is already running."""
    from collector.api.hashkiller import _hk_tasks
    _hk_tasks["_r101_kill_all"] = {
        "status": "running", "result": None, "error": None,
        "progress": None, "cancelled": False, "kind": "kill-all",
    }
    try:
        r = auth_client.post("/api/hk/kill-all")
        assert r.status_code == 409, f"expected 409, got {r.status_code}: {r.text}"
    finally:
        _hk_tasks.pop("_r101_kill_all", None)


def test_kill_409_not_triggered_by_done_task(auth_client, workspace_id):
    """Completed kill task must not block a new run (guard checks status==running only)."""
    from collector.api.hashkiller import _hk_tasks
    _hk_tasks["_r101_done"] = {
        "status": "done", "result": None, "error": None,
        "progress": None, "cancelled": False, "kind": "kill",
        "workspace_id": workspace_id,
    }
    try:
        r = auth_client.post(f"/api/hk/kill/{workspace_id}")
        assert r.status_code == 200, f"done task must not block: {r.text}"
    finally:
        _hk_tasks.pop("_r101_done", None)


def test_delete_file_endpoint(auth_client):
    """Step: /api/hk/delete-file deletes every hash/pair listed in an uploaded txt."""
    H = "77777777777777777777777777777777"
    hk_db.bulk_import(f"{H}:viafile")
    try:
        r = auth_client.post(
            "/api/hk/delete-file",
            files={"file": ("del.txt", f"{H}\n".encode(), "text/plain")},
        )
        assert r.status_code == 200
        assert r.json()["deleted"] == 1
        assert hk_db.bulk_lookup({H}) == {}
    finally:
        hk_db.delete_by_value(H)


# ═══════════════════════════════════════════════════════════════════════════════
# R3.1 — HK Import diagnostic: total_lines field (Г) + format hint signal (А)
# ═══════════════════════════════════════════════════════════════════════════════

def test_bulk_import_empty_string_total_lines_zero():
    r = hk_db.bulk_import("")
    assert "total_lines" in r
    assert r["total_lines"] == 0

def test_bulk_import_only_blank_lines_total_lines_zero():
    r = hk_db.bulk_import("\n  \n\t\n")
    assert r["total_lines"] == 0

def test_bulk_import_only_comments_total_lines_zero():
    r = hk_db.bulk_import("# this is a comment\n# another comment\n")
    assert r["total_lines"] == 0

def test_bulk_import_valid_lines_counted_in_total():
    try:
        r = hk_db.bulk_import(f"{H1}:secretpass\n{H2}:anotherpass\n")
        assert r["total_lines"] == 2
        assert r["added"] == 2
    finally:
        hk_db.delete_by_value(H1)
        hk_db.delete_by_value(H2)

def test_bulk_import_invalid_lines_counted_in_total():
    r = hk_db.bulk_import("not_a_hash:plain\nalso_invalid\nthird_bad_line")
    assert r["invalid"] == 3
    assert r["total_lines"] == 3

def test_bulk_import_mixed_total_lines_is_valid_plus_invalid():
    try:
        r = hk_db.bulk_import(f"{H1}:pass\nbad_line\n# comment\n  \n")
        assert r["total_lines"] == 2   # 1 valid + 1 invalid; comment and blank excluded
        assert r["added"] == 1
        assert r["invalid"] == 1
    finally:
        hk_db.delete_by_value(H1)


# ═══════════════════════════════════════════════════════════════════════════════
# R6.2 — sync_brutforced: clears stale Brutforced entries after HK pair deletion
# ═══════════════════════════════════════════════════════════════════════════════

_H_BF = "ab" * 16  # 32-hex, unique to R6.2 tests


def _insert_cred_with_bf(workspace_id, username, plain):
    from collector.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR IGNORE INTO credentials"
            " (workspace_id, proto, domain, username, password, credtype, brutforced)"
            " VALUES (?,?,?,?,?,?,?)",
            (workspace_id, "smb", "testdom", username, _H_BF, "hash", plain),
        )


def _delete_cred(workspace_id, username):
    from collector.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            "DELETE FROM credentials WHERE workspace_id=? AND username=?",
            (workspace_id, username),
        )


def test_sync_brutforced_clears_stale_plain(workspace_id):
    """Plain not in HK → brutforced cleared to NULL."""
    plain = "syncbf_stale_9x1"
    hk_db.delete_by_value(plain)
    _insert_cred_with_bf(workspace_id, "syncbf_u1", plain)
    try:
        result = hk_db.sync_brutforced(workspace_id)
        assert result["cleared"] >= 1
        from collector.db import db_cursor
        with db_cursor() as cur:
            row = cur.execute(
                "SELECT brutforced FROM credentials WHERE workspace_id=? AND username='syncbf_u1'",
                (workspace_id,),
            ).fetchone()
        assert row is None or row["brutforced"] is None
    finally:
        _delete_cred(workspace_id, "syncbf_u1")


def test_sync_brutforced_keeps_valid_plain(workspace_id):
    """Plain still in HK → brutforced preserved."""
    plain = "syncbf_valid_9x2"
    hk_db.bulk_import(f"{_H_BF}:{plain}")
    _insert_cred_with_bf(workspace_id, "syncbf_u2", plain)
    try:
        hk_db.sync_brutforced(workspace_id)
        from collector.db import db_cursor
        with db_cursor() as cur:
            row = cur.execute(
                "SELECT brutforced FROM credentials WHERE workspace_id=? AND username='syncbf_u2'",
                (workspace_id,),
            ).fetchone()
        assert row is not None and row["brutforced"] == plain
    finally:
        _delete_cred(workspace_id, "syncbf_u2")
        hk_db.delete_by_value(plain)


def test_sync_brutforced_returns_cleared_count(workspace_id):
    """Response has 'cleared' int."""
    plain = "syncbf_count_9x3"
    hk_db.delete_by_value(plain)
    _insert_cred_with_bf(workspace_id, "syncbf_u3", plain)
    try:
        result = hk_db.sync_brutforced(workspace_id)
        assert "cleared" in result
        assert isinstance(result["cleared"], int)
        assert result["cleared"] >= 1
    finally:
        _delete_cred(workspace_id, "syncbf_u3")


def test_sync_brutforced_clears_custom_credentials(workspace_id):
    """Stale brutforced in custom_credentials is also cleared."""
    plain = "syncbf_custom_9x4"
    hk_db.delete_by_value(plain)
    from collector.db import db_cursor
    with db_cursor() as cur:
        cur.execute(
            "INSERT OR IGNORE INTO custom_credentials"
            " (workspace_id, login, password, credtype, brutforced)"
            " VALUES (?,?,?,?,?)",
            (workspace_id, "syncbf_cu4", _H_BF, "hash", plain),
        )
    try:
        result = hk_db.sync_brutforced(workspace_id)
        assert result["cleared"] >= 1
        with db_cursor() as cur:
            row = cur.execute(
                "SELECT brutforced FROM custom_credentials WHERE workspace_id=? AND login='syncbf_cu4'",
                (workspace_id,),
            ).fetchone()
        assert row is None or row["brutforced"] is None
    finally:
        from collector.db import db_cursor
        with db_cursor() as cur:
            cur.execute(
                "DELETE FROM custom_credentials WHERE workspace_id=? AND login='syncbf_cu4'",
                (workspace_id,),
            )


def test_sync_brutforced_endpoint(auth_client, workspace_id):
    """POST /api/hk/sync-brutforced/{ws_id} → 200 {cleared: int}."""
    r = auth_client.post(f"/api/hk/sync-brutforced/{workspace_id}")
    assert r.status_code == 200
    d = r.json()
    assert "cleared" in d
    assert isinstance(d["cleared"], int)
