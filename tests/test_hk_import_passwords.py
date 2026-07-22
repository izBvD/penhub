"""
Password-list import (Block 1 IMPORT → "add by password").

Each pasted/uploaded plaintext password is hashed locally to its NT hash and stored as a
(nt_hash, plaintext) pair, so KILL THEM ALL applies it exactly like an imported hash:plain
pair. Semantics reuse the precise import core (conflict → warning), so counting matches
bulk_import.
"""
import pytest

import collector.hashkiller_db as hk_db
from collector.db import db_cursor
from collector.nt_hash import nt_hash


@pytest.fixture(autouse=True)
def _hk_ready():
    """Ensure the HK schema exists (app lifespan may not have run for pure-core tests)."""
    hk_db.init_hk_db()


def _cleanup(*plains):
    for p in plains:
        hk_db.delete_by_value(p)


def test_import_passwords_adds_nt_pairs():
    """Each password is stored under its real NT hash → resolvable via bulk_lookup."""
    plains = ["Zx_pwlist_alpha_1", "Zx_pwlist_beta_2"]
    try:
        res = hk_db.import_passwords("\n".join(plains))
        assert res["added"] == 2
        assert res["total_lines"] == 2
        for p in plains:
            h = nt_hash(p)
            assert hk_db.bulk_lookup({h}) == {h: p}
    finally:
        _cleanup(*plains)


def test_import_passwords_skips_duplicates():
    p = "Zx_pwlist_dup_3"
    try:
        first = hk_db.import_passwords(p)
        assert first["added"] == 1
        second = hk_db.import_passwords(p)
        assert second["added"] == 0
        assert second["skipped"] == 1
    finally:
        _cleanup(p)


def test_import_passwords_conflict_warns():
    """A password whose NT hash already maps to a different plaintext → warning on both,
    and the hash is skipped by bulk_lookup (live conflict)."""
    p = "Zx_pwlist_conflict_4"
    h = nt_hash(p)
    try:
        hk_db.bulk_import(f"{h}:OTHERPLAIN")  # same hash, different plaintext preloaded
        res = hk_db.import_passwords(p)
        assert res["warned"] == 1
        assert h not in hk_db.bulk_lookup({h})
        assert h in {r["nt_hash"] for r in hk_db.get_warning_pairs()}
    finally:
        hk_db.delete_by_value(h)


def test_import_passwords_skips_blank_keeps_hash_prefix():
    # '#' is a common password character — lines starting with '#' are PASSWORDS,
    # not comments. Only blank / whitespace-only lines are skipped.
    real = "Zx_pwlist_real_5"
    hashy = "#Zx_pwlist_hash_9"
    try:
        res = hk_db.import_passwords(f"\n  \n{hashy}\n{real}\n")
        assert res["total_lines"] == 2
        assert res["added"] == 2
        h = nt_hash(hashy)
        assert hk_db.bulk_lookup({h}) == {h: hashy}
    finally:
        _cleanup(real, hashy)


def test_import_passwords_preserves_password_verbatim():
    """Password content is not trimmed — edge/internal spaces are part of the password."""
    p = "  spaced pass 6  "
    try:
        res = hk_db.import_passwords(p)
        assert res["added"] == 1
        h = nt_hash(p)
        assert hk_db.bulk_lookup({h}) == {h: p}
    finally:
        hk_db.delete_by_value(p)


def test_import_passwords_endpoint(auth_client):
    p = "Zx_pwlist_endpoint_7"
    try:
        r = auth_client.post("/api/hk/import-passwords", data={"text": p})
        assert r.status_code == 200
        d = r.json()
        assert d["added"] == 1
        h = nt_hash(p)
        assert hk_db.bulk_lookup({h}) == {h: p}
    finally:
        hk_db.delete_by_value(p)


def test_import_passwords_then_kill_applies(workspace_id):
    """End-to-end: add a password, then KILL THEM ALL fills Brutforced for the matching hash."""
    p = "Zx_pwlist_kill_8"
    h = nt_hash(p)
    try:
        with db_cursor() as cur:
            cur.execute(
                "INSERT INTO credentials (workspace_id, proto, domain, username, password,"
                " credtype, brutforced) VALUES (?,?,?,?,?,?,NULL)",
                (workspace_id, "smb", "d", "pwkill_u", h, "hash"),
            )
        hk_db.import_passwords(p)
        res = hk_db.kill_workspace(workspace_id)
        assert res["updated"] >= 1
        with db_cursor() as cur:
            row = cur.execute(
                "SELECT brutforced FROM credentials WHERE workspace_id=? AND username='pwkill_u'",
                (workspace_id,),
            ).fetchone()
        assert row["brutforced"] == p
    finally:
        with db_cursor() as cur:
            cur.execute(
                "DELETE FROM credentials WHERE workspace_id=? AND username='pwkill_u'",
                (workspace_id,),
            )
        hk_db.delete_by_value(h)
