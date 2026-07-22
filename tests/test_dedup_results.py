"""
UNIQ dedup for results / auth-relation views (dedup_results).

Key = cred_domain + username + password + ip (host-aware):
- distinct hosts are preserved (one row per credential x host);
- duplicates from different protocols / operators on the SAME host collapse
  (proto & operator are not part of the key; winner picked by rank);
- rows without a host (ip empty) still dedup by the (domain, login, password) triple.

These are pure-function tests — no DB, no app.
"""
from collector.services.data_service import dedup_results


def _row(**kw):
    base = {
        "cred_domain": "corp", "username": "alice", "password": "P@ss",
        "credtype": "plaintext", "relation_type": "loggedin",
        "ip": "10.0.0.1", "proto": "SMB", "admin_cred": None,
    }
    base.update(kw)
    return base


# ── Per-host: distinct hosts preserved ────────────────────────────────────────

def test_same_cred_on_three_hosts_kept_as_three_rows():
    rows = [_row(ip="10.0.0.1"), _row(ip="10.0.0.2"), _row(ip="10.0.0.3")]
    out = dedup_results(rows)
    assert len(out) == 3
    assert {r["ip"] for r in out} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


def test_admin_and_loggedin_on_different_hosts_both_kept():
    rows = [
        _row(ip="10.0.0.1", relation_type="admin"),
        _row(ip="10.0.0.2", relation_type="loggedin"),
    ]
    out = dedup_results(rows)
    assert len(out) == 2


# ── Same host: duplicates collapse ────────────────────────────────────────────

def test_same_cred_same_host_two_protocols_collapses_smb_wins():
    rows = [_row(proto="WINRM"), _row(proto="SMB")]
    out = dedup_results(rows)
    assert len(out) == 1
    assert out[0]["proto"] == "SMB"


def test_same_cred_same_host_two_operators_collapses():
    rows = [_row(operator="alice"), _row(operator="bob")]
    out = dedup_results(rows)
    assert len(out) == 1


def test_admin_beats_loggedin_on_same_host():
    rows = [_row(relation_type="loggedin"), _row(relation_type="admin")]
    out = dedup_results(rows)
    assert len(out) == 1
    assert out[0]["relation_type"] == "admin"


# ── Rows without a host ───────────────────────────────────────────────────────

def test_rows_without_ip_dedup_by_triple():
    rows = [_row(ip=""), _row(ip="")]
    out = dedup_results(rows)
    assert len(out) == 1


def test_empty_ip_and_hosted_are_separate():
    rows = [_row(ip=""), _row(ip="10.0.0.1")]
    out = dedup_results(rows)
    assert len(out) == 2


# ── Preserved behaviours ──────────────────────────────────────────────────────

def test_admin_cred_propagates_to_winner_on_same_host():
    rows = [
        _row(proto="SMB", admin_cred=None),
        _row(proto="WINRM", admin_cred=1),
    ]
    out = dedup_results(rows)
    assert len(out) == 1
    assert out[0]["admin_cred"] == 1


def test_different_passwords_same_cred_host_stay_separate():
    rows = [_row(password="P@ss"), _row(password="NThashabc", credtype="hash")]
    out = dedup_results(rows)
    assert len(out) == 2
