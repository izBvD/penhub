"""
Unit tests for dicgenerat — pure generation logic (no network/disk).
"""

import importlib.util
import textwrap
from pathlib import Path


def _load():
    spec = importlib.util.spec_from_file_location(
        "dicgenerat_ut", Path(__file__).parent.parent / "dicgenerat.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dg = _load()


# ── Task 1: extraction helpers ──────────────────────────────────────────────

def test_is_skip_user():
    assert dg.is_skip_user("guest")
    assert dg.is_skip_user("GUEST")
    assert dg.is_skip_user("Гость")
    assert dg.is_skip_user("defaultaccount")
    assert dg.is_skip_user("")
    assert not dg.is_skip_user("epifanov")


def test_plaintext_of_plaintext():
    assert dg.plaintext_of({"credtype": "plaintext", "password": "Summer2024"}) == "Summer2024"


def test_plaintext_of_bruted_hash():
    row = {"credtype": "hash", "password": "aad3...:abcd", "brutforced": "Winter1"}
    assert dg.plaintext_of(row) == "Winter1"


def test_plaintext_of_unbruted_hash_is_none():
    assert dg.plaintext_of({"credtype": "hash", "password": "abcd", "brutforced": None}) is None


def test_plaintext_of_empty_sentinel_is_none():
    assert dg.plaintext_of({"credtype": "plaintext", "password": "<empty_password>"}) is None
    assert dg.plaintext_of({"credtype": "plaintext", "password": ""}) is None


# ── Task 2: build_base ──────────────────────────────────────────────────────

def test_build_base_merges_all_sources():
    creds = [
        {"credtype": "plaintext", "password": "Summer2024", "username": "epifanov", "domain": "CORP"},
        {"credtype": "hash", "password": "h", "brutforced": "Bruted1", "username": "guest", "domain": "CORP"},
    ]
    custom = [
        {"credtype": "plaintext", "password": "Custom1", "username": "svc_web", "domain": "corp"},
    ]
    dpapi = [
        {"username": "dp_user", "password": "DpPass1"},
        {"username": "GUEST", "password": "SecretY"},
    ]
    out = dg.build_base(creds, custom, dpapi)

    # passwords (incl bruteforced, custom, dpapi)
    assert "Summer2024" in out and "Bruted1" in out and "Custom1" in out
    assert "DpPass1" in out and "SecretY" in out
    # logins minus skip-users
    assert "epifanov" in out and "svc_web" in out and "dp_user" in out
    assert "guest" not in out and "GUEST" not in out
    # domains lowercased & deduped
    assert "corp" in out and "CORP" not in out
    # sorted unique
    assert out == sorted(set(out))


# ── Task 3: strip_login ─────────────────────────────────────────────────────

def test_strip_login_defaults_noop():
    assert dg.strip_login("epifanov") == "epifanov"


def test_strip_login_sb_cuts_through_first_left_sep():
    assert dg.strip_login("av_epifanov", sb="_") == "epifanov"
    assert dg.strip_login("a_b_epifanov", sb="_") == "b_epifanov"  # first from left


def test_strip_login_sa_cuts_from_last_sep():
    assert dg.strip_login("epifanov_av", sa="_") == "epifanov"
    assert dg.strip_login("epifanov_a_b", sa="_") == "epifanov_a"  # last sep


def test_strip_login_sep_not_found_noop():
    assert dg.strip_login("epifanov", sb="_", sa=".") == "epifanov"


def test_strip_login_b_a_exact_counts():
    assert dg.strip_login("avepifanov", b=2) == "epifanov"
    assert dg.strip_login("epifanovav", a=2) == "epifanov"


def test_strip_login_order_and_overshoot():
    assert dg.strip_login("av_epifanovXY", sb="_", a=2) == "epifanov"
    assert dg.strip_login("abc", b=5) == ""      # b longer than login
    assert dg.strip_login("abc", a=5) == ""      # a longer than login


# ── Task 4: translit_variants ───────────────────────────────────────────────

def test_translit_basic_and_cap():
    v = dg.translit_variants("boss")
    assert "босс" in v
    assert len(v) <= 8
    assert v[0]  # primary present, non-empty


def test_translit_sh_branches():
    v = dg.translit_variants("shakov")
    assert "шаков" in v and "щаков" in v          # sh -> ш | щ


def test_translit_digraphs():
    assert "чехов" in dg.translit_variants("chehov")   # ch, h->х primary
    assert "жуков" in dg.translit_variants("zhukov")    # zh


def test_translit_surname_ending():
    assert "иванов" in dg.translit_variants("ivanof")   # -of -> -ов
    assert "иванов" in dg.translit_variants("ivanov")   # -ov natural


def test_translit_soft_sign_cluster():
    assert "кузьмин" in dg.translit_variants("kuzmin")  # зм -> зьм


def test_translit_deterministic():
    assert dg.translit_variants("nikiforov") == dg.translit_variants("nikiforov")


# ── Task 5: to_en_layout ────────────────────────────────────────────────────

def test_layout_lowercase_word():
    assert dg.to_en_layout("босс") == ",jcc"


def test_layout_uppercase_is_shift_symbol():
    assert dg.to_en_layout("Б") == "<"          # Shift on the б key
    assert dg.to_en_layout("Босс") == "<jcc"


def test_layout_passthrough_unknown():
    assert dg.to_en_layout("abc123") == "abc123"  # latin/digits not in RU map


# ── Task 6: append_tails + years_since ──────────────────────────────────────

def test_charset_b_is_20_chars():
    assert dg.CHARSET_B == "0123456789!@#$%&*_-."
    assert len(dg.CHARSET_B) == 20


def test_years_since():
    assert dg.years_since(1972) == ["1970", "1971", "1972"]
    assert dg.years_since(1969) == []


def test_append_tails_small_charset():
    out = list(dg.append_tails("x", "ab", ["1970", "1971"]))
    # base(1) + (2 + 4 + 8) + years(2) = 17
    assert len(out) == 17
    assert out[0] == "x"
    assert "xa" in out and "xab" in out and "xaba" in out
    assert "x1970" in out and "x1971" in out


def test_append_tails_counts_full_charset():
    out = list(dg.append_tails("x", dg.CHARSET_B, []))
    # base + 20 + 400 + 8000
    assert len(out) == 1 + 20 + 400 + 8000


# ── Task 7: mutate_login ────────────────────────────────────────────────────

def test_mutate_login_empty_stem_yields_nothing():
    assert list(dg.mutate_login("abc", b=5)) == []


def test_mutate_login_pipeline_small():
    # charset empty, no years -> one line per (translit variant x case form)
    out = list(dg.mutate_login("boss", charset="", years=[]))
    # base 'босс' -> ",jcc"; capitalized 'Босс' -> "<jcc"
    assert ",jcc" in out
    assert "<jcc" in out


def test_mutate_login_applies_strip_first():
    out = list(dg.mutate_login("av_boss", sb="_", charset="", years=[]))
    assert ",jcc" in out                        # stem 'boss' after -sb "_"
    assert not any("fd" in v for v in out)       # 'av'->'ав'->'fd' initials gone


def test_mutate_login_enriches_with_tails():
    out = list(dg.mutate_login("boss", charset="1", years=["2024"]))
    assert ",jcc1" in out
    assert ",jcc2024" in out


# ── Task 8: IO helpers (no network/disk-heavy) ──────────────────────────────

def test_load_config_normalizes_server(tmp_path):
    conf = tmp_path / ".nxc-collector.conf"
    conf.write_text(textwrap.dedent("""
        [collector]
        server = 10.0.0.5
        port = 322
        password = secret
        workspace = proj1
    """), encoding="utf-8")
    c = dg.load_config(conf)
    assert c["server"] == "http://10.0.0.5:322"
    assert c["workspace"] == "proj1"
    assert c["password"] == "secret"


def test_collect_logins_unique_minus_skip():
    creds = [{"username": "epifanov"}, {"username": "guest"}, {"username": "epifanov"}]
    custom = [{"username": "svc"}]
    dpapi = [{"username": "dp"}, {"username": ""}]
    assert dg.collect_logins(creds, custom, dpapi) == ["dp", "epifanov", "svc"]


def test_argparse_defaults():
    args = dg._parse_args(["-ws", "proj", "-b", "2", "-sb", "_"])
    assert args.workspace == "proj" and args.b == 2 and args.sb == "_"
    assert args.a == 0 and args.sa is None
