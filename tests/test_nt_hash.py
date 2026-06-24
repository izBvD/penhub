"""Tests for the pure-stdlib NT-hash helper (collector/nt_hash.py)."""

from collector.nt_hash import nt_hash


def test_known_vector_password():
    # Canonical NT hash of "password".
    assert nt_hash("password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_empty_password_is_nt_empty():
    assert nt_hash("") == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_known_vector_password1():
    # NT hash of "Password1" (well-known test vector).
    assert nt_hash("Password1") == "64f12cddaa88057e06a81b54e73b949b"


def test_unicode_password():
    # Non-ASCII must be encoded UTF-16-LE before MD4 (NT semantics).
    # Hash of "пароль" computed via the same algorithm — just assert it is
    # a stable 32-char lowercase hex string and differs from ASCII inputs.
    h = nt_hash("пароль")
    assert len(h) == 32
    assert h == h.lower()
    assert all(c in "0123456789abcdef" for c in h)
    assert h != nt_hash("password")


def test_lowercase_hex_output():
    h = nt_hash("ABCdef123!@#")
    assert h == h.lower() and len(h) == 32
