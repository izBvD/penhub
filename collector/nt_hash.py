"""
NT-hash helper — pure standard library, no third-party dependencies.

NT hash = MD4(password encoded as UTF-16-LE), lowercase 32-char hex.

`hashlib` cannot be relied on for MD4 (OpenSSL 3 dropped the legacy digest,
so `hashlib.new("md4")` raises on modern builds — including this one). A small
self-contained MD4 keeps the dependency footprint at zero and is fast enough:
SMART ENRICH only ever hashes a workspace's distinct plaintext passwords
(hundreds–thousands), so a pure-Python digest is effectively instant.

Usage:
    from collector.nt_hash import nt_hash
    nt_hash("password")  -> "8846f7eaee8fb117ad06bdd830b7586c"

    python -m collector.nt_hash "Password1"
"""

import struct

_MASK = 0xFFFFFFFF


def _lrot(x: int, n: int) -> int:
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def _md4(data: bytes) -> bytes:
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    # Padding: append 0x80, then zeros to 56 mod 64, then 64-bit little-endian bit length.
    msg_len = len(data)
    data += b"\x80"
    data += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    data += struct.pack("<Q", (msg_len * 8) & 0xFFFFFFFFFFFFFFFF)

    for off in range(0, len(data), 64):
        x = list(struct.unpack("<16I", data[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for i in (0, 4, 8, 12):
            a = _lrot(a + ((b & c) | (~b & d)) + x[i],     3)
            d = _lrot(d + ((a & b) | (~a & c)) + x[i + 1], 7)
            c = _lrot(c + ((d & a) | (~d & b)) + x[i + 2], 11)
            b = _lrot(b + ((c & d) | (~c & a)) + x[i + 3], 19)

        # Round 2
        for i in (0, 1, 2, 3):
            a = _lrot(a + ((b & c) | (b & d) | (c & d)) + x[i]      + 0x5A827999, 3)
            d = _lrot(d + ((a & b) | (a & c) | (b & c)) + x[i + 4]  + 0x5A827999, 5)
            c = _lrot(c + ((d & a) | (d & b) | (a & b)) + x[i + 8]  + 0x5A827999, 9)
            b = _lrot(b + ((c & d) | (c & a) | (d & a)) + x[i + 12] + 0x5A827999, 13)

        # Round 3
        for i in (0, 2, 1, 3):
            a = _lrot(a + (b ^ c ^ d) + x[i]      + 0x6ED9EBA1, 3)
            d = _lrot(d + (a ^ b ^ c) + x[i + 8]  + 0x6ED9EBA1, 9)
            c = _lrot(c + (d ^ a ^ b) + x[i + 4]  + 0x6ED9EBA1, 11)
            b = _lrot(b + (c ^ d ^ a) + x[i + 12] + 0x6ED9EBA1, 15)

        a = (a + aa) & _MASK
        b = (b + bb) & _MASK
        c = (c + cc) & _MASK
        d = (d + dd) & _MASK

    return struct.pack("<4I", a, b, c, d)


def nt_hash(password: str) -> str:
    """Return the NT hash (MD4 of UTF-16-LE password) as lowercase 32-hex."""
    return _md4(password.encode("utf-16-le")).hex()


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("usage: python -m collector.nt_hash <password>", file=sys.stderr)
        sys.exit(2)
    print(nt_hash(sys.argv[1]))
