#!/usr/bin/env python3
"""Independent from-scratch KAT generator for the PAKE Gate SRP-6a Track-2 profile.

Profile (declared standalone teaching profile — NOT RFC 5054's K/M1/M2, NOT RFC 2945
SHA_Interleave): RFC 5054 Appendix A 4096-bit group (== RFC 3526 group 16), g=5,
SHA-256, simple-hash K = SHA-256(PAD(S)), and the M1/M2 evidence messages below.

This file uses ONLY hashlib + native big integers, written directly from the profile
text, independent of the TypeScript engine — so a byte-for-byte match cross-validates
the runnable SRP profile (including K/M1/M2, which RFC 5054 does not publish).

Run:  python tests/vectors/gen/srp_track2_kat.py
Emits tests/vectors/srp_track2.kat.json (consumed by tests/srp.track2.test.ts).
"""

import hashlib
import json
import os
import unicodedata

# --- RFC 3526 4096-bit prime via its closed form (matches derive_groups.py). ---

def pi_times_2exp(k: int) -> int:
    guard = 80
    S = 1 << (k + guard)

    def arctan_inv(x: int) -> int:
        x2 = x * x
        total = 0
        xpow = S // x
        n = 0
        sign = 1
        while xpow > 0:
            total += sign * (xpow // (2 * n + 1))
            sign = -sign
            xpow //= x2
            n += 1
        return total

    return (16 * arctan_inv(5) - 4 * arctan_inv(239)) >> guard


N = (1 << 4096) - (1 << 4032) - 1 + (1 << 64) * (pi_times_2exp(3966) + 240904)
g = 5
NLEN = 512  # length(N) in bytes


def H(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def i2osp(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def PAD(n: int) -> bytes:
    return i2osp(n, NLEN)


def nfc(s: str) -> bytes:
    return unicodedata.normalize("NFC", s).encode("utf-8")


def compute(fixture: dict) -> dict:
    I = fixture["I"]
    p = fixture["p"]
    salt = bytes.fromhex(fixture["salt"])
    a = int(fixture["a"], 16)
    b = int(fixture["b"], 16)

    k = os2ip(H(PAD(N), PAD(g)))
    x = os2ip(H(salt, H(nfc(I), b":", nfc(p))))
    v = pow(g, x, N)
    A = pow(g, a, N)
    B = (k * v + pow(g, b, N)) % N
    u = os2ip(H(PAD(A), PAD(B)))

    # client S = (B - k*g^x)^(a + u*x) mod N
    base_c = (B - (k * pow(g, x, N)) % N) % N
    S_client = pow(base_c, a + u * x, N)
    # server S = (A * v^u)^b mod N
    S_server = pow((A * pow(v, u, N)) % N, b, N)
    assert S_client == S_server, "premaster mismatch"
    S = S_client

    K = H(PAD(S))
    hN = H(PAD(N))
    hg = H(PAD(g))
    xor_ng = bytes(x ^ y for x, y in zip(hN, hg))
    M1 = H(xor_ng, H(nfc(I)), salt, PAD(A), PAD(B), K)
    M2 = H(PAD(A), M1, K)

    hx = lambda n: format(n, "x")
    hb = lambda by: by.hex()
    return {
        "profile": "srp6a/pake-gate-4096-sha256",
        "group": "RFC 5054 4096-bit (== RFC 3526 group 16), g=5, SHA-256",
        "fixture": fixture,
        "k": hx(k),
        "x": hx(x),
        "v": hx(v),
        "A": hx(A),
        "B": hx(B),
        "u": hx(u),
        "S_client": hx(S_client),
        "S_server": hx(S_server),
        "K": hb(K),
        "M1": hb(M1),
        "M2": hb(M2),
    }


FIXTURE = {
    "I": "alice",
    "p": "Correct-Horse-Battery-Staple-42",
    "salt": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
    "a": (
        "5f3c9a1b7e0d2648f19a3c5b7d9e0f21436587a9cbed0f1324"
        "5768a9bcde0f213546879abcde0f1234"
    ),
    "b": (
        "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192"
        "a3b4c5d6e7f8091a2b3c4d5e6f708192"
    ),
}


def main() -> None:
    out = compute(FIXTURE)
    dest = os.path.join(os.path.dirname(__file__), "..", "srp_track2.kat.json")
    with open(os.path.normpath(dest), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("wrote", os.path.normpath(dest))
    print("K =", out["K"])
    print("M1 =", out["M1"])
    print("M2 =", out["M2"])


if __name__ == "__main__":
    main()
