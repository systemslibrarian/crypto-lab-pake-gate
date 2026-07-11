#!/usr/bin/env python3
"""Independent from-scratch KAT for the PAKE Gate J-PAKE profile.

RFC 8236 publishes NO test vectors. This generator (hashlib + hmac + native bigint,
written directly from the profile) independently reproduces the deterministic values
of the pinned profile — g1..g4, A, B, Ka, Kb, K_material, the HKDF ISK/kc, and the
KC_1_U confirmation tags — so a byte-for-byte match cross-validates the algebra
(notably the g2/g4 key formula) AND the HKDF + confirmation layers the RFC leaves to
the application. See tests/vectors/README.md.

Run:  python tests/vectors/gen/jpake_kat.py  ->  tests/vectors/jpake.kat.json
"""

import hashlib
import hmac
import json
import os
import unicodedata

# RFC 3526 3072-bit prime via closed form (matches derive_groups.py / params.ts).

def pi_times_2exp(k: int) -> int:
    guard = 80
    S = 1 << (k + guard)

    def arctan_inv(x: int) -> int:
        x2 = x * x
        total, xpow, n, sign = 0, S // x, 0, 1
        while xpow > 0:
            total += sign * (xpow // (2 * n + 1))
            sign = -sign
            xpow //= x2
            n += 1
        return total

    return (16 * arctan_inv(5) - 4 * arctan_inv(239)) >> guard


p = (1 << 3072) - (1 << 3008) - 1 + (1 << 64) * (pi_times_2exp(2942) + 1690314)
q = (p - 1) // 2
g = 2
PLEN = 384


def nfc(s: str) -> bytes:
    return unicodedata.normalize("NFC", s).encode("utf-8")


def sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def PADp(n: int) -> bytes:
    return n.to_bytes(PLEN, "big")


def lp16(b: bytes) -> bytes:
    return len(b).to_bytes(2, "big") + b


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def password_to_scalar(pw: str) -> int:
    return (os2ip(sha256(nfc(pw))) % (q - 1)) + 1


def mac_tag(kc: bytes, id_self: bytes, id_peer: bytes, gens: list) -> bytes:
    msg = lp16(b"KC_1_U") + lp16(id_self) + lp16(id_peer)
    for gg in gens:
        msg += lp16(PADp(gg))
    return hmac.new(kc, msg, hashlib.sha256).digest()


def compute(fx: dict) -> dict:
    x1, x2, x3, x4 = (int(fx[k], 16) for k in ("x1", "x2", "x3", "x4"))
    idA, idB = fx["idA"], fx["idB"]
    s = password_to_scalar(fx["password"])

    g1 = pow(g, x1, p)
    g2 = pow(g, x2, p)
    g3 = pow(g, x3, p)
    g4 = pow(g, x4, p)

    GA = (g1 * g3 * g4) % p          # Alice's combined generator
    GB = (g1 * g2 * g3) % p          # Bob's combined generator
    expA = (x2 * s) % q
    expB = (x4 * s) % q
    A = pow(GA, expA, p)
    B = pow(GB, expB, p)

    # Alice removes Bob's g4; Bob removes Alice's g2.
    Ka = pow((B * pow(pow(g4, expA, p), p - 2, p)) % p, x2, p)
    Kb = pow((A * pow(pow(g2, expB, p), p - 2, p)) % p, x4, p)
    assert Ka == Kb, "K_material mismatch — g2/g4 swap bug"

    k_material = PADp(Ka)
    isk = hkdf_sha256(k_material, bytes(32), b"JPAKE_ISK", 32)
    kc = hkdf_sha256(k_material, bytes(32), b"JPAKE_KC", 32)

    tagA = mac_tag(kc, nfc(idA), nfc(idB), [g1, g2, g3, g4])
    tagB = mac_tag(kc, nfc(idB), nfc(idA), [g3, g4, g1, g2])

    hx = lambda n: format(n, "x")
    return {
        "profile": "jpake/pake-gate-rfc3526-3072",
        "fixture": fx,
        "g1": hx(g1), "g2": hx(g2), "g3": hx(g3), "g4": hx(g4),
        "A": hx(A), "B": hx(B),
        "Ka": hx(Ka), "Kb": hx(Kb),
        "k_material": k_material.hex(),
        "isk": isk.hex(), "kc": kc.hex(),
        "tagA": tagA.hex(), "tagB": tagB.hex(),
    }


FIXTURE = {
    "idA": "Alice",
    "idB": "Bob",
    "password": "correct horse",
    "x1": "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff01",
    "x2": "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff02",
    "x3": "223344556677889900aabbccddeeff11223344556677889900aabbccddeeff03",
    "x4": "334455667788990011aabbccddeeff22334455667788990011aabbccddeeff04",
}


def main() -> None:
    out = compute(FIXTURE)
    dest = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "jpake.kat.json"))
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("wrote", dest)
    print("isk =", out["isk"])
    print("tagA =", out["tagA"])


if __name__ == "__main__":
    main()
