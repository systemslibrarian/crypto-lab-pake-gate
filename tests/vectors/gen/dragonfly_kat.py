#!/usr/bin/env python3
"""Independent from-scratch KAT for the PAKE Gate Dragonfly (RFC 7664 / P-256) profile.

RFC 7664 publishes NO test vectors. This generator implements P-256 arithmetic and the
frozen profile directly (hashlib + hmac + native bigint), independent of the TS engine,
and emits every intermediate — PE, the commit scalars/elements, ss, kck, mk, and the
two confirm tags — so a byte-for-byte match cross-validates the whole derivation
(hunting-and-pecking PE seed, the SP800-108 KDF split, and the RFC 7664 confirm).
See tests/vectors/README.md.

Run:  python tests/vectors/gen/dragonfly_kat.py  ->  tests/vectors/dragonfly.kat.json
"""

import hashlib
import hmac
import json
import os
import unicodedata

# --- NIST P-256 ---
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def inv(x, m=P):
    return pow(x, m - 2, m)


def pt_add(pt1, pt2):
    if pt1 is None:
        return pt2
    if pt2 is None:
        return pt1
    x1, y1 = pt1
    x2, y2 = pt2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if pt1 == pt2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, pt):
    r = None
    while k > 0:
        if k & 1:
            r = pt_add(r, pt)
        pt = pt_add(pt, pt)
        k >>= 1
    return r


def negate(pt):
    if pt is None:
        return None
    return (pt[0], (-pt[1]) % P)


def sec1_uncompressed(pt) -> bytes:
    x, y = pt
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


# --- profile primitives ---
def nfc(s: str) -> bytes:
    return unicodedata.normalize("NFC", s).encode("utf-8")


def sha256(*chunks: bytes) -> bytes:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c)
    return h.digest()


def kdf_800108(key: bytes, label: bytes, context: bytes, length_bits: int) -> bytes:
    out_len = (length_bits + 7) // 8
    out, i = b"", 1
    while len(out) < out_len:
        block = hmac.new(
            key,
            i.to_bytes(4, "big") + label + b"\x00" + context + length_bits.to_bytes(4, "big"),
            hashlib.sha256,
        ).digest()
        out += block
        i += 1
    return out[:out_len]


PE_LABEL = b"Dragonfly-PAKE-Gate-PE-v1"
KEY_LABEL = b"Dragonfly Key Derivation"
K_MIN = 40


def encode_id(s: str) -> bytes:
    b = nfc(s)
    return len(b).to_bytes(2, "big") + b


def sqrt_mod_p(a):
    r = pow(a, (P + 1) // 4, P)
    return r if (r * r) % P == a % P else None


def derive_pe(idA: str, idB: str, password: str, k: int = K_MIN):
    eA, eB = encode_id(idA), encode_id(idB)
    hi, lo = (eA, eB) if int.from_bytes(eA, "big") >= int.from_bytes(eB, "big") else (eB, eA)
    pw = nfc(password)
    found = None
    found_at = 0
    counter = 1
    while True:
        base = sha256(hi, lo, pw, bytes([counter & 0xFF]))
        temp = kdf_800108(base, PE_LABEL, b"", 320)
        seed = (int.from_bytes(temp, "big") % (P - 1)) + 1
        if found is None and seed < P:
            rhs = (pow(seed, 3, P) + A * seed + B) % P
            y = sqrt_mod_p(rhs)
            if y is not None:
                want_odd = (temp[-1] & 1) == 1
                y_final = y if (y & 1) == (1 if want_odd else 0) else (P - y)
                found = (seed, y_final)
                found_at = counter
        if counter >= k and found is not None:
            return found, found_at, counter
        counter += 1


def compute(fx: dict) -> dict:
    idA, idB = fx["idA"], fx["idB"]
    PE, found_at, iters = derive_pe(idA, idB, fx["password"])
    privA, maskA = int(fx["privA"], 16), int(fx["maskA"], 16)
    privB, maskB = int(fx["privB"], 16), int(fx["maskB"], 16)

    scalarA = (privA + maskA) % N
    scalarB = (privB + maskB) % N
    elemA = negate(scalar_mul(maskA, PE))
    elemB = negate(scalar_mul(maskB, PE))

    # A: K = privA * (scalarB*PE + elemB) ; B: K = privB * (scalarA*PE + elemA)
    KA = scalar_mul(privA, pt_add(scalar_mul(scalarB, PE), elemB))
    KB = scalar_mul(privB, pt_add(scalar_mul(scalarA, PE), elemA))
    assert KA == KB, "shared point mismatch"
    ss = KA[0]

    derived = kdf_800108(ss.to_bytes(32, "big"), KEY_LABEL, b"", 512)
    kck, mk = derived[:32], derived[32:64]

    def confirm(sc_self, sc_peer, el_self, el_peer, sender):
        return sha256(
            kck,
            sc_self.to_bytes(32, "big"),
            sc_peer.to_bytes(32, "big"),
            sec1_uncompressed(el_self),
            sec1_uncompressed(el_peer),
            encode_id(sender),
        )

    confirmA = confirm(scalarA, scalarB, elemA, elemB, idA)
    confirmB = confirm(scalarB, scalarA, elemB, elemA, idB)

    return {
        "profile": "dragonfly/rfc7664-p256",
        "fixture": fx,
        "pe_found_at": found_at,
        "pe": sec1_uncompressed(PE).hex(),
        "scalarA": format(scalarA, "064x"),
        "scalarB": format(scalarB, "064x"),
        "elementA": sec1_uncompressed(elemA).hex(),
        "elementB": sec1_uncompressed(elemB).hex(),
        "ss": format(ss, "064x"),
        "kck": kck.hex(),
        "mk": mk.hex(),
        "confirmA": confirmA.hex(),
        "confirmB": confirmB.hex(),
    }


FIXTURE = {
    "idA": "Alice",
    "idB": "Bob",
    "password": "mesh network",
    "privA": "1122334455667788990011223344556677889900112233445566778899001122",
    "maskA": "2233445566778899001122334455667788990011223344556677889900112233",
    "privB": "3344556677889900112233445566778899001122334455667788990011223344",
    "maskB": "4455667788990011223344556677889900112233445566778899001122334455",
}


def main() -> None:
    out = compute(FIXTURE)
    dest = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "dragonfly.kat.json"))
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("wrote", dest)
    print("pe_found_at =", out["pe_found_at"], "pe =", out["pe"][:24], "...")
    print("mk =", out["mk"])
    print("confirmA =", out["confirmA"])


if __name__ == "__main__":
    main()
