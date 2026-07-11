#!/usr/bin/env python3
"""Derive and verify the MODP group primes used by PAKE Gate, from first principles.

We do NOT trust a copy-pasted hex blob (long hex is easy to corrupt in transit).
Instead we reconstruct each RFC 3526 prime from its published closed form
(RFC 3526 gives each as  2^N - 2^(N-64) - 1 + 2^64 * { [2^(N-130) pi] + X }) and
mechanically verify it is a SAFE PRIME of the exact bit length. A transcription
error in the offset X or the exponents would fail primality with overwhelming
probability, so a passing run is strong evidence the constant is correct.

The 1024-bit RFC 5054 Appendix A group is checked from the RFC hex (short enough to
transfer intact) and re-verified as a safe prime.

Run:  python tests/vectors/gen/derive_groups.py
"""

import sys


def pi_times_2exp(k: int) -> int:
    """Return floor(pi * 2^k) using the Machin formula in scaled integer arithmetic."""
    guard = 80
    S = 1 << (k + guard)

    def arctan_inv(x: int) -> int:
        # S * arctan(1/x) = S * sum_{n>=0} (-1)^n / ((2n+1) x^(2n+1))
        x2 = x * x
        total = 0
        xpow = S // x  # S / x
        n = 0
        sign = 1
        while xpow > 0:
            total += sign * (xpow // (2 * n + 1))
            sign = -sign
            xpow //= x2
            n += 1
        return total

    pi_scaled = 16 * arctan_inv(5) - 4 * arctan_inv(239)  # pi * S
    return pi_scaled >> guard


def modp_prime(bits: int, offset: int) -> int:
    # 2^bits - 2^(bits-64) - 1 + 2^64 * ( floor(2^(bits-130) * pi) + offset )
    return (
        (1 << bits)
        - (1 << (bits - 64))
        - 1
        + (1 << 64) * (pi_times_2exp(bits - 130) + offset)
    )


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    # deterministic-ish bases for large n + extra fixed bases
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]
    for a in bases[:rounds]:
        a %= n
        if a == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def verify_safe_prime(name: str, p: int, expected_bits: int) -> bool:
    ok = True
    bl = p.bit_length()
    if bl != expected_bits:
        print(f"  [FAIL] {name}: bit length {bl} != {expected_bits}")
        ok = False
    if not is_probable_prime(p):
        print(f"  [FAIL] {name}: not prime")
        ok = False
    q = (p - 1) // 2
    if not is_probable_prime(q):
        print(f"  [FAIL] {name}: (p-1)/2 not prime (not a safe prime)")
        ok = False
    if ok:
        print(f"  [OK]   {name}: {expected_bits}-bit safe prime")
    return ok


# RFC 5054 Appendix A 1024-bit prime (short enough to carry intact; re-verified).
N1024_HEX = (
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576"
    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1"
    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC"
    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"
)


def main() -> int:
    print("Deriving + verifying MODP groups")
    all_ok = True

    n1024 = int(N1024_HEX, 16)
    all_ok &= verify_safe_prime("RFC5054 1024-bit (SRP Track 1)", n1024, 1024)

    p3072 = modp_prime(3072, 1690314)  # RFC 3526 group 15 (J-PAKE)
    all_ok &= verify_safe_prime("RFC3526 3072-bit (J-PAKE)", p3072, 3072)

    p4096 = modp_prime(4096, 240904)  # RFC 3526 group 16 == RFC 5054 4096 (SRP Track 2)
    all_ok &= verify_safe_prime("RFC3526 4096-bit (SRP Track 2)", p4096, 4096)

    # Sanity: RFC 3526 primes start FFFFFFFFFFFFFFFFC90FDAA22168C234 and end FFFFFFFFFFFFFFFF
    for name, p in (("3072", p3072), ("4096", p4096)):
        h = format(p, "x").upper()
        assert h.startswith("FFFFFFFFFFFFFFFFC90FDAA22168C234"), f"{name} head mismatch"
        assert h.endswith("FFFFFFFFFFFFFFFF"), f"{name} tail mismatch"

    print("\n--- Constants (hex) for embedding ---")
    print("N1024 =", format(n1024, "x"))
    print("P3072 =", format(p3072, "x"))
    print("P4096 =", format(p4096, "x"))

    print("\n" + ("ALL GROUPS VERIFIED" if all_ok else "VERIFICATION FAILED"))
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
