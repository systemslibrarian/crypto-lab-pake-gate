import { describe, it, expect } from "vitest";
import {
  SRP_GROUP_1024_SHA1,
  SRP_GROUP_4096_SHA256,
  JPAKE_GROUP_3072,
} from "../src/pake/params";

// Re-verify the embedded group constants at test time (a mechanical guard against a
// corrupted literal). Full safe-prime proof lives in tests/vectors/gen/derive_groups.py;
// here we check exact bit length and probable-primality of p and (p-1)/2.
function modpow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
function millerRabin(n: bigint, bases: bigint[]): boolean {
  if (n < 2n) return false;
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    r++;
  }
  for (const a of bases) {
    if (a % n === 0n) continue;
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let ok = false;
    for (let i = 0n; i < r - 1n; i++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        ok = true;
        break;
      }
    }
    if (!ok) return false;
  }
  return true;
}
const BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

describe("group parameters are safe primes of the expected bit length", () => {
  for (const [name, p, bits, g] of [
    ["SRP 1024", SRP_GROUP_1024_SHA1.N, 1024, 2n],
    ["SRP 4096", SRP_GROUP_4096_SHA256.N, 4096, 5n],
    ["J-PAKE 3072", JPAKE_GROUP_3072.p, 3072, 2n],
  ] as const) {
    it(`${name}: ${bits}-bit safe prime`, () => {
      expect(p.toString(2).length).toBe(bits);
      expect(millerRabin(p, BASES)).toBe(true);
      expect(millerRabin((p - 1n) / 2n, BASES)).toBe(true);
      expect(g).toBeGreaterThan(1n);
    });
  }

  it("J-PAKE q = (p-1)/2 is exposed and consistent", () => {
    expect(JPAKE_GROUP_3072.q * 2n + 1n).toBe(JPAKE_GROUP_3072.p);
  });
});
