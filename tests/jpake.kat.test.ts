import { describe, it, expect } from "vitest";
import { JPakeParty } from "../src/pake/jpake";
import { asPassword } from "../src/pake/types";
import { toHex } from "../src/pake/encoding";
import { Wire } from "../src/pake/wire";
import kat from "./vectors/jpake.kat.json";

// Independent Python KAT cross-check for the J-PAKE profile (algebra + HKDF +
// KC_1_U confirmation). See tests/vectors/gen/jpake_kat.py + tests/vectors/README.md.
// Driven with the fixture's x1..x4 as exponents; Schnorr nonces are arbitrary (they
// don't affect g1..g4 / A / B / keys / tags).
const F = kat.fixture;
const hx = (n: bigint) => n.toString(16);

function party(role: "A" | "B", e1: string, e2: string) {
  const b = (h: string) => BigInt("0x" + h);
  return new JPakeParty({
    role,
    selfId: role === "A" ? F.idA : F.idB,
    peerId: role === "A" ? F.idB : F.idA,
    password: asPassword(F.password),
    nonces: { e1: b(e1), e2: b(e2), v1: 3n, v2: 5n, vr: 7n },
  });
}

describe("J-PAKE independent Python KAT cross-check", () => {
  const A = party("A", F.x1, F.x2);
  const B = party("B", F.x3, F.x4);
  const wire = new Wire();
  const a1 = wire.send(A.round1());
  const b1 = wire.send(B.round1());
  A.recvRound1(b1);
  B.recvRound1(a1);
  const a2 = wire.send(A.round2());
  const b2 = wire.send(B.round2());
  A.recvRound2(b2);
  B.recvRound2(a2);
  A.deriveKey();
  B.deriveKey();
  const ac = wire.send(A.confirm());
  const bc = wire.send(B.confirm());
  A.recvConfirm(bc);
  B.recvConfirm(ac);

  it("g1..g4 match the KAT", () => {
    expect(hx(A.trace.g1!)).toBe(kat.g1);
    expect(hx(A.trace.g2!)).toBe(kat.g2);
    expect(hx(A.trace.g3!)).toBe(kat.g3);
    expect(hx(A.trace.g4!)).toBe(kat.g4);
  });

  it("Round-2 elements A and B match the KAT", () => {
    expect(hx(A.trace.elemSelf!)).toBe(kat.A);
    expect(hx(B.trace.elemSelf!)).toBe(kat.B);
  });

  it("K_material, ISK, kc match the KAT byte-for-byte", () => {
    expect(toHex(A.trace.kMaterial!)).toBe(kat.k_material);
    expect(toHex(B.trace.kMaterial!)).toBe(kat.k_material);
    expect(toHex(A.trace.isk!)).toBe(kat.isk);
    expect(toHex(A.trace.kc!)).toBe(kat.kc);
  });

  it("confirmation tags match the KAT and both sides confirm", () => {
    expect(toHex(A.trace.tagSelf!)).toBe(kat.tagA);
    expect(toHex(B.trace.tagSelf!)).toBe(kat.tagB);
    expect(A.phase).toBe("confirmed");
    expect(B.phase).toBe("confirmed");
  });
});
