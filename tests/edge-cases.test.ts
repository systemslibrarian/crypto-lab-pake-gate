import { describe, it, expect } from "vitest";
import {
  decodeSrpPublicValue,
  decodeJPakeElement,
  decodeRistrettoElement,
  decodeDragonflyCommitElement,
} from "../src/pake/groups";
import { SRP_GROUP_4096_SHA256, JPAKE_GROUP_3072 } from "../src/pake/params";
import { padHex } from "../src/pake/groups";
import { toHex, i2osp } from "../src/pake/encoding";
import type { Hex } from "../src/pake/types";
import { HandshakeAbort } from "../src/pake/types";

const asHex = (s: string) => s as Hex;

describe("Fail-closed edge cases (each rejects with a teaching tooltip)", () => {
  it("SRP: A ≡ 0 (mod N) is rejected", () => {
    const zeroA = padHex(0n, SRP_GROUP_4096_SHA256.nLen);
    expect(() => decodeSrpPublicValue(zeroA, SRP_GROUP_4096_SHA256, "A")).toThrow(HandshakeAbort);
  });
  it("SRP: A == N (out of range) is rejected", () => {
    const bigA = padHex(SRP_GROUP_4096_SHA256.N, SRP_GROUP_4096_SHA256.nLen);
    expect(() => decodeSrpPublicValue(bigA, SRP_GROUP_4096_SHA256, "A")).toThrow(/out of range/);
  });

  it("J-PAKE: g2 == 1 (identity) is rejected but g1 == 1 is allowed", () => {
    const one = toHex(i2osp(1n, JPAKE_GROUP_3072.pLen));
    expect(() =>
      decodeJPakeElement(one, JPAKE_GROUP_3072, { field: "g2", rejectIdentity: true }),
    ).toThrow(/identity/);
    // g1 = 1 is legitimate (x1 may be 0) — must NOT throw the identity error.
    expect(() =>
      decodeJPakeElement(one, JPAKE_GROUP_3072, { field: "g1", rejectIdentity: false }),
    ).not.toThrow();
  });
  it("J-PAKE: an out-of-subgroup element (a non-residue) is rejected", () => {
    // p-1 ≡ -1 is the order-2 element; since p ≡ 3 (mod 4), q is odd so (-1)^q = -1 ≠ 1,
    // i.e. p-1 is NOT in the prime-order subgroup — a guaranteed non-residue.
    const nonResidue = toHex(i2osp(JPAKE_GROUP_3072.p - 1n, JPAKE_GROUP_3072.pLen));
    expect(() =>
      decodeJPakeElement(nonResidue, JPAKE_GROUP_3072, { field: "g1", rejectIdentity: false }),
    ).toThrow(/subgroup/);
  });

  it("CPace: the ristretto255 identity encoding is rejected", () => {
    const identity = asHex("00".repeat(32)); // canonical ristretto identity encoding
    expect(() => decodeRistrettoElement(identity, "K")).toThrow(/identity/);
  });
  it("CPace: a non-canonical ristretto encoding is rejected", () => {
    const garbage = asHex("ff".repeat(32));
    expect(() => decodeRistrettoElement(garbage, "Y")).toThrow(HandshakeAbort);
  });

  it("Dragonfly: an off-curve / malformed SEC1 point is rejected", () => {
    // 0x04 || X=1 || Y=1 is not on P-256.
    const offCurve = asHex("04" + "00".repeat(31) + "01" + "00".repeat(31) + "01");
    expect(() => decodeDragonflyCommitElement(offCurve, "Element")).toThrow(HandshakeAbort);
  });
  it("Dragonfly: wrong-length element is rejected", () => {
    expect(() => decodeDragonflyCommitElement(asHex("0400"), "Element")).toThrow(/SEC1/);
  });
});
