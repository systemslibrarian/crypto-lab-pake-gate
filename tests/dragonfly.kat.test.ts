import { describe, it, expect } from "vitest";
import { DragonflyParty } from "../src/pake/dragonfly";
import { p256PointToHex, scalar32 } from "../src/pake/groups";
import { asPassword } from "../src/pake/types";
import { toHex } from "../src/pake/encoding";
import { Wire } from "../src/pake/wire";
import kat from "./vectors/dragonfly.kat.json";

// Independent Python KAT cross-check for Dragonfly (PE, ss, kck, mk, confirms).
// See tests/vectors/gen/dragonfly_kat.py + tests/vectors/README.md.
const F = kat.fixture;
const big = (h: string) => BigInt("0x" + h);

function party(self: string, peer: string, priv: string, mask: string) {
  return new DragonflyParty({
    selfId: self,
    peerId: peer,
    password: asPassword(F.password),
    nonces: { priv: big(priv), mask: big(mask) },
  });
}

describe("Dragonfly independent Python KAT cross-check", () => {
  const A = party(F.idA, F.idB, F.privA, F.maskA);
  const B = party(F.idB, F.idA, F.privB, F.maskB);
  const wire = new Wire();
  A.derivePE();
  B.derivePE();
  const aC = wire.send(A.commit());
  const bC = wire.send(B.commit());
  A.recvCommit(bC);
  B.recvCommit(aC);
  A.deriveKey();
  B.deriveKey();
  const aConf = wire.send(A.confirm());
  const bConf = wire.send(B.confirm());
  A.recvConfirm(bConf);
  B.recvConfirm(aConf);

  it("password element matches the KAT (both peers)", () => {
    expect(p256PointToHex(A.trace.PE!)).toBe(kat.pe);
    expect(p256PointToHex(B.trace.PE!)).toBe(kat.pe);
    expect(A.trace.peIterations).toBeGreaterThanOrEqual(40);
  });

  it("commit scalars and elements match the KAT", () => {
    expect(scalar32(A.trace.scalarSelf!)).toBe(kat.scalarA);
    expect(scalar32(B.trace.scalarSelf!)).toBe(kat.scalarB);
    expect(p256PointToHex(A.trace.elemSelf!)).toBe(kat.elementA);
    expect(p256PointToHex(B.trace.elemSelf!)).toBe(kat.elementB);
  });

  it("ss, kck, mk match the KAT byte-for-byte", () => {
    expect(scalar32(A.trace.ss!)).toBe(kat.ss);
    expect(toHex(A.trace.kck!)).toBe(kat.kck);
    expect(toHex(A.trace.mk!)).toBe(kat.mk);
    expect(toHex(A.sessionKeyBytes!)).toBe(kat.mk);
  });

  it("confirm tags match the KAT and both sides confirm", () => {
    expect(toHex(A.trace.confirmSelf!)).toBe(kat.confirmA);
    expect(toHex(B.trace.confirmSelf!)).toBe(kat.confirmB);
    expect(A.phase).toBe("confirmed");
    expect(B.phase).toBe("confirmed");
  });
});
