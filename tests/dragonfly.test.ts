import { describe, it, expect } from "vitest";
import {
  DragonflyParty,
  derivePasswordElement,
  firstValidCounter,
  type DragonflyConfig,
} from "../src/pake/dragonfly";
import { compareModels, fixedWork, legacyEarlyExit } from "../src/pake/dragonblood";
import { P256_ORDER_N } from "../src/pake/groups";
import { asPassword } from "../src/pake/types";
import { SHA256 } from "../src/pake/hashes";
import { os2ip, utf8Nfc } from "../src/pake/encoding";
import { Wire } from "../src/pake/wire";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
function scalar(label: string): bigint {
  return (os2ip(SHA256(utf8Nfc(label))) % (P256_ORDER_N - 3n)) + 2n;
}
function cfg(self: string, peer: string, pw: string, tag: string): DragonflyConfig {
  return {
    selfId: self,
    peerId: peer,
    password: asPassword(pw),
    nonces: { priv: scalar(tag + "-priv"), mask: scalar(tag + "-mask") },
  };
}

function run(pwA: string, pwB: string) {
  const wire = new Wire();
  const A = new DragonflyParty(cfg("Alice", "Bob", pwA, "A"));
  const B = new DragonflyParty(cfg("Bob", "Alice", pwB, "B"));
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
  return { A, B, wire, aConf, bConf, aC, bC };
}

describe("Dragonfly (RFC 7664 / P-256) honest handshake", () => {
  it("both peers derive the same password element (balanced PAKE)", () => {
    const pe1 = derivePasswordElement("Alice", "Bob", asPassword("pw"));
    const pe2 = derivePasswordElement("Bob", "Alice", asPassword("pw"));
    expect(pe1.PE.equals(pe2.PE)).toBe(true);
    expect(pe1.iterations).toBeGreaterThanOrEqual(40); // minimum-k honest loop
  });

  it("honest run: identical mk and mutual confirmation", () => {
    const { A, B, aConf, bConf } = run("mesh network", "mesh network");
    A.recvConfirm(bConf);
    B.recvConfirm(aConf);
    expect(A.phase).toBe("confirmed");
    expect(B.phase).toBe("confirmed");
    expect(hex(A.sessionKeyBytes!)).toBe(hex(B.sessionKeyBytes!));
  });

  it("wrong password: keys differ and confirmation fails", () => {
    const { A, B, aConf, bConf } = run("mesh network", "wrong net");
    expect(hex(A.sessionKeyBytes!)).not.toBe(hex(B.sessionKeyBytes!));
    expect(() => A.recvConfirm(bConf)).toThrow();
    expect(() => B.recvConfirm(aConf)).toThrow();
  });

  it("reflection guard: a mirrored commit is rejected", () => {
    const A = new DragonflyParty(cfg("Alice", "Bob", "pw", "A"));
    A.derivePE();
    const aC = A.commit();
    // reflect A's own commit back at it
    expect(() => A.recvCommit(aC)).toThrow(/reflection/i);
  });
});

describe("Dragonblood side-channel comparison (models only; never honest keys)", () => {
  const candidates = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"].map(asPassword);

  it("legacy early-exit iteration count varies with the password (the leak)", () => {
    const counts = candidates.map((pw) => legacyEarlyExit("Alice", "Bob", pw).modeledIterations);
    expect(new Set(counts).size).toBeGreaterThan(1);
  });

  it("fixed-work model performs constant iterations independent of the password", () => {
    const counts = candidates.map((pw) => fixedWork("Alice", "Bob", pw, 40).modeledIterations);
    expect(new Set(counts).size).toBe(1);
    expect(counts[0]).toBe(40);
  });

  it("fixed-work FAILS rather than inventing a PE when none is found within the cap", () => {
    // cap 0 → no iteration can find a PE → found must be false, no PE invented.
    const r = fixedWork("Alice", "Bob", asPassword("alpha"), 0);
    expect(r.found).toBe(false);
    expect(r.modeledIterations).toBe(0);
  });

  it("compareModels summarizes leak vs flat", () => {
    const cmp = compareModels("Alice", "Bob", candidates, 40);
    expect(cmp.legacyLeaks).toBe(true);
    expect(cmp.fixedWorkFlat).toBe(true);
  });

  it("first-valid counter is a small positive integer for typical passwords", () => {
    const at = firstValidCounter("Alice", "Bob", asPassword("alpha"));
    expect(at).not.toBeNull();
    expect(at!).toBeGreaterThanOrEqual(1);
  });
});
