import { describe, it, expect } from "vitest";
import { JPakeParty, passwordToScalar, type JPakeConfig } from "../src/pake/jpake";
import { JPAKE_GROUP_3072 } from "../src/pake/params";
import { asPassword } from "../src/pake/types";
import { SHA256 } from "../src/pake/hashes";
import { os2ip, utf8Nfc } from "../src/pake/encoding";
import { Wire } from "../src/pake/wire";

const g = JPAKE_GROUP_3072;

// Deterministic nonce in [1, q-1] from a label (test-only; real demo uses randomness).
function nonce(label: string): bigint {
  return (os2ip(SHA256(utf8Nfc(label))) % (g.q - 1n)) + 1n;
}

function alice(pw: string): JPakeConfig {
  return {
    role: "A",
    selfId: "Alice",
    peerId: "Bob",
    password: asPassword(pw),
    nonces: { e1: nonce("a-e1"), e2: nonce("a-e2"), v1: nonce("a-v1"), v2: nonce("a-v2"), vr: nonce("a-vr") },
  };
}
function bob(pw: string): JPakeConfig {
  return {
    role: "B",
    selfId: "Bob",
    peerId: "Alice",
    password: asPassword(pw),
    nonces: { e1: nonce("b-e3"), e2: nonce("b-e4"), v1: nonce("b-v3"), v2: nonce("b-v4"), vr: nonce("b-vr") },
  };
}

function runHandshake(pwA: string, pwB: string) {
  const wire = new Wire();
  const A = new JPakeParty(alice(pwA));
  const B = new JPakeParty(bob(pwB));

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
  return { A, B, wire, ac, bc };
}

describe("J-PAKE pinned profile (RFC 3526 3072-bit MODP)", () => {
  it("password → scalar is in [1, q-1]", () => {
    const s = passwordToScalar(g, asPassword("hunter2"));
    expect(s >= 1n && s <= g.q - 1n).toBe(true);
  });

  it("honest run: both sides derive byte-identical K_material (catches g2/g4 swap)", () => {
    const { A, B } = runHandshake("correct horse", "correct horse");
    expect(Buffer.from(A.trace.kMaterial!).toString("hex")).toBe(
      Buffer.from(B.trace.kMaterial!).toString("hex"),
    );
  });

  it("honest run: identical ISK and mutual confirmation succeeds", () => {
    const { A, B, ac, bc } = runHandshake("correct horse", "correct horse");
    A.recvConfirm(bc);
    B.recvConfirm(ac);
    expect(A.phase).toBe("confirmed");
    expect(B.phase).toBe("confirmed");
    expect(Buffer.from(A.sessionKeyBytes!).toString("hex")).toBe(
      Buffer.from(B.sessionKeyBytes!).toString("hex"),
    );
  });

  it("wrong password: keys differ AND confirmation fails", () => {
    const { A, B, ac, bc } = runHandshake("correct horse", "wrong horse");
    expect(Buffer.from(A.trace.kMaterial!).toString("hex")).not.toBe(
      Buffer.from(B.trace.kMaterial!).toString("hex"),
    );
    expect(() => A.recvConfirm(bc)).toThrow();
    expect(() => B.recvConfirm(ac)).toThrow();
    expect(A.phase).toBe("aborted");
  });
});
