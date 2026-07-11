import { describe, it, expect } from "vitest";
import { proveSchnorr, verifySchnorr } from "../src/pake/schnorr-nizk";
import { modPow } from "../src/pake/groups";
import { JPakeParty } from "../src/pake/jpake";
import { JPAKE_GROUP_3072 } from "../src/pake/params";
import {
  SRP_TRACK2_4096_SHA256,
  SrpClientSession,
  SrpServerSession,
  register,
  requireValidU,
} from "../src/pake/srp6a";
import { asPassword, HandshakeAbort } from "../src/pake/types";
import { randomSalt } from "../src/pake/factories";
import { toHex } from "../src/pake/encoding";
import { Wire } from "../src/pake/wire";

const g = JPAKE_GROUP_3072;

describe("NIZK soundness (RFC 8235 Schnorr, toy)", () => {
  const x = 1234567n;
  const G = modPow(g.g, x, g.p);
  const proof = proveSchnorr(g, g.g, x, G, "Alice", "ctx", 42n);

  it("a valid proof verifies for its own statement", () => {
    expect(verifySchnorr(g, g.g, G, proof, "Alice", "ctx")).toBe(true);
  });
  it("a proof does NOT verify for a DIFFERENT exponent's statement (soundness)", () => {
    const Gwrong = modPow(g.g, x + 1n, g.p);
    expect(verifySchnorr(g, g.g, Gwrong, proof, "Alice", "ctx")).toBe(false);
  });
  it("a tampered response r fails verification", () => {
    const tampered = { V: proof.V, r: (proof.r + 1n) % g.q };
    expect(verifySchnorr(g, g.g, G, tampered, "Alice", "ctx")).toBe(false);
  });
  it("a proof bound to the wrong participant id is refused (identity binding)", () => {
    expect(verifySchnorr(g, g.g, G, proof, "Mallory", "ctx")).toBe(false);
  });
  it("a proof bound to the wrong context is refused", () => {
    expect(verifySchnorr(g, g.g, G, proof, "Alice", "other-ctx")).toBe(false);
  });
});

describe("SRP u == 0 guard", () => {
  it("requireValidU throws on 0 and passes otherwise", () => {
    expect(() => requireValidU(0n)).toThrow(HandshakeAbort);
    expect(() => requireValidU(1n)).not.toThrow();
  });
});

describe("J-PAKE structural rejections", () => {
  const nonces = { e1: 3n, e2: 5n, v1: 7n, v2: 11n, vr: 13n };
  it("identical participant ids are rejected", () => {
    expect(
      () =>
        new JPakeParty({ role: "A", selfId: "Alice", peerId: "Alice", password: asPassword("x"), nonces }),
    ).toThrow(/identical participant/i);
  });
  it("a degenerate second exponent (x2 ≡ 0 mod q) is rejected", () => {
    expect(
      () =>
        new JPakeParty({
          role: "A",
          selfId: "Alice",
          peerId: "Bob",
          password: asPassword("x"),
          nonces: { ...nonces, e2: g.q }, // q ≡ 0 (mod q)
        }),
    ).toThrow(/degenerate exponent/i);
  });
});

describe("Empty password runs (with a UI warning) but still completes the protocol", () => {
  it("SRP with an empty password still reaches a confirmed shared key", () => {
    const p = SRP_TRACK2_4096_SHA256;
    const salt = randomSalt();
    const empty = asPassword("");
    const rec = register(p, "arthur", empty, salt);
    const c = new SrpClientSession(p, "arthur", empty, 424242n);
    const s = new SrpServerSession(p, rec, 131313n);
    const wire = new Wire();
    const cProof = c.proof(wire.send(s.hello(wire.send(c.hello()))));
    const sProof = s.proof(wire.send(cProof));
    c.confirm(wire.send(sProof));
    expect(c.phase).toBe("confirmed");
    expect(s.phase).toBe("confirmed");
    expect(toHex(c.sessionKeyBytes!)).toBe(toHex(s.sessionKeyBytes!));
  });
});
