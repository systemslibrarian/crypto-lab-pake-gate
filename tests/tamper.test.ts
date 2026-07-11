import { describe, it, expect } from "vitest";
import { JPakeParty } from "../src/pake/jpake";
import { JPAKE_GROUP_3072 } from "../src/pake/params";
import { asPassword, HandshakeAbort, type Hex, type WireMsg } from "../src/pake/types";
import { SHA256 } from "../src/pake/hashes";
import { os2ip, utf8Nfc } from "../src/pake/encoding";

// Deterministic nonces (fixed) so the tamper outcome is reproducible, not flaky.
const q = JPAKE_GROUP_3072.q;
const n = (label: string) => (os2ip(SHA256(utf8Nfc(label))) % (q - 1n)) + 1n;
const PW = "thread-network";

// Backs the "Active tamper (curated menu)" launcher: mutating a Round-1 element or
// Schnorr proof makes NIZK verification fail at the RECEIVING step and aborts
// fail-closed BEFORE any session key is computed (assert the key is still undefined).

function flipNibble(msg: WireMsg, field: string): WireMsg {
  const clone: WireMsg = JSON.parse(JSON.stringify(msg));
  const v = clone.fields[field];
  if (typeof v !== "string") throw new Error("field not hex");
  const flipped = ((parseInt(v[0]!, 16) ^ 0x1) & 0xf).toString(16);
  (clone.fields as Record<string, Hex>)[field] = (flipped + v.slice(1)) as Hex;
  return clone;
}

// Alice's honest Round-1 message (fixed nonces).
function aliceRound1(): WireMsg {
  const A = new JPakeParty({
    role: "A",
    selfId: "Alice",
    peerId: "Bob",
    password: asPassword(PW),
    nonces: { e1: n("a1"), e2: n("a2"), v1: n("av1"), v2: n("av2"), vr: n("avr") },
  });
  return A.round1();
}
// A fresh Bob that has sent its own Round-1 and is ready to receive Alice's.
function readyBob() {
  const B = new JPakeParty({
    role: "B",
    selfId: "Bob",
    peerId: "Alice",
    password: asPassword(PW),
    nonces: { e1: n("b3"), e2: n("b4"), v1: n("bv3"), v2: n("bv4"), vr: n("bvr") },
  });
  B.round1();
  return B;
}

describe("Active tamper aborts pre-key (J-PAKE)", () => {
  it("corrupting a Round-1 Schnorr proof (r1) → verification fails, no key produced", () => {
    const tampered = flipNibble(aliceRound1(), "r1");
    const B = readyBob();
    expect(() => B.recvRound1(tampered)).toThrow(HandshakeAbort);
    expect(B.phase).toBe("aborted");
    expect(B.sessionKeyBytes).toBeUndefined(); // pre-key abort
  });

  it("corrupting a Round-1 element (g1) → aborts fail-closed, no key", () => {
    const tampered = flipNibble(aliceRound1(), "g1");
    const B = readyBob();
    expect(() => B.recvRound1(tampered)).toThrow(HandshakeAbort);
    expect(B.phase).toBe("aborted");
    expect(B.sessionKeyBytes).toBeUndefined();
  });
});
