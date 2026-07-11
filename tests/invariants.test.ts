import { describe, it, expect } from "vitest";
import { Wire, auditTranscript } from "../src/pake/wire";
import {
  srpRegister,
  makeSrpClient,
  makeSrpServer,
  makeJPakeParty,
  makeCPaceParty,
  makeDragonflyParty,
  makePassword,
  cpaceCI,
} from "../src/pake/factories";
import type { WireMsg } from "../src/pake/types";
import { toHex } from "../src/pake/encoding";

const PW = "Zaphod-Beeblebrox-2!";

function srpTranscript() {
  const wire = new Wire();
  const pw = makePassword(PW);
  const rec = srpRegister("arthur", pw);
  const c = makeSrpClient("arthur", pw);
  const s = makeSrpServer(rec);
  const h = wire.send(c.hello());
  const sh = wire.send(s.hello(h));
  const cp = wire.send(c.proof(sh));
  const sp = wire.send(s.proof(cp));
  c.confirm(sp);
  return wire;
}
function jpakeTranscript() {
  const wire = new Wire();
  const pw = makePassword(PW);
  const A = makeJPakeParty("A", "Alice", "Bob", pw);
  const B = makeJPakeParty("B", "Bob", "Alice", pw);
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
  wire.send(A.confirm());
  wire.send(B.confirm());
  return wire;
}
function cpaceTranscript() {
  const wire = new Wire();
  const pw = makePassword(PW);
  const ci = cpaceCI("A", "B");
  const sid = new Uint8Array(16).fill(9);
  const A = makeCPaceParty("A", pw, ci, sid, new TextEncoder().encode("ADa"));
  const B = makeCPaceParty("B", pw, ci, sid, new TextEncoder().encode("ADb"));
  const am = wire.send(A.message());
  const bm = wire.send(B.message());
  A.receive(bm);
  B.receive(am);
  wire.send(A.confirm());
  wire.send(B.confirm());
  return wire;
}
function dragonflyTranscript() {
  const wire = new Wire();
  const pw = makePassword(PW);
  const A = makeDragonflyParty("Alice", "Bob", pw);
  const B = makeDragonflyParty("Bob", "Alice", pw);
  A.derivePE();
  B.derivePE();
  const ac = wire.send(A.commit());
  const bc = wire.send(B.commit());
  A.recvCommit(bc);
  B.recvCommit(ac);
  A.deriveKey();
  B.deriveKey();
  wire.send(A.confirm());
  wire.send(B.confirm());
  return wire;
}

describe("Invariant #1 — the password never crosses the wire (runtime backstop)", () => {
  const pw = makePassword(PW);
  for (const [name, build] of [
    ["SRP-6a", srpTranscript],
    ["J-PAKE", jpakeTranscript],
    ["CPace", cpaceTranscript],
    ["Dragonfly", dragonflyTranscript],
  ] as const) {
    it(`${name} transcript reveals no password (utf8/utf16/hex/base64)`, () => {
      const audit = auditTranscript(build().transcript(), pw);
      expect(audit.clean).toBe(true);
      expect(audit.hits).toEqual([]);
    });
  }
});

describe("Invariant #2 — clone-on-send (no shared reference across the wire)", () => {
  it("mutating the sender's message does not change what the receiver holds", () => {
    const wire = new Wire();
    const original: WireMsg = {
      protocol: "srp6a",
      step: "test",
      from: "client",
      fields: { A: toHex(new Uint8Array([0xab, 0xcd])) },
    };
    const delivered = wire.send(original);
    // mutate the sender's object AFTER send
    (original.fields as Record<string, string>).A = "ffff";
    expect(delivered.fields.A).toBe("abcd");
    // and the recorded transcript is likewise independent
    expect(wire.transcript()[0]!.fields.A).toBe("abcd");
  });
});

describe("Invariant #3 — SRP stores a verifier, not a password", () => {
  it("the registration record has only {I, salt, v} — no password field", () => {
    const rec = srpRegister("arthur", makePassword(PW));
    expect(Object.keys(rec).sort()).toEqual(["I", "salt", "v"]);
    // no field of the record contains the password in any form (bigint-safe stringify)
    const dump = JSON.stringify(rec, (_k, v) => (typeof v === "bigint" ? v.toString(16) : v));
    expect(dump).not.toContain(PW);
  });
});
