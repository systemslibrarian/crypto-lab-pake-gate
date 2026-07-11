import { describe, it, expect } from "vitest";
import {
  SRP_TRACK2_4096_SHA256,
  computeVerifier,
  computeX,
  register,
} from "../src/pake/srp6a";
import { passwordToScalar } from "../src/pake/jpake";
import { JPAKE_GROUP_3072 } from "../src/pake/params";
import {
  makeJPakeParty,
  makePassword,
  randomSalt,
} from "../src/pake/factories";
import { SHA256 } from "../src/pake/hashes";
import { i2osp, toHex, utf8Nfc } from "../src/pake/encoding";
import { Wire } from "../src/pake/wire";

// Backs the side-by-side offline-grind simulator: the balanced-vs-augmented asymmetry.
const CANDIDATES = ["password", "letmein", "hunter2", "dragon", "correct horse", "qwerty", "trustno1", "swordfish"];
const TRUE_PW = "correct horse";

describe("Offline-grind asymmetry", () => {
  it("stolen SRP verifier: exactly the true password recomputes v (a direct offline test)", () => {
    const p = SRP_TRACK2_4096_SHA256;
    const salt = randomSalt();
    const record = register(p, "arthur", makePassword(TRUE_PW), salt);
    const matches = CANDIDATES.filter((guess) => {
      const x = computeX(p, "arthur", makePassword(guess), record.salt);
      return computeVerifier(p, x) === record.v; // v' == v ?
    });
    expect(matches).toEqual([TRUE_PW]); // only the true password matches
  });

  it("balanced transcript: no verifier-shaped value to grind (inconclusive for every guess)", () => {
    // Build an honest J-PAKE transcript.
    const wire = new Wire();
    const pw = makePassword(TRUE_PW);
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

    // Collect every hex value an on-path observer sees.
    const wireHex = new Set<string>();
    for (const m of wire.transcript()) {
      for (const v of Object.values(m.fields)) if (typeof v === "string") wireHex.add(v);
    }

    // A passive attacker with the TRUE password still has nothing verifier-shaped to
    // test against: neither the password scalar s nor H(password) appears on the wire.
    const sHex = toHex(i2osp(passwordToScalar(JPAKE_GROUP_3072, pw), JPAKE_GROUP_3072.pLen));
    const hPwHex = toHex(SHA256(utf8Nfc(TRUE_PW)));
    for (const w of wireHex) {
      expect(w.includes(sHex)).toBe(false);
      expect(w.includes(hPwHex)).toBe(false);
    }
    // Wrong guesses are equally inconclusive — there is simply no offline oracle.
    expect(wireHex.size).toBeGreaterThan(0);
  });
});
