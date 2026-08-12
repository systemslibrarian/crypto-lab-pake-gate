import { describe, it, expect } from "vitest";
import {
  DragonflyParty,
  derivePasswordElement,
  firstValidCounter,
  huntAndPeckScan,
  type DragonflyConfig,
} from "../src/pake/dragonfly";
import { compareModels, fixedWork, legacyEarlyExit } from "../src/pake/dragonblood";
import {
  DEMO_ID_A,
  DEMO_ID_B,
  DRAGONBLOOD_CANDIDATES,
  DRAGONBLOOD_FIXED_WORK_CAP,
} from "../src/ui/model";
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

  /**
   * Regression: "the fixed-work variant is flat" used to be unfalsifiable.
   * `fixedWork()` returned `modeledIterations: cap` as a literal, so the panel's
   * "constant work" line, the assertion above and the browser test all compared a
   * constant with itself. Re-introducing an early exit into the fixed-work model —
   * the exact regression the mitigation exists to prevent — would have changed
   * nothing any check could see.
   *
   * These assertions run on the SHIPPED panel configuration (identities, candidate
   * list and cap all imported from the UI module rather than chosen here), and they
   * require the interesting state to actually occur.
   */
  it("fixed-work flatness is COUNTED by the loop, on the shipped panel configuration", () => {
    const cap = DRAGONBLOOD_FIXED_WORK_CAP;
    const shipped = DRAGONBLOOD_CANDIDATES.map(asPassword);

    // The test only means anything if some candidate finds a PE well before the cap —
    // that gap is what an early exit would skip. Fail loudly if it never happens.
    const firstValid = shipped.map((pw) => firstValidCounter(DEMO_ID_A, DEMO_ID_B, pw));
    expect(firstValid.every((v) => v !== null)).toBe(true);
    const earlyOnes = firstValid.filter((v) => v !== null && v < cap);
    expect(
      earlyOnes.length,
      "no shipped candidate finds a PE before the cap, so this test proves nothing",
    ).toBeGreaterThan(0);

    // The fixed-work MODEL really executes every iteration despite that. Note this
    // reads what `fixedWork` itself reports — re-running the scan here instead would
    // check the loop rather than the model, and would still pass if the model went
    // back to early-exiting and stating the cap.
    for (const pw of shipped) {
      const run = fixedWork(DEMO_ID_A, DEMO_ID_B, pw, cap);
      expect(run.iterationsPerformed).toBe(cap);
      expect(run.modeledIterations).toBe(run.iterationsPerformed);
      expect(run.found).toBe(true);
    }

    // The legacy model, over the SAME shipped candidates, really does less work — and
    // a DIFFERENT amount for different passwords. That difference is the leak the
    // panel plots, so it must be non-zero here or the panel's claim is empty.
    const legacyRuns = shipped.map((pw) => legacyEarlyExit(DEMO_ID_A, DEMO_ID_B, pw));
    const legacyCounts = legacyRuns.map((r) => r.iterationsPerformed);
    expect(legacyRuns.every((r) => r.modeledIterations === r.iterationsPerformed)).toBe(true);
    expect(legacyCounts.every((c) => c < cap)).toBe(true);
    expect(
      new Set(legacyCounts).size,
      "the shipped candidates must not all cost the same, or the plotted leak is flat",
    ).toBeGreaterThan(1);
    expect(compareModels(DEMO_ID_A, DEMO_ID_B, shipped, cap).legacyLeaks).toBe(true);
  });

  it("an early-exit scan stops at the first valid counter; a fixed-work scan does not", () => {
    const pw = asPassword("correct-horse");
    const early = huntAndPeckScan(DEMO_ID_A, DEMO_ID_B, pw, { maxCounter: 40, earlyExit: true });
    const flat = huntAndPeckScan(DEMO_ID_A, DEMO_ID_B, pw, { maxCounter: 40, earlyExit: false });
    expect(early.firstValidAt).toBe(flat.firstValidAt);
    expect(early.iterationsPerformed).toBe(early.firstValidAt);
    expect(flat.iterationsPerformed).toBe(40);
    expect(flat.iterationsPerformed).toBeGreaterThan(early.iterationsPerformed);
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
