// The Dragonblood side-channel comparison panel (Vanhoef & Ronen, 2019).
//
// This module is STRICTLY for the side-channel comparison — it never produces the
// honest handshake's keys (invariant #8; the honest run lives in dragonfly.ts and
// uses the accurate minimum-k loop). It contrasts teaching models by MODELED
// ITERATION COUNT, which is the authoritative signal; raw browser wall-clock timing
// is explicitly NOT the oracle (JIT/GC/timer-precision noise) and, if ever shown, is
// a secondary overlay only.
//
// The lesson: the LEGACY early-exit model's iteration count depends on the password
// (the leak Dragonblood exploited); the FIXED-WORK teaching model's does not (but it
// FAILS rather than inventing a PE if none is found within its cap). "Fixed-work
// teaching variant" — NEVER "constant-time": browser TS gives no such guarantee.

import { huntAndPeckScan } from "./dragonfly";
import type { Password } from "./types";

export type SideChannelModel = "legacy-early-exit" | "fixed-work";

export interface ModelRun {
  readonly model: SideChannelModel;
  readonly password: string;
  /** modeled iteration count — the authoritative side-channel signal. */
  readonly modeledIterations: number;
  /**
   * Iterations the scan behind this run ACTUALLY executed, counted by the loop.
   *
   * This field exists so that "the fixed-work model is flat" is falsifiable. Before,
   * `fixedWork` returned `modeledIterations: cap` as a literal and never ran a
   * fixed-work loop at all — it called the early-exit counter and then stated the
   * number it wished were true. Every check of the mitigation (the panel's own
   * summary line, the unit test, the browser test) therefore compared a constant with
   * itself and could not fail. Reading this field instead means a fixed-work model
   * that quietly early-exits reports the counter it stopped at, and those checks bite.
   */
  readonly iterationsPerformed: number;
  /** whether a valid PE was found within the modeled work. */
  readonly found: boolean;
  /** the true first-valid counter (what the leak reveals), for teaching. */
  readonly firstValidAt: number | null;
}

export interface DragonbloodComparison {
  readonly idA: string;
  readonly idB: string;
  readonly fixedWorkCap: number;
  readonly runs: ModelRun[];
  /** true iff the legacy model's iteration count varies across the candidates. */
  readonly legacyLeaks: boolean;
  /** true iff the fixed-work model's iteration count is constant across candidates. */
  readonly fixedWorkFlat: boolean;
}

/**
 * Legacy vulnerable model: exits as soon as the first valid PE is found. Its modeled
 * iteration count == the first-valid counter → password-dependent (the leak).
 */
export function legacyEarlyExit(idA: string, idB: string, password: Password): ModelRun {
  const scan = huntAndPeckScan(idA, idB, password, { earlyExit: true });
  const at = scan.firstValidAt;
  return {
    model: "legacy-early-exit",
    password: password as string,
    modeledIterations: at === null ? Number.NaN : scan.iterationsPerformed,
    iterationsPerformed: scan.iterationsPerformed,
    found: at !== null,
    firstValidAt: at,
  };
}

/**
 * Fixed-work teaching model: always performs exactly `cap` modeled iterations (no
 * early exit) and selects the first valid candidate. If NONE is valid within the cap,
 * it FAILS — it never invents a PE.
 *
 * `modeledIterations` is COUNTED BY THE SCAN, not assigned from `cap`. It used to be
 * the literal `cap`, which made "the fixed-work model is flat" a tautology: the
 * panel, the unit test and the browser test all compared a constant with itself and
 * could not have failed. Counting the loop's own work means reintroducing an early
 * exit here would make the reported numbers vary and every one of those checks bite.
 */
export function fixedWork(
  idA: string,
  idB: string,
  password: Password,
  cap: number,
): ModelRun {
  const scan = huntAndPeckScan(idA, idB, password, { maxCounter: cap, earlyExit: false });
  const at = scan.firstValidAt;
  return {
    model: "fixed-work",
    password: password as string,
    modeledIterations: scan.iterationsPerformed,
    iterationsPerformed: scan.iterationsPerformed,
    found: at !== null && at <= cap,
    firstValidAt: at,
  };
}

/** Run both models over a candidate list and summarize whether the leak shows. */
export function compareModels(
  idA: string,
  idB: string,
  candidates: Password[],
  fixedWorkCap = 40,
): DragonbloodComparison {
  const runs: ModelRun[] = [];
  for (const pw of candidates) {
    runs.push(legacyEarlyExit(idA, idB, pw));
    runs.push(fixedWork(idA, idB, pw, fixedWorkCap));
  }
  const legacyCounts = runs.filter((r) => r.model === "legacy-early-exit").map((r) => r.modeledIterations);
  // Flatness is judged on the iterations the fixed-work scans REALLY performed.
  const fixedCounts = runs.filter((r) => r.model === "fixed-work").map((r) => r.iterationsPerformed);
  return {
    idA,
    idB,
    fixedWorkCap,
    runs,
    legacyLeaks: new Set(legacyCounts).size > 1,
    fixedWorkFlat: new Set(fixedCounts).size === 1,
  };
}
