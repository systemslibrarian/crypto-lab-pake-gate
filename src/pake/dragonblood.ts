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

import { firstValidCounter } from "./dragonfly";
import type { Password } from "./types";

export type SideChannelModel = "legacy-early-exit" | "fixed-work";

export interface ModelRun {
  readonly model: SideChannelModel;
  readonly password: string;
  /** modeled iteration count — the authoritative side-channel signal. */
  readonly modeledIterations: number;
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
  const at = firstValidCounter(idA, idB, password);
  return {
    model: "legacy-early-exit",
    password: password as string,
    modeledIterations: at ?? Number.NaN,
    found: at !== null,
    firstValidAt: at,
  };
}

/**
 * Fixed-work teaching model: always performs exactly `cap` modeled iterations (no
 * early exit) and selects the first valid candidate. If NONE is valid within the cap,
 * it FAILS — it never invents a PE. Iteration count is `cap` regardless of password.
 */
export function fixedWork(
  idA: string,
  idB: string,
  password: Password,
  cap: number,
): ModelRun {
  const at = firstValidCounter(idA, idB, password, cap);
  return {
    model: "fixed-work",
    password: password as string,
    modeledIterations: cap, // constant work, independent of the password
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
  const fixedCounts = runs.filter((r) => r.model === "fixed-work").map((r) => r.modeledIterations);
  return {
    idA,
    idB,
    fixedWorkCap,
    runs,
    legacyLeaks: new Set(legacyCounts).size > 1,
    fixedWorkFlat: new Set(fixedCounts).size === 1,
  };
}
