// Scripted launcher definitions. Each sets up a run configuration + an expected
// outcome blurb the UI shows before/while running. The tab controller consumes these.

import type { ProtocolId } from "./model.ts";

export type LauncherId =
  | "honest"
  | "wrong-password"
  | "observer"
  | "tamper"
  | "breach"
  | "dragonblood";

export interface Launcher {
  readonly id: LauncherId;
  readonly label: string;
  readonly expect: string;
}

export function launchersFor(protocol: ProtocolId): Launcher[] {
  const base: Launcher[] = [
    { id: "honest", label: "Honest run", expect: "Same password both sides → confirmed shared key (green success)." },
    { id: "wrong-password", label: "Wrong password", expect: "Different second password → keys differ, confirmation fails → red alarm." },
    { id: "observer", label: "On-path observer", expect: "Reveal what a passive attacker sees over the current transcript (raw bytes)." },
    { id: "tamper", label: "Active tamper (menu)", expect: "Pick one curated tamper op; watch the handshake fail-closed at the rejecting step." },
  ];
  const breach: Launcher =
    protocol === "srp6a"
      ? { id: "breach", label: "Server breach", expect: "Dump stored {salt, v}; it is NOT the password — needs an offline dictionary attack." }
      : { id: "breach", label: "Server breach (balanced lesson)", expect: "No augmented verifier record — but a peer's stored secret can still be exposed directly." };
  const out = [...base, breach];
  if (protocol === "dragonfly") {
    out.push({ id: "dragonblood", label: "Dragonblood side-channel", expect: "Modeled iteration count per candidate: legacy leaks, fixed-work is flat." });
  }
  return out;
}
