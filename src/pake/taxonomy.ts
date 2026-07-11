// The PAKE family property matrix. Data only — the UI renders it. The OPAQUE row is
// a REFERENCE (this lab does not rebuild OPAQUE) and carries the deep link to the
// sibling lab. `constructionFamily` is a per-row field so a future PQ-PAKE row's
// different shape (KEM-EKE / OPRF) is visible in the matrix, not hidden (see the
// extension seam). All standardization claims are per-row so each reads accurately.

export type PakeKind = "balanced" | "augmented" | "augmented (aPAKE)";
export type ConstructionFamily = "DH-group" | "KEM-EKE" | "OPRF";

export interface TaxonomyRow {
  readonly id: string;
  readonly name: string;
  readonly kind: PakeKind;
  /** what the server stores (the balanced-vs-augmented crux). */
  readonly serverStored: string;
  readonly rounds: string;
  readonly quantumResistant: boolean;
  readonly constructionFamily: ConstructionFamily;
  readonly standardization: string;
  readonly deployment: string;
  /** one-line "reach for it when…". */
  readonly reachFor: string;
  readonly reference?: boolean;
  readonly deepLink?: { href: string; label: string };
  readonly notes?: string;
}

export const TAXONOMY: TaxonomyRow[] = [
  {
    id: "srp6a",
    name: "SRP-6a",
    kind: "augmented",
    serverStored: "verifier {salt, v = g^x} — never the password",
    rounds: "2 (client hello / server hello, then mutual proof)",
    quantumResistant: false,
    constructionFamily: "DH-group",
    standardization: "RFC 2945 / RFC 5054 (Informational)",
    deployment: "iCloud Keychain; a former TLS-SRP ciphersuite",
    reachFor:
      "an augmented PAKE with wide deployment history where the server must not hold the password.",
    notes:
      "Stolen {salt, v} still permits a DIRECT per-user offline dictionary attack (recompute v'=g^{H(salt,H(user:pass'))}, compare to v).",
  },
  {
    id: "jpake",
    name: "J-PAKE",
    kind: "balanced",
    serverStored:
      "no augmented verifier record — but BOTH peers still hold the shared password/credential",
    rounds: "2 rounds + key confirmation",
    quantumResistant: false,
    constructionFamily: "DH-group",
    standardization: "RFC 8236 (Informational), Schnorr NIZK per RFC 8235; ISO/IEC 11770-4",
    deployment: "Thread (IoT) commissioning; Pale Moon Sync; Firefox Sync 1.1 (retired 2015)",
    reachFor:
      "a symmetric/balanced setting (two peers, same secret) with no asymmetric verifier database.",
    notes:
      "Balanced ≠ 'nothing stored': compromise of a peer's secret storage can expose the password directly.",
  },
  {
    id: "cpace",
    name: "CPace",
    kind: "balanced",
    serverStored:
      "no augmented verifier record — both peers hold the shared password (balanced)",
    rounds: "1 round (+ pinned confirmation)",
    quantumResistant: false,
    constructionFamily: "DH-group",
    standardization:
      "draft-irtf-cfrg-cpace-21 — an ACTIVE CFRG Internet-Draft (intended Informational RFC); NOT yet an RFC (never 'RFC 9836')",
    deployment: "the CFRG-selected balanced PAKE; reference implementations exist, broad deployment still early",
    reachFor:
      "a compact modern balanced PAKE — the CFRG's recommended choice for new balanced designs.",
    notes: "Password-and-context-derived generator + ephemeral DH + transcript-bound ISK.",
  },
  {
    id: "dragonfly",
    name: "Dragonfly / SAE",
    kind: "balanced",
    serverStored:
      "balanced — both peers hold an identical password representation; a stolen SALTED database still permits impersonation (RFC 7664 §4)",
    rounds: "1 commit/confirm exchange (after PE derivation)",
    quantumResistant: false,
    constructionFamily: "DH-group",
    standardization: "RFC 7664 (Informational); IEEE 802.11 SAE builds 802.11 framing on top",
    deployment: "WPA3 personal (SAE)",
    reachFor:
      "network access authentication where the two peers share one secret; the family behind WPA3.",
    notes:
      "Hunting-and-pecking password mapping is the surface Dragonblood (2019) attacked via iteration-count timing / cache side-channels.",
  },
  {
    id: "opaque",
    name: "OPAQUE",
    kind: "augmented (aPAKE)",
    serverStored:
      "an OPRF-derived envelope; password hidden from the server even during registration",
    rounds: "2 (OPRF + 3DH stages)",
    quantumResistant: false,
    constructionFamily: "OPRF",
    standardization: "RFC 9807 (Informational, July 2025)",
    deployment: "WhatsApp (end-to-end encrypted backups); facebook/opaque-ke reference impl",
    reachFor:
      "a full asymmetric PAKE that hides the password from the server AND resists precomputation on breach.",
    reference: true,
    deepLink: {
      href: "https://systemslibrarian.github.io/crypto-lab-opaque-gate/",
      label: "Take the next step → OPAQUE Gate",
    },
    notes:
      "Secure against PRECOMPUTATION upon server compromise (unpredictable OPRF secret prevents reusable password→mapping tables) and forward-secret via 3DH. NOT immune to a per-user offline dictionary attack after full single-server compromise — RFC 9807 states this is inevitable once the credential file leaks; key stretching raises each guess's cost.",
  },
];

/** The three distinct breach economics the offline-grind simulator teaches. */
export const BREACH_ECONOMICS = {
  balancedTranscript:
    "Passive balanced-PAKE transcript (correctly executed): gives a passive attacker NO direct offline password test — guesses must go online.",
  srpVerifier:
    "Stolen SRP verifier: enables a DIRECT per-user offline password test at the attacker's own pace (recompute v'=g^{H(salt,H(user:pass'))}, compare to v).",
  opaqueServer:
    "Fully compromised single OPAQUE server: a per-user offline dictionary attack REMAINS possible (RFC 9807); what OPAQUE prevents is reusable PRECOMPUTATION, and key stretching hardens each guess.",
} as const;
