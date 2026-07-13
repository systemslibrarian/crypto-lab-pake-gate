// The shared UI model over all four engines. Each protocol is wrapped in a Runner
// that exposes a uniform, step-at-a-time interface so the panels stay generic.

import type { WireMsg } from "../pake/types.ts";
import { SHA256 } from "../pake/hashes.ts";
import { toHex } from "../pake/encoding.ts";

export type ProtocolId = "srp6a" | "jpake" | "cpace" | "dragonfly";

export type SideId = "left" | "right";

/** A scratchpad row: a private/derived value shown inside a peer box. */
export interface ScratchRow {
  readonly label: string;
  readonly value: string;
  /** true = a secret that must never touch the wire (locked styling). */
  readonly secret: boolean;
  /**
   * Plain-language name for the "Start here / simple" view — e.g. "my private
   * nonce" for `a (private nonce)`. Shown in place of the notation for newcomers.
   */
  readonly plain?: string;
  /**
   * Glossary key (see ui/glossary.ts). When present the notation label gets an
   * in-context, one-sentence definition on hover / focus.
   */
  readonly term?: string;
}

/** A rendered peer at a moment in time. */
export interface PeerView {
  readonly title: string;
  readonly role: string;
  readonly scratch: ScratchRow[];
}

/** A card on the Wire. */
export interface WireCard {
  readonly msg: WireMsg;
  /** field names produced/changed by the step that pushed this card. */
  readonly highlight: string[];
  /**
   * One-sentence, plain-language description of WHAT this message is — leads the
   * hex so a newcomer can follow the handshake as a story, not a byte dump.
   */
  readonly caption?: string;
  /** if the receiving side rejected it, the abort tooltip. */
  aborted?: { reason: string; tooltip: string };
  /** if this card was tampered before delivery. */
  tampered?: boolean;
}

/** The right-hand key view for one side. */
export interface KeyView {
  readonly present: boolean;
  readonly keyBytes?: Uint8Array;
  readonly confirmed: boolean;
}

export type RunStatus =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "confirmed" } // both keys match AND confirmation verified
  | { kind: "mismatch"; message: string } // completed but keys differ / not confirmed
  | { kind: "aborted"; message: string; tooltip: string };

/**
 * A tamper operation from the curated menu. Applied to a produced WireMsg *before*
 * delivery: flips one hex nibble in one field.
 */
export interface TamperOp {
  readonly id: string;
  readonly label: string;
  /** which step's produced message to mutate (step name on the WireMsg). */
  readonly step: string;
  readonly field: string;
  /** documented expected outcome. */
  readonly expect: string;
}

/** The uniform runner interface each engine wrapper implements. */
export interface Runner {
  readonly protocol: ProtocolId;
  /** number of remaining steps that can still be taken. */
  hasNext(): boolean;
  /** total step count for progress display. */
  totalSteps(): number;
  /** index of the next step (0-based). */
  nextIndex(): number;
  /**
   * Advance exactly one protocol message. Returns the produced WireCard (if this
   * step put something on the wire) or null (pure local computation). Throws only in
   * unexpected cases; HandshakeAbort is caught internally and surfaced via status().
   */
  step(): { card: WireCard | null; label: string };
  leftPeer(): PeerView;
  rightPeer(): PeerView;
  leftKey(): KeyView;
  rightKey(): KeyView;
  status(): RunStatus;
  /** the curated tamper menu for this protocol. */
  tamperMenu(): TamperOp[];
  /** arm a tamper op (or clear with null). Must be set before the target step runs. */
  setTamper(op: TamperOp | null): void;
  armedTamper(): TamperOp | null;
}

// --- shared formatting helpers -------------------------------------------------

export function bigHex(n: bigint): string {
  let h = n.toString(16);
  if (h.length % 2 === 1) h = "0" + h;
  return h;
}

export function bytesHex(b: Uint8Array): string {
  return toHex(b);
}

/** Truncate a long hex string for display (keeps head + tail). */
export function truncMiddle(hex: string, head = 12, tail = 8): string {
  if (hex.length <= head + tail + 3) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

/** Short fingerprint of key bytes: first 8 bytes of SHA-256(key), hex. */
export function fingerprint(keyBytes: Uint8Array): string {
  const h = SHA256(keyBytes);
  return toHex(h.slice(0, 8));
}

export function bytesEqual(a?: Uint8Array, b?: Uint8Array): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Flip one hex nibble in a field value (for the tamper menu). */
export function flipNibble(hex: string): string {
  if (hex.length === 0) return hex;
  // Flip the last nibble deterministically (xor with 1), keeping it valid hex.
  const chars = hex.split("");
  const i = chars.length - 1;
  const v = parseInt(chars[i]!, 16);
  chars[i] = ((v ^ 0x1) & 0xf).toString(16);
  return chars.join("");
}
