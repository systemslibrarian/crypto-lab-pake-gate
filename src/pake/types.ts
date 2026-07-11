// Branded types + Phase state machines + the extension seam.
//
// The load-bearing barrier (invariant #1): every value that crosses the wire is a
// `Hex` string (or a plain number). A `Password` is a *distinctly* branded string
// and is NOT assignable to `Hex`, so a `WireMsg` typed with `Hex` fields cannot be
// constructed containing a Password at compile time. See tests/type-barrier for the
// `@ts-expect-error` proof. Runtime scanning (wire.ts audit) is only a secondary
// backstop — it cannot prove the absence of every reversible encoding, and says so.

declare const brandSymbol: unique symbol;
type Brand<T, B extends string> = T & { readonly [brandSymbol]: B };

/** A UTF-8 password. Deliberately un-assignable to Hex so it cannot reach the wire. */
export type Password = Brand<string, "Password">;

/** A lowercase hex string. The ONLY string shape permitted on the wire. */
export type Hex = Brand<string, "Hex">;

/** An integer scalar (exponent / private value), reduced mod the relevant order. */
export type Scalar = Brand<bigint, "Scalar">;

/** A finite-field group element (MODP), as an integer in [0, p). */
export type FieldEl = Brand<bigint, "FieldEl">;

export function asPassword(s: string): Password {
  return s as Password;
}
export function asScalar(n: bigint): Scalar {
  return n as Scalar;
}
export function asFieldEl(n: bigint): FieldEl {
  return n as FieldEl;
}

// ---------------------------------------------------------------------------
// Wire messages. A WireMsg is a plain, serializable DTO whose byte-bearing
// fields are ALL `Hex`. Constructed only by protocol factories (see each engine
// + wire.ts). `kind` tags the protocol/step for the transcript UI.
// ---------------------------------------------------------------------------

export interface WireMsg {
  readonly protocol: "srp6a" | "jpake" | "cpace" | "dragonfly";
  readonly step: string;
  readonly from: "A" | "B" | "client" | "server";
  /**
   * Byte-bearing fields: every value is `Hex` (or a plain number). A `Password` is a
   * branded string that is NOT assignable to `Hex`, and a bare `string` is not either
   * — so nothing but a value that went through toHex() can land on the wire. This is
   * the real compile-time barrier of invariant #1 (see tests/type-barrier.test.ts).
   */
  readonly fields: Readonly<Record<string, Hex | number>>;
}

// ---------------------------------------------------------------------------
// Per-engine Phase state machines (invariant #5, made structural). Every engine
// advances through an explicit enum and refuses out-of-order invocation, so a key
// can never be derived on an unverified transcript. Each ends in confirmed|aborted.
// ---------------------------------------------------------------------------

export type SrpPhase =
  | "init"
  | "registered"
  | "client-hello-sent" // A sent
  | "server-hello-sent" // B, salt sent
  | "u-computed"
  | "key-derived"
  | "client-proof-sent" // M1 sent
  | "server-proof-sent" // M2 sent
  | "confirmed"
  | "aborted";

export type JPakePhase =
  | "init"
  | "round1-sent"
  | "round1-verified"
  | "round2-sent"
  | "round2-verified"
  | "key-derived"
  | "confirm-sent"
  | "confirmed"
  | "aborted";

export type CPacePhase =
  | "init"
  | "msg-sent"
  | "msg-received"
  | "isk-derived"
  | "confirm-sent"
  | "confirmed"
  | "aborted";

export type DragonflyPhase =
  | "init"
  | "pe-derived"
  | "commit-sent"
  | "commit-received"
  | "key-derived"
  | "confirm-sent"
  | "confirmed"
  | "aborted";

export class PhaseError extends Error {
  constructor(expected: string, actual: string) {
    super(`out-of-order handshake step: expected phase ${expected}, was ${actual}`);
    this.name = "PhaseError";
  }
}

export class HandshakeAbort extends Error {
  constructor(
    public readonly reason: string,
    public readonly tooltip: string,
  ) {
    super(reason);
    this.name = "HandshakeAbort";
  }
}

// ---------------------------------------------------------------------------
// Extension seam (PQ-PAKE). See docs/pq-pake-seam.md. A KEM is NOT a drop-in for a
// DH group: the four current engines consume a DhGroup; a future PQ-PAKE engine
// consumes KemBackend + PasswordKeyedEncoding (an EKE-style wrapper), never a Group.
// ---------------------------------------------------------------------------

export interface DhGroup {
  readonly kind: "dh-group";
  readonly name: string;
}

export interface KemBackend {
  readonly kind: "kem";
  readonly name: string;
  // keygen / encaps / decaps — stubs only in this pass. // [extension] point
}

export interface PasswordKeyedEncoding {
  readonly kind: "password-keyed-encoding";
  // encryptPubkey / decryptPubkey under a password-derived key. // [extension] point
}

export type PakeBackend = DhGroup | KemBackend;
