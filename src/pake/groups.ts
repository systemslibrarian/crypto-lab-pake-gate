// Group arithmetic (MODP / ristretto255 / P-256) and PROTOCOL-SPECIFIC decoders.
//
// Arithmetic only lives here; validation rules are per-protocol and per-field
// (invariant #7, edge cases). There is NO single permissive generic decoder — a
// blanket "reject any identity element" would wrongly abort valid J-PAKE handshakes.

import { RistrettoPoint } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/p256.js";
import { mod, invert, pow } from "@noble/curves/abstract/modular.js";
import { HandshakeAbort, type Hex } from "./types";
import { fromHex, i2osp, os2ip, padTo, toHex } from "./encoding";
import type { JPakeGroupParameters, SrpGroupParameters } from "./params";

// --- MODP arithmetic ---
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  return pow(mod(base, m), exp, m);
}
export function modInverse(a: bigint, m: bigint): bigint {
  return invert(mod(a, m), m);
}
export function modMul(a: bigint, b: bigint, m: bigint): bigint {
  return mod(a * b, m);
}

// ---------------------------------------------------------------------------
// SRP public-value decoding (RFC 5054): reject A % N == 0 (classic abort).
// ---------------------------------------------------------------------------
export function decodeSrpPublicValue(
  h: Hex,
  group: SrpGroupParameters,
  which: "A" | "B",
): bigint {
  const v = os2ip(fromHex(h));
  if (v <= 0n || v >= group.N) {
    throw new HandshakeAbort(
      `SRP ${which} out of range`,
      `${which} must satisfy 0 < ${which} < N; a non-canonical value is rejected.`,
    );
  }
  if (mod(v, group.N) === 0n) {
    throw new HandshakeAbort(
      `SRP ${which} % N == 0`,
      `${which} ≡ 0 (mod N) would force a known shared secret — classic SRP abort.`,
    );
  }
  return v;
}

// ---------------------------------------------------------------------------
// J-PAKE finite-field element decoding. Canonical 1 <= Y < p and Y^q == 1 (valid
// subgroup member). Identity rules are per-FIELD, passed in by the caller — g1/g3
// and a Schnorr commitment V may legitimately be 1; g2/g4 may not.
// ---------------------------------------------------------------------------
export interface JPakeDecodeRule {
  /** human label for tooltips/errors */
  readonly field: string;
  /** if true, Y == 1 (identity) is rejected (g2, g4, combined generators) */
  readonly rejectIdentity: boolean;
}

export function decodeJPakeElement(
  h: Hex,
  group: JPakeGroupParameters,
  rule: JPakeDecodeRule,
): bigint {
  const Y = os2ip(fromHex(h));
  if (Y < 1n || Y >= group.p) {
    throw new HandshakeAbort(
      `J-PAKE ${rule.field} not canonical`,
      `every received element must satisfy 1 ≤ Y < p; out-of-range is rejected.`,
    );
  }
  if (rule.rejectIdentity && Y === 1n) {
    throw new HandshakeAbort(
      `J-PAKE ${rule.field} is the identity`,
      `only g2/g4 and the Round-2 combined generators must be non-identity; ` +
        `${rule.field} = 1 is refused (g1/g3/V may be 1).`,
    );
  }
  if (modPow(Y, group.q, group.p) !== 1n) {
    throw new HandshakeAbort(
      `J-PAKE ${rule.field} not in prime-order subgroup`,
      `Y^q mod p must equal 1; a value outside the subgroup could leak key bits.`,
    );
  }
  return Y;
}

// ---------------------------------------------------------------------------
// Ristretto255 element decoding (CPace). Any 32-byte string that decodes is a valid
// group element (ristretto absorbs the cofactor); we additionally reject the
// identity, which CPace forbids for K and for the generator.
// ---------------------------------------------------------------------------
export type RistPoint = InstanceType<typeof RistrettoPoint>;

export function decodeRistrettoElement(h: Hex, field: string): RistPoint {
  let P: RistPoint;
  try {
    P = RistrettoPoint.fromHex(h);
  } catch {
    throw new HandshakeAbort(
      `CPace ${field} not a canonical ristretto255 encoding`,
      `non-canonical point encodings are rejected — lenient parsing is a vuln class.`,
    );
  }
  if (P.is0()) {
    throw new HandshakeAbort(
      `CPace ${field} is the identity element`,
      `the identity element must be excluded — it would fix a known key.`,
    );
  }
  return P;
}

export function ristrettoToHex(P: RistPoint): Hex {
  return toHex(P.toBytes());
}

/** Ristretto one-way map from 64 uniform bytes (CPace element_derivation). */
export function ristrettoFromUniform(bytes64: Uint8Array): RistPoint {
  return RistrettoPoint.hashToCurve(bytes64);
}

// ---------------------------------------------------------------------------
// Dragonfly / P-256 element decoding. Uncompressed SEC1 (65 bytes, 0x04||X||Y),
// must be on-curve and not the identity. Reflection is checked by the engine.
// ---------------------------------------------------------------------------
export type P256Point = ReturnType<typeof p256.Point.fromHex>;

export const P256 = p256;
export const P256_FIELD_P: bigint = p256.Point.Fp.ORDER; // field prime p
export const P256_ORDER_N: bigint = p256.Point.Fn.ORDER; // group order n

export function decodeDragonflyCommitElement(h: Hex, field: string): P256Point {
  const bytes = fromHex(h);
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new HandshakeAbort(
      `Dragonfly ${field} not uncompressed SEC1`,
      `element must be exactly 65 bytes (0x04 || X || Y); other encodings are refused.`,
    );
  }
  let P: P256Point;
  try {
    P = p256.Point.fromHex(bytes);
    P.assertValidity();
  } catch {
    throw new HandshakeAbort(
      `Dragonfly ${field} not on curve`,
      `off-curve / small-order points are rejected — canonical on-curve validation is mandatory.`,
    );
  }
  if (P.is0?.() ?? false) {
    throw new HandshakeAbort(
      `Dragonfly ${field} is the identity`,
      `the identity element is not a valid commit — rejected fail-closed.`,
    );
  }
  return P;
}

export function p256PointToHex(P: P256Point): Hex {
  return toHex(P.toBytes(false)); // uncompressed 65-byte SEC1
}

/** Fixed 32-byte big-endian scalar encoding (Dragonfly). */
export function scalar32(n: bigint): Hex {
  return toHex(i2osp(n, 32));
}

/** Left-pad an integer to length(N) bytes and hex it (SRP/J-PAKE PAD-for-hash). */
export function padHex(n: bigint, len: number): Hex {
  return toHex(padTo(i2osp(n, len), len));
}
