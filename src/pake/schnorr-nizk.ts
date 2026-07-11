// Schnorr NIZK proof of knowledge of a discrete log (RFC 8235), used by J-PAKE.
//
// The proof binds the prover's participant identity and a context string, so a proof
// valid "in the abstract" but presenting the wrong participant id is refused
// (invariant #5 / edge cases). The challenge is over a caller-supplied generator,
// because J-PAKE's Round-2 proofs use combined generators, not the group generator.
//
// Pinned challenge serialization (recorded in tests/vectors/README.md):
//   h = OS2IP( SHA-256( lp16(PAD_p(gen)) || lp16(PAD_p(V)) || lp16(PAD_p(G))
//                       || lp16(utf8(userId)) || lp16(utf8(ctx)) ) ) mod q
// where PAD_p is the fixed 384-byte big-endian encoding and lp16 is a 2-byte
// big-endian length prefix.

import { SHA256 } from "./hashes";
import { i2osp, lp16, os2ip, padTo, toHex, utf8Nfc, fromHex } from "./encoding";
import { modInverse, modMul, modPow } from "./groups";
import { type Hex } from "./types";
import type { JPakeGroupParameters } from "./params";

export interface SchnorrProof {
  readonly V: bigint;
  readonly r: bigint;
}

const PADp = (n: bigint, g: JPakeGroupParameters) => padTo(i2osp(n, g.pLen), g.pLen);

export function schnorrChallenge(
  group: JPakeGroupParameters,
  generator: bigint,
  V: bigint,
  G: bigint,
  userId: string,
  ctx: string,
): bigint {
  const h = SHA256(
    lp16(PADp(generator, group)),
    lp16(PADp(V, group)),
    lp16(PADp(G, group)),
    lp16(utf8Nfc(userId)),
    lp16(utf8Nfc(ctx)),
  );
  return os2ip(h) % group.q;
}

/**
 * Prove knowledge of x such that G = generator^x mod p.
 * nonce v is injected for deterministic KATs; in the demo it is random in [1, q-1].
 */
export function proveSchnorr(
  group: JPakeGroupParameters,
  generator: bigint,
  x: bigint,
  G: bigint,
  userId: string,
  ctx: string,
  v: bigint,
): SchnorrProof {
  const V = modPow(generator, v, group.p);
  const h = schnorrChallenge(group, generator, V, G, userId, ctx);
  const r = (((v - x * h) % group.q) + group.q) % group.q;
  return { V, r };
}

/**
 * Verify a Schnorr proof. Checks range of r, that V is a valid subgroup element,
 * and V == generator^r · G^h mod p. Returns true/false; the engine turns false into
 * a fail-closed abort.
 */
export function verifySchnorr(
  group: JPakeGroupParameters,
  generator: bigint,
  G: bigint,
  proof: SchnorrProof,
  userId: string,
  ctx: string,
): boolean {
  const { p, q } = group;
  const { V, r } = proof;
  if (r < 0n || r >= q) return false;
  if (V < 1n || V >= p) return false;
  if (modPow(V, q, p) !== 1n) return false; // V must be in the prime-order subgroup
  // G validity (range + subgroup) is enforced by the caller's decodeJPakeElement.
  const h = schnorrChallenge(group, generator, V, G, userId, ctx);
  const rhs = modMul(modPow(generator, r, p), modPow(G, h, p), p);
  return rhs === V;
}

// --- wire serialization of a proof (hex fields) ---
export function proofToWire(proof: SchnorrProof, group: JPakeGroupParameters): {
  V: Hex;
  r: Hex;
} {
  return { V: toHex(PADp(proof.V, group)), r: toHex(i2osp(proof.r, group.pLen)) };
}

export function proofFromWire(V: Hex, r: Hex): SchnorrProof {
  return { V: os2ip(fromHex(V)), r: os2ip(fromHex(r)) };
}

export { modInverse };
