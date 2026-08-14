// Convenience constructors that fill in the per-session randomness, so UI code never
// has to know nonce internals. Secrets are generated per-session in memory via the
// platform CSPRNG and never persisted (WebCrypto in the browser, node:crypto in tests).

import { randomBytes } from "@noble/hashes/utils";
import { i2ospLE, os2ip, os2ipLE, prependLen, utf8Nfc } from "./encoding";
import {
  SRP_TRACK2_4096_SHA256,
  SrpClientSession,
  SrpServerSession,
  register,
  type SrpProfile,
  type SrpVerifierRecord,
} from "./srp6a";
import { JPakeParty, type Role } from "./jpake";
import { CPaceParty, RISTRETTO255_ORDER } from "./cpace";
import { DragonflyParty } from "./dragonfly";
import { JPAKE_GROUP_3072, type JPakeGroupParameters } from "./params";
import { P256_ORDER_N } from "./groups";
import { asPassword, type Password } from "./types";

/** Byte source, injectable so the samplers' rejection paths are testable. */
export type RandBytes = (n: number) => Uint8Array;

/**
 * Uniform random integer in [min, max-1], by rejection sampling: draw
 * ceil(bitlen(max-1)/8) bytes, mask the surplus top bits down to bitlen(max-1),
 * and redraw until the value lands in range. No modular reduction, so no
 * reduction bias; acceptance probability is at least 1/2 per draw.
 */
export function uniformInt(max: bigint, min = 1n, rand: RandBytes = randomBytes): bigint {
  const top = max - 1n;
  if (top < min) throw new RangeError("uniformInt: empty range");
  const bits = top.toString(2).length;
  const nBytes = Math.ceil(bits / 8);
  const topByteMask = (1 << (((bits - 1) % 8) + 1)) - 1;
  for (;;) {
    const b = rand(nBytes);
    b[0]! &= topByteMask;
    const r = os2ip(b);
    if (r >= min && r <= top) return r;
  }
}

// 2^384: the size of the pinned MODP-group exponent window (see randExponent384).
const EXP384 = 1n << 384n;

/**
 * PAKE-Gate ephemeral-exponent policy for the large MODP groups (SRP-Track-2 4096,
 * J-PAKE 3072): a uniform 384-bit exponent — os2ip of 48 CSPRNG bytes, +1, i.e.
 * uniform on [1, 2^384]. This is ≥ 384 bits of entropy (RFC 5054 §3 asks only for
 * ≥ 256-bit ephemerals) and is deliberately NOT uniform over the full group order:
 * full-width exponents would multiply every modexp's cost ~8-11x for no teaching
 * benefit. An earlier version documented this function as "uniform in [1, max-1]",
 * which it never was — do not call it that. The guard below makes the window
 * strictly smaller than the group order, so the old silent-modulo-bias path can
 * never re-appear; groups at or below 2^384 must use uniformInt instead.
 */
export function randExponent384(max: bigint, rand: RandBytes = randomBytes): bigint {
  if (max - 1n <= EXP384) {
    throw new RangeError("randExponent384: group order too small for the 384-bit window — use uniformInt");
  }
  return os2ip(rand(48)) + 1n;
}

export function makePassword(s: string): Password {
  return asPassword(s);
}

export function randomSalt(len = 16): Uint8Array {
  return randomBytes(len);
}

// --- SRP (Track 2 runnable profile by default) ---
export function srpRegister(
  I: string,
  password: Password,
  salt: Uint8Array = randomSalt(),
  profile: SrpProfile = SRP_TRACK2_4096_SHA256,
): SrpVerifierRecord {
  return register(profile, I, password, salt);
}

export function makeSrpClient(
  I: string,
  password: Password,
  profile: SrpProfile = SRP_TRACK2_4096_SHA256,
): SrpClientSession {
  return new SrpClientSession(profile, I, password, randExponent384(profile.group.N));
}

export function makeSrpServer(
  record: SrpVerifierRecord,
  profile: SrpProfile = SRP_TRACK2_4096_SHA256,
): SrpServerSession {
  return new SrpServerSession(profile, record, randExponent384(profile.group.N));
}

// --- J-PAKE ---
export function makeJPakeParty(
  role: Role,
  selfId: string,
  peerId: string,
  password: Password,
  group: JPakeGroupParameters = JPAKE_GROUP_3072,
): JPakeParty {
  const q = group.q;
  return new JPakeParty({
    role,
    selfId,
    peerId,
    password,
    nonces: {
      e1: randExponent384(q),
      e2: randExponent384(q),
      v1: randExponent384(q),
      v2: randExponent384(q),
      vr: randExponent384(q),
    },
  });
}

// --- CPace ---

/**
 * Canonical little-endian bytes of a uniform ristretto255 scalar in [1, L-1], by
 * rejection sampling: draw 32 bytes, clear the top 3 bits (L < 2^253), redraw on 0
 * or >= L. Never reduces mod L — an earlier version passed raw CSPRNG bytes to be
 * reduced, which over-weights the low residues by ~1/16.
 */
export function sampleRistrettoScalar(rand: RandBytes = randomBytes): Uint8Array {
  for (;;) {
    const b = rand(32);
    b[31]! &= 0x1f; // 253 low bits
    const s = os2ipLE(b);
    if (s >= 1n && s < RISTRETTO255_ORDER) return i2ospLE(s, 32);
  }
}

export function makeCPaceParty(
  role: "A" | "B",
  password: Password,
  ci: Uint8Array,
  sid: Uint8Array,
  ad: Uint8Array,
): CPaceParty {
  return new CPaceParty({ role, password, ci, sid, ad, scalar: sampleRistrettoScalar() });
}

/**
 * CI = concat of length-prefixed party ids, for demos. The prefixes use the draft's
 * own LEB128 prepend_len (encoding.ts): a single byte for ids under 128 bytes —
 * byte-identical to the old fixed one-byte prefix for every id this demo uses — and
 * multi-byte beyond, where the old fixed prefix silently wrapped lengths mod 256.
 */
export function cpaceCI(idA: string, idB: string): Uint8Array {
  const a = prependLen(utf8Nfc(idA));
  const b = prependLen(utf8Nfc(idB));
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// --- Dragonfly ---
export function makeDragonflyParty(
  selfId: string,
  peerId: string,
  password: Password,
): DragonflyParty {
  return new DragonflyParty({
    selfId,
    peerId,
    password,
    // RFC 7664 range: 1 < scalar < n. uniformInt is unbiased rejection sampling.
    nonces: { priv: uniformInt(P256_ORDER_N, 2n), mask: uniformInt(P256_ORDER_N, 2n) },
  });
}
