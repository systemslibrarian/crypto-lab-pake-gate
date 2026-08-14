// Dragonfly (balanced PAKE), an RFC 7664-DERIVED ECC profile over NIST P-256. This is
// Dragonfly proper — the family underlying WPA3's SAE — NOT a WPA3 SAE implementation
// (no IEEE 802.11 framing).
//
// This is a PINNED PAKE-Gate profile, not a literal reproduction of RFC 7664 §3.2.1.
// Three deliberate, documented deviations (tests/vectors/README.md); the Python KAT
// generator pins the SAME profile, so TS/Python agreement does not by itself prove
// RFC fidelity:
//   1. identity input — uint16(len)||NFC(id) blobs, ordered by their encoded value;
//      the RFC orders the raw identities (max(A,B) || min(A,B)).
//   2. y-parity — chosen from the low bit of `temp` (the KDF output); the RFC saves
//      the low bit of `base` and uses that.
//   3. KDF label — the application-specific "Dragonfly-PAKE-Gate-PE-v1"; the RFC uses
//      "Dragonfly Hunting And Pecking".
// The hunting-and-pecking STRUCTURE is the RFC's: a minimum-iteration parameter k,
// keeping the first valid candidate, no early exit. Its
// quadratic-residue test is NOT blinded — RFC 7664 §3.2.1 recommends blinding it, and
// this demo does not implement that; see derivePasswordElement. The legacy early-exit
// and fixed-work TEACHING models live in dragonblood.ts and never produce these
// honest-run keys (invariant #8).
//
// Frozen profile (tests/vectors/README.md):
//   · Curve P-256, H=SHA-256, KDF = SP800-108 counter/HMAC-SHA-256.
//   · PE seed (RFC 7664 §3.2.1, n=len(p)+64=320 bits):
//       idA = uint16(len(NFC(Alice)))||NFC(Alice); idB likewise;
//       hi=max_unsigned(idA,idB), lo=min_unsigned(idA,idB);
//       base = SHA-256(hi||lo||NFC(pw)||counter);
//       temp = KDF(base, "Dragonfly-PAKE-Gate-PE-v1", "", 320);
//       seed = (OS2IP(temp) mod (p-1)) + 1  → candidate x-coordinate.
//   · Key split: key=I2OSP(ss,32) (ss = shared x), Label="Dragonfly Key Derivation",
//       L=512 → kck=bytes[0:32], mk=bytes[32:64].
//   · Confirm = SHA-256(kck || scalar_self32 || scalar_peer32 || elem_self65 ||
//       elem_peer65 || encoded_sender_id).

import { SHA256, kdf800108 } from "./hashes";
import {
  concat,
  fromHex,
  i2osp,
  os2ip,
  toHex,
  uint16be,
  utf8Nfc,
} from "./encoding";
import {
  P256,
  P256_FIELD_P,
  P256_ORDER_N,
  decodeDragonflyCommitElement,
  p256PointToHex,
  scalar32,
  type P256Point,
} from "./groups";
import {
  HandshakeAbort,
  PhaseError,
  type DragonflyPhase,
  type Hex,
  type Password,
  type WireMsg,
} from "./types";

export const DRAGONFLY_K = 40; // minimum hunting-and-pecking iterations
const PE_LABEL = utf8Nfc("Dragonfly-PAKE-Gate-PE-v1");
const KEY_LABEL = utf8Nfc("Dragonfly Key Derivation");
const A_COEFF = P256.CURVE.a; // -3 mod p
const B_COEFF = P256.CURVE.b;

/** length-prefixed identity encoding: uint16_be(len) || NFC(id). */
export function encodeId(id: string): Uint8Array {
  const b = utf8Nfc(id);
  return concat(uint16be(b.length), b);
}

/** sqrt mod p for P-256 (p ≡ 3 mod 4): r^((p+1)/4). Returns null if not a QR. */
function sqrtModP(a: bigint): bigint | null {
  const p = P256_FIELD_P;
  const r = modPowP(a, (p + 1n) / 4n);
  return (r * r) % p === a % p ? r : null;
}
function modPowP(base: bigint, exp: bigint): bigint {
  let b = ((base % P256_FIELD_P) + P256_FIELD_P) % P256_FIELD_P;
  let e = exp;
  let res = 1n;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % P256_FIELD_P;
    b = (b * b) % P256_FIELD_P;
    e >>= 1n;
  }
  return res;
}

/** RHS of the curve equation: x^3 + a·x + b mod p. */
function curveRhs(x: bigint): bigint {
  const p = P256_FIELD_P;
  return (((x * x % p) * x % p) + A_COEFF * x + B_COEFF) % p;
}

export interface PeResult {
  PE: P256Point;
  /** counter at which the PE was first found (1-based). */
  foundAt: number;
  /** total iterations performed (>= k for the accurate honest model). */
  iterations: number;
}

/**
 * Hunting-and-pecking with the RFC 7664 §3.2.1 STRUCTURE (at least k iterations,
 * continuing past k until a valid PE is found; keeps the FIRST valid candidate, no
 * early exit) over this lab's pinned profile — see the three documented deviations
 * in the module header, which change the derived PE bytes. The QR
 * test here is a straightforward Legendre-style check; RFC 7664 recommends blinding
 * it, which does not change the result (only the honest run's side-channel profile,
 * which is the subject of dragonblood.ts, not this function).
 */
export function derivePasswordElement(
  idA: string,
  idB: string,
  password: Password,
  k: number = DRAGONFLY_K,
): PeResult {
  assertCounterBound(k, "k");
  const eA = encodeId(idA);
  const eB = encodeId(idB);
  const [hi, lo] = os2ip(eA) >= os2ip(eB) ? [eA, eB] : [eB, eA];
  const pw = utf8Nfc(password);

  let found: P256Point | null = null;
  let foundAt = 0;
  let counter = 1;
  for (;;) {
    const base = SHA256(hi, lo, pw, Uint8Array.of(counter));
    const temp = kdf800108(base, PE_LABEL, new Uint8Array(0), 320);
    const seed = (os2ip(temp) % (P256_FIELD_P - 1n)) + 1n;
    if (found === null && seed < P256_FIELD_P) {
      const rhs = curveRhs(seed);
      const y = sqrtModP(rhs);
      if (y !== null) {
        // Profile deviation 2: y-parity from the low bit of temp. RFC 7664 saves the
        // low bit of `base` instead, which yields a different PE.
        const wantOdd = (temp[temp.length - 1]! & 1) === 1;
        const yFinal = (y & 1n) === (wantOdd ? 1n : 0n) ? y : P256_FIELD_P - y;
        found = P256.Point.fromAffine({ x: seed, y: yFinal });
        found.assertValidity();
        foundAt = counter;
      }
    }
    // minimum-k: keep going to at least k iterations; if not found by k, continue.
    if (counter >= k && found !== null) {
      return { PE: found, foundAt, iterations: counter };
    }
    counter++;
    // The counter is serialized as ONE octet, so 255 is the last distinct value.
    // The loop used to run to 4,000 with `counter & 0xff`, silently repeating the
    // candidate sequence past 255. Reaching this abort needs ~255 consecutive
    // misses at ~1/2 each (~2^-255) — unreachable in practice, but the bound must
    // exist so a candidate is never repeated.
    if (counter > 255) {
      throw new HandshakeAbort(
        "Dragonfly PE not found",
        "no valid password element within the one-octet counter range (1-255); abort rather than wrap and repeat candidates.",
      );
    }
  }
}

/**
 * The Dragonfly counter is one octet: every counter-like bound must sit in
 * [min, 255]. min is 1 for the honest derivation's k; the teaching scan allows a
 * degenerate zero-iteration bound (it serializes nothing at cap 0).
 */
function assertCounterBound(v: number, name: string, min = 1): void {
  if (!Number.isInteger(v) || v < min || v > 255) {
    throw new RangeError(`Dragonfly ${name} must be an integer in [${min}, 255] (one-octet counter); got ${v}`);
  }
}

export interface HuntScan {
  /** 1-based counter of the first valid password element, or null within the bound. */
  readonly firstValidAt: number | null;
  /**
   * How many hunt-and-peck iterations the loop ACTUALLY executed. This is the
   * side-channel observable, and it is counted by the loop rather than assumed:
   * an early-exit scan reports the counter it stopped at, a fixed-work scan
   * reports the full bound because it really ran that far.
   */
  readonly iterationsPerformed: number;
}

/**
 * One hunt-and-peck scan over `[1, maxCounter]`.
 *
 * `earlyExit: true` models the LEGACY Dragonfly loop — it returns the moment a
 * valid candidate appears, so the work it did is password-dependent. That
 * dependency is the Dragonblood leak.
 *
 * `earlyExit: false` models the FIXED-WORK teaching variant — it keeps iterating to
 * the bound whatever it finds. Its `iterationsPerformed` is flat across passwords
 * because the loop genuinely runs that far, which is the property the mitigation
 * panel claims; the panel must be able to observe it, not be handed a constant.
 */
export function huntAndPeckScan(
  idA: string,
  idB: string,
  password: Password,
  opts: { maxCounter?: number; earlyExit?: boolean } = {},
): HuntScan {
  const maxCounter = opts.maxCounter ?? 255;
  assertCounterBound(maxCounter, "maxCounter", 0);
  const earlyExit = opts.earlyExit ?? true;
  const eA = encodeId(idA);
  const eB = encodeId(idB);
  const [hi, lo] = os2ip(eA) >= os2ip(eB) ? [eA, eB] : [eB, eA];
  const pw = utf8Nfc(password);
  let firstValidAt: number | null = null;
  let iterationsPerformed = 0;
  for (let counter = 1; counter <= maxCounter; counter++) {
    iterationsPerformed = counter;
    const base = SHA256(hi, lo, pw, Uint8Array.of(counter));
    const temp = kdf800108(base, PE_LABEL, new Uint8Array(0), 320);
    const seed = (os2ip(temp) % (P256_FIELD_P - 1n)) + 1n;
    if (firstValidAt === null && seed < P256_FIELD_P && sqrtModP(curveRhs(seed)) !== null) {
      firstValidAt = counter;
      if (earlyExit) break;
    }
  }
  return { firstValidAt, iterationsPerformed };
}

/**
 * The 1-based counter at which the first valid password element appears — the
 * password-dependent quantity the Dragonblood timing/cache side-channel recovers.
 * Exposed for the side-channel comparison panel (dragonblood.ts); NOT used by the
 * honest handshake, which always runs the full minimum-k loop.
 */
export function firstValidCounter(
  idA: string,
  idB: string,
  password: Password,
  maxCounter = 255,
): number | null {
  return huntAndPeckScan(idA, idB, password, { maxCounter, earlyExit: true }).firstValidAt;
}

export interface DragonflyNonces {
  /** private scalar in [2, n-1]. */
  priv: bigint;
  /** mask scalar in [2, n-1]. */
  mask: bigint;
}

export interface DragonflyTrace {
  PE?: P256Point;
  peIterations?: number;
  scalarSelf?: bigint;
  elemSelf?: P256Point;
  scalarPeer?: bigint;
  elemPeer?: P256Point;
  ss?: bigint;
  kck?: Uint8Array;
  mk?: Uint8Array;
  confirmSelf?: Uint8Array;
}

export interface DragonflyConfig {
  selfId: string;
  peerId: string;
  password: Password;
  nonces: DragonflyNonces;
  k?: number;
}

export class DragonflyParty {
  phase: DragonflyPhase = "init";
  readonly trace: DragonflyTrace = {};
  private scalarSelf = 0n;
  private elemSelf!: P256Point;
  private readonly priv: bigint;

  constructor(private readonly cfg: DragonflyConfig) {
    // RFC 7664 range rule, enforced BEFORE any commit is derived: injected nonces
    // (tests, KATs, direct callers) must satisfy 1 < scalar < n, matching the
    // check recvCommit already applies to the peer's commit scalar.
    const n = P256_ORDER_N;
    for (const [name, v] of [["private", cfg.nonces.priv], ["mask", cfg.nonces.mask]] as const) {
      if (v <= 1n || v >= n) {
        throw new HandshakeAbort(
          `Dragonfly ${name} scalar out of range`,
          "RFC 7664 requires 1 < scalar < n for the private and mask values; regenerate the nonce.",
        );
      }
    }
    this.priv = cfg.nonces.priv;
  }

  /** Derive the password element (identical on both peers — balanced PAKE). */
  derivePE(): void {
    if (this.phase !== "init") throw new PhaseError("init", this.phase);
    // Identity order is canonical (hi/lo) so both peers derive the SAME PE.
    const pe = derivePasswordElement(this.cfg.selfId, this.cfg.peerId, this.cfg.password, this.cfg.k);
    this.trace.PE = pe.PE;
    this.trace.peIterations = pe.iterations;
    this.phase = "pe-derived";
  }

  /** Build the commit {scalar, Element}. Element = -(mask · PE). */
  commit(): WireMsg {
    if (this.phase !== "pe-derived") throw new PhaseError("pe-derived", this.phase);
    const { priv, mask } = this.cfg.nonces;
    const n = P256_ORDER_N;
    this.scalarSelf = (priv + mask) % n;
    if (this.scalarSelf <= 1n) {
      throw new HandshakeAbort("Dragonfly scalar <= 1", "scalar = (private+mask) mod n must exceed 1; regenerate.");
    }
    this.elemSelf = this.trace.PE!.multiply(mask).negate();
    this.trace.scalarSelf = this.scalarSelf;
    this.trace.elemSelf = this.elemSelf;
    this.phase = "commit-sent";
    return {
      protocol: "dragonfly",
      step: "commit",
      from: this.cfg.selfId === peerA(this.cfg) ? "A" : "B",
      fields: { scalar: scalar32(this.scalarSelf), element: p256PointToHex(this.elemSelf) },
    };
  }

  /** Consume the peer commit, derive ss / kck / mk. */
  recvCommit(peer: WireMsg): void {
    if (this.phase !== "commit-sent") throw new PhaseError("commit-sent", this.phase);
    const scalarPeer = os2ip(fromHex(peer.fields.scalar as Hex));
    if (scalarPeer <= 1n || scalarPeer >= P256_ORDER_N) {
      throw new HandshakeAbort("Dragonfly peer scalar out of range", "commit scalar must satisfy 1 < scalar < n.");
    }
    const elemPeer = decodeDragonflyCommitElement(peer.fields.element as Hex, "peer Element");
    // Reflection guard: a mirrored commit (same scalar AND element) is refused.
    if (scalarPeer === this.scalarSelf && elemPeer.equals(this.elemSelf)) {
      this.phase = "aborted";
      throw new HandshakeAbort("Dragonfly reflection attack", "a mirrored commit must be refused — it would fix the key.");
    }
    // K = private · (scalar_peer · PE + Element_peer) = private·private_peer·PE.
    const K = this.trace.PE!.multiply(scalarPeer).add(elemPeer).multiply(this.priv);
    if (K.is0()) {
      this.phase = "aborted";
      throw new HandshakeAbort("Dragonfly shared point is identity", "degenerate shared secret; abort.");
    }
    const ss = K.toAffine().x;
    const key = i2osp(ss, 32);
    const derived = kdf800108(key, KEY_LABEL, new Uint8Array(0), 512);
    Object.assign(this.trace, {
      scalarPeer,
      elemPeer,
      ss,
      kck: derived.slice(0, 32),
      mk: derived.slice(32, 64),
    });
    this.phase = "commit-received";
  }

  deriveKey(): void {
    if (this.phase !== "commit-received") throw new PhaseError("commit-received", this.phase);
    this.phase = "key-derived";
  }

  /** RFC 7664 confirm = SHA-256(kck||scalar_self||scalar_peer||elem_self||elem_peer||sender_id). */
  confirm(): WireMsg {
    if (this.phase !== "key-derived") throw new PhaseError("key-derived", this.phase);
    const tag = this.confirmTag(
      this.trace.scalarSelf!,
      this.trace.scalarPeer!,
      this.trace.elemSelf!,
      this.trace.elemPeer!,
      this.cfg.selfId,
    );
    this.trace.confirmSelf = tag;
    this.phase = "confirm-sent";
    return {
      protocol: "dragonfly",
      step: "confirm",
      from: this.cfg.selfId === peerA(this.cfg) ? "A" : "B",
      fields: { confirm: toHex(tag) },
    };
  }

  recvConfirm(peer: WireMsg): void {
    if (this.phase !== "confirm-sent") throw new PhaseError("confirm-sent", this.phase);
    // Peer's confirm swaps self/peer scalars+elements and uses the peer's sender id.
    const expected = this.confirmTag(
      this.trace.scalarPeer!,
      this.trace.scalarSelf!,
      this.trace.elemPeer!,
      this.trace.elemSelf!,
      this.cfg.peerId,
    );
    const got = fromHex(peer.fields.confirm as Hex);
    if (!eqBytes(got, expected)) {
      this.phase = "aborted";
      throw new HandshakeAbort("Dragonfly confirm mismatch", "peer confirm did not verify — wrong password or tamper.");
    }
    this.phase = "confirmed";
  }

  private confirmTag(
    scalarA: bigint,
    scalarB: bigint,
    elemA: P256Point,
    elemB: P256Point,
    senderId: string,
  ): Uint8Array {
    return SHA256(
      this.trace.kck!,
      i2osp(scalarA, 32),
      i2osp(scalarB, 32),
      fromHex(p256PointToHex(elemA)),
      fromHex(p256PointToHex(elemB)),
      encodeId(senderId),
    );
  }

  get sessionKeyBytes(): Uint8Array | undefined {
    return this.trace.mk;
  }
}

function peerA(cfg: DragonflyConfig): string {
  // Deterministic "A" label = the lexicographically smaller id, for wire `from`.
  return cfg.selfId < cfg.peerId ? cfg.selfId : cfg.peerId;
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
