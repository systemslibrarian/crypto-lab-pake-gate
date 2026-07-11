// CPace (balanced PAKE), the CFRG selection — draft-irtf-cfrg-cpace-21 (an active
// Internet-Draft, NOT an RFC; never call it "RFC 9836"). Ciphersuite:
// CPace-ristretto255-SHA-512, parallel / order-independent execution mode.
//
// Core (vector-tested through ISK, draft-21 Appendix B.3):
//   DSI_gen = "CPaceRistretto255", DSI_isk = "CPaceRistretto255_ISK", s_in_bytes=128.
//   generator_string(PRS,CI,sid) = lv_cat(DSI, PRS, zeros(len_zpad), CI, sid)
//     len_zpad = max(0, 128 - 1 - len(prepend_len(PRS)) - len(prepend_len(DSI)))
//   g   = ristretto_map( SHA-512(generator_string) )   (element_derivation, 64 bytes)
//   Ya  = ya·g ; Yb = yb·g ; K = ya·Yb = yb·Ya  (reject identity)
//   ISK = SHA-512( lv_cat(DSI_isk, sid, K) || o_cat(lv_cat(Ya,ADa), lv_cat(Yb,ADb)) )
//
// Confirmation is a pinned add-on (draft-21 §10.4), tested separately (no draft
// vectors): mac_key = SHA-512("CPaceMac" || sid || ISK); Ta = HMAC-SHA-512(mac_key,
// lv_cat(Ya, ADa)); Tb = HMAC-SHA-512(mac_key, lv_cat(Yb, ADb)); full 64-byte tags.

import { SHA512, HMAC_SHA512 } from "./hashes";
import {
  concat,
  fromHex,
  lvCat,
  oCat,
  os2ipLE,
  prependLen,
  toHex,
  utf8Nfc,
  zeroBytes,
} from "./encoding";
import {
  decodeRistrettoElement,
  ristrettoFromUniform,
  ristrettoToHex,
  type RistPoint,
} from "./groups";
import {
  HandshakeAbort,
  PhaseError,
  type CPacePhase,
  type Hex,
  type Password,
  type WireMsg,
} from "./types";

// ristretto255 / ed25519 group order L.
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const DSI_GEN = utf8Nfc("CPaceRistretto255");
const DSI_ISK = utf8Nfc("CPaceRistretto255_ISK");
const S_IN_BYTES = 128;

export interface CPaceConfig {
  role: "A" | "B";
  password: Password;
  /** channel identifier CI (already the concatenated party ids, per draft). */
  ci: Uint8Array;
  /** session id sid (fresh, agreed out of band or exchanged). */
  sid: Uint8Array;
  /** associated data for this party (ADa or ADb). */
  ad: Uint8Array;
  /** ephemeral scalar bytes (32, little-endian). Injected for KATs; random in demo. */
  scalar: Uint8Array;
}

export function generatorString(prs: Uint8Array, ci: Uint8Array, sid: Uint8Array): Uint8Array {
  const lenZpad = Math.max(
    0,
    S_IN_BYTES - 1 - prependLen(prs).length - prependLen(DSI_GEN).length,
  );
  return lvCat(DSI_GEN, prs, zeroBytes(lenZpad), ci, sid);
}

export function calculateGenerator(prs: Uint8Array, ci: Uint8Array, sid: Uint8Array): RistPoint {
  const h = SHA512(generatorString(prs, ci, sid)); // 64 bytes
  return ristrettoFromUniform(h);
}

function scalarInt(bytes: Uint8Array): bigint {
  const s = os2ipLE(bytes) % L;
  if (s === 0n) throw new HandshakeAbort("CPace scalar is zero", "ephemeral scalar must be nonzero mod L.");
  return s;
}

/** ISK for parallel/order-independent mode. */
export function computeISK(
  sid: Uint8Array,
  K: RistPoint,
  Ya: Uint8Array,
  ADa: Uint8Array,
  Yb: Uint8Array,
  ADb: Uint8Array,
): Uint8Array {
  const transcript = oCat(lvCat(Ya, ADa), lvCat(Yb, ADb));
  return SHA512(concat(lvCat(DSI_ISK, sid, K.toBytes()), transcript));
}

export interface CPaceTrace {
  g?: RistPoint;
  Yself?: Uint8Array;
  Ypeer?: Uint8Array;
  K?: RistPoint;
  isk?: Uint8Array;
  macKey?: Uint8Array;
  tagSelf?: Uint8Array;
}

export class CPaceParty {
  phase: CPacePhase = "init";
  readonly trace: CPaceTrace = {};
  private readonly scalar: bigint;
  private readonly g: RistPoint;
  private readonly Yself: RistPoint;
  private adPeer?: Uint8Array;

  constructor(private readonly cfg: CPaceConfig) {
    this.g = calculateGenerator(cfg.password ? bytesOf(cfg.password) : new Uint8Array(), cfg.ci, cfg.sid);
    this.scalar = scalarInt(cfg.scalar);
    this.Yself = this.g.multiply(this.scalar);
    this.trace.g = this.g;
    this.trace.Yself = this.Yself.toBytes();
  }

  /** Emit this party's message Y (+ AD). */
  message(): WireMsg {
    if (this.phase !== "init") throw new PhaseError("init", this.phase);
    this.phase = "msg-sent";
    return {
      protocol: "cpace",
      step: "msg",
      from: this.cfg.role,
      fields: { Y: ristrettoToHex(this.Yself), AD: toHex(this.cfg.ad) },
    };
  }

  /** Consume the peer message, derive K and ISK. */
  receive(peer: WireMsg): void {
    if (this.phase !== "msg-sent") throw new PhaseError("msg-sent", this.phase);
    const Ypeer = decodeRistrettoElement(peer.fields.Y as Hex, "peer message Y");
    this.adPeer = fromHex(peer.fields.AD as Hex);
    const K = Ypeer.multiply(this.scalar);
    if (K.is0()) {
      this.phase = "aborted";
      throw new HandshakeAbort("CPace K is identity", "shared point must not be the identity element.");
    }
    // Order Ya/ADa (initiator A) vs Yb/ADb (responder B) canonically for the ISK.
    const YpeerBytes = Ypeer.toBytes();
    const [Ya, ADa, Yb, ADb] =
      this.cfg.role === "A"
        ? [this.Yself.toBytes(), this.cfg.ad, YpeerBytes, this.adPeer]
        : [YpeerBytes, this.adPeer, this.Yself.toBytes(), this.cfg.ad];
    const isk = computeISK(this.cfg.sid, K, Ya, ADa, Yb, ADb);
    this.trace.Ypeer = YpeerBytes;
    this.trace.K = K;
    this.trace.isk = isk;
    this.trace.macKey = SHA512(utf8Nfc("CPaceMac"), this.cfg.sid, isk);
    this.phase = "isk-derived";
  }

  /** Produce this party's confirmation tag (pinned draft-21 §10.4 construction). */
  confirm(): WireMsg {
    if (this.phase !== "isk-derived") throw new PhaseError("isk-derived", this.phase);
    const tag = HMAC_SHA512(this.trace.macKey!, lvCat(this.trace.Yself!, this.cfg.ad));
    this.trace.tagSelf = tag;
    this.phase = "confirm-sent";
    return { protocol: "cpace", step: "confirm", from: this.cfg.role, fields: { tag: toHex(tag) } };
  }

  recvConfirm(peer: WireMsg): void {
    if (this.phase !== "confirm-sent") throw new PhaseError("confirm-sent", this.phase);
    const expected = HMAC_SHA512(this.trace.macKey!, lvCat(this.trace.Ypeer!, this.adPeer!));
    const got = fromHex(peer.fields.tag as Hex);
    if (!eqBytes(got, expected)) {
      this.phase = "aborted";
      throw new HandshakeAbort("CPace confirmation failed", "peer MAC tag did not verify — key not established.");
    }
    this.phase = "confirmed";
  }

  get sessionKeyBytes(): Uint8Array | undefined {
    return this.trace.isk;
  }
}

function bytesOf(s: string): Uint8Array {
  return utf8Nfc(s);
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
