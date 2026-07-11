// J-PAKE (balanced PAKE), RFC 8236 + Hao/Ryan "juggling", with RFC 8235 Schnorr
// proofs. Pinned profile (see tests/vectors/README.md):
//   · Group: RFC 3526 3072-bit MODP (p, q=(p-1)/2, g=2). Elements PAD to 384 bytes.
//   · Password scalar: s = (OS2IP(SHA-256(UTF8_NFC(pw))) mod (q-1)) + 1 ∈ [1, q-1].
//   · Keys (RFC 8236 §2.2): Alice Ka = (B / g4^{x2·s})^{x2}; Bob Kb = (A / g2^{x4·s})^{x4}.
//     Alice removes BOB's g4, Bob removes ALICE's g2 — swapping them is a protocol
//     break that makes the two sides derive different keys. K_material = PAD_p(K).
//   · ISK  = HKDF-SHA-256(K_material, salt=32 zeros, info="JPAKE_ISK", 32).
//   · k'   = HKDF-SHA-256(K_material, salt=32 zeros, info="JPAKE_KC",  32).
//   · Tags = HMAC-SHA-256(k', lp16("KC_1_U") || lp16(idSelf) || lp16(idPeer)
//                              || lp16(PAD(gA)) .. ) with role-ordered generators.

import { HMAC_SHA256, SHA256, hkdfSha256 } from "./hashes";
import {
  concat,
  fromHex,
  i2osp,
  lp16,
  os2ip,
  padTo,
  toHex,
  utf8Nfc,
  zeroBytes,
} from "./encoding";
import { decodeJPakeElement, modInverse, modMul, modPow } from "./groups";
import {
  proofFromWire,
  proofToWire,
  proveSchnorr,
  verifySchnorr,
  type SchnorrProof,
} from "./schnorr-nizk";
import {
  HandshakeAbort,
  PhaseError,
  type Hex,
  type JPakePhase,
  type Password,
  type WireMsg,
} from "./types";
import { JPAKE_GROUP_3072, type JPakeGroupParameters } from "./params";

export type Role = "A" | "B";

const PADp = (n: bigint, g: JPakeGroupParameters) => padTo(i2osp(n, g.pLen), g.pLen);

/** s = (OS2IP(SHA-256(UTF8_NFC(pw))) mod (q-1)) + 1  ∈ [1, q-1]. */
export function passwordToScalar(group: JPakeGroupParameters, password: Password): bigint {
  const h = SHA256(utf8Nfc(password));
  return (os2ip(h) % (group.q - 1n)) + 1n;
}

export interface JPakeNonces {
  /** first exponent: Alice x1, Bob x3 (may be 0). */
  e1: bigint;
  /** second exponent: Alice x2, Bob x4 (must be nonzero). */
  e2: bigint;
  /** Schnorr nonce for the first-generator proof. */
  v1: bigint;
  /** Schnorr nonce for the second-generator proof. */
  v2: bigint;
  /** Schnorr nonce for the Round-2 proof. */
  vr: bigint;
}

export interface JPakeConfig {
  group?: JPakeGroupParameters;
  role: Role;
  selfId: string;
  peerId: string;
  password: Password;
  ctx?: string;
  nonces: JPakeNonces;
}

export interface JPakeTrace {
  s: bigint;
  g1?: bigint;
  g2?: bigint;
  g3?: bigint;
  g4?: bigint;
  gCombinedSelf?: bigint;
  gCombinedPeer?: bigint;
  elemSelf?: bigint; // A (if Alice) or B (if Bob)
  elemPeer?: bigint;
  kMaterial?: Uint8Array;
  isk?: Uint8Array;
  kc?: Uint8Array;
  tagSelf?: Uint8Array;
}

export class JPakeParty {
  phase: JPakePhase = "init";
  readonly trace: JPakeTrace;
  private readonly g: JPakeGroupParameters;
  private readonly ctx: string;

  // own contributions
  private gFirst = 0n; // Alice g1, Bob g3
  private gSecond = 0n; // Alice g2, Bob g4
  // peer contributions (learned in round 1)
  private gPeerFirst = 0n; // for Alice: g3, for Bob: g1
  private gPeerSecond = 0n; // for Alice: g4, for Bob: g2

  constructor(private readonly cfg: JPakeConfig) {
    if (cfg.selfId === cfg.peerId) {
      throw new HandshakeAbort(
        "J-PAKE identical participant ids",
        "the two parties' ids must differ; equal ids collapse the construction.",
      );
    }
    if (cfg.nonces.e2 % (cfg.group ?? JPAKE_GROUP_3072).q === 0n) {
      throw new HandshakeAbort(
        "J-PAKE degenerate exponent x2/x4 == 0",
        "the second exponent must be nonzero mod q; regenerate.",
      );
    }
    this.g = cfg.group ?? JPAKE_GROUP_3072;
    this.ctx = cfg.ctx ?? "PAKE-Gate-JPAKE";
    this.trace = { s: passwordToScalar(this.g, cfg.password) };
  }

  // --- Round 1: publish g^e1, g^e2 with Schnorr proofs ---
  round1(): WireMsg {
    if (this.phase !== "init") throw new PhaseError("init", this.phase);
    const { e1, e2, v1, v2 } = this.cfg.nonces;
    this.gFirst = modPow(this.g.g, e1, this.g.p);
    this.gSecond = modPow(this.g.g, e2, this.g.p);
    const p1 = proveSchnorr(this.g, this.g.g, e1, this.gFirst, this.cfg.selfId, this.ctx, v1);
    const p2 = proveSchnorr(this.g, this.g.g, e2, this.gSecond, this.cfg.selfId, this.ctx, v2);
    this.phase = "round1-sent";
    return this.emitRound1(p1, p2);
  }

  recvRound1(peer: WireMsg): void {
    if (this.phase !== "round1-sent") throw new PhaseError("round1-sent", this.phase);
    const [fFirst, fSecond] = this.cfg.role === "A" ? ["g3", "g4"] : ["g1", "g2"];
    const [pf, ps] = this.cfg.role === "A" ? ["3", "4"] : ["1", "2"];
    // g1/g3 (first) MAY be identity; g2/g4 (second) must NOT be.
    this.gPeerFirst = decodeJPakeElement(peer.fields[fFirst] as Hex, this.g, {
      field: fFirst,
      rejectIdentity: false,
    });
    this.gPeerSecond = decodeJPakeElement(peer.fields[fSecond] as Hex, this.g, {
      field: fSecond,
      rejectIdentity: true,
    });
    const proofFirst = proofFromWire(peer.fields[`V${pf}`] as Hex, peer.fields[`r${pf}`] as Hex);
    const proofSecond = proofFromWire(peer.fields[`V${ps}`] as Hex, peer.fields[`r${ps}`] as Hex);
    const okFirst = verifySchnorr(this.g, this.g.g, this.gPeerFirst, proofFirst, this.cfg.peerId, this.ctx);
    const okSecond = verifySchnorr(this.g, this.g.g, this.gPeerSecond, proofSecond, this.cfg.peerId, this.ctx);
    if (!okFirst || !okSecond) {
      this.phase = "aborted";
      throw new HandshakeAbort(
        "J-PAKE Round-1 Schnorr proof failed",
        "an unproven exponent could hide a chosen value — handshake aborts fail-closed.",
      );
    }
    // record g1..g4 in canonical slots for the trace + confirmation
    if (this.cfg.role === "A") {
      Object.assign(this.trace, { g1: this.gFirst, g2: this.gSecond, g3: this.gPeerFirst, g4: this.gPeerSecond });
    } else {
      Object.assign(this.trace, { g1: this.gPeerFirst, g2: this.gPeerSecond, g3: this.gFirst, g4: this.gSecond });
    }
    this.phase = "round1-verified";
  }

  // --- Round 2: combined generator, mix in password scalar s ---
  round2(): WireMsg {
    if (this.phase !== "round1-verified") throw new PhaseError("round1-verified", this.phase);
    const { g1, g2, g3, g4 } = this.trace;
    // Alice's combined generator = g1·g3·g4 ; Bob's = g1·g2·g3.
    const combined =
      this.cfg.role === "A"
        ? modMul(modMul(g1!, g3!, this.g.p), g4!, this.g.p)
        : modMul(modMul(g1!, g2!, this.g.p), g3!, this.g.p);
    if (combined === 1n) {
      this.phase = "aborted";
      throw new HandshakeAbort(
        "J-PAKE combined Round-2 generator is identity",
        "g1·g3·g4 (Alice) / g1·g2·g3 (Bob) must be non-identity, else the element leaks.",
      );
    }
    const s = this.trace.s;
    const exp = modMul(this.cfg.nonces.e2, s, this.g.q); // x2·s or x4·s, mod q
    const elem = modPow(combined, exp, this.g.p);
    const proof = proveSchnorr(this.g, combined, exp, elem, this.cfg.selfId, this.ctx, this.cfg.nonces.vr);
    this.trace.gCombinedSelf = combined;
    this.trace.elemSelf = elem;
    this.phase = "round2-sent";
    return this.emitRound2(elem, proof);
  }

  recvRound2(peer: WireMsg): void {
    if (this.phase !== "round2-sent") throw new PhaseError("round2-sent", this.phase);
    const { g1, g2, g3, g4 } = this.trace;
    // The peer's combined generator (Alice verifies Bob's g1·g2·g3; Bob verifies Alice's g1·g3·g4).
    const peerCombined =
      this.cfg.role === "A"
        ? modMul(modMul(g1!, g2!, this.g.p), g3!, this.g.p)
        : modMul(modMul(g1!, g3!, this.g.p), g4!, this.g.p);
    if (peerCombined === 1n) {
      this.phase = "aborted";
      throw new HandshakeAbort(
        "J-PAKE peer combined generator is identity",
        "the peer's Round-2 combined generator must be non-identity.",
      );
    }
    const elemPeer = decodeJPakeElement(peer.fields.elem as Hex, this.g, {
      field: "Round-2 element",
      rejectIdentity: false,
    });
    const proof: SchnorrProof = proofFromWire(peer.fields.V as Hex, peer.fields.r as Hex);
    const ok = verifySchnorr(this.g, peerCombined, elemPeer, proof, this.cfg.peerId, this.ctx);
    if (!ok) {
      this.phase = "aborted";
      throw new HandshakeAbort(
        "J-PAKE Round-2 Schnorr proof failed",
        "the peer's password-mixed element is unproven — aborting before any key.",
      );
    }
    this.trace.gCombinedPeer = peerCombined;
    this.trace.elemPeer = elemPeer;
    this.phase = "round2-verified";
  }

  deriveKey(): void {
    if (this.phase !== "round2-verified") throw new PhaseError("round2-verified", this.phase);
    const { g2, g4, elemPeer } = this.trace;
    const s = this.trace.s;
    const exp = modMul(this.cfg.nonces.e2, s, this.g.q); // x2·s (Alice) or x4·s (Bob)
    // Alice: Ka = (B · inverse(g4^{x2·s}))^{x2}. Bob: Kb = (A · inverse(g2^{x4·s}))^{x4}.
    const removedGen = this.cfg.role === "A" ? g4! : g2!;
    const removedTerm = modPow(removedGen, exp, this.g.p);
    const base = modMul(elemPeer!, modInverse(removedTerm, this.g.p), this.g.p);
    const K = modPow(base, this.cfg.nonces.e2, this.g.p);
    const kMaterial = PADp(K, this.g);
    const isk = hkdfSha256(kMaterial, zeroBytes(32), utf8Nfc("JPAKE_ISK"), 32);
    const kc = hkdfSha256(kMaterial, zeroBytes(32), utf8Nfc("JPAKE_KC"), 32);
    Object.assign(this.trace, { kMaterial, isk, kc });
    this.phase = "key-derived";
  }

  /** Produce this party's key-confirmation tag (RFC 8236 §5 MAC method). */
  confirm(): WireMsg {
    if (this.phase !== "key-derived") throw new PhaseError("key-derived", this.phase);
    const tag = this.macTag(this.cfg.role, this.trace.kc!);
    this.trace.tagSelf = tag;
    this.phase = "confirm-sent";
    return { protocol: "jpake", step: "confirm", from: this.cfg.role, fields: { tag: toHex(tag) } };
  }

  recvConfirm(peer: WireMsg): void {
    if (this.phase !== "confirm-sent") throw new PhaseError("confirm-sent", this.phase);
    const peerRole: Role = this.cfg.role === "A" ? "B" : "A";
    const expected = this.macTag(peerRole, this.trace.kc!);
    const got = fromHex(peer.fields.tag as Hex);
    if (!eqBytes(got, expected)) {
      this.phase = "aborted";
      throw new HandshakeAbort(
        "J-PAKE key confirmation failed",
        "peer's MAC tag did not verify — wrong password or tamper; key not established.",
      );
    }
    this.phase = "confirmed";
  }

  /** MAC tag for a given role: role-ordered generators, all fields length-prefixed. */
  private macTag(role: Role, kc: Uint8Array): Uint8Array {
    const { g1, g2, g3, g4 } = this.trace;
    const idA = this.cfg.role === "A" ? this.cfg.selfId : this.cfg.peerId;
    const idB = this.cfg.role === "A" ? this.cfg.peerId : this.cfg.selfId;
    // Alice: MAC(kc, "KC_1_U" | Alice | Bob | g1 | g2 | g3 | g4)
    // Bob:   MAC(kc, "KC_1_U" | Bob   | Alice | g3 | g4 | g1 | g2)
    const idSelf = role === "A" ? idA : idB;
    const idPeer = role === "A" ? idB : idA;
    const gens =
      role === "A"
        ? [g1!, g2!, g3!, g4!]
        : [g3!, g4!, g1!, g2!];
    return HMAC_SHA256(
      kc,
      lp16(utf8Nfc("KC_1_U")),
      lp16(utf8Nfc(idSelf)),
      lp16(utf8Nfc(idPeer)),
      ...gens.map((x) => lp16(PADp(x, this.g))),
    );
  }

  get sessionKeyBytes(): Uint8Array | undefined {
    return this.trace.isk;
  }

  // --- wire factories ---
  private emitRound1(p1: SchnorrProof, p2: SchnorrProof): WireMsg {
    const w1 = proofToWire(p1, this.g);
    const w2 = proofToWire(p2, this.g);
    if (this.cfg.role === "A") {
      return {
        protocol: "jpake",
        step: "round1",
        from: "A",
        fields: {
          g1: toHex(PADp(this.gFirst, this.g)),
          g2: toHex(PADp(this.gSecond, this.g)),
          V1: w1.V, r1: w1.r, V2: w2.V, r2: w2.r,
          id: toHex(utf8Nfc(this.cfg.selfId)),
        },
      };
    }
    return {
      protocol: "jpake",
      step: "round1",
      from: "B",
      fields: {
        g3: toHex(PADp(this.gFirst, this.g)),
        g4: toHex(PADp(this.gSecond, this.g)),
        V3: w1.V, r3: w1.r, V4: w2.V, r4: w2.r,
        id: toHex(utf8Nfc(this.cfg.selfId)),
      },
    };
  }

  private emitRound2(elem: bigint, proof: SchnorrProof): WireMsg {
    const w = proofToWire(proof, this.g);
    return {
      protocol: "jpake",
      step: "round2",
      from: this.cfg.role,
      fields: { elem: toHex(PADp(elem, this.g)), V: w.V, r: w.r, id: toHex(utf8Nfc(this.cfg.selfId)) },
    };
  }
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export { concat };
