// J-PAKE runner (balanced, two peers A/B). Strongest tamper surface: corrupting a
// Round-1 element or its Schnorr proof makes NIZK verification fail at receipt and the
// handshake aborts fail-closed before any key.

import { makeJPakeParty } from "../../pake/factories.ts";
import type { JPakeParty } from "../../pake/jpake.ts";
import type { Password, WireMsg } from "../../pake/types.ts";
import {
  bigHex,
  bytesHex,
  type KeyView,
  type PeerView,
  type Runner,
  type ScratchRow,
  type TamperOp,
  type WireCard,
} from "../model.ts";
import { StepMachine, eqBytes } from "./base.ts";

const TAMPER: TamperOp[] = [
  {
    id: "jpake-elem",
    label: "Corrupt a Round-1 element (g1)",
    step: "round1",
    field: "g1",
    expect: "Peer B's Schnorr verification fails at receipt — the exponent behind g1 is unproven — aborts fail-closed BEFORE any key.",
  },
  {
    id: "jpake-proof",
    label: "Corrupt a Round-1 Schnorr proof (r1)",
    step: "round1",
    field: "r1",
    expect: "The NIZK no longer verifies for g1 — Peer B rejects at receipt — handshake aborts before Round 2; key panels never light.",
  },
];

export class JPakeRunner extends StepMachine implements Runner {
  readonly protocol = "jpake" as const;
  private readonly a: JPakeParty;
  private readonly b: JPakeParty;

  constructor(
    private readonly idA: string,
    private readonly idB: string,
    pwA: Password,
    pwB: Password,
  ) {
    super();
    this.a = makeJPakeParty("A", idA, idB, pwA);
    this.b = makeJPakeParty("B", idB, idA, pwB);
    this.build();
  }

  private build(): void {
    let a1: WireMsg, b1: WireMsg, a2: WireMsg, b2: WireMsg, ac: WireMsg, bc: WireMsg;
    let a1c: WireCard, b1c: WireCard, a2c: WireCard, b2c: WireCard, acc: WireCard, bcc: WireCard;
    this.stages.push(
      { label: "A → Round 1", run: () => { a1 = this.maybeTamper(this.a.round1()); return (a1c = this.push(a1, ["g1", "g2", "V1", "r1", "V2", "r2"], "Peer A publishes two public group elements plus a zero-knowledge (Schnorr) proof for each — 'I know the exponent behind this' — without revealing the exponent.")); } },
      { label: "B → Round 1", run: () => { b1 = this.maybeTamper(this.b.round1()); return (b1c = this.push(b1, ["g3", "g4", "V3", "r3", "V4", "r4"], "Peer B does the same: two public elements and their zero-knowledge proofs. No password material has crossed — only proofs of knowledge.")); } },
      { label: "A receives B's Round 1", run: () => { this.consuming = b1c; this.a.recvRound1(b1); return null; } },
      { label: "B receives A's Round 1", run: () => { this.consuming = a1c; this.b.recvRound1(a1); return null; } },
      { label: "A → Round 2", run: () => { a2 = this.maybeTamper(this.a.round2()); return (a2c = this.push(a2, ["elem", "V", "r"], "Now A mixes the shared password into a new public element (with another proof). This is the only step the password influences — and it still crosses only as an exponent nobody can extract.")); } },
      { label: "B → Round 2", run: () => { b2 = this.maybeTamper(this.b.round2()); return (b2c = this.push(b2, ["elem", "V", "r"], "B mixes the same password in the same way. If both passwords match, these two elements will combine into one shared key.")); } },
      { label: "A receives B's Round 2", run: () => { this.consuming = b2c; this.a.recvRound2(b2); return null; } },
      { label: "B receives A's Round 2", run: () => { this.consuming = a2c; this.b.recvRound2(a2); return null; } },
      { label: "A derives key", run: () => { this.a.deriveKey(); return null; } },
      { label: "B derives key", run: () => { this.b.deriveKey(); return null; } },
      { label: "A → confirm tag", run: () => { ac = this.maybeTamper(this.a.confirm()); return (acc = this.push(ac, ["tag"], "A sends a MAC of its derived key so B can check they truly agree — the key itself never crosses.")); } },
      { label: "B → confirm tag", run: () => { bc = this.maybeTamper(this.b.confirm()); return (bcc = this.push(bc, ["tag"], "B sends its matching confirmation tag. Both verify, and the handshake confirms.")); } },
      { label: "A verifies B's tag", run: () => { this.consuming = bcc; this.a.recvConfirm(bc); return null; } },
      { label: "B verifies A's tag", run: () => { this.consuming = acc; this.b.recvConfirm(ac); this.finish(); return null; } },
    );
  }

  private finish(): void {
    const lk = this.a.sessionKeyBytes;
    const rk = this.b.sessionKeyBytes;
    const confirmed = this.a.phase === "confirmed" && this.b.phase === "confirmed";
    this.status_ = confirmed && eqBytes(lk, rk)
      ? { kind: "confirmed" }
      : { kind: "mismatch", message: "Keys differ or confirmation incomplete — handshake did not confirm." };
  }

  private peerView(p: JPakeParty, title: string, self: string, peer: string): PeerView {
    const t = p.trace;
    const scratch: ScratchRow[] = [
      { label: "s = scalar(password)", plain: "my password as a secret number", term: "scalar", value: bigHex(t.s), secret: true },
      { label: "K_material", plain: "my raw shared secret", term: "premaster", value: t.kMaterial ? bytesHex(t.kMaterial) : "—", secret: true },
      { label: "kc (confirm key)", plain: "my confirmation key", term: "confirmtag", value: t.kc ? bytesHex(t.kc) : "—", secret: true },
      { label: "gCombined (self)", plain: "my mixing base (public)", term: "gpow", value: t.gCombinedSelf !== undefined ? bigHex(t.gCombinedSelf) : "—", secret: false },
      { label: "own element", plain: "my public share", term: "gpow", value: t.elemSelf !== undefined ? bigHex(t.elemSelf) : "—", secret: false },
    ];
    return { title, role: `self "${self}", peer "${peer}"`, scratch };
  }

  leftPeer(): PeerView {
    return this.peerView(this.a, "Peer A", this.idA, this.idB);
  }
  rightPeer(): PeerView {
    return this.peerView(this.b, "Peer B", this.idB, this.idA);
  }
  leftKey(): KeyView {
    return { present: !!this.a.sessionKeyBytes, keyBytes: this.a.sessionKeyBytes, confirmed: this.a.phase === "confirmed" };
  }
  rightKey(): KeyView {
    return { present: !!this.b.sessionKeyBytes, keyBytes: this.b.sessionKeyBytes, confirmed: this.b.phase === "confirmed" };
  }
  tamperMenu(): TamperOp[] {
    return TAMPER;
  }
}
