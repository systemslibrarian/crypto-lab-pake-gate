// CPace runner (balanced, two peers A/B). Confirmation-tag tamper.

import { cpaceCI, makeCPaceParty } from "../../pake/factories.ts";
import type { CPaceParty } from "../../pake/cpace.ts";
import type { Password, WireMsg } from "../../pake/types.ts";
import {
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
    id: "cpace-msg",
    label: "Corrupt a message element (Y)",
    step: "msg",
    field: "Y",
    expect: "The two sides now derive different K → different ISK → the confirmation tags fail to verify; handshake aborts, no shared key.",
  },
  {
    id: "cpace-tag",
    label: "Corrupt a confirmation tag",
    step: "confirm",
    field: "tag",
    expect: "The receiving peer recomputes the HMAC tag and rejects — 'confirmation failed' — key not established.",
  },
];

export class CPaceRunner extends StepMachine implements Runner {
  readonly protocol = "cpace" as const;
  private readonly a: CPaceParty;
  private readonly b: CPaceParty;

  constructor(
    private readonly idA: string,
    private readonly idB: string,
    pwA: Password,
    pwB: Password,
  ) {
    super();
    const ci = cpaceCI(idA, idB);
    const sid = crypto.getRandomValues(new Uint8Array(16));
    const ad = new Uint8Array(0);
    this.a = makeCPaceParty("A", pwA, ci, sid, ad);
    this.b = makeCPaceParty("B", pwB, ci, sid, ad);
    this.build();
  }

  private build(): void {
    let am: WireMsg, bm: WireMsg, ac: WireMsg, bc: WireMsg;
    let amc: WireCard, bmc: WireCard, acc: WireCard, bcc: WireCard;
    this.stages.push(
      { label: "A → message (Y, AD)", run: () => { am = this.maybeTamper(this.a.message()); return (amc = this.push(am, ["Y", "AD"])); } },
      { label: "B → message (Y, AD)", run: () => { bm = this.maybeTamper(this.b.message()); return (bmc = this.push(bm, ["Y", "AD"])); } },
      { label: "A receives B's message", run: () => { this.consuming = bmc; this.a.receive(bm); return null; } },
      { label: "B receives A's message", run: () => { this.consuming = amc; this.b.receive(am); return null; } },
      { label: "A → confirm tag", run: () => { ac = this.maybeTamper(this.a.confirm()); return (acc = this.push(ac, ["tag"])); } },
      { label: "B → confirm tag", run: () => { bc = this.maybeTamper(this.b.confirm()); return (bcc = this.push(bc, ["tag"])); } },
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

  private peerView(p: CPaceParty, title: string, self: string): PeerView {
    const t = p.trace;
    const scratch: ScratchRow[] = [
      { label: "Y (self, sent)", value: t.Yself ? bytesHex(t.Yself) : "—", secret: false },
      { label: "K (shared point)", value: t.K ? bytesHex(t.K.toBytes()) : "—", secret: true },
      { label: "ISK (session key)", value: t.isk ? bytesHex(t.isk) : "—", secret: true },
      { label: "mac_key", value: t.macKey ? bytesHex(t.macKey) : "—", secret: true },
    ];
    return { title, role: `party "${self}"`, scratch };
  }

  leftPeer(): PeerView {
    return this.peerView(this.a, "Peer A", this.idA);
  }
  rightPeer(): PeerView {
    return this.peerView(this.b, "Peer B", this.idB);
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
