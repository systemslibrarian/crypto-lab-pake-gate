// Dragonfly runner (balanced, two peers). Confirm-tag tamper surface.

import { makeDragonflyParty } from "../../pake/factories.ts";
import type { DragonflyParty } from "../../pake/dragonfly.ts";
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
    id: "dragonfly-commit",
    label: "Corrupt a commit scalar",
    step: "commit",
    field: "scalar",
    expect: "The peer derives a different shared point → different kck → confirm tags fail to verify; handshake aborts with no key.",
  },
  {
    id: "dragonfly-confirm",
    label: "Corrupt a confirm tag",
    step: "confirm",
    field: "confirm",
    expect: "The receiving peer recomputes SHA-256(kck||…) and rejects — 'confirm mismatch' — key not established.",
  },
];

export class DragonflyRunner extends StepMachine implements Runner {
  readonly protocol = "dragonfly" as const;
  private readonly a: DragonflyParty;
  private readonly b: DragonflyParty;

  constructor(
    private readonly idA: string,
    private readonly idB: string,
    pwA: Password,
    pwB: Password,
  ) {
    super();
    this.a = makeDragonflyParty(idA, idB, pwA);
    this.b = makeDragonflyParty(idB, idA, pwB);
    this.build();
  }

  private build(): void {
    let ac: WireMsg, bc: WireMsg, acon: WireMsg, bcon: WireMsg;
    let acc: WireCard, bcc: WireCard, aconc: WireCard, bconc: WireCard;
    this.stages.push(
      { label: "A derives password element (PE)", run: () => { this.a.derivePE(); return null; } },
      { label: "B derives password element (PE)", run: () => { this.b.derivePE(); return null; } },
      { label: "A → commit (scalar, element)", run: () => { ac = this.maybeTamper(this.a.commit()); return (acc = this.push(ac, ["scalar", "element"], "A commits: it sends a scalar and a curve element built from the password-derived point. Neither reveals the password on its own.")); } },
      { label: "B → commit (scalar, element)", run: () => { bc = this.maybeTamper(this.b.commit()); return (bcc = this.push(bc, ["scalar", "element"], "B sends its matching commit. Combined with A's, and only if the passwords agree, they reconstruct the same shared point.")); } },
      { label: "A receives B's commit", run: () => { this.consuming = bcc; this.a.recvCommit(bc); return null; } },
      { label: "B receives A's commit", run: () => { this.consuming = acc; this.b.recvCommit(ac); return null; } },
      { label: "A derives key", run: () => { this.a.deriveKey(); return null; } },
      { label: "B derives key", run: () => { this.b.deriveKey(); return null; } },
      { label: "A → confirm", run: () => { acon = this.maybeTamper(this.a.confirm()); return (aconc = this.push(acon, ["confirm"], "A sends a hash-based confirmation over the shared key so B can check they match — the key never crosses.")); } },
      { label: "B → confirm", run: () => { bcon = this.maybeTamper(this.b.confirm()); return (bconc = this.push(bcon, ["confirm"], "B returns its confirmation; both verify and the handshake confirms.")); } },
      { label: "A verifies B's confirm", run: () => { this.consuming = bconc; this.a.recvConfirm(bcon); return null; } },
      { label: "B verifies A's confirm", run: () => { this.consuming = aconc; this.b.recvConfirm(acon); this.finish(); return null; } },
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

  private peerView(p: DragonflyParty, title: string, self: string, peer: string): PeerView {
    const t = p.trace;
    const scratch: ScratchRow[] = [
      { label: "PE iterations", plain: "hunt-and-peck tries", term: "huntpeck", value: t.peIterations !== undefined ? String(t.peIterations) : "—", secret: false },
      { label: "scalar (self)", plain: "my public share", term: "scalar", value: t.scalarSelf !== undefined ? bigHex(t.scalarSelf) : "—", secret: false },
      { label: "ss (shared x)", plain: "my raw shared secret", term: "premaster", value: t.ss !== undefined ? bigHex(t.ss) : "—", secret: true },
      { label: "kck (confirm key)", plain: "my confirmation key", term: "confirmtag", value: t.kck ? bytesHex(t.kck) : "—", secret: true },
      { label: "mk (session key)", plain: "my session key", term: "isk", value: t.mk ? bytesHex(t.mk) : "—", secret: true },
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
