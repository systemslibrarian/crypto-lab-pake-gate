// Shared step-machine plumbing for the balanced runners (J-PAKE / CPace / Dragonfly)
// and re-used pieces. Keeps tamper/push/abort handling in one place.

import { HandshakeAbort, type Hex, type WireMsg } from "../../pake/types.ts";
import {
  flipNibble,
  type RunStatus,
  type TamperOp,
  type WireCard,
} from "../model.ts";

export interface Stage {
  readonly label: string;
  readonly run: () => WireCard | null;
}

export abstract class StepMachine {
  protected readonly stages: Stage[] = [];
  protected idx = 0;
  protected tamper: TamperOp | null = null;
  protected status_: RunStatus = { kind: "idle" };
  protected lastCard: WireCard | null = null;
  /** the card whose message the current receive-stage is consuming (abort target). */
  protected consuming: WireCard | null = null;

  hasNext(): boolean {
    return this.idx < this.stages.length && this.status_.kind !== "aborted";
  }
  totalSteps(): number {
    return this.stages.length;
  }
  nextIndex(): number {
    return this.idx;
  }

  step(): { card: WireCard | null; label: string } {
    const stage = this.stages[this.idx];
    if (!stage) return { card: null, label: "" };
    this.idx++;
    this.consuming = null;
    if (this.status_.kind === "idle") this.status_ = { kind: "running" };
    try {
      const card = stage.run();
      return { card, label: stage.label };
    } catch (e) {
      if (e instanceof HandshakeAbort) {
        this.status_ = { kind: "aborted", message: e.reason, tooltip: e.tooltip };
        // Attribute the rejection to the card actually being received (if any), else
        // to the last produced card.
        const card = this.consuming ?? this.lastCard;
        if (card) card.aborted = { reason: e.reason, tooltip: e.tooltip };
        return { card, label: stage.label };
      }
      throw e;
    }
  }

  status(): RunStatus {
    return this.status_;
  }
  setTamper(op: TamperOp | null): void {
    this.tamper = op;
  }
  armedTamper(): TamperOp | null {
    return this.tamper;
  }

  protected push(msg: WireMsg, highlight: string[], caption?: string): WireCard {
    const card: WireCard = { msg, highlight, caption };
    if (this.tamper?.step === msg.step) card.tampered = true;
    this.lastCard = card;
    return card;
  }

  /** Apply an armed tamper op to a just-produced message before delivery. */
  protected maybeTamper(msg: WireMsg): WireMsg {
    if (!this.tamper || this.tamper.step !== msg.step) return msg;
    const cur = msg.fields[this.tamper.field];
    if (typeof cur !== "string") return msg;
    const flipped = flipNibble(cur) as Hex;
    return { ...msg, fields: { ...msg.fields, [this.tamper.field]: flipped } };
  }
}

export function eqBytes(a?: Uint8Array, b?: Uint8Array): boolean {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}
