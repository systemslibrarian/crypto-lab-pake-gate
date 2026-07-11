// A single protocol tab: shared split view (peers / wire / keys) + password controls,
// scripted launchers, the curated tamper menu, and the attacker / breach / dragonblood
// auxiliary panels.

import { makePassword, srpRegister } from "../pake/factories.ts";
import type { Password, WireMsg } from "../pake/types.ts";
import type { SrpVerifierRecord } from "../pake/srp6a.ts";
import { button, clear, el, labeledInput } from "./dom.ts";
import {
  type ProtocolId,
  type Runner,
  type TamperOp,
  type WireCard,
} from "./model.ts";
import { SrpRunner } from "./runners/srpRunner.ts";
import { JPakeRunner } from "./runners/jpakeRunner.ts";
import { CPaceRunner } from "./runners/cpaceRunner.ts";
import { DragonflyRunner } from "./runners/dragonflyRunner.ts";
import { renderPeerPanel } from "./peerPanel.ts";
import { renderWirePanel } from "./wirePanel.ts";
import { renderKeyPanel, type KeyPanelState } from "./keyPanel.ts";
import { launchersFor, type LauncherId } from "./launchers.ts";
import {
  renderObserverPanel,
  renderSrpBreachPanel,
  renderBalancedBreachNote,
} from "./attacker.ts";
import { renderDragonbloodPanel } from "./dragonbloodPanel.ts";
import { TAXONOMY } from "../pake/taxonomy.ts";

const ID_A = "alice@example";
const ID_B = "bob@example";

// Per-tab "what you are actually watching here" — the concrete demonstration, not the
// abstract definition (that lives in the taxonomy matrix below the tabs).
const DEMONSTRATES: Record<ProtocolId, string> = {
  srp6a:
    "The augmented case: the server stores only a verifier {salt, v}, never your password. Watch the A / B / u / S exchange end in a mutually-confirmed key — then open “Server breach” to see why a stolen verifier still costs the attacker an offline dictionary attack.",
  jpake:
    "The balanced case: two peers who share the same password each publish g^x with a zero-knowledge proof, then mix the password in — no verifier is stored anywhere. Try “Active tamper” on a Round-1 proof to watch the handshake abort before any key even exists.",
  cpace:
    "The compact one-round balanced PAKE the CFRG chose: the generator is derived from the password AND the session context, a Diffie–Hellman runs over it, and the key is bound to the whole transcript before confirmation.",
  dragonfly:
    "The family behind WPA3’s SAE: the password is mapped to a curve point by “hunting and pecking.” That search loop is exactly what the Dragonblood attack timed — open the Dragonblood panel to see the leak, and why the honest run uses a minimum-iteration derivation.",
};

const TRY_HINT: Record<ProtocolId, string> = {
  srp6a: "Type a password, click Register, then Honest run — both keys match and confirm (green). Try Wrong password to watch it fail (red).",
  jpake: "Click Honest run (same password both sides) → keys match and confirm. Type a different Peer B password (Wrong password) to see it fail.",
  cpace: "Click Honest run → both sides derive the same key and confirm. Change one side’s password (Wrong password) to watch the keys diverge.",
  dragonfly: "Click Honest run → both peers derive the same key from the shared password. Then open the Dragonblood side-channel panel.",
};

type Aux = "none" | "observer" | "breach" | "dragonblood";

export class TabView {
  readonly root: HTMLElement;
  private runner: Runner;
  private cards: WireCard[] = [];
  private wireOnly = false;
  private keyState: KeyPanelState = { reveal: false };
  private armedTamper: TamperOp | null = null;
  private aux: Aux = "none";
  private activeLauncher: LauncherId | null = null;

  // SRP-only registration state.
  private srpRecord: SrpVerifierRecord | null = null;

  // password inputs (values kept live).
  private pwPrimary = "";
  private pwSecondary = "";

  // element handles for partial re-render.
  private peerLeftHost!: HTMLElement;
  private peerRightHost!: HTMLElement;
  private wireHost!: HTMLElement;
  private keyHost!: HTMLElement;
  private auxHost!: HTMLElement;
  private tamperHost!: HTMLElement;
  private statusHost!: HTMLElement;
  private controlsHost!: HTMLElement;

  constructor(readonly protocol: ProtocolId) {
    this.root = el("div", { class: "tabview", role: "tabpanel" });
    this.runner = this.freshRunner();
    this.build();
    this.rerender();
  }

  // --- runner lifecycle ---

  private registeredPassword(): Password {
    // For SRP the record must exist before a runner can meaningfully step.
    return makePassword(this.pwPrimary);
  }

  private freshRunner(): Runner {
    const pwA = makePassword(this.pwPrimary || "hunter2");
    const pwB = makePassword((this.pwSecondary || this.pwPrimary) || "hunter2");
    switch (this.protocol) {
      case "srp6a": {
        const record = this.srpRecord ?? srpRegister(ID_A, this.registeredPassword() || makePassword("hunter2"));
        this.srpRecord = record;
        // client uses pwPrimary (may differ from registered for "wrong password").
        return new SrpRunner(ID_A, makePassword(this.pwPrimary || "hunter2"), record);
      }
      case "jpake":
        return new JPakeRunner(ID_A, ID_B, pwA, pwB);
      case "cpace":
        return new CPaceRunner(ID_A, ID_B, pwA, pwB);
      case "dragonfly":
        return new DragonflyRunner(ID_A, ID_B, pwA, pwB);
    }
  }

  private reset(keepRecord = true): void {
    if (!keepRecord && this.protocol === "srp6a") this.srpRecord = null;
    this.cards = [];
    this.aux = "none";
    this.activeLauncher = null;
    this.runner = this.freshRunner();
    this.runner.setTamper(this.armedTamper);
    this.rerender();
  }

  private transcript(): WireMsg[] {
    return this.cards.map((c) => c.msg);
  }

  private truePassword(): Password {
    return makePassword(this.pwPrimary || "hunter2");
  }

  // --- build static layout ---

  private build(): void {
    this.root.append(this.buildExplainer());
    this.root.append(this.buildControls());

    this.statusHost = el("div", { class: "status", role: "status", "aria-live": "polite" });
    this.root.append(this.statusHost);

    this.tamperHost = el("div", { class: "tamper" });
    this.root.append(this.tamperHost);

    const split = el("div", { class: "split" });
    this.peerLeftHost = el("div", { class: "split__peer" });
    this.wireHost = el("div", { class: "split__wire", role: "region", "aria-label": "the wire (transcript)" });
    this.peerRightHost = el("div", { class: "split__peer" });
    const keyCol = el("aside", { class: "split__keys" });
    this.keyHost = keyCol;
    split.append(this.peerLeftHost, this.wireHost, this.peerRightHost);
    this.root.append(split);
    this.root.append(keyCol);

    this.auxHost = el("div", { class: "aux" });
    this.root.append(this.auxHost);
  }

  private buildExplainer(): HTMLElement {
    const row = TAXONOMY.find((r) => r.id === this.protocol)!;
    const family = row.kind === "balanced" ? "balanced PAKE" : "augmented PAKE";
    const badgeClass = row.kind === "balanced" ? "badge badge--balanced" : "badge badge--augmented";
    return el("section", { class: "explainer", "aria-label": `About ${row.name}` }, [
      el("div", { class: "explainer__head" }, [
        el("h2", { class: "explainer__title", text: row.name }),
        el("span", { class: badgeClass, text: family }),
        el("span", { class: "explainer__std", text: row.standardization }),
      ]),
      el("p", { class: "explainer__what", text: DEMONSTRATES[this.protocol] }),
      el("p", { class: "explainer__try" }, [
        el("strong", { text: "Try it: " }),
        TRY_HINT[this.protocol],
      ]),
    ]);
  }

  private buildControls(): HTMLElement {
    this.controlsHost = el("div", { class: "controls" });
    this.renderControls();
    return this.controlsHost;
  }

  private renderControls(): void {
    clear(this.controlsHost);

    // Password fields.
    const fields = el("div", { class: "controls__fields" });
    const primaryLabel = this.protocol === "srp6a" ? "Client password" : "Peer A password";
    const p = labeledInput(primaryLabel, {
      id: `${this.protocol}-pw1`,
      type: "text",
      value: this.pwPrimary,
      placeholder: "hunter2",
      autocomplete: "off",
    });
    p.input.addEventListener("input", () => { this.pwPrimary = p.input.value; });
    fields.append(p.wrap);

    if (this.protocol === "srp6a") {
      const reg = button("Register {salt, v}", () => {
        this.srpRecord = srpRegister(ID_A, makePassword(this.pwPrimary || "hunter2"));
        this.reset(true);
      }, { class: "btn--secondary", title: "One-time: derive and store the verifier record" });
      fields.append(el("div", { class: "field field--action" }, [reg]));
    } else {
      const s = labeledInput("Peer B password", {
        id: `${this.protocol}-pw2`,
        type: "text",
        value: this.pwSecondary,
        placeholder: "(same as A)",
        autocomplete: "off",
      });
      s.input.addEventListener("input", () => { this.pwSecondary = s.input.value; });
      fields.append(s.wrap);
    }
    this.controlsHost.append(fields);

    // Launcher buttons.
    const launchers = el("div", { class: "controls__launchers", role: "group", "aria-label": "scripted scenarios" });
    for (const l of launchersFor(this.protocol)) {
      const b = button(l.label, () => this.runLauncher(l.id), {
        class: "btn--launcher" + (this.activeLauncher === l.id ? " is-active" : ""),
        title: l.expect,
      });
      launchers.append(b);
    }
    this.controlsHost.append(launchers);

    // Stepper + view toggles.
    const stepper = el("div", { class: "controls__stepper" });
    const stepBtn = button("Step ▸", () => this.doStep(), {
      class: "btn--primary",
      disabled: !this.runner.hasNext(),
      title: "Advance exactly one protocol message",
    });
    const resetBtn = button("Reset", () => this.reset(true), { class: "btn--ghost" });
    const wireToggle = el("label", { class: "toggle" }, [
      (() => {
        const cb = el("input", { type: "checkbox", class: "toggle__cb", "aria-label": "Wire only — hide both peer scratchpads" }) as HTMLInputElement;
        cb.checked = this.wireOnly;
        cb.addEventListener("change", () => { this.wireOnly = cb.checked; this.rerender(); });
        return cb;
      })(),
      el("span", { text: "Wire only (hide scratchpads)" }),
    ]);
    stepper.append(stepBtn, resetBtn, wireToggle);
    this.controlsHost.append(stepper);
  }

  // --- actions ---

  private addCard(card: WireCard | null): void {
    // A step may return an already-recorded card (e.g. an abort attributed to the
    // message being received). Only append genuinely new cards.
    if (card && !this.cards.includes(card)) this.cards.push(card);
  }

  private doStep(): void {
    if (!this.runner.hasNext()) return;
    const { card } = this.runner.step();
    this.addCard(card);
    this.rerender();
  }

  private runAll(): void {
    let guard = 0;
    while (this.runner.hasNext() && guard++ < 64) {
      const { card } = this.runner.step();
      this.addCard(card);
      if (this.runner.status().kind === "aborted") break;
    }
  }

  private runLauncher(id: LauncherId): void {
    this.activeLauncher = id;
    switch (id) {
      case "honest": {
        const good = (this.pwPrimary || "hunter2").replace(/-WRONG$/, "");
        this.pwPrimary = good;
        this.pwSecondary = good;
        if (this.protocol === "srp6a") this.srpRecord = srpRegister(ID_A, makePassword(good));
        this.armedTamper = null;
        this.aux = "none";
        this.cards = [];
        this.runner = this.freshRunner();
        this.runAll();
        break;
      }
      case "wrong-password": {
        // Strip any prior "-WRONG" suffix so repeated clicks stay coherent.
        const good = (this.pwPrimary || "hunter2").replace(/-WRONG$/, "");
        if (this.protocol === "srp6a") {
          // register with the good password, then run the client with a wrong one.
          this.srpRecord = srpRegister(ID_A, makePassword(good));
          this.pwPrimary = good + "-WRONG";
        } else {
          this.pwPrimary = good;
          this.pwSecondary = good + "-WRONG";
        }
        this.armedTamper = null;
        this.aux = "none";
        this.cards = [];
        this.runner = this.freshRunner();
        this.runAll();
        break;
      }
      case "observer": {
        if (this.cards.length === 0) { this.runLauncher("honest"); this.activeLauncher = "observer"; }
        this.aux = "observer";
        break;
      }
      case "tamper": {
        // Show the curated menu; the user picks an op, then steps/runs.
        this.aux = "none";
        this.rerender();
        return;
      }
      case "breach": {
        this.aux = "breach";
        if (this.protocol === "srp6a" && !this.srpRecord) {
          this.srpRecord = srpRegister(ID_A, makePassword(this.pwPrimary || "hunter2"));
        }
        break;
      }
      case "dragonblood": {
        this.aux = "dragonblood";
        break;
      }
    }
    this.rerender();
  }

  private armTamper(op: TamperOp | null): void {
    this.armedTamper = op;
    // arming requires a fresh run so the target step is still ahead.
    this.cards = [];
    this.aux = "none";
    this.runner = this.freshRunner();
    this.runner.setTamper(op);
    if (op) this.runAll();
    this.rerender();
  }

  // --- render ---

  private rerender(): void {
    this.renderControls();
    this.renderStatus();
    this.renderTamperMenu();
    renderPeerPanel(this.peerLeftHost, this.runner.leftPeer(), { hideScratch: this.wireOnly });
    renderPeerPanel(this.peerRightHost, this.runner.rightPeer(), { hideScratch: this.wireOnly });
    renderWirePanel(this.wireHost, this.cards, { rawBytes: false });
    renderKeyPanel(
      this.keyHost,
      this.runner.leftKey(),
      this.runner.rightKey(),
      this.runner.status(),
      this.keyState,
      () => { this.keyState.reveal = !this.keyState.reveal; this.rerender(); },
    );
    this.renderAux();
  }

  private renderStatus(): void {
    clear(this.statusHost);
    const st = this.runner.status();
    const next = this.runner.hasNext() ? `Step ${this.runner.nextIndex() + 1} of ${this.runner.totalSteps()} ready.` : "All steps complete.";
    let cls = "status__pill";
    let text = next;
    if (st.kind === "confirmed") { cls += " status__pill--ok"; text = "✓ Confirmed — password never left either box."; }
    else if (st.kind === "aborted") { cls += " status__pill--alarm"; text = `⚠ Aborted — ${st.message}`; }
    else if (st.kind === "mismatch") { cls += " status__pill--alarm"; text = `⚠ ${st.message}`; }
    this.statusHost.append(el("span", { class: cls, text }));
    if (this.activeLauncher) {
      const l = launchersFor(this.protocol).find((x) => x.id === this.activeLauncher);
      if (l) this.statusHost.append(el("span", { class: "status__expect", text: `Expected: ${l.expect}` }));
    }
  }

  private renderTamperMenu(): void {
    clear(this.tamperHost);
    if (this.activeLauncher !== "tamper") return;
    const menu = el("div", { class: "tamper__menu", role: "group", "aria-label": "curated tamper operations" }, [
      el("h3", { class: "tamper__title", text: "Active tamper — curated menu" }),
      el("p", { class: "tamper__lead", text: "Each op flips one hex nibble in one field at one step, then delivers it. The documented expected result follows." }),
    ]);
    for (const op of this.runner.tamperMenu()) {
      const active = this.armedTamper?.id === op.id;
      menu.append(
        el("div", { class: "tamper__op" + (active ? " is-active" : "") }, [
          button(active ? "✓ armed" : "Arm & run", () => this.armTamper(active ? null : op), { class: "btn--attack" }),
          el("div", { class: "tamper__op-body" }, [
            el("strong", { text: op.label }),
            el("span", { class: "tamper__expect", text: op.expect }),
          ]),
        ]),
      );
    }
    this.tamperHost.append(menu);
  }

  private renderAux(): void {
    clear(this.auxHost);
    switch (this.aux) {
      case "observer":
        this.auxHost.append(renderObserverPanel(this.protocol, this.transcript(), this.truePassword()));
        break;
      case "breach":
        if (this.protocol === "srp6a") {
          const record = this.srpRecord ?? srpRegister(ID_A, makePassword(this.pwPrimary || "hunter2"));
          this.auxHost.append(renderSrpBreachPanel(record, this.truePassword(), this.transcript()));
        } else {
          this.auxHost.append(renderBalancedBreachNote(this.protocol));
        }
        break;
      case "dragonblood":
        this.auxHost.append(renderDragonbloodPanel(ID_A, ID_B));
        break;
      case "none":
        break;
    }
  }
}
