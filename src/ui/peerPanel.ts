// LEFT / RIGHT peer boxes. Each shows a dimmed "private — never leaves this box"
// scratchpad of secrets plus running derived (public) values.

import { clear, el, hexBox } from "./dom.ts";
import { truncMiddle, type PeerView, type ScratchRow } from "./model.ts";
import { glossaryTip } from "./glossary.ts";

export interface PeerPanelOpts {
  readonly hideScratch: boolean;
  /**
   * "plain" — the Start-here view: lead each row with a plain-language name and
   * put the notation second. "notation" — the Go-deeper view: notation leads, plain
   * name is the sub-caption. Default "notation".
   */
  readonly labelMode?: "plain" | "notation";
  /**
   * Field names the just-taken step published to the wire, for THIS peer — their
   * secret rows pulse their lock to show the secret stayed home while a public
   * value crossed. (Only the sending peer receives a non-empty set.)
   */
  readonly justPublished?: boolean;
}

export function renderPeerPanel(
  host: HTMLElement,
  view: PeerView,
  opts: PeerPanelOpts,
): void {
  clear(host);
  const secrets = view.scratch.filter((r) => r.secret);
  const publics = view.scratch.filter((r) => !r.secret);
  const mode = opts.labelMode ?? "notation";

  const head = el("div", { class: "peer__head" }, [
    el("h3", { class: "peer__title", text: view.title }),
    el("p", { class: "peer__role", text: view.role }),
  ]);
  host.append(head);

  if (!opts.hideScratch && secrets.length) {
    const pad = el("div", { class: "scratch" + (opts.justPublished ? " scratch--stayed" : ""), role: "group", "aria-label": "private scratchpad" }, [
      el("div", { class: "scratch__banner" }, [
        el("span", { class: "scratch__lock", "aria-hidden": "true", text: "🔒" }),
        el("span", { text: "private — never leaves this box" }),
      ]),
      ...secrets.map((r) => scratchRow(r, true, mode)),
    ]);
    host.append(pad);
  }

  const pub = el("div", { class: "derived", role: "group", "aria-label": "derived public values" }, [
    el("div", { class: "derived__banner", text: "derived / public (safe to send)" }),
    ...publics.map((r) => scratchRow(r, false, mode)),
  ]);
  host.append(pub);
}

function scratchRow(r: ScratchRow, secret: boolean, mode: "plain" | "notation"): HTMLElement {
  const { label, value } = r;
  const showRaw = value !== "—" && value.length > 20;
  const tip = glossaryTip(r.term);

  // Label block: which of (plain, notation) leads depends on mode.
  const lead = mode === "plain" && r.plain ? r.plain : label;
  const sub = mode === "plain" && r.plain ? label : r.plain;

  const labelEl = el("span", { class: "srow__label" + (tip ? " srow__label--term" : "") }, [
    el("span", { class: "srow__lead", text: lead }),
    sub ? el("span", { class: "srow__sub", text: sub }) : undefined,
  ]);
  if (tip) {
    // In-context definition, available on hover AND keyboard focus (WCAG 1.4.13).
    labelEl.setAttribute("tabindex", "0");
    labelEl.setAttribute("role", "note");
    labelEl.setAttribute("aria-label", `${lead}. ${tip.title}: ${tip.text}`);
    labelEl.append(
      el("span", { class: "srow__tip", role: "tooltip" }, [
        el("strong", { text: tip.title }),
        el("span", { text: " — " + tip.text }),
      ]),
    );
  }

  const row = el("div", { class: "srow" + (secret ? " srow--secret" : "") }, [
    labelEl,
    showRaw
      ? hexBox(value, { label })
      : el("code", { class: "srow__value", text: value === "—" ? "—" : truncMiddle(value, 18, 10) }),
  ]);
  return row;
}
