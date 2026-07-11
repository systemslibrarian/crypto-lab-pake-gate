// LEFT / RIGHT peer boxes. Each shows a dimmed "private — never leaves this box"
// scratchpad of secrets plus running derived (public) values.

import { clear, el, hexBox } from "./dom.ts";
import { truncMiddle, type PeerView } from "./model.ts";

export function renderPeerPanel(
  host: HTMLElement,
  view: PeerView,
  opts: { hideScratch: boolean },
): void {
  clear(host);
  const secrets = view.scratch.filter((r) => r.secret);
  const publics = view.scratch.filter((r) => !r.secret);

  const head = el("div", { class: "peer__head" }, [
    el("h3", { class: "peer__title", text: view.title }),
    el("p", { class: "peer__role", text: view.role }),
  ]);
  host.append(head);

  if (!opts.hideScratch && secrets.length) {
    const pad = el("div", { class: "scratch", role: "group", "aria-label": "private scratchpad" }, [
      el("div", { class: "scratch__banner" }, [
        el("span", { class: "scratch__lock", "aria-hidden": "true", text: "🔒" }),
        el("span", { text: "private — never leaves this box" }),
      ]),
      ...secrets.map((r) => scratchRow(r.label, r.value, true)),
    ]);
    host.append(pad);
  }

  const pub = el("div", { class: "derived", role: "group", "aria-label": "derived public values" }, [
    el("div", { class: "derived__banner", text: "derived / public" }),
    ...publics.map((r) => scratchRow(r.label, r.value, false)),
  ]);
  host.append(pub);
}

function scratchRow(label: string, value: string, secret: boolean): HTMLElement {
  const showRaw = value !== "—" && value.length > 20;
  const row = el("div", { class: "srow" + (secret ? " srow--secret" : "") }, [
    el("span", { class: "srow__label", text: label }),
    showRaw
      ? hexBox(value, { label })
      : el("code", { class: "srow__value", text: value === "—" ? "—" : truncMiddle(value, 18, 10) }),
  ]);
  return row;
}
