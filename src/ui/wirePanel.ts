// CENTER: the Wire. Every crossed message is a card with its fields expanded. Hex in
// horizontally-scrollable copy boxes (never wrapped). This is the transcript.

import { clear, el, hexBox } from "./dom.ts";
import type { WireCard } from "./model.ts";

function looksHex(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && v.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(v);
}

export function renderWirePanel(
  host: HTMLElement,
  cards: WireCard[],
  opts?: { rawBytes?: boolean },
): void {
  clear(host);
  if (cards.length === 0) {
    host.append(el("p", { class: "wire__empty", text: "No messages yet. Press Step (or a scripted run) to cross a message." }));
    return;
  }
  for (const card of cards) {
    host.append(renderCard(card, opts?.rawBytes ?? false));
  }
}

function renderCard(card: WireCard, rawBytes: boolean): HTMLElement {
  const cls =
    "wcard" +
    (card.aborted ? " wcard--abort" : "") +
    (card.tampered ? " wcard--tampered" : "");
  const from = card.msg.from;
  const header = el("div", { class: "wcard__head" }, [
    el("span", { class: `wcard__from wcard__from--${from}`, text: `from ${from}` }),
    el("span", { class: "wcard__step", text: card.msg.step }),
    card.tampered ? el("span", { class: "wcard__badge wcard__badge--tamper", text: "⚠ tampered" }) : undefined,
    card.aborted ? el("span", { class: "wcard__badge wcard__badge--abort", text: "⚠ rejected" }) : undefined,
  ]);

  const fields = el("div", { class: "wcard__fields" });
  for (const [name, value] of Object.entries(card.msg.fields)) {
    const hot = card.highlight.includes(name);
    const fieldEl = el("div", { class: "wfield" + (hot ? " wfield--hot" : "") }, [
      el("span", { class: "wfield__name", text: name }),
      looksHex(value)
        ? hexBox(rawBytes ? spacedBytes(value) : value, { highlight: hot, label: name })
        : el("code", { class: "wfield__scalar", text: String(value) }),
    ]);
    fields.append(fieldEl);
  }

  const card_ = el("div", { class: cls }, [header, fields]);
  if (card.aborted) {
    card_.append(
      el("p", { class: "wcard__abort-msg" }, [
        el("strong", { text: card.aborted.reason }),
        el("span", { text: " — " + card.aborted.tooltip }),
      ]),
    );
  }
  return card_;
}

/** For the raw-bytes attacker view: group hex into space-separated byte pairs. */
function spacedBytes(hex: string): string {
  return hex.replace(/(..)/g, "$1 ").trim();
}
