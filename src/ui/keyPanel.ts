// RIGHT: the derived session key on each side. Shown by DEFAULT as a short
// fingerprint (truncated SHA-256 of the key bytes). A "reveal demo bytes" control
// expands the full key with a production-warning note. The confirmation badge lights
// only when BOTH keys match (true bytes) AND confirmation verified.

import { clear, el, hexBox } from "./dom.ts";
import {
  bytesEqual,
  bytesHex,
  fingerprint,
  type KeyView,
  type RunStatus,
} from "./model.ts";

export interface KeyPanelState {
  reveal: boolean;
}

export function renderKeyPanel(
  host: HTMLElement,
  left: KeyView,
  right: KeyView,
  status: RunStatus,
  state: KeyPanelState,
  onToggleReveal: () => void,
): void {
  clear(host);

  const matched = bytesEqual(left.keyBytes, right.keyBytes);
  const bothConfirmed = left.confirmed && right.confirmed;
  const success = status.kind === "confirmed" && matched && bothConfirmed;

  host.append(el("h3", { class: "keys__title", text: "Session keys" }));

  host.append(sideCard("Left side", left, state.reveal));
  host.append(sideCard("Right side", right, state.reveal));

  const toggle = el(
    "button",
    { type: "button", class: "btn btn--ghost keys__reveal", "aria-pressed": String(state.reveal) },
    [state.reveal ? "hide demo bytes" : "reveal demo bytes"],
  );
  toggle.addEventListener("click", onToggleReveal);
  host.append(toggle);

  if (state.reveal) {
    host.append(
      el("p", { class: "keys__warn", text: "Demo only: production interfaces must never expose session keys. Shown here purely to prove both sides derived the same secret." }),
    );
  }

  host.append(renderBadge(success, status, matched, bothConfirmed, left, right));
}

function sideCard(title: string, view: KeyView, reveal: boolean): HTMLElement {
  const rows: (Node | undefined)[] = [
    el("div", { class: "keycard__head" }, [
      el("span", { class: "keycard__title", text: title }),
      view.confirmed
        ? el("span", { class: "keycard__flag keycard__flag--ok", text: "✓ confirmed" })
        : el("span", { class: "keycard__flag", text: "not confirmed" }),
    ]),
  ];
  if (view.present && view.keyBytes) {
    rows.push(
      el("div", { class: "keycard__fp" }, [
        el("span", { class: "keycard__fp-label", text: "fingerprint" }),
        el("code", { class: "keycard__fp-value", text: fingerprint(view.keyBytes) }),
      ]),
    );
    if (reveal) {
      rows.push(hexBox(bytesHex(view.keyBytes), { label: "session key" }));
    }
  } else {
    rows.push(el("p", { class: "keycard__none", text: "— no key derived yet —" }));
  }
  return el("div", { class: "keycard" }, rows);
}

function renderBadge(
  success: boolean,
  status: RunStatus,
  matched: boolean,
  bothConfirmed: boolean,
  left: KeyView,
  right: KeyView,
): HTMLElement {
  if (success) {
    return el("div", { class: "verdict verdict--ok", role: "status" }, [
      el("span", { class: "verdict__icon", "aria-hidden": "true", text: "✓" }),
      el("span", { class: "verdict__text", text: "Key confirmed — password never left either box." }),
    ]);
  }
  if (status.kind === "aborted") {
    return el("div", { class: "verdict verdict--alarm", role: "alert" }, [
      el("span", { class: "verdict__icon", "aria-hidden": "true", text: "⚠" }),
      el("span", { class: "verdict__text", text: `Handshake aborted — ${status.message}` }),
    ]);
  }
  if (status.kind === "mismatch") {
    const detail = left.present && right.present && !matched
      ? "Keys differ — handshake aborted."
      : "Confirmation incomplete — handshake did not confirm.";
    return el("div", { class: "verdict verdict--alarm", role: "alert" }, [
      el("span", { class: "verdict__icon", "aria-hidden": "true", text: "⚠" }),
      el("span", { class: "verdict__text", text: detail }),
    ]);
  }
  // running / idle: neutral, but if run finished with divergence, force alarm.
  if (left.present && right.present && (!matched || !bothConfirmed) && status.kind !== "running") {
    return el("div", { class: "verdict verdict--alarm", role: "alert" }, [
      el("span", { class: "verdict__icon", "aria-hidden": "true", text: "⚠" }),
      el("span", { class: "verdict__text", text: "Keys differ — handshake aborted." }),
    ]);
  }
  return el("div", { class: "verdict verdict--pending", role: "status" }, [
    el("span", { class: "verdict__icon", "aria-hidden": "true", text: "…" }),
    el("span", { class: "verdict__text", text: status.kind === "idle" ? "Awaiting handshake." : "Handshake in progress…" }),
  ]);
}
