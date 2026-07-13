// The four-tab surface (SRP-6a · J-PAKE · CPace · Dragonfly). Tabs become a
// scrollable/segmented control below 640px. Each tab lazily builds its TabView once.

import { el } from "./dom.ts";
import type { ProtocolId } from "./model.ts";
import { TabView } from "./tabView.ts";
import { renderTaxonomyPanel } from "./taxonomyPanel.ts";

interface TabDef {
  readonly id: ProtocolId;
  readonly label: string;
}

const TABS: TabDef[] = [
  { id: "srp6a", label: "SRP-6a" },
  { id: "jpake", label: "J-PAKE" },
  { id: "cpace", label: "CPace" },
  { id: "dragonfly", label: "Dragonfly" },
];

export function mountApp(root: HTMLElement): void {
  const app = el("div", { class: "app" });

  const intro = el("section", { class: "intro" }, [
    el("header", { class: "cl-hero" }, [
      el("div", { class: "cl-hero-main" }, [
        el("h1", { class: "cl-hero-title", text: "PAKE Gate" }),
        el("p", { class: "cl-hero-sub", text: "PAKE · SRP-6a · J-PAKE · CPace · Dragonfly" }),
        el("p", {
          class: "cl-hero-desc",
          text: "Run four password-authenticated key exchanges for real in your browser and watch each side derive the same session key while the password — and anything grindable offline — never crosses the wire.",
        }),
      ]),
      el("aside", { class: "cl-hero-why", "aria-label": "Why it matters" }, [
        el("span", { class: "cl-hero-why-label", text: "WHY IT MATTERS" }),
        el("p", {
          class: "cl-hero-why-text",
          text: "A PAKE is NOT “hash the password and send it.” It defends the weakest secret people actually use — passwords — against eavesdroppers and server breaches, so a stolen record and a captured transcript still can't be grinded back to the login.",
        }),
      ]),
    ]),
    el("p", { class: "intro__how" }, [
      el("strong", { text: "Start here: " }),
      "the lab opens on ",
      el("em", { text: "SRP-6a" }),
      " in a plain-language view. Type a password and click ",
      el("em", { text: "Honest run" }),
      " — both sides derive the same key and the badge turns green (“key confirmed”). Change one side's password (",
      el("em", { text: "Wrong password" }),
      ") and it fails red. When it clicks, press ",
      el("em", { text: "Go deeper" }),
      " to reveal the full notation, the tamper / observer / breach panels, and the other three protocols. ",
      el("em", { text: "Step ▸" }),
      " advances one message at a time so you can watch each value lift onto the Wire while the secrets stay home.",
    ]),
    el("ul", { class: "legend", "aria-label": "how to read the split view" }, [
      el("li", { class: "legend__item" }, [el("b", { text: "Left & Right — " }), "each peer's private scratchpad: secrets that never touch the wire."]),
      el("li", { class: "legend__item" }, [el("b", { text: "Center — the Wire: " }), "every field that actually crosses the network (the transcript an eavesdropper sees)."]),
      el("li", { class: "legend__item" }, [el("b", { text: "Below — the key: " }), "each side's derived session key, shown as a short fingerprint; it lights green only when both match and confirm."]),
    ]),
  ]);
  app.append(intro);

  const tablist = el("div", { class: "tabs", role: "tablist", "aria-label": "PAKE protocols" });
  const panelHost = el("div", { class: "tabs__panels" });
  // Guided default: only the first protocol (SRP-6a) is available. The other three
  // stay gated behind a "Go deeper" reveal so a newcomer meets one handshake, not
  // four dense peer tabs at once. Clicking "Go deeper" inside SRP unlocks them.
  const gateNote = el("p", { class: "tabs__gate", role: "note" }, [
    "Starting with ",
    el("strong", { text: "SRP-6a" }),
    ". The other three protocols unlock when you press ",
    el("em", { text: "Go deeper" }),
    " below.",
  ]);
  app.append(tablist, gateNote, panelHost);

  const views = new Map<ProtocolId, TabView>();
  const buttons = new Map<ProtocolId, HTMLButtonElement>();
  let unlocked = false;

  const GATED: ProtocolId[] = ["jpake", "cpace", "dragonfly"];

  const applyGate = (): void => {
    for (const id of GATED) {
      const btn = buttons.get(id);
      if (!btn) continue;
      btn.disabled = !unlocked;
      btn.setAttribute("aria-disabled", String(!unlocked));
      btn.title = unlocked ? "" : "Press “Go deeper” in the SRP-6a tab to unlock the other protocols";
    }
    gateNote.hidden = unlocked;
  };

  const unlock = (): void => {
    if (unlocked) return;
    unlocked = true;
    applyGate();
  };

  const select = (id: ProtocolId): void => {
    if (!unlocked && GATED.includes(id)) return; // gated: ignore
    for (const [pid, btn] of buttons) {
      const on = pid === id;
      btn.classList.toggle("is-active", on);
      btn.setAttribute("aria-selected", String(on));
      btn.tabIndex = on ? 0 : -1;
    }
    let view = views.get(id);
    if (!view) {
      // A gated protocol can only ever be reached after unlock, so it opens directly
      // in deep mode; SRP opens in the guided simple view.
      view = new TabView(id, { startDeep: unlocked && id !== "srp6a" });
      view.onGoDeeper = unlock;
      views.set(id, view);
    }
    panelHost.replaceChildren(view.root);
  };

  TABS.forEach((t, i) => {
    const btn = el("button", {
      type: "button",
      class: "tab",
      role: "tab",
      id: `tab-${t.id}`,
      "aria-selected": "false",
      tabindex: "-1",
    }, [t.label]) as HTMLButtonElement;
    btn.addEventListener("click", () => select(t.id));
    btn.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const dir = e.key === "ArrowRight" ? 1 : -1;
        // Skip gated tabs while locked.
        let step = 1;
        let next = TABS[(i + dir + TABS.length) % TABS.length]!;
        while (!unlocked && GATED.includes(next.id) && step < TABS.length) {
          step++;
          next = TABS[(i + dir * step + TABS.length * step) % TABS.length]!;
        }
        buttons.get(next.id)?.focus();
        select(next.id);
      }
    });
    buttons.set(t.id, btn);
    tablist.append(btn);
  });

  applyGate();

  app.append(renderTaxonomyPanel());

  app.append(
    el("section", { class: "seam" }, [
      el("h2", { class: "seam__title", text: "The post-quantum seam" }),
      el("p", { class: "seam__text", text: "A KEM has no group structure to run a Diffie–Hellman over, so real PQ-PAKEs (CAKE/OCAKE, Noise-KEM-PAKE) encrypt or blind the KEM public key under a password-derived symmetric key (EKE-style) rather than doing PAKE inside the KEM's group. The extension seam therefore consumes KemBackend + PasswordKeyedEncoding, never a Group. See docs/pq-pake-seam.md." }),
    ]),
  );

  root.replaceChildren(app);
  select("srp6a");
}
