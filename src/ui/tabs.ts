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
    el("h1", { class: "intro__title", text: "PAKE Gate — watch the password stay home" }),
    el("p", { class: "intro__lead", text: "A PAKE (Password-Authenticated Key Exchange) lets two parties turn a shared, low-entropy password into a strong shared key — without the password, or anything an attacker could grind offline, ever crossing the network. The lesson: a PAKE is NOT “hash the password and send it.” This lab runs four of them for real in your browser, no backend." }),
    el("p", { class: "intro__how" }, [
      el("strong", { text: "How to use: " }),
      "pick a protocol tab, type a password, and click ",
      el("em", { text: "Honest run" }),
      " — both sides derive the same key and the badge turns green (“key confirmed”). Change one side's password (",
      el("em", { text: "Wrong password" }),
      ") and it fails red. ",
      el("em", { text: "Step ▸" }),
      " advances one message at a time so you can read each field as it crosses.",
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
  app.append(tablist, panelHost);

  const views = new Map<ProtocolId, TabView>();
  const buttons = new Map<ProtocolId, HTMLButtonElement>();

  const select = (id: ProtocolId): void => {
    for (const [pid, btn] of buttons) {
      const on = pid === id;
      btn.classList.toggle("is-active", on);
      btn.setAttribute("aria-selected", String(on));
      btn.tabIndex = on ? 0 : -1;
    }
    let view = views.get(id);
    if (!view) {
      view = new TabView(id);
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
        const next = TABS[(i + dir + TABS.length) % TABS.length]!;
        buttons.get(next.id)?.focus();
        select(next.id);
      }
    });
    buttons.set(t.id, btn);
    tablist.append(btn);
  });

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
