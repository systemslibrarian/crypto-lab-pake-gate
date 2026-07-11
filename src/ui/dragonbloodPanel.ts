// Dragonblood side-channel comparison (Dragonfly tab only). compareModels over ~6
// built-in candidate passwords; plot modeled iteration count per password for
// legacy-early-exit (varies — the leak) vs fixed-work (flat). Mitigation is labeled
// "fixed-work teaching variant", NEVER "constant-time".

import { compareModels } from "../pake/dragonblood.ts";
import { makePassword } from "../pake/factories.ts";
import { el } from "./dom.ts";

const CANDIDATES = ["password", "hunter2", "correct-horse", "letmein", "s3cr3t!", "wpa3-demo"];

export function renderDragonbloodPanel(idA: string, idB: string): HTMLElement {
  const section = el("section", { class: "dblood", "aria-labelledby": "dblood-h" }, [
    el("h2", { id: "dblood-h", class: "dblood__title", text: "Dragonblood side-channel (Dragonfly only)" }),
    el("p", { class: "dblood__lead", text: "Vanhoef & Ronen (2019): the hunting-and-pecking password mapping leaks a password-dependent iteration count. Below, the modeled iteration count per candidate — legacy early-exit varies (the leak); the fixed-work teaching variant is flat." }),
  ]);

  const cmp = compareModels(idA, idB, CANDIDATES.map((c) => makePassword(c)), 40);
  const legacy = cmp.runs.filter((r) => r.model === "legacy-early-exit");
  const fixed = cmp.runs.filter((r) => r.model === "fixed-work");

  const maxIter = Math.max(cmp.fixedWorkCap, ...legacy.map((r) => (Number.isFinite(r.modeledIterations) ? r.modeledIterations : 0))) || 1;

  const scroll = el("div", { class: "dblood__scroll", tabindex: "0", role: "region", "aria-label": "iteration-count plot (scrollable)" });
  const plot = el("div", { class: "plot" });
  for (let i = 0; i < CANDIDATES.length; i++) {
    const pw = CANDIDATES[i]!;
    const l = legacy[i]!;
    const f = fixed[i]!;
    const lIter = Number.isFinite(l.modeledIterations) ? l.modeledIterations : 0;
    plot.append(
      el("div", { class: "plot__group" }, [
        el("div", { class: "plot__bars" }, [
          bar("legacy", lIter, maxIter, "bar--legacy", `legacy early-exit: ${Number.isFinite(l.modeledIterations) ? lIter : "not found"} iterations`),
          bar("fixed", f.modeledIterations, maxIter, "bar--fixed", `fixed-work teaching variant: ${f.modeledIterations} iterations`),
        ]),
        el("div", { class: "plot__label", text: pw }),
      ]),
    );
  }
  scroll.append(plot);
  section.append(scroll);

  section.append(
    el("div", { class: "dblood__legend" }, [
      el("span", { class: "swatch swatch--legacy" }),
      el("span", { text: "legacy early-exit (leaks — iteration count depends on the password)" }),
      el("span", { class: "swatch swatch--fixed" }),
      el("span", { text: "fixed-work teaching variant (flat — no per-password variation)" }),
    ]),
  );

  section.append(
    el("ul", { class: "dblood__notes" }, [
      el("li", { text: `Legacy model leaks across these candidates: ${cmp.legacyLeaks ? "yes — iteration count varies" : "no variation in this sample"}.` }),
      el("li", { text: `Fixed-work model flat across these candidates: ${cmp.fixedWorkFlat ? "yes — constant work" : "no"}.` }),
      el("li", { text: "Modeled iteration count is the signal; raw browser timing is noisy and not the oracle." }),
      el("li", { text: "Neither model produces the honest-run keys — this panel is strictly the side-channel comparison." }),
    ]),
  );

  return section;
}

function bar(label: string, value: number, max: number, cls: string, title: string): HTMLElement {
  const pct = Math.max(4, Math.round((value / max) * 100));
  return el("div", { class: "bar " + cls, title, style: `height:${pct}%`, role: "img", "aria-label": title }, [
    el("span", { class: "bar__val", text: String(value || "—") }),
    el("span", { class: "bar__tag", text: label }),
  ]);
}
