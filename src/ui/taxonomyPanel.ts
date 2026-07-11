// The PAKE family property matrix, rendered from TAXONOMY. Horizontally scrollable on
// mobile. The OPAQUE row carries its deepLink as a visible "Take the next step →" link.

import { TAXONOMY, type TaxonomyRow } from "../pake/taxonomy.ts";
import { el } from "./dom.ts";

export function renderTaxonomyPanel(): HTMLElement {
  const section = el("section", { class: "taxonomy", "aria-labelledby": "tax-h" }, [
    el("h2", { id: "tax-h", class: "taxonomy__title", text: "PAKE family property matrix" }),
    el("p", { class: "taxonomy__lead", text: "Balanced vs augmented is the crux: what, if anything, the server stores." }),
  ]);

  const scroll = el("div", { class: "taxonomy__scroll", tabindex: "0", role: "region", "aria-label": "property matrix (scrollable)" });
  const table = el("table", { class: "matrix" });

  const cols: { key: string; label: string }[] = [
    { key: "name", label: "Protocol" },
    { key: "kind", label: "Kind" },
    { key: "serverStored", label: "Server stores" },
    { key: "rounds", label: "Rounds" },
    { key: "quantumResistant", label: "Quantum-resistant" },
    { key: "constructionFamily", label: "Construction" },
    { key: "standardization", label: "Standardization" },
    { key: "deployment", label: "Deployment" },
    { key: "reachFor", label: "Reach for it when…" },
  ];

  const thead = el("thead", {}, [
    el("tr", {}, cols.map((c) => el("th", { scope: "col", text: c.label }))),
  ]);
  const tbody = el("tbody");
  for (const row of TAXONOMY) {
    tbody.append(renderRow(row, cols));
  }
  table.append(thead, tbody);
  scroll.append(table);
  section.append(scroll);
  return section;
}

function renderRow(row: TaxonomyRow, cols: { key: string; label: string }[]): HTMLElement {
  const tr = el("tr", { class: row.reference ? "matrix__row--ref" : "" });
  for (const c of cols) {
    if (c.key === "name") {
      const cell = el("th", { scope: "row", class: "matrix__name" }, [
        el("span", { class: "matrix__proto", text: row.name }),
        row.deepLink
          ? el("a", { class: "matrix__deeplink", href: row.deepLink.href, target: "_blank", rel: "noopener" }, [row.deepLink.label])
          : undefined,
      ]);
      tr.append(cell);
      continue;
    }
    if (c.key === "quantumResistant") {
      const yes = row.quantumResistant;
      tr.append(
        el("td", {}, [
          el("span", { class: "pill " + (yes ? "pill--yes" : "pill--no") }, [yes ? "✓ yes" : "✗ no"]),
        ]),
      );
      continue;
    }
    if (c.key === "kind") {
      tr.append(el("td", {}, [el("span", { class: "pill pill--kind", text: row.kind })]));
      continue;
    }
    const val = (row as unknown as Record<string, string>)[c.key] ?? "";
    tr.append(el("td", { text: val }));
  }
  return tr;
}
