// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import axe from "axe-core";
import { mountApp } from "../src/ui/tabs";

// Automated WCAG audit (axe-core) of the mounted app. Runs in jsdom, so layout-only
// rules (color-contrast) are disabled — those are verified by design in styles.css
// (icon+text+color, never color alone). Structural rules (labels, roles, names, aria)
// DO run and must be clean of serious/critical violations.
describe("axe-core WCAG audit", () => {
  it("has no serious or critical accessibility violations", async () => {
    document.body.innerHTML = '<main id="app"></main>';
    mountApp(document.getElementById("app")!);

    const results = await axe.run(document.body, {
      rules: {
        "color-contrast": { enabled: false }, // needs real layout; verified in CSS
        region: { enabled: false }, // standardization pass adds the page landmarks
      },
    });

    const serious = results.violations.filter(
      (v) => v.impact === "serious" || v.impact === "critical",
    );
    if (serious.length > 0) {
      // Surface actionable detail if this ever fails.
      console.error(
        serious.map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s) — ${v.help}`).join("\n"),
      );
    }
    expect(serious).toEqual([]);
  });
});
