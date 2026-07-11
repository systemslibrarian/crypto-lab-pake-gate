// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from "vitest";
import { mountApp } from "../src/ui/tabs";

// A genuine render check: mount the real app into a jsdom #app and assert the surface
// renders with the four protocols, interactive controls, and ADA-relevant elements.
describe("UI renders (jsdom)", () => {
  let root: HTMLElement;
  beforeEach(() => {
    document.body.innerHTML = '<div id="app"></div>';
    root = document.getElementById("app")!;
    mountApp(root);
  });

  it("mounts a non-trivial surface into #app", () => {
    expect(root.innerHTML.length).toBeGreaterThan(500);
  });

  it("shows all four PAKE protocols", () => {
    const text = document.body.textContent ?? "";
    for (const kw of ["SRP", "J-PAKE", "CPace", "Dragonfly"]) {
      expect(text).toContain(kw);
    }
  });

  it("has keyboard-operable controls and labeled inputs (ADA)", () => {
    expect(document.querySelectorAll("button").length).toBeGreaterThan(0);
    const inputs = document.querySelectorAll("input, textarea");
    expect(inputs.length).toBeGreaterThan(0);
    // every input/textarea has an accessible name (a <label for> or aria-label)
    for (const input of Array.from(inputs)) {
      const id = input.getAttribute("id");
      const hasLabelEl = id ? document.querySelector(`label[for="${id}"]`) !== null : false;
      const hasAria =
        input.getAttribute("aria-label") !== null || input.getAttribute("aria-labelledby") !== null;
      const hasImplicitLabel = input.closest("label") !== null; // nested-in-label is valid ADA
      expect(hasLabelEl || hasAria || hasImplicitLabel).toBe(true);
    }
  });

  it("exposes ARIA roles/tabs for the tab surface", () => {
    const tabs = document.querySelectorAll('[role="tab"], [aria-selected]');
    expect(tabs.length).toBeGreaterThan(0);
  });
});
