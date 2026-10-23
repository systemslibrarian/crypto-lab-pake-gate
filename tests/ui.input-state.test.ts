// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";
import { TabView } from "../src/ui/tabView";

function typeInto(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector);
  expect(input).not.toBeNull();
  input!.value = value;
  input!.dispatchEvent(new Event("input", { bubbles: true }));
}

function runManualSteps(root: HTMLElement): void {
  for (let step = 0; step < 64; step++) {
    const button = Array.from(root.querySelectorAll<HTMLButtonElement>("button"))
      .find((candidate) => candidate.textContent === "Step ▸");
    expect(button).toBeDefined();
    if (button!.disabled) return;
    button!.click();
  }
  throw new Error("manual runner did not terminate within 64 steps");
}

describe("manual runner captures password edits made before the first step", () => {
  beforeEach(() => {
    document.body.replaceChildren();
  });

  it("uses the visible J-PAKE inputs instead of the constructor defaults", () => {
    const view = new TabView("jpake", { startDeep: true });
    document.body.append(view.root);

    typeInto(view.root, "#jpake-pw1", "correct horse");
    typeInto(view.root, "#jpake-pw2", "different battery");

    // There was no prior run to discard, so this edit should stay quiet.
    expect(view.root.querySelector(".status__expect--stale")).toBeNull();

    runManualSteps(view.root);

    // Different visible passwords must never execute the initial hunter2/hunter2
    // runner and produce a false green confirmation.
    expect(view.root.querySelector(".status__pill--ok")).toBeNull();
    expect(view.root.querySelector(".status__pill--alarm")).not.toBeNull();
  });
});
