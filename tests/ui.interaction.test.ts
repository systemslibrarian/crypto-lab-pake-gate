import { describe, it, expect } from "vitest";
import { SrpRunner } from "../src/ui/runners/srpRunner";
import { JPakeRunner } from "../src/ui/runners/jpakeRunner";
import { CPaceRunner } from "../src/ui/runners/cpaceRunner";
import { DragonflyRunner } from "../src/ui/runners/dragonflyRunner";
import { srpRegister, makePassword } from "../src/pake/factories";
import type { Runner } from "../src/ui/model";
import { bytesEqual } from "../src/ui/model";

// Drives the actual UI Runners (the exact objects the launchers/step button use) to
// their terminal states — the truest "does the UI work" check short of a browser.

function runToEnd(r: Runner): Runner {
  let guard = 0;
  while (r.hasNext() && guard++ < 50) r.step();
  return r;
}

function balancedRunners(pwA: string, pwB: string): Record<string, Runner> {
  return {
    "J-PAKE": new JPakeRunner("Alice", "Bob", makePassword(pwA), makePassword(pwB)),
    CPace: new CPaceRunner("Alice", "Bob", makePassword(pwA), makePassword(pwB)),
    Dragonfly: new DragonflyRunner("Alice", "Bob", makePassword(pwA), makePassword(pwB)),
  };
}

describe("UI runners — honest run reaches a confirmed, matching key", () => {
  it("SRP: honest run → confirmed, keys match", () => {
    const rec = srpRegister("arthur", makePassword("open sesame"));
    const r = runToEnd(new SrpRunner("arthur", makePassword("open sesame"), rec));
    expect(r.status().kind).toBe("confirmed");
    expect(r.leftKey().confirmed && r.rightKey().confirmed).toBe(true);
    expect(bytesEqual(r.leftKey().keyBytes, r.rightKey().keyBytes)).toBe(true);
  });

  for (const [name, r] of Object.entries(balancedRunners("open sesame", "open sesame"))) {
    it(`${name}: honest run → confirmed, keys match`, () => {
      runToEnd(r);
      expect(r.status().kind).toBe("confirmed");
      expect(bytesEqual(r.leftKey().keyBytes, r.rightKey().keyBytes)).toBe(true);
    });
  }
});

describe("UI runners — wrong password is a FAILURE (alarm), never confirmed", () => {
  it("SRP: wrong password → not confirmed", () => {
    const rec = srpRegister("arthur", makePassword("open sesame"));
    const r = runToEnd(new SrpRunner("arthur", makePassword("WRONG"), rec));
    expect(r.status().kind).not.toBe("confirmed");
  });

  for (const [name, r] of Object.entries(balancedRunners("open sesame", "different"))) {
    it(`${name}: wrong password → not confirmed (mismatch or abort)`, () => {
      runToEnd(r);
      expect(r.status().kind).not.toBe("confirmed");
      expect(["mismatch", "aborted"]).toContain(r.status().kind);
    });
  }
});

describe("UI runners — curated tamper aborts fail-closed before any key", () => {
  it("J-PAKE: arming a Round-1 tamper op aborts, marks a card, and yields no confirmed key", () => {
    const r = new JPakeRunner("Alice", "Bob", makePassword("thread"), makePassword("thread"));
    const menu = r.tamperMenu();
    expect(menu.length).toBeGreaterThan(0);
    r.setTamper(menu[0]!); // e.g. "corrupt a Round-1 element/proof"
    const cards: (ReturnType<Runner["step"]>)[] = [];
    let guard = 0;
    while (r.hasNext() && guard++ < 50) cards.push(r.step());
    expect(r.status().kind).toBe("aborted");
    // no side reports a confirmed key
    expect(r.leftKey().confirmed).toBe(false);
    expect(r.rightKey().confirmed).toBe(false);
    // some card was flagged aborted with a tooltip
    const aborted = cards.map((c) => c.card).find((c) => c?.aborted);
    expect(aborted?.aborted?.tooltip).toBeTruthy();
  });
});
