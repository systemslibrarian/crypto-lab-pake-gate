// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import {
  MAX_EXTRA_CANDIDATES,
  parseExtraGuesses,
  renderObserverPanel,
} from "../src/ui/attacker";
import { makePassword } from "../src/pake/factories";
import { toHex } from "../src/pake/encoding";
import type { WireMsg } from "../src/pake/types";

function msg(fields: Record<string, string>): WireMsg {
  return { protocol: "srp6a", step: "client-hello", from: "client", fields } as WireMsg;
}

const hexOf = (s: string) => toHex(new TextEncoder().encode(s));

describe("parseExtraGuesses — dedupe and cap", () => {
  it("drops empties, duplicates, and words already in the built-in wordlist", () => {
    const { extras, dropped } = parseExtraGuesses("  foo, foo bar\nhunter2,  ,bar ");
    expect(extras).toEqual(["foo", "bar"]);
    expect(dropped).toBe(0);
  });

  it("caps the extras per run and reports how many were dropped", () => {
    const raw = Array.from({ length: MAX_EXTRA_CANDIDATES + 6 }, (_, i) => `cand-${i}`).join(" ");
    const { extras, dropped } = parseExtraGuesses(raw);
    expect(extras.length).toBe(MAX_EXTRA_CANDIDATES);
    expect(dropped).toBe(6);
  });
});

describe("observer audit — scans every credential in play and says so", () => {
  const targets = [
    { label: "the registered password", password: makePassword("good") },
    { label: "the client-entered password", password: makePassword("good-WRONG") },
  ];

  it("names both scanned credentials in the clean verdict", () => {
    const panel = renderObserverPanel("srp6a", [msg({ A: "00aabb" })], targets);
    const audit = panel.querySelector(".attacker__audit")!;
    expect(audit.className).toContain("ok");
    expect(audit.textContent).toContain("Transcript audit: clean");
    expect(audit.textContent).toContain("the registered password");
    expect(audit.textContent).toContain("the client-entered password");
  });

  it("catches a leak of the REGISTERED password, which scanning only the attempted one would miss", () => {
    // The field carries utf8-hex of "good". "good-WRONG" is a longer needle and
    // cannot match it — so a single-password audit of the client-entered value
    // (the pre-fix behavior) reported this transcript clean.
    const leaky = [msg({ A: hexOf("good") })];
    const panel = renderObserverPanel("srp6a", leaky, targets);
    const audit = panel.querySelector(".attacker__audit")!;
    expect(audit.className).toContain("bad");
    expect(audit.textContent).toContain("Transcript audit: HIT");
  });

  it("notes when the scanned credentials are identical", () => {
    const same = [
      { label: "Peer A's password", password: makePassword("hunter2") },
      { label: "Peer B's password", password: makePassword("hunter2") },
    ];
    const panel = renderObserverPanel("jpake", [msg({ gx1: "00aabb" })], same);
    expect(panel.querySelector(".attacker__audit")!.textContent).toContain("identical in this run");
  });
});
