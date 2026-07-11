import { describe, it, expect } from "vitest";
import { asPassword, type WireMsg } from "../src/pake/types";
import { toHex } from "../src/pake/encoding";

// Invariant #1, the compile-time barrier (THE real guarantee). This file is included
// in the tsconfig, so `tsc --noEmit` enforces the @ts-expect-error below: if a Password
// (or a bare string) WERE assignable to a Hex wire field, the directive would become an
// "unused @ts-expect-error" error and the typecheck would fail. esbuild/vitest strip
// types, so the runtime assertion here is trivial — tsc does the real work.

describe("Invariant #1 — WireMsg cannot be built containing a Password (compile-time)", () => {
  it("a Password is not assignable to a Hex wire field", () => {
    const pw = asPassword("super-secret");
    const bad: WireMsg = {
      protocol: "jpake",
      step: "leak-attempt",
      from: "A",
      // @ts-expect-error a Password (branded string) is not assignable to Hex
      fields: { leak: pw },
    };
    expect(bad).toBeDefined();
  });

  it("a bare string is not assignable either — only toHex() output is", () => {
    const good: WireMsg = {
      protocol: "jpake",
      step: "ok",
      from: "A",
      // @ts-expect-error a plain string literal is not Hex-branded
      fields: { g1: "not-hex-branded" },
    };
    expect(good).toBeDefined();
    // The sanctioned path: toHex() produces a Hex.
    const ok: WireMsg = { protocol: "jpake", step: "ok", from: "A", fields: { g1: toHex(new Uint8Array([1])) } };
    expect(ok.fields.g1).toBe("01");
  });
});
