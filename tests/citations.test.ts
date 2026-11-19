import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

// Section citations in comments are claims too, and two of them were wrong:
//
//  · factories.ts cited "RFC 5054 §3" for the ≥ 256-bit ephemeral rule. §3 is
//    Security Considerations and gives no length. The 256-bit SHOULD is in
//    §2.5.3 (the server's private value b) and §2.5.4 (the client's a).
//  · the CPace lv_cat / prepend_len encoding was cited as draft-21 "§4"; it is
//    §6.3 of draft-irtf-cfrg-cpace-21.
//
// These pin the corrected sections and forbid the old ones in src/ and tests/.

const ROOT = join(__dirname, "..");
const read = (rel: string) => readFileSync(join(ROOT, rel), "utf8");
const filesIn = (dir: string) =>
  readdirSync(join(ROOT, dir), { recursive: true, encoding: "utf8" })
    .filter((f) => /\.(ts|mjs|md)$/.test(f))
    .map((f) => join(dir, f));

describe("section citations", () => {
  it("cites RFC 5054 §2.5.3 and §2.5.4 for the 256-bit ephemeral SHOULD, never §3", () => {
    const factories = read("src/pake/factories.ts");
    expect(factories).toMatch(/RFC 5054 §2\.5\.3 and §2\.5\.4/);
    for (const f of [...filesIn("src"), ...filesIn("tests")]) {
      if (f.endsWith("citations.test.ts")) continue;
      expect(read(f), f).not.toMatch(/RFC 5054 §3 asks/);
      expect(read(f), f).not.toMatch(/RFC 5054 §3\b(?!\.)[^,]*256/);
    }
  });

  it("cites draft-21 §6.3 for lv_cat / prepend_len, never §4", () => {
    expect(read("src/pake/encoding.ts")).toMatch(/draft-irtf-cfrg-cpace-21 §6\.3/);
    for (const f of [...filesIn("src"), ...filesIn("tests")]) {
      if (f.endsWith("citations.test.ts")) continue;
      expect(read(f), f).not.toMatch(/(cpace-21|draft-21),? §4\b/);
      expect(read(f), f).not.toMatch(/\(draft-21 §4\)/);
    }
  });
});
