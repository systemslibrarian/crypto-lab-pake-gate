import { describe, it, expect } from "vitest";
import { CPaceParty, calculateGenerator, computeISK } from "../src/pake/cpace";
import { fromHex, os2ipLE, toHex } from "../src/pake/encoding";
import { asPassword } from "../src/pake/types";
import { Wire } from "../src/pake/wire";
import official from "./vectors/cpace_official.json";

// PUBLISHED draft-irtf-cfrg-cpace-21 test vectors, ristretto255/SHA-512.
// Source: the CFRG CPace repo's machine-readable testvectors.json (downloaded intact
// via raw GitHub — NOT the summarizing web tool, which mangles long hex). The
// ristretto255 group is "G_Coffee25519" (ristretto ≈ a coffee shot — the authors'
// naming); "G_25519" is X25519 (Montgomery) and is a different suite. ISK_SY is the
// parallel / order-independent (symmetric) execution mode this lab pins.
// File SHA-256: e2a18e6f38d375c70902fb981005140388a0cad3247e1418eeacb2f6b2b94c37
// Source commit: cfrg/draft-irtf-cfrg-cpace @ 701eb533ab31e6927bdc6130aa6e6e8f3c1d2a61
// See tests/vectors/README.md.
const V = official.G_Coffee25519;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const lc = (s: string) => s.toLowerCase();

describe("CPace ristretto255/SHA-512 — PUBLISHED draft-21 vectors (G_Coffee25519)", () => {
  const prs = fromHex(V.PRS);
  const ci = fromHex(V.CI);
  const sid = fromHex(V.sid);
  const g = calculateGenerator(prs, ci, sid);
  const yaInt = os2ipLE(fromHex(V.ya)) % L;
  const ybInt = os2ipLE(fromHex(V.yb)) % L;

  it("generator g matches the published value", () => {
    expect(toHex(g.toBytes())).toBe(lc(V.g));
  });
  it("Ya = ya·g and Yb = yb·g match the published messages", () => {
    expect(toHex(g.multiply(yaInt).toBytes())).toBe(lc(V.Ya));
    expect(toHex(g.multiply(ybInt).toBytes())).toBe(lc(V.Yb));
  });
  it("shared K matches the published value", () => {
    const Yb = g.multiply(ybInt);
    expect(toHex(Yb.multiply(yaInt).toBytes())).toBe(lc(V.K));
  });
  it("ISK (parallel / symmetric mode) matches the published ISK_SY", () => {
    const Ya = g.multiply(yaInt);
    const Yb = g.multiply(ybInt);
    const K = Yb.multiply(yaInt);
    const isk = computeISK(sid, K, Ya.toBytes(), fromHex(V.ADa), Yb.toBytes(), fromHex(V.ADb));
    expect(toHex(isk)).toBe(lc(V.ISK_SY));
  });

  it("the stateful CPaceParty engine reproduces the published ISK_SY end-to-end", () => {
    // PRS "Password" = 50617373776f7264; the party derives the generator from it.
    const password = asPassword("Password");
    const A = new CPaceParty({ role: "A", password, ci, sid, ad: fromHex(V.ADa), scalar: fromHex(V.ya) });
    const B = new CPaceParty({ role: "B", password, ci, sid, ad: fromHex(V.ADb), scalar: fromHex(V.yb) });
    const wire = new Wire();
    const am = wire.send(A.message());
    const bm = wire.send(B.message());
    A.receive(bm);
    B.receive(am);
    expect(toHex(A.sessionKeyBytes!)).toBe(lc(V.ISK_SY));
    expect(toHex(B.sessionKeyBytes!)).toBe(lc(V.ISK_SY));
  });
});
