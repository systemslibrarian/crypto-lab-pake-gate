import { describe, it, expect } from "vitest";
import { CPaceParty, calculateGenerator, type CPaceConfig } from "../src/pake/cpace";
import { prependLen, lvCat, oCat, utf8Nfc, fromHex } from "../src/pake/encoding";
import { asPassword } from "../src/pake/types";
import { Wire } from "../src/pake/wire";
import { sha256 } from "@noble/hashes/sha2";

// NOTE ON VALIDATION: the CPace core follows draft-irtf-cfrg-cpace-21 (ristretto255/
// SHA-512, parallel mode) and is validated byte-for-byte against the PUBLISHED draft
// vectors in tests/cpace.vectors.test.ts. This file adds round-trip agreement,
// context-binding, and the pinned encoding primitives.

const ci = fromHex("0b415f696e69746961746f720b425f726573706f6e646572");
const sid = fromHex("7e4b4791d6a8ef019b936c79fb7f2c57");

function scalar(label: string): Uint8Array {
  return sha256(utf8Nfc(label)).slice(0, 32);
}
function party(role: "A" | "B", pw: string, adLabel: string, sLabel: string): CPaceConfig {
  return { role, password: asPassword(pw), ci, sid, ad: utf8Nfc(adLabel), scalar: scalar(sLabel) };
}

function run(pwA: string, pwB: string) {
  const wire = new Wire();
  const A = new CPaceParty(party("A", pwA, "ADa", "scalar-a"));
  const B = new CPaceParty(party("B", pwB, "ADb", "scalar-b"));
  const aMsg = wire.send(A.message());
  const bMsg = wire.send(B.message());
  A.receive(bMsg);
  B.receive(aMsg);
  const aTag = wire.send(A.confirm());
  const bTag = wire.send(B.confirm());
  return { A, B, wire, aTag, bTag };
}

describe("CPace encoding primitives (draft-21 §4) — pinned", () => {
  it("prepend_len uses a single length byte for short data", () => {
    expect(Buffer.from(prependLen(fromHex("aabbcc"))).toString("hex")).toBe("03aabbcc");
    expect(Buffer.from(prependLen(new Uint8Array(0))).toString("hex")).toBe("00");
  });
  it("lv_cat concatenates length-prefixed args", () => {
    expect(Buffer.from(lvCat(fromHex("aa"), fromHex("bbbb"))).toString("hex")).toBe("01aa02bbbb");
  });
  it("o_cat is order-independent (larger blob first, 'oc' prefix)", () => {
    const x = fromHex("01");
    const y = fromHex("02");
    expect(Buffer.from(oCat(x, y)).toString("hex")).toBe(Buffer.from(oCat(y, x)).toString("hex"));
    expect(Buffer.from(oCat(x, y)).toString("hex")).toBe("6f630201"); // "oc" || 02 || 01
  });
});

describe("CPace ristretto255/SHA-512 — round-trip", () => {
  it("generator derivation is deterministic for fixed inputs", () => {
    const g1 = calculateGenerator(utf8Nfc("pw"), ci, sid);
    const g2 = calculateGenerator(utf8Nfc("pw"), ci, sid);
    expect(g1.equals(g2)).toBe(true);
  });

  it("honest run: both parties derive identical ISK and confirm", () => {
    const { A, B, aTag, bTag } = run("open sesame", "open sesame");
    A.recvConfirm(bTag);
    B.recvConfirm(aTag);
    expect(A.phase).toBe("confirmed");
    expect(B.phase).toBe("confirmed");
    expect(Buffer.from(A.sessionKeyBytes!).toString("hex")).toBe(
      Buffer.from(B.sessionKeyBytes!).toString("hex"),
    );
  });

  it("wrong password: ISKs differ and confirmation fails", () => {
    const { A, B, aTag, bTag } = run("open sesame", "not sesame");
    expect(Buffer.from(A.sessionKeyBytes!).toString("hex")).not.toBe(
      Buffer.from(B.sessionKeyBytes!).toString("hex"),
    );
    expect(() => A.recvConfirm(bTag)).toThrow();
    expect(() => B.recvConfirm(aTag)).toThrow();
  });

  it("mismatched sid ⇒ different keys (context binding)", () => {
    const A = new CPaceParty(party("A", "pw", "ADa", "sa"));
    const Bcfg = party("B", "pw", "ADb", "sb");
    const B = new CPaceParty({ ...Bcfg, sid: fromHex("00000000000000000000000000000000") });
    const wire = new Wire();
    const aMsg = wire.send(A.message());
    const bMsg = wire.send(B.message());
    A.receive(bMsg);
    B.receive(aMsg);
    expect(Buffer.from(A.sessionKeyBytes!).toString("hex")).not.toBe(
      Buffer.from(B.sessionKeyBytes!).toString("hex"),
    );
  });
});
