import { describe, it, expect } from "vitest";
import {
  SRP_TRACK1_1024_SHA1,
  computeK,
  computeX,
  computeVerifier,
  clientA,
  serverB,
  computeU,
  clientS,
  serverS,
} from "../src/pake/srp6a";
import { asPassword } from "../src/pake/types";
import { fromHex } from "../src/pake/encoding";

// RFC 5054 Appendix B test vectors (Track 1 — validates the arithmetic core ONLY).
// Source: RFC 5054 Appendix B; group RFC 5054 Appendix A 1024-bit; hash SHA-1.
// See tests/vectors/README.md.
const V = {
  I: "alice",
  P: "password123",
  s: "beb25379d1a8581eb5a727673a2441ee",
  k: "7556aa045aef2cdd07abaf0f665c3e818913186f",
  x: "94b7555aabe9127cc58ccf4993db6cf84d16c124",
  // v = g^x mod N (256 hex = 128 bytes). Verified transitively: both client and
  // server premaster paths reproduce RFC 5054 App. B's published premaster secret,
  // which pins v = g^x. (The RFC prose rendering of v is 128 bytes; some transcribed
  // copies add a stray digit — this is the canonical mod-N value.)
  v:
    "7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f18" +
    "22223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48" +
    "cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e05" +
    "8ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb",
  a: "60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393",
  b: "e487cb59d31ac550471e81f00f6928e01dda08e974a004f49e61f5d105284d20",
  A:
    "61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e890" +
    "3211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e" +
    "42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261" +
    "eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b",
  B:
    "bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964" +
    "dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610" +
    "d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a" +
    "00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58",
  u: "ce38b9593487da98554ed47d70a7ae5f462ef019",
  premaster:
    "b0dc82babcf30674ae450c0287745e7990a3381f63b387aaf271a10d233861e3" +
    "59b48220f7c4693c9ae12b0a6f67809f0876e2d013800d6c41bb59b6d5979b5c" +
    "00a172b4a2a5903a0bdcaf8a709585eb2afafa8f3499b200210dcc1f10eb3394" +
    "3cd67fc88a2f39a4be5bec4ec0a3212dc346d7e474b29ede8a469ffeca686e5a",
};

const big = (h: string) => BigInt("0x" + h);

describe("SRP-6a Track 1: RFC 5054 Appendix B (1024-bit / SHA-1) — arithmetic core", () => {
  const p = SRP_TRACK1_1024_SHA1;
  const salt = fromHex(V.s);
  const a = big(V.a);
  const b = big(V.b);

  it("k = H(N | PAD(g))", () => {
    expect(computeK(p).toString(16)).toBe(V.k);
  });
  it("x = H(s | H(I:P))", () => {
    expect(computeX(p, V.I, asPassword(V.P), salt).toString(16)).toBe(V.x);
  });
  it("v = g^x mod N", () => {
    const x = computeX(p, V.I, asPassword(V.P), salt);
    expect(computeVerifier(p, x).toString(16)).toBe(V.v);
  });
  it("A = g^a mod N", () => {
    expect(clientA(p, a).toString(16)).toBe(V.A);
  });
  it("B = (k*v + g^b) mod N", () => {
    const x = computeX(p, V.I, asPassword(V.P), salt);
    const v = computeVerifier(p, x);
    expect(serverB(p, computeK(p), v, b).toString(16)).toBe(V.B);
  });
  it("u = H(PAD(A) | PAD(B))", () => {
    expect(computeU(p, big(V.A), big(V.B)).toString(16)).toBe(V.u);
  });
  it("client and server premaster S both equal the published value", () => {
    const x = computeX(p, V.I, asPassword(V.P), salt);
    const v = computeVerifier(p, x);
    const k = computeK(p);
    const u = computeU(p, big(V.A), big(V.B));
    const cS = clientS(p, big(V.A), big(V.B), a, x, k, u);
    const sS = serverS(p, big(V.A), v, u, b);
    expect(cS.toString(16)).toBe(V.premaster);
    expect(sS.toString(16)).toBe(V.premaster);
    expect(cS).toBe(sS);
  });
});
