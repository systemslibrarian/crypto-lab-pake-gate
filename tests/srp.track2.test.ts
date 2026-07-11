import { describe, it, expect } from "vitest";
import {
  SRP_TRACK2_4096_SHA256,
  clientA,
  clientS,
  computeK,
  computeM1,
  computeM2,
  computeU,
  computeVerifier,
  computeX,
  register,
  sessionKey,
  serverB,
  serverS,
  SrpClientSession,
  SrpServerSession,
} from "../src/pake/srp6a";
import { asPassword } from "../src/pake/types";
import { fromHex, toHex } from "../src/pake/encoding";
import { Wire } from "../src/pake/wire";
import kat from "./vectors/srp_track2.kat.json";

// Track 2 — the runnable standalone SRP-6a profile (4096-bit / SHA-256). Validated
// against an INDEPENDENT from-scratch Python (hashlib) KAT generator (see
// tests/vectors/gen/srp_track2_kat.py and tests/vectors/README.md). K/M1/M2 are the
// declared standalone profile's, NOT attributable to RFC 5054.
const p = SRP_TRACK2_4096_SHA256;
const F = kat.fixture;
const salt = fromHex(F.salt);
const a = BigInt("0x" + F.a);
const b = BigInt("0x" + F.b);
const pw = asPassword(F.p);

describe("SRP-6a Track 2 (4096-bit / SHA-256) — independent Python KAT cross-check", () => {
  const x = computeX(p, F.I, pw, salt);
  const v = computeVerifier(p, x);
  const A = clientA(p, a);
  const k = computeK(p);
  const B = serverB(p, k, v, b);
  const u = computeU(p, A, B);

  it("x, v, A, B, u match the KAT", () => {
    expect(x.toString(16)).toBe(kat.x);
    expect(v.toString(16)).toBe(kat.v);
    expect(A.toString(16)).toBe(kat.A);
    expect(B.toString(16)).toBe(kat.B);
    expect(u.toString(16)).toBe(kat.u);
  });

  it("client S == server S == KAT premaster", () => {
    const Sc = clientS(p, A, B, a, x, k, u);
    const Ss = serverS(p, A, v, u, b);
    expect(Sc.toString(16)).toBe(kat.S_client);
    expect(Ss.toString(16)).toBe(kat.S_server);
    expect(Sc).toBe(Ss);
  });

  it("K, M1, M2 match the KAT byte-for-byte", () => {
    const S = clientS(p, A, B, a, x, k, u);
    const K = sessionKey(p, S);
    const M1 = computeM1(p, F.I, salt, A, B, K);
    const M2 = computeM2(p, A, M1, K);
    expect(toHex(K)).toBe(kat.K);
    expect(toHex(M1)).toBe(kat.M1);
    expect(toHex(M2)).toBe(kat.M2);
  });

  it("stateful client/server sessions run to a confirmed shared key (Track 2)", () => {
    const record = register(p, F.I, pw, salt);
    // invariant #3: the record has salt + v, no password field.
    expect(Object.keys(record).sort()).toEqual(["I", "salt", "v"]);
    const client = new SrpClientSession(p, F.I, pw, a);
    const server = new SrpServerSession(p, record, b);
    const wire = new Wire();
    const hello = wire.send(client.hello());
    const sHello = wire.send(server.hello(hello));
    const cProof = wire.send(client.proof(sHello));
    const sProof = wire.send(server.proof(cProof));
    client.confirm(sProof);
    expect(client.phase).toBe("confirmed");
    expect(server.phase).toBe("confirmed");
    expect(toHex(client.sessionKeyBytes!)).toBe(toHex(server.sessionKeyBytes!));
    expect(toHex(client.sessionKeyBytes!)).toBe(kat.K);
  });
});
