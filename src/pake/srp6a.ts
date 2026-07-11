// SRP-6a (augmented PAKE), RFC 5054 arithmetic. Two profiles:
//
//  · Track 1 — RFC 5054 Appendix A 1024-bit / SHA-1. Validates the modular-exponent
//    core against Appendix B's published k/x/v/A/B/u/premaster. Used for nothing else.
//  · Track 2 — the runnable demo: RFC 5054 4096-bit / SHA-256, K = SHA-256(PAD(S))
//    (simple-hash SRP-6a convention, explicitly NOT RFC 2945 SHA_Interleave), with
//    the exact M1/M2 evidence messages below. These K/M1/M2 are a declared standalone
//    teaching profile — NOT attributable to RFC 5054, which does not publish them.
//
// The server never stores the password: the registration record is {salt, v} only.

import { SHA1, SHA256 } from "./hashes";
import {
  fromHex,
  i2osp,
  os2ip,
  padTo,
  toHex,
  utf8Nfc,
} from "./encoding";
import { decodeSrpPublicValue, modMul, modPow, padHex } from "./groups";
import {
  HandshakeAbort,
  PhaseError,
  asPassword,
  type Hex,
  type Password,
  type SrpPhase,
  type WireMsg,
} from "./types";
import {
  SRP_GROUP_1024_SHA1,
  SRP_GROUP_4096_SHA256,
  type SrpGroupParameters,
} from "./params";

type HashFn = (...m: Uint8Array[]) => Uint8Array;

export interface SrpProfile {
  readonly id: string;
  readonly group: SrpGroupParameters;
  readonly H: HashFn;
}

export const SRP_TRACK1_1024_SHA1: SrpProfile = {
  id: "srp6a/rfc5054-1024-sha1",
  group: SRP_GROUP_1024_SHA1,
  H: SHA1,
};

export const SRP_TRACK2_4096_SHA256: SrpProfile = {
  id: "srp6a/pake-gate-4096-sha256",
  group: SRP_GROUP_4096_SHA256,
  H: SHA256,
};

const PAD = (n: bigint, p: SrpProfile) => padTo(i2osp(n, p.group.nLen), p.group.nLen);

// --- functional core (KAT-friendly; a/b injected) ---

/** k = H(PAD(N) | PAD(g)). */
export function computeK(p: SrpProfile): bigint {
  return os2ip(p.H(PAD(p.group.N, p), PAD(p.group.g, p)));
}

/** x = H(salt | H(I | ":" | P)). */
export function computeX(p: SrpProfile, I: string, password: Password, salt: Uint8Array): bigint {
  const inner = p.H(utf8Nfc(I), utf8Nfc(":"), utf8Nfc(password));
  return os2ip(p.H(salt, inner));
}

/** v = g^x mod N. */
export function computeVerifier(p: SrpProfile, x: bigint): bigint {
  return modPow(p.group.g, x, p.group.N);
}

/** A = g^a mod N. */
export function clientA(p: SrpProfile, a: bigint): bigint {
  return modPow(p.group.g, a, p.group.N);
}

/** B = (k*v + g^b) mod N. */
export function serverB(p: SrpProfile, k: bigint, v: bigint, b: bigint): bigint {
  const { g, N } = p.group;
  return (modMul(k, v, N) + modPow(g, b, N)) % N;
}

/** u = H(PAD(A) | PAD(B)). */
export function computeU(p: SrpProfile, A: bigint, B: bigint): bigint {
  return os2ip(p.H(PAD(A, p), PAD(B, p)));
}

/** u must be nonzero, else the verifier drops out of S (classic SRP abort). */
export function requireValidU(u: bigint): void {
  if (u === 0n) {
    throw new HandshakeAbort("SRP u == 0", "u = H(A,B) must be nonzero, else the verifier drops out of S.");
  }
}

/** client premaster S = (B - k*g^x)^(a + u*x) mod N. */
export function clientS(
  p: SrpProfile,
  A: bigint,
  B: bigint,
  a: bigint,
  x: bigint,
  k: bigint,
  u: bigint,
): bigint {
  void A;
  const { g, N } = p.group;
  const base = ((B - modMul(k, modPow(g, x, N), N)) % N + N) % N;
  return modPow(base, a + u * x, N);
}

/** server premaster S = (A * v^u)^b mod N. */
export function serverS(p: SrpProfile, A: bigint, v: bigint, u: bigint, b: bigint): bigint {
  const { N } = p.group;
  return modPow(modMul(A, modPow(v, u, N), N), b, N);
}

/** K = H(PAD(S)). */
export function sessionKey(p: SrpProfile, S: bigint): Uint8Array {
  return p.H(PAD(S, p));
}

/** M1 = H( (H(PAD(N)) XOR H(PAD(g))) | H(I) | s | PAD(A) | PAD(B) | K ). */
export function computeM1(
  p: SrpProfile,
  I: string,
  salt: Uint8Array,
  A: bigint,
  B: bigint,
  K: Uint8Array,
): Uint8Array {
  const hN = p.H(PAD(p.group.N, p));
  const hg = p.H(PAD(p.group.g, p));
  const xorNg = new Uint8Array(hN.length);
  for (let i = 0; i < hN.length; i++) xorNg[i] = hN[i]! ^ hg[i]!;
  return p.H(xorNg, p.H(utf8Nfc(I)), salt, PAD(A, p), PAD(B, p), K);
}

/** M2 = H( PAD(A) | M1 | K ). */
export function computeM2(p: SrpProfile, A: bigint, M1: Uint8Array, K: Uint8Array): Uint8Array {
  return p.H(PAD(A, p), M1, K);
}

// --- wire factories (invariant #1: byte fields are Hex, never Password) ---
function srpClientHello(A: bigint, p: SrpProfile): WireMsg {
  return { protocol: "srp6a", step: "client-hello", from: "client", fields: { A: padHex(A, p.group.nLen) } };
}
function srpServerHello(salt: Uint8Array, B: bigint, p: SrpProfile): WireMsg {
  return {
    protocol: "srp6a",
    step: "server-hello",
    from: "server",
    fields: { salt: toHex(salt), B: padHex(B, p.group.nLen) },
  };
}
function srpClientProof(M1: Uint8Array): WireMsg {
  return { protocol: "srp6a", step: "client-proof", from: "client", fields: { M1: toHex(M1) } };
}
function srpServerProof(M2: Uint8Array): WireMsg {
  return { protocol: "srp6a", step: "server-proof", from: "server", fields: { M2: toHex(M2) } };
}

// --- registration record (invariant #3: NO password field) ---
export interface SrpVerifierRecord {
  readonly I: string;
  readonly salt: Uint8Array;
  readonly v: bigint;
}

export function register(
  p: SrpProfile,
  I: string,
  password: Password,
  salt: Uint8Array,
): SrpVerifierRecord {
  const x = computeX(p, I, password, salt);
  const v = computeVerifier(p, x);
  return { I, salt, v };
}

// --- stateful sessions with Phase machine ---
export interface SrpTrace {
  k: bigint;
  x?: bigint;
  a?: bigint;
  b?: bigint;
  A?: bigint;
  B?: bigint;
  u?: bigint;
  S?: bigint;
  K?: Uint8Array;
  M1?: Uint8Array;
  M2?: Uint8Array;
}

export class SrpClientSession {
  phase: SrpPhase = "init";
  readonly trace: SrpTrace;
  private A = 0n;
  private x = 0n;
  private readonly a: bigint;

  constructor(
    private readonly p: SrpProfile,
    private readonly I: string,
    private readonly password: Password,
    a: bigint,
  ) {
    this.a = a;
    this.trace = { k: computeK(p) };
  }

  hello(): WireMsg {
    if (this.phase !== "init") throw new PhaseError("init", this.phase);
    this.A = clientA(this.p, this.a);
    this.trace.a = this.a;
    this.trace.A = this.A;
    this.phase = "client-hello-sent";
    return srpClientHello(this.A, this.p);
  }

  /** Consume the server hello, derive S/K, return the client proof M1. */
  proof(serverHello: WireMsg): WireMsg {
    if (this.phase !== "client-hello-sent") throw new PhaseError("client-hello-sent", this.phase);
    const salt = fromHex(serverHello.fields.salt as Hex);
    const B = decodeSrpPublicValue(serverHello.fields.B as Hex, this.p.group, "B");
    const u = computeU(this.p, this.A, B);
    requireValidU(u);
    this.x = computeX(this.p, this.I, this.password, salt);
    const k = this.trace.k;
    const S = clientS(this.p, this.A, B, this.a, this.x, k, u);
    const K = sessionKey(this.p, S);
    const M1 = computeM1(this.p, this.I, salt, this.A, B, K);
    Object.assign(this.trace, { x: this.x, B, u, S, K, M1 });
    this.phase = "client-proof-sent";
    return srpClientProof(M1);
  }

  /** Verify server proof M2, confirming mutual authentication. */
  confirm(serverProof: WireMsg): void {
    if (this.phase !== "client-proof-sent") throw new PhaseError("client-proof-sent", this.phase);
    const M2 = fromHex(serverProof.fields.M2 as Hex);
    const expected = computeM2(this.p, this.A, this.trace.M1!, this.trace.K!);
    if (!eq(M2, expected)) {
      this.phase = "aborted";
      throw new HandshakeAbort("SRP M2 mismatch", "server failed to prove knowledge of K — mutual auth failed.");
    }
    this.phase = "confirmed";
  }

  get sessionKeyBytes(): Uint8Array | undefined {
    return this.phase === "confirmed" || this.phase === "client-proof-sent" ? this.trace.K : undefined;
  }
}

export class SrpServerSession {
  phase: SrpPhase = "registered";
  readonly trace: SrpTrace;
  private B = 0n;
  private A = 0n;
  private readonly b: bigint;

  constructor(
    private readonly p: SrpProfile,
    private readonly record: SrpVerifierRecord,
    b: bigint,
  ) {
    this.b = b;
    this.trace = { k: computeK(p) };
  }

  /** Consume client hello, produce server hello (salt, B). */
  hello(clientHello: WireMsg): WireMsg {
    if (this.phase !== "registered") throw new PhaseError("registered", this.phase);
    this.A = decodeSrpPublicValue(clientHello.fields.A as Hex, this.p.group, "A");
    const k = this.trace.k;
    this.B = (modMul(k, this.record.v, this.p.group.N) + modPow(this.p.group.g, this.b, this.p.group.N)) % this.p.group.N;
    if (this.B % this.p.group.N === 0n) throw new HandshakeAbort("SRP B % N == 0", "server nonce yields B ≡ 0; regenerate b.");
    Object.assign(this.trace, { A: this.A, b: this.b, B: this.B });
    this.phase = "server-hello-sent";
    return srpServerHello(this.record.salt, this.B, this.p);
  }

  /** Verify client proof M1, derive K, return server proof M2. */
  proof(clientProof: WireMsg): WireMsg {
    if (this.phase !== "server-hello-sent") throw new PhaseError("server-hello-sent", this.phase);
    const u = computeU(this.p, this.A, this.B);
    requireValidU(u);
    const S = serverS(this.p, this.A, this.record.v, u, this.b);
    const K = sessionKey(this.p, S);
    const M1expected = computeM1(this.p, this.record.I, this.record.salt, this.A, this.B, K);
    const M1 = fromHex(clientProof.fields.M1 as Hex);
    if (!eq(M1, M1expected)) {
      this.phase = "aborted";
      throw new HandshakeAbort("SRP M1 mismatch", "client failed to prove knowledge of K — wrong password or tamper.");
    }
    const M2 = computeM2(this.p, this.A, M1expected, K);
    Object.assign(this.trace, { u, S, K, M1: M1expected, M2 });
    this.phase = "confirmed";
    return srpServerProof(M2);
  }

  get sessionKeyBytes(): Uint8Array | undefined {
    return this.phase === "confirmed" ? this.trace.K : undefined;
  }
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

// Re-export for convenience in demos/tests.
export { asPassword };
export type { Password };
