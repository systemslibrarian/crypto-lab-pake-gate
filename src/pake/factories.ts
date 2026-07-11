// Convenience constructors that fill in the per-session randomness, so UI code never
// has to know nonce internals. Secrets are generated per-session in memory via the
// platform CSPRNG and never persisted (WebCrypto in the browser, node:crypto in tests).

import { randomBytes } from "@noble/hashes/utils";
import { os2ip, utf8Nfc } from "./encoding";
import {
  SRP_TRACK2_4096_SHA256,
  SrpClientSession,
  SrpServerSession,
  register,
  type SrpProfile,
  type SrpVerifierRecord,
} from "./srp6a";
import { JPakeParty, type Role } from "./jpake";
import { CPaceParty } from "./cpace";
import { DragonflyParty } from "./dragonfly";
import { JPAKE_GROUP_3072, type JPakeGroupParameters } from "./params";
import { P256_ORDER_N } from "./groups";
import { asPassword, type Password } from "./types";

/** Uniform random integer in [1, max-1]. */
function randInt(max: bigint, bytes = 48): bigint {
  const r = os2ip(randomBytes(bytes)) % (max - 1n);
  return r + 1n;
}

export function makePassword(s: string): Password {
  return asPassword(s);
}

export function randomSalt(len = 16): Uint8Array {
  return randomBytes(len);
}

// --- SRP (Track 2 runnable profile by default) ---
export function srpRegister(
  I: string,
  password: Password,
  salt: Uint8Array = randomSalt(),
  profile: SrpProfile = SRP_TRACK2_4096_SHA256,
): SrpVerifierRecord {
  return register(profile, I, password, salt);
}

export function makeSrpClient(
  I: string,
  password: Password,
  profile: SrpProfile = SRP_TRACK2_4096_SHA256,
): SrpClientSession {
  return new SrpClientSession(profile, I, password, randInt(profile.group.N));
}

export function makeSrpServer(
  record: SrpVerifierRecord,
  profile: SrpProfile = SRP_TRACK2_4096_SHA256,
): SrpServerSession {
  return new SrpServerSession(profile, record, randInt(profile.group.N));
}

// --- J-PAKE ---
export function makeJPakeParty(
  role: Role,
  selfId: string,
  peerId: string,
  password: Password,
  group: JPakeGroupParameters = JPAKE_GROUP_3072,
): JPakeParty {
  const q = group.q;
  return new JPakeParty({
    role,
    selfId,
    peerId,
    password,
    nonces: {
      e1: randInt(q),
      e2: randInt(q),
      v1: randInt(q),
      v2: randInt(q),
      vr: randInt(q),
    },
  });
}

// --- CPace ---
export function makeCPaceParty(
  role: "A" | "B",
  password: Password,
  ci: Uint8Array,
  sid: Uint8Array,
  ad: Uint8Array,
): CPaceParty {
  return new CPaceParty({ role, password, ci, sid, ad, scalar: randomBytes(32) });
}

/** CI = concat of length-prefixed party ids (draft convention), for demos. */
export function cpaceCI(idA: string, idB: string): Uint8Array {
  const a = utf8Nfc(idA);
  const b = utf8Nfc(idB);
  const out = new Uint8Array(2 + a.length + b.length);
  out[0] = a.length;
  out.set(a, 1);
  out[1 + a.length] = b.length;
  out.set(b, 2 + a.length);
  return out;
}

// --- Dragonfly ---
export function makeDragonflyParty(
  selfId: string,
  peerId: string,
  password: Password,
): DragonflyParty {
  return new DragonflyParty({
    selfId,
    peerId,
    password,
    nonces: { priv: randInt(P256_ORDER_N), mask: randInt(P256_ORDER_N) },
  });
}
