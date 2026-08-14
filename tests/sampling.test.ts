import { describe, it, expect } from "vitest";
import {
  cpaceCI,
  makePassword,
  randExponent384,
  sampleRistrettoScalar,
  uniformInt,
  type RandBytes,
} from "../src/pake/factories";
import { CPaceParty, RISTRETTO255_ORDER } from "../src/pake/cpace";
import { DragonflyParty, derivePasswordElement, huntAndPeckScan } from "../src/pake/dragonfly";
import { P256_ORDER_N } from "../src/pake/groups";
import { i2osp, i2ospLE, os2ipLE, prependLen, utf8Nfc } from "../src/pake/encoding";
import { HandshakeAbort, asPassword } from "../src/pake/types";

/** A byte source that replays a fixed script of outputs, then fails. */
function scripted(outputs: Uint8Array[]): RandBytes {
  let i = 0;
  return (n: number) => {
    const out = outputs[i++];
    if (!out) throw new Error("scripted rand exhausted");
    if (out.length !== n) throw new Error(`scripted rand: wanted ${n} bytes, script has ${out.length}`);
    // Copy: the sampler masks its buffer in place.
    return Uint8Array.from(out);
  };
}

const L = RISTRETTO255_ORDER;

describe("uniformInt — rejection-sampled, no modular reduction", () => {
  it("returns min/top exactly when the draw encodes them (bounds are inclusive)", () => {
    const max = 100n; // range [1, 99]
    expect(uniformInt(max, 1n, scripted([i2osp(1n, 1)]))).toBe(1n);
    expect(uniformInt(max, 1n, scripted([i2osp(99n, 1)]))).toBe(99n);
  });

  it("rejects below-min and above-top draws and redraws instead of reducing", () => {
    // range [2, n-1] for P-256: 0, 1 and (masked) values >= n must all be redrawn.
    const n = P256_ORDER_N;
    const len = 32;
    const r = uniformInt(
      n,
      2n,
      scripted([i2osp(0n, len), i2osp(1n, len), i2osp(n, len), i2osp(7n, len)]),
    );
    expect(r).toBe(7n);
  });

  it("masks surplus top bits down to the bit length of max-1", () => {
    // max-1 = 99 → 7 bits → mask 0x7f: a draw of 0xff must become 0x7f = 127,
    // which is > 99 → rejected; next draw 50 accepted. If the mask were absent the
    // first draw would still be rejected, so ALSO check a draw where only the mask
    // brings it into range: 0xC0 & 0x7f = 64.
    expect(uniformInt(100n, 1n, scripted([Uint8Array.of(0xc0)]))).toBe(64n);
  });

  it("never returns out-of-range over many real draws", () => {
    for (let i = 0; i < 200; i++) {
      const r = uniformInt(P256_ORDER_N, 2n);
      expect(r >= 2n && r < P256_ORDER_N).toBe(true);
    }
  });

  it("throws on an empty range", () => {
    expect(() => uniformInt(2n, 2n)).toThrow(RangeError);
  });
});

describe("randExponent384 — the documented MODP exponent window", () => {
  it("refuses groups at or below the 384-bit window (no silent modulo bias path)", () => {
    expect(() => randExponent384(P256_ORDER_N)).toThrow(RangeError);
    expect(() => randExponent384((1n << 384n) + 1n)).toThrow(RangeError);
  });

  it("is os2ip(48 bytes) + 1: uniform on [1, 2^384]", () => {
    const big = 1n << 4000n;
    expect(randExponent384(big, scripted([new Uint8Array(48)]))).toBe(1n);
    const allFf = new Uint8Array(48).fill(0xff);
    expect(randExponent384(big, scripted([allFf]))).toBe(1n << 384n);
  });
});

describe("sampleRistrettoScalar — canonical draft-style sampling", () => {
  it("rejects zero and redraws", () => {
    const bytes = sampleRistrettoScalar(scripted([new Uint8Array(32), i2ospLE(5n, 32)]));
    expect(os2ipLE(bytes)).toBe(5n);
  });

  it("clears the top 3 bits, then rejects masked values >= L", () => {
    // all-0xff masks to 2^253 - 1 >= L → reject; exactly L → reject; L-1 → accept.
    const allFf = new Uint8Array(32).fill(0xff);
    const bytes = sampleRistrettoScalar(scripted([allFf, i2ospLE(L, 32), i2ospLE(L - 1n, 32)]));
    expect(os2ipLE(bytes)).toBe(L - 1n);
  });

  it("real draws are always canonical", () => {
    for (let i = 0; i < 100; i++) {
      const s = os2ipLE(sampleRistrettoScalar());
      expect(s >= 1n && s < L).toBe(true);
    }
  });
});

describe("CPace scalar bytes are validated, not reduced", () => {
  const cfg = (scalar: Uint8Array) => ({
    role: "A" as const,
    password: asPassword("pw"),
    ci: cpaceCI("A_initiator", "B_responder"),
    sid: new Uint8Array(16),
    ad: new Uint8Array(0),
    scalar,
  });

  it("accepts the canonical boundary L-1 and rejects 0, L, L+5, and wrong lengths", () => {
    expect(() => new CPaceParty(cfg(i2ospLE(L - 1n, 32)))).not.toThrow();
    expect(() => new CPaceParty(cfg(new Uint8Array(32)))).toThrow(HandshakeAbort);
    expect(() => new CPaceParty(cfg(i2ospLE(L, 32)))).toThrow(HandshakeAbort);
    // L+5 is the mutation-sensitive case: silent reduction mod L would accept it
    // as 5 and derive a working share from non-canonical bytes.
    expect(() => new CPaceParty(cfg(i2ospLE(L + 5n, 32)))).toThrow(HandshakeAbort);
    expect(() => new CPaceParty(cfg(new Uint8Array(31)))).toThrow(HandshakeAbort);
  });
});

describe("cpaceCI — LEB128 length prefixes (no one-byte wrap)", () => {
  it("is byte-identical to the old fixed one-byte prefix for short ids", () => {
    const ci = cpaceCI("A_initiator", "B_responder");
    const a = utf8Nfc("A_initiator");
    const b = utf8Nfc("B_responder");
    const old = new Uint8Array(2 + a.length + b.length);
    old[0] = a.length;
    old.set(a, 1);
    old[1 + a.length] = b.length;
    old.set(b, 2 + a.length);
    expect(Buffer.from(ci).toString("hex")).toBe(Buffer.from(old).toString("hex"));
  });

  it("encodes a 300-byte identity without wrapping the length mod 256", () => {
    const long = "x".repeat(300);
    const ci = cpaceCI(long, "B");
    // LEB128 of 300 = 0xac 0x02 (the old code wrote 300 & 0xff = 0x2c, ambiguous).
    expect(ci[0]).toBe(0xac);
    expect(ci[1]).toBe(0x02);
    expect(Buffer.from(ci).toString("hex")).toBe(
      Buffer.from(prependLen(utf8Nfc(long))).toString("hex") +
        Buffer.from(prependLen(utf8Nfc("B"))).toString("hex"),
    );
  });
});

describe("Dragonfly range and counter bounds", () => {
  const nonces = (priv: bigint, mask: bigint) => ({
    selfId: "Alice",
    peerId: "Bob",
    password: makePassword("mesh network"),
    nonces: { priv, mask },
  });

  it("constructor rejects private/mask of 0, 1, n and n+1 (RFC 7664 range rule)", () => {
    const n = P256_ORDER_N;
    for (const bad of [0n, 1n, n, n + 1n]) {
      expect(() => new DragonflyParty(nonces(bad, 5n))).toThrow(HandshakeAbort);
      expect(() => new DragonflyParty(nonces(5n, bad))).toThrow(HandshakeAbort);
    }
  });

  it("constructor accepts the valid boundaries 2 and n-1", () => {
    const n = P256_ORDER_N;
    expect(() => new DragonflyParty(nonces(2n, n - 1n))).not.toThrow();
    expect(() => new DragonflyParty(nonces(n - 1n, 2n))).not.toThrow();
  });

  it("k and maxCounter must fit the one-octet counter: [1, 255]", () => {
    const pw = makePassword("mesh network");
    expect(() => derivePasswordElement("Alice", "Bob", pw, 0)).toThrow(RangeError);
    expect(() => derivePasswordElement("Alice", "Bob", pw, 256)).toThrow(RangeError);
    expect(() => huntAndPeckScan("Alice", "Bob", pw, { maxCounter: 256 })).toThrow(RangeError);
    expect(() => huntAndPeckScan("Alice", "Bob", pw, { maxCounter: -1 })).toThrow(RangeError);
    // 0 is the scan's legitimate degenerate bound: zero iterations, nothing serialized.
    expect(huntAndPeckScan("Alice", "Bob", pw, { maxCounter: 0 }).iterationsPerformed).toBe(0);
    // 255 itself is the last legal value on both paths.
    expect(() => huntAndPeckScan("Alice", "Bob", pw, { maxCounter: 255 })).not.toThrow();
    expect(derivePasswordElement("Alice", "Bob", pw, 255).iterations).toBeGreaterThanOrEqual(255);
  });
});
