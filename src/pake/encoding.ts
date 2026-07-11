// Byte-level encoding helpers shared by all engines.
//
// Every function here is deterministic and side-effect free. All hashing lives in
// hashes.ts. Wire-facing hex is produced via toHex() and is branded `Hex` — the
// only string shape permitted to cross the wire (see types.ts / invariant #1).

import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/abstract/utils";
import type { Hex } from "./types";

export function toHex(b: Uint8Array): Hex {
  return bytesToHex(b) as Hex;
}

export function fromHex(h: Hex | string): Uint8Array {
  return hexToBytes(h);
}

/** UTF-8 bytes of the NFC-normalized string (used for identities + passwords). */
export function utf8Nfc(s: string): Uint8Array {
  return utf8ToBytes(s.normalize("NFC"));
}

/** OS2IP: big-endian bytes -> non-negative integer. */
export function os2ip(b: Uint8Array): bigint {
  return bytesToNumberBE(b);
}

/** I2OSP: integer -> fixed-length big-endian bytes. Throws if it does not fit. */
export function i2osp(n: bigint, len: number): Uint8Array {
  if (n < 0n) throw new RangeError("i2osp: negative integer");
  const out = numberToBytesBE(n, len);
  return out;
}

/** Little-endian bytes -> integer (ristretto255 scalars are little-endian). */
export function os2ipLE(b: Uint8Array): bigint {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]!);
  return n;
}

/** Integer -> fixed-length little-endian bytes. */
export function i2ospLE(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError("i2ospLE: integer too large");
  return out;
}

export function concat(...arrs: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** PAD(v) to exactly `len` bytes, left-padded with zeros (SRP/J-PAKE PAD). */
export function padTo(b: Uint8Array, len: number): Uint8Array {
  if (b.length > len) throw new RangeError(`padTo: ${b.length} > ${len}`);
  if (b.length === len) return b;
  const out = new Uint8Array(len);
  out.set(b, len - b.length);
  return out;
}

/** PAD of an integer to `len` bytes big-endian (i2osp alias, semantic name). */
export function padInt(n: bigint, len: number): Uint8Array {
  return i2osp(n, len);
}

export function uint16be(n: number): Uint8Array {
  if (n < 0 || n > 0xffff) throw new RangeError("uint16be out of range");
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

export function uint32be(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** 2-byte big-endian length prefix + data (J-PAKE / Dragonfly identity encoding). */
export function lp16(data: Uint8Array): Uint8Array {
  return concat(uint16be(data.length), data);
}

// --- CPace length-value concatenation (draft-irtf-cfrg-cpace-21 §4) ---
// prepend_len uses LEB128; all PAKE-Gate fields are < 128 bytes so this is a single
// length byte, but the full LEB128 is implemented for correctness.
export function prependLen(data: Uint8Array): Uint8Array {
  let length = data.length;
  const parts: number[] = [];
  for (;;) {
    if (length < 128) parts.push(length);
    else parts.push((length & 0x7f) + 0x80);
    length >>= 7;
    if (length === 0) break;
  }
  return concat(Uint8Array.from(parts), data);
}

export function lvCat(...args: Uint8Array[]): Uint8Array {
  return concat(...args.map(prependLen));
}

/** o_cat (draft-21): order-independent concat for parallel mode; larger blob first. */
export function oCat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const larger = compareBytes(a, b) >= 0;
  return concat(utf8Nfc("oc"), larger ? a : b, larger ? b : a);
}

/** Lexicographic comparison of byte strings: -1, 0, or 1. */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  if (a.length < b.length) return -1;
  if (a.length > b.length) return 1;
  return 0;
}

/**
 * Byte-string equality. NOT constant-time — browser TypeScript cannot guarantee
 * that (JIT/GC/bignum branching all leak). Used only for demo comparisons; never
 * label this constant-time (see the anti-hallucination rules).
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function zeroBytes(n: number): Uint8Array {
  return new Uint8Array(n);
}
