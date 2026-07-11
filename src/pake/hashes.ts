// Real hash primitives. We use @noble/hashes (SHA-1/256/512, HMAC, HKDF) rather than
// WebCrypto's async SubtleCrypto: identical, audited primitives, but synchronous so
// the engines and KATs stay deterministic and testable without async ceremony. These
// are real implementations — nothing here is simulated.

import { sha1 } from "@noble/hashes/sha1";
import { sha256, sha512 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";
import { extract as hkdfExtract, expand as hkdfExpand } from "@noble/hashes/hkdf";
import { concat, uint32be } from "./encoding";

export const SHA1 = (...m: Uint8Array[]) => sha1(concat(...m));
export const SHA256 = (...m: Uint8Array[]) => sha256(concat(...m));
export const SHA512 = (...m: Uint8Array[]) => sha512(concat(...m));

export const HMAC_SHA256 = (key: Uint8Array, ...m: Uint8Array[]) =>
  hmac(sha256, key, concat(...m));
export const HMAC_SHA512 = (key: Uint8Array, ...m: Uint8Array[]) =>
  hmac(sha512, key, concat(...m));

/** HKDF-SHA-256 (RFC 5869) as used by J-PAKE ISK/kc derivation. */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  const prk = hkdfExtract(sha256, ikm, salt);
  return hkdfExpand(sha256, prk, info, length);
}

/**
 * NIST SP 800-108 counter-mode KDF with HMAC-SHA-256 PRF, as RFC 7664's KDF-n.
 * K(i) = HMAC-SHA-256(key, [i]_4 || Label || 0x00 || Context || [L]_4), L in BITS.
 * Blocks K(1)||K(2)||... truncated to L bits.
 */
export function kdf800108(
  key: Uint8Array,
  label: Uint8Array,
  context: Uint8Array,
  lengthBits: number,
): Uint8Array {
  const outLen = Math.ceil(lengthBits / 8);
  const lBytes = uint32be(lengthBits);
  const blocks: Uint8Array[] = [];
  let produced = 0;
  let i = 1;
  while (produced < outLen) {
    const block = HMAC_SHA256(
      key,
      uint32be(i),
      label,
      new Uint8Array([0x00]),
      context,
      lBytes,
    );
    blocks.push(block);
    produced += block.length;
    i++;
  }
  let out = concat(...blocks).subarray(0, outLen);
  // Truncate to the leftmost L bits: keep the high `rem` bits of the final byte.
  // (Our uses are byte-aligned — L=320, L=512 — so this branch is inert, but kept
  // correct so the KDF is right for any L.)
  const rem = lengthBits % 8;
  if (rem !== 0) {
    const copy = out.slice();
    const mask = (0xff << (8 - rem)) & 0xff;
    copy[copy.length - 1] = copy[copy.length - 1]! & mask;
    out = copy;
  }
  return out;
}
