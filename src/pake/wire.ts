// The Wire: the ONLY channel between the two simulated peers (invariant #2).
//
// Wire.send() serialize/clones every message before delivery, so the receiver never
// holds a reference into the sender's state — no shared Uint8Array or nested object
// can leak across the boundary even if the two sides' types differ. The Wire also
// records the transcript (exactly what an on-path observer sees) and offers the
// invariant #1 runtime backstop audit.

import type { Hex, Password, WireMsg } from "./types";
import { fromHex } from "./encoding";

export class Wire {
  private readonly log: WireMsg[] = [];

  /**
   * Deliver a message across the wire. Returns a deep clone: the receiving side
   * gets an independent copy, proving no reference is shared (invariant #2). We
   * clone via JSON round-trip because a WireMsg is, by construction, a plain
   * serializable DTO of Hex strings / numbers — if it weren't, this would throw,
   * which is itself a useful structural check.
   */
  send(msg: WireMsg): WireMsg {
    const clone: WireMsg = JSON.parse(JSON.stringify(msg));
    this.log.push(clone);
    return clone;
  }

  /** The full ordered transcript (independent clones). */
  transcript(): readonly WireMsg[] {
    return this.log.map((m) => JSON.parse(JSON.stringify(m)) as WireMsg);
  }

  clear(): void {
    this.log.length = 0;
  }
}

// ---------------------------------------------------------------------------
// Invariant #1 runtime backstop. Scans every wire field for the password in the
// encodings the application could itself accidentally produce: UTF-8, UTF-16LE,
// UTF-16BE, hex, base64. It does NOT sweep arbitrary reversible/XOR keyspaces —
// that would be meaningless and give false confidence. The real guarantee is the
// compile-time barrier (Hex vs Password) plus the protocol factories; this audit is
// secondary and cannot prove the absence of every reversible encoding.
// ---------------------------------------------------------------------------

export interface AuditResult {
  readonly clean: boolean;
  readonly hits: { step: string; field: string; encoding: string }[];
}

function candidateEncodingsOf(password: string): { name: string; bytesHex: string }[] {
  const nfc = password.normalize("NFC");
  const enc = new TextEncoder();
  const utf8 = enc.encode(nfc);
  const utf16le = new Uint8Array(nfc.length * 2);
  const utf16be = new Uint8Array(nfc.length * 2);
  for (let i = 0; i < nfc.length; i++) {
    const c = nfc.charCodeAt(i);
    utf16le[i * 2] = c & 0xff;
    utf16le[i * 2 + 1] = (c >> 8) & 0xff;
    utf16be[i * 2] = (c >> 8) & 0xff;
    utf16be[i * 2 + 1] = c & 0xff;
  }
  const toHexStr = (b: Uint8Array) =>
    Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const toB64 = (b: Uint8Array) => btoaBytes(b);
  return [
    { name: "utf8", bytesHex: toHexStr(utf8) },
    { name: "utf16le", bytesHex: toHexStr(utf16le) },
    { name: "utf16be", bytesHex: toHexStr(utf16be) },
    { name: "hex-of-utf8", bytesHex: toHexStr(enc.encode(toHexStr(utf8))) },
    { name: "base64-of-utf8", bytesHex: toHexStr(enc.encode(toB64(utf8))) },
  ];
}

function btoaBytes(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return typeof btoa === "function"
    ? btoa(s)
    : Buffer.from(b).toString("base64");
}

/** Recursively audit a transcript for the password (invariant #1 backstop). */
export function auditTranscript(
  transcript: readonly WireMsg[],
  password: Password,
): AuditResult {
  const cands = candidateEncodingsOf(password);
  const hits: AuditResult["hits"] = [];
  for (const msg of transcript) {
    for (const [field, value] of Object.entries(msg.fields)) {
      if (typeof value !== "string") continue;
      // Wire byte fields are hex; normalize both to hex for substring comparison.
      const haystack = looksHex(value) ? value.toLowerCase() : hexOfUtf8(value);
      for (const c of cands) {
        if (c.bytesHex.length > 0 && haystack.includes(c.bytesHex)) {
          hits.push({ step: msg.step, field, encoding: c.name });
        }
      }
    }
  }
  return { clean: hits.length === 0, hits };
}

function looksHex(s: string): boolean {
  return s.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(s);
}

function hexOfUtf8(s: string): string {
  return Array.from(new TextEncoder().encode(s), (x) =>
    x.toString(16).padStart(2, "0"),
  ).join("");
}

/** Convenience: bytes of a hex wire field (for the attacker/raw-bytes view). */
export function wireFieldBytes(h: Hex): Uint8Array {
  return fromHex(h);
}
