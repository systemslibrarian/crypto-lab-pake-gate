import { describe, it, expect } from "vitest";
import {
  bytesEqual,
  compareBytes,
  i2osp,
  i2ospLE,
  os2ip,
  padInt,
  padTo,
  uint16be,
} from "../src/pake/encoding";
import { PhaseError } from "../src/pake/types";

// The integer<->bytes helpers in encoding.ts are the layer every engine's PAD(),
// I2OSP() and length-prefix rules are built on. Their *guards* are what keep a
// silent truncation from becoming a wrong-but-plausible transcript, and those
// guard paths had no direct coverage — the protocol suites only ever hit the
// happy path. These pin the refusals themselves.

const bytes = (...xs: number[]) => Uint8Array.from(xs);

describe("I2OSP / I2OSP-LE refuse to encode what does not fit", () => {
  it("i2osp rejects a negative integer rather than encoding two's complement", () => {
    expect(() => i2osp(-1n, 4)).toThrow(RangeError);
    expect(() => i2osp(-1n, 4)).toThrow(/negative/);
  });

  it("i2osp round-trips through os2ip at the exact width", () => {
    expect(i2osp(0x0102n, 4)).toEqual(bytes(0, 0, 1, 2));
    expect(os2ip(i2osp(0xdeadbeefn, 8))).toBe(0xdeadbeefn);
  });

  it("i2ospLE throws when the integer overruns the requested length", () => {
    // 0x0100 needs two bytes; asking for one must fail, not wrap to 0x00.
    expect(() => i2ospLE(0x0100n, 1)).toThrow(RangeError);
    expect(() => i2ospLE(0x0100n, 1)).toThrow(/too large/);
    expect(i2ospLE(0x0100n, 2)).toEqual(bytes(0x00, 0x01));
  });
});

describe("PAD() left-pads and never truncates", () => {
  it("returns the input untouched when it is already the target width", () => {
    const b = bytes(1, 2, 3);
    expect(padTo(b, 3)).toBe(b);
  });

  it("left-pads with zeros, keeping the value big-endian", () => {
    expect(padTo(bytes(1, 2), 5)).toEqual(bytes(0, 0, 0, 1, 2));
  });

  it("throws rather than dropping high-order bytes when the input is too long", () => {
    expect(() => padTo(bytes(1, 2, 3), 2)).toThrow(RangeError);
    expect(() => padTo(bytes(1, 2, 3), 2)).toThrow(/3 > 2/);
  });

  it("padInt is I2OSP at a fixed width (the SRP/J-PAKE PAD-for-hash input)", () => {
    expect(padInt(0xffn, 4)).toEqual(i2osp(0xffn, 4));
    expect(padInt(0n, 3)).toEqual(bytes(0, 0, 0));
  });
});

describe("uint16be guards the 2-byte length prefix", () => {
  it("encodes big-endian", () => {
    expect(uint16be(0x0102)).toEqual(bytes(0x01, 0x02));
    expect(uint16be(0xffff)).toEqual(bytes(0xff, 0xff));
  });

  it("refuses an out-of-range length instead of wrapping it mod 65536", () => {
    // A wrapped prefix would silently re-frame an identity blob on the wire.
    expect(() => uint16be(0x10000)).toThrow(RangeError);
    expect(() => uint16be(-1)).toThrow(RangeError);
  });
});

describe("compareBytes / bytesEqual — the ordering o_cat depends on", () => {
  it("orders by content first, then treats a prefix as the smaller string", () => {
    expect(compareBytes(bytes(1, 2), bytes(1, 3))).toBe(-1);
    expect(compareBytes(bytes(1, 3), bytes(1, 2))).toBe(1);
    // Equal on the shared prefix: the shorter blob sorts first.
    expect(compareBytes(bytes(1, 2), bytes(1, 2, 0))).toBe(-1);
    expect(compareBytes(bytes(1, 2, 0), bytes(1, 2))).toBe(1);
    expect(compareBytes(bytes(1, 2), bytes(1, 2))).toBe(0);
  });

  it("bytesEqual is length-sensitive and content-sensitive", () => {
    expect(bytesEqual(bytes(1, 2, 3), bytes(1, 2, 3))).toBe(true);
    expect(bytesEqual(bytes(1, 2, 3), bytes(1, 2))).toBe(false);
    expect(bytesEqual(bytes(1, 2, 3), bytes(1, 2, 4))).toBe(false);
    // A zero prefix must not read as equal to a zero-length input.
    expect(bytesEqual(new Uint8Array(0), bytes(0))).toBe(false);
  });
});

describe("PhaseError names both the expected and the actual phase", () => {
  it("carries enough detail for the UI to say what was out of order", () => {
    const e = new PhaseError("commit-sent", "init");
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("PhaseError");
    expect(e.message).toContain("commit-sent");
    expect(e.message).toContain("init");
  });
});
