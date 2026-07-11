// Distinct, typed parameter sets — NOT one generic ModpGroupConfig.
//
// SrpGroupParameters and JPakeGroupParameters are separate types even though they
// share arithmetic, so a builder cannot silently reuse SRP's group for J-PAKE
// without matching its subgroup assumptions. All primes here are DERIVED + VERIFIED
// as safe primes of exact bit length by tests/vectors/gen/derive_groups.py (see
// tests/vectors/README.md). The bignum literals below are the verified output of
// that script, and tests/params.test.ts re-checks them at test time.

const hexToBig = (h: string): bigint => BigInt("0x" + h.replace(/\s+/g, ""));

export interface SrpGroupParameters {
  readonly kind: "srp-group";
  readonly name: string;
  readonly N: bigint;
  readonly g: bigint;
  readonly hash: "SHA-1" | "SHA-256";
  /** length(N) in bytes — the PAD width. */
  readonly nLen: number;
}

export interface JPakeGroupParameters {
  readonly kind: "jpake-group";
  readonly name: string;
  readonly p: bigint;
  /** prime subgroup order q = (p-1)/2 (safe prime). */
  readonly q: bigint;
  readonly g: bigint;
  /** length(p) in bytes — the PAD width for elements. */
  readonly pLen: number;
}

// --- SRP Track 1: RFC 5054 Appendix A 1024-bit group + SHA-1 (validates arithmetic
// against Appendix B; used for NOTHING else). ---
const N_1024 = hexToBig(
  "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576" +
    "d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad1" +
    "5dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec" +
    "68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3",
);

export const SRP_GROUP_1024_SHA1: SrpGroupParameters = {
  kind: "srp-group",
  name: "RFC 5054 1024-bit (Appendix A) / SHA-1",
  N: N_1024,
  g: 2n,
  hash: "SHA-1",
  nLen: 128,
};

// --- SRP Track 2 (the runnable demo): RFC 5054 Appendix A 4096-bit group (== RFC
// 3526 group 16) with g=5, SHA-256. This is a declared standalone teaching profile:
// simple-hash K = SHA-256(PAD(S)), NOT TLS-SRP and NOT RFC 2945 SHA_Interleave. ---
const N_4096 = hexToBig(
  "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74" +
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437" +
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" +
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05" +
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb" +
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" +
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183" +
    "995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a" +
    "85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7ab" +
    "f5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87" +
    "602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e2" +
    "4fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719" +
    "a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2" +
    "db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba18" +
    "6515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea98" +
    "8d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff",
);

export const SRP_GROUP_4096_SHA256: SrpGroupParameters = {
  kind: "srp-group",
  name: "RFC 5054 4096-bit (Appendix A) / SHA-256 [PAKE-Gate standalone profile]",
  N: N_4096,
  g: 5n,
  hash: "SHA-256",
  nLen: 512,
};

// --- J-PAKE: RFC 3526 3072-bit MODP group (group 15), g=2, q=(p-1)/2. ---
const P_3072 = hexToBig(
  "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74" +
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437" +
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" +
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05" +
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb" +
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" +
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183" +
    "995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a" +
    "85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7ab" +
    "f5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87" +
    "602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e2" +
    "4fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff",
);

export const JPAKE_GROUP_3072: JPakeGroupParameters = {
  kind: "jpake-group",
  name: "RFC 3526 3072-bit MODP (group 15)",
  p: P_3072,
  q: (P_3072 - 1n) / 2n,
  g: 2n,
  pLen: 384,
};

// Dragonfly (P-256) and CPace (ristretto255) take their parameters directly from
// @noble/curves; no MODP constants needed here.
