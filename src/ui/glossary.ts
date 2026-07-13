// In-context glossary. One plain sentence per notation symbol actually on screen,
// so a newcomer meeting g^a / a scalar / a verifier / a NIZK for the first time has
// an anchor without the labels being dumbed down. Definitions are attached where the
// symbol appears (scratchpad rows), surfaced on hover AND keyboard focus.

export interface GlossaryEntry {
  /** short human title shown as the tooltip heading. */
  readonly title: string;
  /** one-sentence, plain-language definition. */
  readonly text: string;
}

export const GLOSSARY: Record<string, GlossaryEntry> = {
  scalar: {
    title: "scalar",
    text: "Just a big secret number. Multiplying a group element by a scalar is the one-way 'lock' step: easy to do, effectively impossible to undo without the number.",
  },
  gpow: {
    title: "g^a — a Diffie–Hellman share",
    text: "A public generator g raised to your secret exponent a. Publishing g^a reveals nothing about a (that's the discrete-log hardness), yet lets both sides mix secrets into one shared value.",
  },
  nonce: {
    title: "private nonce",
    text: "A fresh random number picked for THIS run only. It never leaves the box; it makes every handshake unique so a recorded transcript can't be replayed.",
  },
  verifier: {
    title: "verifier v",
    text: "A one-way fingerprint of the password the server stores instead of the password. It can CHECK a login but can't be turned back into the password without an offline guessing attack.",
  },
  salt: {
    title: "salt",
    text: "A public random value mixed in before hashing the password, so two users with the same password get different stored records and precomputed 'rainbow' tables don't apply.",
  },
  premaster: {
    title: "premaster secret S",
    text: "The raw shared secret both sides compute independently. It never crosses the wire; the actual session key is hashed from it.",
  },
  nizk: {
    title: "Schnorr NIZK proof",
    text: "A zero-knowledge proof: 'I know the secret exponent behind this public value' — convincing to check, but revealing nothing about the exponent itself.",
  },
  confirmtag: {
    title: "confirmation tag",
    text: "A MAC computed from the derived key. Each side sends one so the other can verify 'we really did land on the same key' before trusting it.",
  },
  huntpeck: {
    title: "hunting-and-pecking",
    text: "Dragonfly's loop that hashes the password with a counter until the result lands on a valid curve point. How many tries it takes is what the Dragonblood side-channel measured.",
  },
  isk: {
    title: "session key (ISK)",
    text: "The final strong key both sides derive. Same on both ends after an honest run; used to protect the actual session.",
  },
};

export function glossaryTip(term: string | undefined): GlossaryEntry | undefined {
  return term ? GLOSSARY[term] : undefined;
}
