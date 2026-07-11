# PAKE Gate 🤝

**SRP-6a · J-PAKE · CPace · Dragonfly (RFC 7664) — the PAKE family, side by side.**

A live, in-browser tour of Password-Authenticated Key Exchange: how two parties turn a
shared, low-entropy **password** into a strong shared key **without the password (or
anything an attacker could grind offline) ever crossing the wire**. Real WebCrypto and
real group arithmetic — no backend, no network, nothing persisted.

> [!WARNING]
> **This is a teaching/demo lab, not production authentication code.** The engines are
> hand-rolled so every step is inspectable; browser TypeScript is **not** constant-time,
> session keys are exposed in the UI on purpose, and randomness/parameters are chosen for
> clarity. Do not lift this code into a real auth system — use a reviewed library.

## What it demonstrates

The one lesson: **a PAKE is not "hash the password and send it."** Each tab runs a real
handshake one message at a time, showing the two peers' private scratchpads, the **Wire**
(literally everything an on-path observer sees), and each side's derived key — which lights
green only when both sides match **and** confirm.

| Protocol | Family | What's distinctive | Standard |
| --- | --- | --- | --- |
| **SRP-6a** | augmented | server stores a verifier `{salt, v}`, never the password | RFC 2945 / 5054 |
| **J-PAKE** | balanced | both peers share the password; Schnorr NIZK proofs, no verifier stored | RFC 8236 (+ RFC 8235) |
| **CPace** | balanced | one-round; generator derived from password + session context | draft-irtf-cfrg-cpace-21 (Internet-Draft, **not** an RFC) |
| **Dragonfly** | balanced | hunting-and-pecking password→point (the surface Dragonblood attacked) | RFC 7664 (family behind WPA3 SAE) |

Plus a family **taxonomy matrix** (with an OPAQUE / RFC 9807 reference row and a deep link to
the sibling [OPAQUE Gate](https://systemslibrarian.github.io/crypto-lab-opaque-gate/) lab), a
curated **tamper** menu, an **offline-grind** simulator contrasting balanced-transcript vs
stolen-SRP-verifier breach economics, and the **Dragonblood** side-channel comparison.

## Run it

```bash
npm install
npm run dev        # local dev server
npm run build      # static build → dist/  (deployed to GitHub Pages)
```

Live demo (once Pages is enabled): `https://systemslibrarian.github.io/crypto-lab-pake-gate/`

## Test & verify

```bash
npm test           # full suite (Vitest)
npm run test:fast  # skips the slow big-integer primality/grind tests
npm run coverage   # coverage; enforces a floor on the crypto core (src/pake/**)
npm run typecheck  # tsc --noEmit
npm run lint       # eslint (bans unsafe casts in src/pake — the password barrier)
```

Every engine is validated against **published test vectors where they exist** (SRP RFC 5054
Appendix B; CPace draft-21 ristretto255/SHA-512) and against **independent from-scratch
Python KAT generators** where the RFC publishes none (SRP Track 2, J-PAKE, Dragonfly). Group
primes are derived from first principles and verified as safe primes. Full provenance is in
[`tests/vectors/README.md`](tests/vectors/README.md).

## How it's built

- `src/pake/` — the four headless engines, shared group arithmetic, the `Wire` transport,
  branded types (the compile-time `Hex`-vs-`Password` barrier that keeps the password off the
  wire), and the taxonomy data.
- `src/ui/` — vanilla-DOM UI (no framework): tabbed split view, wire transcript, key panel,
  attacker/breach/Dragonblood panels.
- `tests/` — 90+ tests: published vectors, independent KATs, round-trips, security invariants,
  fail-closed edge cases, tamper-aborts-pre-key, offline-grind asymmetry, plus jsdom render +
  axe-core accessibility + runner interaction tests.

**Accessibility & mobile:** WCAG 2.1 AA — state is conveyed by icon + text + color (never color
alone), all controls are keyboard-operable with focus rings, inputs are labeled, contrast is AA
in both light and dark themes, and `prefers-reduced-motion` is respected. The layout stacks
below 640px.

---

*Part of the Crypto Lab suite. This build produces the demo logic, UI, and content; a separate
standardization pass owns the shared header, theme toggle, and footer.*
