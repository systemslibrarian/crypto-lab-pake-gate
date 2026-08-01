// Attacker surfaces: on-path observer, SRP server breach + the two-column offline
// grind, and the balanced-PAKE breach note. Renders into a container the caller owns.

import { auditTranscript } from "../pake/wire.ts";
import type { WireMsg, Password } from "../pake/types.ts";
import type { SrpVerifierRecord } from "../pake/srp6a.ts";
import {
  SRP_TRACK2_4096_SHA256,
  computeVerifier,
  computeX,
} from "../pake/srp6a.ts";
import { BREACH_ECONOMICS } from "../pake/taxonomy.ts";
import { makePassword } from "../pake/factories.ts";
import { toHex } from "../pake/encoding.ts";
import { bigHex, bytesHex, type ProtocolId } from "./model.ts";
import { button, el, labeledInput } from "./dom.ts";

// A fixed attacker wordlist. It is deliberately built WITHOUT reference to the
// password the demo is currently using: the offline attack must be able to miss.
// "hunter2" is the demo's default password and is in the list, so the default
// run lands a real hit; type any password outside this list into the header and
// the same attack honestly finds nothing.
const DICTIONARY = [
  "password", "hunter2", "letmein", "swordfish", "dragon",
  "correct-horse", "s3cr3t!", "openupplease", "trustno1", "qwerty12",
] as const;

/** Split a learner-typed candidate list on commas / whitespace. */
function parseExtraGuesses(raw: string): string[] {
  const seen = new Set<string>(DICTIONARY);
  const out: string[] = [];
  for (const token of raw.split(/[,\s]+/)) {
    const t = token.trim();
    if (t.length === 0 || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  return out;
}

// --- On-path observer -------------------------------------------------------

export function renderObserverPanel(
  protocol: ProtocolId,
  transcript: readonly WireMsg[],
  truePassword: Password,
): HTMLElement {
  const balanced = protocol !== "srp6a";
  const audit = auditTranscript(transcript, truePassword);

  const section = el("section", { class: "attacker", "aria-labelledby": "obs-h" }, [
    el("h2", { id: "obs-h", class: "attacker__title", text: "On-path observer" }),
    el("p", { class: "attacker__lead", text: "This is exactly what a passive attacker on the wire sees — the raw bytes below, and nothing else." }),
  ]);

  section.append(
    el("div", { class: "attacker__audit " + (audit.clean ? "ok" : "bad") }, [
      el("strong", { text: audit.clean ? "Transcript audit: clean" : "Transcript audit: HIT" }),
      el("span", { text: audit.clean
        ? " — the password appears in no recognized encoding across any wire field (compile-time barrier is the real guarantee; this scan is a secondary backstop)."
        : ` — ${audit.hits.length} hit(s); investigate.` }),
    ]),
  );

  const note = balanced
    ? "Balanced PAKE, correctly executed: a passive transcript gives the attacker NO offline password test. Every guess must be tried in a fresh online interaction."
    : "SRP is augmented: this passive transcript is NOT the stolen-verifier offline test. The offline dictionary attack needs the server's stored {salt, v}, not the wire — see the server-breach panel.";
  section.append(el("p", { class: "attacker__note", text: note }));

  const list = el("div", { class: "attacker__raw", tabindex: "0", role: "region", "aria-label": "raw transcript bytes" });
  if (transcript.length === 0) {
    list.append(el("p", { class: "wire__empty", text: "No transcript yet — run a handshake first." }));
  }
  for (const msg of transcript) {
    const card = el("div", { class: "rawmsg" }, [
      el("div", { class: "rawmsg__head", text: `${msg.from} · ${msg.step}` }),
    ]);
    for (const [name, value] of Object.entries(msg.fields)) {
      card.append(
        el("div", { class: "rawmsg__field" }, [
          el("span", { class: "rawmsg__name", text: name }),
          el("code", { class: "rawmsg__hex", text: typeof value === "string" ? spaced(value) : String(value) }),
        ]),
      );
    }
    list.append(card);
  }
  section.append(list);
  return section;
}

function spaced(hex: string): string {
  if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) return hex;
  return hex.replace(/(..)/g, "$1 ").trim();
}

// --- SRP server breach + offline-grind race ---------------------------------

export function renderSrpBreachPanel(
  record: SrpVerifierRecord,
  truePassword: Password,
  balancedTranscript: readonly WireMsg[],
): HTMLElement {
  const section = el("section", { class: "breach", "aria-labelledby": "breach-h" }, [
    el("h2", { id: "breach-h", class: "breach__title", text: "Server breach — the stolen record is NOT the password" }),
  ]);

  section.append(
    el("div", { class: "breach__dump" }, [
      el("div", { class: "breach__dump-row" }, [el("span", { text: "I (identity)" }), el("code", { text: record.I })]),
      el("div", { class: "breach__dump-row" }, [el("span", { text: "salt" }), el("code", { text: bytesHex(record.salt) })]),
      el("div", { class: "breach__dump-row" }, [el("span", { text: "v (verifier)" }), el("code", { text: bigHex(record.v).slice(0, 40) + "…" })]),
    ]),
  );
  section.append(
    el("p", { class: "breach__note", text: "This dump is {salt, v} — NOT the password. Recovering the password requires an offline dictionary attack: for each guess recompute v' = g^{H(salt, H(I:guess))} and compare to v." }),
  );

  // Two-column race.
  const race = el("div", { class: "race" });
  race.append(renderBalancedColumn(balancedTranscript, truePassword));
  race.append(renderVerifierColumn(record));
  section.append(race);

  // Breach economics (the three distinct cases) + OPAQUE cross-link.
  section.append(
    el("div", { class: "economics" }, [
      el("h3", { class: "economics__title", text: "Three distinct breach economics" }),
      economicsRow("Balanced transcript", BREACH_ECONOMICS.balancedTranscript),
      economicsRow("Stolen SRP verifier", BREACH_ECONOMICS.srpVerifier),
      economicsRow("Fully-compromised OPAQUE server", BREACH_ECONOMICS.opaqueServer),
      el("p", { class: "economics__link" }, [
        el("a", { href: "https://systemslibrarian.github.io/crypto-lab-opaque-gate/", target: "_blank", rel: "noopener" }, ["Take the next step → OPAQUE Gate"]),
      ]),
    ]),
  );
  return section;
}

function economicsRow(label: string, text: string): HTMLElement {
  return el("div", { class: "economics__row" }, [
    el("strong", { text: label }),
    el("span", { text: text }),
  ]);
}

function renderBalancedColumn(transcript: readonly WireMsg[], truePassword: Password): HTMLElement {
  const col = el("div", { class: "race__col race__col--balanced" }, [
    el("h3", { class: "race__title", text: "Attack a balanced transcript" }),
    el("p", { class: "race__sub", text: "A captured balanced-PAKE transcript. There is no verification equation in it, so there is nothing to recompute-and-compare — the only offline move left is to scan the raw bytes for each candidate, which finds nothing." }),
  ]);
  const out = el("div", { class: "race__out" });
  const counter = el("div", { class: "race__counter", text: "candidates tested: 0" });
  col.append(counter, out);
  col.append(
    button("Scan the transcript for each candidate", () => {
      out.replaceChildren();
      let n = 0;
      let leaks = 0;
      for (const guess of DICTIONARY) {
        n++;
        // A correctly-executed balanced transcript exposes no offline password test.
        // All we can do passively is look for the candidate appearing in some
        // recognized encoding across the wire fields. It should never be there.
        const clean = transcript.length === 0 || auditTranscript(transcript, makePassword(guess)).clean;
        if (!clean) leaks++;
        out.append(
          el("div", { class: "guess guess--neutral" }, [
            el("code", { text: guess }),
            el("span", { text: clean ? "not present on the wire — no offline test exists; needs a fresh online interaction" : "unexpected leak — investigate" }),
          ]),
        );
      }
      counter.textContent = `candidates tested: ${n}`;
      out.append(
        leaks === 0
          ? el("p", { class: "race__verdict race__verdict--neutral", text: "Nothing resolved offline. A balanced transcript gives a passive attacker no equation to grind — each guess costs one live handshake against a server that can rate-limit and lock out." })
          : el("p", { class: "race__verdict race__verdict--amber", text: `${leaks} candidate(s) appeared in the transcript — that is a real leak in this build, not the expected result.` }),
      );
      void truePassword; // knowing it confers no offline advantage here either.
    }, { class: "btn--attack" }),
  );
  return col;
}

function renderVerifierColumn(record: SrpVerifierRecord): HTMLElement {
  const col = el("div", { class: "race__col race__col--verifier" }, [
    el("h3", { class: "race__title", text: "Grind the stolen SRP {salt, v}" }),
    el("p", { class: "race__sub", text: "For each candidate recompute v' = g^{H(salt, H(I:candidate))} and test v' == v. Real modular exponentiation, at the attacker's own pace, fully offline — no server involved and no rate limit to hit." }),
    el("p", { class: "race__sub", text: "The wordlist below is fixed and does not know the demo's password. Change the password in the header to something outside it and this attack genuinely finds nothing — the only thing standing between the breached record and the password is whether the password is guessable." }),
  ]);
  const { wrap, input } = labeledInput("Extra candidates to add to the wordlist (comma or space separated)", {
    id: "srp-extra-guesses",
    type: "text",
    placeholder: "e.g. correct horse battery staple",
    autocomplete: "off",
  });
  const out = el("div", { class: "race__out" });
  const counter = el("div", { class: "race__counter", text: "candidates tested: 0" });
  col.append(wrap, counter, out);
  col.append(
    button("Run offline grind", () => {
      out.replaceChildren();
      const extras = parseExtraGuesses(input.value);
      const dict: string[] = [...DICTIONARY, ...extras];
      const p = SRP_TRACK2_4096_SHA256;
      let n = 0;
      let hit = false;
      for (const guess of dict) {
        n++;
        const x = computeX(p, record.I, makePassword(guess), record.salt);
        const vPrime = computeVerifier(p, x);
        const matched = vPrime === record.v;
        out.append(
          el("div", { class: "guess " + (matched ? "guess--hit" : "guess--miss") }, [
            el("code", { text: guess }),
            el("span", { text: matched ? "verifier matched — password recovered offline" : "v' ≠ v" }),
          ]),
        );
        if (matched) { hit = true; break; }
      }
      counter.textContent = `candidates tested: ${n}${extras.length > 0 ? ` (${DICTIONARY.length} wordlist + ${extras.length} yours)` : ""}`;
      out.append(
        hit
          ? el("p", { class: "race__verdict race__verdict--amber", text: "Recovered — and note it was not 'the password read off the wire'. The stolen verifier handed the attacker a free offline test, and this candidate satisfied it." })
          : el("p", { class: "race__verdict race__verdict--neutral", text: `No match in ${n} candidates. The attacker has learned only that the password is outside this list — and can keep going, for free, at billions of candidates per GPU-day. That is the real cost of a breached augmented-PAKE verifier: it does not stop the attack, it only makes it as expensive as your password is unguessable.` }),
      );
    }, { class: "btn--attack" }),
  );
  return col;
}

// --- Balanced-PAKE breach note (replaces the SRP breach launcher) -----------

export function renderBalancedBreachNote(protocol: ProtocolId): HTMLElement {
  const dragonfly = protocol === "dragonfly";
  const base =
    "Balanced PAKE — no augmented verifier record. Both peers must still possess the shared password/credential; compromise of a peer's secret storage can expose it directly.";
  const extra = dragonfly
    ? " Dragonfly: RFC 7664 §4 — a stolen salted database still permits impersonation."
    : "";
  return el("section", { class: "breach breach--balanced", "aria-labelledby": "bbreach-h" }, [
    el("h2", { id: "bbreach-h", class: "breach__title", text: "Server breach (balanced lesson)" }),
    el("p", { class: "breach__note", text: base + extra }),
    el("p", { class: "breach__note breach__note--muted", text: "This is deliberately NOT 'nothing is stored to breach' — a balanced peer still holds a password-equivalent secret." }),
  ]);
}

// Re-export the plain hex helper for callers building raw dumps.
export { toHex };
