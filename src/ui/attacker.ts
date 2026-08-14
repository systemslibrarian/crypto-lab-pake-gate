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

/**
 * Cap on learner-typed extra candidates per grind run. Each candidate costs one
 * synchronous 4096-bit modular exponentiation (~a few ms) on the UI thread, so an
 * unbounded pasted dictionary would freeze the page for its whole duration.
 */
export const MAX_EXTRA_CANDIDATES = 64;

/** Split a learner-typed candidate list on commas / whitespace; dedupe, then cap. */
export function parseExtraGuesses(raw: string): { extras: string[]; dropped: number } {
  const seen = new Set<string>(DICTIONARY);
  const out: string[] = [];
  for (const token of raw.split(/[,\s]+/)) {
    const t = token.trim();
    if (t.length === 0 || seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }
  const extras = out.slice(0, MAX_EXTRA_CANDIDATES);
  return { extras, dropped: out.length - extras.length };
}

// --- On-path observer -------------------------------------------------------

/** One credential the observer audit scans the wire for, with its provenance. */
export interface AuditTarget {
  /** e.g. "the registered password", "Peer B's password". */
  readonly label: string;
  readonly password: Password;
}

export function renderObserverPanel(
  protocol: ProtocolId,
  transcript: readonly WireMsg[],
  /**
   * EVERY credential in play for the run on screen. After an SRP wrong-password
   * run the registered password and the client-entered one differ; the audit used
   * to scan only the client-entered value and say "the password" — leaving the
   * registered password unscanned and the scope unstated. Both matter, and the
   * verdict must say exactly what was scanned.
   */
  targets: readonly AuditTarget[],
): HTMLElement {
  const balanced = protocol !== "srp6a";
  // Dedupe identical password values but keep every label for the scope line.
  const unique: AuditTarget[] = [];
  for (const t of targets) {
    if (!unique.some((u) => u.password === t.password)) unique.push(t);
  }
  const audits = unique.map((t) => ({ target: t, audit: auditTranscript(transcript, t.password) }));
  const clean = audits.every((a) => a.audit.clean);
  const hitCount = audits.reduce((n, a) => n + a.audit.hits.length, 0);
  const labels = targets.map((t) => t.label);
  const scope =
    labels.join(" and ") +
    (unique.length === 1 && targets.length > 1 ? " (identical in this run)" : "");

  const section = el("section", { class: "attacker", "aria-labelledby": "obs-h" }, [
    el("h2", { id: "obs-h", class: "attacker__title", text: "On-path observer" }),
    el("p", { class: "attacker__lead", text: "This is exactly what a passive attacker on the wire sees — the raw bytes below, and nothing else." }),
  ]);

  section.append(
    el("div", { class: "attacker__audit " + (clean ? "ok" : "bad") }, [
      el("strong", { text: clean ? "Transcript audit: clean" : "Transcript audit: HIT" }),
      el("span", { text: clean
        ? ` — scanned for ${scope}: no recognized encoding of ${unique.length > 1 ? "either" : "it"} appears in any wire field (compile-time barrier is the real guarantee; this scan is a secondary backstop).`
        : ` — ${hitCount} hit(s) scanning for ${scope}; investigate.` }),
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
  /**
   * The transcript of the run currently on screen. This panel only ever exists on
   * the SRP tab, so this is an SRP transcript — it is NOT a J-PAKE / CPace /
   * Dragonfly transcript and the left column must never label it as one. It is also
   * EMPTY until a handshake has been run, which the column has to say rather than
   * reporting ten clean candidates against zero bytes.
   */
  passiveTranscript: readonly WireMsg[],
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
  race.append(renderPassiveColumn(passiveTranscript, truePassword));
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

/** How much material a candidate scan actually has to work with. */
function transcriptSize(transcript: readonly WireMsg[]): { fields: number; bytes: number } {
  let fields = 0;
  let bytes = 0;
  for (const msg of transcript) {
    for (const value of Object.values(msg.fields)) {
      if (typeof value !== "string") continue;
      fields++;
      bytes += /^[0-9a-fA-F]*$/.test(value) && value.length % 2 === 0 ? value.length / 2 : value.length;
    }
  }
  return { fields, bytes };
}

/**
 * LEFT column: the passive wire transcript of the run on screen.
 *
 * Two things this column must not do, both of which it used to.
 *
 * 1. Call the artifact a "balanced-PAKE transcript". This panel exists only on the
 *    SRP tab and is handed the SRP run's own transcript, so the bytes below are
 *    `client-hello / server-hello / client-proof / server-proof` — SRP, not J-PAKE
 *    or CPace or Dragonfly.
 * 2. Report a result when there is nothing to scan. "Server breach" is reachable
 *    without running a handshake first, and the scan then examined **0 wire fields**
 *    yet printed ten "not present on the wire — no offline test exists" rows and the
 *    verdict "Nothing resolved offline". That is a property asserted about the empty
 *    set.
 *
 * What the scan computes is a literal-encoding leak audit (UTF-8 / UTF-16 / hex /
 * base64 substring search). "A passive transcript provides no offline password test"
 * is a statement about the PAKE security model, not a result this loop can produce,
 * so it is stated separately and labelled as such.
 */
function renderPassiveColumn(transcript: readonly WireMsg[], truePassword: Password): HTMLElement {
  const size = transcriptSize(transcript);
  const col = el("div", { class: "race__col race__col--balanced" }, [
    el("h3", { class: "race__title", text: "Scan the passive SRP transcript" }),
    el("p", { class: "race__sub", text: "The wire transcript of the SRP run currently on screen. It carries no verifier record, so it offers no recompute-and-compare equation — the only offline move a passive attacker has here is to look for each candidate appearing literally, in some recognized encoding, across the wire fields." }),
  ]);
  const out = el("div", { class: "race__out" });
  const counter = el("div", { class: "race__counter", text: "candidates tested: 0" });
  col.append(counter, out);
  col.append(
    button("Scan for obvious password encodings", () => {
      out.replaceChildren();
      if (size.fields === 0) {
        counter.textContent = "candidates tested: 0 — nothing captured to scan";
        out.append(
          el("p", { class: "race__verdict race__verdict--amber", text: "No transcript captured yet: 0 wire fields, 0 bytes. Run a handshake first — a scan of nothing is not a clean result." }),
        );
        return;
      }
      let n = 0;
      let leaks = 0;
      for (const guess of DICTIONARY) {
        n++;
        const clean = auditTranscript(transcript, makePassword(guess)).clean;
        if (!clean) leaks++;
        out.append(
          el("div", { class: "guess guess--neutral" }, [
            el("code", { text: guess }),
            el("span", { text: clean ? "no literal encoding found in any wire field" : "unexpected leak — investigate" }),
          ]),
        );
      }
      counter.textContent = `candidates tested: ${n}`;
      out.append(
        leaks === 0
          ? el("p", { class: "race__verdict race__verdict--neutral", text: `No literal encoding leak found: ${n} candidates checked against ${size.fields} wire field(s), ${size.bytes} bytes, in 5 encodings.` })
          : el("p", { class: "race__verdict race__verdict--amber", text: `${leaks} candidate(s) appeared in the transcript — that is a real leak in this build, not the expected result.` }),
      );
      out.append(
        el("p", { class: "race__claim", text: "That is a leak audit, not a proof. The stronger claim — that a passive PAKE transcript gives an attacker no offline password test at all, so every guess costs one live handshake against a server that can rate-limit — rests on the protocol's security analysis (RFC 5054 / RFC 8236 / draft-irtf-cfrg-cpace-21), not on this byte scan. A password can be absent as a literal byte sequence while a flawed protocol still leaks a password-dependent test." }),
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
  const { wrap, input } = labeledInput(`Extra candidates to add to the wordlist (comma or space separated, up to ${MAX_EXTRA_CANDIDATES} per run)`, {
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
      const { extras, dropped } = parseExtraGuesses(input.value);
      const dict: string[] = [...DICTIONARY, ...extras];
      const p = SRP_TRACK2_4096_SHA256;
      let n = 0;
      let hit = false;
      const t0 = performance.now();
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
      const elapsedMs = performance.now() - t0;
      counter.textContent = `candidates tested: ${n}${extras.length > 0 ? ` (${DICTIONARY.length} wordlist + ${extras.length} yours)` : ""}`;
      if (dropped > 0) {
        out.append(
          el("p", { class: "race__sub", text: `${dropped} extra candidate(s) over the ${MAX_EXTRA_CANDIDATES}-per-run cap were not tested — each test is a real 4096-bit modular exponentiation on this thread, and an unbounded list would freeze the page. A real attacker has no such cap.` }),
        );
      }
      // The rate is MEASURED from the loop that just ran, in this tab, on this
      // machine. It used to read "billions of candidates per GPU-day" — a figure
      // nothing in the lab computes and nothing here can support.
      const perSec = elapsedMs > 0 ? (n / elapsedMs) * 1000 : 0;
      const rate = `${n} candidate${n === 1 ? "" : "s"} in ${elapsedMs.toFixed(0)} ms — about ${perSec.toFixed(0)} per second (${(perSec * 86400).toExponential(1)} per day) on one thread in this browser tab. Local demonstration speed, not a GPU benchmark: each candidate here is one 4096-bit modular exponentiation, and a real attacker parallelises it across cores and machines.`;
      out.append(
        hit
          ? el("p", { class: "race__verdict race__verdict--amber", text: "Recovered — and note it was not 'the password read off the wire'. The stolen verifier handed the attacker a free offline test, and this candidate satisfied it." })
          : el("p", { class: "race__verdict race__verdict--neutral", text: `No match in ${n} candidates. The attacker has learned only that the password is outside this list — and can keep going, offline, at its own pace with no server to rate-limit it. That is the real cost of a breached augmented-PAKE verifier: it does not stop the attack, it only makes it as expensive as your password is unguessable.` }),
      );
      out.append(el("p", { class: "race__rate", text: rate }));
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
