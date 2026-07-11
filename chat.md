# What Else Would Make This Perfect

Quick baseline before suggesting anything else:

- Local validation is green: `npm test` passed 18 files / 91 tests, and `npm run lint` is clean.
- The repo already has strong crypto-specific quality signals: the wire/type barrier in [src/pake/types.ts](src/pake/types.ts#L1), tamper-path tests in [tests/tamper.test.ts](tests/tamper.test.ts), and structural accessibility checks in [tests/ui.axe.test.ts](tests/ui.axe.test.ts).

## Highest-value next steps

1. Add a top-level README with an explicit educational/non-production boundary.

Evidence:
The repo has no top-level README; the only README currently in tree is [tests/vectors/README.md](tests/vectors/README.md). The UI already contains a demo-only safety warning in [src/ui/keyPanel.ts](src/ui/keyPanel.ts#L48), but that warning is not visible on the GitHub landing page.

Why this matters:
This project is good enough that people may cargo-cult pieces of it. A repo-level warning, run instructions, and protocol summary should be the first thing they see.

Definition of done:
A root README covers purpose, supported PAKEs, local run/test commands, GitHub Pages/demo link, and a clear "teaching/demo, not production auth code" note.

2. Put lint into CI.

Evidence:
`lint` exists in [package.json](package.json#L13), but CI currently runs only typecheck, test, and build in [.github/workflows/ci.yml](.github/workflows/ci.yml#L18) and [.github/workflows/ci.yml](.github/workflows/ci.yml#L20).

Why this matters:
Your ESLint rules are carrying real security/discipline value in the crypto core; they should gate pull requests, not just local runs.

Definition of done:
Add `npm run lint` to the CI workflow before the build step.

3. Add one real-browser E2E lane.

Evidence:
Vitest is configured around a Node environment in [vitest.config.ts](vitest.config.ts#L5), and the current axe pass explicitly disables `color-contrast` and `region` in [tests/ui.axe.test.ts](tests/ui.axe.test.ts#L17) and [tests/ui.axe.test.ts](tests/ui.axe.test.ts#L18).

Why this matters:
The current UI tests are strong for logic and structure, but jsdom cannot prove layout, focus movement, responsive breakpoints, real tab behavior, or visual contrast.

Definition of done:
Add a small Playwright suite that covers initial render, keyboard tab navigation, honest run, wrong-password run, and one browser-based accessibility scan.

4. Add coverage reporting and thresholds.

Evidence:
[vitest.config.ts](vitest.config.ts) has no coverage configuration, and [package.json](package.json) has no coverage script.

Why this matters:
The suite is already substantial; the missing piece is a quantitative floor that keeps future refactors from creating silent blind spots.

Definition of done:
Enable V8 coverage, publish the summary in CI, and enforce thresholds with stricter floors for `src/pake/**` than for the teaching UI.

5. Widen CI runtime coverage slightly.

Evidence:
CI is pinned to Node 20 in [.github/workflows/ci.yml](.github/workflows/ci.yml#L15).

Why this matters:
This is a public demo with modern TypeScript and runtime-heavy crypto code. Catching engine drift one LTS ahead is cheap insurance.

Definition of done:
Run CI on a small Node matrix such as 20 and 22, or keep 20 required and run 22 as a scheduled/non-blocking job.

6. Turn the PQ seam from a documented seam into an executable proof.

Evidence:
The seam is clearly documented in [docs/pq-pake-seam.md](docs/pq-pake-seam.md) and typed in [src/pake/types.ts](src/pake/types.ts#L122), but `KemBackend` is still marked as "stubs only" in [src/pake/types.ts](src/pake/types.ts#L133).

Why this matters:
Right now the idea is clear to a reader. A tiny mock backend plus tests would make it clear to the compiler and to future contributors as well.

Definition of done:
Add a toy `KemBackend + PasswordKeyedEncoding` implementation and one test proving it composes through the seam while remaining non-interchangeable with `DhGroup`.

## Nice-to-have polish

7. Split the slowest tests into a second lane or document a fast path.

Evidence:
The current local run is green, but a few slices are materially slower than the rest: `tests/params.test.ts`, `tests/jpake.test.ts`, `tests/invariants.test.ts`, and `tests/grind.test.ts`.

Why this matters:
Contributor feedback loops stay sharper when the default path is fast and the heavier path is still easy to run intentionally.

Definition of done:
Expose something like `test:fast` and `test:full`, or tag the slow slice clearly in Vitest.

## Bottom line

I do not see an urgent correctness hole from this pass. The project already looks disciplined. The remaining gap to "perfect" is mostly repo hardening and presentation: better first-contact docs, stricter CI gates, a browser-realistic UI lane, numeric coverage floors, and an executable PQ seam example.