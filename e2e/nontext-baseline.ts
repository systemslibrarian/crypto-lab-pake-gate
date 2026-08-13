/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * ── What this file does NOT contain ─────────────────────────────────────────
 *
 * Everything this lab owns. A capture pass over {dark, light} × {1280, 380} and
 * all 44 driven states found ten distinct control-boundary failures in this
 * repo's own stylesheet — every button, every tab, both accent-filled controls
 * and the hex-box copy button. They were fixed rather than baselined, and the
 * measured before/after numbers are in the commit message. The gate now runs
 * with those ten gone and this file holding only what follows.
 *
 * ── The two entries below ───────────────────────────────────────────────────
 *
 * Both are the SHARED Crypto Lab top bar, which every repo in the fleet carries
 * an identical copy of, and neither is this repo's to change unilaterally:
 * `.cl-btn` draws its edge with `color-mix(in srgb, var(--accent) 38%,
 * transparent)` over the bar's fixed `#0b1512`, which composites to
 * rgb(80, 63, 107) and measures 2.00:1 against it.
 *
 * The ratio is IDENTICAL in both themes, and that is not a bug in the
 * measurement: the bar is always dark regardless of page theme, and `--accent`
 * is set once in `index.html` with no light override, so nothing in the
 * expression depends on `data-theme`. It is reported upward as a fleet-wide
 * observation rather than patched in one repo — a local fix here would diverge
 * this lab's header from the other ~175.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  'control-boundary|a.cl-btn': { ratio: 2, required: 3, unverified: false },
  'control-boundary|button#cl-theme-toggle.cl-btn.cl-icon': {
    ratio: 2,
    required: 3,
    unverified: false,
  },
};
