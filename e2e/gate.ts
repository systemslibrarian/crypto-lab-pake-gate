import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/** The four protocol tabs, in the order the tablist presents them. */
export const PROTOCOLS = ['srp6a', 'jpake', 'cpace', 'dragonfly'] as const;

/** The three tabs that ship DISABLED until "Go deeper" is pressed inside SRP-6a. */
export const GATED_TABS = ['jpake', 'cpace', 'dragonfly'] as const;

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `killMotion()` pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`, which BYPASSED this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *     That block is load-bearing on this page: `styles.css` runs two keyframe
 *     animations that fire on every single protocol step — `wcard-lift`, which
 *     starts at `opacity: 0` and lifts the newest wire card onto the Wire, and
 *     `lock-pulse`, which scales the sending peer's padlock. `wcard-lift`
 *     STARTS INVISIBLE, so the interesting question is precisely whether the
 *     reduced-motion block leaves the card at its end state or strands it at
 *     `opacity: 0`; an injected `animation: none` answers a different question.
 *     `boot` asks for the preference and ASSERTS it took effect, and
 *     `expectNotBlank` then measures the outcome in every driven state.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. `revealAll()` set `open` on every `<details>`
 *     and stripped `hidden` from every element carrying it. On this page the only
 *     thing wearing `hidden` is `.tabs__gate` — the note that says the other three
 *     protocols are locked — so `revealAll()` assembled a document in which the
 *     lock note is showing AND the tabs are unlocked, a combination no visitor can
 *     reach. This gate never touches `hidden` or `open`; the gate note disappears
 *     because "Go deeper" was pressed.
 *
 *  3. IT SCANNED ONCE, AT ONE VIEWPORT, AFTER THE WHOLE DRIVE. The old spec drove
 *     all four tabs and every launcher and then called `scan()` exactly once, on
 *     whatever the last tab happened to leave on screen — so the SRP breach panel,
 *     the offline-grind race, the tamper menu, every aborted handshake and every
 *     red verdict were built and then thrown away unmeasured. It also never
 *     resized: the 380px column, where `.split` collapses to one track and
 *     `.controls__stepper` becomes a sticky bottom bar, had never been scanned at
 *     all. This drive scans after every step, in {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Two things on this page
 *     are invisible to a violations-only assertion in particular: the hero aside
 *     and every wire caption sit on `color-mix(in oklab/srgb, var(--accent) N%,
 *     transparent)` over an unknown backdrop, which axe files under `incomplete`;
 *     and an `aria-label` on a role-less element is PROHIBITED and lands in
 *     `incomplete` too, never in `violations` — a live risk here, because
 *     `peerPanel.ts` puts an `aria-label` on a `<span>` and makes it legal only by
 *     also setting `role="note"`.
 *
 *  5. ITS ONE NON-TEXT CHECK WAS SELF-CONFIRMING, AND IT HAD NO REFLOW ORACLE.
 *     `minimumControlBoundaryRatio()` measured `input.field__input:visible` — and
 *     `.field__input` is the single selector in the whole stylesheet that uses
 *     `--control-line`, the token written for exactly that job and correctly
 *     applied there. Pointing a 1.4.11 check only at the place a rule is already
 *     kept is the same as not having it. Every BUTTON on this page drew its edge
 *     from `--line` / `--line-strong`, which are SURFACE dividers, and none of
 *     them had ever been measured. That check is deleted rather than repaired:
 *     `nontext.ts` strictly supersets it (same composite model, every control
 *     shape, plus outlines, plus generated content).
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Wait out this lab's one self-scheduled DOM mutation.
 *
 * `TabView.markPublished` starts a 1400ms `setTimeout` after every step that
 * crosses a message; when it fires it re-renders BOTH peer panels to drop the
 * `.scratch--stayed` pulse class. A scan started before that fires would have the
 * DOM replaced underneath axe halfway through, which is a flake, not a
 * measurement. Waiting for the class to disappear is a real completion signal for
 * that timer rather than a sleep, and it means every scan measures the settled
 * rendering a reader is left looking at.
 */
async function quiesceLab(page: Page): Promise<void> {
  await expect(page.locator('.scratch--stayed')).toHaveCount(0, { timeout: 10_000 });
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page is a genuine candidate rather than a theoretical one. `wcard-lift`
 * runs on `.wcard--new`, the card the newest protocol message lands in, and its
 * `from` frame is `opacity: 0`. This lab's reduced-motion block clamps
 * `animation-duration` to `0.01ms` and `animation-iteration-count` to 1 rather
 * than setting `animation: none`, so the animation still runs — instantly — and
 * lands on its `to` frame, `opacity: 1`. That is the safe shape, and this
 * assertion is what makes it a measurement instead of a reading: it runs in every
 * driven state, and every driven state that steps the protocol paints a
 * `.wcard--new`.
 *
 * `aria-hidden` subtrees are excluded, matching the boundary `contrast.ts` draws.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * This lab needs the outcome asserted rather than assumed, because it has a
 * second `<header>`: `tabs.ts` builds the hero as `<header class="cl-hero">`
 * inside `<section class="intro">` inside `<main id="app">`. Sectioning content
 * scopes a `<header>` out of the banner role on its own, and `index.html`'s
 * `dedupeBanner()` skips it for exactly that reason (`el.closest('main, …')`
 * returns early). Two independent mechanisms therefore have to agree, and the
 * hero is one refactor away from being lifted out of `<main>`. Asserting the
 * OUTCOME catches that; asserting either mechanism would not.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * An explicit `role` on a `<ul>`/`<ol>` REPLACES its implicit `list` role and
 * orphans every `<li>` inside it, which axe then reports once per child.
 *
 * A source grep cannot see this class reliably, because this lab assigns every
 * attribute as a JS property bag through `dom.ts`'s `el()` — `el('ul', { class:
 * 'legend', 'aria-label': … })` has no `<ul` anywhere near the word `role`. The
 * page is already open, so ask the DOM instead. Two lists here are one keystroke
 * from the defect: `tabs.ts`'s `.legend` (three `<li>` explaining the split view)
 * and `dragonbloodPanel.ts`'s `.dblood__notes` (four `<li>` of measured findings).
 */
export async function expectListSemanticsIntact(page: Page, label: string): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els.map(
      (e) =>
        `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
    )
  );
  expect(broken, `an explicit role on a list deletes its list semantics in state: ${label}`).toEqual(
    []
  );
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')` and the shared header's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice. The old gate reached light by CLICKING the toggle,
 * which cannot tell those two apart.
 *
 * The defaults are asserted at length because this lab's shipped state is a
 * PROGRESSIVE-DISCLOSURE state, and which half of the page a gate sees depends
 * entirely on it. On arrival: SRP-6a is the only selectable protocol, the other
 * three tabs are `disabled`, the `.tabs__gate` note explaining that is showing,
 * the launcher row holds only "Honest run" and "Wrong password" (the observer,
 * tamper, breach and Dragonblood launchers do not exist in the DOM yet), the
 * peer panels are in plain-language label mode rather than notation mode, no
 * handshake has run, and the verdict is `--pending`. Every one of those is a
 * fork whose other branch a gate that assumed the defaults would never see.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await expect(page.locator('#app .app')).toBeVisible();
  await assertSingleBanner(page);

  // ── The progressive-disclosure default, asserted rather than assumed ──────
  await expect(page.locator('#tab-srp6a')).toHaveAttribute('aria-selected', 'true');
  for (const id of GATED_TABS) {
    await expect(page.locator(`#tab-${id}`)).toBeDisabled();
    await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-selected', 'false');
  }
  await expect(page.locator('.tabs__gate')).toBeVisible();

  // Only the two guided launchers exist; the other four are not in the DOM.
  await expect(page.locator('.btn--launcher')).toHaveCount(2);
  await expect(page.locator('.btn--launcher').nth(0)).toHaveText('Honest run');
  await expect(page.locator('.btn--launcher').nth(1)).toHaveText('Wrong password');
  await expect(page.getByRole('button', { name: /Go deeper/ })).toBeVisible();

  // ── Nothing has run ──────────────────────────────────────────────────────
  await expect(page.locator('#srp6a-pw1')).toHaveValue('');
  await expect(page.locator('.toggle__cb')).not.toBeChecked();
  await expect(page.locator('.wire__empty')).toBeVisible();
  await expect(page.locator('.verdict')).toHaveClass(/verdict--pending/);
  await expect(page.locator('.status__pill')).toHaveText('Step 1 of 5 ready.');
  await expect(page.locator('.keys__reveal')).toHaveText('reveal demo bytes');
  await expect(page.locator('.keys__reveal')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('.keycard__none')).toHaveCount(2);
  // No auxiliary panel exists until a launcher builds one.
  await expect(page.locator('.aux > *')).toHaveCount(0);

  // The taxonomy matrix is static content and is on the page from first paint —
  // it is the widest thing this lab renders (a 900px `min-width` table) and the
  // reflow oracle needs it present in every state, not just late ones.
  await expect(page.locator('.matrix tbody tr')).toHaveCount(5);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page has
 * three shapes that break it: the taxonomy matrix (`min-width: 900px`), the
 * Dragonblood plot (`min-width: max-content` across six candidate groups), and
 * every hex value on the page (`white-space: nowrap` over a full 64-hex-char
 * key). Each is meant to scroll inside its own container; the assertion here is
 * that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has a decoy behind every `.taxonomy__scroll`, `.dblood__scroll` and
    // `.hexbox__value`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab knows about the pattern and applies it by hand in four places —
 * `dom.ts`'s `hexBox()`, `taxonomyPanel.ts`'s `.taxonomy__scroll`,
 * `attacker.ts`'s `.attacker__raw` and `dragonbloodPanel.ts`'s `.dblood__scroll`
 * — which is a convention, not an enforcement. The assertion matters most in the
 * states the drive has to build: `.rawmsg__hex` and `.breach__dump-row code` are
 * `white-space: nowrap` blocks that only overflow once a transcript exists, and
 * `.tabs` itself becomes a horizontal scroller only once all four protocol tabs
 * are unlocked at 380px.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run with it
 * set prints every finding as it happens and then FAILS at the end, so a green
 * collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node.
 *
 * IT IS CALLED FROM `scan()`. In the reference gate this fleet was copied from it
 * was reachable only from inside the scroller check, AFTER that function's
 * `if (!COLLECTING) return` guard, so it never executed in a strict run and every
 * "no new non-text failures" claim was vacuous.
 *
 * The ratchet: anything NOT in the baseline fails, anything in the baseline that
 * got WORSE fails, and anything in the baseline that has been FIXED fails until
 * its entry is deleted. That last rule is what stops the allowlist becoming a
 * permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(
        `NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`
      );
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters here because the hero aside, every
 *    `.wcard__caption` and the `.matrix__row--ref` highlight are all
 *    `color-mix(… var(--accent) N%, transparent)` that axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not finish
 *    — including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides, a defect that never reaches the violations array at
 *    all. That one is live here: `peerPanel.ts` puts an `aria-label` on a
 *    `<span>` and makes it legal with `role="note"`, and the role is easy to drop.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast + generated content — SC 1.4.11, which axe has no rule for.
 *  - list semantics — see `expectListSemanticsIntact`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await quiesceLab(page);
  await settle(page);
  await expectNotBlank(page, label);

  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe therefore runs those
  // FOUR best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them, and this page has
  // the shape they catch: a shared sticky `<header role="banner">` above a
  // `<main>` that contains a second `<header>` (the hero) with an
  // `<aside class="cl-hero-why">` inside it, plus a second `<aside>` — the
  // session-key column — inside every tab panel.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectListSemanticsIntact(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Click a launcher by its exact label and wait for the rerender it triggers. */
async function launcher(page: Page, label: string): Promise<void> {
  await page.getByRole('button', { name: label, exact: true }).click();
}

/**
 * Drive the lab through every state it renders, scanning each.
 *
 * Seven things shape this drive:
 *
 *  - THE GUIDED DEFAULT IS SCANNED FIRST, AND IT IS SCANNED AS SHIPPED. Three of
 *    the four tabs are `disabled`, four of the six launchers do not exist in the
 *    DOM, and the peer rows are in plain-language mode. That is the state every
 *    first-time reader meets, and the gate this replaces pressed "Go deeper"
 *    before it looked at anything.
 *
 *  - THE LOCKED STATE IS MEASURED BEFORE THE UNLOCK. Each gated tab is asserted
 *    `disabled` with the `.tabs__gate` note showing, scanned, and only then
 *    unlocked — so the "before" rendering, which is what a reader arrives in, is
 *    measured as well as the "after".
 *
 *  - BOTH OUTCOMES OF EVERY FORK. "Honest run" paints `verdict--ok` /
 *    `status__pill--ok`; "Wrong password" paints `verdict--alarm` /
 *    `status__pill--alarm` and, on the balanced protocols, an aborted wire card
 *    with `.wcard--abort` and `.wcard__badge--abort`. Both are driven on every
 *    protocol, because the alarm palette (`--alarm`, `--alarm-bg`, `--alarm-line`)
 *    is painted nowhere else.
 *
 *  - THE STATES ONLY AN EDIT REACHES. Typing into a password field after a run
 *    calls `invalidateRun()`, which discards the result and paints
 *    `.status__expect--stale` — an ink (`--ink` at weight 700) that no other
 *    state on the page uses. It is reachable only by editing, never by clicking.
 *
 *  - EVERY AUXILIARY PANEL, ON THE PROTOCOL THAT OWNS IT. The observer panel and
 *    its `.attacker__audit.ok` / `.bad` banners; the curated tamper menu, both
 *    disarmed and ARMED (which is the only route to `.tamper__op.is-active`, the
 *    amber-tinted row, and to a tampered/rejected wire card); the SRP breach
 *    panel with its two-column offline grind, `.guess--hit` / `.guess--miss`
 *    rows and the economics table; the balanced breach note; and the Dragonblood
 *    plot, including a bar selected so `.plot__pick.is-active` and the
 *    `role="status"` explainer are both live.
 *
 *  - THE VIEW TOGGLES ON BOTH SIDES. "reveal demo bytes" expands two full 64-hex
 *    session keys into `.hexbox` scrollers — the only state where the keys are
 *    long enough to overflow — and "Wire only" removes both scratchpads, which is
 *    a different layout, not a different colour.
 *
 *  - NO FIXED TIMEOUTS. Every runner is synchronous, and the one asynchronous
 *    thing on the page — `markPublished`'s 1400ms pulse timer — has a DOM
 *    completion signal (`.scratch--stayed` disappearing) that `scan` waits on.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, guided view, three protocols locked');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── SRP-6a, still in the guided view ─────────────────────────────────────
  await page.fill('#srp6a-pw1', 'hunter2');
  await launcher(page, 'Honest run');
  await expect(page.locator('.verdict')).toHaveClass(/verdict--ok/);
  await expect(page.locator('.status__pill--ok')).toBeVisible();
  // Five protocol steps, four of which put a message on the wire — the client's
  // final confirmation check consumes the server's proof rather than sending one.
  await expect(page.locator('.wcard')).toHaveCount(4);
  await expect(page.locator('.keycard__flag--ok')).toHaveCount(2);
  await scanAt('SRP-6a honest run confirmed, guided view');

  // Two full 64-hex keys in scrollable hex boxes — the only state where the
  // session keys are long enough to overflow their container.
  await page.locator('.keys__reveal').click();
  await expect(page.locator('.keys__reveal')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.keys__warn')).toBeVisible();
  await scanAt('session key bytes revealed');
  await page.locator('.keys__reveal').click();
  await expect(page.locator('.keys__reveal')).toHaveAttribute('aria-pressed', 'false');

  await launcher(page, 'Wrong password');
  await expect(page.locator('.verdict')).toHaveClass(/verdict--alarm/);
  await expect(page.locator('.status__pill--alarm')).toBeVisible();
  await scanAt('SRP-6a wrong password, red alarm');

  // Editing a password after a run discards it — the only route to the stale note.
  await page.fill('#srp6a-pw1', 'hunter2x');
  await expect(page.locator('.status__expect--stale')).toBeVisible();
  await expect(page.locator('.wire__empty')).toBeVisible();
  await scanAt('password edited, previous result discarded');

  // Register rebuilds the verifier record and resets the run.
  await page.getByRole('button', { name: 'Register {salt, v}', exact: true }).click();
  await expect(page.locator('.status__expect--stale')).toHaveCount(0);
  await expect(page.locator('.wire__empty')).toBeVisible();
  await scanAt('verifier re-registered, run reset');

  // Single-stepping: a mid-handshake state no launcher produces.
  await page.getByRole('button', { name: 'Step ▸', exact: true }).click();
  await expect(page.locator('.wcard')).toHaveCount(1);
  await expect(page.locator('.status__pill')).toHaveText('Step 2 of 5 ready.');
  await scanAt('stepped one message, handshake mid-flight');

  await page.locator('.toggle__cb').check();
  await expect(page.locator('.scratch')).toHaveCount(0);
  await scanAt('wire-only view, both scratchpads hidden');
  await page.locator('.toggle__cb').uncheck();

  await page.getByRole('button', { name: 'Reset', exact: true }).click();
  await expect(page.locator('.wire__empty')).toBeVisible();
  await expect(page.locator('.verdict')).toHaveClass(/verdict--pending/);
  await scanAt('reset back to the empty handshake');

  // ── Go deeper: notation labels, four more launchers, three tabs unlocked ──
  for (const id of GATED_TABS) await expect(page.locator(`#tab-${id}`)).toBeDisabled();
  await page.getByRole('button', { name: /Go deeper/ }).click();
  await expect(page.locator('.btn--launcher')).toHaveCount(5);
  await expect(page.locator('.tabs__gate')).toBeHidden();
  for (const id of GATED_TABS) await expect(page.locator(`#tab-${id}`)).toBeEnabled();
  await expect(page.getByRole('button', { name: /Back to simple view/ })).toBeVisible();
  await scanAt('deep view unlocked, notation labels, all protocols available');

  await drivePanels(page, scanAt, 'srp6a');

  // Back to the guided view — a return path, not just a one-way reveal.
  await page.getByRole('button', { name: /Back to simple view/ }).click();
  await expect(page.locator('.btn--launcher')).toHaveCount(2);
  await expect(page.locator('.aux > *')).toHaveCount(0);
  await scanAt('returned to the guided view after going deep');

  // ── The other three protocols ────────────────────────────────────────────
  for (const id of GATED_TABS) {
    await page.locator(`#tab-${id}`).click();
    await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-selected', 'true');
    // A gated protocol can only be reached after the unlock, so it opens
    // directly in deep mode with every launcher present.
    await expect(page.locator('.btn--launcher')).toHaveCount(id === 'dragonfly' ? 6 : 5);
    await scanAt(`${id} tab opened in deep mode`);

    await launcher(page, 'Honest run');
    await expect(page.locator('.verdict')).toHaveClass(/verdict--ok/);
    await scanAt(`${id} honest run confirmed`);

    await launcher(page, 'Wrong password');
    await expect(page.locator('.verdict')).toHaveClass(/verdict--alarm/);
    await scanAt(`${id} wrong password, keys diverge`);

    await drivePanels(page, scanAt, id);
  }
}

/**
 * The four auxiliary panels, driven on whichever protocol is currently selected.
 *
 * They are reachable only in deep mode, and two of them differ by protocol: the
 * breach launcher renders the SRP verifier dump plus the offline-grind race on
 * `srp6a` and the balanced-PAKE note everywhere else, and the Dragonblood panel
 * exists only on `dragonfly`. Both branches are driven rather than one.
 */
async function drivePanels(
  page: Page,
  scanAt: (s: string) => Promise<void>,
  id: string
): Promise<void> {
  // Observer. Its audit banner is `.ok` on a clean transcript; the drive gets
  // there from whatever run is currently on screen rather than assuming one.
  await launcher(page, 'On-path observer');
  await expect(page.locator('.attacker')).toBeVisible();
  await expect(page.locator('.attacker__raw .rawmsg').first()).toBeVisible();
  await expect(page.locator('.attacker__audit')).toBeVisible();
  await scanAt(`${id} on-path observer, raw transcript bytes`);

  // Tamper menu, disarmed then ARMED. Arming is the only route to
  // `.tamper__op.is-active` (amber-tinted), to `.wcard--tampered` /
  // `.wcard__badge--tamper`, and to the `.wcard--abort` rejection card.
  await launcher(page, 'Active tamper (menu)');
  await expect(page.locator('.tamper__menu')).toBeVisible();
  const ops = page.locator('.tamper__op');
  expect(await ops.count(), `${id} must offer at least one tamper op`).toBeGreaterThan(0);
  await expect(page.locator('.tamper__op.is-active')).toHaveCount(0);
  await scanAt(`${id} tamper menu shown, nothing armed`);

  await ops.first().getByRole('button', { name: 'Arm & run', exact: true }).click();
  await expect(page.locator('.tamper__op.is-active')).toHaveCount(1);
  // How many cards carry the tamper badge is protocol-dependent — a flipped
  // nibble in a CPace round-1 field is carried forward into the message that
  // quotes it — so the assertion is that the tamper is VISIBLE on the wire and
  // that the handshake failed closed, not an exact card count.
  await expect(page.locator('.wcard--tampered').first()).toBeVisible();
  await expect(page.locator('.wcard--abort')).toHaveCount(1);
  await expect(page.locator('.wcard__badge--tamper').first()).toBeVisible();
  await expect(page.locator('.wcard__badge--abort')).toHaveCount(1);
  await expect(page.locator('.verdict--alarm')).toBeVisible();
  await scanAt(`${id} tamper armed, handshake failed closed`);

  await page.locator('.tamper__op.is-active').getByRole('button', { name: '✓ armed' }).click();
  await expect(page.locator('.tamper__op.is-active')).toHaveCount(0);
  await scanAt(`${id} tamper disarmed`);

  // Breach. Two different panels behind one launcher label.
  if (id === 'srp6a') {
    // A wordlist password, so the offline grind can land a real hit. The
    // attacker's dictionary is fixed and built without reference to the demo
    // password, so BOTH outcomes are reachable and both are driven below.
    //
    // Register, not just type: the panel grinds against the STORED verifier
    // record, and `freshRunner()` keeps an existing `srpRecord` rather than
    // rebuilding it, so typing a new password alone leaves the record — and
    // therefore the attack — pointed at the old one.
    await page.fill('#srp6a-pw1', 'hunter2');
    await page.getByRole('button', { name: 'Register {salt, v}', exact: true }).click();
    await launcher(page, 'Server breach');
    await expect(page.locator('.breach')).toBeVisible();
    await expect(page.locator('.breach__dump-row')).toHaveCount(3);
    await expect(page.locator('.economics__row')).toHaveCount(3);
    await expect(page.locator('.guess')).toHaveCount(0);
    await scanAt('srp6a server breach, {salt, v} dumped, nothing ground yet');

    // The passive column with NOTHING captured: it refuses to answer rather
    // than printing ten clean rows against zero wire bytes. That refusal is a
    // state of its own, with its own amber verdict ink.
    await page.getByRole('button', { name: 'Scan for obvious password encodings' }).click();
    await expect(page.locator('.race__counter').first()).toHaveText(/nothing captured to scan/);
    await expect(page.locator('.race__verdict--amber')).toHaveCount(1);
    await scanAt('srp6a passive scan refused, no transcript captured');

    // The grind itself, with a learner-typed candidate added to the wordlist.
    await page.fill('#srp-extra-guesses', 'battery, staple');
    await page.getByRole('button', { name: 'Run offline grind' }).click();
    await expect(page.locator('.guess--hit')).toHaveCount(1);
    await expect(page.locator('.guess--miss').first()).toBeVisible();
    await expect(page.locator('.race__rate')).toBeVisible();
    await scanAt('srp6a offline grind recovered the password');

    // A password outside the wordlist — the same attack honestly finds nothing,
    // which is the other verdict ink and the lesson the panel is actually for.
    await page.fill('#srp6a-pw1', 'v0ndtqz-outside-every-list');
    await page.getByRole('button', { name: 'Register {salt, v}', exact: true }).click();
    await expect(page.locator('.aux > *')).toHaveCount(0);
    await launcher(page, 'Server breach');
    await page.getByRole('button', { name: 'Run offline grind' }).click();
    await expect(page.locator('.guess--hit')).toHaveCount(0);
    await expect(page.locator('.guess--miss')).toHaveCount(10);
    await expect(page.locator('.race__verdict--neutral')).toHaveCount(1);
    await scanAt('srp6a offline grind found nothing, password outside the wordlist');

    // And the passive scan over a transcript that exists.
    await launcher(page, 'Honest run');
    await launcher(page, 'Server breach');
    await page.getByRole('button', { name: 'Scan for obvious password encodings' }).click();
    await expect(page.locator('.guess--neutral')).toHaveCount(10);
    await expect(page.locator('.race__claim')).toBeVisible();
    await scanAt('srp6a passive transcript scanned, no literal encoding leak');
  } else {
    await launcher(page, 'Server breach (balanced lesson)');
    await expect(page.locator('.breach--balanced')).toBeVisible();
    await scanAt(`${id} balanced-PAKE breach note`);
  }

  if (id === 'dragonfly') {
    await launcher(page, 'Dragonblood side-channel');
    await expect(page.locator('.dblood')).toBeVisible();
    await expect(page.locator('.plot__pick')).toHaveCount(6);
    await expect(page.locator('.dblood__explain')).not.toBeEmpty();
    await scanAt('dragonfly Dragonblood plot, first candidate explained');

    // Selecting a bar is the only route to `.plot__pick.is-active`.
    await page.locator('.plot__pick').nth(3).click();
    await expect(page.locator('.plot__pick.is-active')).toHaveCount(1);
    await scanAt('dragonfly Dragonblood candidate selected');
  }
}
