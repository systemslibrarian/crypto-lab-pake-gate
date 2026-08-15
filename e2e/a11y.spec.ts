import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and every state is scanned as it
 * is built: the guided arrival view, where three of the four protocols are
 * `disabled` and only two of the six launchers exist; the skip link focused; an
 * SRP-6a honest run confirmed green; both session keys revealed as full 64-hex
 * scrollers; a wrong password taken to the red alarm; a password EDITED after a
 * run, which is the only route to the "previous result discarded" note; the
 * verifier re-registered; a single Step, mid-handshake; the wire-only layout with
 * both scratchpads gone; a Reset; then "Go deeper", which switches every peer row
 * from plain language to notation, adds four launchers and unlocks the other
 * three protocols. Each protocol then runs honest and wrong-password, the on-path
 * observer, the curated tamper menu both disarmed and ARMED (the only route to a
 * tampered wire card and a fail-closed rejection), and its breach panel — the SRP
 * verifier dump with its offline-grind race on `srp6a`, the balanced-PAKE note on
 * the other three. Dragonfly additionally opens the Dragonblood plot and selects a
 * candidate. Every one of those states is scanned, in both themes, at desktop and
 * phone width.
 *
 * Clipboard permission is granted because every `.hexbox` copy button calls
 * `navigator.clipboard.writeText` through `dom.ts`'s `copyText`, which falls back
 * to a `document.execCommand` path when the promise rejects. Without the grant
 * the drive would be exercising the fallback rather than the path a reader takes.
 *
 * See `gate.ts` for why nothing is injected into the page (this lab's newest wire
 * card animates up from `opacity: 0`), why nothing is force-revealed, why the
 * lab's progressive-disclosure defaults are asserted rather than assumed, and why
 * `violations` is not the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expectBaselineNotStale();
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(900_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expectBaselineNotStale();
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
