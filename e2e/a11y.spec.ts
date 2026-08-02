import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. The palette is driven by html[data-theme], toggled by
 * the shared header's #cl-theme-toggle button; dark is the default and light is
 * reached by clicking the toggle (matching the ascon/vdf pattern). The lab opens
 * in a guided "simple" view with only SRP-6a available and the other three
 * protocols gated behind "Go deeper"; we press it first to unlock everything,
 * then drive every protocol tab and reveal every auxiliary panel (observer /
 * tamper menu / server breach / dragonblood) so the dynamically injected result
 * regions are all in the DOM.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const TAB_IDS = ['srp6a', 'jpake', 'cpace', 'dragonfly'] as const;

async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{transition:none!important;animation:none!important}`,
  });
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) d.open = true;
    for (const h of document.querySelectorAll('[hidden]')) h.removeAttribute('hidden');
  });
}

async function clickLaunchers(page: Page): Promise<void> {
  // Within the currently-selected tab, click every scripted launcher so each
  // auxiliary panel and the tamper menu are populated and rendered.
  const labels = [
    'Honest run',
    'Wrong password',
    'On-path observer',
    'Active tamper (menu)',
    'Server breach',
    'Server breach (balanced lesson)',
    'Dragonblood side-channel',
  ];
  for (const label of labels) {
    const btn = page.getByRole('button', { name: label, exact: true });
    if (await btn.count()) {
      await btn.first().click();
    }
  }
  // Reveal the key fingerprint if there is a reveal control.
  const reveal = page.getByRole('button', { name: /reveal/i });
  if (await reveal.count()) {
    await reveal.first().click();
  }
}

async function unlockDeep(page: Page): Promise<void> {
  // The guided default gates the other three protocols and the aux panels behind
  // "Go deeper" (shown in the SRP-6a tab, which opens first). Press it to reveal
  // the full surface the scan needs.
  const deeper = page.getByRole('button', { name: /Go deeper/i });
  if (await deeper.count()) {
    await deeper.first().click();
  }
  await expect(page.locator('#tab-jpake')).not.toBeDisabled();
}

async function driveAllTabs(page: Page): Promise<void> {
  for (const id of TAB_IDS) {
    await page.locator(`#tab-${id}`).click();
    await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-selected', 'true');
    await clickLaunchers(page);
  }
}

/**
 * WCAG 1.4.11 (non-text contrast) regression for text-entry control boundaries.
 * Axe does not flag low-contrast control borders, so we measure them directly:
 * for every visible text input the rendered border color must reach 3:1 against
 * both the control's own fill and the first opaque ancestor surface behind it.
 * Translucent colors are composited against those real surfaces before the
 * ratio is taken.
 */
async function minimumControlBoundaryRatio(page: Page): Promise<number> {
  return page.locator('input.field__input:visible').evaluateAll((elements) => {
    const parse = (value: string): { c: number[]; a: number } => {
      const n = (value.match(/[\d.]+/g) ?? ['0', '0', '0']).map(Number);
      return { c: n.slice(0, 3), a: n.length > 3 ? n[3] : 1 };
    };
    const luminance = (parts: number[]): number => {
      const c = parts.map((part) => {
        const v = part / 255;
        return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
    };
    const ratio = (a: number[], b: number[]): number => {
      const [la, lb] = [luminance(a), luminance(b)];
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const composite = (fg: number[], alpha: number, bg: number[]): number[] =>
      fg.map((v, i) => v * alpha + bg[i] * (1 - alpha));
    const surfaceBehind = (el: Element): number[] => {
      for (let node = el.parentElement; node; node = node.parentElement) {
        const bg = parse(getComputedStyle(node).backgroundColor);
        if (bg.a >= 1) return bg.c;
      }
      return [255, 255, 255];
    };
    return Math.min(
      ...elements.map((el) => {
        const style = getComputedStyle(el);
        const exterior = surfaceBehind(el);
        const bg = parse(style.backgroundColor);
        const fill = bg.a >= 1 ? bg.c : composite(bg.c, bg.a, exterior);
        const b = parse(style.borderTopColor);
        const border = b.a >= 1 ? b.c : composite(b.c, b.a, fill);
        return Math.min(ratio(border, fill), ratio(border, exterior));
      }),
    );
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#app .app')).toBeVisible();
  await killMotion(page);
  await unlockDeep(page);
  await driveAllTabs(page);
  await revealAll(page);
  expect(await minimumControlBoundaryRatio(page)).toBeGreaterThanOrEqual(3);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#app .app')).toBeVisible();
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await killMotion(page);
  await unlockDeep(page);
  await driveAllTabs(page);
  await revealAll(page);
  expect(await minimumControlBoundaryRatio(page)).toBeGreaterThanOrEqual(3);
  await scan(page);
});
