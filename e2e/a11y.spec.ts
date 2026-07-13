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
  await scan(page);
});
