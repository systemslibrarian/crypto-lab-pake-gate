import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. This lab has no runtime theme toggle — the palette is
 * driven entirely by prefers-color-scheme — so both themes are exercised via
 * colorScheme emulation. Before scanning we drive every protocol tab and reveal
 * every auxiliary panel (observer / tamper menu / server breach / dragonblood)
 * so the dynamically-injected result regions are all in the DOM.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const TAB_IDS = ['srp6a', 'jpake', 'cpace', 'dragonfly'] as const;

// Kill animations/transitions so nothing is mid-fade when axe measures contrast.
const NEUTRALIZE = `
  *, *::before, *::after {
    transition: none !important;
    animation: none !important;
  }
`;

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

async function driveAllTabs(page: Page): Promise<void> {
  for (const id of TAB_IDS) {
    await page.locator(`#tab-${id}`).click();
    await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-selected', 'true');
    await clickLaunchers(page);
  }
}

async function prepare(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#app .app')).toBeVisible();
  await page.addStyleTag({ content: NEUTRALIZE });
  await driveAllTabs(page);
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
  await page.emulateMedia({ colorScheme: 'dark' });
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await prepare(page);
  await scan(page);
});
