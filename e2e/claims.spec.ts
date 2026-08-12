import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate for the claims this page makes on screen.
 *
 * The a11y suite drives every control and asks axe whether the result is
 * reachable. This suite asks whether it is true: the green verdict is checked
 * against the two fingerprints the page derived and against the revealed key
 * bytes themselves, every tamper op in every protocol's curated menu is armed
 * and required to abort with a named reason, the step counter is checked against
 * the messages actually on the wire, and the offline-grind and side-channel
 * panels are checked against the numbers they themselves printed.
 */

const PROTOCOLS = ['srp6a', 'jpake', 'cpace', 'dragonfly'] as const;
type Protocol = (typeof PROTOCOLS)[number];

const TAB_LABEL: Record<Protocol, string> = {
  srp6a: 'SRP-6a',
  jpake: 'J-PAKE',
  cpace: 'CPace',
  dragonfly: 'Dragonfly',
};

// ---------------------------------------------------------------- guards

function guardPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(`console.error: ${msg.text()}`);
  });
  return errors;
}

test.beforeEach(async ({ page }) => {
  (test.info() as unknown as { _pageErrors: string[] })._pageErrors = guardPageErrors(page);
});

test.afterEach(async () => {
  const errors = (test.info() as unknown as { _pageErrors?: string[] })._pageErrors ?? [];
  expect(errors, 'page must raise no uncaught exceptions or console errors').toEqual([]);
});

// ---------------------------------------------------------------- helpers

function panel(page: Page): Locator {
  return page.locator('.tabs__panels .tabview');
}

/** Press "Go deeper" so the other protocols and the aux panels are reachable. */
async function goDeeper(page: Page): Promise<void> {
  const btn = panel(page).getByRole('button', { name: 'Go deeper ▾' });
  if (await btn.count()) await btn.click();
  await expect(panel(page).getByRole('button', { name: 'On-path observer' })).toBeVisible();
}

async function openTab(page: Page, protocol: Protocol, deep = false): Promise<void> {
  // The gated protocols are only reachable after "Go deeper", and they open in
  // deep mode; SRP-6a needs the press explicitly when a test wants the full
  // launcher set.
  if (protocol !== 'srp6a' || deep) await goDeeper(page);
  await page.getByRole('tab', { name: TAB_LABEL[protocol], exact: true }).click();
  await expect(page.locator(`#tab-${protocol}`)).toHaveAttribute('aria-selected', 'true');
}

async function statusPill(page: Page): Promise<string> {
  return ((await panel(page).locator('.status__pill').textContent()) ?? '').replace(/\s+/g, ' ');
}

async function verdictText(page: Page): Promise<string> {
  return ((await panel(page).locator('.verdict .verdict__text').textContent()) ?? '').replace(
    /\s+/g,
    ' ',
  );
}

async function fingerprints(page: Page): Promise<string[]> {
  return (await panel(page).locator('.keycard__fp-value').allTextContents()).map((s) => s.trim());
}

async function keyFlags(page: Page): Promise<string[]> {
  return (await panel(page).locator('.keycard__flag').allTextContents()).map((s) => s.trim());
}

/** The full key hex each side derived, with "reveal demo bytes" turned on. */
async function revealedKeys(page: Page): Promise<string[]> {
  const toggle = panel(page).locator('.keys__reveal');
  if ((await toggle.getAttribute('aria-pressed')) !== 'true') await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  const boxes = panel(page).locator('.keycard .hexbox__value');
  return (await boxes.allTextContents()).map((s) => s.trim());
}

// ---------------------------------------------------------------- honest run

for (const protocol of PROTOCOLS) {
  test(`${protocol}: an honest run confirms, and the green verdict is the derived keys`, async ({
    page,
  }) => {
    await page.goto('/');
    await openTab(page, protocol);
    await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();

    // The headline verdict.
    expect(await statusPill(page)).toBe('✓ Confirmed — password never left either box.');
    await expect(panel(page).locator('.verdict')).toHaveClass(/verdict--ok/);
    expect(await verdictText(page)).toBe('Key confirmed — password never left either box.');

    // ...and it must be backed by both sides' own derived material.
    const fps = await fingerprints(page);
    expect(fps, 'both sides must publish a fingerprint').toHaveLength(2);
    expect(fps[0], 'a confirmed run means both fingerprints are the same key').toBe(fps[1]);
    expect(fps[0]).not.toBe('');

    const flags = await keyFlags(page);
    expect(flags).toEqual(['✓ confirmed', '✓ confirmed']);

    const keys = await revealedKeys(page);
    expect(keys).toHaveLength(2);
    expect(keys[0], 'the revealed key bytes must be identical, not merely similar').toBe(keys[1]);
    expect(keys[0]).toMatch(/^[0-9a-f]+$/);
    expect(keys[0].length).toBeGreaterThanOrEqual(32);
    await expect(panel(page).locator('.keys__warn')).toContainText('Demo only');

    // The run is complete and every message it needed is on the wire.
    await expect(panel(page).locator('.wire__empty')).toHaveCount(0);
    await expect(panel(page).locator('.wcard--abort')).toHaveCount(0);
    await expect(panel(page).locator('.wcard__badge--abort')).toHaveCount(0);

    // The launcher's own documented expectation is shown alongside its result.
    await expect(panel(page).locator('.status__expect')).toContainText(
      'confirmed shared key (green success)',
    );
  });

  test(`${protocol}: a wrong password fails closed and says so`, async ({ page }) => {
    await page.goto('/');
    await openTab(page, protocol);
    await panel(page).getByRole('button', { name: 'Wrong password', exact: true }).click();

    const pill = await statusPill(page);
    expect(pill, 'a wrong password must not read as confirmed').not.toContain('✓ Confirmed');
    expect(pill, 'the failure must be flagged, not merely omitted').toMatch(/^⚠ /);
    await expect(panel(page).locator('.status__pill')).toHaveClass(/status__pill--alarm/);

    await expect(panel(page).locator('.verdict')).toHaveClass(/verdict--alarm/);
    const verdict = await verdictText(page);
    expect(verdict, 'the alarm must name a cause').toMatch(
      /Keys differ|Handshake aborted|Confirmation incomplete/,
    );

    // Neither side may claim confirmation, and no two matching keys may be shown.
    expect(await keyFlags(page)).not.toContain('✓ confirmed');
    const fps = await fingerprints(page);
    if (fps.length === 2) {
      expect(fps[0], 'two different passwords must not produce one key').not.toBe(fps[1]);
    }
    await expect(panel(page).locator('.status__expect')).toContainText('red alarm');
  });
}

// ---------------------------------------------------------------- stepping

test('the step counter counts the messages that are actually on the wire', async ({ page }) => {
  await page.goto('/');
  const p = panel(page);

  const idle = await statusPill(page);
  const m = /Step (\d+) of (\d+) ready\./.exec(idle);
  expect(m, `no step counter on an idle tab: ${idle}`).not.toBeNull();
  expect(Number(m![1]), 'an untouched tab is waiting on step 1').toBe(1);
  const total = Number(m![2]);
  expect(total).toBeGreaterThan(1);
  await expect(p.locator('.wcard')).toHaveCount(0);
  await expect(p.locator('.wire__empty')).toContainText('No messages yet');

  const step = p.getByRole('button', { name: 'Step ▸' });
  let seen = 0;
  for (let i = 1; i <= total; i++) {
    await step.click();
    // "Advance exactly one protocol message": a step may cross one message or
    // none (a purely local verification), but never more than one.
    const cards = await p.locator('.wcard').count();
    expect(cards - seen, `step ${i} crossed more than one message`).toBeGreaterThanOrEqual(0);
    expect(cards - seen, `step ${i} crossed more than one message`).toBeLessThanOrEqual(1);
    seen = cards;

    // ...and the counter must agree about how many steps are left.
    const pill = await statusPill(page);
    if (i < total) {
      expect(pill).toBe(`Step ${i + 1} of ${total} ready.`);
    } else {
      expect(pill, 'the last step must complete the run').toMatch(
        /All steps complete\.|✓ Confirmed/,
      );
    }
  }
  await expect(step).toBeDisabled();
  expect(seen, 'stepping through must actually put messages on the wire').toBeGreaterThan(0);

  // Stepping all the way through is the same handshake the launcher runs.
  await expect(p.locator('.verdict')).toHaveClass(/verdict--ok/);
  const fps = await fingerprints(page);
  expect(fps[0]).toBe(fps[1]);

  const steppedSteps = await p.locator('.wcard .wcard__step').allTextContents();
  await p.getByRole('button', { name: 'Honest run', exact: true }).click();
  expect(
    await p.locator('.wcard .wcard__step').allTextContents(),
    'one step at a time must produce the same transcript as the scripted run',
  ).toEqual(steppedSteps);

  // Reset must clear the transcript and the verdict together.
  await p.getByRole('button', { name: 'Reset' }).click();
  await expect(p.locator('.wcard')).toHaveCount(0);
  await expect(p.locator('.verdict')).toHaveClass(/verdict--pending/);
  expect(await statusPill(page)).toBe(`Step 1 of ${total} ready.`);
  await expect(step).toBeEnabled();
});

// ---------------------------------------------------------------- tampering

for (const protocol of PROTOCOLS) {
  test(`${protocol}: every curated tamper op aborts the handshake by name`, async ({ page }) => {
    test.slow();
    await page.goto('/');
    await openTab(page, protocol, true);
    await panel(page).getByRole('button', { name: 'Active tamper (menu)', exact: true }).click();

    const ops = panel(page).locator('.tamper__op');
    const count = await ops.count();
    expect(count, 'each protocol must offer at least one tamper op').toBeGreaterThan(0);

    for (let i = 0; i < count; i++) {
      const op = ops.nth(i);
      const label = ((await op.locator('strong').textContent()) ?? '').trim();
      const expected = ((await op.locator('.tamper__expect').textContent()) ?? '').trim();
      expect(expected, `${label} must document an expected outcome`).not.toBe('');

      await op.getByRole('button', { name: 'Arm & run' }).click();

      // The op must fail the handshake closed — never silently succeed.
      const pill = await statusPill(page);
      expect(pill, `tamper "${label}" must not still confirm`).not.toContain('✓ Confirmed');
      expect(pill, `tamper "${label}" must raise an alarm`).toMatch(/^⚠ /);
      expect(
        pill.replace(/^⚠ (Aborted — )?/, ''),
        `tamper "${label}" must name why it stopped`,
      ).not.toBe('');
      await expect(panel(page).locator('.verdict'), label).toHaveClass(/verdict--alarm/);
      // A tampered run may still leave ONE side believing it confirmed (SRP's
      // server verifies M1 before the client rejects the corrupted M2). What must
      // never happen is mutual confirmation — that is what the green badge means.
      const flags = await keyFlags(page);
      expect(
        flags.filter((f) => f === '✓ confirmed').length,
        `${label}: both sides must not confirm`,
      ).toBeLessThan(2);

      // The tampered message must be marked on the wire, and the rejecting card
      // must carry the reason rather than just a red border.
      await expect(panel(page).locator('.wcard--tampered'), label).not.toHaveCount(0);
      const rejected = panel(page).locator('.wcard--abort');
      if (await rejected.count()) {
        const reason = ((await rejected.first().locator('.wcard__abort-msg').textContent()) ?? '')
          .replace(/\s+/g, ' ')
          .trim();
        expect(reason, `${label}: the rejecting card must state a reason`).not.toBe('');
        expect(reason).toContain('—');
      }

      // Re-open the menu for the next op (arming re-renders the tab).
      await panel(page)
        .getByRole('button', { name: 'Active tamper (menu)', exact: true })
        .click();
    }
  });
}

// ---------------------------------------------------------------- regression

for (const protocol of PROTOCOLS) {
  test(`${protocol}: regression — editing the password discards the verdict it produced`, async ({
    page,
  }) => {
    // The runner captures the password when it is constructed, so a confirmed
    // result describes the password that was in the box at run time. Editing the
    // field afterwards used to leave the whole result surface standing — green
    // pill, "Key confirmed" badge, both "✓ confirmed" flags and both
    // fingerprints — describing a handshake for a password no longer on screen.
    await page.goto('/');
    await openTab(page, protocol);
    await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
    await expect(panel(page).locator('.verdict')).toHaveClass(/verdict--ok/);
    const before = await fingerprints(page);
    expect(before[0]).toBe(before[1]);

    const field = panel(page).locator(`#${protocol}-pw1`);
    // The launcher normalises the field to the password it ran with; append to it.
    const ran = await field.inputValue();
    await field.click();
    await field.press('End');
    await field.press('x');

    // Nothing computed from the old password may survive.
    expect(await statusPill(page), 'the green pill must go').not.toContain('✓ Confirmed');
    await expect(panel(page).locator('.verdict')).not.toHaveClass(/verdict--ok/);
    expect(await verdictText(page)).not.toContain('Key confirmed');
    expect(await keyFlags(page)).not.toContain('✓ confirmed');
    await expect(panel(page).locator('.keycard__fp-value')).toHaveCount(0);
    await expect(panel(page).locator('.wcard')).toHaveCount(0);

    // ...and the page must say why, rather than just going blank.
    await expect(panel(page).locator('.status__expect--stale')).toContainText(
      'Password changed — the previous result was discarded. Run it again.',
    );
    await expect(panel(page).locator('.status__expect--stale')).toBeVisible();

    // The edit must survive the invalidation (the controls are not rebuilt).
    await expect(field).toBeFocused();
    expect(await field.inputValue()).toBe(`${ran}x`);

    // Running again clears the notice and produces a fresh, valid verdict.
    await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
    await expect(panel(page).locator('.status__expect--stale')).toHaveCount(0);
    await expect(panel(page).locator('.verdict')).toHaveClass(/verdict--ok/);
    const after = await fingerprints(page);
    expect(after[0]).toBe(after[1]);
    expect(after[0], 'a different password must derive a different key').not.toBe(before[0]);
  });
}

test('regression: typing into an untouched tab does not raise a discard notice', async ({
  page,
}) => {
  await page.goto('/');
  await panel(page).locator('#srp6a-pw1').fill('hunter2');
  await expect(panel(page).locator('.status__expect--stale')).toHaveCount(0);
  expect(await statusPill(page)).toMatch(/^Step 1 of \d+ ready\.$/);
});

// ---------------------------------------------------------------- observer

test('the on-path observer shows the transcript and audits it for the password', async ({
  page,
}) => {
  await page.goto('/');
  await goDeeper(page);
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  const wireCards = await panel(page).locator('.wcard').count();
  expect(wireCards).toBeGreaterThan(0);

  await panel(page).getByRole('button', { name: 'On-path observer', exact: true }).click();
  const obs = panel(page).locator('.attacker');
  await expect(obs).toBeVisible();

  // The observer must show exactly the messages that crossed — no more, no fewer.
  await expect(obs.locator('.rawmsg')).toHaveCount(wireCards);

  // The audit is a real scan, and on a correct run it must come back clean.
  await expect(obs.locator('.attacker__audit')).toHaveClass(/\bok\b/);
  await expect(obs.locator('.attacker__audit')).toContainText('Transcript audit: clean');
  await expect(obs.locator('.attacker__audit')).not.toContainText('HIT');

  // And the password itself must not appear anywhere in the raw dump.
  const raw = await obs.locator('.attacker__raw').innerText();
  expect(raw.toLowerCase(), 'the password must not be on the wire').not.toContain('hunter2');

  await expect(obs.locator('.attacker__note')).toContainText('augmented');
});

// ---------------------------------------------------------------- breach

test('the SRP breach panel dumps the verifier, and the grind reports what it tested', async ({
  page,
}) => {
  test.slow();
  await page.goto('/');
  await goDeeper(page);
  await panel(page).locator('#srp6a-pw1').fill('hunter2');
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  await panel(page).getByRole('button', { name: 'Server breach', exact: true }).click();

  const breach = panel(page).locator('.breach');
  await expect(breach).toBeVisible();

  // The dump is {I, salt, v} — and the password must not be in it.
  const rows = breach.locator('.breach__dump-row');
  await expect(rows).toHaveCount(3);
  const dump = await breach.locator('.breach__dump').innerText();
  expect(dump.toLowerCase(), 'the stolen record must not contain the password').not.toContain(
    'hunter2',
  );
  await expect(breach.locator('.breach__note').first()).toContainText('NOT the password');

  // The offline grind: the counter must equal the guesses it actually printed,
  // and the run must stop at the hit rather than pretending to test the rest.
  await breach.getByRole('button', { name: 'Run offline grind' }).click();
  const verifierCol = breach.locator('.race__col--verifier');
  await expect(verifierCol.locator('.race__verdict')).toBeVisible({ timeout: 60_000 });

  const guesses = await verifierCol.locator('.guess').count();
  const counter = ((await verifierCol.locator('.race__counter').textContent()) ?? '').trim();
  const cm = /candidates tested: (\d+)/.exec(counter);
  expect(cm, `unparseable counter: ${counter}`).not.toBeNull();
  expect(
    Number(cm![1]),
    'the counter must equal the candidates it actually printed',
  ).toBe(guesses);

  const hits = await verifierCol.locator('.guess--hit').count();
  const misses = await verifierCol.locator('.guess--miss').count();
  expect(hits + misses, 'every candidate is either a hit or a miss').toBe(guesses);
  expect(hits, 'hunter2 is in the wordlist, so the grind must land exactly one hit').toBe(1);
  await expect(verifierCol.locator('.guess--hit')).toContainText('verifier matched');
  await expect(verifierCol.locator('.race__verdict')).toContainText('Recovered');

  // A password outside the wordlist must make the same attack honestly miss.
  await panel(page).locator('#srp6a-pw1').fill('a-password-not-in-any-wordlist-42');
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  await panel(page).getByRole('button', { name: 'Server breach', exact: true }).click();
  await panel(page)
    .locator('.race__col--verifier')
    .getByRole('button', { name: 'Run offline grind' })
    .click();
  const col2 = panel(page).locator('.race__col--verifier');
  await expect(col2.locator('.race__verdict')).toBeVisible({ timeout: 60_000 });
  expect(
    await col2.locator('.guess--hit').count(),
    'the wordlist must not be able to find a password it does not contain',
  ).toBe(0);
  await expect(col2.locator('.race__verdict')).toContainText('No match in');

  const n2 = await col2.locator('.guess').count();
  expect(
    ((await col2.locator('.race__counter').textContent()) ?? '').trim(),
  ).toContain(`candidates tested: ${n2}`);

  // Regression: the no-match verdict used to promise the attacker "billions of
  // candidates per GPU-day" — a figure nothing in this lab computes. The panel must
  // now quote a rate it MEASURED from the grind that just ran, over the candidates
  // it actually tested.
  const verdict = ((await col2.locator('.race__verdict').textContent()) ?? '').replace(/\s+/g, ' ');
  expect(verdict, 'an unsupported hardware figure must not be asserted').not.toMatch(/GPU-day/i);
  expect(verdict, 'an unsupported hardware figure must not be asserted').not.toMatch(/billions/i);

  const rate = ((await col2.locator('.race__rate').textContent()) ?? '').replace(/\s+/g, ' ');
  expect(rate, 'the measured rate must be reported').not.toBe('');
  expect(rate).toContain(`${n2} candidates in `);
  const perSec = /about (\d+) per second/.exec(rate);
  expect(perSec, `no measured per-second rate in: ${rate}`).not.toBeNull();
  expect(
    Number(perSec![1]),
    'the measured rate must be a real positive number, not a placeholder',
  ).toBeGreaterThan(0);
  expect(rate, 'and it must be labelled for what it is').toContain(
    'not a GPU benchmark',
  );
});

/** Every hex/string field on the wire — what a candidate scan actually has to read. */
async function wireFieldCount(page: Page): Promise<number> {
  return panel(page).locator('.wcard .wfield').count();
}

test('the passive-transcript scan reports what it read, and finds no literal encoding', async ({
  page,
}) => {
  test.slow();
  await page.goto('/');
  await goDeeper(page);
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  const fields = await wireFieldCount(page);
  expect(fields, 'an honest run must put fields on the wire to scan').toBeGreaterThan(0);

  await panel(page).getByRole('button', { name: 'Server breach', exact: true }).click();

  const col = panel(page).locator('.race__col--balanced');
  await col.getByRole('button', { name: 'Scan for obvious password encodings' }).click();
  await expect(col.locator('.race__verdict')).toBeVisible({ timeout: 60_000 });

  const guesses = await col.locator('.guess').count();
  expect(guesses).toBeGreaterThan(0);
  expect(((await col.locator('.race__counter').textContent()) ?? '').trim()).toBe(
    `candidates tested: ${guesses}`,
  );
  await expect(col.locator('.race__verdict')).toHaveClass(/race__verdict--neutral/);

  // The verdict must be about the scan that ran: the candidate count and the number
  // of wire fields it read, both quoted, and the field count must match the wire.
  const verdict = ((await col.locator('.race__verdict').textContent()) ?? '').replace(/\s+/g, ' ');
  expect(verdict).toContain('No literal encoding leak found');
  expect(verdict, 'the verdict must say how many candidates it checked').toContain(
    `${guesses} candidates`,
  );
  expect(
    verdict,
    'the verdict must say how much transcript it read, and agree with the wire',
  ).toContain(`${fields} wire field`);

  // ...and the stronger security claim must be attributed to protocol analysis, not
  // produced by the byte scan.
  await expect(col.locator('.race__claim')).toContainText('leak audit, not a proof');

  expect(await col.innerText(), 'a leak here would be a real bug, not the lesson').not.toContain(
    'unexpected leak',
  );
});

/**
 * Regression: this panel exists only on the SRP tab and is handed the SRP run's own
 * transcript, yet the left column called it "A captured balanced-PAKE transcript".
 * The old test ran an honest handshake first and only checked that the scan came
 * back clean, so it never looked at what the column said the bytes were.
 */
test('regression: the passive column never calls the SRP transcript a balanced-PAKE one', async ({
  page,
}) => {
  test.slow();
  await page.goto('/');
  await goDeeper(page);
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();

  // Establish what is actually on the wire: an SRP transcript.
  const steps = await panel(page).locator('.wcard .wcard__step').allTextContents();
  expect(steps.length, 'the run must have produced a transcript').toBeGreaterThan(0);
  expect(steps).toEqual(['client-hello', 'server-hello', 'client-proof', 'server-proof']);

  await panel(page).getByRole('button', { name: 'Server breach', exact: true }).click();
  const col = panel(page).locator('.race__col--balanced');
  const text = (await col.innerText()).replace(/\s+/g, ' ');
  expect(text, 'an SRP transcript must not be described as a balanced-PAKE one').not.toMatch(
    /balanced[- ]PAKE transcript/i,
  );
  expect(text, 'the column must name the protocol it is actually showing').toContain('SRP');
});

/**
 * Regression: "Server breach" is reachable without running a handshake, and the scan
 * then read **0 wire fields** yet printed "candidates tested: 10", ten "not present
 * on the wire — no offline test exists" rows, and the verdict "Nothing resolved
 * offline". A property asserted about the empty set. Two clicks from first paint.
 */
test('regression: scanning an empty transcript must not report a clean result', async ({
  page,
}) => {
  test.slow();
  await page.goto('/');
  await goDeeper(page);

  // Deliberately no handshake.
  await expect(panel(page).locator('.wcard')).toHaveCount(0);
  await expect(panel(page).locator('.wire__empty')).toBeVisible();
  await panel(page).getByRole('button', { name: 'Server breach', exact: true }).click();

  const col = panel(page).locator('.race__col--balanced');
  await col.getByRole('button', { name: 'Scan for obvious password encodings' }).click();
  await expect(col.locator('.race__verdict')).toBeVisible({ timeout: 60_000 });

  const text = (await col.innerText()).replace(/\s+/g, ' ');
  expect(
    await col.locator('.guess').count(),
    'no candidate can be cleared against a transcript that does not exist',
  ).toBe(0);
  expect(text, 'a scan of nothing must not read as a clean sweep').not.toContain(
    'No literal encoding leak found',
  );
  expect(text, 'a scan of nothing must not read as a clean sweep').not.toContain(
    'Nothing resolved offline',
  );
  expect(text, 'the empty state must be named').toMatch(/No transcript captured yet/);
  expect(text, 'and it must say the scan read nothing').toContain('0 wire fields');
  await expect(col.locator('.race__verdict')).toHaveClass(/race__verdict--amber/);

  // Running a handshake then makes the scan meaningful again.
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  await panel(page).getByRole('button', { name: 'Server breach', exact: true }).click();
  const col2 = panel(page).locator('.race__col--balanced');
  await col2.getByRole('button', { name: 'Scan for obvious password encodings' }).click();
  await expect(col2.locator('.race__verdict')).toContainText('No literal encoding leak found', {
    timeout: 60_000,
  });
  expect(await col2.locator('.guess').count()).toBeGreaterThan(0);
});

// ---------------------------------------------------------------- dragonblood

test('the Dragonblood plot shows a varying legacy cost against a flat fixed-work one', async ({
  page,
}) => {
  await page.goto('/');
  await openTab(page, 'dragonfly');
  await panel(page).getByRole('button', { name: 'Dragonblood side-channel', exact: true }).click();

  const dblood = panel(page).locator('.dblood');
  await expect(dblood).toBeVisible();

  const groups = dblood.locator('.plot__group');
  const n = await groups.count();
  expect(n, 'the plot must compare several candidates').toBeGreaterThan(1);

  const legacy: number[] = [];
  const fixed: number[] = [];
  for (let i = 0; i < n; i++) {
    const bars = groups.nth(i).locator('.bar');
    await expect(bars).toHaveCount(2);
    legacy.push(Number((await bars.nth(0).locator('.bar__val').textContent())?.trim()));
    fixed.push(Number((await bars.nth(1).locator('.bar__val').textContent())?.trim()));
    await expect(bars.nth(0)).toHaveClass(/bar--legacy/);
    await expect(bars.nth(1)).toHaveClass(/bar--fixed/);
  }

  // The whole claim: legacy varies with the password, fixed-work does not.
  expect(new Set(fixed).size, 'the fixed-work variant must be flat').toBe(1);
  expect(fixed[0]).toBeGreaterThan(0);
  expect(
    new Set(legacy).size,
    'legacy early-exit must differ across candidates — that difference IS the leak',
  ).toBeGreaterThan(1);

  // Clicking a candidate must explain that candidate's own number.
  await dblood.locator('.plot__pick').first().click();
  const explain = dblood.locator('.dblood__explain');
  const head = ((await explain.locator('.dblood__explain-head').textContent()) ?? '').replace(
    /\s+/g,
    ' ',
  );
  expect(head).toContain(`${legacy[0]} hunt-and-peck iteration`);
  const body = ((await explain.locator('.dblood__explain-body').textContent()) ?? '').replace(
    /\s+/g,
    ' ',
  );
  expect(body, 'the explanation must quote the flat fixed-work cost').toContain(
    `full ${fixed[0]} passes`,
  );
  await expect(explain.locator('.dblood__explain-exploit')).toContainText(
    'That timing leak is the Dragonblood attack',
  );

  // The mitigation must never be called constant-time.
  expect(await dblood.innerText()).not.toContain('constant-time');
  await expect(dblood.locator('.dblood__lead')).toContainText('fixed-work teaching variant');

  // The summary lines must quote the numbers the plot actually produced, not assert
  // "flat" / "varies" as adjectives. `fixedWork()` used to return the cap as a
  // literal, so "constant work" was a claim no measurement could contradict.
  const notes = (await dblood.locator('.dblood__notes').innerText()).replace(/\s+/g, ' ');
  expect(notes).toContain(`every scan performed ${fixed[0]} iterations`);
  expect(notes).toContain(
    `iteration count varies (${Math.min(...legacy)}–${Math.max(...legacy)} iterations)`,
  );
  expect(
    Math.min(...legacy),
    'the legacy model must really do less work than the fixed-work one somewhere',
  ).toBeLessThan(fixed[0]!);
});

// ---------------------------------------------------------------- captions

/**
 * Each wire card's caption names the construction the panel is showing. Three of
 * them named the wrong one: SRP's `M1` is `SHA-256(...)`, not a MAC; CPace's tag is
 * `HMAC(mac_key, lv_cat(Y_self, AD_self))`, a MAC over that party's own contribution
 * rather than "the whole transcript"; and J-PAKE's tag is keyed by a value derived
 * from the secret and computed over the round-1 generators, not "of its derived key".
 */
test('the confirmation captions describe the construction the code computes', async ({ page }) => {
  test.slow();
  await page.goto('/');
  await goDeeper(page);

  // SRP: M1/M2 are evidence hashes, not MACs.
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  const srpCaptions = await panel(page).locator('.wcard__caption').allInnerTexts();
  expect(srpCaptions.length, 'the SRP run must caption its wire cards').toBeGreaterThan(0);
  const srpText = srpCaptions.join(' ').replace(/\s+/g, ' ');
  expect(srpText, 'SRP M1 is a SHA-256 evidence hash, not a MAC').not.toMatch(/MAC M1|M1 .{0,12}MAC/i);
  expect(srpText).toMatch(/evidence hash/i);

  // CPace: the tag covers this party's own Y and AD, not the whole transcript.
  await page.getByRole('tab', { name: 'CPace', exact: true }).click();
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  const cpaceCaptions = await panel(page).locator('.wcard__caption').allInnerTexts();
  expect(cpaceCaptions.length).toBeGreaterThan(0);
  const cpaceText = cpaceCaptions.join(' ').replace(/\s+/g, ' ');
  expect(cpaceText, 'the CPace tag is not computed over the whole transcript').not.toMatch(
    /MAC over the whole transcript/i,
  );
  expect(cpaceText).toMatch(/own public contribution/i);
  expect(cpaceText, 'and the transcript binding must be attributed to the key').toMatch(
    /transcript-bound ISK/i,
  );

  // J-PAKE: the derived key is not the MAC's input.
  await page.getByRole('tab', { name: 'J-PAKE', exact: true }).click();
  await panel(page).getByRole('button', { name: 'Honest run', exact: true }).click();
  const jpakeCaptions = await panel(page).locator('.wcard__caption').allInnerTexts();
  expect(jpakeCaptions.length).toBeGreaterThan(0);
  const jpakeText = jpakeCaptions.join(' ').replace(/\s+/g, ' ');
  expect(jpakeText, 'the J-PAKE tag is keyed by the secret, not computed over the key').not.toMatch(
    /MAC of its derived key/i,
  );
  expect(jpakeText).toMatch(/keyed by a value derived from its shared secret/i);
});

// ---------------------------------------------------------------- gating

test('the other protocols stay gated until "Go deeper" is pressed', async ({ page }) => {
  await page.goto('/');

  for (const id of ['jpake', 'cpace', 'dragonfly'] as const) {
    await expect(page.locator(`#tab-${id}`)).toBeDisabled();
    await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-disabled', 'true');
  }
  await expect(page.locator('.tabs__gate')).toBeVisible();
  await expect(page.locator('#tab-srp6a')).toHaveAttribute('aria-selected', 'true');

  // The guided view offers only the two core scenarios.
  await expect(panel(page).locator('.controls__launchers button')).toHaveCount(2);
  await expect(panel(page).getByRole('button', { name: 'On-path observer' })).toHaveCount(0);

  await panel(page).getByRole('button', { name: 'Go deeper ▾' }).click();

  for (const id of ['jpake', 'cpace', 'dragonfly'] as const) {
    await expect(page.locator(`#tab-${id}`)).toBeEnabled();
  }
  await expect(page.locator('.tabs__gate')).toBeHidden();
  await expect(panel(page).locator('.controls__launchers button')).toHaveCount(5);

  // And back again — without re-gating what has already been unlocked.
  await panel(page).getByRole('button', { name: '◂ Back to simple view' }).click();
  await expect(panel(page).locator('.controls__launchers button')).toHaveCount(2);
  await expect(page.locator('#tab-jpake')).toBeEnabled();
});
