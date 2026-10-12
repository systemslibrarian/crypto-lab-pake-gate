import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { ESLint, Linter } from 'eslint';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const baseline = JSON.parse(await readFile(new URL('./fixtures/lint-baseline.json', import.meta.url), 'utf8'));
const eslint = new ESLint({ cwd: root });
const levels = { off: 0, warn: 1, error: 2 };
const normalize = (value, name) => {
  const list = Array.isArray(value) ? value : [value];
  let options = list.length > 1 ? list.slice(1) : baseline.implicitOptions[name] ?? [];
  if (name === 'no-constant-condition') {
    const value = options[0]?.checkLoops;
    options = [{ checkLoops: value === 'all' ? true : value }];
  }
  // This new default adds a check; it cannot weaken the old unrestricted rule.
  if (name === 'no-shadow-restricted-names' && options[0]?.reportGlobalThis === true) options = [];
  return [levels[list[0]] ?? list[0], ...options];
};

test('every previously enabled rule, option and compiler-facing parser mode remains active', async () => {
  assert.equal(baseline.sourceSha, '8cfae8ec5f15f2889f934e87a2d7a9dd77f36d4b');
  for (const [name, before] of Object.entries(baseline.configurations)) {
    const after = await eslint.calculateConfigForFile(path.join(root, name));
    assert.ok(after, `Missing configuration for ${name}`);
    for (const [rule, value] of Object.entries(before.rules)) {
      const old = normalize(value, rule);
      if (!old[0]) continue;
      const current = normalize(after.rules[rule], rule);
      assert.ok(current[0] >= old[0], `${name}: ${rule} severity weakened`);
      assert.deepEqual(current.slice(1), old.slice(1), `${name}: ${rule} options changed`);
    }
    assert.equal(after.languageOptions.ecmaVersion, 2022);
    assert.equal(after.languageOptions.sourceType, 'module');
  }
});

test('the effective global names and writability remain identical in every prior scope', async () => {
  for (const name of Object.keys(baseline.configurations)) {
    const config = await eslint.calculateConfigForFile(path.join(root, name));
    const linter = new Linter();
    const messages = linter.verify('export {};', [{
      files: ['**/*.ts'], languageOptions: config.languageOptions, plugins: config.plugins,
      rules: config.rules,
    }], { filename: name });
    assert.ok(!messages.some(m => m.fatal), JSON.stringify(messages));
    assert.ok(linter.getSourceCode(), 'A missing configuration must not count as a clean scan');
    const globals = Object.fromEntries(linter.getSourceCode().scopeManager.globalScope.variables
      .filter(v => v.defs.length === 0).map(v => [v.name, !!v.writeable]).sort(([a], [b]) => a.localeCompare(b)));
    assert.deepEqual(globals, baseline.globals, `${name}: allowed globals changed`);
  }
});

test('every tracked TypeScript path and representative legacy ignore boundary keeps its coverage', async () => {
  for (const [name, ignored] of Object.entries(baseline.ignoredPaths)) {
    assert.equal(await eslint.isPathIgnored(path.join(root, name)), ignored, `${name}: coverage changed`);
  }
});

const restrict = async (source, name = 'src/pake/lint-negative.ts') => {
  const [result] = await eslint.lintText(source, { filePath: path.join(root, name) });
  assert.ok(result && !result.fatalErrorCount, JSON.stringify(result?.messages));
  return result.messages.filter(m => m.ruleId === 'no-restricted-syntax');
};

test('password laundering through unknown and angle-bracket assertions is rejected in the crypto core', async () => {
  const throughUnknown = await restrict('type Hex = string; export const wire = "password" as unknown as Hex;');
  assert.equal(throughUnknown.length, 1);
  assert.equal(throughUnknown[0].severity, 2);
  const angle = await restrict('type Hex = string; export const wire = <Hex>"password";');
  assert.equal(angle.length, 1);
  assert.equal(angle[0].severity, 2);
});

test('ordinary branding remains legal and the password barrier retains its original core-only scope', async () => {
  assert.deepEqual(await restrict('type Hex = string; export const wire = "public bytes" as Hex;'), []);
  assert.deepEqual(await restrict('type Hex = string; export const wire = "public bytes" as unknown as Hex;', 'tests/lint-scope.ts'), []);
});

test('the previous constant-condition rule still rejects constant branches and loops', async () => {
  const [result] = await eslint.lintText('if (true) { console.log("branch"); } while (true) { console.log("loop"); }', { filePath: path.join(root, 'src/pake/lint-negative.ts') });
  assert.equal(result.fatalErrorCount, 0);
  assert.equal(result.messages.filter(m => m.ruleId === 'no-constant-condition' && m.severity === 2).length, 2);
});

test('retained recommended rules still reject block functions, extra semicolons and mixed indentation', async () => {
  for (const [source, rule] of [
    ['if (condition) { function blocked() {} }', 'no-inner-declarations'],
    ['export const value = 1;;', 'no-extra-semi'],
    ['function mixed() {\n \treturn 1;\n}', 'no-mixed-spaces-and-tabs'],
  ]) {
    const [result] = await eslint.lintText(source, { filePath: path.join(root, 'src/pake/lint-negative.ts') });
    assert.equal(result.fatalErrorCount, 0);
    assert.ok(result.messages.some(m => m.ruleId === rule && m.severity === 2), rule);
  }
});
