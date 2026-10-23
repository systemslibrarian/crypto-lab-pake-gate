// Run only from a committed source baseline. Every mutation must alter the
// production bundle, be killed by its named assertion owner, restore exactly,
// and leave that owner green again.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
process.chdir(root);

const build = ["npm", ["run", "build"]];
const vitest = (file, title) => [
  "npx",
  ["vitest", "run", file, "--testNamePattern", title],
];

function run([command, args]) {
  return spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, CI: "1", NO_COLOR: "1" },
  });
}

function pass(command, label) {
  const result = run(command);
  if (result.status !== 0) {
    throw new Error(`${label}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function distHash() {
  const hash = createHash("sha256");
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else {
        hash.update(path);
        hash.update(readFileSync(path));
      }
    }
  };
  walk("dist");
  return hash.digest("hex");
}

const cases = [
  [
    "idle password edits keep the constructor runner",
    "src/ui/tabView.ts",
    "    if (discardedVisibleState) this.invalidated = true;\n    this.runner = this.freshRunner();",
    "    if (discardedVisibleState) this.invalidated = true;\n    if (!discardedVisibleState) return;\n    this.runner = this.freshRunner();",
    vitest("tests/ui.input-state.test.ts", "uses the visible J-PAKE inputs instead of the constructor defaults"),
  ],
  [
    "hero collapses passive transcripts and stolen records",
    "src/ui/tabs.ts",
    "A PAKE is NOT “hash the password and send it.” A passive transcript does not give an eavesdropper a direct offline password test. A server breach is different: a stolen SRP verifier supports per-user offline password guessing, while a balanced PAKE stores no server verifier.",
    "A PAKE is NOT “hash the password and send it.” A stolen record and a captured transcript still can't be grinded back to the login.",
    vitest("tests/ui.smoke.test.ts", "distinguishes passive transcripts from stolen SRP verifier records"),
  ],
  [
    "shortened J-PAKE element encoding is accepted",
    "src/pake/groups.ts",
    "  if (encoded.length !== group.pLen) {",
    "  if (false && encoded.length !== group.pLen) {",
    vitest("tests/edge-cases.test.ts", "numerically valid but shortened elements are rejected"),
  ],
  [
    "shortened J-PAKE proof encoding is accepted",
    "src/pake/schnorr-nizk.ts",
    "  if (encodedV.length !== group.pLen || encodedR.length !== group.pLen) {",
    "  if (false && (encodedV.length !== group.pLen || encodedR.length !== group.pLen)) {",
    vitest("tests/edge-cases.test.ts", "shortened Schnorr fields are rejected before verification"),
  ],
  [
    "J-PAKE Round-1 proof failure is ignored",
    "src/pake/jpake.ts",
    "    if (!okFirst || !okSecond) {",
    "    if (false && (!okFirst || !okSecond)) {",
    vitest("tests/tamper.test.ts", "corrupting a Round-1 Schnorr proof"),
  ],
  [
    "J-PAKE confirmation failure is ignored",
    "src/pake/jpake.ts",
    "    if (!eqBytes(got, expected)) {",
    "    if (false && !eqBytes(got, expected)) {",
    vitest("tests/jpake.test.ts", "wrong password: keys differ AND confirmation fails"),
  ],
  [
    "CPace confirmation failure is ignored",
    "src/pake/cpace.ts",
    "    if (!eqBytes(got, expected)) {",
    "    if (false && !eqBytes(got, expected)) {",
    vitest("tests/cpace.test.ts", "wrong password: ISKs differ and confirmation fails"),
  ],
  [
    "Dragonfly reflection guard is bypassed",
    "src/pake/dragonfly.ts",
    "    if (scalarPeer === this.scalarSelf && elemPeer.equals(this.elemSelf)) {",
    "    if (false && scalarPeer === this.scalarSelf && elemPeer.equals(this.elemSelf)) {",
    vitest("tests/dragonfly.test.ts", "reflection guard: a mirrored commit is rejected"),
  ],
  [
    "Dragonfly honest derivation exits before minimum k",
    "src/pake/dragonfly.ts",
    "    if (counter >= k && found !== null) {",
    "    if (counter >= 1 && found !== null) {",
    vitest("tests/dragonfly.test.ts", "both peers derive the same password element"),
  ],
  [
    "SRP server accepts an invalid client proof",
    "src/pake/srp6a.ts",
    "    if (!eq(M1, M1expected)) {",
    "    if (false && !eq(M1, M1expected)) {",
    vitest("tests/protocol-edge.test.ts", "server rejects a proof computed from the wrong password"),
  ],
];

const sourceFiles = [...new Set(cases.map((entry) => entry[1]))];
const dirty = spawnSync("git", ["diff", "--exit-code", "--", ...sourceFiles], {
  cwd: root,
  encoding: "utf8",
});
if (dirty.status !== 0) {
  throw new Error("Commit the source baseline before mutation checks.");
}

pass(build, "baseline build");
const baseline = distHash();
const evidence = [];
console.log("baseline: unmutated copy PASSES");
mkdirSync("mutation-logs", { recursive: true });

for (const [name, file, before, after, owner] of cases) {
  pass(owner, `${name}: baseline owner`);
  const original = readFileSync(file, "utf8");
  if (original.split(before).length !== 2) {
    throw new Error(`${name}: expected exactly one mutation site`);
  }

  let restoredBuild;
  let restoredHash;
  let restoredOwner;
  try {
    writeFileSync(file, original.replace(before, after));
    const sourceDiff = spawnSync("git", ["diff", "--", file], {
      cwd: root,
      encoding: "utf8",
    }).stdout;
    if (!sourceDiff.trim()) throw new Error(`${name}: source diff is empty`);

    pass(build, `${name}: mutant build`);
    const mutant = distHash();
    if (mutant === baseline) throw new Error(`${name}: production artifact did not move`);

    const result = run(owner);
    const output = result.stdout + result.stderr;
    writeFileSync(`mutation-logs/${name.replaceAll(" ", "-")}.log`, output);
    if (
      result.status === 0 ||
      !/AssertionError|expected|FAIL|Test Files\s+\d+ failed/i.test(output)
    ) {
      throw new Error(`${name}: no assertion kill\n${output}`);
    }

    evidence.push({
      name,
      sourceDiff,
      baseline,
      mutant,
      namedTest: owner[1][owner[1].indexOf("--testNamePattern") + 1],
      assertionFailure: true,
      retries: 0,
    });
  } finally {
    writeFileSync(file, original);
    restoredBuild = run(build);
    if (restoredBuild.status === 0) restoredHash = distHash();
    restoredOwner = run(owner);
  }

  if (restoredBuild.status !== 0) {
    throw new Error(`${name}: restore build failed\n${restoredBuild.stdout}\n${restoredBuild.stderr}`);
  }
  if (restoredHash !== baseline) throw new Error(`${name}: restored artifact hash differs`);
  if (restoredOwner.status !== 0) {
    throw new Error(`${name}: restored owner failed\n${restoredOwner.stdout}\n${restoredOwner.stderr}`);
  }
  evidence.at(-1).restoredGreen = true;
  console.log(`${name}: killed; exact artifact restored; owning test green`);
}

writeFileSync("mutation-evidence.json", `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`all ${cases.length} mutation(s) caught`);
