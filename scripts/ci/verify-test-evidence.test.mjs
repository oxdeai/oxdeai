// SPDX-License-Identifier: Apache-2.0
// Self-tests for the test-evidence test-evidence gate (scripts/ci/verify-test-evidence.mjs)
// and reporter (scripts/ci/test-evidence-reporter.mjs).
//
// Every gate rule has at least one negative case. Each case builds a throwaway
// mini repository, runs `node --test` with the reporter attached through
// NODE_OPTIONS exactly as CI does, then runs the gate and checks its verdict.
// Child processes get an explicitly constructed environment, so these tests
// never write into the evidence directory of the CI run that executes them.
import test from "node:test";
import { mkdirSync, writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPORTER = join(HERE, "test-evidence-reporter.mjs");
const GATE = join(HERE, "verify-test-evidence.mjs");
const NODE = process.execPath;
const WORK = mkdtempSync(join(tmpdir(), "oxdeai-evidence-gate-"));
test.after(() => rmSync(WORK, { recursive: true, force: true }));

const F = "pkg/test/security.test.mjs";
const GOOD = `import test, { describe, it } from "node:test";
test("replay is denied", () => {});
describe("binding", () => { it("args mismatch is denied", () => {}); });
test("helper", () => {});`;
const base = () => ({ version: 1, jobs: { ci: {
  minTests: 1,
  requiredFiles: [{ file: F, minTests: 3 }],
  requiredTests: [{ file: F, name: "replay is denied" }, { file: F, name: "binding > args mismatch is denied" }],
  sourceCoverage: [{ sourceDir: "pkg/test", sourceSuffix: ".test.mjs", compiledDir: "pkg/test", compiledSuffix: ".test.mjs" }],
} } });
const withJob = (m, f) => { f(m.jobs.ci); return m; };
const IR = GOOD + `\ntest("residual", { todo: "documented" }, () => { throw new Error("x"); });`;
const permitTodo = (extra = {}) => withJob(base(), (j) => {
  j.permittedSkips = [{ file: F, name: "residual", kind: "todo", reason: "documented residual", ref: "README", ...extra }];
});

// Environment for children: inherited test-runner/evidence settings are removed, never reused.
function cleanEnv(extra = {}) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (k === "NODE_OPTIONS" || k.startsWith("OXDEAI_TEST_EVIDENCE_") || k.startsWith("NODE_TEST")) delete env[k];
  return { ...env, ...extra };
}
const reporterEnv = (root, extra = {}) => cleanEnv({
  OXDEAI_TEST_EVIDENCE_DIR: join(root, "evidence"), OXDEAI_TEST_EVIDENCE_ROOT: root,
  NODE_OPTIONS: `--test-reporter=${REPORTER} --test-reporter-destination=stdout --test-reporter=tap --test-reporter-destination=stderr`, ...extra,
});

// Synthetic `run.mjs <surface> --json` outputs (same shape as scripts/conformance/run.mjs).
const ids = (n) => Array.from({ length: n }, (_, i) => `case-${i + 1}`);
const vectorsDoc = (corpora, result = "PASS") => JSON.stringify({ result, executions: [{ consumer: "x", runtime: "Python", exitCode: 0 }],
  evidenceScope: { corpora: corpora.map(([id, all, passed]) => ({ id, caseIds: ids(all), passedCaseIds: ids(passed) })) } });
const PY = { surface: "py", corpora: { "docs-canonicalization-v1": 11, "profile-c": 8 } };

async function runCase({ files = { [F]: GOOD }, manifest = base(), run = "list", extraEnv = {}, vectors, noManifest = false, today }) {
  const root = mkdtempSync(join(WORK, "case-"));
  for (const [p, src] of Object.entries(files)) { mkdirSync(dirname(join(root, p)), { recursive: true }); writeFileSync(join(root, p), src); }
  mkdirSync(join(root, "pkg/test"), { recursive: true });
  const env = reporterEnv(root, extraEnv);
  const cwd = join(root, "pkg");
  const list = (fs, e = env) => spawnSync(NODE, ["--test", ...fs], { cwd, env: e, encoding: "utf8" }).status;
  let runner;
  if (run === "list") runner = list(["test/security.test.mjs"]);
  else if (run === "list-missing") runner = list(["test/security.test.mjs", "test/removed.test.mjs"]);
  else if (run === "twice") runner = [list(["test/security.test.mjs"]), list(["test/security.test.mjs"])];
  else if (run === "no-reporter") runner = list(["test/security.test.mjs"], cleanEnv());
  else if (run === "parallel") {
    runner = await Promise.all([0, 1, 2, 3].map(() => new Promise((res) => spawn(NODE, ["--test", "test/security.test.mjs"], { cwd, env, stdio: "ignore" }).on("exit", res))));
  } else if (run === "sh-glob") {
    runner = spawnSync("sh", ["-c", `"${NODE}" --test test/**/*.test.mjs`], { cwd, env }).status; // unquoted glob under sh
  } else if (run === "find-empty") {
    // Empty $(find) degrades to bare `node --test`, which rediscovers in the cwd; model "build output absent".
    mkdirSync(join(root, "build-out"), { recursive: true });
    runner = spawnSync("sh", ["-c", `"${NODE}" --test $(find . -name '*.test.js')`], { cwd: join(root, "build-out"), env }).status;
  } else if (run === "killed") {
    runner = await new Promise((res) => {
      const c = spawn(NODE, ["--test", "test/security.test.mjs"], { cwd, env, stdio: "ignore" });
      setTimeout(() => c.kill("SIGKILL"), 3000);
      c.on("exit", (code, sig) => res(sig));
    });
  }
  const man = join(root, "manifest.json");
  if (!noManifest) writeFileSync(man, JSON.stringify(manifest));
  const gargs = [GATE, "--manifest", man, "--job", "ci", "--evidence", join(root, "evidence"), "--root", root];
  if (vectors !== undefined) {
    if (vectors !== null) { writeFileSync(join(root, "vectors-py.json"), vectors); gargs.push("--vectors", `py=${join(root, "vectors-py.json")}`); }
  }
  if (today) gargs.push("--today", today);
  const g = spawnSync(NODE, gargs, { encoding: "utf8", env: cleanEnv() });
  return { runner, gate: g.status, out: (g.stdout ?? "") + (g.stderr ?? "") };
}
const has = (out, code) => out.includes(code + ":");
const replace = (from, to) => ({ [F]: GOOD.replace(from, to) });
const REPLAY = `test("replay is denied", () => {})`;

// ---------------------------------------------------------------- positive
test("P1 all required tests executed and passed: gate PASS", async (t) => {
  t.plan(2);
  const r = await runCase({});
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 0, r.out);
});
test("P2 permitted todo with reason/ref: gate PASS", async (t) => {
  t.plan(1);
  const r = await runCase({ files: { [F]: IR }, manifest: permitTodo() });
  t.assert.equal(r.gate, 0, r.out);
});
test("P3 four concurrent runner processes write separate evidence files: gate PASS", async (t) => {
  t.plan(2);
  const r = await runCase({ run: "parallel" });
  t.assert.deepEqual(r.runner, [0, 0, 0, 0]);
  t.assert.equal(r.gate, 0, r.out);
});
test("P4 same required test in two separate runs: gate PASS", async (t) => {
  t.plan(1);
  const r = await runCase({ run: "twice" });
  t.assert.equal(r.gate, 0, r.out);
});
test("P5 env-gated describe with the gate variable set: gate PASS", async (t) => {
  t.plan(1);
  const r = await runCase({ files: replace(`describe("binding", () =>`, `describe("binding", { skip: process.env.GATE_ON !== "1" }, () =>`), extraEnv: { GATE_ON: "1" } });
  t.assert.equal(r.gate, 0, r.out);
});
test("V1 conformance surface fully executed: gate PASS", async (t) => {
  t.plan(1);
  const r = await runCase({ manifest: withJob(base(), (j) => { j.conformance = [PY]; }), vectors: vectorsDoc([["docs-canonicalization-v1", 11, 11], ["profile-c", 8, 8]]) });
  t.assert.equal(r.gate, 0, r.out);
});

// ---------------------------------------------------------------- skips, todos, failures
test("N1 required test with { skip: true } (runner exits 0): gate FAIL", async (t) => {
  t.plan(4);
  const r = await runCase({ files: replace(REPLAY, `test("replay is denied", { skip: true }, () => {})`) });
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_NOT_PASSED"), r.out);
  t.assert.ok(has(r.out, "UNPERMITTED_SKIP"), r.out);
});
test("N2 required test marked todo while failing (runner exits 0): gate FAIL", async (t) => {
  t.plan(4);
  const r = await runCase({ files: replace(REPLAY, `test("replay is denied", { todo: true }, () => { throw new Error("x"); })`) });
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_NOT_PASSED"), r.out);
  t.assert.ok(has(r.out, "UNPERMITTED_TODO"), r.out);
});
test("N3 required test calling t.skip() at runtime: gate FAIL", async (t) => {
  t.plan(3);
  const r = await runCase({ files: replace(REPLAY, `test("replay is denied", (t) => { t.skip("no env"); })`) });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_NOT_PASSED"), r.out);
  t.assert.ok(has(r.out, "UNPERMITTED_SKIP"), r.out);
});
test("N4 env-gated describe skipped (tests 0, skipped 0, runner exits 0): gate FAIL", async (t) => {
  t.plan(4);
  const r = await runCase({ files: replace(`describe("binding", () =>`, `describe("binding", { skip: process.env.GATE_ON !== "1" }, () =>`) });
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_MISSING"), r.out);
  t.assert.ok(has(r.out, "UNPERMITTED_SKIP"), r.out);
});
test("N5 empty test discovery (runner exits 0): gate FAIL", async (t) => {
  t.plan(6);
  const r = await runCase({ run: "find-empty" });
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 1);
  for (const c of ["NO_TESTS", "REQUIRED_FILE_MISSING", "REQUIRED_MISSING", "TEST_FILE_NOT_EXECUTED"]) t.assert.ok(has(r.out, c), `${c}\n${r.out}`);
});
test("N6 required test renamed: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ files: { [F]: GOOD.replace("replay is denied", "replay is rejected") } });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_MISSING"), r.out);
});
test("N7 required test name duplicated within one run: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ files: { [F]: GOOD + `\ntest("replay is denied", () => {});` } });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_DUPLICATE"), r.out);
});
test("N8 required test fails: gate FAIL", async (t) => {
  t.plan(3);
  const r = await runCase({ files: replace(REPLAY, `test("replay is denied", () => { throw new Error("x"); })`) });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "TEST_FAILED"), r.out);
  t.assert.ok(has(r.out, "REQUIRED_NOT_PASSED"), r.out);
});

// ---------------------------------------------------------------- evidence integrity
test("N9 tests ran without the reporter attached: gate FAIL", async (t) => {
  t.plan(3);
  const r = await runCase({ run: "no-reporter" });
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "EVIDENCE_MISSING"), r.out);
});
test("N10 unquoted sh glob silently drops top-level files: gate FAIL", async (t) => {
  t.plan(4);
  const r = await runCase({ files: { [F]: GOOD, "pkg/test/sub/nested.test.mjs": `import test from "node:test"; test("nested", () => {});` }, run: "sh-glob" });
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_MISSING"), r.out);
  t.assert.ok(has(r.out, "TEST_FILE_NOT_EXECUTED"), r.out);
});
test("N11 runner killed before finishing: gate FAIL", async (t) => {
  t.plan(3);
  const r = await runCase({ files: { [F]: GOOD + `\ntest("hangs", () => new Promise(() => setInterval(() => {}, 1000)));` }, run: "killed" });
  t.assert.equal(r.runner, "SIGKILL");
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REPORT_INCOMPLETE"), r.out);
});
test("N12 required file below its floor: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ files: { [F]: GOOD.replace(`\ntest("helper", () => {});`, "") } });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_FILE_BELOW_FLOOR"), r.out);
});
test("N13 required file missing from an explicit list (node ignores it and exits 0): gate FAIL", async (t) => {
  t.plan(3);
  const r = await runCase({ run: "list-missing", manifest: withJob(base(), (j) => { j.requiredFiles.push({ file: "pkg/test/removed.test.mjs", minTests: 1 }); }) });
  t.assert.equal(r.runner, 0);
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_FILE_MISSING"), r.out);
});
test("N14 new test source file that no runner executes: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ files: { [F]: GOOD, "pkg/test/new-security.test.mjs": `import test from "node:test"; test("never run", () => {});` } });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "TEST_FILE_NOT_EXECUTED"), r.out);
});

// ---------------------------------------------------------------- permitted-skip rules
test("N15 permitted todo past its expiry date: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ files: { [F]: IR }, manifest: permitTodo({ expires: "2026-01-01" }), today: "2026-11-09" });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "PERMITTED_SKIP_EXPIRED"), r.out);
});
test("N16 permitted todo but the test is skipped instead (kind mismatch): gate FAIL", async (t) => {
  t.plan(3);
  const r = await runCase({ files: { [F]: GOOD + `\ntest("residual", { skip: true }, () => {});` }, manifest: permitTodo() });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "UNPERMITTED_SKIP"), r.out);
  t.assert.ok(has(r.out, "PERMITTED_SKIP_STALE"), r.out);
});
test("N17 permitted entry that never occurs (stale allowance): gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ manifest: permitTodo() });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "PERMITTED_SKIP_STALE"), r.out);
});
test("N18 notExecuted entry for a file that did run: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ manifest: withJob(base(), (j) => { j.notExecuted = [{ file: F, reason: "x", ref: "y" }]; }) });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "NOT_EXECUTED_STALE"), r.out);
});

// ---------------------------------------------------------------- manifest integrity
test("N19 manifest with an unknown key (e.g. an advisory switch): gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ manifest: withJob(base(), (j) => { j.advisoryOnly = true; }) });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "MANIFEST_INVALID"), r.out);
});
test("N20 manifest missing: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ noManifest: true });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "MANIFEST_INVALID"), r.out);
});
test("N21 permitted-skip entry naming a required test: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ manifest: withJob(base(), (j) => { j.permittedSkips = [{ file: F, name: "replay is denied", kind: "skip", reason: "x", ref: "y" }]; }) });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "MANIFEST_INVALID"), r.out);
});
test("N25 job not declared in the manifest: gate FAIL", async (t) => {
  t.plan(2);
  const m = base(); m.jobs = { other: m.jobs.ci };
  const r = await runCase({ manifest: m });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "MANIFEST_INVALID"), r.out);
});

// ---------------------------------------------------------------- conformance completeness
const pyJob = () => withJob(base(), (j) => { j.conformance = [PY]; });
test("N22 verifier reporting PASS with zero executed cases: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ manifest: pyJob(), vectors: vectorsDoc([]) });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "CORPUS_NOT_EXECUTED"), r.out);
});
test("N23 conformance corpus with one case not passed: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ manifest: pyJob(), vectors: vectorsDoc([["docs-canonicalization-v1", 11, 10], ["profile-c", 8, 8]]) });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "CORPUS_INCOMPLETE"), r.out);
});
test("N24 conformance output not supplied: gate FAIL", async (t) => {
  t.plan(2);
  const r = await runCase({ manifest: pyJob(), vectors: null });
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "CONFORMANCE_EVIDENCE_MISSING"), r.out);
});
test("N26 conformance output unparseable or result FAIL: gate FAIL", async (t) => {
  t.plan(4);
  const a = await runCase({ manifest: pyJob(), vectors: "not json" });
  t.assert.equal(a.gate, 1);
  t.assert.ok(has(a.out, "CONFORMANCE_EVIDENCE_INVALID"), a.out);
  const b = await runCase({ manifest: pyJob(), vectors: vectorsDoc([["docs-canonicalization-v1", 11, 11], ["profile-c", 8, 8]], "FAIL") });
  t.assert.equal(b.gate, 1);
  t.assert.ok(has(b.out, "CONFORMANCE_RESULT"), b.out);
});

// ---------------------------------------------------------------- documented limitation and its mitigation
test("L1 vacuous required test (early return, no assertions) passes: documented limitation", async (t) => {
  t.plan(1);
  const r = await runCase({ files: replace(REPLAY, `test("replay is denied", () => { if (!process.env.X) return; throw new Error("x"); })`) });
  t.assert.equal(r.gate, 0, r.out);
});
test("L1b the same test with t.plan(1) fails, so the gate fails: mitigation", async (t) => {
  t.plan(3);
  const r = await runCase({ files: replace(REPLAY, `test("replay is denied", (t) => { t.plan(1); if (!process.env.X) return; t.assert.ok(true); })`) });
  t.assert.equal(r.runner, 1);
  t.assert.equal(r.gate, 1);
  t.assert.ok(has(r.out, "REQUIRED_NOT_PASSED"), r.out);
});
