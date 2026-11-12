#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// test-evidence fail-closed test-evidence gate.
//
//   node scripts/ci/verify-test-evidence.mjs \
//     --manifest docs/conformance/required-tests.json --job <job-id> \
//     --evidence <dir written by test-evidence-reporter.mjs> --root <repository root> \
//     [--vectors <surface>=<file with `run.mjs <surface> --json` stdout>]... \
//     [--today YYYY-MM-DD] [--emit-observed <file>]
//
// Exit 0 only if every rule below holds; any doubt is a failure (exit 1).
//   G1  manifest: version 1, job declared, closed key sets, no permitted skip may name a required test
//   G2  evidence: present, parseable, each file exactly one run-start (first) and one run-end (last)
//   G3  executed tests >= job minTests
//   G4  no failed test (a permitted todo excepted)
//   G5  every skipped/todo test AND skipped suite matches a permitted entry (file + name + kind)
//   G6  permitted entries past `expires` fail
//   G7  permitted entries that did not occur fail (no stale allowances)
//   G8  required files reported tests and met their floor
//   G9  required tests ran exactly once per run, passed, not skip/todo
//   G10 every test source file under sourceCoverage executed, or is listed in notExecuted (which must not be stale)
//   G11 conformance: run.mjs --json output supplied, result PASS, each declared corpus fully executed and passed
import { readFileSync, readdirSync, existsSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
const vectorArgs = args.flatMap((a, i) => (a === "--vectors" ? [args[i + 1]] : []));
const problems = [];
const summary = [];
const fail = (code, detail) => problems.push(`${code}: ${detail}`);
const done = () => {
  if (summary.length) console.log(summary.join("\n"));
  if (problems.length) {
    console.error(`TEST-EVIDENCE GATE: FAIL (${problems.length} problem${problems.length === 1 ? "" : "s"})\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  console.log("TEST-EVIDENCE GATE: PASS");
  process.exit(0);
};

// ---------- G1 manifest (strict schema) ----------
const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const keysOnly = (x, allowed, at) => { for (const k of Object.keys(x)) if (!allowed.includes(k)) fail("MANIFEST_INVALID", `${at}: unknown key ${k}`); };
const str = (x, at) => { if (typeof x !== "string" || !x) fail("MANIFEST_INVALID", `${at}: expected non-empty string`); };
const posInt = (x, at) => { if (!Number.isSafeInteger(x) || x < 1) fail("MANIFEST_INVALID", `${at}: expected integer >= 1`); };
const arr = (x, at) => { if (x === undefined) return []; if (!Array.isArray(x)) { fail("MANIFEST_INVALID", `${at}: expected array`); return []; } return x; };
const objEntry = (x, at) => { if (!isObj(x)) { fail("MANIFEST_INVALID", `${at}: expected object`); return false; } return true; };

const manifestPath = opt("--manifest"), jobId = opt("--job"), evDir = opt("--evidence"), root = opt("--root");
const today = opt("--today") ?? new Date().toISOString().slice(0, 10);
if (!manifestPath || !jobId || !evDir || !root) { fail("USAGE", "--manifest --job --evidence --root are required"); done(); }
let manifest;
try { manifest = JSON.parse(readFileSync(manifestPath, "utf8")); } catch (e) { fail("MANIFEST_INVALID", `unreadable: ${e.message}`); done(); }
if (!isObj(manifest) || manifest.version !== 1 || !isObj(manifest.jobs)) { fail("MANIFEST_INVALID", "expected {version:1, jobs:{}}"); done(); }
keysOnly(manifest, ["$comment", "version", "jobs"], "manifest");
const job = manifest.jobs[jobId];
if (!isObj(job)) { fail("MANIFEST_INVALID", `job ${jobId} not declared`); done(); }
keysOnly(job, ["minTests", "requiredFiles", "requiredTests", "permittedSkips", "sourceCoverage", "notExecuted", "conformance"], `jobs.${jobId}`);
posInt(job.minTests, "minTests");
const requiredFiles = arr(job.requiredFiles, "requiredFiles");
requiredFiles.forEach((r, i) => { if (!objEntry(r, `requiredFiles[${i}]`)) return; keysOnly(r, ["file", "minTests"], `requiredFiles[${i}]`); str(r.file, `requiredFiles[${i}].file`); posInt(r.minTests, `requiredFiles[${i}].minTests`); });
const requiredTests = arr(job.requiredTests, "requiredTests");
requiredTests.forEach((r, i) => { if (!objEntry(r, `requiredTests[${i}]`)) return; keysOnly(r, ["file", "name"], `requiredTests[${i}]`); str(r.file, `requiredTests[${i}].file`); str(r.name, `requiredTests[${i}].name`); });
const permitted = arr(job.permittedSkips, "permittedSkips");
permitted.forEach((r, i) => {
  if (!objEntry(r, `permittedSkips[${i}]`)) return;
  keysOnly(r, ["file", "name", "kind", "reason", "ref", "expires"], `permittedSkips[${i}]`);
  for (const k of ["file", "name", "reason", "ref"]) str(r[k], `permittedSkips[${i}].${k}`);
  if (r.kind !== "skip" && r.kind !== "todo") fail("MANIFEST_INVALID", `permittedSkips[${i}].kind must be skip|todo`);
  if (r.expires !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(r.expires)) fail("MANIFEST_INVALID", `permittedSkips[${i}].expires must be YYYY-MM-DD`);
  if (requiredTests.some((t) => t.file === r.file && t.name === r.name)) fail("MANIFEST_INVALID", `permittedSkips[${i}] names a required test`);
});
const coverage = arr(job.sourceCoverage, "sourceCoverage");
coverage.forEach((r, i) => { if (!objEntry(r, `sourceCoverage[${i}]`)) return; keysOnly(r, ["sourceDir", "sourceSuffix", "compiledDir", "compiledSuffix"], `sourceCoverage[${i}]`); for (const k of ["sourceDir", "sourceSuffix", "compiledDir", "compiledSuffix"]) str(r[k], `sourceCoverage[${i}].${k}`); });
const notExecuted = arr(job.notExecuted, "notExecuted");
notExecuted.forEach((r, i) => { if (!objEntry(r, `notExecuted[${i}]`)) return; keysOnly(r, ["file", "reason", "ref"], `notExecuted[${i}]`); for (const k of ["file", "reason", "ref"]) str(r[k], `notExecuted[${i}].${k}`); });
const conformance = arr(job.conformance, "conformance");
conformance.forEach((r, i) => {
  if (!objEntry(r, `conformance[${i}]`)) return;
  keysOnly(r, ["surface", "corpora"], `conformance[${i}]`); str(r.surface, `conformance[${i}].surface`);
  if (!isObj(r.corpora) || !Object.keys(r.corpora).length) fail("MANIFEST_INVALID", `conformance[${i}].corpora`);
  else for (const [k, v] of Object.entries(r.corpora)) posInt(v, `conformance[${i}].corpora.${k}`);
});
if (problems.length) done();

// ---------- G2 evidence ----------
if (!existsSync(evDir) || !statSync(evDir).isDirectory()) { fail("EVIDENCE_MISSING", evDir); done(); }
const files = readdirSync(evDir).filter((f) => f.endsWith(".ndjson")).sort();
if (!files.length) fail("EVIDENCE_MISSING", `${evDir} has no evidence files`);
const recs = [];
for (const f of files) {
  let lines;
  try { lines = readFileSync(join(evDir, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); }
  catch (e) { fail("EVIDENCE_INVALID", `${f}: ${e.message}`); continue; }
  const starts = lines.filter((l) => l.kind === "run-start").length, ends = lines.filter((l) => l.kind === "run-end").length;
  if (starts !== 1 || ends !== 1 || lines[0]?.kind !== "run-start" || lines.at(-1)?.kind !== "run-end") fail("REPORT_INCOMPLETE", f);
  recs.push(...lines.filter((l) => l.kind === "test" || l.kind === "suite"));
}
const tests = recs.filter((r) => r.kind === "test");
const executed = tests.filter((r) => !r.skip && !r.todo);
// ---------- G3 ----------
if (executed.length < job.minTests) fail("NO_TESTS", `executed ${executed.length} < minTests ${job.minTests}`);
summary.push(`evidence: ${files.length} runner process(es), ${tests.length} test(s), ${executed.length} executed, job minTests ${job.minTests}`);

// ---------- G4-G7 failures, skips, todos ----------
const used = new Set();
for (const r of recs) {
  if (r.status === "fail" && !r.todo) fail("TEST_FAILED", `${r.file} :: ${r.name}`);
  if (!r.skip && !r.todo) continue;
  const kind = r.skip ? "skip" : "todo";
  const idx = permitted.findIndex((p) => p.file === r.file && p.name === r.name && p.kind === kind && r.kind === "test");
  if (idx < 0) { fail(kind === "skip" ? "UNPERMITTED_SKIP" : "UNPERMITTED_TODO", `${r.kind} ${r.file} :: ${r.name}`); continue; }
  used.add(idx);
  if (permitted[idx].expires && permitted[idx].expires < today) fail("PERMITTED_SKIP_EXPIRED", `${r.file} :: ${r.name} (expired ${permitted[idx].expires})`);
}
permitted.forEach((p, i) => { if (!used.has(i)) fail("PERMITTED_SKIP_STALE", `${p.file} :: ${p.name} did not ${p.kind} in this run`); });

// ---------- G8 required files ----------
for (const rf of requiredFiles) {
  const n = executed.filter((r) => r.file === rf.file).length;
  if (!tests.some((r) => r.file === rf.file)) fail("REQUIRED_FILE_MISSING", rf.file);
  else if (n < rf.minTests) fail("REQUIRED_FILE_BELOW_FLOOR", `${rf.file}: executed ${n} < ${rf.minTests}`);
}
if (requiredFiles.length) {
  const met = requiredFiles.filter((rf) => executed.filter((r) => r.file === rf.file).length >= rf.minTests).length;
  summary.push(`required files: ${met}/${requiredFiles.length} met their floor`);
}

// ---------- G9 required tests ----------
for (const rt of requiredTests) {
  const hits = tests.filter((r) => r.file === rt.file && r.name === rt.name);
  if (!hits.length) { fail("REQUIRED_MISSING", `${rt.file} :: ${rt.name}`); continue; }
  const perRun = new Map();
  for (const h of hits) perRun.set(h.run, (perRun.get(h.run) ?? 0) + 1);
  if ([...perRun.values()].some((c) => c > 1)) fail("REQUIRED_DUPLICATE", `${rt.file} :: ${rt.name}`);
  if (hits.some((h) => h.status !== "pass" || h.skip || h.todo)) fail("REQUIRED_NOT_PASSED", `${rt.file} :: ${rt.name}`);
}
if (requiredTests.length) summary.push(`required tests: ${requiredTests.length} declared`);

// ---------- G10 source coverage ----------
const walk = (d) => (existsSync(d) ? readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)])) : []);
const executedFiles = new Set(tests.map((r) => r.file));
const neUsed = new Set();
let covered = 0;
for (const c of coverage) {
  const srcRoot = join(root, c.sourceDir);
  if (!existsSync(srcRoot)) { fail("SOURCE_DIR_MISSING", c.sourceDir); continue; }
  for (const abs of walk(srcRoot).filter((f) => f.endsWith(c.sourceSuffix)).sort()) {
    const relSrc = abs.slice(srcRoot.length + 1).split("\\").join("/");
    const compiled = `${c.compiledDir}/${relSrc.slice(0, -c.sourceSuffix.length)}${c.compiledSuffix}`;
    const srcRepoRel = `${c.sourceDir}/${relSrc}`;
    const ne = notExecuted.findIndex((n) => n.file === srcRepoRel);
    if (ne >= 0) { neUsed.add(ne); if (executedFiles.has(compiled)) fail("NOT_EXECUTED_STALE", `${srcRepoRel} is listed as not executed but ran`); continue; }
    if (!executedFiles.has(compiled)) fail("TEST_FILE_NOT_EXECUTED", `${srcRepoRel} (expected ${compiled})`);
    else covered++;
  }
}
notExecuted.forEach((n, i) => { if (!neUsed.has(i)) fail("NOT_EXECUTED_STALE", `${n.file} not found under any sourceCoverage root`); });
if (coverage.length) summary.push(`source coverage: ${covered} test source file(s) executed, ${notExecuted.length} declared not executed`);

// ---------- G11 conformance completeness ----------
for (const c of conformance) {
  const spec = vectorArgs.find((v) => v.startsWith(c.surface + "="));
  if (!spec) { fail("CONFORMANCE_EVIDENCE_MISSING", c.surface); continue; }
  const path = spec.slice(c.surface.length + 1);
  let result;
  try { const lines = readFileSync(path, "utf8").trim().split("\n"); result = JSON.parse(lines.at(-1)); }
  catch { fail("CONFORMANCE_EVIDENCE_INVALID", `${c.surface}: ${path}`); continue; }
  if (!isObj(result)) { fail("CONFORMANCE_EVIDENCE_INVALID", `${c.surface}: ${path}`); continue; }
  if (result.result !== "PASS") fail("CONFORMANCE_RESULT", `${c.surface}: ${result.result}`);
  for (const [id, expected] of Object.entries(c.corpora)) {
    const k = (result.evidenceScope?.corpora ?? []).find((x) => x.id === id);
    if (!k) { fail("CORPUS_NOT_EXECUTED", `${c.surface}/${id}`); continue; }
    const passed = new Set(k.passedCaseIds ?? []);
    if (passed.size !== expected || (k.caseIds ?? []).length !== expected) fail("CORPUS_INCOMPLETE", `${c.surface}/${id}: passed ${passed.size}/${expected}`);
  }
}
if (conformance.length) summary.push(`conformance: ${conformance.length} surface(s) declared`);

// Optional: observed per-file counts, to help maintainers review or update floors (never changes the verdict).
const emit = opt("--emit-observed");
if (emit) {
  const counts = {};
  for (const r of executed) counts[r.file] = (counts[r.file] ?? 0) + 1;
  writeFileSync(emit, JSON.stringify({ job: jobId, executed: executed.length, files: Object.fromEntries(Object.entries(counts).sort()) }, null, 2) + "\n");
}
done();
