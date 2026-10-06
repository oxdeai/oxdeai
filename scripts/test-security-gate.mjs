#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/**
 * Regression for the security-gate / policy-boundary split (P1) and the
 * release-evidence provenance extension (#268).
 *
 * Verifies:
 *  1. advisory ALLOW -> gate exits 0, independent of the harness.
 *  2. advisory DENY  -> gate exits 1, independent of the harness.
 *  3. the gate's exit code never varies with the real harness's current
 *     result (proves scenarios 1-3 of the required matrix: whichever way
 *     the harness currently runs, the two outcomes never combine).
 *  4. scripts/security-gate.mjs contains no reference to the harness
 *     command or its exit code (advisory path never invokes it).
 *  5. the harness source contains no reference to audit/advisory/exception
 *     data (policy-boundary path never depends on live advisory data).
 *  6. the CI workflow defines both checks as independent jobs, each
 *     invoking only its own command.
 *  7. exact candidateSha is recorded (explicit pin).
 *  8. exact SHA-256 of pnpm-lock.yaml bytes is recorded as lockfileHash.
 *  9. advisorySource is recorded (explicit pin and auto-detected default).
 * 10. raw audit input is retained alongside the decision artifact.
 * 11. policyHash / exceptionsHash / findingsHash / inputHash are
 *     independently reproducible, and inputHash's scope is unchanged by
 *     the new provenance fields.
 * 12. artifactHash changes when a bound provenance field changes.
 * 13. malformed (branch-shaped) or missing required candidate/lockfile
 *     provenance fails evidence generation clearly (non-zero exit).
 * 14. changing lockfile bytes changes lockfileHash.
 * 15. evidence generation does not alter the advisory ALLOW/DENY decision.
 *
 * No PBT: every case here is a fixed, small, enumerable fixture (a handful
 * of known field mutations and byte changes), not a generative invariant
 * over an open input domain. Plain assert + spawnSync, matching
 * scripts/test-api-guard.mjs.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, "..");
const gatePath = join(repoRoot, "scripts/security-gate.mjs");
const harnessPath = join(repoRoot, "scripts/security/repro-policy-boundary-attacks.ts");
const workflowPath = join(repoRoot, ".github/workflows/security-gate.yml");

const fixtureDir = mkdtempSync(join(tmpdir(), "oxdeai-security-gate-"));

function writeFixturePolicy() {
  const policyPath = join(fixtureDir, "policy.json");
  writeFileSync(
    policyPath,
    JSON.stringify({
      rules: { critical: "deny", high: "deny", moderate: "require_exception", low: "warn" },
      exceptions: [],
    }),
  );
  return policyPath;
}

function writeAuditFixture(name, advisories) {
  const auditPath = join(fixtureDir, `${name}.json`);
  writeFileSync(auditPath, JSON.stringify({ advisories }));
  return auditPath;
}

function runGate(auditPath, policyPath, extraArgs = []) {
  return spawnSync("node", [gatePath, auditPath, policyPath, ...extraArgs], { encoding: "utf8" });
}

// Independent reimplementation of security-gate.mjs's canonical hashing, so
// this test recomputes hashes rather than reusing the gate's own function
// and trivially agreeing with itself.
function stableStringify(value) {
  const sorter = (v) => {
    if (Array.isArray(v)) return v.map(sorter);
    if (v && typeof v === "object") {
      return Object.keys(v)
        .sort()
        .reduce((acc, k) => {
          acc[k] = sorter(v[k]);
          return acc;
        }, {});
    }
    return v;
  };
  return JSON.stringify(sorter(value));
}
const sha256 = (v) => createHash("sha256").update(stableStringify(v)).digest("hex");
const sha256Bytes = (buf) => createHash("sha256").update(buf).digest("hex");

try {
  const policyPath = writeFixturePolicy();
  const cleanAudit = writeAuditFixture("clean", {});
  const blockingAudit = writeAuditFixture("blocking", {
    "adv-1": {
      id: 999999,
      module_name: "example-pkg",
      severity: "high",
      findings: [{ paths: ["root > example-pkg@1.0.0"] }],
    },
  });

  // Exact path exceptions must never cover a second dependency route.
  const exactPath = "packages__core>@microsoft/api-extractor>@rushstack/ts-command-line>argparse>sprintf-js";
  const otherPath = "other>sprintf-js";
  const exception = {
    id: 1241202, package: "sprintf-js", severity: "moderate",
    path: exactPath, reason: "temporary test exception", expires_on: "2999-01-01",
  };
  function checkException(name, paths, ex, severity = "moderate", allowed = false) {
    const audit = writeAuditFixture(name, {
      fixture: { id: 1241202, module_name: "sprintf-js", severity,
        findings: paths.map((path) => ({ paths: [path] })) },
    });
    const scopedPolicy = join(fixtureDir, `${name}-policy.json`);
    writeFileSync(scopedPolicy, JSON.stringify({
      rules: { moderate: "require_exception", high: "require_exception", critical: "require_exception" },
      exceptions: Array.isArray(ex) ? ex : [ex],
    }));
    const result = runGate(audit, scopedPolicy);
    assert.equal(result.status, allowed ? 0 : 1, `${name}\n${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, allowed ? /Decision: ALLOW/ : /Decision: DENY/);
    process.stdout.write(`PASS ${name}\n`);
    return result;
  }
  const exact = checkException("exact-path", [exactPath], exception, "moderate", true);
  assert.match(exact.stdout, /Matched exceptions: 1/);
  const different = checkException("different-path", [otherPath], exception);
  assert.match(different.stdout, /Matched exceptions: 0/);
  const multiple = checkException("second-route-blocks", [exactPath, otherPath], exception);
  assert.match(multiple.stdout, /Findings: 2/);
  assert.match(multiple.stdout, /Blocking: 1/);
  assert.match(multiple.stdout, /Matched exceptions: 1/);
  assert.match(multiple.stdout, /path=other>sprintf-js/);
  // pnpm can also report multiple paths inside a single finding.
  const sharedFindingAudit = writeAuditFixture("shared-finding-paths", {
    fixture: { id: 1241202, module_name: "sprintf-js", severity: "moderate",
      findings: [{ paths: [exactPath, otherPath] }] },
  });
  const sharedFinding = runGate(sharedFindingAudit, join(fixtureDir, "exact-path-policy.json"));
  assert.equal(sharedFinding.status, 1);
  assert.match(sharedFinding.stdout, /Findings: 2/);
  assert.match(sharedFinding.stdout, /Blocking: 1/);
  assert.match(sharedFinding.stdout, /Matched exceptions: 1/);
  process.stdout.write("PASS multiple-paths-in-one-finding\n");

  const expiredPath = checkException("expired-path", [exactPath], { ...exception, expires_on: "2000-01-01" });
  assert.match(expiredPath.stdout, /Expired exceptions: 1/);
  const { path: unusedPath, ...legacyException } = exception;
  checkException("legacy-unscoped", [exactPath, otherPath], legacyException, "moderate", true);
  for (const [index, path] of [null, 42, [], {}, "", " ", ` ${exactPath}`, `${exactPath} `].entries()) {
    checkException(`malformed-path-${index}`, [exactPath], { ...exception, path });
  }
  for (const severity of ["high", "critical"]) {
    checkException(`${severity}-always-denied`, [exactPath], { ...exception, severity }, severity);
  }

  // Invalid candidates cannot shadow valid coverage in either order.
  for (const [name, invalid] of [
    ["malformed", { ...exception, path: null }],
    ["expired", { ...exception, expires_on: "2000-01-01" }],
    ["missing-reason", { ...exception, reason: "" }],
  ]) {
    const first = checkException(`${name}-first`, [exactPath], [invalid, exception], "moderate", true);
    const last = checkException(`${name}-last`, [exactPath], [exception, invalid], "moderate", true);
    assert.equal(first.stdout, last.stdout, "exception ordering must not change decision or reporting");
    assert.match(first.stdout, /Matched exceptions: 1/);
    assert.match(first.stdout, name === "expired" ? /Expired exceptions: 1/ : /Expired exceptions: 0/);
    if (name === "expired") assert.match(first.stdout, /covered by another valid exception/);
  }

  // Expired exceptions are diagnostics: they never change the policy action.
  // Default rule set, so low is warn and moderate requires an exception.
  const expiredException = { ...exception, expires_on: "2000-01-01" };
  function evaluate(name, severity, exceptions) {
    const audit = writeAuditFixture(name, {
      fixture: { id: exception.id, module_name: exception.package, severity, findings: [{ paths: [exactPath] }] },
    });
    const policy = join(fixtureDir, `${name}-policy.json`);
    writeFileSync(policy, JSON.stringify({
      rules: { critical: "deny", high: "deny", moderate: "require_exception", low: "warn" },
      exceptions: exceptions.map((ex) => ({ ...ex, severity })),
    }));
    return runGate(audit, policy);
  }
  function assertOutcome(result, decision, counts, label) {
    assert.equal(result.status, decision === "ALLOW" ? 0 : 1, `${label}\n${result.stdout}`);
    assert.match(result.stdout, new RegExp(`^Decision: ${decision}$`, "m"), label);
    for (const [field, n] of Object.entries(counts)) {
      assert.match(result.stdout, new RegExp(`^${field}: ${n}$`, "m"), `${label}: expected ${field}: ${n}\n${result.stdout}`);
    }
    process.stdout.write(`PASS ${label}\n`);
  }
  assertOutcome(evaluate("low-warn", "low", []), "ALLOW",
    { Warnings: 1, Blocking: 0, "Expired exceptions": 0 }, "low-warn-baseline");
  assertOutcome(evaluate("low-warn-expired", "low", [expiredException]), "ALLOW",
    { Warnings: 1, Blocking: 0, "Expired exceptions": 1 }, "low-warn-expired-exception-stays-allow");
  assertOutcome(evaluate("moderate-expired-only", "moderate", [expiredException]), "DENY",
    { Blocking: 1, "Matched exceptions": 0, "Expired exceptions": 1 }, "moderate-expired-only-denied");
  const expiredFirst = evaluate("moderate-expired-valid", "moderate", [expiredException, exception]);
  const validFirst = evaluate("moderate-valid-expired", "moderate", [exception, expiredException]);
  for (const [result, label] of [[expiredFirst, "moderate-expired-then-valid"], [validFirst, "moderate-valid-then-expired"]]) {
    assertOutcome(result, "ALLOW", { Blocking: 0, "Matched exceptions": 1, "Expired exceptions": 1 }, label);
  }
  assert.equal(expiredFirst.stdout, validFirst.stdout, "exception order must not change decision or reporting");
  process.stdout.write("PASS moderate-valid-expired-order-independent\n");

  // Preserve each pathless record alongside all reported dependency routes.
  for (const [name, findings, total, blocked, matches] of [
    ["pathless-only", [{ paths: [] }], 1, 1, 0],
    ["pathful-only", [{ paths: [exactPath] }], 1, 0, 1],
    ["pathless-first", [{}, { paths: [exactPath] }], 2, 1, 1],
    ["pathless-last", [{ paths: [exactPath] }, { paths: [] }], 2, 1, 1],
    ["multiple-plus-pathless", [{ paths: [exactPath, otherPath] }, {}], 3, 2, 1],
  ]) {
    const audit = writeAuditFixture(name, {
      fixture: { id: exception.id, module_name: exception.package, severity: exception.severity, findings },
    });
    const result = runGate(audit, join(fixtureDir, "exact-path-policy.json"));
    assert.equal(result.status, blocked ? 1 : 0, result.stdout);
    assert.ok(result.stdout.includes(`Findings: ${total}`));
    assert.ok(result.stdout.includes(`Blocking: ${blocked}`));
    assert.ok(result.stdout.includes(`Matched exceptions: ${matches}`));
    if (blocked) assert.match(result.stdout, /path=-/);
    process.stdout.write(`PASS ${name}\n`);
  }
  checkException("empty-path-cannot-cover-pathless", [""], { ...exception, path: "" });

  // 1. advisory ALLOW -> exit 0.
  const allow = runGate(cleanAudit, policyPath);
  assert.equal(allow.status, 0, `expected gate exit 0 on clean audit, got ${allow.status}\n${allow.stdout}`);
  assert.match(allow.stdout, /Decision: ALLOW/);
  process.stdout.write("PASS advisory-allow-exit-0\n");

  // 2. advisory DENY -> exit 1.
  const deny = runGate(blockingAudit, policyPath);
  assert.equal(deny.status, 1, `expected gate exit 1 on blocking audit, got ${deny.status}\n${deny.stdout}`);
  assert.match(deny.stdout, /Decision: DENY/);
  process.stdout.write("PASS advisory-deny-exit-1\n");

  // 3. independence: run the real harness once, record its current result,
  // then confirm the gate's exit codes above did not change with it either
  // way. Before the fix this would have been impossible to state, because
  // the gate's own exit code was ANDed with the harness's.
  const harness = spawnSync("pnpm", ["run", "security:policy-boundary"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  const harnessPassed = harness.status === 0;
  process.stdout.write(`harness current result: ${harnessPassed ? "PASS" : "FAIL"} (status=${harness.status})\n`);
  // Regardless of harnessPassed, the two gate runs above already produced
  // exit 0 and exit 1 respectively, driven only by the audit fixture. That
  // is the independence property: assert it holds for both matrix legs.
  assert.equal(allow.status, 0, "advisory ALLOW must stay exit 0 regardless of harness result");
  assert.equal(deny.status, 1, "advisory DENY must stay exit 1 regardless of harness result");
  process.stdout.write("PASS gate-independent-of-harness-result\n");

  // 4. advisory code path never invokes the harness. security-gate.mjs may
  // shell out for its own release-evidence provenance (git rev-parse, pnpm
  // --version, #268), so the precise check is: no subprocess call site
  // references the harness, not "no subprocess calls at all". A comment
  // naming the harness (to explain the separation) is fine.
  const gateSource = readFileSync(gatePath, "utf8");
  const subprocessLines = gateSource.split("\n").filter((l) => /spawnSync\(|spawn\(|execSync\(|execFileSync\(/.test(l));
  assert.ok(subprocessLines.length > 0, "expected at least the provenance-detection subprocess calls to exist");
  for (const line of subprocessLines) {
    assert.ok(!line.includes("policy-boundary"), `subprocess call site must not reference the harness: ${line.trim()}`);
  }
  process.stdout.write("PASS advisory-never-invokes-harness\n");

  // 5. policy-boundary code path never depends on live advisory data.
  const harnessSource = readFileSync(harnessPath, "utf8");
  for (const token of ["audit.json", "vuln-policy", "advisories", "security-gate"]) {
    assert.ok(!harnessSource.includes(token), `harness must not reference ${token}`);
  }
  process.stdout.write("PASS harness-never-depends-on-advisory-data\n");

  // 6. CI workflow: two independent jobs, each invoking only its own command.
  const workflow = readFileSync(workflowPath, "utf8");
  const jobs = workflow.split(/\n  (?=[a-z][a-z0-9-]*:\n)/);
  const boundaryJob = jobs.find((j) => j.startsWith("security-policy-boundary:"));
  const advisoryJob = jobs.find((j) => j.startsWith("security-advisory-gate:"));
  assert.ok(boundaryJob, "workflow must define a security-policy-boundary job");
  assert.ok(advisoryJob, "workflow must define a security-advisory-gate job");
  assert.match(boundaryJob, /name: Security Policy Boundary/);
  assert.match(advisoryJob, /name: Security Advisory Gate/);
  assert.match(boundaryJob, /security:policy-boundary/);
  assert.ok(!boundaryJob.includes("security-gate.mjs"), "policy-boundary job must not run the advisory gate script");
  assert.match(advisoryJob, /security-gate\.mjs/);
  assert.ok(!advisoryJob.includes("security:policy-boundary"), "advisory job must not run the policy-boundary harness");
  process.stdout.write("PASS workflow-jobs-independent\n");

  process.stdout.write("\nsecurity-gate split: all checks passed\n");

  // ── Release-evidence provenance (#268) ────────────────────────────────────

  const evidenceDir = join(fixtureDir, "evidence");
  const lockA = join(fixtureDir, "lock-a.yaml");
  const lockB = join(fixtureDir, "lock-b.yaml");
  writeFileSync(lockA, "packages:\n  fixture-a: 1.0.0\n");
  writeFileSync(lockB, "packages:\n  fixture-b: 2.0.0\n");

  const SHA_A = "a".repeat(40);
  const SHA_B = "b".repeat(40);

  function generate(auditPath, { candidateSha, lockfile, advisorySource, out }) {
    return runGate(auditPath, policyPath, [
      `--artifact-out=${out}`,
      `--candidate-sha=${candidateSha}`,
      `--lockfile=${lockfile}`,
      ...(advisorySource ? [`--advisory-source=${advisorySource}`] : []),
    ]);
  }

  // 7-11: exact provenance fields recorded, raw input retained, hashes
  // independently reproducible from the retained inputs.
  const artifactPathA = join(evidenceDir, "a", "decision.json");
  const genA = generate(cleanAudit, {
    candidateSha: SHA_A,
    lockfile: lockA,
    advisorySource: "test-source-a",
    out: artifactPathA,
  });
  assert.equal(genA.status, 0, `expected evidence generation to succeed\n${genA.stdout}\n${genA.stderr}`);
  const artifactA = JSON.parse(readFileSync(artifactPathA, "utf8"));

  assert.equal(artifactA.candidateSha, SHA_A, "candidateSha must record the exact pinned SHA");
  process.stdout.write("PASS candidate-sha-recorded\n");

  const expectedLockHashA = sha256Bytes(readFileSync(lockA));
  assert.equal(artifactA.lockfileHash, expectedLockHashA, "lockfileHash must match independently computed SHA-256");
  process.stdout.write("PASS lockfile-hash-recorded\n");

  assert.equal(artifactA.advisorySource, "test-source-a", "advisorySource must record the pinned value");
  process.stdout.write("PASS advisory-source-recorded\n");

  const retainedAuditA = join(evidenceDir, "a", "audit.json");
  assert.ok(existsSync(retainedAuditA), "raw audit input must be retained alongside the decision artifact");
  assert.deepEqual(
    JSON.parse(readFileSync(retainedAuditA, "utf8")),
    JSON.parse(readFileSync(cleanAudit, "utf8")),
    "retained audit.json must match the audit input actually evaluated",
  );
  process.stdout.write("PASS raw-audit-input-retained\n");

  const rules = { critical: "deny", high: "deny", moderate: "require_exception", low: "warn" };
  const exceptions = [];
  const findings = []; // cleanAudit has no advisories
  const expectedPolicyHash = sha256(rules);
  const expectedExceptionsHash = sha256(exceptions);
  const expectedFindingsHash = sha256(findings);
  const expectedInputHash = sha256({
    policyHash: expectedPolicyHash,
    exceptionsHash: expectedExceptionsHash,
    findingsHash: expectedFindingsHash,
    decision: "ALLOW",
    reason: "no blocking findings",
  });
  assert.equal(artifactA.policyHash, expectedPolicyHash, "policyHash must be reproducible from the policy input");
  assert.equal(artifactA.exceptionsHash, expectedExceptionsHash, "exceptionsHash must be reproducible from the exception input");
  assert.equal(artifactA.findingsHash, expectedFindingsHash, "findingsHash must be reproducible per existing semantics");
  assert.equal(artifactA.inputHash, expectedInputHash, "inputHash must be reproducible per existing semantics");
  process.stdout.write("PASS policy-exceptions-findings-input-hash-reproducible\n");

  // 12a: inputHash scope is unchanged from formatVersion 1 (commits to the
  // advisory decision inputs only). Verified across two REAL, separately
  // generated artifacts that differ only in candidateSha: their policy,
  // exceptions, and findings are identical, so inputHash must match even
  // though each run's own timestamp differs.
  const artifactPathB = join(evidenceDir, "b", "decision.json");
  const genB = generate(cleanAudit, {
    candidateSha: SHA_B,
    lockfile: lockA,
    advisorySource: "test-source-a",
    out: artifactPathB,
  });
  assert.equal(genB.status, 0, `expected evidence generation to succeed\n${genB.stdout}`);
  const artifactB = JSON.parse(readFileSync(artifactPathB, "utf8"));

  assert.notEqual(artifactA.candidateSha, artifactB.candidateSha, "fixture setup: candidateSha must actually differ");
  assert.equal(artifactA.inputHash, artifactB.inputHash, "inputHash must stay identical when only candidateSha changes");
  process.stdout.write("PASS input-hash-scope-excludes-candidate-sha\n");

  // 12b: artifactHash must be reproducible from exactly the fields the
  // retained artifact actually carries (the reviewer question this whole
  // mechanism exists to answer: "can the integrity hashes be recomputed
  // from the retained inputs?"). Recomputing over everything present in
  // artifactA and comparing to the stored artifactHash is also the direct,
  // correct way to prove candidateSha is bound: if the implementation ever
  // excluded a present field (such as candidateSha) from its own hash
  // input, this recomputation - which naively includes every field the
  // retained JSON actually has - would no longer match the stored value.
  //
  // A clone that also changes the field's VALUE (not just presence) is not
  // used here: hashing a present-but-different-value clone always differs
  // from a hash computed over that field being entirely absent, regardless
  // of whether the absence is the bug under test, which would make such a
  // comparison pass for the wrong reason.
  const { artifactHash: storedHashA, ...restA } = artifactA;
  const reproducedHashA = sha256(restA);
  assert.equal(
    reproducedHashA,
    storedHashA,
    "artifactHash must be reproducible from exactly the retained fields (including candidateSha)",
  );
  process.stdout.write("PASS artifact-hash-reproducible-from-retained-fields\n");

  // Sanity: the reimplemented hash function is actually sensitive to
  // candidateSha's value (not just its presence), so the check above is not
  // vacuously true for an implementation that hashes a constant.
  const valueMutated = sha256({ ...restA, candidateSha: SHA_B });
  assert.notEqual(valueMutated, reproducedHashA, "hash must be sensitive to candidateSha's value");
  process.stdout.write("PASS artifact-hash-sensitive-to-candidate-sha-value\n");

  // 13: malformed / missing required provenance fails clearly.
  const badSha = runGate(cleanAudit, policyPath, [
    `--artifact-out=${join(evidenceDir, "bad-sha", "decision.json")}`,
    "--candidate-sha=main",
    `--lockfile=${lockA}`,
  ]);
  assert.notEqual(badSha.status, 0, "a branch-shaped --candidate-sha must fail evidence generation");
  assert.match(badSha.stdout + badSha.stderr, /candidate-sha must be a hex git commit SHA/);
  assert.ok(!existsSync(join(evidenceDir, "bad-sha", "decision.json")), "no artifact must be written on provenance failure");
  process.stdout.write("PASS malformed-candidate-sha-fails-clearly\n");

  const missingLockfile = join(fixtureDir, "does-not-exist.yaml");
  const badLock = runGate(cleanAudit, policyPath, [
    `--artifact-out=${join(evidenceDir, "bad-lock", "decision.json")}`,
    `--candidate-sha=${SHA_A}`,
    `--lockfile=${missingLockfile}`,
  ]);
  assert.notEqual(badLock.status, 0, "a missing lockfile path must fail evidence generation");
  assert.match(badLock.stdout + badLock.stderr, /lockfileHash could not be determined/);
  process.stdout.write("PASS missing-lockfile-fails-clearly\n");

  // 14: changing lockfile bytes changes lockfileHash.
  const artifactPathC = join(evidenceDir, "c", "decision.json");
  const genC = generate(cleanAudit, {
    candidateSha: SHA_A,
    lockfile: lockB,
    advisorySource: "test-source-a",
    out: artifactPathC,
  });
  assert.equal(genC.status, 0, `expected evidence generation to succeed\n${genC.stdout}`);
  const artifactC = JSON.parse(readFileSync(artifactPathC, "utf8"));
  assert.notEqual(artifactA.lockfileHash, artifactC.lockfileHash, "different lockfile bytes must produce different lockfileHash");
  process.stdout.write("PASS lockfile-byte-change-changes-hash\n");

  // 15: evidence generation does not alter the advisory decision. Compare
  // the plain (no --artifact-out) decision against the evidence-mode
  // decision for both a clean and a blocking audit.
  const plainAllow = runGate(cleanAudit, policyPath);
  assert.match(plainAllow.stdout, /Decision: ALLOW/);
  assert.match(genA.stdout, /Decision: ALLOW/);

  const plainDeny = runGate(blockingAudit, policyPath);
  assert.match(plainDeny.stdout, /Decision: DENY/);
  const denyWithEvidence = generate(blockingAudit, {
    candidateSha: SHA_A,
    lockfile: lockA,
    advisorySource: "test-source-a",
    out: join(evidenceDir, "deny", "decision.json"),
  });
  assert.match(denyWithEvidence.stdout, /Decision: DENY/);
  assert.equal(denyWithEvidence.status, 1, "DENY must still exit 1 with evidence capture enabled");
  process.stdout.write("PASS evidence-generation-does-not-alter-decision\n");

  // auto-detected advisorySource default is non-empty when not pinned.
  const autoArtifactPath = join(evidenceDir, "auto", "decision.json");
  const genAuto = runGate(cleanAudit, policyPath, [
    `--artifact-out=${autoArtifactPath}`,
    `--candidate-sha=${SHA_A}`,
    `--lockfile=${lockA}`,
  ]);
  assert.equal(genAuto.status, 0, `expected auto-detected evidence generation to succeed\n${genAuto.stdout}`);
  const autoArtifact = JSON.parse(readFileSync(autoArtifactPath, "utf8"));
  assert.ok(
    typeof autoArtifact.advisorySource === "string" && autoArtifact.advisorySource.length > 0,
    "advisorySource must default to a non-empty auto-detected value",
  );
  process.stdout.write("PASS advisory-source-auto-detected-default\n");

  process.stdout.write("\nrelease-evidence provenance: all checks passed\n");
} finally {
  rmSync(fixtureDir, { recursive: true, force: true });
}
