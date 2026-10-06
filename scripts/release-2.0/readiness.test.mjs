// SPDX-License-Identifier: Apache-2.0
import { bindFixturePrecheck } from "./precheck-fixture.mjs";
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import {
  evaluateReleaseReadiness, computeManifestIntegrity, computeSriIntegrity,
  MANIFEST_VERSION, STATE_VERSION, computePrecheckReceiptDigest,
} from "./orchestrator.mjs";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { observeRegistryPrecheck, RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";

function fixture() {
  const sourceRevision = "a".repeat(40);
  const discovered = Object.entries(POLICY).map(([name, p]) => ({ name, manifest: { name, version: p.version } }));
  const localPrecheck = { ok: true, discovered }; // Caller assertions are ignored.
  const manifest = {
    manifestVersion: MANIFEST_VERSION, releaseId: sourceRevision, sourceRevision,
    createdAt: "2026-09-13T00:00:00.000Z",
    determinismProbe: { package: "@oxdeai/core", deterministic: false, hashA: "a".repeat(64), hashB: "b".repeat(64) },
    packages: Object.entries(POLICY).map(([name, p]) => ({
      package: name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball: `tarballs/${name.slice(8)}.tgz`, integrity: computeSriIntegrity(Buffer.from(name)),
    })),
  };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  const state = {
    stateVersion: STATE_VERSION, releaseId: sourceRevision, phase: "VERIFIED_LOCAL",
    history: ["PRECHECK", "PACKED", "VERIFIED_LOCAL"].map(phase => ({ phase, at: manifest.createdAt })),
    packages: Object.fromEntries(discovered.map(p => [p.name, { publishStatus: "pending" }])),
  };
  const registry = RELEASE_REGISTRY_REQUIREMENTS.registry;
  // Step 3 observations are produced here by in-memory fixtures only, before
  // invoking Step 4. Fake artifact receipts do not claim real verification.
  const authPrecheck = observeRegistryPrecheck({ discovered, authTransport: {
    whoami: () => ({ kind: "identity", registry, username: "maintainer" }),
    listPackageAccess: subject => ({ kind: "access", registry, subject,
      packages: Object.fromEntries(discovered.map(p => [p.name, "read-write"])) }),
    getPackageStatus: packageName => ({ kind: "existing", registry, packageName, visibility: "public" }),
  } });
  bindFixturePrecheck(manifest, state);
  return { policy: structuredClone(POLICY), localPrecheck, manifest, state, authPrecheck };
}
// Re-digest an edited receipt so only the binding (not the digest) is wrong.
function consistent(f, edit) {
  edit(f.manifest.precheck);
  f.manifest.precheck.receiptDigest = computePrecheckReceiptDigest(f.manifest.precheck);
  f.state.history[0].receiptDigest = f.manifest.precheck.receiptDigest;
  f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
}
function notReady(inputs, code) {
  const result = evaluateReleaseReadiness(inputs);
  assert.equal(result.kind, "not-ready");
  assert.ok(!Object.hasOwn(result, "state"));
  assert.ok(result.reasons.some(reason => reason.code === code), JSON.stringify(result));
  assert.ok(result.reasons.every(reason => typeof reason.code === "string" && typeof reason.detail === "string"));
  return result;
}
function deepFreeze(value) {
  if (value && typeof value === "object") { Object.values(value).forEach(deepFreeze); Object.freeze(value); }
  return value;
}

test("positive receipts derive structured READY_FOR_PUBLISH with provenance, without changing phase", () => {
  const f = fixture();
  const before = structuredClone(f);
  const result = evaluateReleaseReadiness(deepFreeze(f));
  assert.equal(result.kind, "ready");
  assert.equal(result.state, "READY_FOR_PUBLISH");
  assert.equal(result.evidence.registry, RELEASE_REGISTRY_REQUIREMENTS.registry);
  assert.equal(result.evidence.username, "maintainer");
  assert.equal(result.evidence.requirements.requiredRegistryAccess, "read-write");
  assert.deepEqual(result.evidence.manifest, f.manifest);
  assert.deepEqual(result.evidence.localPrecheck, f.manifest.precheck);
  assert.deepEqual(result.evidence.authPrecheck, f.authPrecheck);
  assert.deepEqual(result.evidence.packagesEvaluated, Object.keys(POLICY).sort());
  assert.equal(result.evidence.manifest.packages.find(p => p.package === "@oxdeai/cli").version, "0.3.1");
  assert.equal(f.state.phase, "VERIFIED_LOCAL");
  assert.deepEqual(f, before);
  result.evidence.manifest.packages[0].version = "changed output";
  assert.deepEqual(f, before); // Output is detached from input.
});

const mutations = [
  // Caller-supplied localPrecheck ({ ok: true, discovered }) stays in the
  // fixture inputs throughout and never substitutes for persisted evidence.
  ["local precheck missing", f => { delete f.manifest.precheck; f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest); }, "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck malformed", f => { f.manifest.precheck = "{"; }, "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck failed", f => consistent(f, r => { r.ok = false; }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck string success", f => consistent(f, r => { r.ok = "true"; }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck dirty tree", f => consistent(f, r => { r.workingTreeClean = false; }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck dirty source", f => consistent(f, r => { r.source.clean = false; }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck unsupported version", f => consistent(f, r => { r.receiptVersion = 2; }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck tampered", f => { f.manifest.precheck.observedAt = "2020-01-01T00:00:00.000Z"; }, "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck inconsistent revision", f => consistent(f, r => { r.source.revision = "b".repeat(40); }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck source revision mismatch", f => consistent(f, r => { r.sourceRevision = r.source.revision = "b".repeat(40); }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck package version mismatch", f => consistent(f, r => { r.discovered[0].manifest.version = "9.0.0"; }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck package set mismatch", f => consistent(f, r => { r.discovered.pop(); }), "LOCAL_PRECHECK_NOT_PASSED"],
  ["local precheck stale for POLICY", f => { f.policy["@oxdeai/core"].version = "9.0.0"; }, "LOCAL_PRECHECK_NOT_PASSED"],
  ["state PRECHECK entry synthesized", f => { f.state.history[0].at = f.manifest.createdAt; }, "LOCAL_PRECHECK_NOT_PASSED"],
  ["state PRECHECK digest unbound", f => { delete f.state.history[0].receiptDigest; }, "LOCAL_PRECHECK_NOT_PASSED"],
  ["not verified", f => { f.state.phase = "PACKED"; f.state.history.pop(); }, "PACKED_ARTIFACTS_NOT_VERIFIED"],
  ["verification history missing", f => { f.state.history = []; }, "PACKED_ARTIFACTS_NOT_VERIFIED"],
  ["manifest missing", f => { delete f.manifest; }, "PACKED_ARTIFACTS_NOT_VERIFIED"],
  ["tarball missing", f => { delete f.manifest.packages[0].tarball; }, "PACKED_ARTIFACTS_NOT_VERIFIED"],
  ["integrity invalid", f => { f.manifest.packages[0].integrity = "sha512-invalid"; }, "PACKED_ARTIFACTS_NOT_VERIFIED"],
  ["manifest digest changed", f => { f.manifest.createdAt = "changed"; }, "PACKED_ARTIFACTS_NOT_VERIFIED"],
  ["manifest version unsupported", f => { f.manifest.manifestVersion++; }, "PACKED_ARTIFACTS_NOT_VERIFIED"],
  ["identity absent", f => { delete f.authPrecheck.observations.identity; }, "AUTH_IDENTITY_NOT_ESTABLISHED"],
  ["identity malformed", f => { f.authPrecheck.observations.identity.username = true; }, "AUTH_IDENTITY_NOT_ESTABLISHED"],
  ["read-only access", f => { f.authPrecheck.observations.access.packages["@oxdeai/core"] = "read-only"; }, "REGISTRY_ACCESS_INSUFFICIENT"],
  ["missing access entry", f => { delete f.authPrecheck.observations.access.packages["@oxdeai/core"]; }, "REGISTRY_STATE_UNDETERMINED"],
  ["unknown access value", f => { f.authPrecheck.observations.access.packages["@oxdeai/core"] = "owner"; }, "REGISTRY_STATE_UNDETERMINED"],
  ["access wrong subject", f => { f.authPrecheck.observations.access.subject = "other"; }, "REGISTRY_STATE_UNDETERMINED"],
  ["private existing package", f => { f.authPrecheck.observations.packages[0].visibility = "private"; }, "PACKAGE_VISIBILITY_MISMATCH"],
  ["unknown visibility", f => { f.authPrecheck.observations.packages[0].visibility = "unknown"; }, "REGISTRY_STATE_UNDETERMINED"],
  ["unknown existence", f => { f.authPrecheck.observations.packages[0].kind = "unknown"; }, "REGISTRY_STATE_UNDETERMINED"],
  ["missing package", f => { const p = f.authPrecheck.observations.packages[0]; p.kind = "missing"; delete p.visibility; }, "PACKAGE_CREATION_AUTHORITY_NOT_ESTABLISHED"],
  ["missing with public assertion", f => { f.authPrecheck.observations.packages[0].kind = "missing"; }, "REGISTRY_STATE_UNDETERMINED"],
  ["wrong registry", f => { f.authPrecheck.observations.packages[0].registry = "https://other.invalid/"; }, "REGISTRY_STATE_UNDETERMINED"],
  ["missing auth observation", f => { f.authPrecheck.observations.packages.pop(); }, "REGISTRY_STATE_UNDETERMINED"],
  ["duplicate auth observation", f => { f.authPrecheck.observations.packages[1] = f.authPrecheck.observations.packages[0]; }, "REGISTRY_STATE_UNDETERMINED"],
  ["extra auth observation", f => { f.authPrecheck.observations.packages.push({ packageName: "extra" }); }, "REGISTRY_STATE_UNDETERMINED"],
  ["unresolved auth blocker", f => { f.authPrecheck.blockers.push("unresolved"); }, "AUTH_PRECHECK_NOT_PASSED"],
  ["auth blockers missing", f => { delete f.authPrecheck.blockers; }, "AUTH_PRECHECK_NOT_PASSED"],
  ["auth result missing", f => { delete f.authPrecheck; }, "AUTH_PRECHECK_NOT_PASSED"],
  ["policy version mismatch", f => { f.policy["@oxdeai/core"].version = "9.0.0"; }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["manifest release line mismatch", f => { f.manifest.packages[0].releaseLine = "cli"; }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["manifest publish order mismatch", f => { f.manifest.packages[0].publishOrder++; }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["missing manifest package", f => { f.manifest.packages.pop(); }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["extra manifest package", f => { f.manifest.packages.push({ package: "extra" }); }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["duplicate manifest package", f => { f.manifest.packages[1] = f.manifest.packages[0]; }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["releaseId mismatch", f => { f.state.releaseId = "b".repeat(40); }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["state version unknown", f => { f.state.stateVersion++; }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["state missing package", f => { delete f.state.packages["@oxdeai/core"]; }, "POLICY_RELEASE_STATE_MISMATCH"],
  ["publication already started", f => { f.state.phase = "PARTIAL_NEXT"; }, "PUBLICATION_PLANNING_STATE_INVALID"],
  ["publication already recorded", f => { f.state.packages["@oxdeai/core"].publishStatus = "published"; }, "PUBLICATION_PLANNING_STATE_INVALID"],
  ["unresolved state blocker", f => { f.state.blocker = { code: "unresolved" }; }, "PUBLICATION_PLANNING_STATE_INVALID"],
];
for (const [label, mutate, code] of mutations) {
  test(`${label} fails closed`, () => { const f = fixture(); mutate(f); notReady(f, code); });
}

// The receipt stays internally consistent (re-digested) and bound to the
// manifest and state, so readiness accepts it as PRECHECK provenance and then
// rejects only because what PRECHECK recorded differs from POLICY.
function rejectsPrecheckAgainstPolicy(f) {
  const result = notReady(f, "POLICY_RELEASE_STATE_MISMATCH");
  assert.ok(result.reasons.some(r => r.code === "POLICY_RELEASE_STATE_MISMATCH" &&
    r.detail === "local precheck package set/versions differ from POLICY"), JSON.stringify(result));
  assert.ok(!result.reasons.some(r => r.code === "LOCAL_PRECHECK_NOT_PASSED"), JSON.stringify(result));
  assert.ok(!result.reasons.some(r => /receiptDigest|binding mismatch/.test(r.detail)), JSON.stringify(result));
}
test("precheck version mismatch fails closed against POLICY", () => {
  const f = fixture();
  const name = f.manifest.precheck.discovered[0].name;
  f.manifest.packages.find(p => p.package === name).version = "9.0.0"; // the candidate PRECHECK observed
  consistent(f, r => { r.discovered[0].manifest.version = "9.0.0"; });
  rejectsPrecheckAgainstPolicy(f);
});
test("precheck set mismatch fails closed against POLICY", () => {
  const f = fixture();
  const name = f.manifest.precheck.discovered.at(-1).name;
  f.manifest.packages = f.manifest.packages.filter(p => p.package !== name); // the candidate PRECHECK observed
  delete f.state.packages[name];
  consistent(f, r => { r.discovered.pop(); });
  rejectsPrecheckAgainstPolicy(f);
});

for (const code of ["AUTH_UNAUTHENTICATED", "REGISTRY_UNAVAILABLE", "REGISTRY_ACCESS_INSUFFICIENT", "REGISTRY_STATE_UNDETERMINED"]) {
  test(`unknown preserves normalized category ${code}`, () => {
    const f = fixture();
    const p = f.authPrecheck.observations.packages[0];
    f.authPrecheck.observations.packages[0] = { kind: "unknown", registry: p.registry, packageName: p.packageName, reason: { code, detail: "normalized observation failure" } };
    notReady(f, code);
  });
}
test("raw errors are not classified or interpreted by Step 4", () => {
  const results = ["E403", "E404", "ENEEDAUTH"].map(code => {
    const f = fixture();
    f.authPrecheck.observations.packages[0] = { ...f.authPrecheck.observations.packages[0], kind: "unknown", reason: { code, detail: "unrecognized raw input" } };
    return notReady(f, "REGISTRY_STATE_UNDETERMINED");
  });
  assert.deepEqual(results[0], results[1]);
  assert.deepEqual(results[1], results[2]);
});
test("empty inputs are not-ready, never a boolean", () => {
  assert.equal(evaluateReleaseReadiness().kind, "not-ready");
});
test("deterministic pure evaluator needs no npm, filesystem, time or transports for either outcome", () => {
  const f = fixture();
  const expected = evaluateReleaseReadiness(f);
  const bad = fixture(); bad.authPrecheck.observations.packages[0].kind = "unknown";
  const expectedBad = evaluateReleaseReadiness(bad);
  const forbidden = () => { assert.fail("readiness must not invoke effects"); };
  try {
    for (const name of ["spawnSync", "spawn", "exec", "execSync", "execFile", "execFileSync"]) mock.method(childProcess, name, forbidden);
    for (const name of ["readFileSync", "writeFileSync", "readdirSync", "statSync", "existsSync", "mkdirSync", "rmSync"]) mock.method(fs, name, forbidden);
    mock.method(Date, "now", forbidden);
    syncBuiltinESMExports();
    const extra = { authTransport: new Proxy({}, { get: forbidden }), registryTransport: new Proxy({}, { get: forbidden }) };
    assert.deepEqual(evaluateReleaseReadiness({ ...deepFreeze(f), ...extra }), expected);
    assert.deepEqual(evaluateReleaseReadiness(structuredClone(f)), expected);
    assert.deepEqual(evaluateReleaseReadiness(deepFreeze(bad)), expectedBad);
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
});

for (const input of [null, true, [], "ready"]) {
  test(`invalid input container returns structured rejection: ${JSON.stringify(input)}`, () => {
    notReady(input, "POLICY_RELEASE_STATE_MISMATCH");
  });
}
