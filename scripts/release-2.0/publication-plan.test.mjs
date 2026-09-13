// SPDX-License-Identifier: Apache-2.0
// All evidence is local fixture data. No artifact packing or npm operation.
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import {
  derivePublicationPlan, evaluateReleaseReadiness, buildPublishCommandData,
  computeManifestIntegrity, computeSriIntegrity, MANIFEST_VERSION, STATE_VERSION,
  ReleaseOrchestratorError,
} from "./orchestrator.mjs";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";

function fixture() {
  const releaseId = "a".repeat(40);
  const registry = RELEASE_REGISTRY_REQUIREMENTS.registry;
  const packages = Object.entries(POLICY).map(([name, p]) => ({
    package: name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
    tarball: `tarballs/${name.slice(8)}.tgz`, integrity: computeSriIntegrity(Buffer.from(name)),
  }));
  const manifest = {
    manifestVersion: MANIFEST_VERSION, releaseId, sourceRevision: releaseId,
    createdAt: "2026-09-13T00:00:00.000Z", packages,
    determinismProbe: { package: packages[0].package, deterministic: false, hashA: "a".repeat(64), hashB: "b".repeat(64) },
  };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  const inputs = {
    localPrecheck: { ok: true, discovered: packages.map(p => ({ name: p.package, manifest: { version: p.version } })) },
    manifest,
    state: { stateVersion: STATE_VERSION, releaseId, phase: "VERIFIED_LOCAL",
      history: ["PRECHECK", "PACKED", "VERIFIED_LOCAL"].map(phase => ({ phase, at: manifest.createdAt })),
      packages: Object.fromEntries(packages.map(p => [p.package, { publishStatus: "pending" }])) },
    authPrecheck: { blockers: [], observations: {
      identity: { kind: "identity", registry, username: "maintainer" },
      access: { kind: "access", registry, subject: "maintainer", packages: Object.fromEntries(packages.map(p => [p.package, "read-write"])) },
      packages: packages.map(p => ({ kind: "existing", registry, packageName: p.package, visibility: "public" })),
    } },
  };
  const readiness = evaluateReleaseReadiness(inputs);
  assert.equal(readiness.kind, "ready");
  return { readiness, releaseDir: "/explicit/nonexistent/release" };
}
function reject(f, code) {
  assert.throws(() => derivePublicationPlan(f), error => {
    assert.ok(error instanceof ReleaseOrchestratorError);
    assert.equal(error.code, code);
    return true;
  });
}
function deepFreeze(value) {
  if (value && typeof value === "object") { Object.values(value).forEach(deepFreeze); Object.freeze(value); }
  return value;
}

test("valid Step 4 result yields a complete ordered plan with exact operation bindings and provenance", () => {
  const f = fixture();
  const before = structuredClone(f);
  const plan = derivePublicationPlan(deepFreeze(f));
  const manifest = f.readiness.evidence.manifest;
  assert.equal(plan.kind, "publication-plan");
  assert.equal(plan.releaseId, manifest.releaseId);
  assert.equal(plan.registry, f.readiness.evidence.registry);
  assert.equal(plan.tag, "next");
  assert.equal(plan.access, "public");
  assert.equal(plan.operations.length, manifest.packages.length);
  assert.equal(new Set(plan.operations.map(p => p.package)).size, manifest.packages.length);
  assert.deepEqual(plan.operations.map(p => p.publishOrder), [...manifest.packages].map(p => p.publishOrder).sort((a, b) => a - b));
  for (const [index, op] of plan.operations.entries()) {
    const p = manifest.packages.find(p => p.package === op.package);
    assert.deepEqual(op, { index, releaseId: manifest.releaseId, ...p,
      registry: plan.registry, tag: "next", access: "public",
      command: { executable: "npm", args: ["publish", path.join(f.releaseDir, p.tarball), "--tag", "next", "--access", "public", "--registry", plan.registry], package: p.package, version: p.version },
    });
    assert.deepEqual(op.command, buildPublishCommandData(p, f.releaseDir, { registry: plan.registry }));
  }
  assert.equal(plan.evidence.manifestIntegrity, manifest.manifestIntegrity);
  assert.equal(plan.evidence.sourceRevision, manifest.sourceRevision);
  assert.equal(plan.evidence.readinessState, "READY_FOR_PUBLISH");
  assert.deepEqual(plan.evidence.packagesEvaluated, [...f.readiness.evidence.packagesEvaluated].sort());
  assert.equal(plan.evidence.username, "maintainer");
  assert.deepEqual(f, before);
  plan.evidence.requirements.requiredRegistryAccess = "changed output";
  assert.deepEqual(f, before);
});

test("input array order cannot influence the plan; sparse existing order values are valid", () => {
  const f = fixture(), shuffled = structuredClone(f);
  shuffled.readiness.evidence.manifest.packages.reverse();
  shuffled.readiness.evidence.packagesEvaluated.reverse();
  shuffled.readiness.evidence.localPrecheck.discovered.reverse();
  shuffled.readiness.evidence.authPrecheck.observations.packages.reverse();
  // Retain the recorded digest: Step 5 does not regenerate Step 4 evidence.
  assert.deepEqual(derivePublicationPlan(shuffled), derivePublicationPlan(f));
  assert.ok(derivePublicationPlan(f).operations.some(p => p.publishOrder === 85));
});

const mutations = [
  ["missing readiness", f => { delete f.readiness; }, "READINESS_NOT_ESTABLISHED"],
  ["not-ready", f => { f.readiness = { kind: "not-ready", reasons: [] }; }, "READINESS_NOT_ESTABLISHED"],
  ["malformed readiness", f => { f.readiness = true; }, "READINESS_NOT_ESTABLISHED"],
  ["wrong readiness state", f => { f.readiness.state = "VERIFIED_LOCAL"; }, "READINESS_NOT_ESTABLISHED"],
  ["missing evidence", f => { delete f.readiness.evidence; }, "READINESS_EVIDENCE_INVALID"],
  ["missing requirements", f => { delete f.readiness.evidence.requirements; }, "READINESS_EVIDENCE_INVALID"],
  ["local failure remains", f => { f.readiness.evidence.localPrecheck.ok = false; }, "READINESS_EVIDENCE_INVALID"],
  ["auth failure remains", f => { f.readiness.evidence.authPrecheck.blockers.push("unresolved"); }, "READINESS_EVIDENCE_INVALID"],
  ["missing auth observations", f => { delete f.readiness.evidence.authPrecheck.observations; }, "READINESS_EVIDENCE_INVALID"],
  ["identity registry mismatch", f => { f.readiness.evidence.authPrecheck.observations.identity.registry = "https://other.invalid/"; }, "READINESS_EVIDENCE_INVALID"],
  ["package observation registry mismatch", f => { f.readiness.evidence.authPrecheck.observations.packages[0].registry = "https://other.invalid/"; }, "READINESS_EVIDENCE_INVALID"],
  ["malformed manifest", f => { f.readiness.evidence.manifest = null; }, "READINESS_EVIDENCE_INVALID"],
  ["empty manifest", f => { f.readiness.evidence.manifest.packages = []; }, "READINESS_EVIDENCE_INVALID"],
  ["unsupported manifest version", f => { f.readiness.evidence.manifest.manifestVersion++; }, "READINESS_EVIDENCE_INVALID"],
  ["missing releaseId", f => { delete f.readiness.evidence.manifest.releaseId; }, "RELEASE_IDENTITY_MISMATCH"],
  ["releaseId mismatch", f => { f.readiness.evidence.releaseState.releaseId = "b".repeat(40); }, "RELEASE_IDENTITY_MISMATCH"],
  ["source mismatch", f => { f.readiness.evidence.manifest.sourceRevision = "b".repeat(40); }, "RELEASE_IDENTITY_MISMATCH"],
  ["manifest integrity missing", f => { delete f.readiness.evidence.manifest.manifestIntegrity; }, "READINESS_EVIDENCE_INVALID"],
  ["manifest integrity malformed", f => { f.readiness.evidence.manifest.manifestIntegrity = "sha256:abc"; }, "READINESS_EVIDENCE_INVALID"],
  ["package-set mismatch", f => { f.readiness.evidence.packagesEvaluated.pop(); }, "PACKAGE_SET_MISMATCH"],
  ["duplicate package", f => { const ps = f.readiness.evidence.manifest.packages; ps[1] = ps[0]; }, "PACKAGE_SET_MISMATCH"],
  ["duplicate evaluated package", f => { const ps = f.readiness.evidence.packagesEvaluated; ps[1] = ps[0]; }, "PACKAGE_SET_MISMATCH"],
  ["duplicate order", f => { const ps = f.readiness.evidence.manifest.packages; ps[1].publishOrder = ps[0].publishOrder; }, "PUBLICATION_ORDER_INVALID"],
  ["missing order", f => { delete f.readiness.evidence.manifest.packages[0].publishOrder; }, "PUBLICATION_ORDER_INVALID"],
  ["non-numeric order", f => { f.readiness.evidence.manifest.packages[0].publishOrder = "10"; }, "PUBLICATION_ORDER_INVALID"],
  ["unsafe integer order", f => { f.readiness.evidence.manifest.packages[0].publishOrder = Number.MAX_SAFE_INTEGER + 1; }, "PUBLICATION_ORDER_INVALID"],
  ["version mismatch", f => { f.readiness.evidence.manifest.packages[0].version = "2.0.1"; }, "PACKAGE_METADATA_INVALID"],
  ["release-line mismatch", f => { f.readiness.evidence.manifest.packages[0].releaseLine = "cli"; }, "PACKAGE_METADATA_INVALID"],
  ["unknown release line", f => { f.readiness.evidence.manifest.packages[0].releaseLine = "future"; }, "PACKAGE_METADATA_INVALID"],
  ["integrity missing", f => { delete f.readiness.evidence.manifest.packages[0].integrity; }, "PACKAGE_METADATA_INVALID"],
  ["integrity malformed", f => { f.readiness.evidence.manifest.packages[0].integrity = "sha512-invalid"; }, "PACKAGE_METADATA_INVALID"],
  ["shared tarball", f => { const ps = f.readiness.evidence.manifest.packages; ps[1].tarball = ps[0].tarball; }, "PACKAGE_METADATA_INVALID"],
  ["non-pending package", f => { f.readiness.evidence.releaseState.packages["@oxdeai/core"].publishStatus = "published"; }, "PUBLICATION_PLANNING_STATE_INVALID"],
  ["unresolved blocker", f => { f.readiness.evidence.releaseState.blocker = {}; }, "PUBLICATION_PLANNING_STATE_INVALID"],
  ["wrong phase", f => { f.readiness.evidence.releaseState.phase = "PARTIAL_NEXT"; }, "PUBLICATION_PLANNING_STATE_INVALID"],
  ["state version unsupported", f => { f.readiness.evidence.releaseState.stateVersion++; }, "PUBLICATION_PLANNING_STATE_INVALID"],
  ["state package missing", f => { delete f.readiness.evidence.releaseState.packages["@oxdeai/core"]; }, "PUBLICATION_PLANNING_STATE_INVALID"],
  ["local candidate list malformed", f => { f.readiness.evidence.localPrecheck.discovered = {}; }, "PACKAGE_SET_MISMATCH"],
];
for (const [label, mutate, code] of mutations) {
  test(`${label} refuses the whole plan`, () => { const f = fixture(); mutate(f); reject(f, code); });
}
for (const tarball of [undefined, "", "../outside.tgz", "../../secret", "/absolute/path.tgz", "tarballs/../../outside.tgz", "tarballs/../core.tgz", "./core.tgz", "C:\\outside.tgz", "C:outside.tgz", "..\\outside.tgz", "\\\\server\\share\\file.tgz", "tarballs/file\0.tgz", "tarballs/file\n.tgz", "tarballs//core.tgz"]) {
  test(`unsafe manifest path rejected: ${JSON.stringify(tarball)}`, () => {
    const f = fixture(); f.readiness.evidence.manifest.packages.at(-1).tarball = tarball;
    reject(f, "UNSAFE_TARBALL_PATH"); // Invalid last operation cannot yield a partial plan.
  });
}
for (const releaseDir of [undefined, "", ".", "relative/release", "C:\\release", "/tmp/bad\0dir", "/tmp/bad\ndir", 123]) {
  test(`releaseDir must be explicit and absolute: ${JSON.stringify(releaseDir)}`, () => {
    reject({ ...fixture(), releaseDir }, "INVALID_RELEASE_DIRECTORY");
  });
}
for (const input of [undefined, null, [], true]) {
  test(`invalid input rejected: ${JSON.stringify(input)}`, () => reject(input, "READINESS_NOT_ESTABLISHED"));
}

test("planner has no effects, time/cwd/environment dependence, transport calls, state transitions or input mutation", () => {
  const f = fixture();
  const expected = derivePublicationPlan(f);
  const before = structuredClone(f);
  const forbidden = () => { assert.fail("planner must not invoke effect surfaces"); };
  try {
    for (const name of ["spawnSync", "spawn", "exec", "execSync", "execFile", "execFileSync"]) mock.method(childProcess, name, forbidden);
    for (const name of ["readFileSync", "writeFileSync", "readdirSync", "statSync", "existsSync", "mkdirSync", "rmSync"]) mock.method(fs, name, forbidden);
    mock.method(Date, "now", forbidden);
    mock.method(Math, "random", forbidden);
    mock.method(process, "cwd", forbidden);
    syncBuiltinESMExports();
    const inputs = { ...deepFreeze(f) };
    for (const name of ["authTransport", "registryTransport", "publicationTransport"]) Object.defineProperty(inputs, name, { get: forbidden });
    assert.deepEqual(derivePublicationPlan(inputs), expected);
    assert.deepEqual(derivePublicationPlan(inputs), expected);
    assert.deepEqual(f, before);
    assert.equal(f.readiness.evidence.releaseState.phase, "VERIFIED_LOCAL");
  } finally {
    mock.restoreAll();
    syncBuiltinESMExports();
  }
  const source = fs.readFileSync(new URL("./orchestrator.mjs", import.meta.url), "utf8");
  const planner = source.slice(source.indexOf("export function derivePublicationPlan"), source.indexOf("// registryTransport: { getRegistryVersion"));
  assert.doesNotMatch(planner, /\b(?:evaluateReleaseReadiness|precheck|observeRegistryPrecheck|verifyLocal|transition|saveState|computeManifestIntegrity)\s*\(/);
  assert.doesNotMatch(planner, /process\.|Date\b|Math\.random/);
});
