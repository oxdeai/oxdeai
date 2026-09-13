// SPDX-License-Identifier: Apache-2.0
// Local fixture receipts/bytes and in-memory transports only.
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { fixturePlan } from "./publication-fixture.mjs";
import {
  publishPlannedOperation, publishNext, computeManifestIntegrity, computeSriIntegrity,
  MANIFEST_VERSION, STATE_VERSION, loadState, ReleaseOrchestratorError, RegistryIntegrityConflictError,
} from "./orchestrator.mjs";

function fixture(t) {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-single-publication-"));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(releaseDir, "tarballs"));
  const releaseId = "a".repeat(40);
  const packages = Object.entries(POLICY).map(([name, p]) => {
    const tarball = `tarballs/${name.slice(8)}.tgz`;
    const bytes = Buffer.from(name);
    fs.writeFileSync(path.join(releaseDir, tarball), bytes);
    return { package: name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball, integrity: computeSriIntegrity(bytes) };
  });
  const manifest = { manifestVersion: MANIFEST_VERSION, releaseId, sourceRevision: releaseId,
    createdAt: "2026-09-13T00:00:00.000Z", packages,
    determinismProbe: { package: packages[0].package, deterministic: false, hashA: "a".repeat(64), hashB: "b".repeat(64) } };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  const state = { stateVersion: STATE_VERSION, releaseId, phase: "VERIFIED_LOCAL",
    history: ["PRECHECK", "PACKED", "VERIFIED_LOCAL"].map(phase => ({ phase, at: manifest.createdAt })),
    packages: Object.fromEntries(packages.map(p => [p.package, { publishStatus: "pending" }])) };
  const plan = fixturePlan(manifest, releaseDir);
  const calls = { observe: [], publish: [] };
  const registryTransport = {
    getRegistryVersion(name, version) { calls.observe.push([name, version]); return { exists: false }; },
    publish(command) { calls.publish.push(command); return { ok: true }; },
  };
  return { plan, manifest, state, releaseDir, operationIndex: 0, registryTransport, calls };
}
function invoke(f) {
  const before = f.calls.publish.length;
  try { return publishPlannedOperation(f); }
  finally { assert.ok(f.calls.publish.length - before <= 1, "one invocation must call publish at most once"); }
}
function observation(f, fn) {
  f.registryTransport.getRegistryVersion = (name, version) => {
    f.calls.observe.push([name, version]);
    return fn(f.calls.observe.length);
  };
}
function publication(f, fn) {
  f.registryTransport.publish = data => { f.calls.publish.push(data); return fn(data); };
}
function onlySelected(f, others) {
  const selected = f.plan.operations[f.operationIndex];
  assert.ok(f.calls.observe.every(([name, version]) => name === selected.package && version === selected.version));
  assert.ok(f.calls.publish.every(data => data.package === selected.package));
  for (const [name, entry] of Object.entries(others)) {
    if (name !== selected.package) assert.deepEqual(f.state.packages[name], entry);
  }
}

test("correct predecessors allow one explicit non-first selection and leave later packages pending", t => {
  const f = fixture(t); f.operationIndex = 2;
  f.state.phase = "PARTIAL_NEXT";
  for (const predecessor of f.plan.operations.slice(0, f.operationIndex)) {
    f.state.packages[predecessor.package] = { publishStatus: "published", registryIntegrity: predecessor.integrity };
  }
  const before = structuredClone(f.state.packages);
  const planBefore = structuredClone(f.plan), manifestBefore = structuredClone(f.manifest);
  assert.equal(invoke(f).phase, "PARTIAL_NEXT");
  const p = f.plan.operations[2];
  assert.deepEqual(f.calls.publish, [p.command]);
  assert.deepEqual(f.calls.observe, [[p.package, p.version]]);
  assert.deepEqual(f.state.packages[p.package], { publishStatus: "published", registryIntegrity: p.integrity });
  onlySelected(f, before);
  assert.deepEqual(f.state.history.slice(-2).map(h => h.phase), ["PUBLISHING_NEXT", "PARTIAL_NEXT"]);
  assert.deepEqual(loadState(f.releaseDir), f.state);
  assert.deepEqual(f.plan, planBefore); assert.deepEqual(f.manifest, manifestBefore);
});

for (const mode of ["all pending", "partial", "missing", "null", "array", "missing integrity", "wrong integrity", "invalid status"]) {
  test(`predecessor ${mode} rejects explicit selection before all effects`, t => {
    const f = fixture(t); f.operationIndex = 2;
    f.state.phase = "PARTIAL_NEXT";
    const [first, second] = f.plan.operations;
    for (const p of [first, second]) {
      f.state.packages[p.package] = { publishStatus: "published", registryIntegrity: p.integrity };
    }
    if (mode === "all pending") f.state.packages[first.package] = { publishStatus: "pending" };
    if (["all pending", "partial"].includes(mode)) f.state.packages[second.package] = { publishStatus: "pending" };
    if (mode === "missing") delete f.state.packages[first.package];
    if (mode === "null") f.state.packages[first.package] = null;
    if (mode === "array") f.state.packages[first.package] = [];
    if (mode === "missing integrity") delete f.state.packages[first.package].registryIntegrity;
    if (mode === "wrong integrity") f.state.packages[first.package].registryIntegrity = second.integrity;
    if (mode === "invalid status") f.state.packages[first.package].publishStatus = "done";
    const before = structuredClone(f.state);
    const forbidden = () => assert.fail("order rejection must precede all effects and transport access");
    f.registryTransport = new Proxy({}, { get: forbidden });
    try {
      for (const name of ["readFileSync", "existsSync", "writeFileSync"]) mock.method(fs, name, forbidden);
      syncBuiltinESMExports();
      assert.throws(() => invoke(f), { code: "PUBLICATION_ORDER_NOT_SATISFIED" });
      assert.equal(f.calls.publish.length, 0);
      assert.equal(f.calls.observe.length, 0);
      assert.deepEqual(f.state, before);
    } finally { mock.restoreAll(); syncBuiltinESMExports(); }
  });
}

for (const locallyPublished of [false, true]) {
  test(`matching observation records only selected package, zero publish calls (local published=${locallyPublished})`, t => {
    const f = fixture(t), p = f.plan.operations[0];
    if (locallyPublished) {
      f.state.phase = "PARTIAL_NEXT";
      f.state.packages[p.package] = { publishStatus: "published", registryIntegrity: p.integrity };
    }
    const before = structuredClone(f.state.packages);
    observation(f, () => ({ exists: true, integrity: p.integrity }));
    assert.equal(invoke(f).phase, "PARTIAL_NEXT");
    assert.equal(f.calls.publish.length, 0);
    assert.equal(f.state.packages[p.package].publishStatus, "published");
    onlySelected(f, before);
  });
}

test("conflicting selected version persists conflict and stops before publication", t => {
  const f = fixture(t), before = structuredClone(f.state.packages);
  observation(f, () => ({ exists: true, integrity: "sha512-WRONG" }));
  assert.throws(() => invoke(f), RegistryIntegrityConflictError);
  assert.equal(f.calls.publish.length, 0);
  assert.equal(loadState(f.releaseDir).blocker.code, "REGISTRY_INTEGRITY_CONFLICT");
  onlySelected(f, before);
});

for (const response of ["failure", "undefined", "throw", "string success"]) {
  for (const after of ["matching", "missing", "conflict", "unknown", "throw"]) {
    test(`${response} publication then ${after}: one attempt, same-package reconciliation only`, t => {
      const f = fixture(t), p = f.plan.operations[0], before = structuredClone(f.state.packages);
      observation(f, n => {
        if (n === 1 || after === "missing") return { exists: false };
        if (after === "throw") throw new Error("observation unavailable");
        if (after === "unknown") return {};
        return { exists: true, integrity: after === "matching" ? p.integrity : "sha512-WRONG" };
      });
      publication(f, () => {
        if (response === "throw") throw new Error("publication interrupted");
        return response === "undefined" ? undefined : { ok: response === "string success" ? "true" : false };
      });
      if (after === "matching" || (after === "missing" && response !== "throw")) invoke(f);
      else assert.throws(() => invoke(f), after === "conflict" ? RegistryIntegrityConflictError : Error);
      assert.equal(f.calls.publish.length, 1);
      assert.equal(f.calls.observe.length, 2);
      assert.equal(f.state.phase, "PARTIAL_NEXT");
      assert.equal(f.state.packages[p.package].publishStatus, after === "matching" ? "published" : "pending");
      assert.equal(Object.hasOwn(loadState(f.releaseDir), "blocker"), after !== "matching");
      onlySelected(f, before);
    });
  }
}

test("each package requires a separate invocation; only the last completes PUBLISHED_NEXT", t => {
  const f = fixture(t);
  for (const op of f.plan.operations) {
    f.operationIndex = op.index;
    invoke(f);
    assert.equal(f.calls.publish.length, op.index + 1);
    assert.equal(f.state.phase, op.index === f.plan.operations.length - 1 ? "PUBLISHED_NEXT" : "PARTIAL_NEXT");
  }
  assert.deepEqual(loadState(f.releaseDir), f.state);
});

const mutations = [
  ["missing plan", f => { delete f.plan; }],
  ["array plan", f => { f.plan = []; }],
  ["wrong kind", f => { f.plan.kind = "ready"; }],
  ["missing operations", f => { delete f.plan.operations; }],
  ["empty operations", f => { f.plan.operations = []; }],
  ["duplicate operation", f => { f.plan.operations[1] = f.plan.operations[0]; }],
  ["operation not in plan", f => { f.plan.operations[0] = {}; }],
  ["null operation", f => { f.plan.operations[0] = null; }],
  ["plan identity", f => { f.plan.releaseId = "b".repeat(40); }],
  ["missing manifest", f => { delete f.manifest; }],
  ["manifest identity", f => { f.manifest.releaseId = "b".repeat(40); }],
  ["manifest bytes", f => { f.manifest.createdAt = "changed"; }],
  ["manifest package", f => { f.manifest.packages[0].package = "@oxdeai/unknown"; }],
  ["manifest version", f => { f.manifest.manifestVersion++; }],
  ["evidence missing", f => { delete f.plan.evidence; }],
  ["evidence digest", f => { f.plan.evidence.manifestIntegrity = "sha256:wrong"; }],
  ["evidence set", f => { f.plan.evidence.packagesEvaluated.pop(); }],
  ["requirements registry", f => { f.plan.evidence.requirements.registry = "https://other.invalid/"; }],
  ["plan registry", f => { f.plan.registry = "https://other.invalid/"; }],
  ["plan tag", f => { f.plan.tag = "latest"; }],
  ["plan access", f => { f.plan.access = "restricted"; }],
  ["state absent", f => { delete f.state; }],
  ["state identity", f => { f.state.releaseId = "b".repeat(40); }],
  ["state version", f => { f.state.stateVersion++; }],
  ["state package missing", f => { delete f.state.packages["@oxdeai/core"]; }],
  ["state phase", f => { f.state.phase = "PUBLISHED_NEXT"; }],
  ["state integrity", f => { f.state.phase = "PARTIAL_NEXT"; f.state.packages["@oxdeai/core"] = { publishStatus: "published", registryIntegrity: "wrong" }; }],
  ["state later verification", f => { f.state.packages["@oxdeai/core"].registryVerified = true; }],
  ["blocker for another package", f => { f.state.phase = "PARTIAL_NEXT"; f.state.blocker = { package: "@oxdeai/cli" }; }],
  ["missing transport", f => { delete f.registryTransport; }],
  ["malformed transport", f => { f.registryTransport = true; }],
  ["missing publish", f => { delete f.registryTransport.publish; }],
  ["missing observation", f => { delete f.registryTransport.getRegistryVersion; }],
  ["wrong releaseDir", f => { f.releaseDir += "/other"; }],
  ["relative releaseDir", f => { f.releaseDir = "relative"; }],
];
for (const field of ["index", "releaseId", "package", "version", "releaseLine", "tarball", "integrity", "registry", "tag", "access", "publishOrder", "command"]) {
  mutations.push([`operation ${field}`, f => { f.plan.operations[0][field] = "wrong"; }]);
}
for (const index of [undefined, null, -1, 10, 1.5, "0", Number.MAX_SAFE_INTEGER]) {
  mutations.push([`selection ${index}`, f => { f.operationIndex = index; }]);
}
for (const [label, mutate] of mutations) {
  test(`${label} rejects before any transport call`, t => {
    const f = fixture(t); mutate(f);
    assert.throws(() => invoke(f), ReleaseOrchestratorError);
    assert.equal(f.calls.publish.length, 0);
    assert.equal(f.calls.observe.length, 0);
  });
}
for (const tarball of ["../outside.tgz", "/tmp/outside.tgz", "tarballs/../outside.tgz", "C:\\outside.tgz", "tarballs//file.tgz"]) {
  test(`coordinated unsafe path rejected: ${tarball}`, t => {
    const f = fixture(t);
    f.manifest.packages[0].tarball = tarball;
    f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
    f.plan.evidence.manifestIntegrity = f.manifest.manifestIntegrity;
    f.plan.operations[0].tarball = tarball;
    assert.throws(() => invoke(f), { code: "UNSAFE_TARBALL_PATH" });
    assert.equal(f.calls.publish.length, 0); assert.equal(f.calls.observe.length, 0);
  });
}
for (const mode of ["missing", "changed"]) {
  test(`selected original tarball ${mode} stops before transport`, t => {
    const f = fixture(t), file = path.join(f.releaseDir, f.plan.operations[0].tarball);
    if (mode === "missing") fs.rmSync(file); else fs.writeFileSync(file, "other bytes");
    assert.throws(() => invoke(f), ReleaseOrchestratorError);
    assert.equal(f.calls.publish.length, 0); assert.equal(f.calls.observe.length, 0);
  });
}
for (const reg of [null, {}, { exists: "false" }, { exists: true }]) {
  test(`unknown initial registry response ${JSON.stringify(reg)} cannot authorize an attempt`, t => {
    const f = fixture(t); observation(f, () => reg);
    assert.throws(() => invoke(f), { code: "REGISTRY_STATE_UNDETERMINED" });
    assert.equal(f.calls.publish.length, 0);
  });
}

test("historical batch API rejects without consulting even transport properties", t => {
  const f = fixture(t);
  const forbidden = new Proxy({}, { get() { assert.fail("retired API consulted input"); } });
  assert.throws(() => publishNext(forbidden), { code: "PUBLICATION_OPERATION_NOT_FOUND" });
  assert.throws(() => publishNext(f), { code: "PUBLICATION_OPERATION_NOT_FOUND" });
  assert.equal(f.calls.publish.length, 0); assert.equal(f.calls.observe.length, 0);
  const source = fs.readFileSync(new URL("./orchestrator.mjs", import.meta.url), "utf8");
  assert.equal((source.match(/registryTransport\.publish\(/g) ?? []).length, 1);
});

test("publication uses only injected effects; no child process, network or promotion", t => {
  const f = fixture(t);
  const forbidden = () => assert.fail("unexpected effect");
  try {
    for (const name of ["spawnSync", "spawn", "exec", "execSync", "execFile", "execFileSync"]) mock.method(childProcess, name, forbidden);
    mock.method(globalThis, "fetch", forbidden);
    syncBuiltinESMExports();
    f.registryTransport.applyDistTag = forbidden;
    f.registryTransport.observeDistTag = forbidden;
    invoke(f);
    assert.equal(f.calls.publish.length, 1);
  } finally { mock.restoreAll(); syncBuiltinESMExports(); }
});

test("retry requires another explicit invocation and clears only the selected blocker", t => {
  const f = fixture(t);
  publication(f, () => ({ ok: false, error: "not accepted" }));
  invoke(f);
  assert.equal(f.calls.publish.length, 1);
  assert.equal(f.state.blocker.package, f.plan.operations[0].package);
  publication(f, () => ({ ok: true }));
  invoke(f);
  assert.equal(f.calls.publish.length, 2); // Two separate invocations.
  assert.equal(f.state.phase, "PARTIAL_NEXT");
  assert.equal(Object.hasOwn(f.state, "blocker"), false);
  assert.deepEqual(f.state.history.slice(-2).map(h => h.phase), ["PUBLISHING_NEXT", "PARTIAL_NEXT"]);
});

test("an initial observation exception persists a blocker without publication", t => {
  const f = fixture(t);
  observation(f, () => { throw new Error("offline"); });
  assert.throws(() => invoke(f), /offline/);
  assert.equal(f.calls.publish.length, 0);
  assert.equal(f.calls.observe.length, 1);
  assert.equal(loadState(f.releaseDir).blocker.code, "PUBLICATION_FAILED");
});

for (const failingWrite of [1, 2]) {
  test(`state persistence exception at write ${failingWrite} never retries publication`, t => {
    const f = fixture(t), write = fs.writeFileSync;
    let writes = 0;
    try {
      mock.method(fs, "writeFileSync", (...args) => {
        if (++writes === failingWrite) throw new Error("fixture disk unavailable");
        return write(...args);
      });
      syncBuiltinESMExports();
      assert.throws(() => invoke(f), /fixture disk unavailable/);
      assert.equal(f.calls.publish.length, failingWrite === 1 ? 0 : 1);
    } finally { mock.restoreAll(); syncBuiltinESMExports(); }
  });
}

test("a missing unselected tarball causes no implicit work on that package", t => {
  const f = fixture(t);
  fs.rmSync(path.join(f.releaseDir, f.plan.operations[1].tarball));
  invoke(f);
  assert.equal(f.calls.publish.length, 1);
  assert.equal(f.state.packages[f.plan.operations[1].package].publishStatus, "pending");
});

for (const input of [null, [], true]) {
  test(`invalid API container ${JSON.stringify(input)} fails closed`, () => {
    assert.throws(() => publishPlannedOperation(input), { code: "PUBLICATION_PLAN_INVALID" });
  });
}
