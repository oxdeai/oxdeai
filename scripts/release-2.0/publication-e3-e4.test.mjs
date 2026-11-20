// SPDX-License-Identifier: Apache-2.0
// E3/E4 regression tests (release-security audit, 2026-11-19).
//   E3: publication consent must be required before any publication effect, in
//       full AND selection mode, for every operation and any transport.
//   E4: a transport `ok: true` never establishes publication by itself; only an
//       independent registry observation of the exact planned integrity does.
// Hermetic: in-memory registry transports only. No npm process, no network.
// The consent receipt is unsigned control-flow data; these tests do not claim it
// authenticates its issuer.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { forgeSelectionReceipt, persistFixturePrecheck } from "./precheck-fixture.mjs";
import { fixturePlan } from "./publication-fixture.mjs";
import { consent } from "./publication-authorization.fixture.mjs";
import {
  computeManifestIntegrity, computeSriIntegrity, publishPlannedOperation, resume, loadState,
  RegistryIntegrityConflictError, MANIFEST_FILENAME, STATE_FILENAME, F2_CLI1_SELECTION,
} from "./orchestrator.mjs";

// Selection mode on this R3 checkout: the only accepted selection is the exact
// F2_CLI1_SELECTION profile, and the R3 completeness rule refuses that partial
// selection in every phase. No selection manifest can therefore reach a
// publication effect; selection mode is covered below as DENY-before-effect.
const MODES = ["full"];

function fixture(t, mode = "full") {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-e3e4-"));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  const revision = "a".repeat(40);
  const discovered = Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version, ...(name === "@oxdeai/core" ? {} : { dependencies: { "@oxdeai/core": "workspace:*" } }) } }));
  const precheckDir = fs.mkdtempSync(path.join(releaseDir, "precheck-"));
  const precheck = mode === "selection"
    ? forgeSelectionReceipt(discovered, precheckDir, revision, "/fake", { selection: F2_CLI1_SELECTION })
    : persistFixturePrecheck(discovered, precheckDir, revision, "/fake");
  fs.mkdirSync(path.join(releaseDir, "tarballs"));
  const packages = discovered.map((d) => {
    const tarball = `tarballs/${d.name.slice(8)}.tgz`, bytes = Buffer.from(d.name);
    fs.writeFileSync(path.join(releaseDir, tarball), bytes);
    const p = POLICY[d.name];
    return { package: d.name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball, integrity: computeSriIntegrity(bytes) };
  });
  const manifest = { manifestVersion: 1, releaseId: revision, sourceRevision: revision, packages, precheck,
    ...(mode === "selection" ? { selection: structuredClone(F2_CLI1_SELECTION) } : {}) };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  // A selection manifest yields no plan on this checkout; reuse the full-mode
  // plan an operator could hold from before the selection was introduced.
  const plan = fixturePlan(mode === "selection" ? fullModeTwin(manifest) : manifest, releaseDir);
  const state = { stateVersion: 1, releaseId: revision, phase: "VERIFIED_LOCAL",
    history: [{ phase: "PRECHECK", at: precheck.observedAt, receiptDigest: precheck.receiptDigest },
      { phase: "PACKED" }, { phase: "VERIFIED_LOCAL" }],
    packages: Object.fromEntries(packages.map((p) => [p.package, { publishStatus: "pending" }])) };
  // Simulated registry. `accept` decides what a publish call does to it.
  const registry = new Map(), observations = [], effects = [];
  const f = { manifest, plan, state, releaseDir, discovered, operationIndex: 0, registry, observations, effects,
    accept: (p) => registry.set(p.package, p.integrity), response: () => ({ ok: true }), observe: null };
  f.registryTransport = {
    getRegistryVersion(name, version) {
      observations.push(`${name}@${version}`);
      if (f.observe) return f.observe(name, observations.length);
      return registry.has(name) ? { exists: true, integrity: registry.get(name) } : { exists: false };
    },
    publish(command) {
      effects.push(command.package);
      f.accept(packages.find((p) => p.package === command.package));
      return f.response(command);
    },
  };
  f.authorization = consent(f);
  return f;
}
function fullModeTwin(manifest) {
  const twin = structuredClone(manifest);
  delete twin.selection;
  twin.precheck = persistFixturePrecheck(Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version, ...(name === "@oxdeai/core" ? {} : { dependencies: { "@oxdeai/core": "workspace:*" } }) } })),
    fs.mkdtempSync(path.join(tmpdir(), "oxdeai-e3e4-twin-")), manifest.sourceRevision, "/fake");
  twin.manifestIntegrity = computeManifestIntegrity(twin);
  return twin;
}
const select = (f, index) => { f.operationIndex = index; f.authorization = consent(f); return f; };
const save = (f) => {
  fs.writeFileSync(path.join(f.releaseDir, MANIFEST_FILENAME), JSON.stringify(f.manifest));
  fs.writeFileSync(path.join(f.releaseDir, STATE_FILENAME), JSON.stringify(f.state));
};
const stateFile = (f) => path.join(f.releaseDir, STATE_FILENAME);
function assertNoEffect(f, before) {
  assert.deepEqual(f.effects, [], "no publication effect");
  assert.deepEqual(f.observations, [], "no registry observation");
  assert.equal(fs.existsSync(stateFile(f)), false, "no persisted state transition");
  if (before) assert.deepEqual(f.state, before, "in-memory state unchanged");
}
// Forbids every transport property access: proves consent is checked first.
const untouchable = () => new Proxy({}, { get() { assert.fail("transport consulted before consent"); } });

// ── E3: mandatory consent ─────────────────────────────────────────────────

for (const mode of MODES) {
  test(`E3 [${mode}] missing authorization: DENY before any transport access or state write`, (t) => {
    const f = fixture(t, mode); delete f.authorization;
    const before = structuredClone(f.state);
    f.registryTransport = untouchable();
    assert.throws(() => publishPlannedOperation(f), { code: "PUBLICATION_AUTHORIZATION_REQUIRED" });
    assertNoEffect(f, before);
  });

  test(`E3 [${mode}] missing authorization is refused for every operation index and package`, (t) => {
    for (let i = 0; i < 10; i++) {
      const f = fixture(t, mode);
      for (let j = 0; j < i; j++) { // satisfy predecessor order with recorded registry evidence
        const op = f.plan.operations[j];
        f.state.packages[op.package] = { publishStatus: "published", registryIntegrity: op.integrity };
      }
      if (i > 0) f.state.phase = "PARTIAL_NEXT";
      f.operationIndex = i; f.authorization = null;
      assert.throws(() => publishPlannedOperation(f), { code: "PUBLICATION_AUTHORIZATION_REQUIRED" }, `operation ${i}`);
      assert.deepEqual(f.effects, []);
      assert.deepEqual(f.observations, []);
    }
  });

  for (const [label, make, code] of [
    ["string", () => "yes", "PUBLICATION_AUTHORIZATION_INVALID"],
    ["array", () => [], "PUBLICATION_AUTHORIZATION_INVALID"],
    ["empty object", () => ({}), "PUBLICATION_AUTHORIZATION_INVALID"],
    ["wrong kind", (f) => ({ ...consent(f), kind: "promotion-authorization" }), "PUBLICATION_AUTHORIZATION_INVALID"],
    ["wrong version", (f) => ({ ...consent(f), authorizationVersion: 2 }), "PUBLICATION_AUTHORIZATION_INVALID"],
    ["extra authority field", (f) => ({ ...consent(f), operations: "all" }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["missing field", (f) => { const a = consent(f); delete a.integrity; return a; }, "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other release", (f) => ({ ...consent(f), releaseId: "b".repeat(40) }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other manifest digest", (f) => ({ ...consent(f), manifestIntegrity: "sha256:" + "0".repeat(64) }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other operation", (f) => consent(f, 1), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other operation index only", (f) => ({ ...consent(f), operationIndex: 1 }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other package", (f) => ({ ...consent(f), package: "@oxdeai/cli" }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other version", (f) => ({ ...consent(f), version: "9.9.9" }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other tarball", (f) => ({ ...consent(f), tarball: f.plan.operations[1].tarball }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other integrity", (f) => ({ ...consent(f), integrity: f.plan.operations[1].integrity }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other registry", (f) => ({ ...consent(f), registry: "https://other.invalid/" }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other tag", (f) => ({ ...consent(f), tag: "latest" }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
    ["other access", (f) => ({ ...consent(f), access: "restricted" }), "PUBLICATION_AUTHORIZATION_MISMATCH"],
  ]) {
    test(`E3 [${mode}] ${label} authorization: DENY (${code}) before any effect`, (t) => {
      const f = fixture(t, mode); f.authorization = make(f);
      const before = structuredClone(f.state);
      f.registryTransport = untouchable();
      assert.throws(() => publishPlannedOperation(f), { code });
      assertNoEffect(f, before);
    });
  }

  test(`E3 [${mode}] a receipt valid for operation 0 cannot be reused for operation 1`, (t) => {
    const f = fixture(t, mode);
    publishPlannedOperation(f);
    const reused = f.authorization;
    f.operationIndex = 1; f.authorization = reused;
    const effects = f.effects.length;
    assert.throws(() => publishPlannedOperation(f), { code: "PUBLICATION_AUTHORIZATION_MISMATCH" });
    assert.equal(f.effects.length, effects);
  });

  // ── Valid consent + verified effect ─────────────────────────────────────

  test(`E3/E4 [${mode}] valid authorization and verified registry effect: PASS`, (t) => {
    const f = fixture(t, mode), p = f.plan.operations[0];
    const s = publishPlannedOperation(f);
    assert.deepEqual(f.effects, [p.package]);
    assert.deepEqual(f.observations, [`${p.package}@${p.version}`, `${p.package}@${p.version}`], "observed before and after");
    assert.deepEqual(s.packages[p.package], { publishStatus: "published", registryIntegrity: p.integrity });
    assert.equal(Object.hasOwn(s, "blocker"), false);
    assert.equal(s.phase, "PARTIAL_NEXT");
    assert.deepEqual(loadState(f.releaseDir), s);
  });

  test(`E3/E4 [${mode}] ten authorized operations in frozen order reach PUBLISHED_NEXT`, (t) => {
    const f = fixture(t, mode);
    for (let i = 0; i < 10; i++) publishPlannedOperation(select(f, i));
    assert.equal(f.state.phase, "PUBLISHED_NEXT");
    assert.deepEqual(f.effects, f.plan.operations.map((o) => o.package));
  });

  // ── E4: transport success is not registry evidence ──────────────────────

  test(`E4 [${mode}] transport ok:true but registry has no version: BLOCK, not published`, (t) => {
    const f = fixture(t, mode), p = f.plan.operations[0];
    f.accept = () => {}; // npm "succeeded" but the version never appears
    const s = publishPlannedOperation(f);
    assert.equal(f.effects.length, 1);
    assert.equal(f.observations.length, 2);
    assert.deepEqual(s.packages[p.package], { publishStatus: "pending" });
    assert.equal(s.phase, "PARTIAL_NEXT");
    assert.equal(s.blocker.package, p.package);
    assert.equal(s.blocker.code, "PUBLICATION_FAILED");
    assert.deepEqual(loadState(f.releaseDir), s);
  });

  test(`E4 [${mode}] transport ok:true but registry integrity differs: hard conflict`, (t) => {
    const f = fixture(t, mode), p = f.plan.operations[0];
    f.accept = (q) => f.registry.set(q.package, "sha512-" + "C".repeat(86) + "==");
    assert.throws(() => publishPlannedOperation(f), RegistryIntegrityConflictError);
    const s = loadState(f.releaseDir);
    assert.equal(f.effects.length, 1);
    assert.deepEqual(s.packages[p.package], { publishStatus: "pending" });
    assert.equal(s.blocker.code, "REGISTRY_INTEGRITY_CONFLICT");
    assert.equal(s.phase, "PARTIAL_NEXT");
  });

  for (const [label, after] of [["empty", () => ({})], ["exists without integrity", () => ({ exists: true })],
    ["non-boolean exists", () => ({ exists: "true" })], ["throws", () => { throw new Error("registry unavailable"); }]]) {
    test(`E4 [${mode}] transport ok:true, post-publication observation ${label}: BLOCK (fail closed)`, (t) => {
      const f = fixture(t, mode), p = f.plan.operations[0];
      f.observe = (name, n) => (n === 1 ? { exists: false } : after());
      assert.throws(() => publishPlannedOperation(f));
      const s = loadState(f.releaseDir);
      assert.equal(f.effects.length, 1);
      assert.deepEqual(s.packages[p.package], { publishStatus: "pending" });
      assert.equal(s.phase, "PARTIAL_NEXT");
      assert.equal(s.blocker.package, p.package);
    });
  }

  test(`E4 [${mode}] registry observation unknown before publication: BLOCK, no effect`, (t) => {
    const f = fixture(t, mode);
    f.observe = () => ({});
    assert.throws(() => publishPlannedOperation(f), { code: "REGISTRY_STATE_UNDETERMINED" });
    assert.deepEqual(f.effects, []);
  });

  for (const response of [{ ok: true }, { ok: "true" }, { ok: false }, undefined, "ok"]) {
    test(`E4 [${mode}] response ${JSON.stringify(response)} is never evidence: the outcome follows the registry only`, (t) => {
      const f = fixture(t, mode), p = f.plan.operations[0];
      f.response = () => response; f.accept = () => {};
      const s = publishPlannedOperation(f);
      assert.equal(s.packages[p.package].publishStatus, "pending");
      assert.equal(s.blocker.package, p.package);
    });
  }

  // ── Ambiguity and repeated attempts ─────────────────────────────────────

  test(`E4 [${mode}] ambiguous publication effect: PARTIAL_NEXT, exactly one attempt, no automatic retry`, (t) => {
    const f = fixture(t, mode), p = f.plan.operations[0];
    f.accept = () => {};
    f.response = () => { throw new Error("ETIMEDOUT: publication interrupted"); };
    assert.throws(() => publishPlannedOperation(f), /ETIMEDOUT/);
    const s = loadState(f.releaseDir);
    assert.equal(f.effects.length, 1, "one attempt only");
    assert.equal(s.phase, "PARTIAL_NEXT");
    assert.equal(s.blocker.code, "PUBLICATION_FAILED");
    assert.deepEqual(s.packages[p.package], { publishStatus: "pending" });
  });

  test(`E4 [${mode}] repeated publication attempt after uncertainty: BLOCK until full-plan reconciliation`, (t) => {
    const f = fixture(t, mode), p = f.plan.operations[0];
    f.accept = () => {};
    publishPlannedOperation(f); // ok:true, version absent -> blocker
    assert.equal(f.state.blocker.package, p.package);
    const effects = f.effects.length, observations = f.observations.length;
    f.accept = (q) => f.registry.set(q.package, q.integrity);
    f.authorization = consent(f); // even with fresh, exactly bound consent
    assert.throws(() => publishPlannedOperation(f), { code: "PUBLICATION_STATE_INVALID" });
    assert.equal(f.effects.length, effects, "no second publication attempt");
    assert.equal(f.observations.length, observations, "rejected before any registry access");
  });

  test(`E4 [${mode}] after explicit resume reconciliation, an authorized retry is allowed (PARTIAL_NEXT semantics preserved)`, (t) => {
    const f = fixture(t, mode), p = f.plan.operations[0];
    f.accept = () => {};
    publishPlannedOperation(f);
    save(f);
    const resumed = resume(f); // full-plan reconciliation: version still absent
    assert.equal(Object.hasOwn(resumed.state, "blocker"), false);
    assert.equal(resumed.toPublish.length, 10);
    f.state = resumed.state; f.accept = (q) => f.registry.set(q.package, q.integrity);
    f.authorization = consent(f);
    const s = publishPlannedOperation(f);
    assert.deepEqual(s.packages[p.package], { publishStatus: "published", registryIntegrity: p.integrity });
    assert.equal(f.effects.length, 2, "the retry is a separate, explicit, authorized invocation");
  });

  test(`E4 [${mode}] late registry appearance is reconciled by resume without a second publication`, (t) => {
    const f = fixture(t, mode), p = f.plan.operations[0];
    f.accept = () => {};
    publishPlannedOperation(f); // registry lagging: absent right after publication
    save(f);
    f.registry.set(p.package, p.integrity); // the version appears later
    const resumed = resume(f);
    assert.deepEqual(resumed.state.packages[p.package], { publishStatus: "published", registryIntegrity: p.integrity });
    assert.equal(f.effects.length, 1);
  });
}

// ── Selection mode: unreachable for publication, DENY before any effect ────

for (const [label, make] of [
  ["missing authorization", () => undefined],
  ["malformed authorization", () => ({ kind: "publication-authorization" })],
  ["authorization for another operation", (f) => ({ ...consent(f, 1) })],
  ["authorization for another tarball", (f) => ({ ...consent(f), tarball: f.plan.operations[1].tarball })],
  ["exactly bound authorization", (f) => consent(f)],
]) {
  test(`E3 [selection f2-cli1] ${label}: DENY before any transport access or state write`, (t) => {
    const f = fixture(t, "selection");
    f.authorization = make(f);
    const before = structuredClone(f.state);
    f.registryTransport = untouchable();
    assert.throws(() => publishPlannedOperation(f));
    assertNoEffect(f, before);
  });
}
