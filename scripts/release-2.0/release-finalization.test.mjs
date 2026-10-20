// SPDX-License-Identifier: Apache-2.0
// RELEASE-FINALIZATION-01. Hermetic: an in-memory dist-tag registry behind an
// injected transport. No npm, no subprocess, no network. Assertions inspect
// the fake registry and the persisted state, not transport return values.
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { POLICY } from "../verify-packed-artifacts.mjs";
import { RELEASE_REGISTRY_REQUIREMENTS } from "./auth-precheck.mjs";
import { persistFixturePrecheck } from "./precheck-fixture.mjs";
import { fixturePlan } from "./publication-fixture.mjs";
import { consent as publicationConsent } from "./publication-authorization.fixture.mjs";
import { validateNextRemovalAuthorization, validatePromotionAuthorization } from "./finalization-authorization.mjs";
import {
  F2_CLI1_SELECTION, MANIFEST_FILENAME, MANIFEST_VERSION, STATE_FILENAME, STATE_VERSION, PHASES,
  computeFinalizationDigest, computeManifestIntegrity, computeSriIntegrity, loadAndValidateManifest, loadState,
  promote, publicationPackages, validateState,
} from "./orchestrator.mjs";
import {
  isReleaseFinalized, promoteLatest, removeNext, verifyFinalization, verifyLatestPromotion,
} from "./release-finalization.mjs";

const REGISTRY = RELEASE_REGISTRY_REQUIREMENTS.registry;
const SELECTED = F2_CLI1_SELECTION.map((p) => p.package);
const EXCLUDED = Object.keys(POLICY).filter((name) => !SELECTED.includes(name));
// Prior `latest` versions the operator consents to replace.
const PRIOR = { "@oxdeai/core": "2.0.1", "@oxdeai/guard": "2.0.2", "@oxdeai/sdk": "2.0.1",
  "@oxdeai/conformance": "2.0.1", "@oxdeai/cli": "0.3.1" };

function fixture(t, { selection = true } = {}) {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-finalization-"));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  const revision = "a".repeat(40);
  const discovered = Object.entries(POLICY).map(([name, p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version, ...(name === "@oxdeai/core" ? {} : { dependencies: { "@oxdeai/core": "workspace:*" } }) } }));
  const precheck = persistFixturePrecheck(discovered, path.join(releaseDir, "precheck"), revision, "/fake",
    selection ? { selection: F2_CLI1_SELECTION } : {});
  const packages = discovered.map((d) => {
    const p = POLICY[d.name];
    return { package: d.name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball: `tarballs/${d.name.slice(8)}.tgz`, integrity: computeSriIntegrity(Buffer.from(d.name)) };
  });
  const manifest = { manifestVersion: MANIFEST_VERSION, releaseId: revision, sourceRevision: revision,
    createdAt: "2026-10-20T00:00:00.000Z", packages, precheck,
    ...(selection ? { selection: structuredClone(F2_CLI1_SELECTION) } : {}) };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  const selected = new Set(publicationPackages(manifest).map((p) => p.package));
  const state = { stateVersion: STATE_VERSION, releaseId: revision, phase: "READY_TO_PROMOTE",
    history: [{ phase: "PRECHECK", at: precheck.observedAt, receiptDigest: precheck.receiptDigest },
      ...["PACKED", "VERIFIED_LOCAL", "PUBLISHING_NEXT", "PUBLISHED_NEXT", "REGISTRY_VERIFIED",
        "EXTERNAL_INSTALL_VERIFIED", "READY_TO_PROMOTE"].map((phase) => ({ phase, at: manifest.createdAt }))],
    packages: Object.fromEntries(packages.map((p) => [p.package, selected.has(p.package)
      ? { publishStatus: "published", registryIntegrity: p.integrity, registryVerified: true, externalInstallVerified: true }
      : { publishStatus: "pending" }])) };
  validateState(manifest, state);
  fs.writeFileSync(path.join(releaseDir, MANIFEST_FILENAME), JSON.stringify(manifest));
  fs.writeFileSync(path.join(releaseDir, STATE_FILENAME), JSON.stringify(state));
  // Fake registry: package -> { latest, next }. Excluded packages carry tags too.
  const tags = new Map(packages.map((p) => [p.package, selected.has(p.package)
    ? { latest: PRIOR[p.package] ?? "1.9.9", next: p.version } : { latest: p.version, next: p.version }]));
  const f = { manifest, state, releaseDir, registry: REGISTRY, tags, effects: [], observations: [], selected: [...selected] };
  f.distTagTransport = {
    observeDistTag({ registry, package: name, tag }) {
      f.observations.push([name, tag]);
      const version = f.tags.get(name)?.[tag];
      return version === undefined ? { registry, package: name, tag, present: false }
        : { registry, package: name, tag, present: true, version };
    },
    addDistTag(op) { f.effects.push(["add", op.package, op.version]); f.tags.get(op.package).latest = op.version; return { ok: true }; },
    removeDistTag(op) { f.effects.push(["rm", op.package]); delete f.tags.get(op.package).next; return { ok: true }; },
  };
  return f;
}

const versionOf = (f, name) => f.manifest.packages.find((p) => p.package === name).version;
const integrityOf = (f, name) => f.manifest.packages.find((p) => p.package === name).integrity;
function promotion(f, name, replaces = PRIOR[name] ?? "1.9.9") {
  return { kind: "promotion-authorization", authorizationVersion: 1, releaseId: f.manifest.releaseId,
    manifestIntegrity: f.manifest.manifestIntegrity, package: name, version: versionOf(f, name),
    integrity: integrityOf(f, name), registry: REGISTRY, tag: "latest", operation: "dist-tag-add", replaces };
}
function removal(f, name) {
  return { kind: "next-removal-authorization", authorizationVersion: 1, releaseId: f.manifest.releaseId,
    manifestIntegrity: f.manifest.manifestIntegrity, package: name, version: versionOf(f, name),
    integrity: integrityOf(f, name), registry: REGISTRY, tag: "next", operation: "dist-tag-rm" };
}
const promoteArgs = (f, name, authorization = promotion(f, name)) => ({ ...f, package: name, authorization });
const removeArgs = (f, name, authorization = removal(f, name)) => ({ ...f, package: name, authorization });
const diskState = (f) => fs.readFileSync(path.join(f.releaseDir, STATE_FILENAME), "utf8");
// Simulated restart: drop all in-memory state and reload persisted evidence.
function restart(f) {
  f.manifest = loadAndValidateManifest(f.releaseDir);
  f.state = loadState(f.releaseDir);
  return f;
}
// Idempotent driver: from any persisted state, perform the remaining steps.
// A persisted in-flight attempt or blocker names the package to resume first.
function finalizeAll(f) {
  restart(f);
  const order = () => {
    const pending = (f.state.finalizationAttempt ?? f.state.finalizationBlocker)?.package;
    return pending ? [pending, ...f.selected.filter((n) => n !== pending)] : f.selected;
  };
  if (["READY_TO_PROMOTE", "PROMOTING_LATEST"].includes(f.state.phase)) {
    for (const name of order()) promoteLatest(promoteArgs(f, name));
    verifyLatestPromotion(f);
  }
  if (["PROMOTED", "REMOVING_NEXT"].includes(f.state.phase)) {
    for (const name of order()) removeNext(removeArgs(f, name));
    verifyFinalization(f);
  }
  return f.state;
}
function assertFinalRegistry(f) {
  for (const p of f.manifest.packages) {
    const t = f.tags.get(p.package);
    if (f.selected.includes(p.package)) assert.deepEqual(t, { latest: p.version }, p.package);
    else assert.deepEqual(t, { latest: p.version, next: p.version }, `excluded ${p.package} untouched`);
  }
}
const assertNoExcludedTraffic = (f) => {
  for (const [name] of [...f.observations, ...f.effects.map(([, n]) => [n])]) assert.ok(f.selected.includes(name), name);
};

test("five selected packages: per-package promotion, independent verification, next removal, persisted finalization", (t) => {
  const f = fixture(t);
  assert.deepEqual(f.selected, SELECTED);
  for (const name of SELECTED) {
    assert.equal(promoteLatest(promoteArgs(f, name)).effect, true);
    assert.equal(f.tags.get(name).latest, versionOf(f, name), "effect observed in registry");
    assert.equal(loadState(f.releaseDir).packages[name].latestVerified, true);
    assert.equal(loadState(f.releaseDir).phase, "PROMOTING_LATEST");
  }
  assert.ok(f.effects.every(([kind]) => kind === "add"), "no next removal before PROMOTED");
  verifyLatestPromotion(f);
  assert.equal(loadState(f.releaseDir).phase, "PROMOTED");
  assert.equal(isReleaseFinalized(f.manifest, f.state), false, "PROMOTED is not finalized");
  for (const name of SELECTED) {
    assert.equal(removeNext(removeArgs(f, name)).effect, true);
    assert.equal(f.tags.get(name).next, undefined);
  }
  assert.equal(isReleaseFinalized(f.manifest, f.state), false, "REMOVING_NEXT is not finalized");
  verifyFinalization({ ...f, now: () => "2026-10-20T12:00:00.000Z" });
  const persisted = loadState(f.releaseDir);
  assert.equal(persisted.phase, "FINALIZED");
  assert.equal(isReleaseFinalized(f.manifest, persisted), true);
  assert.deepEqual(persisted.finalization.packages.map((p) => [p.package, p.version, p.latest, p.next]),
    F2_CLI1_SELECTION.map((p) => [p.package, p.version, p.version, null]));
  assert.equal(persisted.finalization.manifestIntegrity, f.manifest.manifestIntegrity);
  assert.equal(persisted.finalization.finalizationDigest, computeFinalizationDigest(persisted.finalization));
  assert.deepEqual(persisted.history.slice(-4).map((h) => h.phase), ["PROMOTING_LATEST", "PROMOTED", "REMOVING_NEXT", "FINALIZED"]);
  assert.deepEqual(f.effects, [...SELECTED.map((n) => ["add", n, versionOf(f, n)]), ...SELECTED.map((n) => ["rm", n])]);
  for (const name of EXCLUDED) assert.deepEqual(persisted.packages[name], { publishStatus: "pending" });
  assertFinalRegistry(f);
  assertNoExcludedTraffic(f);
});

for (const [label, op] of [["promotion", promoteLatest], ["next removal", removeNext]]) {
  // An explicitly passed undefined must reach the operation, not the default receipt.
  const args = (f, ...auth) => ({ ...(op === promoteLatest ? promoteArgs(f, "@oxdeai/core") : removeArgs(f, "@oxdeai/core")),
    ...(auth.length ? { authorization: auth[0] } : {}) });
  const ready = (f) => { if (op === removeNext) { finalizePromotion(f); f.effects.length = 0; f.observations.length = 0; } };
  const prefix = op === promoteLatest ? "PROMOTION" : "NEXT_REMOVAL";

  for (const receipt of [undefined, null]) {
    test(`${label}: missing authorization (${receipt}) stops before observation or effect`, (t) => {
      const f = fixture(t); ready(f); const before = diskState(f);
      assert.throws(() => op(args(f, receipt)), { code: `${prefix}_AUTHORIZATION_REQUIRED` });
      assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []); assert.equal(diskState(f), before);
    });
  }
  for (const receipt of [false, [], "approve", {}, { kind: "promotion-authorization" }]) {
    test(`${label}: malformed authorization ${JSON.stringify(receipt)} is invalid`, (t) => {
      const f = fixture(t); ready(f); const before = diskState(f);
      assert.throws(() => op(args(f, receipt)), { code: `${prefix}_AUTHORIZATION_INVALID` });
      assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []); assert.equal(diskState(f), before);
    });
  }
  test(`${label}: a publication receipt and the other finalization receipt never authorize it`, (t) => {
    const f = fixture(t); ready(f);
    const plan = fixturePlan(f.manifest, f.releaseDir);
    const other = op === promoteLatest ? removal(f, "@oxdeai/core") : promotion(f, "@oxdeai/core");
    for (const receipt of [publicationConsent({ manifest: f.manifest, plan }, 0), other]) {
      assert.throws(() => op(args(f, receipt)), { code: `${prefix}_AUTHORIZATION_INVALID` });
    }
    assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []);
  });
  const fields = ["releaseId", "manifestIntegrity", "package", "version", "integrity", "registry", "tag", "operation",
    ...(op === promoteLatest ? ["replaces"] : [])];
  for (const field of fields) {
    for (const mode of ["changed", "missing"]) {
      test(`${label}: authorization ${field} ${mode} stops before observation or effect`, (t) => {
        const f = fixture(t); ready(f); const before = diskState(f);
        const auth = op === promoteLatest ? promotion(f, "@oxdeai/core") : removal(f, "@oxdeai/core");
        if (mode === "missing") delete auth[field]; else auth[field] = field === "replaces" ? "2.0.0" : "wrong";
        if (field === "replaces" && mode === "changed") {
          // Valid consent for a different prior version: the observed latest conflicts.
          assert.throws(() => op(args(f, auth)), { code: "DIST_TAG_CONFLICT" });
        } else {
          assert.throws(() => op(args(f, auth)), (e) => /AUTHORIZATION_(INVALID|MISMATCH)$/.test(e.code));
          assert.deepEqual(f.observations, []);
        }
        assert.deepEqual(f.effects, []); assert.equal(diskState(f), before);
      });
    }
  }
  test(`${label}: receipt for another selected package or with extra authority is rejected`, (t) => {
    const f = fixture(t); ready(f);
    const forGuard = op === promoteLatest ? promotion(f, "@oxdeai/guard", "2.0.1") : removal(f, "@oxdeai/guard");
    assert.throws(() => op(args(f, forGuard)), { code: `${prefix}_AUTHORIZATION_MISMATCH` });
    const wide = { ...(op === promoteLatest ? promotion(f, "@oxdeai/core") : removal(f, "@oxdeai/core")), allPackages: true };
    assert.throws(() => op(args(f, wide)), { code: `${prefix}_AUTHORIZATION_MISMATCH` });
    assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []);
  });
  test(`${label}: modified manifest invalidates the operation and its receipt`, (t) => {
    const f = fixture(t); ready(f);
    const auth = op === promoteLatest ? promotion(f, "@oxdeai/core") : removal(f, "@oxdeai/core");
    f.manifest.createdAt = "2000-01-01T00:00:00.000Z";
    assert.throws(() => op(args(f, auth)), { code: "MANIFEST_INTEGRITY_MISMATCH" });
    f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
    assert.throws(() => op(args(f, auth)));
    const validator = op === promoteLatest ? validatePromotionAuthorization : validateNextRemovalAuthorization;
    assert.throws(() => validator({ authorization: auth, manifest: f.manifest, package: "@oxdeai/core", registry: REGISTRY }),
      { code: `${prefix}_AUTHORIZATION_MISMATCH` });
    assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []);
  });
  test(`${label}: excluded package never receives an operation, even with a crafted receipt`, (t) => {
    const f = fixture(t); ready(f); const before = diskState(f);
    for (const name of EXCLUDED) {
      const crafted = { ...(op === promoteLatest ? promotion(f, "@oxdeai/core") : removal(f, "@oxdeai/core")),
        package: name, version: versionOf(f, name), integrity: integrityOf(f, name) };
      const call = op === promoteLatest ? promoteArgs(f, name, crafted) : removeArgs(f, name, crafted);
      assert.throws(() => op(call), { code: "PACKAGE_NOT_SELECTED" });
      const validator = op === promoteLatest ? validatePromotionAuthorization : validateNextRemovalAuthorization;
      assert.throws(() => validator({ authorization: crafted, manifest: f.manifest, package: name, registry: REGISTRY }),
        { code: `${prefix}_AUTHORIZATION_MISMATCH` });
    }
    assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []); assert.equal(diskState(f), before);
  });
  for (const [obsLabel, response] of [
    ["undefined", () => undefined], ["empty", () => ({})],
    ["other registry", (q) => ({ ...q, registry: "https://example.invalid/", present: false })],
    ["other package", (q) => ({ ...q, package: "@oxdeai/guard", present: false })],
    ["other tag", (q) => ({ ...q, tag: q.tag === "latest" ? "next" : "latest", present: false })],
    ["present without version", (q) => ({ ...q, present: true })],
    ["absent with version", (q) => ({ ...q, present: false, version: "2.0.2" })],
    ["string present", (q) => ({ ...q, present: "yes", version: "2.0.2" })],
    ["extra field", (q) => ({ ...q, present: false, cached: true })],
    ["throws", () => { throw new Error("registry unavailable"); }],
  ]) {
    test(`${label}: indeterminate observation (${obsLabel}) fails closed without effect`, (t) => {
      const f = fixture(t); ready(f); const before = diskState(f);
      f.distTagTransport.observeDistTag = response;
      assert.throws(() => op(args(f)), { code: "DIST_TAG_STATE_UNDETERMINED" });
      assert.deepEqual(f.effects, []); assert.equal(diskState(f), before);
    });
  }
  test(`${label}: transport failure leaves a recoverable state that converges on retry`, (t) => {
    const f = fixture(t); ready(f);
    const method = op === promoteLatest ? "addDistTag" : "removeDistTag";
    const original = f.distTagTransport[method];
    f.distTagTransport[method] = () => { throw new Error("EAI_AGAIN"); };
    assert.throws(() => op(args(f)), { code: `${prefix}_NOT_OBSERVED` });
    const persisted = loadState(f.releaseDir);
    assert.equal(persisted.finalizationBlocker.package, "@oxdeai/core");
    assert.equal(persisted.finalizationAttempt, undefined);
    assert.notEqual(persisted.packages["@oxdeai/core"][op === promoteLatest ? "latestVerified" : "nextRemoved"], true);
    assert.equal(isReleaseFinalized(f.manifest, persisted), false);
    // Another package cannot proceed while the blocker is unresolved.
    const guard = op === promoteLatest ? promoteArgs(f, "@oxdeai/guard") : removeArgs(f, "@oxdeai/guard");
    assert.throws(() => op({ ...guard, state: persisted }), { code: "FINALIZATION_BLOCKED" });
    f.distTagTransport[method] = original;
    restart(f);
    assert.equal(op(args(f)).effect, true);
    assert.equal(loadState(f.releaseDir).finalizationBlocker, undefined);
    assert.equal(finalizeAll(f).phase, "FINALIZED");
    assertFinalRegistry(f);
  });
  test(`${label}: a success response without an observed effect is not accepted`, (t) => {
    const f = fixture(t); ready(f);
    f.distTagTransport[op === promoteLatest ? "addDistTag" : "removeDistTag"] = () => ({ ok: true });
    assert.throws(() => op(args(f)), /unchanged after the effect/);
    assert.equal(loadState(f.releaseDir).phase, op === promoteLatest ? "PROMOTING_LATEST" : "REMOVING_NEXT");
  });
  test(`${label}: contradictory post-effect observation persists a conflict blocker`, (t) => {
    const f = fixture(t); ready(f);
    if (op === promoteLatest) f.distTagTransport.addDistTag = (o) => { f.tags.get(o.package).latest = "9.9.9"; };
    else f.distTagTransport.removeDistTag = (o) => { f.tags.get(o.package).next = "9.9.9"; };
    assert.throws(() => op(args(f)), { code: "DIST_TAG_CONFLICT" });
    const persisted = loadState(f.releaseDir);
    assert.equal(persisted.finalizationBlocker.code, "DIST_TAG_CONFLICT");
    assert.equal(isReleaseFinalized(f.manifest, persisted), false);
    assert.throws(() => op({ ...args(f), state: persisted }), { code: "DIST_TAG_CONFLICT" }, "retry still fails closed");
  });
}

function finalizePromotion(f) {
  for (const name of f.selected) promoteLatest(promoteArgs(f, name));
  verifyLatestPromotion(f);
}

test("unexpected latest version is a conflict unless consent names it as the replaced version", (t) => {
  const f = fixture(t), before = diskState(f);
  f.tags.get("@oxdeai/core").latest = "1.0.0";
  assert.throws(() => promoteLatest(promoteArgs(f, "@oxdeai/core")), { code: "DIST_TAG_CONFLICT" });
  assert.deepEqual(f.effects, []); assert.equal(diskState(f), before);
  // Explicit tested replacement policy: exact prior version in the receipt.
  assert.equal(promoteLatest(promoteArgs(f, "@oxdeai/core", promotion(f, "@oxdeai/core", "1.0.0"))).effect, true);
  // Absent latest needs replaces: null.
  delete f.tags.get("@oxdeai/guard").latest;
  assert.throws(() => promoteLatest(promoteArgs(f, "@oxdeai/guard")), { code: "DIST_TAG_CONFLICT" });
  assert.equal(promoteLatest(promoteArgs(f, "@oxdeai/guard", promotion(f, "@oxdeai/guard", null))).effect, true);
  assert.deepEqual(f.effects.map(([, n]) => n), ["@oxdeai/core", "@oxdeai/guard"]);
  assert.throws(() => promoteLatest(promoteArgs(f, "@oxdeai/sdk", promotion(f, "@oxdeai/sdk", versionOf(f, "@oxdeai/sdk")))),
    { code: "PROMOTION_AUTHORIZATION_INVALID" });
});

test("next pointing to another version is a conflict and is never removed", (t) => {
  const f = fixture(t); finalizePromotion(f); f.effects.length = 0;
  f.tags.get("@oxdeai/core").next = "3.0.0-rc.1";
  const before = diskState(f);
  assert.throws(() => removeNext(removeArgs(f, "@oxdeai/core")), { code: "DIST_TAG_CONFLICT" });
  assert.deepEqual(f.effects, []); assert.equal(diskState(f), before);
  assert.equal(f.tags.get("@oxdeai/core").next, "3.0.0-rc.1");
});

test("next removal cannot start before PROMOTED or while any selected latest has drifted", (t) => {
  const f = fixture(t);
  assert.throws(() => removeNext(removeArgs(f, "@oxdeai/core")), { code: "FINALIZATION_PHASE_INVALID" });
  for (const name of SELECTED) promoteLatest(promoteArgs(f, name));
  assert.throws(() => removeNext(removeArgs(f, "@oxdeai/core")), { code: "FINALIZATION_PHASE_INVALID" });
  verifyLatestPromotion(f);
  f.tags.get("@oxdeai/cli").latest = "0.3.1"; // drift on a different package
  const before = diskState(f);
  assert.throws(() => removeNext(removeArgs(f, "@oxdeai/core")), { code: "LATEST_NOT_VERIFIED" });
  assert.deepEqual(f.effects.filter(([k]) => k === "rm"), []); assert.equal(diskState(f), before);
});

test("latest verification requires every selected package and observes them all independently", (t) => {
  const f = fixture(t);
  assert.throws(() => verifyLatestPromotion(f), { code: "FINALIZATION_PHASE_INVALID" });
  for (const name of SELECTED.slice(0, 4)) promoteLatest(promoteArgs(f, name));
  assert.throws(() => verifyLatestPromotion(f), { code: "PROMOTION_INCOMPLETE" });
  promoteLatest(promoteArgs(f, "@oxdeai/cli"));
  f.tags.get("@oxdeai/sdk").latest = "2.0.1"; // out-of-band rollback after recording
  const before = diskState(f);
  assert.throws(() => verifyLatestPromotion(f), { code: "PROMOTION_VERIFICATION_FAILED" });
  assert.equal(diskState(f), before);
  // Re-promotion reconciles under fresh consent, then verification passes.
  promoteLatest(promoteArgs(f, "@oxdeai/sdk"));
  assert.equal(verifyLatestPromotion(f).phase, "PROMOTED");
});

test("already-conforming registry: no effects, all evidence still recorded", (t) => {
  const f = fixture(t);
  for (const name of SELECTED) f.tags.set(name, { latest: versionOf(f, name) });
  assert.equal(finalizeAll(f).phase, "FINALIZED");
  assert.deepEqual(f.effects, []);
  assertFinalRegistry(f);
  // Re-running a conforming step after the fact performs nothing either.
  const g = fixture(t); finalizePromotion(g); g.effects.length = 0;
  assert.throws(() => promoteLatest(promoteArgs(g, "@oxdeai/core")), { code: "FINALIZATION_PHASE_INVALID" });
  assert.deepEqual(g.effects, []);
});

test("partial next removal is not finalization; out-of-band removal reconciles without effect", (t) => {
  const f = fixture(t); finalizePromotion(f); f.effects.length = 0;
  removeNext(removeArgs(f, "@oxdeai/core"));
  removeNext(removeArgs(f, "@oxdeai/guard"));
  restart(f);
  assert.equal(f.state.phase, "REMOVING_NEXT");
  assert.equal(isReleaseFinalized(f.manifest, f.state), false);
  assert.throws(() => verifyFinalization(f), { code: "FINALIZATION_INCOMPLETE" });
  delete f.tags.get("@oxdeai/sdk").next; // removed by someone else meanwhile
  assert.equal(removeNext(removeArgs(f, "@oxdeai/sdk")).effect, false);
  for (const name of ["@oxdeai/conformance", "@oxdeai/cli"]) removeNext(removeArgs(f, name));
  assert.equal(verifyFinalization(f).phase, "FINALIZED");
  assert.deepEqual(f.effects.map(([k, n]) => `${k}:${n}`),
    ["rm:@oxdeai/core", "rm:@oxdeai/guard", "rm:@oxdeai/conformance", "rm:@oxdeai/cli"]);
});

for (const [label, mutate] of [
  ["next reappeared", (f) => { f.tags.get("@oxdeai/conformance").next = "2.0.2"; }],
  ["latest drifted", (f) => { f.tags.get("@oxdeai/guard").latest = "2.0.2"; }],
  ["indeterminate", (f) => { f.distTagTransport.observeDistTag = () => ({}); }],
]) {
  test(`final verification of all five fails closed: ${label}`, (t) => {
    const f = fixture(t); finalizePromotion(f);
    for (const name of SELECTED) removeNext(removeArgs(f, name));
    mutate(f);
    const before = diskState(f);
    assert.throws(() => verifyFinalization(f), /finalization verification failed|indeterminate/);
    assert.equal(diskState(f), before);
    assert.equal(isReleaseFinalized(f.manifest, loadState(f.releaseDir)), false);
  });
}

// Interruption after each simulated remote effect: the effect lands, then the
// process dies before writing anything else. The on-disk state is exactly the
// one persisted before the effect. A restart must converge with no reapplied effect.
for (let crashAt = 0; crashAt < 2 * SELECTED.length; crashAt++) {
  test(`interruption after remote effect #${crashAt + 1} resumes from persisted state without repeating it`, (t) => {
    const f = fixture(t);
    // After the crashing effect the process is dead: every later transport call
    // fails and every later state write is discarded by restoring the snapshot.
    let count = 0, snapshot, dead = false;
    const real = { ...f.distTagTransport };
    for (const method of ["observeDistTag", "addDistTag", "removeDistTag"]) {
      f.distTagTransport[method] = (op) => {
        if (dead) throw new Error("SIGKILL");
        const result = real[method](op);
        if (method !== "observeDistTag" && count++ === crashAt) { snapshot = diskState(f); dead = true; }
        return result;
      };
    }
    assert.throws(() => finalizeAll(f));
    fs.writeFileSync(path.join(f.releaseDir, STATE_FILENAME), snapshot);
    dead = false;
    const persisted = JSON.parse(snapshot);
    assert.equal(persisted.finalizationAttempt.package, SELECTED[crashAt % SELECTED.length]);
    assert.equal(isReleaseFinalized(f.manifest, persisted), false);
    assert.equal(finalizeAll(f).phase, "FINALIZED");
    assert.equal(f.effects.length, 2 * SELECTED.length, "each effect applied exactly once");
    assert.equal(loadState(f.releaseDir).finalizationAttempt, undefined);
    assertFinalRegistry(f);
    assertNoExcludedTraffic(f);
  });
}

for (const op of ["promote", "remove"]) {
  test(`interruption after persisting the ${op} attempt but before the effect applies it exactly once on restart`, (t) => {
    const f = fixture(t);
    if (op === "remove") finalizePromotion(f);
    const method = op === "promote" ? "addDistTag" : "removeDistTag";
    const real = f.distTagTransport[method];
    let snapshot;
    f.distTagTransport[method] = () => { snapshot = diskState(f); throw new Error("SIGKILL"); };
    assert.throws(() => (op === "promote" ? promoteLatest(promoteArgs(f, "@oxdeai/core")) : removeNext(removeArgs(f, "@oxdeai/core"))));
    fs.writeFileSync(path.join(f.releaseDir, STATE_FILENAME), snapshot);
    f.distTagTransport[method] = real;
    assert.equal(JSON.parse(snapshot).finalizationAttempt.package, "@oxdeai/core");
    // A different package cannot jump ahead of the unresolved in-flight attempt.
    restart(f);
    assert.throws(() => (op === "promote" ? promoteLatest(promoteArgs(f, "@oxdeai/guard")) : removeNext(removeArgs(f, "@oxdeai/guard"))),
      { code: "FINALIZATION_BLOCKED" });
    assert.equal(finalizeAll(f).phase, "FINALIZED");
    assert.equal(f.effects.filter(([, n]) => n === "@oxdeai/core").length, 2, "one add and one rm");
    assertFinalRegistry(f);
  });
}

test("interruption during post-effect observation keeps the attempt and reconciles by observation", (t) => {
  const f = fixture(t);
  const observe = f.distTagTransport.observeDistTag;
  let calls = 0;
  f.distTagTransport.observeDistTag = (q) => { if (q.package === "@oxdeai/core" && ++calls === 2) throw new Error("ETIMEDOUT"); return observe(q); };
  assert.throws(() => promoteLatest(promoteArgs(f, "@oxdeai/core")), { code: "DIST_TAG_STATE_UNDETERMINED" });
  const persisted = loadState(f.releaseDir);
  assert.equal(persisted.finalizationAttempt.package, "@oxdeai/core");
  assert.equal(persisted.finalizationBlocker.code, "DIST_TAG_STATE_UNDETERMINED");
  f.distTagTransport.observeDistTag = observe;
  restart(f);
  assert.equal(promoteLatest(promoteArgs(f, "@oxdeai/core")).effect, false, "already applied: not reapplied");
  assert.equal(f.effects.length, 1);
});

test("restart mid-promotion and mid-removal continues from persisted state only", (t) => {
  const f = fixture(t);
  promoteLatest(promoteArgs(f, "@oxdeai/core"));
  promoteLatest(promoteArgs(f, "@oxdeai/guard"));
  restart(f);
  assert.equal(f.state.phase, "PROMOTING_LATEST");
  assert.deepEqual(SELECTED.filter((n) => f.state.packages[n].latestVerified), ["@oxdeai/core", "@oxdeai/guard"]);
  for (const name of SELECTED.slice(2)) promoteLatest(promoteArgs(f, name));
  verifyLatestPromotion(f);
  removeNext(removeArgs(f, "@oxdeai/core"));
  restart(f);
  assert.equal(f.state.phase, "REMOVING_NEXT");
  assert.equal(finalizeAll(f).phase, "FINALIZED");
  assert.equal(f.effects.length, 10);
});

test("persistence failure before the effect: no remote effect, memory abandoned, reload converges", (t) => {
  const f = fixture(t), before = diskState(f);
  t.after(() => mock.restoreAll());
  mock.method(fs, "renameSync", () => { throw Object.assign(new Error("injected rename failure"), { code: "EIO" }); });
  assert.throws(() => promoteLatest(promoteArgs(f, "@oxdeai/core")), { code: "PERSISTENCE_FAILED" });
  mock.restoreAll();
  assert.deepEqual(f.effects, [], "the attempt was not persisted, so no effect was started");
  assert.equal(diskState(f), before);
  assert.deepEqual(fs.readdirSync(f.releaseDir).filter((n) => n.endsWith(".tmp")), []);
  assert.throws(() => promoteLatest(promoteArgs(f, "@oxdeai/core")), /abandoned/);
  assert.equal(finalizeAll(f).phase, "FINALIZED"); // finalizeAll reloads from disk
  assert.equal(f.effects.length, 10);
  assertFinalRegistry(f);
});

test("batch promote() is retired and never consults a transport", (t) => {
  const f = fixture(t);
  const forbidden = new Proxy({}, { get() { assert.fail("transport consulted"); } });
  assert.throws(() => promote({ ...f, promotionTransport: forbidden }), { code: "PROMOTION_BATCH_RETIRED" });
  assert.equal(loadState(f.releaseDir).phase, "READY_TO_PROMOTE");
});

test("missing or incomplete transport and wrong registry fail before any observation", (t) => {
  const f = fixture(t);
  assert.throws(() => promoteLatest({ ...promoteArgs(f, "@oxdeai/core"), distTagTransport: undefined }), { code: "FINALIZATION_TRANSPORT_INVALID" });
  assert.throws(() => promoteLatest({ ...promoteArgs(f, "@oxdeai/core"), distTagTransport: { observeDistTag() {} } }), { code: "FINALIZATION_TRANSPORT_INVALID" });
  assert.throws(() => promoteLatest({ ...promoteArgs(f, "@oxdeai/core"), registry: "https://example.invalid/" }), { code: "FINALIZATION_INPUT_INVALID" });
  assert.throws(() => promoteLatest({ ...promoteArgs(f, "@oxdeai/core"), releaseDir: "relative" }), { code: "FINALIZATION_INPUT_INVALID" });
  assert.deepEqual(f.observations, []); assert.deepEqual(f.effects, []);
});

// ── Compatibility with historical V1 manifests and states ────────────────

test("V1 versions and historical phases are unchanged; PROMOTED is never finalization", (t) => {
  assert.equal(MANIFEST_VERSION, 1); assert.equal(STATE_VERSION, 1);
  for (const phase of ["PRECHECK", "PACKED", "VERIFIED_LOCAL", "PUBLISHING_NEXT", "PARTIAL_NEXT", "PUBLISHED_NEXT",
    "REGISTRY_VERIFIED", "EXTERNAL_INSTALL_VERIFIED", "READY_TO_PROMOTE", "PROMOTED"]) assert.ok(PHASES.includes(phase));
  const f = fixture(t);
  const historical = { ...structuredClone(f.state), phase: "PROMOTED" }; // shape written by the retired promote()
  assert.equal(validateState(f.manifest, historical), historical);
  assert.equal(isReleaseFinalized(f.manifest, historical), false);
});

test("historical PROMOTED state can finalize only after fresh independent latest verification", (t) => {
  const f = fixture(t);
  for (const name of SELECTED) f.tags.get(name).latest = versionOf(f, name);
  f.state.phase = "PROMOTED"; // as left by the retired batch promote
  f.state.history.push({ phase: "PROMOTED", at: f.manifest.createdAt });
  fs.writeFileSync(path.join(f.releaseDir, STATE_FILENAME), JSON.stringify(f.state));
  f.tags.get("@oxdeai/guard").latest = "2.0.2";
  assert.throws(() => removeNext(removeArgs(f, "@oxdeai/core")), { code: "LATEST_NOT_VERIFIED" });
  f.tags.get("@oxdeai/guard").latest = versionOf(f, "@oxdeai/guard");
  assert.equal(finalizeAll(f).phase, "FINALIZED");
  assert.ok(SELECTED.every((n) => f.state.packages[n].latestVerified === true));
  assertFinalRegistry(f);
});

test("legacy all-package V1 manifest (no selection) finalizes all ten under the same rules", (t) => {
  const f = fixture(t, { selection: false });
  assert.equal(f.selected.length, 10);
  assert.equal(finalizeAll(f).phase, "FINALIZED");
  assert.equal(f.state.finalization.packages.length, 10);
  assert.equal(f.effects.length, 20);
});

for (const [label, mutate] of [
  ["FINALIZED without record", (s) => { s.phase = "FINALIZED"; }],
  ["record outside FINALIZED", (s, f) => { s.finalization = { kind: "release-finalization" }; }],
  ["latestVerified before promotion", (s) => { s.packages["@oxdeai/core"].latestVerified = true; }],
  ["nextRemoved in PROMOTED", (s) => { s.phase = "PROMOTED"; for (const n of SELECTED) s.packages[n].latestVerified = true; s.packages["@oxdeai/core"].nextRemoved = true; }],
  ["partial latest evidence in PROMOTED", (s) => { s.phase = "PROMOTED"; s.packages["@oxdeai/core"].latestVerified = true; }],
  ["excluded package evidence", (s) => { s.phase = "PROMOTING_LATEST"; s.packages["@oxdeai/autogen"].latestVerified = true; }],
  ["attempt for excluded package", (s) => { s.phase = "PROMOTING_LATEST"; s.finalizationAttempt = { operation: "promote-latest", package: "@oxdeai/autogen", version: "2.0.0", startedAt: "x" }; }],
  ["attempt with wrong operation", (s) => { s.phase = "PROMOTING_LATEST"; s.finalizationAttempt = { operation: "remove-next", package: "@oxdeai/core", version: "2.0.2", startedAt: "x" }; }],
  ["non-boolean nextRemoved", (s) => { s.phase = "REMOVING_NEXT"; s.packages["@oxdeai/core"].nextRemoved = "yes"; }],
]) {
  test(`forged or inconsistent finalization state rejected: ${label}`, (t) => {
    const f = fixture(t), s = structuredClone(f.state);
    mutate(s, f);
    assert.throws(() => validateState(f.manifest, s), /invalid release state/);
    assert.equal(isReleaseFinalized(f.manifest, s), false);
  });
}

test("finalization record is bound to manifest, selection and its digest", (t) => {
  const f = fixture(t);
  finalizeAll(f);
  for (const mutate of [
    (r) => { r.packages[0].latest = "2.0.1"; }, (r) => { r.packages.pop(); }, (r) => { r.manifestIntegrity = `sha256:${"0".repeat(64)}`; },
    (r) => { r.registry = "https://example.invalid/"; }, (r) => { r.extra = true; }, (r) => { r.verifiedAt = "later"; },
  ]) {
    const s = structuredClone(f.state); mutate(s.finalization);
    s.finalization.finalizationDigest = computeFinalizationDigest(s.finalization);
    assert.throws(() => validateState(f.manifest, s), /finalization record invalid/);
  }
  const s = structuredClone(f.state); s.finalization.verifiedAt = "2030-01-01T00:00:00.000Z";
  assert.throws(() => validateState(f.manifest, s), /digest/);
});

test("safety gate: finalization modules spawn nothing and add no CLI subcommand", () => {
  for (const file of ["release-finalization.mjs", "finalization-authorization.mjs"]) {
    const source = fs.readFileSync(new URL(`./${file}`, import.meta.url), "utf8");
    assert.doesNotMatch(source, /child_process|\bspawn(Sync)?\(|execFile|\bexec(Sync)?\(|fetch\(|https?\.request/);
  }
  const orchestrator = fs.readFileSync(new URL("./orchestrator.mjs", import.meta.url), "utf8");
  const main = orchestrator.slice(orchestrator.indexOf("async function main()"));
  assert.doesNotMatch(main, /cmd === "(promote|finalize|remove-next|promote-latest|dist-tag)/);
  assert.doesNotMatch(main, /release-finalization|promoteLatest|removeNext/);
});
