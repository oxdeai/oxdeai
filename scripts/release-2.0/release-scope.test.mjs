// SPDX-License-Identifier: Apache-2.0
// R3 F-01: what each release mode actually publishes, observed through the
// real precheck() and derivePublicationPlan() over this checkout's real
// package manifests. Round 3: PRECHECK now refuses the partial f2-cli1 mode for
// this release (release-completeness.test.mjs holds the rule's own tests).
// R4: receipt validation and publication planning refuse it too, so a forged
// f2-cli1 receipt cannot yield a plan either.
// Hermetic: only git cleanliness, source snapshot and the registry/auth
// observations are injected; nothing is packed or published.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { tmpdir } from "node:os";
import { POLICY, GUARD_FLOOR_PACKAGES, discoverPublishablePackages } from "../verify-packed-artifacts.mjs";
import { forgeSelectionReceipt, persistFixturePrecheck } from "./precheck-fixture.mjs";
import { fixturePlan } from "./publication-fixture.mjs";
import { F2_CLI1_SELECTION, ROOT, computeManifestIntegrity, computeSriIntegrity, publicationPackages } from "./orchestrator.mjs";

const POLICY_ORDER = Object.entries(POLICY)
  .sort(([, a], [, b]) => a.publishOrder - b.publishOrder)
  .map(([name, p]) => ({ package: name, version: p.version }));

function frozenManifest(t, selection) {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-release-scope-"));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  const revision = "b".repeat(40);
  const discovered = discoverPublishablePackages();
  // Full mode uses the real PRECHECK. PRECHECK refuses a selection on this
  // checkout, so a selection receipt can only be a forgery (negative tests).
  const precheck = selection === undefined
    ? persistFixturePrecheck(discovered, releaseDir, revision, ROOT)
    : forgeSelectionReceipt(discovered, releaseDir, revision, ROOT, { selection });
  fs.mkdirSync(path.join(releaseDir, "tarballs"));
  const packages = discovered.map((d) => {
    const tarball = `tarballs/${d.name.slice(8)}.tgz`, bytes = Buffer.from(d.name);
    fs.writeFileSync(path.join(releaseDir, tarball), bytes);
    const p = POLICY[d.name];
    return { package: d.name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball, integrity: computeSriIntegrity(bytes) };
  });
  const manifest = { manifestVersion: 1, releaseId: revision, sourceRevision: revision, packages, precheck,
    ...(selection === undefined ? {} : { selection: structuredClone(selection) }) };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  return { manifest, releaseDir, discovered };
}

test("real manifests: the ten discovered packages are exactly the POLICY packages at POLICY versions", () => {
  const discovered = discoverPublishablePackages();
  assert.deepEqual(discovered.map((d) => d.name).sort(), Object.keys(POLICY).sort());
  for (const d of discovered) assert.equal(d.manifest.version, POLICY[d.name].version, d.name);
});

test("full mode (no --selection): PRECHECK evaluates ten and the plan publishes all ten, adapters included", (t) => {
  const { manifest, releaseDir } = frozenManifest(t, undefined);
  assert.equal(manifest.precheck.selection, undefined);
  assert.deepEqual(publicationPackages(manifest).map((p) => ({ package: p.package, version: p.version }))
    .sort((a, b) => POLICY[a.package].publishOrder - POLICY[b.package].publishOrder), POLICY_ORDER);
  const plan = fixturePlan(manifest, releaseDir);
  assert.equal(plan.evidence.packagesEvaluated.length, 10);
  assert.deepEqual(plan.operations.map((o) => ({ package: o.package, version: o.version })), POLICY_ORDER);
  for (const name of GUARD_FLOOR_PACKAGES) {
    assert.ok(plan.operations.some((o) => o.package === name && o.version === POLICY[name].version), `${name} must be published`);
  }
});

test("--selection=f2-cli1 on this checkout: PRECHECK refuses it and persists no receipt", (t) => {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), "oxdeai-release-scope-"));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  assert.throws(() => persistFixturePrecheck(discoverPublishablePackages(), releaseDir, "b".repeat(40), ROOT,
    { selection: F2_CLI1_SELECTION }), /R3 release completeness: .*omits @oxdeai\/autogen@2\.0\.1, @oxdeai\/crewai@2\.0\.1, @oxdeai\/langgraph@2\.0\.1, @oxdeai\/openai-agents@2\.0\.1, @oxdeai\/openclaw@2\.0\.1/);
  assert.deepEqual(fs.readdirSync(releaseDir), []);
});

test("why it is refused: f2-cli1 names Guard but none of the five adapters", () => {
  const named = F2_CLI1_SELECTION.map((s) => s.package);
  assert.ok(named.includes("@oxdeai/guard"));
  assert.deepEqual(Object.keys(POLICY).filter((n) => !named.includes(n)).sort(), [...GUARD_FLOOR_PACKAGES].sort());
});

test("a forged f2-cli1 receipt over the real manifests yields no publication set and no plan", (t) => {
  const { manifest, releaseDir } = frozenManifest(t, F2_CLI1_SELECTION);
  assert.throws(() => publicationPackages(manifest), /R3 release completeness/);
  assert.throws(() => fixturePlan(manifest, releaseDir), /R3 release completeness/);
});
