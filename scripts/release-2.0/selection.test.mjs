// SPDX-License-Identifier: Apache-2.0
// Hermetic evidence and archive bytes only; no npm subprocess or official PACK.
// R4 (F-R4-1): on this R3 checkout the f2-cli1 partial selection is invalid in
// every phase (PRECHECK, receipt validation, publication planning). The
// publication tests therefore run in full mode (ten planned operations), and
// every selection case is an explicit rejection test that must stop before any
// registry observation or publication effect.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { POLICY } from '../verify-packed-artifacts.mjs';
import { forgeSelectionReceipt, persistFixturePrecheck } from './precheck-fixture.mjs';
import { fixturePlan } from './publication-fixture.mjs';
import { consent, fixture as authorizedFixture, invoke as invokeAuthorized, publications } from './publication-authorization.fixture.mjs';
import { validatePublicationAuthorization } from './publication-authorization.mjs';
import { F2_CLI1_SELECTION, computeManifestIntegrity, computePrecheckReceiptDigest, computeSriIntegrity,
  publishPlannedOperation, publicationPackages, resume, pack, verifyLocal, verifyRegistry, verifyExternalInstall,
  transitionToReadyToPromote, buildPromotionPlan, STATE_FILENAME, MANIFEST_FILENAME } from './orchestrator.mjs';

const COMPLETENESS = /R3 release completeness/;
const ALL = Object.keys(POLICY);

function fixture(t) {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), 'f2-selection-'));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  const revision = 'a'.repeat(40);
  const discovered = Object.entries(POLICY).map(([name,p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version, ...(name === '@oxdeai/core' ? {} : { dependencies: { '@oxdeai/core': 'workspace:*' } }) } }));
  const precheck = persistFixturePrecheck(discovered, releaseDir, revision, '/fake');
  fs.mkdirSync(path.join(releaseDir, 'tarballs'));
  const packages = discovered.map(d => {
    const tarball = `tarballs/${d.name.slice(8)}.tgz`, bytes = Buffer.from(d.name);
    fs.writeFileSync(path.join(releaseDir, tarball), bytes);
    const p = POLICY[d.name];
    return { package: d.name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball, integrity: computeSriIntegrity(bytes) };
  });
  const manifest = { manifestVersion: 1, releaseId: revision, sourceRevision: revision, packages, precheck };
  manifest.manifestIntegrity = computeManifestIntegrity(manifest);
  const plan = fixturePlan(manifest, releaseDir);
  const state = { stateVersion: 1, releaseId: revision, phase: 'VERIFIED_LOCAL',
    history: [{ phase: 'PRECHECK', at: precheck.observedAt, receiptDigest: precheck.receiptDigest },
      { phase: 'PACKED' }, { phase: 'VERIFIED_LOCAL' }],
    packages: Object.fromEntries(packages.map(p => [p.package, { publishStatus: 'pending' }])) };
  const registry = new Map(), observations = [], effects = [];
  const f = { manifest, plan, state, releaseDir, discovered, operationIndex: 0, registry, observations, effects,
    registryTransport: {
      getRegistryVersion(name) { observations.push(name); return registry.has(name) ? { exists: true, integrity: registry.get(name) } : { exists: false }; },
      publish(command) { effects.push(command.package); const p = packages.find(p => p.package === command.package);
        registry.set(p.package, p.integrity); return { ok: true }; },
    } };
  f.authorization = consent(f);
  return f;
}
function save(f) {
  fs.writeFileSync(path.join(f.releaseDir, MANIFEST_FILENAME), JSON.stringify(f.manifest));
  fs.writeFileSync(path.join(f.releaseDir, STATE_FILENAME), JSON.stringify(f.state));
}
// Turns f's manifest into a selection manifest backed by a forged receipt that
// carries `receiptSelection` (digest recomputed), with the manifest integrity
// recomputed as well. The already-derived plan and authorization are kept, as
// an operator holding them from before the edit would.
function select(f, selection, receiptSelection = selection) {
  const dir = fs.mkdtempSync(path.join(f.releaseDir, 'forged-'));
  f.manifest.precheck = forgeSelectionReceipt(f.discovered, dir, f.manifest.sourceRevision, '/fake', { selection: receiptSelection });
  if (selection === undefined) delete f.manifest.selection; else f.manifest.selection = structuredClone(selection);
  f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
  return f;
}

test('full mode: ten evaluated -> ten frozen -> ten individually authorized, observed operations and full verification', t => {
  const f = fixture(t);
  assert.equal(f.plan.evidence.packagesEvaluated.length, 10);
  assert.deepEqual(f.plan.operations.map(p => p.package).sort(), [...ALL].sort());
  for (let i = 0; i < f.plan.operations.length; i++) {
    f.operationIndex = i; f.authorization = consent(f);
    publishPlannedOperation(f);
  }
  assert.equal(f.state.phase, 'PUBLISHED_NEXT');
  assert.deepEqual(f.effects, f.plan.operations.map(p => p.package));
  verifyRegistry(f);
  const installed = [];
  verifyExternalInstall({ ...f, installTransport: { verifyInstall(name) { installed.push(name); return { ok: true }; } } });
  transitionToReadyToPromote(f);
  assert.equal(buildPromotionPlan(f.manifest, f.state).length, 10);
  assert.deepEqual(installed, f.effects);
});

test('R3: a five-package frozen selection is refused by planning, publication and every verification step', t => {
  const f = fixture(t);
  select(f, F2_CLI1_SELECTION);
  assert.throws(() => publicationPackages(f.manifest), COMPLETENESS);
  assert.throws(() => fixturePlan(f.manifest, f.releaseDir), COMPLETENESS);
  assert.throws(() => publishPlannedOperation(f), COMPLETENESS);
  assert.throws(() => verifyRegistry(f), COMPLETENESS);
  assert.throws(() => verifyExternalInstall({ ...f, installTransport: { verifyInstall() { assert.fail('install consulted'); } } }), COMPLETENESS);
  assert.throws(() => transitionToReadyToPromote(f), COMPLETENESS);
  assert.throws(() => buildPromotionPlan(f.manifest, f.state), COMPLETENESS);
  assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []);
});

const variant = (edit) => { const s = structuredClone(F2_CLI1_SELECTION); edit(s); return s; };
for (const [label, mutate] of [
  ['R3 partial selection (exact f2-cli1)', f => select(f, F2_CLI1_SELECTION)],
  ['altered selection', f => select(f, variant(s => { s[0].version = '2.0.1'; }))],
  ['additional package', f => select(f, variant(s => { s.push({ package: '@oxdeai/autogen', version: '2.0.1' }); }))],
  ['duplicate', f => select(f, variant(s => { s[1] = s[0]; }))],
  ['selection order', f => select(f, variant(s => { s.reverse(); }))],
  ['metadata order', f => { f.manifest.packages[0].publishOrder = 100; }],
  ['manifest omission (receipt carries a selection)', f => select(f, undefined, F2_CLI1_SELECTION)],
  ['extra operation', f => { f.plan.operations.push(f.plan.operations[0]); }],
  ['modified archive', f => { fs.writeFileSync(path.join(f.releaseDir,f.plan.operations[0].tarball),'changed'); }],
  ['missing archive', f => { fs.unlinkSync(path.join(f.releaseDir,f.plan.operations[0].tarball)); }],
  ['out of order', f => { f.operationIndex = 1; f.authorization = consent(f); }],
  ['state for a package outside the manifest', f => { f.state.packages['@oxdeai/unknown'] = {publishStatus:'published'}; }],
]) test(`${label} rejects before registry/publication effects`, t => {
  const f = fixture(t); mutate(f);
  assert.throws(() => publishPlannedOperation(f));
  assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []);
});

// In full mode, per-operation consent is enforced by the authorized npm wrapper
// (publishAuthorizedOperation); publishPlannedOperation itself checks consent
// only for selection manifests. Both are unchanged from the R3 baseline.
for (const [label, mutate] of [
  ['missing authorization', f => { delete f.authorization; }],
  ['wrong operation authorization', f => { f.authorization = consent(f,1); }],
]) test(`full mode: ${label} is refused by the authorized wrapper before any subprocess (mocked subprocess only)`, t => {
  const f = authorizedFixture(t); mutate(f);
  assert.throws(() => validatePublicationAuthorization(f));
  assert.throws(() => invokeAuthorized(f));
  assert.equal(publications(f).length, 0);
});

test('authorization independently rejects an R3 partial-selection manifest', t => {
  const f = fixture(t);
  assert.doesNotThrow(() => validatePublicationAuthorization(f));
  select(f, F2_CLI1_SELECTION);
  assert.throws(() => validatePublicationAuthorization(f), COMPLETENESS);
});

test('partial resume reconciles published originals only and rejects unknown/conflicting registry evidence', t => {
  const f = fixture(t);
  publishPlannedOperation(f);
  save(f);
  f.observations.length = 0;
  const resumed = resume(f);
  assert.equal(resumed.toPublish.length, 9);
  assert.equal(f.observations.length, 10);
  f.operationIndex = 1; f.state = resumed.state; f.authorization = consent(f);
  publishPlannedOperation(f);
  save(f);
  f.registry.set(f.plan.operations[0].package, 'conflict');
  assert.throws(() => resume(f), /differs/);
  f.registryTransport.getRegistryVersion = () => ({});
  assert.throws(() => resume(f), /undetermined/);
});

test('resume refuses an R3 partial-selection manifest before observing the registry', t => {
  const f = fixture(t);
  publishPlannedOperation(f);
  select(f, F2_CLI1_SELECTION); save(f);
  f.observations.length = 0;
  assert.throws(() => resume(f), COMPLETENESS);
  assert.deepEqual(f.observations, []);
});

// Full mode records an `ok` publish response as published (unchanged from the
// R3 baseline); the independent registry verification then fails closed.
test('full mode: success responses without registry bytes cannot pass registry verification', t => {
  const f = fixture(t);
  f.registryTransport.publish = (command) => { f.effects.push(command.package); return {ok:true}; };
  for (let i = 0; i < f.plan.operations.length; i++) { f.operationIndex = i; f.authorization = consent(f); publishPlannedOperation(f); }
  assert.equal(f.state.phase, 'PUBLISHED_NEXT');
  assert.throws(() => verifyRegistry(f), /registry verification failed: .* not present/);
  assert.notEqual(f.state.phase, 'REGISTRY_VERIFIED');
});

for (const field of ['dependencies','peerDependencies','optionalDependencies']) {
  test(`unresolved external ${field} fails before receipt creation`, t => {
    const f = fixture(t);
    f.discovered[0].manifest[field] = { 'missing-external': '^1.0.0' };
    assert.throws(() => persistFixturePrecheck(f.discovered, path.join(f.releaseDir,'fresh'), undefined, undefined,
      { selection:F2_CLI1_SELECTION }), /external dependency resolution required/);
  });
}

const fakePack = (calls = []) => ({ packToDir(d, dir) {
  calls.push(d.name);
  const file = path.join(dir,`${d.name.slice(8)}.tgz`);
  fs.writeFileSync(file,d.name); return file;
} });
const snapshot = { snapshot:()=>({root:'/fake',revision:'a'.repeat(40),clean:true}) };

test('stale receipt and forged or mutated receipt selections refuse fixture PACK before any packing', t => {
  const f = fixture(t);
  const fresh = path.join(f.releaseDir,'fresh');
  persistFixturePrecheck(f.discovered, fresh, 'b'.repeat(40), '/fake');
  assert.throws(() => pack({discovered:f.discovered, releaseDir:fresh, sourceRevision:'a'.repeat(40),
    sourceTransport:snapshot, packTransport:{packToDir(){throw new Error('must not pack');}} }), /source revision/);
  for (const selection of [F2_CLI1_SELECTION, F2_CLI1_SELECTION.slice(0,4)]) {
    const dir = fs.mkdtempSync(path.join(f.releaseDir,'forged-'));
    forgeSelectionReceipt(f.discovered, dir, 'a'.repeat(40), '/fake', { selection });
    assert.throws(() => pack({discovered:f.discovered, releaseDir:dir, sourceRevision:'a'.repeat(40), sourceTransport:snapshot,
      packTransport:{packToDir(){throw new Error('must not pack');}} }), /persisted PRECHECK receipt is invalid/);
    assert.deepEqual(fs.readdirSync(dir), ['local-precheck.json'], 'nothing written beside the forged receipt');
  }
  const receipt = f.manifest.precheck;
  receipt.selection = F2_CLI1_SELECTION.slice(0,4);
  receipt.receiptDigest = computePrecheckReceiptDigest(receipt);
  assert.throws(() => publicationPackages(f.manifest), /selection missing from manifest/);
});

test('fixture PACK freezes all ten archive identities without selection; altered persisted receipt blocks VERIFY_LOCAL', t => {
  const f = fixture(t), releaseDir = path.join(f.releaseDir,'packed');
  persistFixturePrecheck(f.discovered, releaseDir, 'a'.repeat(40), '/fake');
  const result = pack({ discovered:f.discovered, releaseDir, sourceRevision:'a'.repeat(40), sourceTransport:snapshot,
    packageTransport:{read:d=>Buffer.from(JSON.stringify(d.manifest))}, packTransport:fakePack() });
  assert.equal(result.manifest.packages.length,10);
  assert.equal(result.manifest.selection,undefined);
  assert.equal(publicationPackages(result.manifest).length,10);
  const receipt = JSON.parse(fs.readFileSync(path.join(releaseDir,'local-precheck.json')));
  receipt.observedAt = '2000-01-01T00:00:00.000Z';
  receipt.receiptDigest = computePrecheckReceiptDigest(receipt);
  fs.writeFileSync(path.join(releaseDir,'local-precheck.json'),JSON.stringify(receipt));
  assert.throws(()=>verifyLocal({...result,releaseDir,discovered:f.discovered}),/persisted PRECHECK receipt differs/);
});

test('matching published version reconciles with consent and no publish call; conflict fails closed', t => {
  const f = fixture(t), p = f.plan.operations[0];
  f.registry.set(p.package,p.integrity);
  publishPlannedOperation(f);
  assert.equal(f.state.packages[p.package].publishStatus,'published');
  assert.deepEqual(f.effects,[]);
  const bad = fixture(t);
  bad.registry.set(p.package,'different-bytes');
  assert.throws(()=>publishPlannedOperation(bad),/differs/);
  assert.deepEqual(bad.effects,[]);
});

test('changed candidate digest invalidates existing plan and authorization', t => {
  const f = fixture(t);
  f.manifest.createdAt = '2026-10-20T00:00:00Z';
  f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
  assert.throws(()=>validatePublicationAuthorization(f));
  assert.throws(()=>publishPlannedOperation(f));
  assert.deepEqual(f.observations,[]);
});

test('resume refuses a modified not-yet-published archive as well as published originals', t => {
  const f = fixture(t);
  publishPlannedOperation(f); save(f);
  const unpublished = f.manifest.packages.find(p=>p.package===f.plan.operations.at(-1).package);
  fs.writeFileSync(path.join(f.releaseDir,unpublished.tarball),'changed');
  assert.throws(()=>resume(f),/local tarball integrity/);
});


test('authorized npm wrapper refuses an R3 five-operation profile before any subprocess (mocked subprocess only)', t => {
  const f = authorizedFixture(t);
  const fullPlan = f.plan;
  f.manifest.selection = structuredClone(F2_CLI1_SELECTION);
  f.manifest.precheck.selection = structuredClone(F2_CLI1_SELECTION);
  f.manifest.precheck.receiptDigest = computePrecheckReceiptDigest(f.manifest.precheck);
  f.state.history[0].receiptDigest = f.manifest.precheck.receiptDigest;
  f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
  assert.throws(() => fixturePlan(f.manifest,f.releaseDir), COMPLETENESS);
  f.plan = fullPlan;
  assert.throws(() => invokeAuthorized(f));
  assert.equal(publications(f).length,0);
});
