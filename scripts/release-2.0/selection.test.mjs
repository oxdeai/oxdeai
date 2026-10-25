// SPDX-License-Identifier: Apache-2.0
// Hermetic evidence and archive bytes only; no npm subprocess or official PACK.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { POLICY } from '../verify-packed-artifacts.mjs';
import { persistFixturePrecheck } from './precheck-fixture.mjs';
import { fixturePlan } from './publication-fixture.mjs';
import { consent, fixture as authorizedFixture, invoke as invokeAuthorized, publications } from './publication-authorization.fixture.mjs';
import { validatePublicationAuthorization } from './publication-authorization.mjs';
import { F2_CLI1_SELECTION, computeManifestIntegrity, computePrecheckReceiptDigest, computeSriIntegrity,
  publishPlannedOperation, publicationPackages, resume, pack, verifyLocal, verifyRegistry, verifyExternalInstall,
  transitionToReadyToPromote, buildPromotionPlan, STATE_FILENAME, MANIFEST_FILENAME } from './orchestrator.mjs';

function fixture(t) {
  const releaseDir = fs.mkdtempSync(path.join(tmpdir(), 'f2-selection-'));
  t.after(() => fs.rmSync(releaseDir, { recursive: true, force: true }));
  const revision = 'a'.repeat(40);
  const discovered = Object.entries(POLICY).map(([name,p]) => ({ name, dir: `/fake/${name.slice(8)}`,
    manifest: { name, version: p.version, ...(name === '@oxdeai/core' ? {} : { dependencies: { '@oxdeai/core': 'workspace:*' } }) } }));
  const precheck = persistFixturePrecheck(discovered, releaseDir, revision, '/fake', { selection: F2_CLI1_SELECTION });
  fs.mkdirSync(path.join(releaseDir, 'tarballs'));
  const packages = discovered.map(d => {
    const tarball = `tarballs/${d.name.slice(8)}.tgz`, bytes = Buffer.from(d.name);
    fs.writeFileSync(path.join(releaseDir, tarball), bytes);
    const p = POLICY[d.name];
    return { package: d.name, version: p.version, releaseLine: p.releaseLine, publishOrder: p.publishOrder,
      tarball, integrity: computeSriIntegrity(bytes) };
  });
  const manifest = { manifestVersion: 1, releaseId: revision, sourceRevision: revision, packages, precheck,
    selection: structuredClone(F2_CLI1_SELECTION) };
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

test('ten evaluated -> five frozen -> five individually authorized, observed operations and selected verification', t => {
  const f = fixture(t);
  assert.equal(f.plan.evidence.packagesEvaluated.length, 10);
  assert.deepEqual(f.plan.operations.map(p => ({ package: p.package, version: p.version })), F2_CLI1_SELECTION);
  for (let i = 0; i < 5; i++) {
    f.operationIndex = i; f.authorization = consent(f);
    publishPlannedOperation(f);
  }
  assert.equal(f.state.phase, 'PUBLISHED_NEXT');
  assert.deepEqual(f.effects, F2_CLI1_SELECTION.map(p => p.package));
  verifyRegistry(f);
  const installed = [];
  verifyExternalInstall({ ...f, installTransport: { verifyInstall(name) { installed.push(name); return { ok: true }; } } });
  transitionToReadyToPromote(f);
  assert.equal(buildPromotionPlan(f.manifest, f.state).length, 5);
  assert.deepEqual(installed, f.effects);
  assert.ok(f.observations.every(name => F2_CLI1_SELECTION.some(p => p.package === name)));
});

for (const [label, mutate] of [
  ['altered selection', f => { f.manifest.selection[0].version = '2.0.1'; }],
  ['additional package', f => { f.manifest.selection.push({package:'@oxdeai/autogen',version:'2.0.0'}); }],
  ['duplicate', f => { f.manifest.selection[1] = f.manifest.selection[0]; }],
  ['selection order', f => { f.manifest.selection.reverse(); }],
  ['metadata order', f => { f.manifest.packages[0].publishOrder = 100; }],
  ['manifest omission', f => { delete f.manifest.selection; }],
  ['extra operation', f => { f.plan.operations.push(f.plan.operations[0]); }],
  ['modified archive', f => { fs.writeFileSync(path.join(f.releaseDir,f.plan.operations[0].tarball),'changed'); }],
  ['missing archive', f => { fs.unlinkSync(path.join(f.releaseDir,f.plan.operations[0].tarball)); }],
  ['missing authorization', f => { delete f.authorization; }],
  ['wrong operation authorization', f => { f.authorization = consent(f,1); }],
  ['out of order', f => { f.operationIndex = 1; f.authorization = consent(f); }],
  ['excluded state', f => { f.state.packages['@oxdeai/autogen'] = {publishStatus:'published'}; }],
]) test(`${label} rejects before registry/publication effects`, t => {
  const f = fixture(t); mutate(f);
  assert.throws(() => publishPlannedOperation(f));
  assert.deepEqual(f.effects, []); assert.deepEqual(f.observations, []);
});

test('authorization independently rejects an excluded package', t => {
  const f = fixture(t), p = f.manifest.packages.find(p => p.package === '@oxdeai/autogen');
  Object.assign(f.plan.operations[0], p);
  f.authorization = consent(f);
  assert.throws(() => validatePublicationAuthorization(f));
});

test('partial resume reconciles selected originals only and rejects unknown/conflicting registry evidence', t => {
  const f = fixture(t);
  publishPlannedOperation(f);
  save(f);
  f.observations.length = 0;
  const resumed = resume(f);
  assert.equal(resumed.toPublish.length, 4);
  assert.equal(f.observations.length, 5);
  f.operationIndex = 1; f.state = resumed.state; f.authorization = consent(f);
  publishPlannedOperation(f);
  save(f);
  f.registry.set('@oxdeai/core', 'conflict');
  assert.throws(() => resume(f), /differs/);
  f.registryTransport.getRegistryVersion = () => ({});
  assert.throws(() => resume(f), /undetermined/);
});

test('success response without independent registry bytes remains partial', t => {
  const f = fixture(t);
  f.registryTransport.publish = () => ({ok:true});
  assert.equal(publishPlannedOperation(f).phase, 'PARTIAL_NEXT');
  assert.equal(f.state.packages['@oxdeai/core'].publishStatus,'pending');
});

for (const field of ['dependencies','peerDependencies','optionalDependencies']) {
  test(`unresolved external ${field} fails before receipt creation`, t => {
    const f = fixture(t);
    f.discovered[0].manifest[field] = { 'missing-external': '^1.0.0' };
    assert.throws(() => persistFixturePrecheck(f.discovered, path.join(f.releaseDir,'fresh'), undefined, undefined,
      { selection:F2_CLI1_SELECTION }), /external dependency resolution required/);
  });
}

test('stale receipt and mutated selection refuse fixture PACK before any packing', t => {
  const f = fixture(t);
  const fresh = path.join(f.releaseDir,'fresh');
  persistFixturePrecheck(f.discovered, fresh, 'b'.repeat(40), '/fake', {selection:F2_CLI1_SELECTION});
  assert.throws(() => pack({discovered:f.discovered, releaseDir:fresh, sourceRevision:'a'.repeat(40),
    sourceTransport:{snapshot:()=>({root:'/fake',revision:'a'.repeat(40),clean:true})},
    packTransport:{packToDir(){throw new Error('must not pack');}} }), /source revision/);
  const receipt = f.manifest.precheck;
  receipt.selection = receipt.selection.slice(0,4);
  receipt.receiptDigest = computePrecheckReceiptDigest(receipt);
  assert.throws(() => publicationPackages(f.manifest), /PRECHECK/);
});

test('fixture PACK freezes selection with all ten archive identities; altered persisted receipt blocks VERIFY_LOCAL', t => {
  const f = fixture(t), releaseDir = path.join(f.releaseDir,'packed');
  persistFixturePrecheck(f.discovered, releaseDir, 'a'.repeat(40), '/fake', {selection:F2_CLI1_SELECTION});
  const result = pack({ discovered:f.discovered, releaseDir, sourceRevision:'a'.repeat(40),
    sourceTransport:{snapshot:()=>({root:'/fake',revision:'a'.repeat(40),clean:true})},
    packageTransport:{read:d=>Buffer.from(JSON.stringify(d.manifest))},
    packTransport:{packToDir(d, dir){
      const file = path.join(dir,`${d.name.slice(8)}.tgz`);
      fs.writeFileSync(file,d.name); return file;
    }} });
  assert.equal(result.manifest.packages.length,10);
  assert.deepEqual(result.manifest.selection,F2_CLI1_SELECTION);
  assert.equal(publicationPackages(result.manifest).length,5);
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

test('resume refuses a modified excluded archive as well as selected originals', t => {
  const f = fixture(t);
  publishPlannedOperation(f); save(f);
  const adapter = f.manifest.packages.find(p=>p.package==='@oxdeai/autogen');
  fs.writeFileSync(path.join(f.releaseDir,adapter.tarball),'changed');
  assert.throws(()=>resume(f),/local tarball integrity/);
});


test('authorized npm wrapper forwards consent for the five-operation profile (mocked subprocess only)', t => {
  const f = authorizedFixture(t);
  f.manifest.selection = structuredClone(F2_CLI1_SELECTION);
  f.manifest.precheck.selection = structuredClone(F2_CLI1_SELECTION);
  f.manifest.precheck.receiptDigest = computePrecheckReceiptDigest(f.manifest.precheck);
  f.state.history[0].receiptDigest = f.manifest.precheck.receiptDigest;
  f.manifest.manifestIntegrity = computeManifestIntegrity(f.manifest);
  f.plan = fixturePlan(f.manifest,f.releaseDir);
  f.authorization = consent(f);
  assert.equal(invokeAuthorized(f).phase,'PARTIAL_NEXT');
  assert.equal(publications(f).length,1);
  assert.equal(f.plan.operations.length,5);
});
