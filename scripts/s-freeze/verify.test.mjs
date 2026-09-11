// SPDX-License-Identifier: Apache-2.0
//
// Tests for the S_freeze gate (#254).
//
// These validate the VERIFIER, using synthetic fixtures. They deliberately do
// not assert that the repository is freeze-ready: verifier correctness and
// actual freeze clearance are separate facts, and conflating them would let a
// green CI run imply a freeze that has not happened.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ROOT, CRITERIA, REGISTRY, CORPUS_MANIFEST, verify, report, acceptedDisposition, inFreezeScope } from './verify.mjs';

import { evidenceScope, digest, AUDIT } from '../../packages/conformance/src/evidenceScope.mjs';

const shippedCriteria = JSON.parse(readFileSync(resolve(ROOT, CRITERIA), 'utf8'));

const criteria = { ...shippedCriteria, blockerExitConditions: [] };

const claim = (over = {}) => ({
  id: 'X-001', title: 't', evidenceState: 'mapped', scopeDisposition: 'in-scope',
  maintainerDecisionRequired: false, normativeState: 'specified', recordType: 'requirement', ...over,
});

const manifest = (over = {}) => ({
  version: 1,
  corpora: [{
    id: 'profile-c', status: 'normative', semanticScope: 'Profile-C state verification',
    authority: 'docs/spec/test-vectors/profile-c-state-verification.json',
    representations: [
      { path: 'docs/spec/test-vectors/profile-c-state-verification.json', generated: false },
      { path: 'packages/conformance/vectors/profile-c-state-verification.json', generated: true, projectionSource: 'docs/spec/test-vectors/profile-c-state-verification.json' },
    ],
    consumers: [{ runtime: 'Go', execution: 'default-ci' }, { runtime: 'Python', execution: 'default-ci' }],
    ...over,
  }],
});

const disposition = (claimId, over = {}) => ({
  claimId, decision: 'deferred-with-rationale', rationale: 'r', boundedClaim: 'b',
  decidedBy: 'maintainer', decidedAt: '2026-09-08', ...over,
});

/** A complete synthetic candidate that PASSES. */
function candidate(over = {}) {
  return {
    version: 1, candidateId: 'SYNTH',
    source: { sha: 'a'.repeat(40), cleanWorktree: true, toolchain: { node: '22.14.0', pnpm: '10.34.5' }, packageVersions: { '@oxdeai/core': '2.0.0' } },
    rcArtifacts: [
      { package: '@oxdeai/core', version: '2.0.0', tarball: 'core.tgz', integrity: `sha256:${'0'.repeat(64)}`, buildCommand: 'pnpm pack', dependsOn: [] },
      { package: '@oxdeai/conformance', version: '2.0.0', tarball: 'conf.tgz', integrity: `sha256:${'1'.repeat(64)}`, buildCommand: 'pnpm pack', dependsOn: ['@oxdeai/core'] },
    ],
    conformanceAuthority: { projectionVerified: true, releaseRelevantCorpora: [{ id: 'profile-c', claimedRuntimes: ['Go', 'Python'] }] },
    reproduction: {
      cleanEnvironment: ['npm init -y'], externalInstall: ['npm install ./core.tgz'],
      publicInterface: ['node -e "import(\'@oxdeai/conformance\')"'], corpusExecution: ['npx oxdeai-conformance validate'],
      resultVerification: ['test PASS'],
    },
    results: [{ command: 'npx oxdeai-conformance validate', result: 'PASS', assertions: 259, artifacts: ['@oxdeai/core@2.0.0', '@oxdeai/conformance@2.0.0'], sha: 'a'.repeat(40) }],
    findings: [], conditionsAsserted: [], freezeDispositions: [], residualReviewScope: [],
    criteriaEvaluations: criteria.criteria.map((c) => ({ criterionId: c.id, state: 'PASS', evidence: 'synthetic' })),
    ...over,
  };
}

// Synthetic files are byte-bound through the same reader used by the CLI.
// No repository vectors, snapshots or expected values are rewritten.
function fixture(claims = [claim()], over = {}, m = manifest(), rules = criteria) {
  const c = candidate(over), files = new Map();
  const put = (path, value) => {
    const bytes = Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
    files.set(path, bytes); return { path, sha256: digest(bytes) };
  };
  const registry = { version: 2, claims };
  m = structuredClone(m);
  const data = [{ id: 'case-1', expected: 'ALLOW' }];
  for (const corpus of m.corpora) {
    corpus.spec = 'spec.md'; corpus.supportFiles = [];
    for (const r of corpus.representations) put(r.path, data);
    for (const consumer of corpus.consumers) {
      consumer.path ??= `${consumer.runtime}.runner`;
      consumer.representation ??= corpus.representations[0].path;
      consumer.role ??= 'verifier'; put(consumer.path, 'synthetic runner');
    }
  }
  put('spec.md', 'synthetic spec'); put(REGISTRY, registry); put(CORPUS_MANIFEST, m);
  put(AUDIT, 'Synthetic audit: no independent derivation.');
  const source = { revision: c.source.sha, workingTreeDirty: c.source.cleanWorktree !== true,
    artifacts: Object.fromEntries([...files].map(([p, bytes]) => [p, digest(bytes)])) };
  const snapshot = { registry, manifest: m, source,
    provenance: Object.fromEntries(m.corpora.map(c => [c.id, 'reference-generated'])),
    representations: Object.fromEntries(m.corpora.flatMap(c => c.representations.map(r => [r.path, { digest: digest(data), cases: { 'case-1': digest(data[0]) } }]))),
  };
  c.snapshot = put('snapshot.json', snapshot);
  for (const a of c.rcArtifacts) {
    const bytes = `synthetic tarball:${a.package}`;
    put(a.tarball, bytes); a.integrity = `sha256:${digest(Buffer.from(bytes))}`;
  }
  const artifactMap = Object.fromEntries(c.rcArtifacts.map(a => [`${a.package}@${a.version}`, a.integrity]));
  const observations = rules.criteria.map(x => ({ id: x.id, property: x.statement, stage: x.evidenceStages?.[0],
    result: 'PASS', command: `exercise ${x.id}`, expected: 'criterion not triggered', actual: 'criterion not triggered' }));
  for (const f of c.findings) if (f.state === 'FIXED_AND_RETESTED' && f.retestResult === 'PASS') {
    f.failureCondition = 'original failure'; f.stage = 'protected-execution';
    observations.push({ id: f.id, property: f.failureCondition, stage: f.stage, result: 'PASS', command: f.retestCommand, expected: 'blocked', actual: 'blocked' });
    f.evidence = [{ resultId: 'review', observationId: f.id }];
  }
  for (const o of observations) o.log = put(`${o.id}.log.json`, { ...o, source, artifacts: artifactMap });
  const review = { kind: 'review-observations', unsigned: true, reviewedBy: 'synthetic reviewer', reviewedAt: '2026-09-11', result: 'PASS', source, observations };
  function record(id, doc, command = 'synthetic command', selectedArtifacts = Object.keys(artifactMap)) {
    const evidence = put(`${id}.report.json`, doc);
    const binding = put(`${id}.binding.json`, { unsigned: true, command, reportSha256: evidence.sha256, source,
      artifacts: Object.fromEntries(selectedArtifacts.map(id => [id, artifactMap[id]])), unresolvedAssumptions: [], deploymentAssumptions: [] });
    return { id, command, result: doc.result, sha: c.source.sha, artifacts: selectedArtifacts, evidence, binding };
  }
  c.results = c.results.map((r, i) => ({ ...record(`original-${i}`, { ...review, result: r.result }, r.command, r.artifacts), ...r }));
  c.results.push(record('review', review));
  const selections = m.corpora.flatMap(c => c.consumers.filter(x => x.execution !== 'blocked').map(x => ({ representation: x.representation,
    consumer: x.path, runtime: x.runtime, data, caseIds: ['case-1'], passedCaseIds: ['case-1'] })));
  c.results.push(record('conformance', { result: 'PASS', evidenceScope: evidenceScope({ selections, metadata: snapshot }) }));
  for (const e of c.criteriaEvaluations) e.evidence = [{ resultId: 'review', observationId: e.criterionId }];
  c.conformanceAuthority.projectionEvidence = [{ resultId: 'review', observationId: 'CORP-003' }];
  const inputs = { registry, manifest: m, criteria: rules, read: p => {
    if (!files.has(p)) throw Error(`missing supplied file: ${p}`); return files.get(p);
  } };
  return { c, inputs, files, put, snapshot, record, run: () => verify(c, inputs) };
}
const run = (claims, over = {}, m = manifest()) => fixture(claims, over, m).run();
const issues = r => [...r.blockers, ...r.diagnostics];
const ids = (r) => r.blockers.map((b) => b.id);
const classOf = (r, id) => issues(r).find((b) => b.id === id)?.class;

// ── claim-level blocking semantics ──────────────────────────────────────────

test('1. in-scope + mapped + no maintainer decision -> non-blocking', () => {
  assert.equal(run([claim()]).status, 'PASS');
});

test('2. in-scope + gap -> blocking', () => {
  const r = run([claim({ evidenceState: 'gap' })]);
  assert.equal(r.status, 'BLOCKED');
  assert.equal(classOf(r, 'X-001'), 'claim');
});

test('3. in-scope + unassessed -> blocking', () => {
  assert.equal(classOf(run([claim({ evidenceState: 'unassessed' })]), 'X-001'), 'claim');
});

test('4. in-scope + maintainerDecisionRequired without accepted disposition -> blocking', () => {
  const r = run([claim({ maintainerDecisionRequired: true })]);
  assert.equal(classOf(r, 'X-001'), 'maintainer-decision');
});

test('5. deferred/out-of-scope claim with reviewed disposition remains blocking', () => {
  assert.equal(run([claim({ scopeDisposition: 'deferred', evidenceState: 'gap', maintainerDecisionRequired: true })],
    { freezeDispositions: [disposition('X-001')] }).status, 'BLOCKED');
});

test('6. deferred/out-of-scope claim WITHOUT required acceptance -> still blocking when the registry requires a decision', () => {
  for (const scope of ['deferred', 'deployment', 'out-of-scope']) {
    const r = run([claim({ scopeDisposition: scope, maintainerDecisionRequired: true })]);
    assert.equal(classOf(r, 'X-001'), 'maintainer-decision', `scope=${scope} must still block`);
  }
});

test('6b. out-of-scope gap WITHOUT a required decision does not block (scope, not evidence, decides)', () => {
  assert.equal(run([claim({ scopeDisposition: 'deployment', evidenceState: 'gap' })]).status, 'PASS');
});

test('7. conditional claim when the condition applies -> blocking rules apply', () => {
  const c = claim({ id: 'COND-1', scopeDisposition: 'conditional', evidenceState: 'gap' });
  assert.equal(classOf(run([c], { conditionsAsserted: ['COND-1'] }), 'COND-1'), 'claim');
});

test('8. conditional claim when the condition does not apply -> not falsely blocking', () => {
  const c = claim({ id: 'COND-1', scopeDisposition: 'conditional', evidenceState: 'gap' });
  assert.equal(run([c]).status, 'PASS');
});

test('acceptance requires every field: a partial disposition is treated as absent', () => {
  for (const missing of ['rationale', 'boundedClaim', 'decidedBy', 'decidedAt']) {
    const d = disposition('X-001'); delete d[missing];
    const r = run([claim({ maintainerDecisionRequired: true })], { freezeDispositions: [d] });
    assert.equal(r.status, 'BLOCKED', `missing ${missing} must not count as acceptance`);
  }
  const bad = disposition('X-001', { decision: 'looks-fine' });
  assert.equal(run([claim({ maintainerDecisionRequired: true })], { freezeDispositions: [bad] }).status, 'BLOCKED');
});

// ── falsification criteria ──────────────────────────────────────────────────

test('9. mandatory falsification criterion FAIL -> blocking', () => {
  const evals = criteria.criteria.map((c) => ({ criterionId: c.id, state: c.id === 'SEC-002' ? 'FAIL' : 'PASS' }));
  const r = run([claim()], { criteriaEvaluations: evals });
  assert.equal(classOf(r, 'SEC-002'), 'criterion');
});

test('10. mandatory criterion NOT_EVALUATED at freeze time -> blocking', () => {
  const r = run([claim()], { criteriaEvaluations: [] });
  assert.equal(r.status, 'BLOCKED');
  assert.equal(r.diagnostics.filter((b) => b.class === 'criterion').length, criteria.criteria.length);
  assert.match(r.diagnostics.find((b) => b.class === 'criterion').reason, /NOT_EVALUATED/);
});

test('11. a non-mandatory criterion failure does not silently become mandatory', () => {
  const optional = { version: 1, criteria: [{ id: 'OPT-1', class: 'claim', mandatory: false, statement: 's' }] };
  const r = fixture([claim()], { criteriaEvaluations: [{ criterionId: 'OPT-1', state: 'FAIL' }] }, manifest(), optional).run();
  assert.equal(r.status, 'PASS');
});

test('every predeclared criterion in the shipped file is mandatory', () => {
  assert.ok(criteria.criteria.length >= 18);
  assert.equal(criteria.criteria.filter((c) => c.mandatory !== true).length, 0);
});

// ── corpus authority ────────────────────────────────────────────────────────

test('12. ambiguous corpus authority -> blocking', () => {
  const m = manifest({ authority: 'docs/spec/test-vectors/other.json' });
  assert.equal(classOf(run([claim()], {}, m), 'CORPUS-profile-c-AUTHORITY'), 'corpus');
});

test('13. independently editable duplicate authority -> blocking', () => {
  const m = manifest({
    representations: [
      { path: 'docs/spec/test-vectors/profile-c-state-verification.json', generated: false },
      { path: 'packages/conformance/vectors/profile-c-state-verification.json', generated: false },
    ],
  });
  const r = run([claim()], {}, m);
  assert.equal(classOf(r, 'CORPUS-profile-c-AUTHORITY'), 'corpus');
  assert.match(r.diagnostics.find((b) => b.id === 'CORPUS-profile-c-AUTHORITY').reason, /exactly one independently editable/);
});

test('14. missing Profile-C deterministic projection evidence -> blocking', () => {
  const r = run([claim()], { conformanceAuthority: { projectionVerified: false, releaseRelevantCorpora: [{ id: 'profile-c' }] } });
  assert.equal(classOf(r, 'CORPUS-PROJECTION'), 'corpus');
});

test('15. unsupported claimed runtime/language coverage -> blocking', () => {
  const m = manifest({ consumers: [{ runtime: 'Go', execution: 'default-ci' }, { runtime: 'Python', execution: 'blocked' }] });
  const r = run([claim()], {}, m);
  assert.equal(classOf(r, 'CORPUS-profile-c-RUNTIME-Python'), 'corpus');
});

test('a declared release-relevant corpus absent from the manifest blocks', () => {
  const r = run([claim()], { conformanceAuthority: { projectionVerified: true, releaseRelevantCorpora: [{ id: 'ghost' }] } });
  assert.equal(classOf(r, 'CORPUS-ghost'), 'corpus');
});

// ── provenance / artifacts ──────────────────────────────────────────────────

test('16. missing exact Git SHA -> blocking', () => {
  for (const sha of [undefined, '', 'abc', 'A'.repeat(40)]) {
    const r = run([claim()], { source: { sha, cleanWorktree: true, toolchain: { node: '22.14.0', pnpm: '10.34.5' }, packageVersions: { a: '1' } } });
    assert.equal(classOf(r, 'SOURCE-SHA'), 'provenance', `sha=${sha}`);
  }
});

test('17. dirty-worktree freeze record -> blocking', () => {
  const r = run([claim()], { source: { sha: 'a'.repeat(40), cleanWorktree: false, toolchain: { node: '22.14.0', pnpm: '10.34.5' }, packageVersions: { a: '1' } } });
  assert.equal(classOf(r, 'SOURCE-CLEAN'), 'provenance');
});

test('18. missing RC artifact hash/integrity -> blocking', () => {
  const arts = [{ package: '@oxdeai/core', version: '2.0.0', tarball: 'core.tgz', buildCommand: 'pnpm pack', dependsOn: [] }];
  const f = fixture([claim()], { rcArtifacts: arts }); delete f.c.rcArtifacts[0].integrity;
  assert.equal(classOf(f.run(), 'RC-@oxdeai/core-INTEGRITY'), 'artifact');
});

test('an RC artifact depending on a package not supplied in the bundle blocks', () => {
  const arts = [{ package: '@oxdeai/conformance', version: '2.0.0', tarball: 'c.tgz', integrity: `sha256:${'0'.repeat(64)}`, buildCommand: 'pnpm pack', dependsOn: ['@oxdeai/core'] }];
  assert.equal(classOf(run([claim()], { rcArtifacts: arts }), 'RC-@oxdeai/conformance-DEP'), 'artifact');
});

test('19. monorepo-relative external reproduction path -> blocking', () => {
  for (const step of ['pnpm -C packages/conformance validate', 'node ../packages/core/dist/index.js', 'pnpm --filter @oxdeai/core test']) {
    const r = run([claim()], { reproduction: { ...candidate().reproduction, corpusExecution: [step] } });
    assert.equal(classOf(r, 'REPRO-MONOREPO'), 'artifact', step);
  }
});

test('a result not tied to the frozen SHA or to an artifact blocks', () => {
  const r1 = run([claim()], { results: [{ command: 'x', result: 'PASS', artifacts: ['a'], sha: 'b'.repeat(40) }] });
  assert.equal(classOf(r1, 'RESULT-0-SHA'), 'provenance');
  const r2 = run([claim()], { results: [{ command: 'x', result: 'PASS', artifacts: [], sha: 'a'.repeat(40) }] });
  assert.equal(classOf(r2, 'RESULT-0-ARTIFACTS'), 'provenance');
});

// ── finding evidence states ─────────────────────────────────────────────────

test('20. known reproduced security-boundary failure without accepted fix/retest -> blocking', () => {
  const r = run([claim()], { findings: [{ id: 'SEC-F1', state: 'REPRODUCED', summary: 's' }] });
  assert.equal(classOf(r, 'SEC-F1'), 'finding');
});

test('21. REPORTED is not treated as REPRODUCED', () => {
  const r = run([claim()], { findings: [{ id: 'F1', state: 'REPORTED', summary: 's' }] });
  assert.equal(classOf(r, 'F1'), 'finding');
  assert.match(r.diagnostics.find((b) => b.id === 'F1').reason, /has not been reproduced/);
});

test('22. FIXED without retest is not accepted as FIXED_AND_RETESTED', () => {
  const r = run([claim()], { findings: [{ id: 'F1', state: 'FIXED_AND_RETESTED', summary: 's' }] });
  assert.ok(r.diagnostics.some(b => b.id === 'F1' && b.class === 'finding'));
  assert.ok(r.diagnostics.some(b => b.id === 'F1' && /original failure case to be rerun/.test(b.reason)));
  assert.equal(run([claim()], { findings: [{ id: 'F1', state: 'FIXED_AND_RETESTED', retestCommand: 'c', retestResult: 'PASS' }] }).status, 'PASS');
});

test('23. DEFERRED_WITH_RATIONALE requires rationale + bounded claim', () => {
  assert.equal(classOf(run([claim()], { findings: [{ id: 'F1', state: 'DEFERRED_WITH_RATIONALE' }] }), 'F1'), 'finding');
  assert.equal(run([claim()], { findings: [{ id: 'F1', state: 'DEFERRED_WITH_RATIONALE', rationale: 'r', boundedClaim: 'b' }] }).status, 'PASS');
});

test('an invalid finding state is rejected rather than ignored', () => {
  assert.equal(classOf(run([claim()], { findings: [{ id: 'F1', state: 'FIXED' }] }), 'F1'), 'finding');
});

test('a residual review-scope item without explicit treatment blocks', () => {
  assert.equal(classOf(run([claim()], { residualReviewScope: [{ ref: '#197' }] }), '#197'), 'residual');
  assert.equal(run([claim()], { residualReviewScope: [{ ref: '#197', treatment: 'included-in-review-scope', rationale: 'r', boundedClaim: 'b' }] }).status, 'PASS');
});

// ── output + end-to-end ─────────────────────────────────────────────────────

test('24. blocker output is deterministic', () => {
  const claims = [claim({ id: 'Z-1', evidenceState: 'gap' }), claim({ id: 'A-1', maintainerDecisionRequired: true }), claim({ id: 'M-1', evidenceState: 'unassessed' })];
  const a = run(claims, { criteriaEvaluations: [] });
  const b = run([...claims].reverse(), { criteriaEvaluations: [] });
  assert.deepEqual(ids(a), ids(b));
  assert.deepEqual(ids(a), ['A-1', 'M-1', 'Z-1']);
  assert.deepEqual(ids(b), ['A-1', 'M-1', 'Z-1']);
  assert.equal(report(a), report(b));
});

test('25. a complete synthetic freeze candidate produces PASS', () => {
  const r = run([claim({ id: 'OK-1' }), claim({ id: 'OK-2', scopeDisposition: 'deployment', evidenceState: 'gap' })]);
  assert.equal(r.status, 'PASS', JSON.stringify(r.blockers));
  assert.match(report(r), /^S_FREEZE: PASS/);
  assert.match(report(r), /not semantic proof/);
});

// ── mutation tests: PASS -> BLOCKED on a single field change ────────────────

test('mutation: removing any single required candidate field flips PASS -> BLOCKED', () => {
  const base = [claim({ id: 'OK-1' })];
  assert.equal(run(base).status, 'PASS');
  const mutations = {
    'source.sha': (c) => { delete c.source.sha; },
    'source.cleanWorktree': (c) => { c.source.cleanWorktree = false; },
    'source.toolchain': (c) => { c.source.toolchain = {}; },
    'source.packageVersions': (c) => { c.source.packageVersions = {}; },
    'rcArtifacts': (c) => { c.rcArtifacts = []; },
    'rcArtifacts[0].integrity': (c) => { delete c.rcArtifacts[0].integrity; },
    'reproduction.externalInstall': (c) => { c.reproduction.externalInstall = []; },
    'results': (c) => { c.results = []; },
    'conformanceAuthority.projectionVerified': (c) => { c.conformanceAuthority.projectionVerified = false; },
    'criteriaEvaluations': (c) => { c.criteriaEvaluations = []; },
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const f = fixture(base); mutate(f.c);
    const r = f.run();
    assert.equal(r.status, 'BLOCKED', `mutating ${name} must block`);
  }
});

test('dispositions never remove unresolved blockers', () => {
  const claims = [claim({ id: 'D-1', scopeDisposition: 'deferred', evidenceState: 'gap', maintainerDecisionRequired: true })];
  assert.equal(run(claims, { freezeDispositions: [disposition('D-1')] }).status, 'BLOCKED');
  assert.equal(run(claims, { freezeDispositions: [disposition('D-1', { decision: 'noted' })] }).status, 'BLOCKED');
  assert.equal(run(claims, { freezeDispositions: [] }).status, 'BLOCKED');
});

test('the shipped example candidate is explicitly marked non-authoritative', () => {
  const ex = JSON.parse(readFileSync(resolve(ROOT, 'docs/release/s-freeze/candidate.example.json'), 'utf8'));
  assert.match(ex.candidateId, /EXAMPLE/);
  assert.match(ex.note, /NON-AUTHORITATIVE/);
});

// #321/#324/#325 reconciliation: each fixture begins PASS, then changes one
// evidence obligation. The old text-only implementation accepted these states.
function mutateReport(f, id, mutate) {
  const r = f.c.results.find(r => r.id === id);
  const doc = JSON.parse(f.files.get(r.evidence.path)); mutate(doc);
  r.evidence = f.put(r.evidence.path, doc);
  const binding = JSON.parse(f.files.get(r.binding.path)); binding.reportSha256 = r.evidence.sha256;
  r.binding = f.put(r.binding.path, binding);
}
const scopedClaim = () => claim({ evidence: [{ kind: 'vector', path: 'docs/spec/test-vectors/profile-c-state-verification.json', selector: { type: 'vector', id: 'case-1' }, runner: { path: 'Go.runner', runtime: 'Go' }, supports: 'selected rejection only' }] });
const negative = (name, mutate, claims) => test(name, () => {
  const f = fixture(claims); assert.equal(f.run().status, 'PASS', JSON.stringify(f.run().blockers));
  mutate(f); assert.equal(f.run().status, 'BLOCKED');
});
negative('FAIL recorded result cannot satisfy evidence', f => { f.c.results[0].result = 'FAIL'; });
negative('FAIL hashed report cannot satisfy evidence', f => mutateReport(f, 'review', d => { d.result = 'FAIL'; }));
negative('missing mandatory evidence cannot PASS', f => { delete f.c.criteriaEvaluations[0].evidence; });
negative('failed retest cannot satisfy FIXED_AND_RETESTED', f => { f.c.findings = [{ id: 'F1', state: 'FIXED_AND_RETESTED', retestCommand: 'test', retestResult: 'FAIL' }]; });
negative('successful retest label without failure-case evidence remains unresolved', f => { f.c.findings = [{ id: 'F1', state: 'FIXED_AND_RETESTED', retestCommand: 'test', retestResult: 'PASS' }]; });
negative('unresolved result artifact reference cannot satisfy evidence', f => { f.c.results[0].artifacts = ['missing@1']; });
negative('missing evidence file blocks despite nonempty reference', f => { f.files.delete(f.c.results[0].evidence.path); });
negative('modified evidence bytes fail hash binding', f => { f.files.set(f.c.results[0].evidence.path, Buffer.from('{}')); });
negative('modified RC bytes fail integrity binding', f => { f.files.set(f.c.rcArtifacts[0].tarball, Buffer.from('different')); });
negative('dirty evidence is not normalized to candidate clean assertion', f => mutateReport(f, 'review', d => { d.source.workingTreeDirty = true; }));
negative('evidence revision mismatch blocks', f => mutateReport(f, 'review', d => { d.source.revision = 'b'.repeat(40); }));
negative('missing source hashes block', f => mutateReport(f, 'review', d => { d.source.artifacts = {}; }));
negative('unsigned execution binding cannot be presented as attestation', f => { const r=f.c.results[0]; const b=JSON.parse(f.files.get(r.binding.path)); b.unsigned=false; r.binding=f.put(r.binding.path,b); });
negative('missing criterion observation blocks', f => { f.c.criteriaEvaluations[0].evidence[0].observationId = 'ghost'; });
negative('earlier stage cannot satisfy protected-execution criterion', f => mutateReport(f, 'review', d => { d.observations.find(o=>o.id==='SEC-001').stage='artifact-verification'; }));
negative('unexecuted manifest runtime cannot support coverage', f => mutateReport(f, 'conformance', d => { d.evidenceScope.corpora=[]; d.evidenceScope.consumers=[]; }));
negative('overall PASS without passed cases cannot support coverage', f => mutateReport(f, 'conformance', d => { d.evidenceScope.corpora[0].passedCaseIds=[]; }));
negative('wrong runtime cannot inherit another runtime mapping', f => mutateReport(f, 'conformance', d => { d.evidenceScope.corpora[0].runtime='Rust'; }));
negative('broader supports statement cannot be inferred from coveredClaims', f => {
  const r=f.c.results.find(r=>r.id==='conformance'), d=JSON.parse(f.files.get(r.evidence.path));
  r.claims=structuredClone(d.evidenceScope.coveredClaims); r.claims[0].evidence[0].supports='whole protocol and deployment';
}, [scopedClaim()]);
negative('excluded claim cannot support closure', f => { f.c.results.find(r=>r.id==='conformance').claims=[{id:'PEP-DEPLOY-001',evidence:[]}]; });
negative('scope exclusions cannot be dropped', f => mutateReport(f, 'conformance', d => { d.evidenceScope.excludedClaims=[]; }));
negative('reference-generated provenance cannot be promoted', f => mutateReport(f, 'conformance', d => { d.evidenceScope.corpusProvenance[0].classification='independently-derived'; }));
negative('snapshot provenance cannot be promoted either', f => { f.snapshot.provenance['profile-c']='independently-derived'; f.c.snapshot=f.put('snapshot.json',f.snapshot); });
negative('cross-language agreement is not independent normative authority', f => { f.c.conformanceAuthority.independentNormativeAuthority=true; });
negative('projection boolean without executed check evidence blocks', f => { delete f.c.conformanceAuthority.projectionEvidence; });
negative('unresolved assumptions cannot be normalized away', f => { f.c.unresolvedAssumptions=['unknown topology']; });
negative('duplicate evidence IDs are ambiguous', f => { f.c.results[0].id='review'; });

test('text-only closure and reviewed deferral preserve all nine current blockers', () => {
  const registry=JSON.parse(readFileSync(resolve(ROOT,REGISTRY),'utf8'));
  const expected=shippedCriteria.blockerExitConditions.map(c=>c.id).sort();
  for(const decision of ['fixed-before-freeze','deferred-with-rationale','included-in-review-scope']) {
    const f=fixture(registry.claims, {}, manifest(), shippedCriteria);
    f.c.freezeDispositions=expected.map(id=>disposition(id,{decision}));
    const r=f.run(); assert.equal(r.status,'BLOCKED');
    assert.deepEqual([...new Set(r.blockers.filter(b=>expected.includes(b.id)).map(b=>b.id))].sort(),expected);
    assert.ok(r.blockers.some(b=>b.id==='VERIFY-ORDER-001'));
    assert.ok(r.dispositions.every(d=>d.status!=='demonstrated-closure'));
  }
});
test('consume/ALLOW/gateway evidence cannot close deployment blockers', () => {
  for(const stage of ['replay-consume','authorization','artifact-verification','gateway-unit','shared-memory','redis-selection']) {
    const c=claim({id:'PEP-DEPLOY-001',scopeDisposition:'deployment',evidenceState:'gap',maintainerDecisionRequired:true});
    const f=fixture([c], {}, manifest(), shippedCriteria);
    f.c.freezeDispositions=[disposition(c.id,{decision:'fixed-before-freeze',evidence:[{resultId:'review',observationId:'SEC-001'}]})];
    mutateReport(f,'review',d=>{d.observations.find(o=>o.id==='SEC-001').stage=stage;});
    assert.ok(f.run().blockers.some(b=>b.id===c.id));
  }
});
test('report preserves scope, exclusions, snapshot and unsigned assumptions', () => {
  const f=fixture(), r=f.run(); assert.equal(r.status,'PASS'); assert.equal(r.unsigned,true);
  const scope=r.evidence.find(e=>e.id==='conformance').report.evidenceScope;
  assert.deepEqual(scope.excludedClaims,['X-001']); assert.equal(scope.source.workingTreeDirty,false);
  assert.equal(scope.corpusProvenance[0].classification,'reference-generated');
  assert.ok(scope.assumptions.some(x=>x.includes('unsigned'))); assert.deepEqual(r.snapshot.identity,f.c.snapshot);
  assert.ok(r.limitations.some(x=>x.includes('not an attestation')));
});
test('CI runs the canonical verifier tests and retains direct Rust gate', () => {
  const ci=readFileSync(resolve(ROOT,'.github/workflows/ci.yml'),'utf8');
  assert.match(ci,/run: pnpm test:s-freeze/); assert.match(ci,/run: cargo test --locked/);
});

negative('PASS cannot override an observed result differing from expectation', f => mutateReport(f, 'review', d => { d.observations[0].actual='criterion triggered'; }));
negative('unknown disposition cannot be reported as demonstrated closure', f => { f.c.freezeDispositions=[disposition('UNKNOWN')]; });
negative('unknown snapshot dirty state blocks', f => { f.snapshot.source.workingTreeDirty=null; f.c.snapshot=f.put('snapshot.json',f.snapshot); });
negative('unresolved execution assumptions block even with a clean candidate', f => {
  const r=f.c.results[0], b=JSON.parse(f.files.get(r.binding.path)); b.unresolvedAssumptions=['unknown state']; r.binding=f.put(r.binding.path,b);
});
test('resolved synthetic deployment exit needs direct deployment observations', () => {
  const exit=shippedCriteria.blockerExitConditions.find(c=>c.id==='PEP-DEPLOY-001');
  const f=fixture([claim({id:exit.id,scopeDisposition:'deployment'})], {}, manifest(), {...criteria,blockerExitConditions:[exit]});
  const source=f.snapshot.source;
  const r=f.c.results.find(r=>r.id==='review');
  const b=JSON.parse(f.files.get(r.binding.path)); b.deploymentAssumptions=['Synthetic tested topology only']; r.binding=f.put(r.binding.path,b);
  const observation={id:'deployment-test',property:exit.exitCondition,stage:'deployment',command:'exercise deployment',result:'PASS',expected:'protected boundary retained',actual:'protected boundary retained',replayDomain:'synthetic-domain',topology:'synthetic topology'};
  observation.log=f.put('deployment.log.json',{...observation,source,artifacts:b.artifacts});
  mutateReport(f,'review',d=>{d.observations.push(observation);});
  f.c.freezeDispositions=[disposition(exit.id,{decision:'fixed-before-freeze',evidence:[{resultId:'review',observationId:observation.id}]})];
  assert.equal(f.run().status,'PASS',JSON.stringify(f.run().blockers));
  const beforeCollision = f.run().dispositions;
  f.c.findings = [{ id: exit.id, state: 'REPORTED' }];
  const collision = f.run();
  assert.equal(collision.status, 'BLOCKED');
  assert.deepEqual(collision.blockers, []);
  assert.ok(collision.diagnostics.some(d => d.id === exit.id));
  assert.deepEqual(collision.dispositions, beforeCollision, 'diagnostic ID collision must not change demonstrated closure');
  f.c.findings = [];
  // Change both hashed records consistently: the stage guard itself must block,
  // not just an incidental report/log hash mismatch.
  const changed={...observation,stage:'replay-consume'};
  changed.log=f.put('deployment.log.json',{...changed,source,artifacts:b.artifacts});
  mutateReport(f,'review',d=>{d.observations[d.observations.length-1]=changed;});
  assert.ok(f.run().blockers.some(b=>b.id===exit.id));
});

negative('malformed claimed scope is not silently treated as absent', f => { f.c.results[0].claims={id:'PEP-DEPLOY-001'}; });
negative('unknown scope version cannot support evidence', f => mutateReport(f,'conformance',d=>{d.evidenceScope.version=99;}));
test('CLI cannot replace mandatory criteria through an override', () => {
  const r=spawnSync(process.execPath,['scripts/s-freeze/verify.mjs','--criteria','empty.json'],{cwd:ROOT,encoding:'utf8'});
  assert.equal(r.status,1); assert.match(r.stderr,/criteria override is not permitted/);
});
test('shipped example is BLOCKED through canonical gate CLI', () => {
  const r=spawnSync(process.execPath,['scripts/s-freeze/verify.mjs','--candidate','docs/release/s-freeze/candidate.example.json','--json'],{cwd:ROOT,encoding:'utf8'});
  assert.equal(r.status,1); const report=JSON.parse(r.stdout); assert.equal(report.status,'BLOCKED');
  for(const exit of shippedCriteria.blockerExitConditions) assert.ok(report.blockers.some(b=>b.id===exit.id));
  assert.ok(report.diagnostics.some(b=>b.id==='EVIDENCE-SNAPSHOT'));
});

negative('PASS label cannot hide recorded conformance failures', f => mutateReport(f,'conformance',d=>{d.failures=['failed assertion'];}));
negative('PASS label cannot hide a failed runner exit', f => mutateReport(f,'conformance',d=>{d.executions=[{exitCode:1}];}));
test('ambiguous and unknown in-scope registry states do not become satisfied', () => {
  for(const normativeState of ['ambiguous','unresolved',undefined]) assert.equal(run([claim({normativeState})]).status,'BLOCKED');
  for(const evidenceState of ['unknown',undefined]) assert.equal(run([claim({evidenceState})]).status,'BLOCKED');
});


test('evidence diagnostics alone prevent PASS without adding declared blockers', () => {
  const f=fixture(); assert.equal(f.run().status,'PASS');
  f.c.results[0].result='FAIL';
  const r=f.run(); assert.equal(r.status,'BLOCKED'); assert.deepEqual(r.blockers,[]);
  assert.ok(r.diagnostics.some(d=>d.id==='RESULT-0-EVIDENCE'));
  assert.match(report(r),/BLOCKING DIAGNOSTICS/); assert.doesNotMatch(report(r),/DECLARED BLOCKERS/);
});
test('declared blocker alone prevents PASS; reviewed deferral stays a blocker', () => {
  const f=fixture([claim({maintainerDecisionRequired:true})]);
  f.c.freezeDispositions=[disposition('X-001')];
  const r=f.run(); assert.equal(r.status,'BLOCKED'); assert.deepEqual(ids(r),['X-001']);
  assert.deepEqual(r.diagnostics,[]); assert.equal(r.dispositions[0].status,'reviewed-deferral-unresolved');
});
test('example has exactly nine unique declared blockers and separate required diagnostics', () => {
  const candidate=JSON.parse(readFileSync(resolve(ROOT,'docs/release/s-freeze/candidate.example.json'),'utf8'));
  const registry=JSON.parse(readFileSync(resolve(ROOT,REGISTRY),'utf8'));
  const manifest=JSON.parse(readFileSync(resolve(ROOT,CORPUS_MANIFEST),'utf8'));
  const r=verify(candidate,{registry,manifest,criteria:shippedCriteria,read:()=>{throw Error('example evidence is not supplied');}});
  assert.deepEqual(ids(r),shippedCriteria.blockerExitConditions.map(c=>c.id).sort());
  assert.equal(r.blockers.length,9); assert.ok(r.diagnostics.length>0); assert.equal(r.status,'BLOCKED');
  assert.ok(r.diagnostics.some(d=>d.id==='EVIDENCE-SNAPSHOT'));
  assert.match(report(r),/DECLARED BLOCKERS \(9\)/); assert.match(report(r),/BLOCKING DIAGNOSTICS/);
});
test('blockers and diagnostics each have deterministic ordering', () => {
  const f=fixture([claim({id:'Z',maintainerDecisionRequired:true}),claim({id:'A',evidenceState:'gap'})]);
  f.c.findings=[{id:'Z-diagnostic',state:'REPORTED'},{id:'A-diagnostic',state:'REPRODUCED'}];
  const first=f.run(); f.c.findings.reverse();
  const second=f.run(); assert.deepEqual(second.blockers,first.blockers);
  const ordering = r => r.diagnostics.map(({id, class: cls, reason}) => ({id, class: cls, reason}));
  assert.deepEqual(ordering(second),ordering(first));
  assert.deepEqual(f.run(),second, 'identical input produces identical complete diagnostics');
});
test('every exit entry cites an existing registry record and exact repository excerpts', () => {
  const registry=JSON.parse(readFileSync(resolve(ROOT,REGISTRY),'utf8'));
  for(const e of shippedCriteria.blockerExitConditions){
    assert.ok(e.sources.some(s=>s.path===REGISTRY && s.claimId===e.id));
    assert.ok(registry.claims.some(c=>c.id===e.id));
    for(const source of e.sources.filter(s=>s.quote)){
      const text=readFileSync(resolve(ROOT,source.path),'utf8');
      assert.ok(text.includes(source.section),`${e.id}: missing section ${source.section}`);
      assert.ok(text.includes(source.quote),`${e.id}: missing quote ${source.quote}`);
    }
    if(e.exitConditionState==='unresolved') {assert.equal(e.exitCondition,null);assert.deepEqual(e.evidenceStages,[]);}
    else assert.ok(e.sources.some(s=>s.quote===e.exitCondition),`${e.id}: exact exit lacks source`);
  }
});
test('undefined or conflicting exits stay unresolved even if registry flags are changed', () => {
  const unresolved=shippedCriteria.blockerExitConditions.filter(e=>e.exitConditionState==='unresolved');
  assert.deepEqual(unresolved.map(e=>e.id).sort(),['CANON-ESC-001','ETA-SIGNING-001','RT-TRUST-1','VERIFY-ORDER-001']);
  for(const exit of unresolved){
    const f=fixture([claim({id:exit.id})],{},manifest(),{...criteria,blockerExitConditions:[exit]});
    f.c.freezeDispositions=[disposition(exit.id,{decision:'fixed-before-freeze'})];
    assert.deepEqual(ids(f.run()),[exit.id]);
  }
});
test('exit boundary does not add rejection, durability or ecosystem closure obligations', () => {
  const exits=new Map(shippedCriteria.blockerExitConditions.map(e=>[e.id,e]));
  assert.equal(exits.get('CANON-003').exitCondition,'- duplicate keys MUST be detected during parsing');
  assert.equal(exits.get('PEP-DEPLOY-001').exitCondition,'The PEP Gateway **MUST** act as the **sole execution boundary** for protected actions.');
  assert.equal(exits.get('RT-TRUST-2').exitConditionState,'conditional');
  assert.match(shippedCriteria.evidenceBoundary,/no override of protocol specifications/);
});


// Final bounded hardening: unknown scope is a blocking claim diagnostic even
// when the registry would otherwise be mapped/specified with no decision owed.
const malformedScopes = [undefined, null, '', ' ', 'in-scope ', ' in-scope', 'in-scope\n',
  'out-of-scope ', 'deployment\t', 'conditionnal', 'in_scope', 'unknown', 'IN-SCOPE',
  false, true, 0, 1, [], ['in-scope'], {}, { scope: 'in-scope' }];
test('malformed scopeDisposition fails closed for mapped, specified claims', () => {
  for (const scopeDisposition of malformedScopes) {
    const c=claim({scopeDisposition});
    assert.equal(inFreezeScope(c,candidate()),null);
    const r=run([c]); assert.equal(r.status,'BLOCKED',JSON.stringify(scopeDisposition));
    assert.ok(r.diagnostics.some(d=>d.id==='CLAIM-SCOPE-X-001' && d.class==='claim'));
    assert.deepEqual(r.blockers,[],'invalid registry scope is diagnosed, not assigned an invented release scope');
  }
  const missing=claim(); delete missing.scopeDisposition;
  assert.ok(run([missing]).diagnostics.some(d=>d.class==='claim' && d.id==='CLAIM-SCOPE-X-001'));
});
test('mutating gap/unassessed scope cannot remove its failure and create PASS', () => {
  for (const evidenceState of ['gap','unassessed']) {
    assert.equal(run([claim({evidenceState})]).status,'BLOCKED');
    for (const scopeDisposition of malformedScopes) {
      // Build matching source evidence for each mutation so rejection must come
      // from scope validation, not incidental snapshot/hash drift.
      const r=run([claim({evidenceState,scopeDisposition})]);
      assert.equal(r.status,'BLOCKED',`${evidenceState}: ${JSON.stringify(scopeDisposition)}`);
      assert.ok(r.diagnostics.some(d=>d.class==='claim' && d.id==='CLAIM-SCOPE-X-001'));
    }
  }
});
test('existing legitimate scope vocabulary retains its semantics', () => {
  for (const scopeDisposition of ['in-scope','conditional','deferred','deployment','out-of-scope']) {
    const r=run([claim({scopeDisposition})]);
    assert.equal(r.status,'PASS',scopeDisposition);
    assert.ok(!r.diagnostics.some(d=>d.id==='CLAIM-SCOPE-X-001'));
  }
});
test('ranges, wildcards and malformed tool versions cannot satisfy SOURCE-TOOLCHAIN', () => {
  const f=fixture(); assert.equal(f.run().status,'PASS');
  for (const version of ['22.x','10.x','latest','*','>=22','^22.14.0','~22.14.0','22','22.14',
    '22.14.0 || 23.0.0','22.14.0 - 23.0.0',' 22.14.0','22.14.0 ','22.14.0\n',
    '22..0','22.14.0.1','v','01.2.3','22.14.0-','22.14.0+','',null,22,false,{},[]]) {
    f.c.source.toolchain={node:version,pnpm:'10.34.5'};
    const r=f.run(); assert.equal(r.status,'BLOCKED',JSON.stringify(version));
    assert.ok(r.diagnostics.some(d=>d.id==='SOURCE-TOOLCHAIN'));
    assert.deepEqual(r.blockers,[]);
  }
});
test('missing or wrong-typed toolchain records fail closed', () => {
  const f=fixture();
  for (const toolchain of [undefined,null,{},[],['22.14.0'],'22.14.0',22,true]) {
    f.c.source.toolchain=toolchain;
    assert.ok(f.run().diagnostics.some(d=>d.id==='SOURCE-TOOLCHAIN'));
  }
});
test('exact tool versions pass provenance without satisfying TOOL-001 by themselves', () => {
  const f=fixture();
  for (const version of ['22.14.0','v22.14.0','22.14.0-rc.1','22.14.0+build.1']) {
    f.c.source.toolchain={node:version,pnpm:'10.34.5'}; assert.equal(f.run().status,'PASS');
  }
  f.c.criteriaEvaluations.find(c=>c.criterionId==='TOOL-001').evidence=[];
  const r=f.run(); assert.equal(r.status,'BLOCKED');
  assert.ok(!r.diagnostics.some(d=>d.id==='SOURCE-TOOLCHAIN'));
  assert.ok(r.diagnostics.some(d=>d.id==='TOOL-001'));
});
test('shipped example records illustrative exact toolchain versions', () => {
  const c=JSON.parse(readFileSync(resolve(ROOT,'docs/release/s-freeze/candidate.example.json'),'utf8'));
  assert.deepEqual(c.source.toolchain,{node:'22.14.0',pnpm:'10.34.5'});
  assert.match(c.note,/NON-AUTHORITATIVE/);
});
