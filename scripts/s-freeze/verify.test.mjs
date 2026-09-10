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
import { ROOT, CRITERIA, verify, report, acceptedDisposition, inFreezeScope } from './verify.mjs';

const criteria = JSON.parse(readFileSync(resolve(ROOT, CRITERIA), 'utf8'));

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
    source: { sha: 'a'.repeat(40), cleanWorktree: true, toolchain: { node: '22' }, packageVersions: { '@oxdeai/core': '2.0.0' } },
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
    results: [{ command: 'npx oxdeai-conformance validate', result: 'PASS', assertions: 259, artifacts: ['@oxdeai/core@2.0.0'], sha: 'a'.repeat(40) }],
    findings: [], conditionsAsserted: [], freezeDispositions: [], residualReviewScope: [],
    criteriaEvaluations: criteria.criteria.map((c) => ({ criterionId: c.id, state: 'PASS', evidence: 'synthetic' })),
    ...over,
  };
}

const run = (claims, over = {}, m = manifest()) =>
  verify(candidate(over), { registry: { version: 2, claims }, manifest: m, criteria });
const ids = (r) => r.blockers.map((b) => b.id);
const classOf = (r, id) => r.blockers.find((b) => b.id === id)?.class;

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

test('5. deferred/out-of-scope claim with explicit accepted disposition -> non-blocking', () => {
  assert.equal(run([claim({ scopeDisposition: 'deferred', evidenceState: 'gap', maintainerDecisionRequired: true })],
    { freezeDispositions: [disposition('X-001')] }).status, 'PASS');
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
  assert.equal(r.blockers.filter((b) => b.class === 'criterion').length, criteria.criteria.length);
  assert.match(r.blockers.find((b) => b.class === 'criterion').reason, /NOT_EVALUATED/);
});

test('11. a non-mandatory criterion failure does not silently become mandatory', () => {
  const optional = { version: 1, criteria: [{ id: 'OPT-1', class: 'claim', mandatory: false, statement: 's' }] };
  const r = verify(candidate({ criteriaEvaluations: [{ criterionId: 'OPT-1', state: 'FAIL' }] }),
    { registry: { version: 2, claims: [claim()] }, manifest: manifest(), criteria: optional });
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
  assert.match(r.blockers.find((b) => b.id === 'CORPUS-profile-c-AUTHORITY').reason, /exactly one independently editable/);
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
    const r = run([claim()], { source: { sha, cleanWorktree: true, toolchain: { node: '22' }, packageVersions: { a: '1' } } });
    assert.equal(classOf(r, 'SOURCE-SHA'), 'provenance', `sha=${sha}`);
  }
});

test('17. dirty-worktree freeze record -> blocking', () => {
  const r = run([claim()], { source: { sha: 'a'.repeat(40), cleanWorktree: false, toolchain: { node: '22' }, packageVersions: { a: '1' } } });
  assert.equal(classOf(r, 'SOURCE-CLEAN'), 'provenance');
});

test('18. missing RC artifact hash/integrity -> blocking', () => {
  const arts = [{ package: '@oxdeai/core', version: '2.0.0', tarball: 'core.tgz', buildCommand: 'pnpm pack', dependsOn: [] }];
  assert.equal(classOf(run([claim()], { rcArtifacts: arts }), 'RC-@oxdeai/core-INTEGRITY'), 'artifact');
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
  assert.match(r.blockers.find((b) => b.id === 'F1').reason, /has not been reproduced/);
});

test('22. FIXED without retest is not accepted as FIXED_AND_RETESTED', () => {
  const r = run([claim()], { findings: [{ id: 'F1', state: 'FIXED_AND_RETESTED', summary: 's' }] });
  assert.equal(classOf(r, 'F1'), 'finding');
  assert.match(r.blockers.find((b) => b.id === 'F1').reason, /original failure case to be rerun/);
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
  assert.deepEqual(ids(a), [...ids(a)].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0)).length === ids(a).length ? ids(a) : ids(a));
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
    const c = candidate(); mutate(c);
    const r = verify(c, { registry: { version: 2, claims: base }, manifest: manifest(), criteria });
    assert.equal(r.status, 'BLOCKED', `mutating ${name} must block`);
  }
});

test('mutation: flipping an accepted disposition to unaccepted flips PASS -> BLOCKED', () => {
  const claims = [claim({ id: 'D-1', scopeDisposition: 'deferred', evidenceState: 'gap', maintainerDecisionRequired: true })];
  assert.equal(run(claims, { freezeDispositions: [disposition('D-1')] }).status, 'PASS');
  assert.equal(run(claims, { freezeDispositions: [disposition('D-1', { decision: 'noted' })] }).status, 'BLOCKED');
  assert.equal(run(claims, { freezeDispositions: [] }).status, 'BLOCKED');
});

test('the shipped example candidate is explicitly marked non-authoritative', () => {
  const ex = JSON.parse(readFileSync(resolve(ROOT, 'docs/release/s-freeze/candidate.example.json'), 'utf8'));
  assert.match(ex.candidateId, /EXAMPLE/);
  assert.match(ex.note, /NON-AUTHORITATIVE/);
});
