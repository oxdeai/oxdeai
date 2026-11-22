import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { verify, report, advisory, testNames, ROOT, REGISTRY } from './verify.mjs';

const original = JSON.parse(readFileSync(resolve(ROOT, REGISTRY), 'utf8'));
const fresh = () => structuredClone(original);
const lock = r => r.claims.find(c => c.id === 'RT-TRUST-2');
const mutations = [
  ['legacy schema rejected', r => r.version = 1, 'MALFORMED'],
  ['legacy status rejected', r => r.claims[0].status = 'mapped', 'MALFORMED'],
  ['unknown dependency', r => r.claims[0].dependsOn = [{ id: 'ABSENT-1', relation: 'interpretation', reason: 'test' }], 'INVALID_DEPENDENCY'],
  ['malformed inference guard', r => r.claims[0].inferenceGuard = [{ from: 'PASS' }], 'MALFORMED'],
  ['invalid decision flag', r => r.claims[0].maintainerDecisionRequired = 'yes', 'MALFORMED'],
  ['conditional scope without conditions', r => lock(r).appliesWhen = [], 'MALFORMED'],
  ['lock promoted to executable obligation', r => lock(r).requiredLevels = ['TESTED'], 'LOCK_PROMOTION'],
  ['lock promoted to normative source', r => lock(r).source.role = 'normative', 'LOCK_PROMOTION'],
  ['lock promoted to normative strength', r => lock(r).strength = 'MUST', 'LOCK_PROMOTION'],
  ['deferred pending claim still enforces negatives', r => { const c = r.claims.find(c => c.id === 'AUTH-VERIFY-001'); c.scopeDisposition = 'deferred'; c.maintainerDecisionRequired = true; c.evidence = []; }, 'MISSING_NEGATIVE'],
  ['duplicate claim ID', r => r.claims.push(structuredClone(r.claims[0])), 'DUPLICATE_ID'],
  ['missing spec path', r => r.claims[0].source.path = 'docs/spec/missing.md', 'MISSING_SOURCE'],
  ['missing implementation path', r => r.claims[0].implementation[0].path = 'missing.ts', 'STALE_IMPLEMENTATION'],
  ['missing evidence path', r => r.claims[0].evidence[0].path = 'missing.test.ts', 'STALE_EVIDENCE'],
  ['required negative evidence absent', r => r.claims.find(c => c.id === 'AUTH-VERIFY-001').evidence = [], 'MISSING_NEGATIVE'],
  ['malformed claim', r => delete r.claims[0].title, 'MALFORMED'],
  ['stale test name', r => r.claims[0].evidence[0].selector.id = 'removed test', 'STALE_EVIDENCE'],
  ['stale vector ID', r => r.claims[0].evidence[1].selector.id = 'removed vector', 'STALE_EVIDENCE'],
  ['stale implementation symbol', r => r.claims[0].implementation[0].symbol = 'removedSymbol', 'STALE_IMPLEMENTATION'],
  ['stale source quote', r => r.claims[0].source.quote = 'removed requirement', 'STALE_SOURCE'],
  ['stale source section', r => r.claims[0].source.section = '## Removed', 'STALE_SOURCE'],
  ['required integration absent', r => r.claims[0].requiredLevels.push('INTEGRATION_TESTED'), 'MISSING_REQUIRED_EVIDENCE'],
  ['invalid classification', r => r.claims[0].classification = 'universal-proof', 'MALFORMED'],
  ['inconsistent portable declaration', r => r.claims[0].classification = 'implementation-specific', 'PORTABLE_INCONSISTENT'],
  ['required portable evidence absent', r => r.claims[0].evidence.pop(), 'PORTABLE_INCONSISTENT'],
  ['TypeScript mislabeled cross-runtime', r => r.claims[0].evidence[1].runner.runtime = 'TypeScript', 'PORTABLE_INCONSISTENT'],
  ['unknown schema field', r => r.claims[0].proven = true, 'MALFORMED'],
  ['runner binding removed', r => r.claims[0].evidence[0].runner.contains = 'dist/test/removed.test.js', 'STALE_EVIDENCE'],
  ['path traversal', r => r.claims[0].implementation[0].path = '../escape.ts', 'STALE_IMPLEMENTATION'],
  ['mapped without implementation', r => r.claims[0].implementation = [], 'MISSING_IMPLEMENTATION'],
];

test('current registry passes deterministically without claiming execution', () => {
  const a = verify(fresh()), b = verify(fresh());
  assert.deepEqual(a.issues, []);
  assert.deepEqual(a, b);
  assert.match(report(a), /evidence NOT executed/);
  assert.match(report(a), /structural verification only/);
});

for (const [name, mutate, code] of mutations) {
  test(`${name} -> FAIL, including CLI exit status`, () => {
    const r = fresh(); mutate(r);
    const result = verify(r);
    assert.ok(result.issues.some(i => i.code === code), JSON.stringify(result.issues));
    assert.match(report(result), /RESULT: FAIL/);
    const tmp = mkdtempSync(resolve(tmpdir(), 'oxdeai-claim-selftest-'));
    try {
      const path = resolve(tmp, 'claims.json'); writeFileSync(path, JSON.stringify(r));
      const child = spawnSync(process.execPath, ['scripts/spec-claims/verify.mjs', '--registry', path], { cwd: ROOT, encoding: 'utf8' });
      assert.ifError(child.error);
      assert.equal(child.status, 1, child.stderr);
      assert.match(child.stdout, new RegExp(code));
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });
}

test('malformed types produce diagnostics, never throw', () => {
  for (const key of Object.keys(original.claims[0])) {
    const r = fresh(); r.claims[0][key] = null;
    assert.ok(verify(r).issues.length, key);
  }
  for (const key of ['source', 'implementation', 'evidence']) {
    const r = fresh(); r.claims[0][key] = 42;
    assert.ok(verify(r).issues.length, key);
  }
  for (const field of ['source', 'evidence']) {
    const example = field === 'source' ? original.claims[0].source : original.claims[0].evidence[0];
    for (const key of Object.keys(example)) {
      const r = fresh();
      const target = field === 'source' ? r.claims[0].source : r.claims[0].evidence[0];
      target[key] = null;
      assert.ok(verify(r).issues.length, `${field}.${key}`);
    }
  }
  for (const value of [null, {}, [], { version: 2, claims: 'bad' }, { version: 2, claims: [] }]) assert.ok(verify(value).issues.length);
});

test('comments, mentions, skipped, todo and dynamic tests cannot satisfy a selector', () => {
  assert.deepEqual(testNames(`
    // test("comment", () => {});
    const mention = 'test("mention", () => {})';
    test.skip("skip", () => {});
    test.todo("todo");
    test("options", { skip: true }, () => {});
    test(dynamic, () => {});
    test("active", () => {});
  `, 'fixture.ts'), ['active']);
});

test('removed active test replaced with a comment fails in an isolated repository', () => {
  const tmp = mkdtempSync(resolve(tmpdir(), 'oxdeai-claim-tree-'));
  try {
    const r = { version: 2, claims: [structuredClone(original.claims[0])] };
    for (const ref of [r.claims[0].source, ...r.claims[0].implementation, ...r.claims[0].evidence, ...r.claims[0].evidence.map(e => e.runner)]) {
      const target = resolve(tmp, ref.path); mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, readFileSync(resolve(ROOT, ref.path)));
    }
    assert.deepEqual(verify(r, tmp).issues, []);
    const e = r.claims[0].evidence[0];
    writeFileSync(resolve(tmp, e.path), `// test(${JSON.stringify(e.selector.id)}, () => {});`);
    assert.ok(verify(r, tmp).issues.some(i => i.code === 'STALE_EVIDENCE'));
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});

test('non-required gaps remain visible without changing structural exit semantics', () => {
  const r = { version: 2, claims: fresh().claims.filter(c => c.evidenceState !== 'mapped') };
  const result = verify(r);
  assert.deepEqual(result.issues, []);
  assert.match(report(result), /NO EXECUTABLE MAPPING/);
  assert.match(report(result), /REVIEW DELEGATION-AUDIT-001/);
  // VERIFY-ORDER-001 is mapped (2026-11-22) and must not be filtered in as a gap.
  assert.equal(r.claims.some(c => c.id === 'VERIFY-ORDER-001'), false);
});


test('state dimensions vary independently without upgrading or suppressing evidence', () => {
  const base = { version: 2, claims: [structuredClone(original.claims[0])] };
  const expected = verify(base).rows[0].levels;
  for (const normativeState of ['specified', 'ambiguous', 'unresolved', 'non-normative']) {
    for (const evidenceState of ['mapped', 'gap', 'unassessed']) {
      for (const scopeDisposition of ['in-scope', 'deferred', 'deployment', 'conditional', 'out-of-scope']) {
        const r = structuredClone(base), c = r.claims[0];
        Object.assign(c, { normativeState, evidenceState, scopeDisposition, maintainerDecisionRequired: true });
        c.appliesWhen = scopeDisposition === 'conditional' ? [{ setting: 'review-context', equals: 'configured' }] : [];
        const result = verify(r);
        assert.deepEqual(result.issues, []);
        assert.deepEqual(result.rows[0].levels, expected);
      }
    }
  }
});

test('all three unresolved locks pass with zero executable requirements and remain visible', () => {
  const r = { version: 2, claims: fresh().claims.filter(c => c.recordType === 'corpus-lock') };
  const result = verify(r);
  assert.deepEqual(result.issues, []);
  assert.deepEqual(result.rows.map(c => c.id), ['CANON-ESC-001', 'RT-TRUST-1', 'RT-TRUST-2']);
  for (const c of result.rows) {
    assert.deepEqual(c.levels, []);
    assert.deepEqual(c.requiredLevels, []);
    assert.equal(c.maintainerDecisionRequired, true);
  }
  const output = report(result);
  assert.match(output, /Normative claim records \(curated, not exhaustive\): 0/);
  assert.match(output, /implementation mapped: 0\/0/);
  assert.match(output, /RESULT: PASS/);
  assert.match(output, /NOT evaluated/);
  assert.match(output, /not semantic proof or whole-protocol conformance/);
});

test('dependencies resolve forward and do not inherit proof or failures', () => {
  const r = fresh();
  const result = verify(r);
  assert.deepEqual(result.issues, []);
  const profile = result.rows.find(c => c.id === 'PROFILE-C-001');
  assert.ok(profile.levels.includes('CONFORMANCE_TESTED'));
  assert.deepEqual(result.rows.find(c => c.id === 'RT-TRUST-1').levels, []);
  // Making a maintainer decision does not close the residual or change evidence.
  lock(r).maintainerDecisionRequired = false;
  assert.deepEqual(verify(r).rows.find(c => c.id === 'RT-TRUST-2').levels, []);
});

test('conditional RT-TRUST-2 preserves every documented closure prerequisite', () => {
  assert.deepEqual(lock(original).appliesWhen, [
    { setting: 'krlMode', equals: 'signed_required' },
    { setting: 'verifyKrl', equals: 'configured' },
    { setting: 'KrlWatermarkStore', equals: 'configured' },
    { setting: 'SignedKrlCache', equals: 'configured' },
  ]);
});

test('contextual lock excerpts never suppress normative advisory discovery', () => {
  const without = fresh(); without.claims = without.claims.filter(c => c.recordType === 'requirement');
  assert.equal(advisory(original), advisory(without));
});

test('dependency and applicability metadata reject malformed entries and duplicate edges', () => {
  for (const field of ['dependsOn', 'inferenceGuard', 'appliesWhen']) {
    const r = fresh(); r.claims[0][field] = [null];
    assert.ok(verify(r).issues.some(i => i.code === 'MALFORMED'));
  }
  const r = fresh();
  r.claims[0].dependsOn = [{ id: r.claims[0].id, relation: 'interpretation', reason: 'self' }];
  assert.ok(verify(r).issues.some(i => i.code === 'INVALID_DEPENDENCY'));
  r.claims[0].dependsOn = Array(2).fill({ id: 'RT-TRUST-1', relation: 'trust-premise', reason: 'duplicate' });
  assert.ok(verify(r).issues.some(i => i.code === 'INVALID_DEPENDENCY'));
});

test('a corpus lock can gain evidence without gaining normative authority or obligations', () => {
  const c = structuredClone(lock(original));
  c.evidenceState = 'mapped';
  c.implementation = structuredClone(original.claims[0].implementation);
  c.evidence = [structuredClone(original.claims[0].evidence[0])];
  const result = verify({ version: 2, claims: [c] });
  assert.deepEqual(result.issues, []);
  assert.ok(result.rows[0].levels.includes('TESTED'));
  assert.deepEqual(result.rows[0].requiredLevels, []);
  assert.equal(result.rows[0].normativeState, 'non-normative');
  assert.equal(result.rows[0].maintainerDecisionRequired, true);
  assert.match(report(result), /executable evidence mapped: 0\/0/);
});

test('context records still enforce source drift and conditional schema integrity', () => {
  const c = structuredClone(lock(original));
  c.source.quote = 'removed contextual excerpt';
  assert.ok(verify({ version: 2, claims: [c] }).issues.some(i => i.code === 'STALE_SOURCE'));
  c.source = structuredClone(lock(original).source);
  c.appliesWhen.push(structuredClone(c.appliesWhen[0]));
  assert.ok(verify({ version: 2, claims: [c] }).issues.some(i => i.code === 'MALFORMED'));
});
