// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, copyFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { evidenceScope, loadEvidenceMetadata } from './evidenceScope.mjs';
import { runTrustedTimeConformance, trustedTimeExitCode } from './trustedTimeConformance.js';
const metadata = loadEvidenceMetadata();
const root = fileURLToPath(new URL('../../../../', import.meta.url));
const data = JSON.parse(readFileSync(new URL('../../vectors/authorization-verification.json', import.meta.url), 'utf8'));
const selection = { representation: 'packages/conformance/vectors/authorization-verification.json', consumer: 'packages/conformance/src/validate.ts', runtime: 'TypeScript', data, caseIds: ['authorization-verify-004'], passedCaseIds: ['authorization-verify-004'] };
const scope = (m = metadata, s = selection) => evidenceScope({ metadata: m, selections: [s] });

test('scope explicitly covers only an executed registry mapping and includes its support boundary', () => {
  const result = scope();
  assert.deepEqual(result.coveredClaims.map(c => c.id), ['AUTH-ARTIFACT-001']);
  assert.equal(result.coveredClaims[0]!.evidence[0]!.caseId, 'authorization-verify-004');
  assert.match(result.coveredClaims[0]!.evidence[0]!.supports, /Non-ALLOW/);
  assert.deepEqual(result.excludedClaims, metadata.registry.claims.map((c: any) => c.id).filter((id: string) => id !== 'AUTH-ARTIFACT-001').sort());
});

test('new unmapped claim and removed mapping are mechanically excluded', () => {
  const m = structuredClone(metadata);
  m.registry.claims.push({ ...m.registry.claims[0], id: 'SYNTHETIC-001', evidence: [] });
  m.registry.claims.find((c: any) => c.id === 'AUTH-ARTIFACT-001').evidence = [];
  assert.equal(scope(m).coveredClaims.length, 0);
  assert.ok(scope(m).excludedClaims.includes('SYNTHETIC-001'));
  assert.ok(scope(m).excludedClaims.includes('AUTH-ARTIFACT-001'));
});

test('changed expected values, wrong runtime, missing cases and failed cases cannot cover claims', () => {
  const changed = structuredClone(selection);
  changed.data.vectors.find((v: any) => v.id === 'authorization-verify-004').expected.status = 'ok';
  for (const s of [changed, { ...selection, runtime: 'Go' }, { ...selection, consumer: 'other.ts' }, { ...selection, caseIds: [] }, { ...selection, passedCaseIds: [] }, { ...selection, data: { ...data, changedContext: true } }]) {
    assert.equal(scope(metadata, s).coveredClaims.length, 0);
  }
});

test('ambiguous, conditional and deployment claims fail closed even with matching evidence', () => {
  for (const patch of [{ normativeState: 'ambiguous' }, { scopeDisposition: 'deployment' }, { scopeDisposition: 'conditional' }, { evidenceState: 'gap' }]) {
    const m = structuredClone(metadata);
    Object.assign(m.registry.claims.find((c: any) => c.id === 'AUTH-ARTIFACT-001'), patch);
    assert.equal(scope(m).coveredClaims.length, 0);
  }
});

test('registry, evidence and case ordering do not affect serialized scope', () => {
  const m = structuredClone(metadata);
  m.registry.claims.reverse();
  for (const c of m.registry.claims) c.evidence.reverse();
  const s = { ...selection, caseIds: ['authorization-verify-004', 'authorization-verify-002'], passedCaseIds: ['authorization-verify-004', 'authorization-verify-002'] };
  const reversed = { ...s, caseIds: [...s.caseIds].reverse(), passedCaseIds: [...s.passedCaseIds].reverse() };
  assert.equal(JSON.stringify(scope(metadata, s)), JSON.stringify(scope(m, reversed)));
});

test('structural PASS has no executed corpora or covered claims', () => {
  const result = evidenceScope({ kind: 'structural-only', metadata });
  assert.deepEqual(result.coveredClaims, []);
  assert.deepEqual(result.corpora, []);
  assert.equal(result.excludedClaims.length, metadata.registry.claims.length);
});

test('#325 reference-generated and mixed provenance never imply independent normative authority', () => {
  assert.equal(scope().corpusProvenance[0]!.classification, 'reference-generated');
  const canonical = JSON.parse(readFileSync(root + 'docs/spec/test-vectors/canonicalization-v1.json', 'utf8'));
  const result = evidenceScope({ metadata, selections: [{ representation: 'docs/spec/test-vectors/canonicalization-v1.json', data: canonical, consumer: 'python-harness/verify_canonicalization_vectors.py', runtime: 'Python', caseIds: ['i1-float-rejected'], passedCaseIds: ['i1-float-rejected'] }] });
  const p = result.corpusProvenance[0]!;
  assert.equal(p.classification, 'mixed');
  assert.deepEqual(p.specDerived?.map(x => x.field), ['status', 'status', 'status']);
  assert.equal(p.remainder, 'reference-generated');
  assert.ok(result.limitations.some(x => x.includes('no demonstrated independent normative authority')));
});

test('trusted-time returned PASS and FAIL retain semantics and explicit scope for caller-supplied data', () => {
  const raw = JSON.parse(readFileSync(new URL('../../vectors/trusted-time.json', import.meta.url), 'utf8'));
  const passing = runTrustedTimeConformance(raw, () => {});
  assert.equal(trustedTimeExitCode(passing), 0);
  assert.equal(passing.passed, 44);
  assert.equal(passing.evidenceScope.corpora[0]!.registeredContent, true);
  assert.deepEqual(passing.evidenceScope.coveredClaims, []); // registry maps Core tests, not this runner
  raw.vectors.find((v: any) => v.id === 'tt-neg-001').expected = { decision: 'ALLOW', reasons: [] };
  const failing = runTrustedTimeConformance(raw, () => {});
  assert.equal(trustedTimeExitCode(failing), 1);
  assert.equal(failing.failed, 1);
  assert.equal(failing.evidenceScope.corpora[0]!.registeredContent, false);
  assert.ok(!failing.evidenceScope.corpora[0]!.passedCaseIds.includes('tt-neg-001'));
});

test('package CLI emits a JSON PASS with explicit scope and unchanged assertion results', () => {
  const run = spawnSync(process.execPath, [fileURLToPath(new URL('./validate.js', import.meta.url)), '--json'], { encoding: 'utf8' });
  assert.ifError(run.error);
  assert.equal(run.status, 0, run.stderr);
  const report = JSON.parse(run.stdout);
  assert.equal(report.result, 'PASS');
  assert.ok(report.passed > 0);
  assert.equal(report.evidenceScope.corpora.length, 18);
  assert.ok(report.evidenceScope.coveredClaims.some((c: any) => c.id === 'AUTH-ARTIFACT-001'));
  assert.ok(report.evidenceScope.excludedClaims.includes('PEP-DEPLOY-001'));
  assert.ok(report.evidenceScope.excludedClaims.includes('AUTH-BIND-001'));
});


test('installed scope builder uses its bundled registry without a checkout', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oxdeai-scope-'));
  try {
    mkdirSync(join(dir, 'src'));
    copyFileSync(new URL('./evidenceScope.mjs', import.meta.url), join(dir, 'src/evidenceScope.mjs'));
    writeFileSync(join(dir, 'evidence-metadata.json'), JSON.stringify(metadata));
    const installed = await import(pathToFileURL(join(dir, 'src/evidenceScope.mjs')).href);
    const result = installed.evidenceScope();
    assert.deepEqual(result.source, metadata.source);
    assert.equal(result.excludedClaims.length, metadata.registry.claims.length);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('legacy report wrapper preserves failing child exit and excludes unexecuted claims', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oxdeai-runner-'));
  try {
    writeFileSync(join(dir, 'go'), '#!/bin/sh\nexit 7\n', { mode: 0o755 });
    const run = spawnSync(process.execPath, [root + 'scripts/conformance/run.mjs', 'go', '--json'], {
      encoding: 'utf8', env: { ...process.env, PATH: dir },
    });
    assert.ifError(run.error);
    assert.equal(run.status, 7, run.stderr);
    const report = JSON.parse(run.stdout);
    assert.equal(report.result, 'FAIL');
    assert.deepEqual(report.evidenceScope.corpora, []);
    assert.deepEqual(report.evidenceScope.coveredClaims, []);
    assert.equal(report.evidenceScope.excludedClaims.length, metadata.registry.claims.length);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});


test('legacy malformed, missing and contradictory diagnostics cannot grant coverage on exit zero', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oxdeai-diagnostic-'));
  const ids = Object.keys(metadata.representations['docs/spec/test-vectors/canonicalization-v1.json'].cases);
  const valid = ids.map(id => `PASS ${id}`).join('\n');
  try {
    for (const output of ['', 'All checks passed', 'PASS v1-object-key-ordering extra', 'PASS v1-object-key-ordering',
      valid + '\nPASS unregistered-case', valid + '\nFAIL v1-object-key-ordering: contradiction']) {
      // The Python surface has actual registry mappings, so this checks coverage
      // denial rather than relying on an already-unmapped runtime such as Go.
      writeFileSync(join(dir, 'python3'), `#!/bin/sh\nwhile IFS= read -r line; do printf '%s\n' "$line"; done <<'DIAGNOSTICS'\n${output}\nDIAGNOSTICS\nexit 0\n`, { mode: 0o755 });
      const run = spawnSync(process.execPath, [root + 'scripts/conformance/run.mjs', 'py', '--json'], {
        encoding: 'utf8', env: { ...process.env, PATH: dir },
      });
      assert.ifError(run.error);
      assert.equal(run.status, 0, run.stderr);
      const report = JSON.parse(run.stdout);
      assert.equal(report.result, 'PASS'); // native exit semantics are unchanged
      assert.deepEqual(report.evidenceScope.coveredClaims, [], output);
      assert.equal(report.evidenceScope.excludedClaims.length, metadata.registry.claims.length);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
