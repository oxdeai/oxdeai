import { evidenceScope } from "../../packages/conformance/src/evidenceScope.mjs";
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, realpathSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROOT, AUTHORITY, SECONDARY, check } from './profile-c.mjs';
export const MANIFEST = 'docs/conformance/corpus-authority.json';
export function verifyAuthority(manifest, root = ROOT) {
  assert.equal(manifest.version, 1);
  assert.ok(Array.isArray(manifest.corpora) && manifest.corpora.length);
  const corpora = new Set(), paths = new Set(), result = [];
  const read = path => {
    assert.ok(typeof path === 'string' && !path.startsWith('/') && !path.split('/').includes('..'), `invalid path: ${path}`);
    const abs = realpathSync(resolve(root, path));
    assert.ok(!relative(realpathSync(root), abs).startsWith('..'), 'path escapes repository');
    return readFileSync(abs, 'utf8');
  };
  for (const c of manifest.corpora) {
    assert.ok(typeof c.id === 'string' && c.id && !corpora.has(c.id), `duplicate/missing corpus: ${c.id}`);corpora.add(c.id);
    assert.ok(typeof c.authority === 'string', `${c.id}: exactly one authority required`);
    assert.ok(['normative', 'implementation-specific', 'supplemental'].includes(c.status));
    assert.ok(typeof c.semanticScope === 'string' && c.semanticScope.trim());read(c.spec);
    assert.ok(Array.isArray(c.representations) && c.representations.length);
    assert.equal(c.representations.filter(r => r.path === c.authority && r.generated === false).length, 1, `${c.id}: authority must be a single editable representation`);
    const reps = new Set(), ids = new Map();
    for (const r of c.representations) {
      assert.ok(!paths.has(r.path), `representation assigned to multiple corpora: ${r.path}`);paths.add(r.path);reps.add(r.path);
      assert.ok(typeof r.generated === 'boolean');
      if (r.path !== c.authority) assert.ok(c.id === 'profile-c' && r.path === SECONDARY && r.generated, 'only Profile-C may have a generated secondary');
      const data = JSON.parse(read(r.path));
      assert.ok(['vectors','fixture'].includes(r.format));
      const vectorIds = r.format === 'fixture' ? [data.auth_id] : (Array.isArray(data) ? data : data.vectors).map(v => v.id);
      assert.ok(vectorIds.length && vectorIds.every(id => typeof id === 'string' && id.length));
      assert.equal(new Set(vectorIds).size, vectorIds.length, `${r.path}: duplicate vector IDs`);
      ids.set(r.path, vectorIds);
    }
    if (c.id === 'profile-c') {
      assert.equal(c.authority, AUTHORITY);assert.equal(c.representations.length, 2);
      assert.deepEqual(ids.get(SECONDARY), ids.get(AUTHORITY));
    }
    for (const p of c.supportFiles) read(p);
    assert.ok(c.consumers.length, `${c.id}: consumers required`);
    for (const consumer of c.consumers) {
      assert.ok(reps.has(consumer.representation), `${c.id}: consumer uses undeclared representation`);
      for (const k of ['binding','command','notes']) assert.ok(typeof consumer[k] === 'string' && consumer[k].trim());
      assert.ok(['TypeScript','JavaScript','Go','Python','Rust'].includes(consumer.runtime));
      assert.ok(['default-ci','manual','blocked'].includes(consumer.execution));
      assert.ok(['verifier','driver','input-fixture','maintenance'].includes(consumer.role));
      assert.ok(read(consumer.path).includes(consumer.binding), `${consumer.path}: stale consumer binding ${consumer.binding}`);
    }
    for (const r of c.representations) assert.ok(c.consumers.some(x => x.representation === r.path), `${r.path}: representation has no consumer`);
    result.push({ corpus: c.id, authority: c.authority, ids: ids.get(c.authority), representations: [...reps] });
  }
  assert.ok(corpora.has('profile-c'), 'Profile-C authority missing');
  for (const dir of ['docs/spec/test-vectors','packages/conformance/vectors']) {
    for (const name of readdirSync(resolve(root, dir)).filter(n => n.endsWith('.json'))) assert.ok(paths.has(`${dir}/${name}`), `unregistered release corpus: ${dir}/${name}`);
  }
  return result;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.ok(process.argv.slice(2).every(a => a === '--json'), 'usage: verify-authority.mjs [--json]');
    const manifest = JSON.parse(readFileSync(resolve(ROOT, MANIFEST), 'utf8'));
    const rows = verifyAuthority(manifest);check();
    const scoped = evidenceScope({ kind: 'structural-only', consumer: 'scripts/corpus/verify-authority.mjs', runtime: 'JavaScript' });
    if (process.argv.includes('--json')) console.log(JSON.stringify({ result: 'PASS', scope: 'structural-only', inventory: rows, evidenceScope: scoped }, null, 2));
    else console.log(`Corpus authority: PASS (${rows.length} logical corpora; Profile-C projection exact)`);
    if (!process.argv.includes('--json')) {
      console.log('Authority/reference consistency is not runtime execution proof or whole-protocol conformance.');
      console.log(JSON.stringify({ evidenceScope: scoped }));
    }
  } catch (e) { console.error(`Corpus authority: FAIL: ${e.message}`);process.exitCode = 1; }
}
