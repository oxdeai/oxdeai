// SPDX-License-Identifier: Apache-2.0
// Legacy diagnostic adapter for harnesses without structured result output.
// Package/library and structural JSON reports do not use this compatibility parser.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evidenceScope, repositoryMetadata } from '../../packages/conformance/src/evidenceScope.mjs';
const root = fileURLToPath(new URL('../../', import.meta.url));
const commands = {
  ts: [[process.execPath, ['--import', 'tsx', 'scripts/verify-canonicalization-vectors.ts'], '.', 'scripts/verify-canonicalization-vectors.ts', 'TypeScript']],
  auth: [[process.execPath, ['scripts/verify-authorization-vectors.mjs'], '.', 'scripts/verify-authorization-vectors.mjs', 'JavaScript']],
  pep: [[process.execPath, ['scripts/verify-pep-vectors.mjs'], '.', 'scripts/verify-pep-vectors.mjs', 'JavaScript']],
  delegation: [[process.execPath, ['scripts/verify-delegation-vectors.mjs'], '.', 'scripts/verify-delegation-vectors.mjs', 'JavaScript']],
  go: [['go', ['run', '.'], 'go-harness', 'go-harness/canonicalization_verify.go', 'Go']],
  py: ['canonicalization', 'profile_c', 'signed_krl'].map(name => ['python3', [`python-harness/verify_${name}_vectors.py`], '.', `python-harness/verify_${name}_vectors.py`, 'Python']),
  rust: [['cargo', ['test', '--locked'], 'examples/rust-verifier', 'examples/rust-verifier/tests/verify_authorization.rs', 'Rust']],
};
const [surface, ...args] = process.argv.slice(2);
if (!commands[surface] || args.some(a => a !== '--json')) throw new Error('usage: run.mjs ts|auth|pep|delegation|go|py|rust [--json]');
const metadata = repositoryMetadata(root);
const selections = [], consumers = [], statuses = [];
let status = 0;
for (const [bin, argv, cwd, path, runtime] of commands[surface]) {
  const result = spawnSync(bin, argv, { cwd: resolve(root, cwd), encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  const stdout = result.stdout ?? '';
  if (args.includes('--json')) process.stderr.write(stdout);
  else process.stdout.write(stdout);
  process.stderr.write(result.stderr ?? '');
  if (result.error) console.error(result.error.message);
  status = result.error ? 1 : (result.status ?? 1);
  statuses.push({ consumer: path, runtime, exitCode: status });
  // Go's entrypoint calls all three verifier functions. Match each registered
  // source separately: a Go PASS must not match the Python registry mapping.
  const paths = surface === 'go' ? [path, 'go-harness/profile_c_verify.go', 'go-harness/signed_krl_verify.go'] : [path];
  consumers.push(...paths.map(path => ({ path, runtime })));
  const bindings = metadata.manifest.corpora.flatMap(c => c.consumers.filter(x => paths.includes(x.path) && x.runtime === runtime && x.role === 'verifier'));
  const knownIds = new Set(bindings.flatMap(b => Object.keys(metadata.representations[b.representation].cases)));
  const observations = new Map();
  let recognized = true;
  for (const line of (stdout + '\n' + (result.stderr ?? '')).split(/\r?\n/)) {
    if (!/^(PASS|FAIL)\b/.test(line)) continue; // ordinary diagnostic prose
    const match = /^(PASS|FAIL) ([^ :]+)(.*)$/.exec(line);
    if (!match || !knownIds.has(match[2]) || observations.has(match[2]) ||
        (match[1] === 'PASS' ? match[3] !== '' : !/^[: ]/.test(match[3]))) {
      recognized = false; // malformed, unknown, duplicate or contradictory result
      continue;
    }
    observations.set(match[2], match[1]);
  }
  // A zero exit status alone is never evidence coverage. Require a complete,
  // unambiguous result set; preserve the native exit code even if scope is empty.
  const complete = recognized && status === 0 && [...knownIds].every(id => observations.has(id));
  for (const c of metadata.manifest.corpora) {
    for (const binding of c.consumers.filter(x => paths.includes(x.path) && x.runtime === runtime && x.role === 'verifier')) {
      const data = JSON.parse(readFileSync(resolve(root, binding.representation), 'utf8'));
      const ids = Object.keys(metadata.representations[binding.representation].cases);
      const passedCaseIds = complete ? ids.filter(id => observations.get(id) === 'PASS') : [];
      const caseIds = ids.filter(id => observations.has(id));
      if (surface === 'rust' && /^test allow_at_last_valid_second \.\.\. (ok|FAILED)$/m.test(stdout)) {
        caseIds.push(...ids);
        if (status === 0) passedCaseIds.push(...ids);
      }
      if (caseIds.length) selections.push({ representation: binding.representation, data, consumer: binding.path, runtime, caseIds, passedCaseIds });
    }
  }
  // Preserve the existing chained Python command's short-circuit on failure.
  if (status !== 0) break;
}
const scope = evidenceScope({ metadata, selections });
scope.consumers = consumers.sort((a, b) => a.path.localeCompare(b.path, 'en'));
console.log(JSON.stringify({ result: status === 0 ? 'PASS' : 'FAIL', executions: statuses, evidenceScope: scope }));
process.exitCode = status;
