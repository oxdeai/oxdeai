// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REGISTRY = 'docs/verification/spec-claims/claims.json';
export const AUTHORITY = 'docs/conformance/corpus-authority.json';
export const AUDIT = 'docs/conformance/corpus-provenance-audit.md';
const sort = xs => [...new Set(xs)].sort();
const canonical = x => Array.isArray(x) ? x.map(canonical) : x && typeof x === 'object'
  ? Object.fromEntries(Object.keys(x).sort().map(k => [k, canonical(x[k])])) : x;
export const digest = x => createHash('sha256').update(typeof x === 'string' || Buffer.isBuffer(x) ? x : JSON.stringify(canonical(x))).digest('hex');
const vectors = data => Array.isArray(data) ? data : data.vectors ?? [{ ...data, id: data.auth_id }];

// Snapshot registry and provenance source, not generated expectations. Used live in
// the repository and bundled at package build time for installations without .git.
export function repositoryMetadata(root) {
  const read = p => readFileSync(resolve(root, p), 'utf8');
  const registryText = read(REGISTRY), manifestText = read(AUTHORITY), audit = read(AUDIT);
  const registry = JSON.parse(registryText), manifest = JSON.parse(manifestText);
  const artifacts = { [REGISTRY]: digest(registryText), [AUTHORITY]: digest(manifestText), [AUDIT]: digest(audit) };
  const representations = {};
  const provenance = {};
  for (const c of manifest.corpora) {
    const row = audit.split('\n').find(line => line.startsWith(`| [${c.id}](`));
    const classification = row?.split(' | ')[4];
    // No automatic promotion when future audit prose or inventory changes.
    provenance[c.id] = classification?.startsWith('Mixed: spec-derived') && c.id === 'docs-canonicalization-v1'
      ? 'mixed' : 'reference-generated';
    for (const r of c.representations) {
      const text = read(r.path), data = JSON.parse(text);
      artifacts[r.path] = digest(text);
      representations[r.path] = { digest: digest(data), cases: Object.fromEntries(vectors(data).map(v => [v.id, digest(v)])) };
    }
    for (const p of [c.spec, ...c.supportFiles, ...c.consumers.map(x => x.path)]) artifacts[p] = digest(read(p));
  }
  let revision = null, workingTreeDirty = null;
  try { revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    workingTreeDirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=normal'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim().length > 0;
  } catch { /* artifact hashes still identify inputs */ }
  return { registry, manifest, provenance, representations, source: { revision, workingTreeDirty, artifacts: canonical(artifacts) } };
}

export function loadEvidenceMetadata() {
  // Use current metadata in this checkout, and the build snapshot when installed.
  // Never use an unrelated enclosing checkout for an installed package.
  const here = dirname(fileURLToPath(import.meta.url));
  const bundled = resolve(here, '../evidence-metadata.json');
  for (let root = here; dirname(root) !== root; root = dirname(root)) {
    const ownSource = resolve(root, 'packages/conformance/src');
    const ownBuild = resolve(root, 'packages/conformance/dist/src');
    if ((here === ownSource || here === ownBuild) && existsSync(resolve(root, REGISTRY)) && existsSync(resolve(root, AUTHORITY))) return repositoryMetadata(root);
  }
  if (existsSync(bundled)) return JSON.parse(readFileSync(bundled, 'utf8'));
  throw new Error('Evidence registry unavailable; build the conformance package before reporting results');
}

/**
 * @param {{kind?: string, selections?: any[], metadata?: any, consumer?: string, runtime?: string}} options
 * Each selection is supplied by a runner after execution, never by an issuer's
 * claimed assurance level. Failed/pending cases cannot support coveredClaims.
 */
export function evidenceScope({ kind = 'execution', selections = [], metadata = loadEvidenceMetadata(), consumer = '', runtime = '' } = {}) {
  const corpora = [];
  for (const s of selections) {
    const c = metadata.manifest.corpora.find(c => c.representations.some(r => r.path === s.representation));
    if (!c) throw new Error(`Unregistered corpus representation: ${s.representation}`);
    const binding = c.consumers.find(x => x.path === s.consumer && x.runtime === s.runtime && x.representation === s.representation && x.role === 'verifier' && x.execution !== 'blocked');
    const known = metadata.representations[s.representation];
    const actual = new Map(vectors(s.data).map(v => [v.id, digest(v)]));
    const caseIds = sort(s.caseIds ?? []);
    const passedCaseIds = sort(s.passedCaseIds ?? []).filter(id => caseIds.includes(id));
    const matchedCaseIds = passedCaseIds.filter(id => binding && known?.digest === digest(s.data) && known?.cases[id] === actual.get(id) && actual.has(id));
    corpora.push({ id: c.id, representation: s.representation, consumer: s.consumer, runtime: s.runtime,
      sha256: digest(s.data), registeredContent: known?.digest === digest(s.data), caseIds, passedCaseIds, matchedCaseIds });
  }
  corpora.sort((a, b) => JSON.stringify([a.id, a.consumer, a.runtime]).localeCompare(JSON.stringify([b.id, b.consumer, b.runtime]), 'en'));
  const coveredClaims = [];
  for (const claim of metadata.registry.claims) {
    if (kind !== 'execution' || claim.recordType !== 'requirement' || claim.normativeState !== 'specified' || claim.evidenceState !== 'mapped' || claim.scopeDisposition !== 'in-scope' || claim.appliesWhen?.length || claim.maintainerDecisionRequired) continue;
    const evidence = [];
    for (const ref of claim.evidence ?? []) {
      if (ref.selector?.type !== 'vector' || !['vector', 'cross-runtime'].includes(ref.kind)) continue;
      for (const c of corpora) {
        if (ref.path === c.representation && ref.runner?.path === c.consumer && ref.runner?.runtime === c.runtime && c.matchedCaseIds.includes(ref.selector.id)) {
          evidence.push({ corpus: c.id, representation: c.representation, caseId: ref.selector.id, consumer: c.consumer, runtime: c.runtime, supports: ref.supports });
        }
      }
    }
    if (evidence.length) coveredClaims.push({ id: claim.id, evidence: evidence.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), 'en')) });
  }
  coveredClaims.sort((a, b) => a.id.localeCompare(b.id, 'en'));
  const covered = new Set(coveredClaims.map(c => c.id));
  const excludedClaims = sort(metadata.registry.claims.map(c => c.id)).filter(id => !covered.has(id));
  const corpusProvenance = sort(corpora.map(c => c.id)).map(id => ({
    corpus: id, classification: metadata.provenance[id] ?? 'reference-generated',
    ...(metadata.provenance[id] === 'mixed' ? {
      specDerived: ['i1-float-rejected', 'i3-string-timestamp-rejected', 'i4-float-timestamp-rejected'].map(caseId => ({ caseId, field: 'status', value: 'error' })),
      remainder: 'reference-generated',
    } : {}),
  }));
  return {
    version: 1, kind,
    consumers: canonical([...new Map([...corpora.map(c => ({ path: c.consumer, runtime: c.runtime })), ...(consumer ? [{ path: consumer, runtime }] : [])].map(c => [JSON.stringify(c), c])).values()].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), 'en'))),
    corpora, coveredClaims, excludedClaims, corpusProvenance,
    assumptions: ['The runner and its local execution record are trusted; this is unsigned evidence.', 'Registry mappings describe selected evidence, not exhaustive claim obligations.', 'Inputs and runner files remain unchanged during execution.'],
    limitations: [
      'PASS applies only to the declared surface and cases; excluded claims are not proven.',
      'Covered claims mean only the listed supports statements, not all evidence levels or the entire claim.',
      'Structural validation is not semantic proof; signatures do not establish truth or trusted premises.',
      'Independent consumption and cross-language agreement do not establish independent expectation derivation.',
      'Reference-generated expectations have no demonstrated independent normative authority.',
      'Artifact verification does not prove non-bypassable enforcement, deployment properties or later execution stages.',
      'Applicability conditions and deployment premises are not evaluated; no assurance class is inferred.',
      'Corpus digests identify parsed JSON; source artifact digests identify exact recorded file bytes.',
    ],
    source: metadata.source,
  };
}
