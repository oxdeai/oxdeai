#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// S_freeze gate (#254).
//
// Answers ONE question from recorded evidence:
//
//   Can an independent third party start from the supplied OxDeAI 2.0
//   release-candidate artifacts, identify exactly what is normative,
//   reproduce the claimed conformance result for the frozen SHA, and attempt
//   to falsify the security boundary using criteria declared before review?
//
// It is NOT a security audit, NOT the publication step, and a PASS here is NOT
// a claim of whole-protocol conformance or of non-bypassable deployment
// enforcement. It reports whether declared, recorded evidence is internally
// sufficient within scope; unresolved blockers remain blocking.
//
// Declared blockers and blocking diagnostics are separate. Both prevent PASS.
// Diagnostic classes preserve evidence failure detail:
//
//   claim              release-blocking spec-claim state
//   maintainer-decision claim the registry says a human must rule on
//   corpus             conformance-authority defect
//   artifact           RC artifact / external-consumability defect
//   provenance         source identity / reproduction traceability defect
//   criterion          predeclared falsification criterion failed or unevaluated
//   finding            freeze finding whose evidence state is insufficient
//   residual           residual review-scope item without explicit treatment
//
// Deliberately NOT encoded: "all gap/unassessed claims block". That is wrong.
// What is encoded is "all RELEASE-BLOCKING unresolved claims block", where
// release-blocking derives from declared freeze scope and unresolved exits. See resolveClaimBlockers().

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { evidenceScope, digest, AUDIT } from '../../packages/conformance/src/evidenceScope.mjs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
export const CRITERIA = 'docs/release/s-freeze/criteria.json';
export const REGISTRY = 'docs/verification/spec-claims/claims.json';
export const CORPUS_MANIFEST = 'docs/conformance/corpus-authority.json';

/** Freeze-finding evidence states. Deliberately DISTINCT from the spec-claims
 *  registry `evidenceState` vocabulary (mapped/gap/unassessed): a registry
 *  evidenceState describes whether a normative claim has mapped evidence; a
 *  finding state describes how far a specific freeze finding has been driven.
 *  They are modelled separately and never coerced into one another. */
export const FINDING_STATES = ['REPORTED', 'REPRODUCED', 'FIXED_AND_RETESTED', 'DEFERRED_WITH_RATIONALE'];

/** Scope dispositions that place a claim inside the declared 2.0 freeze boundary. */
const IN_FREEZE_SCOPE = new Set(['in-scope']);
/** Scope dispositions that require an explicitly asserted condition to be in scope. */
const CONDITIONAL_SCOPE = new Set(['conditional']);
// Existing scope semantics (tests 5, 6, 6b, 7, 8); no implicit fallback state.
const VALID_SCOPE = new Set([...IN_FREEZE_SCOPE, ...CONDITIONAL_SCOPE, 'deferred', 'deployment', 'out-of-scope']);

/** Decisions that count as an explicit, reviewed freeze disposition. */
const ACCEPTED_DECISIONS = new Set(['fixed-before-freeze', 'included-in-review-scope', 'deferred-with-rationale']);

// Freeze provenance only: resolved major.minor.patch, optionally prefixed by
// Node's 'v' and/or carrying an exact prerelease/build suffix. Not TOOL-001 policy.
const EXACT_VERSION_RE = /^v?(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

const SHA_RE = /^[0-9a-f]{40}$/;
const INTEGRITY_RE = /^(sha512-[A-Za-z0-9+/]+={0,2}|sha256:[0-9a-f]{64})$/;

const text = (v) => typeof v === 'string' && v.trim().length > 0;
const blocker = (id, cls, reason, evidence) => ({ id, class: cls, reason, evidence: evidence ?? null });

/**
 * A complete review disposition; it does not remove a blocker. Every field
 * below is required, and a disposition that fails any check is treated as
 * absent rather than as a weaker acceptance.
 */
export function acceptedDisposition(candidate, claimId) {
  const d = (candidate.freezeDispositions ?? []).find((x) => x?.claimId === claimId);
  if (!d) return null;
  if (!ACCEPTED_DECISIONS.has(d.decision)) return null;
  if (!text(d.rationale) || !text(d.boundedClaim) || !text(d.decidedBy) || !text(d.decidedAt)) return null;
  return d;
}

/** True/false for known scope states; null is invalid, never out-of-scope. */
export function inFreezeScope(claim, candidate) {
  const disp = claim.scopeDisposition;
  if (!VALID_SCOPE.has(disp)) return null;
  if (IN_FREEZE_SCOPE.has(disp)) return true;
  if (!CONDITIONAL_SCOPE.has(disp)) return false;
  // A conditional claim is in scope only when the candidate explicitly asserts
  // that its condition applies. Silence means "condition not asserted", which
  // keeps a conditional claim out of scope rather than guessing either way.
  const asserted = new Set(candidate.conditionsAsserted ?? []);
  return asserted.has(claim.id);
}

function resolveScopeDiagnostics(registry) {
  return (registry.claims ?? []).filter(claim => !VALID_SCOPE.has(claim.scopeDisposition)).map(claim =>
    blocker(`CLAIM-SCOPE-${claim.id}`, 'claim',
      'missing, malformed or unknown scopeDisposition; cannot infer out-of-scope',
      `${REGISTRY}#${claim.id}.scopeDisposition`));
}

/** Registry gaps and required maintainer decisions remain blocking. Candidate
 * dispositions cannot override the registry or stand in for direct evidence. */
export function resolveClaimBlockers(registry, candidate) {
  const out = [];
  for (const claim of registry.claims ?? []) {
    // A disposition records review posture, never repairs unresolved evidence.
    const scoped = inFreezeScope(claim, candidate);

    if (claim.maintainerDecisionRequired === true) {
      out.push(blocker(claim.id, 'maintainer-decision',
        `maintainerDecisionRequired=true; a disposition cannot resolve the normative/evidence question (scopeDisposition=${claim.scopeDisposition})`,
        `${REGISTRY}#${claim.id}`));
      continue;
    }
    if (!scoped) continue;
    if (!['specified', 'non-normative'].includes(claim.normativeState) || claim.evidenceState !== 'mapped') {
      out.push(blocker(claim.id, 'claim',
        `evidenceState=${claim.evidenceState} for release-blocking ${claim.scopeDisposition} claim`,
        `${REGISTRY}#${claim.id}`));
    }
  }
  return out;
}

/** Source identity and reproduction traceability. */
export function resolveProvenanceBlockers(candidate) {
  const out = [];
  const src = candidate.source ?? {};
  if (!SHA_RE.test(src.sha ?? '')) out.push(blocker('SOURCE-SHA', 'provenance', 'missing or malformed exact 40-hex Git SHA', 'candidate.source.sha'));
  if (src.cleanWorktree !== true) out.push(blocker('SOURCE-CLEAN', 'provenance', 'freeze record does not assert a clean worktree', 'candidate.source.cleanWorktree'));
  if (!src.toolchain || typeof src.toolchain !== 'object' || Array.isArray(src.toolchain) ||
      Object.keys(src.toolchain).length === 0 ||
      Object.values(src.toolchain).some(version => typeof version !== 'string' || !EXACT_VERSION_RE.test(version))) {
    out.push(blocker('SOURCE-TOOLCHAIN', 'provenance', 'toolchain must record resolved exact versions; missing, partial, ranged or wildcard versions are not freeze provenance', 'candidate.source.toolchain'));
  }
  if (!src.packageVersions || Object.keys(src.packageVersions).length === 0) out.push(blocker('SOURCE-PKGVER', 'provenance', 'no package versions recorded', 'candidate.source.packageVersions'));

  const repro = candidate.reproduction ?? {};
  for (const k of ['cleanEnvironment', 'externalInstall', 'publicInterface', 'corpusExecution', 'resultVerification']) {
    if (!Array.isArray(repro[k]) || repro[k].length === 0) out.push(blocker(`REPRO-STEP-${k}`, 'provenance', `reproduction.${k} is missing or empty`, 'candidate.reproduction'));
  }
  // A reproduction step that reaches back into the monorepo is not an external
  // reproduction, regardless of whether it happens to succeed here.
  const steps = Object.values(repro).flatMap((v) => (Array.isArray(v) ? v : []));
  for (const step of steps) {
    if (typeof step === 'string' && /(^|\s)(\.\.\/|\.\/packages\/|packages\/|pnpm -C |--filter )/.test(step)) {
      out.push(blocker('REPRO-MONOREPO', 'artifact', 'reproduction step uses a monorepo-relative path or workspace filter', step));
    }
  }

  const results = candidate.results ?? [];
  if (results.length === 0) out.push(blocker('RESULTS-EMPTY', 'provenance', 'no recorded results', 'candidate.results'));
  for (const [i, r] of results.entries()) {
    const ref = `candidate.results[${i}]`;
    if (!text(r?.command)) out.push(blocker(`RESULT-${i}-CMD`, 'provenance', 'result has no command', ref));
    if (r?.result !== 'PASS') out.push(blocker(`RESULT-${i}-OUTCOME`, 'provenance', 'result must be PASS', ref));
    if (r?.sha !== src.sha) out.push(blocker(`RESULT-${i}-SHA`, 'provenance', 'result is not tied to the frozen source SHA', ref));
    if (!Array.isArray(r?.artifacts) || r.artifacts.length === 0) out.push(blocker(`RESULT-${i}-ARTIFACTS`, 'provenance', 'result is not tied to any RC artifact identity', ref));
  }
  return out;
}

/** RC artifact bundle and external consumability. */
export function resolveArtifactBlockers(candidate) {
  const out = [];
  const arts = candidate.rcArtifacts ?? [];
  if (arts.length === 0) return [blocker('RC-EMPTY', 'artifact', 'no release-candidate artifacts recorded', 'candidate.rcArtifacts')];
  const names = new Set(arts.map((a) => a?.package));
  for (const [i, a] of arts.entries()) {
    const ref = `candidate.rcArtifacts[${i}]`;
    const id = a?.package ?? `#${i}`;
    if (!text(a?.package)) out.push(blocker(`RC-${i}-NAME`, 'artifact', 'artifact has no package name', ref));
    if (!text(a?.version)) out.push(blocker(`RC-${id}-VERSION`, 'artifact', 'artifact has no version', ref));
    if (!text(a?.tarball)) out.push(blocker(`RC-${id}-TARBALL`, 'artifact', 'artifact has no tarball filename', ref));
    if (!INTEGRITY_RE.test(a?.integrity ?? '')) out.push(blocker(`RC-${id}-INTEGRITY`, 'artifact', 'artifact has no usable integrity/hash value', ref));
    if (!text(a?.buildCommand)) out.push(blocker(`RC-${id}-BUILD`, 'artifact', 'artifact has no recorded build command', ref));
    // Every internal dependency must itself be supplied in the bundle, or the
    // reviewer cannot install the artifact without unpublished registry state.
    for (const dep of a?.dependsOn ?? []) {
      if (!names.has(dep)) out.push(blocker(`RC-${id}-DEP`, 'artifact', `depends on ${dep}, which is not supplied in the RC bundle`, ref));
    }
  }
  return out;
}

/** Conformance authority, evaluated against the #290 manifest. */
export function resolveCorpusBlockers(candidate, manifest) {
  const out = [];
  const declared = candidate.conformanceAuthority ?? {};
  const relevant = declared.releaseRelevantCorpora ?? [];
  if (relevant.length === 0) return [blocker('CORPUS-NONE', 'corpus', 'candidate declares no release-relevant corpora', 'candidate.conformanceAuthority')];

  const byId = new Map((manifest.corpora ?? []).map((c) => [c.id, c]));
  for (const entry of relevant) {
    const id = typeof entry === 'string' ? entry : entry?.id;
    const c = byId.get(id);
    if (!c) { out.push(blocker(`CORPUS-${id}`, 'corpus', 'declared release-relevant corpus is absent from the authority manifest', CORPUS_MANIFEST)); continue; }
    // Exactly one editable authoritative representation.
    const editable = (c.representations ?? []).filter((r) => r.generated === false);
    if (editable.length !== 1) out.push(blocker(`CORPUS-${id}-AUTHORITY`, 'corpus', `expected exactly one independently editable authoritative representation, found ${editable.length}`, CORPUS_MANIFEST));
    else if (editable[0].path !== c.authority) out.push(blocker(`CORPUS-${id}-AUTHORITY`, 'corpus', 'declared authority is not the editable representation', CORPUS_MANIFEST));
    if (!text(c.semanticScope)) out.push(blocker(`CORPUS-${id}-SCOPE`, 'corpus', 'corpus has no semantic purpose, so a claim cannot be mapped to it', CORPUS_MANIFEST));
    if (!(c.consumers ?? []).length) out.push(blocker(`CORPUS-${id}-CONSUMERS`, 'corpus', 'corpus has no declared consumer', CORPUS_MANIFEST));
    // A generated secondary must declare the projection that produces it.
    for (const r of c.representations ?? []) {
      if (r.generated === true && !text(r.projectionSource ?? c.authority)) {
        out.push(blocker(`CORPUS-${id}-PROJECTION`, 'corpus', 'generated representation declares no projection source', CORPUS_MANIFEST));
      }
    }
    // A claimed runtime must be backed by a consumer that actually executes.
    const claimedRuntimes = (typeof entry === 'object' && Array.isArray(entry.claimedRuntimes)) ? entry.claimedRuntimes : [];
    const executing = new Set((c.consumers ?? []).filter((x) => x.execution !== 'blocked').map((x) => x.runtime));
    for (const rt of claimedRuntimes) {
      if (!executing.has(rt)) out.push(blocker(`CORPUS-${id}-RUNTIME-${rt}`, 'corpus', `claimed runtime coverage ${rt} has no executing consumer (blocked or absent)`, CORPUS_MANIFEST));
    }
  }
  if (declared.projectionVerified !== true) out.push(blocker('CORPUS-PROJECTION', 'corpus', 'deterministic Profile-C projection evidence is not recorded as verified', 'candidate.conformanceAuthority.projectionVerified'));
  return out;
}

/** Predeclared falsification criteria. */
export function resolveCriterionBlockers(candidate, criteria) {
  const out = [];
  const evals = new Map((candidate.criteriaEvaluations ?? []).map((e) => [e?.criterionId, e]));
  for (const c of criteria.criteria ?? []) {
    const e = evals.get(c.id);
    if (!c.mandatory) {
      // A non-mandatory criterion never silently becomes mandatory; a failure
      // is surfaced as advisory only.
      continue;
    }
    if (!e) { out.push(blocker(c.id, 'criterion', 'mandatory criterion NOT_EVALUATED at freeze time', CRITERIA)); continue; }
    if (e.state === 'FAIL') { out.push(blocker(c.id, 'criterion', `mandatory criterion FAILED: ${c.statement}`, e.evidence ?? CRITERIA)); continue; }
    if (e.state !== 'PASS') out.push(blocker(c.id, 'criterion', `mandatory criterion state=${e.state ?? 'NOT_EVALUATED'} (must be PASS)`, e.evidence ?? CRITERIA));
  }
  return out;
}

/** Freeze findings: state discipline. */
export function resolveFindingBlockers(candidate) {
  const out = [];
  for (const [i, f] of (candidate.findings ?? []).entries()) {
    const ref = `candidate.findings[${i}]`;
    const id = f?.id ?? `#${i}`;
    if (!FINDING_STATES.includes(f?.state)) { out.push(blocker(id, 'finding', `invalid or missing finding state (expected one of ${FINDING_STATES.join('|')})`, ref)); continue; }
    // REPORTED is not REPRODUCED: an unreproduced finding cannot be discharged.
    if (f.state === 'REPORTED') out.push(blocker(id, 'finding', 'finding is REPORTED and has not been reproduced against a recorded revision', ref));
    // Code change alone is not a fix: the original failure case must be rerun.
    if (f.state === 'FIXED_AND_RETESTED' && !(text(f.retestCommand) && f.retestResult === 'PASS')) {
      out.push(blocker(id, 'finding', 'FIXED_AND_RETESTED requires the original failure case to be rerun (retestCommand + successful retestResult)', ref));
    }
    if (f.state === 'REPRODUCED') out.push(blocker(id, 'finding', 'finding is REPRODUCED and has no accepted fix/retest or explicit deferral', ref));
    if (f.state === 'DEFERRED_WITH_RATIONALE' && !(text(f.rationale) && text(f.boundedClaim))) {
      out.push(blocker(id, 'finding', 'DEFERRED_WITH_RATIONALE requires rationale and a bounded release claim', ref));
    }
  }
  return out;
}

/** Residual review-scope items must be explicitly treated, never omitted. */
export function resolveResidualBlockers(candidate) {
  const out = [];
  const TREATMENTS = new Set(['fixed-before-freeze', 'included-in-review-scope', 'deferred-with-rationale']);
  for (const [i, r] of (candidate.residualReviewScope ?? []).entries()) {
    const ref = `candidate.residualReviewScope[${i}]`;
    const id = r?.ref ?? `#${i}`;
    if (!TREATMENTS.has(r?.treatment)) { out.push(blocker(id, 'residual', 'residual item has no explicit accepted treatment', ref)); continue; }
    if (!text(r?.rationale) || !text(r?.boundedClaim)) out.push(blocker(id, 'residual', 'residual treatment requires rationale and a bounded release claim', ref));
  }
  return out;
}

// Evidence is unsigned local/reviewer evidence. Hashes bind bytes, not truth.
// Non-conformance observations are a freeze-bundle record, not a new protocol
// artifact. A trusted reviewer must assess whether their tests exercise the
// declared property. No report type, PASS label or assurance class proves it.
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const same = (a, b) => digest(a) === digest(b);
const array = v => Array.isArray(v) ? v : [];
const nonempty = v => Array.isArray(v) && v.length > 0;
const unique = xs => new Set(xs).size === xs.length;

export function resolveEvidence(candidate, { registry, manifest, criteria, read }) {
  const blockers = [], diagnostics = [], records = [], valid = new Map();
  const fail = (id, reason) => diagnostics.push(blocker(id, 'evidence', reason, 'candidate.results'));
  const load = descriptor => {
    if (!text(descriptor?.path) || !/^[0-9a-f]{64}$/.test(descriptor?.sha256 ?? '')) throw Error('missing evidence path/hash');
    const bytes = read(descriptor.path);
    if (sha256(bytes) !== descriptor.sha256) throw Error(`evidence hash mismatch: ${descriptor.path}`);
    return JSON.parse(bytes.toString());
  };
  const artifacts = new Map();
  for (const a of array(candidate.rcArtifacts)) {
    const id = `${a.package}@${a.version}`;
    try {
      if (artifacts.has(id)) throw Error('duplicate artifact identity');
      const bytes = read(a.tarball);
      const integrity = a.integrity?.startsWith('sha256:') ? `sha256:${sha256(bytes)}`
        : `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
      if (a.integrity !== integrity) throw Error('RC artifact bytes do not match integrity');
      artifacts.set(id, a.integrity);
    } catch (e) { fail(`RC-${id}-BYTES`, e.message); }
  }
  let snapshot, capturedSnapshot;
  try {
    snapshot = load(candidate.snapshot);
    capturedSnapshot = snapshot;
    if (!same(snapshot.registry, registry) || !same(snapshot.manifest, manifest)) throw Error('snapshot registry/manifest differs from gate inputs');
    if (snapshot.source?.revision !== candidate.source?.sha || snapshot.source?.workingTreeDirty !== false) throw Error('snapshot source is not the clean candidate revision');
    if (!Object.keys(snapshot.source?.artifacts ?? {}).length) throw Error('snapshot has no source hashes');
    // Source files accompany the bundle; do not substitute the live checkout's
    // SHA or clean-tree assertion for evidence-level byte identity.
    for (const [path, hash] of Object.entries(snapshot.source.artifacts)) {
      if (sha256(read(path)) !== hash) throw Error(`snapshot source hash mismatch: ${path}`);
    }
    const requiredFiles = new Set([REGISTRY, CORPUS_MANIFEST, AUDIT]);
    const audit = read(AUDIT).toString();
    for (const c of manifest.corpora) {
      for (const p of [c.spec, ...array(c.supportFiles), ...array(c.consumers).map(x => x.path), ...c.representations.map(r => r.path)].filter(text)) requiredFiles.add(p);
      const row = audit.split('\n').find(line => line.startsWith(`| [${c.id}](`));
      const classification = row?.split(' | ')[4];
      const provenance = classification?.startsWith('Mixed: spec-derived') && c.id === 'docs-canonicalization-v1' ? 'mixed' : 'reference-generated';
      if (snapshot.provenance?.[c.id] !== provenance) throw Error('snapshot promotes or changes audited expectation provenance');
      for (const r of c.representations) {
        const data = JSON.parse(read(r.path));
        const cases = Array.isArray(data) ? data : data.vectors ?? [{ ...data, id: data.auth_id }];
        if (!same(snapshot.representations?.[r.path], { digest: digest(data), cases: Object.fromEntries(cases.map(v => [v.id, digest(v)])) })) throw Error('snapshot corpus fingerprints differ from bundled bytes');
      }
    }
    for (const p of requiredFiles) if (!snapshot.source.artifacts[p]) throw Error(`snapshot omits required source hash: ${p}`);
    const registryBytes = read(REGISTRY), manifestBytes = read(CORPUS_MANIFEST);
    if (!same(JSON.parse(registryBytes), registry) || !same(JSON.parse(manifestBytes), manifest)) throw Error('bundled registry/manifest mismatch');
    if (snapshot.source.artifacts[REGISTRY] !== sha256(registryBytes) || snapshot.source.artifacts[CORPUS_MANIFEST] !== sha256(manifestBytes)) throw Error('registry/manifest hashes missing');
  } catch (e) { fail('EVIDENCE-SNAPSHOT', e.message); snapshot = null; }

  const dispositionIds = array(candidate.freezeDispositions).map(d => d?.claimId);
  for (const id of dispositionIds) {
    if (!registry.claims.some(c => c.id === id) || dispositionIds.filter(x => x === id).length !== 1 || !acceptedDisposition(candidate, id)) fail(id ?? 'DISPOSITION', 'unknown, ambiguous or incomplete disposition');
  }
  const ids = array(candidate.results).map(r => r?.id);
  if (!unique(ids) || ids.some(id => !text(id))) fail('EVIDENCE-IDS', 'result IDs must be present and unique');
  for (const [i, r] of array(candidate.results).entries()) {
    let doc;
    try {
      doc = load(r.evidence);
      records.push({ id: r.id, evidence: r.evidence, report: doc });
      if (!text(r.id) || ids.filter(id => id === r.id).length !== 1) throw Error('missing or duplicate result ID');
      if (!snapshot) throw Error('no valid source snapshot');
      if (r.result !== 'PASS' || doc.result !== 'PASS') throw Error('result/evidence is not PASS');
      if ((typeof doc.failed === 'number' && doc.failed !== 0) ||
          (Array.isArray(doc.failures) ? doc.failures.length !== 0 : doc.failures !== undefined && doc.failures !== 0) ||
          (doc.executions !== undefined && (!Array.isArray(doc.executions) || doc.executions.some(e => e.exitCode !== 0)))) throw Error('PASS contradicts recorded failures or execution exits');
      const source = doc.evidenceScope?.source ?? doc.source;
      if (!same(source, snapshot.source)) throw Error('evidence source revision, dirty state or hashes differ from snapshot');
      if (!nonempty(r.artifacts) || r.artifacts.some(id => !artifacts.has(id))) throw Error('unresolved RC artifact reference');
      // Binding record is hashed separately so the existing #324 report remains
      // byte-for-byte unchanged. It records the command and exact tested tarballs.
      const binding = load(r.binding);
      if (binding.unsigned !== true || binding.command !== r.command || binding.reportSha256 !== r.evidence.sha256 || !same(binding.source, source)) throw Error('missing/mismatched unsigned execution binding');
      const expected = Object.fromEntries(r.artifacts.map(id => [id, artifacts.get(id)]));
      if (!same(binding.artifacts, expected)) throw Error('execution binding does not identify tested RC bytes');
      if (!Array.isArray(binding.unresolvedAssumptions) || !Array.isArray(binding.deploymentAssumptions)) throw Error('missing assumption records');
      records.at(-1).binding = binding;
      if (binding.unresolvedAssumptions.length) throw Error('execution has unresolved assumptions');
      if (r.claims !== undefined && !Array.isArray(r.claims)) throw Error('malformed claimed scope');
      if (doc.evidenceScope) {
        const scope = doc.evidenceScope;
        if (scope.version !== 1 || !['execution', 'structural-only'].includes(scope.kind)) throw Error('unknown scope kind');
        // Reuse #324 coverage construction, including its provenance audit. The
        // snapshot supplies source identity; audit classifications are checked
        // against the bundled audit, never promoted by the candidate.
        const selections = array(scope.corpora).map(c => ({ ...c, data: JSON.parse(read(c.representation)) }));
        const expectedScope = evidenceScope({ kind: scope.kind, selections, metadata: snapshot });
        for (const key of ['corpora', 'coveredClaims', 'excludedClaims', 'corpusProvenance', 'assumptions', 'limitations', 'source']) {
          if (!same(scope[key], expectedScope[key])) throw Error(`invalid evidenceScope.${key}`);
        }
        for (const c of scope.corpora) {
          if (!nonempty(c.caseIds) || !unique(c.caseIds) || !same(c.caseIds, c.passedCaseIds) || !same(c.caseIds, c.matchedCaseIds)) throw Error('unexecuted, failed or unmatched corpus cases');
          if (!array(scope.consumers).some(x => x.path === c.consumer && x.runtime === c.runtime)) throw Error('missing exact consumer/runtime');
        }
        for (const claim of array(r.claims)) {
          if (!scope.coveredClaims.some(c => c.id === claim.id && same(c.evidence, claim.evidence))) throw Error('claim exceeds exact bounded evidenceScope');
        }
        // Structural-only reports may document consistency, never execution.
        if (scope.kind === 'structural-only' && (scope.corpora.length || array(r.claims).length)) throw Error('structural evidence cannot claim execution');
      } else {
        if (doc.kind !== 'review-observations' || doc.unsigned !== true || !text(doc.reviewedBy) || !text(doc.reviewedAt)) throw Error('missing reviewed observations');
        if (array(r.claims).length) throw Error('review observations cannot manufacture coveredClaims');
        if (!nonempty(doc.observations)) throw Error('no direct observations');
        for (const o of doc.observations) {
          if (!text(o.id) || o.expected !== o.actual || o.result !== 'PASS' || !text(o.command) || !text(o.expected) || !text(o.actual) || !text(o.property)) throw Error('incomplete or failed observation');
          const log = load(o.log);
          for (const key of ['result', 'command', 'property', 'stage', 'expected', 'actual', ...(o.stage === 'deployment' ? ['replayDomain', 'topology'] : [])]) {
            if (log[key] !== o[key]) throw Error('observation differs from recorded output');
          }
          if (!same(log.source, source) || !same(log.artifacts, expected)) throw Error('observation output source/artifact mismatch');
        }
        if (!unique(doc.observations.map(o => o.id))) throw Error('ambiguous observation IDs');
      }
      valid.set(r.id, { entry: r, doc, binding });
    } catch (e) { fail(`RESULT-${i}-EVIDENCE`, e.message); }
  }
  // A reviewed observation supports only its exact predeclared property/stage.
  // A conformance report supports only a selected registry evidence statement;
  // it is not a substitute for a whole criterion or a later execution stage.
  const supports = (refs, property, stages) => nonempty(refs) && refs.every(ref => {
    const r = valid.get(ref.resultId);
    const o = r?.doc.kind === 'review-observations' && r.doc.observations.find(o => o.id === ref.observationId);
    return o && o.property === property && stages.includes(o.stage) &&
      (o.stage !== 'deployment' || (text(o.replayDomain) && text(o.topology) && nonempty(r.binding.deploymentAssumptions)));
  });
  for (const c of criteria.criteria ?? []) {
    const evals = array(candidate.criteriaEvaluations).filter(e => e.criterionId === c.id);
    if (c.mandatory && (evals.length !== 1 || evals[0].state !== 'PASS' || !supports(evals[0].evidence, c.statement, array(c.evidenceStages)))) fail(c.id, 'mandatory criterion lacks successful, exact, stage-appropriate observations');
  }
  for (const f of array(candidate.findings)) {
    if (f.state === 'FIXED_AND_RETESTED' && (!text(f.failureCondition) || !supports(f.evidence, f.failureCondition, [f.stage].filter(text)) || !array(f.evidence).every(ref => valid.get(ref.resultId)?.doc.observations?.find(o => o.id === ref.observationId)?.command === f.retestCommand))) fail(f.id, 'successful retest must exercise the original failure condition');
  }
  for (const c of criteria.blockerExitConditions ?? []) {
    const claim = registry.claims.find(x => x.id === c.id);
    const d = array(candidate.freezeDispositions).find(x => x.claimId === c.id);
    if (!['specified', 'conditional'].includes(c.exitConditionState) || !text(c.exitCondition) || !array(c.sources).some(s => text(s.path) && text(s.section) && s.quote === c.exitCondition) || !acceptedDisposition(candidate, c.id) || !claim || claim.maintainerDecisionRequired !== false || !['specified', 'non-normative'].includes(claim.normativeState) || claim.evidenceState !== 'mapped' ||
        d?.decision !== 'fixed-before-freeze' || !supports(d.evidence, c.exitCondition, c.evidenceStages)) {
      blockers.push(blocker(c.id, 'claim', 'exit condition remains unresolved; disposition is not demonstrated closure', c.exitCondition ?? c.boundary));
    }
  }
  for (const entry of array(candidate.conformanceAuthority?.releaseRelevantCorpora)) {
    for (const runtime of array(entry.claimedRuntimes)) {
      const executed = [...valid.values()].some(r => r.doc.evidenceScope?.kind === 'execution' && r.doc.evidenceScope.corpora.some(c => c.id === entry.id && c.runtime === runtime && c.matchedCaseIds.length));
      if (!executed) fail(`CORPUS-${entry.id}-RUNTIME-${runtime}`, 'no exact executed and passed corpus/runtime evidence');
    }
  }
  if (candidate.conformanceAuthority?.independentNormativeAuthority !== undefined && candidate.conformanceAuthority.independentNormativeAuthority !== false) fail('CORPUS-PROVENANCE', 'no independently-derived corpus authority demonstrated by the current audit');
  if (criteria.criteria.some(c => c.id === 'CORP-003') && !supports(candidate.conformanceAuthority?.projectionEvidence,
      criteria.criteria.find(c => c.id === 'CORP-003')?.statement, ['structural-review'])) fail('CORPUS-PROJECTION-EVIDENCE', 'projectionVerified alone is insufficient; exact projection check evidence required');
  if (array(candidate.unresolvedAssumptions).length) fail('UNRESOLVED-ASSUMPTIONS', 'candidate has unresolved assumptions');
  return { blockers, diagnostics, records, snapshot: capturedSnapshot ?? null };
}

export function verify(candidate, { registry, manifest, criteria, read = p => readFileSync(resolve(ROOT, p)) }) {
  const evidence = resolveEvidence(candidate, { registry, manifest, criteria, read });
  // Only registry-declared release claims and declared freeze exits enter this
  // array. Never classify failures by ID prefixes: a diagnostic ID may collide
  // with a declared claim without changing that claim's disposition.
  const declared = [...resolveClaimBlockers(registry, candidate), ...evidence.blockers];
  const order = (a, b) => `${a.id}:${a.class}:${a.reason}`.localeCompare(`${b.id}:${b.class}:${b.reason}`, 'en');
  const blockers = [...new Set(declared.map(b => b.id))].sort().map(id => {
    const entries = declared.filter(b => b.id === id).sort(order);
    return { ...entries[0], reason: [...new Set(entries.map(b => b.reason))].join('; '), details: entries };
  });
  const diagnostics = [
    ...resolveScopeDiagnostics(registry),
    ...resolveCorpusBlockers(candidate, manifest),
    ...resolveArtifactBlockers(candidate),
    ...resolveProvenanceBlockers(candidate),
    ...resolveFindingBlockers(candidate),
    ...resolveResidualBlockers(candidate),
    ...resolveCriterionBlockers(candidate, criteria),
    ...evidence.diagnostics,
  ].sort(order);
  return { status: blockers.length === 0 && diagnostics.length === 0 ? 'PASS' : 'BLOCKED', unsigned: true,
    limitations: ['Unsigned local evidence, not an attestation or an assurance class.',
      'Hashes establish byte identity, not truth or independent reproduction.',
      'A reviewer must assess whether recorded observations directly exercise each exit condition.',
      'Reference-generated expectations and cross-language agreement do not establish independent normative authority.',
      'Consume and ALLOW do not prove execution; generic conformance does not prove deployment durability.'],
    blockers, diagnostics, dispositions: array(candidate.freezeDispositions).map(d => ({ ...d,
      status: blockers.some(b => b.id === d.claimId) ? (d.decision === 'deferred-with-rationale' && acceptedDisposition(candidate, d.claimId) ? 'reviewed-deferral-unresolved' : 'unresolved') : (criteria.blockerExitConditions?.some(c => c.id === d.claimId) ? 'demonstrated-closure' : 'reviewed-disposition') })),
    gateInputs: { registry: digest(registry), manifest: digest(manifest), criteria: digest(criteria) },
    declaredResults: candidate.results ?? [],
    source: candidate.source ?? null, snapshot: { identity: candidate.snapshot ?? null, metadata: evidence.snapshot },
    evidence: evidence.records, unresolvedAssumptions: candidate.unresolvedAssumptions ?? [],
    deploymentAssumptions: candidate.deploymentAssumptions ?? [],
  };
}

export function report(result) {
  const lines = [`S_FREEZE: ${result.status}`];
  for (const [label, entries] of [['DECLARED BLOCKERS', result.blockers], ['BLOCKING DIAGNOSTICS', result.diagnostics]]) {
    if (!entries.length) continue;
    lines.push('', `${label} (${entries.length}):`);
    for (const b of entries) lines.push(`- ${b.id}\n  class: ${b.class}\n  reason: ${b.reason}${b.evidence ? `\n  evidence: ${b.evidence}` : ''}`);
  }
  lines.push('', 'S_freeze is a reviewed-candidate gate, not a publication step.',
    'Structural traceability is not semantic proof. Verifier correctness is not non-bypassable deployment enforcement.',
    'Either declared blockers or evidence diagnostics prevent PASS; diagnostics are not advisory.',
    'Unsigned evidence; not an attestation. Reviewed deferrals remain unresolved and blocking.',
    'PASS is bounded by the recorded evidence, assumptions and limitations; it is not protocol conformance.');
  return lines.join('\n');
}

function load(p) { return JSON.parse(readFileSync(resolve(ROOT, p), 'utf8')); }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    const at = (flag) => { const i = args.indexOf(flag); return i === -1 ? null : args[i + 1]; };
    if (args.includes('--criteria')) throw Error('criteria override is not permitted for a freeze decision');
    const candidatePath = at('--candidate');
    if (!candidatePath) throw Error('usage: node scripts/s-freeze/verify.mjs --candidate <path> [--json]');
    const result = verify(JSON.parse(readFileSync(resolve(candidatePath), 'utf8')), {
      registry: load(at('--registry') ?? REGISTRY),
      manifest: load(at('--manifest') ?? CORPUS_MANIFEST),
      criteria: load(CRITERIA),
      read: p => readFileSync(resolve(dirname(resolve(candidatePath)), p)),
    });
    console.log(args.includes('--json') ? JSON.stringify(result, null, 2) : `${report(result)}\n${JSON.stringify({ unsigned: result.unsigned, diagnostics: result.diagnostics, gateInputs: result.gateInputs, declaredResults: result.declaredResults, source: result.source, snapshot: result.snapshot, evidence: result.evidence, dispositions: result.dispositions, unresolvedAssumptions: result.unresolvedAssumptions, deploymentAssumptions: result.deploymentAssumptions, limitations: result.limitations })}`);
    process.exitCode = result.status === 'PASS' ? 0 : 1;
  } catch (e) { console.error(`S_FREEZE: BLOCKED — ${e.message}`); process.exitCode = 1; }
}
