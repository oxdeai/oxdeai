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
// sufficient and unresolved items are explicitly dispositioned.
//
// Blocker classes are kept separate on purpose — never collapsed into one
// opaque boolean:
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
// release-blocking derives from declared freeze scope plus explicit reviewed
// disposition. See resolveClaimBlockers().

import { readFileSync } from 'node:fs';
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

/** Decisions that count as an explicit, reviewed freeze disposition. */
const ACCEPTED_DECISIONS = new Set(['fixed-before-freeze', 'included-in-review-scope', 'deferred-with-rationale']);

const SHA_RE = /^[0-9a-f]{40}$/;
const INTEGRITY_RE = /^(sha512-[A-Za-z0-9+/]+={0,2}|sha256:[0-9a-f]{64})$/;

const text = (v) => typeof v === 'string' && v.trim().length > 0;
const blocker = (id, cls, reason, evidence) => ({ id, class: cls, reason, evidence: evidence ?? null });

/**
 * An explicit, reviewed disposition that removes a claim from the
 * freeze-critical set. Absence of evidence is never acceptance: every field
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

/** True when a claim sits inside the declared 2.0 freeze boundary. */
export function inFreezeScope(claim, candidate) {
  const disp = claim.scopeDisposition;
  if (IN_FREEZE_SCOPE.has(disp)) return true;
  if (!CONDITIONAL_SCOPE.has(disp)) return false;
  // A conditional claim is in scope only when the candidate explicitly asserts
  // that its condition applies. Silence means "condition not asserted", which
  // keeps a conditional claim out of scope rather than guessing either way.
  const asserted = new Set(candidate.conditionsAsserted ?? []);
  return asserted.has(claim.id);
}

/**
 * Release-blocking claim rules.
 *
 *  1. maintainerDecisionRequired blocks REGARDLESS of scopeDisposition until an
 *     explicit accepted disposition exists. Being out-of-scope, deferred or
 *     deployment-scoped does NOT by itself discharge a decision the registry
 *     says a human owes. (Inferring acceptance from scopeDisposition alone is
 *     exactly the shortcut this gate exists to prevent.)
 *  2. An unresolved evidence state (gap/unassessed) blocks only when the claim
 *     is inside the declared freeze boundary and has no accepted disposition.
 */
export function resolveClaimBlockers(registry, candidate) {
  const out = [];
  for (const claim of registry.claims ?? []) {
    const accepted = acceptedDisposition(candidate, claim.id);
    const scoped = inFreezeScope(claim, candidate);

    if (claim.maintainerDecisionRequired === true && !accepted) {
      out.push(blocker(claim.id, 'maintainer-decision',
        `maintainerDecisionRequired=true and no accepted freeze disposition (scopeDisposition=${claim.scopeDisposition})`,
        `${REGISTRY}#${claim.id}`));
      continue;
    }
    if (!scoped || accepted) continue;
    if (claim.evidenceState === 'gap' || claim.evidenceState === 'unassessed') {
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
  if (!src.toolchain || Object.keys(src.toolchain).length === 0) out.push(blocker('SOURCE-TOOLCHAIN', 'provenance', 'no toolchain versions recorded', 'candidate.source.toolchain'));
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
    if (!text(r?.result)) out.push(blocker(`RESULT-${i}-OUTCOME`, 'provenance', 'result has no outcome', ref));
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
    if (f.state === 'FIXED_AND_RETESTED' && !(text(f.retestCommand) && text(f.retestResult))) {
      out.push(blocker(id, 'finding', 'FIXED_AND_RETESTED requires the original failure case to be rerun (retestCommand + retestResult)', ref));
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

export function verify(candidate, { registry, manifest, criteria }) {
  const blockers = [
    ...resolveClaimBlockers(registry, candidate),
    ...resolveCorpusBlockers(candidate, manifest),
    ...resolveArtifactBlockers(candidate),
    ...resolveProvenanceBlockers(candidate),
    ...resolveFindingBlockers(candidate),
    ...resolveResidualBlockers(candidate),
    ...resolveCriterionBlockers(candidate, criteria),
  ];
  // Deterministic ordering: class, then id.
  blockers.sort((a, b) => (a.class === b.class ? (a.id < b.id ? -1 : a.id > b.id ? 1 : 0) : a.class < b.class ? -1 : 1));
  return { status: blockers.length === 0 ? 'PASS' : 'BLOCKED', blockers };
}

export function report(result) {
  const lines = [`S_FREEZE: ${result.status}`];
  if (result.blockers.length) {
    lines.push('', `BLOCKERS (${result.blockers.length}):`);
    for (const b of result.blockers) lines.push(`- ${b.id}\n  class: ${b.class}\n  reason: ${b.reason}${b.evidence ? `\n  evidence: ${b.evidence}` : ''}`);
  }
  lines.push('', 'S_freeze is a reviewed-candidate gate, not a publication step.',
    'Structural traceability is not semantic proof. Verifier correctness is not non-bypassable deployment enforcement.',
    'A PASS states that recorded evidence is internally sufficient and unresolved items are explicitly dispositioned — not that the protocol is conformant.');
  return lines.join('\n');
}

function load(p) { return JSON.parse(readFileSync(resolve(ROOT, p), 'utf8')); }

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    const at = (flag) => { const i = args.indexOf(flag); return i === -1 ? null : args[i + 1]; };
    const candidatePath = at('--candidate');
    if (!candidatePath) throw Error('usage: node scripts/s-freeze/verify.mjs --candidate <path> [--json]');
    const result = verify(JSON.parse(readFileSync(resolve(candidatePath), 'utf8')), {
      registry: load(at('--registry') ?? REGISTRY),
      manifest: load(at('--manifest') ?? CORPUS_MANIFEST),
      criteria: load(at('--criteria') ?? CRITERIA),
    });
    console.log(args.includes('--json') ? JSON.stringify(result, null, 2) : report(result));
    process.exitCode = result.status === 'PASS' ? 0 : 1;
  } catch (e) { console.error(`S_FREEZE: BLOCKED — ${e.message}`); process.exitCode = 1; }
}
