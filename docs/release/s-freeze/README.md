# S_freeze gate

`S_freeze` is the reviewed candidate supplied for independent review, not a
publication milestone. Run the existing commands:

```sh
pnpm test:s-freeze
pnpm verify:s-freeze --candidate /path/to/bundle/candidate.json --json
```

Exit 0 requires both `blockers` and `diagnostics` to be empty; exit 1 means
BLOCKED. `blockers` contains declared release/freeze claims, once per ID.
`diagnostics` contains evidence, artifact, criterion, finding and residual validation
failures. Diagnostics are blocking, never advisory. Each array is deterministically
ordered, and diagnostic ID collisions cannot change a blocker disposition. The CLI does not accept a replacement criteria file. CI runs the verifier's synthetic regression tests, not a claim that a
development checkout is freeze-ready. The shipped example is incomplete,
non-authoritative and intentionally BLOCKED.

## Evidence boundary

This gate consumes unsigned local execution/reviewer records. It is not an
attestation, independent reproduction, an assurance classification, or proof of
whole-protocol conformance. Hashes identify supplied bytes; they do not establish
truth. The reviewer must assess whether observations exercise the stated property.
There is no AARM conformance or EU AI Act compliance claim.

A conformance PASS applies only to the existing #324 `evidenceScope`, including
exact corpus, representation, consumer, runtime, executed/passed cases and bounded
`supports` statements. The gate reconstructs coverage with the existing #324
builder and compares coverage, exclusions, provenance and limitations. Manifest
presence, structural checks and an overall PASS cannot create execution evidence.
A result's optional `claims` array must match exact covered IDs and their complete
bounded evidence entries. Those statements do not establish an entire blocker.

The #325 audit remains authoritative for expectation provenance: 24 logical
corpora, 23 reference-generated and one mixed. Only three canonicalization
rejection outcomes have a spec-derived status basis; their exact error codes
remain reference-generated. No independently-derived corpus has been demonstrated.
Neither projection consistency nor cross-language agreement changes that finding.

The #321 boundary also remains intact: authenticate/verify before authoritative
replay mutation, consume before protected execution, and fail closed when required
history is unavailable or indeterminate. Consumption spends entitlement; it does
not establish execution or completion. Redis selection, atomic consume, shared
in-process stores, artifact verification and gateway unit tests do not prove
non-bypassability, restart persistence, replica visibility, topology, persistence
configuration, HA or recovery. Such claims need direct deployment evidence for
the declared replay domain.

## Bundle and byte binding

All supplied file paths resolve relative to the candidate file. No commands from
the bundle are executed by this checker. The independent reproduction procedure
must still install and run RC artifacts outside the monorepo.

The existing source, RC-artifact and reproduction fields remain required.
`source.toolchain` records exact major.minor.patch versions (optional `v` prefix
and exact prerelease/build suffixes), not ranges, wildcards or partial versions.
This is freeze provenance only; TOOL-001 still requires reviewer-exercised evidence. RC
references use `package@version`, resolve to supplied tarballs, and their integrity
values are checked against actual bytes. Version strings alone are insufficient.

`snapshot: { path, sha256 }` references a JSON snapshot in the existing #324
metadata shape (`registry`, `manifest`, `provenance`, `representations`, `source`).
Supply the source files referenced by that snapshot as well. The gate checks their
hashes, corpus fingerprints, registry/manifest identity and audit classification.
The snapshot's revision must match the candidate SHA and its dirty state must be
explicitly false. Dirty or unknown evidence is retained diagnostically and blocks;
a candidate-level clean assertion cannot override it. The snapshot must correspond
to the registry/manifest evaluated by the gate, not an unrelated package snapshot.

Each `results[]` entry contains:

- Unique `id`, actual `command`, `result: "PASS"`, source `sha`, and tested RC
  `artifacts` identities.
- `evidence: { path, sha256 }` referencing the unchanged JSON conformance report
  or a reviewed observation record.
- `binding: { path, sha256 }` referencing an unsigned execution binding with
  `command`, `reportSha256`, exact `source`, `artifacts` mapping identities to
  integrity values, `unresolvedAssumptions`, and `deploymentAssumptions`.

The binding preserves the #324 report unchanged. It must describe the artifacts
actually exercised, not a later reconstruction from package names. Nonempty
unresolved assumptions block; deployment assumptions remain explicit and require
review. Execution bindings are trusted local records, not authenticated provenance.

## Criteria and direct observations

A mandatory criterion's `PASS` means its falsifying statement was tested and was
not triggered. `criteria.json` keeps those statements and adds permissible evidence
stages. Every evaluation references an existing result and observation:

```json
{"criterionId":"ISO-001","state":"PASS","evidence":[
  {"resultId":"external-install","observationId":"clean-install"}
]}
```

A non-conformance result uses `kind: "review-observations"`, `unsigned: true`,
`reviewedBy`, `reviewedAt`, `result`, `source`, and `observations[]`. Each observation
has a unique `id`, exact criterion/exit-condition `property`, appropriate `stage`,
`command`, `result: "PASS"`, matching nonempty `expected` and `actual` observations,
and a hash-bound `log` descriptor.
The supplied JSON log must contain matching result, command, property, stage,
expected/actual, source and tested-artifact identities. Review observations cannot
manufacture `coveredClaims`. Criterion evidence must exercise the whole stated
criterion; selected conformance support is not substituted for it.

Deployment-stage observations also identify `replayDomain` and `topology`, with
explicit deployment assumptions in their binding. These fields document scope;
the reviewer still needs to inspect the recorded deployment experiment. Merely
labelling a replay unit test as deployment evidence is not valid evidence.

`conformanceAuthority.projectionEvidence` references the successful structural
review observation for CORP-003. `projectionVerified: true` alone is insufficient.
Claimed runtimes additionally need exact executed and passing scoped corpus cases.

## Blockers, dispositions and findings

The nine existing blocker identities are recorded in `criteria.json`. Each entry
has repository sources and an `exitConditionState`: `specified`, `conditional`,
or `unresolved`. Specified/conditional exit text is an exact source excerpt.
An unresolved exit is `null` with no executable evidence stages, and remains
blocking even if a candidate claims closure or registry flags alone change.
The `evidenceBoundary` explicitly limits this file to gate evidence requirements;
it does not override protocol specifications or supply a maintainer resolution.

| Blocker | Existing source and audit outcome |
|---|---|
| CANON-003 | canonicalization-v1 §5 and registry CANON-003: duplicate keys must be detected during parsing. No additional unconditional rejection rule is created. |
| VERIFY-ORDER-001 | verification-v1 §§5/9 versus authorization-v1 §10, recorded by the registry: conflicting order; exact exit remains unresolved/null. |
| DELEGATION-AUDIT-001 | delegation-v1 §7 and registry: both delegation execution/denial events belong in the hash-chained log. |
| ETA-SIGNING-001 | eta-core-v1 §5 versus authorization-v1 signing preimage, recorded by the registry: conflicting preimages; exact exit remains unresolved/null. |
| PEP-DEPLOY-001 | pep-gateway-v1 §4.1 and registry: sole protected execution boundary. Verification §4.3 limits evidence for any separately claimed replay deployment guarantees; those are not blanket new exit obligations. |
| STATE-TRUST-001 | state-provider-requirements §2.1, with deployment evidence in §8, and registry: coherent state view to getState. |
| CANON-ESC-001 | Registry notes say the lock has no repository definition; canonicalization-v1 §6 is context only. Exact exit remains unresolved/null. |
| RT-TRUST-1 | protocol-audit-post-interoperability §5.3 and registry explicitly retain the provider-integrity residual. They do not define generic full closure; exact exit remains unresolved/null. |
| RT-TRUST-2 | external-provider-profile §2.2.5 and protocol-audit-post-interoperability §5.3 document closure conditional on signed_required, verifyKrl, KrlWatermarkStore and SignedKrlCache for a deployment. This is not ecosystem/default-mode closure. |

Issue #254 establishes the freeze procedure and evidence discipline; it does not
supply resolved protocol semantics for the ambiguous entries. Source paths,
sections, roles and verbatim excerpts are recorded per entry in `criteria.json`.
All nine remain unresolved in the current repository.

The existing scope vocabulary is `in-scope`, `conditional`, `deferred`,
`deployment`, and `out-of-scope`. Missing, wrong-typed or unrecognized values
(including surrounding whitespace) produce a blocking diagnostic of class `claim`;
they are never inferred to mean out-of-scope.

Registry gaps and required maintainer decisions remain blocking. For a known
blocker's demonstrated closure, its exit must have an established source, the registry must reflect a resolution and
mapped evidence; the candidate must then supply a `fixed-before-freeze`
disposition with direct evidence for its exact exit condition and stage.

`deferred-with-rationale` records a reviewed deferral and leaves the blocker in the
blocking set. `included-in-review-scope` likewise does not discharge it. A text-only
disposition never establishes closure. VERIFY-ORDER-001 remains unresolved until
a repository maintainer resolution addresses the conflicting normative sequences.

Finding states remain REPORTED, REPRODUCED, FIXED_AND_RETESTED and
DEFERRED_WITH_RATIONALE. A successful retest must identify the original
`failureCondition`, `stage`, `retestCommand`, `retestResult: "PASS"` and evidence
references to matching observations. A failed retest or successful label without
failure-case evidence does not establish a fix. Residual issues outside the
freeze-blocking set may retain explicit bounded review treatment; they do not
silently become additional protocol requirements.

Both JSON and text reports retain evidence scopes, exclusions, snapshot identity,
source state, assumptions, limitations and unresolved dispositions. Reports remain
unsigned. Supplying files and passing consistency checks does not authenticate the
reviewer or independently verify that an experiment actually ran.
