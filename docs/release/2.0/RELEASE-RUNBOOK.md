# OxDeAI 2.0 Release Runbook

## Purpose

This runbook defines the operator procedure for the OxDeAI 2.0 npm release after the release-hardening work merged through:

```text
7a3e5a5 feat(release): require explicit authorization for npm publication
a7c47d2 feat(release): enforce single-package publication boundary
2c01eb3 feat(release): add deterministic publication planning
a996756 feat(release): add verified release readiness evaluation
ca1fb8e feat(release): add read-only npm auth transport
270d9b0 fix(release): enforce partial dist-tag recovery contract
```

The release process preserves the following separations:

```text
readiness
!= publication plan
!= publication authorization
!= publication attempt
!= verified publication effect
!= dist-tag promotion
```

No real npm publication may occur before this runbook is merged and the final release freeze is established.

---

## Phase 0 — Runbook prerequisite

This runbook must be merged into `main` before the final precheck and source freeze.

Required order:

```text
merge runbook
→ git fetch
→ fast-forward main
→ verify clean tree
→ verify main == origin/main
→ final precheck
→ freeze source SHA
```

The source SHA recorded in the final release manifest and evidence bundle must therefore be the post-runbook-merge revision.

A precheck performed before the runbook merge must not be treated as the final release precheck.

---

## Phase 1 — Pre-freeze validation

Before establishing the final release freeze:

* work from `main`
* fetch the latest remote state
* fast-forward to `origin/main`
* verify the working tree is clean
* verify local `main` matches `origin/main`
* run the repository-defined release precheck
* run all required release, test, and security gates
* do not reuse artifacts generated from an earlier source revision

The operator must distinguish:

* local evidence
* registry/network evidence
* operator assertions

The final precheck must complete before the freeze is established.

---

## Phase 2 — Final freeze and S_freeze

The freeze is repository-wide.

The complete Git repository state is considered release-relevant.

Any new commit after `S_freeze`, including a documentation-only commit, invalidates the freeze.

Invariant:

```text
current source SHA != S_freeze source SHA
→ frozen evidence invalid
→ stop
→ establish a new freeze from the new revision
```

Do not patch or extend an existing frozen evidence bundle after the source revision changes.

### Minimum S_freeze evidence

Record at minimum:

* source Git SHA
* clean-tree status
* release ID
* release manifest
* manifest integrity
* exact package set
* package versions
* release lines
* `publishOrder`
* tarball paths
* tarball SHA-512 integrities
* target registry
* intended publication tag: `next`
* intended access: `public`
* required local validation results
* npm identity/access/status observations used for readiness
* deterministic publication plan

The complete evidence bundle must exist before the first real publication effect.

---

## Phase 3 — Publication under `next`

Publication occurs package-by-package.

Each publication operation requires its own explicit authorization.

One authorization must never authorize multiple publication effects.

Invariant:

```text
one explicit operation
+
one explicit authorization
+
predecessor order satisfied
=
at most one npm publish attempt
```

The operator does not choose publication order manually.

The frozen plan's `publishOrder` is authoritative.

The expected dependency-aware shape is:

```text
core first
→ guard and conformance according to frozen publishOrder
→ adapters and SDK according to frozen publishOrder
→ CLI last
```

If prose and the generated plan differ, the frozen publication plan is authoritative.

Each authorization must bind exactly to:

* release ID
* manifest integrity
* operation index
* package
* version
* tarball
* integrity
* registry
* tag
* access

Publication authorization cannot override predecessor-order checks.

---

## Phase 4 — PARTIAL_NEXT recovery

`PARTIAL_NEXT` is a valid intermediate release state and must be treated as a first-class recovery phase.

When entering `PARTIAL_NEXT`:

* do not unpublish anything
* do not promote any dist-tag
* do not generate a new publication order
* do not skip an unresolved predecessor
* do not automatically retry an ambiguous publication effect
* preserve the original frozen manifest
* preserve the original frozen publication plan

Reconciliation must inspect the full frozen publication plan, not only the package whose publication was interrupted or ambiguous.

After full-plan reconciliation, resume only through the existing single-package authorized publication path and continue according to the original `publishOrder`.

Invariant:

```text
PARTIAL_NEXT is a recovery state,
not authorization to compensate by deleting
or rewriting already-published packages.
```

Process result is not registry evidence:

```text
npm process success/failure
!= registry publication evidence
```

Registry reconciliation outcomes:

```text
version exists + exact planned integrity
→ accept as published

version exists + conflicting integrity
→ hard conflict / stop

version absent after reconciliation
→ remain blocked / PARTIAL_NEXT

registry observation unknown
→ fail closed
```

No automatic second publication attempt is allowed for an ambiguous effect.

---

## Phase 5 — Registry verification

Before any dist-tag promotion, every package in the frozen release plan must be independently verified from the target registry.

For each package, verify:

* expected package name
* expected version
* expected registry integrity
* correspondence with the frozen manifest
* published state recorded in the release state

Promotion is forbidden while any package is:

* unpublished
* unverified
* conflicting
* unknown
* in unresolved `PARTIAL_NEXT`

A successful npm process exit is never sufficient publication evidence.

---

## Phase 6 — Dist-tag promotion

Promotion from `next` to `latest` is a separate irreversible effect boundary.

Publication authorization does not imply promotion authorization.

Invariant:

```text
publication under next
!= authorization to promote latest
```

Use the repository's existing promotion and recovery contract.

Required semantic contract:

```text
partialDistTagRecovery === "registry-observed-idempotent-retry"
```

Do not invent a new promotion mechanism.

Promotion may begin only after the complete frozen release set has been verified from the registry.

---

## Phase 7 — Verify `latest`

After promotion, independently verify that every package exposes the expected `latest` dist-tag and expected version.

Do not proceed while any package has an ambiguous, conflicting, or unexpected dist-tag state.

---

## Phase 8 — Remove `next`

After successful promotion and verification of `latest`, remove the `next` dist-tag from the complete release set using the repository-supported procedure.

Do not leave the completed release simultaneously represented as both `next` and `latest`.

After removal, independently verify the final dist-tag state from the public registry.

If the repository does not provide a safe supported mechanism for removing `next`, treat that as a blocker. Do not invent an ad hoc procedure.

---

## Phase 9 — Final external verification

Perform final verification from the public registry and, where supported by the existing release procedure, from an external consumer/install path.

Verify:

* expected package versions are publicly available
* expected registry integrities match
* `latest` points to the intended versions
* `next` has been removed
* external installation/consumption succeeds
* final evidence still corresponds to the original `S_freeze` source SHA and manifest integrity

The final evidence chain must make it possible to trace:

```text
source SHA
→ manifest
→ tarballs
→ publication plan
→ per-operation authorization
→ publication attempt/effect
→ registry reconciliation
→ verified package set
→ latest promotion
→ next removal
→ final registry verification
→ external consumer/install verification
```

---

## Abort conditions

Stop rather than improvise if any of the following occurs:

* dirty working tree before freeze
* source SHA mismatch
* any repository commit after `S_freeze`
* manifest mismatch
* manifest integrity mismatch
* tarball integrity mismatch
* publication-plan mismatch
* missing authorization
* malformed authorization
* authorization mismatch
* predecessor-order violation
* unexpected registry
* unexpected package/version
* conflicting registry integrity
* ambiguous registry state
* unresolved `PARTIAL_NEXT`
* required validation failure
* required security gate failure

A correction that changes the repository revision requires a new freeze.

Do not mutate the existing frozen evidence bundle in place.

---

## Trust-boundary limitations

The publication authorization used by the release tooling is an explicit unsigned control-flow consent artifact.

It does not, by itself:

* authenticate operator identity
* prove issuer identity
* prove authorization freshness
* provide global single-use semantics across process restarts
* prove registry publication from npm process exit status
* hermetically control arbitrary operator npm configuration

These limitations must not be represented as stronger guarantees in release evidence or public claims.

---

## External-review note: evaluator premises (#197)

This is review context, not a new OxDeAI 2.0 release requirement.

The external review should examine not only the provenance and authenticity of evaluator inputs, but whether an authorization artifact declares which premises remain live at application time.

A verifier cannot be assigned responsibility for re-validating live premises unless the artifact makes clear which premises remain live.

---

## Completion condition

The release is complete only after:

* all frozen packages are published and registry-verified
* any `PARTIAL_NEXT` state has been fully reconciled
* `latest` promotion is complete and verified
* `next` has been removed and verified absent
* external install/consumer verification succeeds
* the final evidence chain is recorded
* the complete release state still traces back to the original `S_freeze`

Only then may the release issue be finalized.
