# S_freeze gate

`S_freeze` is the exact reviewed candidate OxDeAI can hand to an independent
third party. It is **not** a publication milestone and **not** a repository
hygiene checklist. Registry publication, npm dist-tags, GitHub releases,
historical deprecation and `latest` promotion all happen after `S_freeze` and
are tracked separately.

The gate answers one question from recorded evidence:

> Can an independent third party start from the supplied OxDeAI 2.0
> release-candidate artifacts, identify exactly what is normative, reproduce
> the claimed conformance result for the frozen SHA, and attempt to falsify the
> security boundary using criteria declared before the review?

`S_freeze` does not clear unless the answer is yes.

## What a PASS does and does not mean

A PASS states that the recorded evidence is internally sufficient and that every
unresolved item carries an explicit, reviewed disposition. It does **not** state:

| Not implied by a PASS | Why |
|---|---|
| Semantic proof | Structural traceability is not semantic proof. |
| Issuer-policy authority | Signature validity is not policy authority. |
| Non-bypassable enforcement | Verifier correctness is not deployment enforcement. |
| Independent evidence from a generated corpus | A projected representation is not independent evidence. |
| External reproducibility | Internal CI PASS is not third-party reproduction. |
| Installable artifact evidence | A source-tree test PASS is not RC artifact evidence. |
| A completed fix | Changed code is not `FIXED_AND_RETESTED`. |
| Acceptance | Deferred is not silently accepted. |
| Publication | `S_freeze` is not published OxDeAI 2.0. |

## Files

| Path | Role |
|---|---|
| `criteria.json` | Predeclared falsification criteria. Declared **before** review begins. |
| `candidate.example.json` | Non-authoritative example of the candidate record shape. Not a freeze candidate. |
| `../../../scripts/s-freeze/verify.mjs` | The gate. |
| `../../../scripts/s-freeze/verify.test.mjs` | Verifier tests, including mutation tests. |

Run: `pnpm verify:s-freeze --candidate <path>` and `pnpm test:s-freeze`.

## Blocker classes

Blockers are reported separately, never collapsed into one opaque boolean:

- `claim` — a release-blocking spec-claim state
- `maintainer-decision` — a claim the registry says a human must rule on
- `corpus` — a conformance-authority defect
- `artifact` — an RC artifact or external-consumability defect
- `provenance` — a source-identity or reproduction-traceability defect
- `finding` — a freeze finding whose evidence state is insufficient
- `residual` — a residual review-scope item without explicit treatment
- `criterion` — a mandatory falsification criterion failed or unevaluated

## Release-blocking claims

The gate deliberately does **not** encode *"all gap/unassessed claims block"*.
That would be wrong: a claim outside the declared 2.0 freeze boundary may be
unresolved without blocking the freeze.

What it encodes is:

1. `maintainerDecisionRequired === true` blocks **regardless of
   `scopeDisposition`**, until an explicit accepted disposition exists. Being
   `deferred`, `deployment` or out-of-scope does not by itself discharge a
   decision the registry says a maintainer owes. Inferring acceptance from
   `scopeDisposition` alone is precisely the shortcut this gate exists to stop.
2. An unresolved `evidenceState` (`gap` / `unassessed`) blocks **only** when the
   claim is inside the declared freeze boundary and has no accepted disposition.

Freeze scope is derived from `scopeDisposition`:

| `scopeDisposition` | In freeze scope? |
|---|---|
| `in-scope` | yes |
| `conditional` | only when the candidate explicitly asserts the claim ID in `conditionsAsserted` |
| `deferred`, `deployment`, out-of-scope | no (but rule 1 still applies) |

Silence is never acceptance. An accepted disposition requires *all* of
`decision` ∈ {`fixed-before-freeze`, `included-in-review-scope`,
`deferred-with-rationale`}, `rationale`, `boundedClaim`, `decidedBy`,
`decidedAt`. A partial disposition is treated as absent.

## Why dispositions live in the candidate, not in the claims registry

A freeze disposition is a property of **a specific freeze candidate**, not a
durable property of a normative claim. Recording it in
`docs/verification/spec-claims/claims.json` would mutate the normative registry
on every freeze cycle and would let one cycle's acceptance silently carry into
the next.

The candidate record therefore holds `freezeDispositions[]`, referencing claim
IDs. **No schema-v2 change was required.** The gate evaluates the authoritative
current registry and never duplicates it.

## Two evidence vocabularies, deliberately separate

| Vocabulary | Where | Meaning |
|---|---|---|
| `mapped` / `gap` / `unassessed` | spec-claims registry `evidenceState` | whether a normative claim has mapped evidence |
| `REPORTED` / `REPRODUCED` / `FIXED_AND_RETESTED` / `DEFERRED_WITH_RATIONALE` | candidate `findings[].state` | how far a specific freeze finding has been driven |

These are modelled separately and never coerced into one another. A registry
claim being `mapped` says nothing about whether a finding was retested, and a
finding being `FIXED_AND_RETESTED` does not change a claim's `evidenceState`.

Rules: `REPORTED` is not `REPRODUCED`; changed code alone is not
`FIXED_AND_RETESTED` (the original failure case must be rerun, recorded as
`retestCommand` + `retestResult`); `DEFERRED_WITH_RATIONALE` requires a
rationale and a bounded release claim.

## Critical-path issue references

Issue #254 names #284, #285, #289, #290 and #291 as the critical path. **All are
now closed**, and #291 was superseded by #301 and then corrected by #316.

The gate therefore does **not** depend on that issue list. It evaluates
*properties* — corpus authority, artifact consumability, provenance, claim
disposition, criteria — so it cannot go stale when issue numbers move. The issue
IDs remain useful as historical provenance in a candidate's `findings[]` and
`residualReviewScope[]`, which is where they belong.

## CI posture

CI validates the **verifier** against synthetic fixtures (`pnpm test:s-freeze`).
It must not assert that an ordinary development branch is a completed freeze
candidate. Running the gate against a real candidate record is a deliberate
maintainer action at the freeze decision point, where it is **not** advisory.
