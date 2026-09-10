# Spec-to-Code Claim Verification

This is a curated traceability module, not a protocol proof or a replacement for
conformance execution. Run from the repository root:

```sh
pnpm verify:spec-claims
pnpm test:spec-claims
pnpm verify:spec-claims --json
pnpm verify:spec-claims --advisory
```

`PASS` means the registry is structurally consistent and its required references
resolve. The checker does not execute the referenced evidence. Test execution
results belong to the existing test/conformance jobs and the review record in
[VALIDATION.md](VALIDATION.md). Neither a source file nor an existing test proves
a normative claim. Even passing tests demonstrate only their asserted cases.

## Architecture and CI

- [claims.json](claims.json): explicitly curated, versioned inventory under
  non-normative documentation. Stable IDs survive title/path changes.
- [verify.mjs](../../../scripts/spec-claims/verify.mjs): read-only checker,
  exported verification/report functions, text/JSON CLI, optional advisory scan.
- [verify.test.mjs](../../../scripts/spec-claims/verify.test.mjs): isolated
  perturbations and CLI exit-code tests; no tracked source is modified.
- Root package scripts expose both commands. `.github/workflows/ci.yml` runs
  them immediately after installation in `build-test`, before typechecking.

The module lives at repository level because deployment assumptions, guard
execution behavior and portable verifier semantics have different owners.
It uses Node built-ins and the repository's existing TypeScript dependency to
parse implementation declarations and static test names. No dependencies,
protocol behavior, wire formats, normative prose or vectors were changed.

The CI step only checks traceability and the checker itself. Existing CI already
executes core/guard tests, package conformance, normative vector harnesses, and
Go/Python validators. Running all of these again in the new step would duplicate
work. `adapter-validation`, `packed-artifact-consumer-gate`, `rust-verifier`, and
`pep-redis-replay` remain separate. `security-gate.yml` separately runs the
policy-boundary reproduction and the externally refreshed dependency advisory
gate; a green vulnerability gate is not specification evidence.

## Registry schema (version 2)

The checker is the executable schema authority. Objects reject unknown and
missing fields; arrays, strings, booleans and enums are checked explicitly.
Every record has all of these fields. The former overloaded `status` is rejected.
See [MIGRATION.md](MIGRATION.md) for the exact v1 → v2 mapping and affected IDs:

| Field | Contract |
|---|---|
| `id` | Stable uppercase identifier ending in one or more digits; globally unique |
| `title` | Narrow human-readable property, not necessarily every rule in its source section |
| `source` | `{path, section, quote, role}`: exact Markdown heading/excerpt; `normative` requires `docs/spec`, `context` conveys no normative authority |
| `strength` | `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `normative-statement` for non-RFC-keyword normative tables/rules, or `not-applicable` for corpus locks |
| `category` | `ARTIFACT`, `VERIFY`, `ENFORCEMENT`, `TRUST`, `DELEGATION`, `TIME`, `REPLAY`, `STATE`, `AUDIT` |
| `implementation` | Array of `{path, symbol}`; symbol must resolve to a function, method, class or variable declaration |
| `evidence` | Array of evidence records, described below |
| `requiredLevels` | Explicit obligations selected by maintainers; not inferred at runtime from tests or prose |
| `securityCritical` | Whether the property affects the security boundary |
| `negativeRequired` | Missing negative evidence fails when true; requires `securityCritical` |
| `classification` | `portable`, `implementation-specific`, `deployment-assumption`, `documentation-only` |
| `portableRequired` | Requires a portable classification and explicitly declared portable vector evidence |
| `recordType` | `requirement` or contextual `corpus-lock`; locks are excluded from normative/evidence coverage denominators |
| `normativeState` | `specified`, `ambiguous`, `unresolved`, `non-normative`; describes interpretation/authority, not testing |
| `evidenceState` | `mapped`, `gap`, `unassessed`; curated evidence disposition, separate from derived capabilities |
| `scopeDisposition` | `in-scope`, `deferred`, `deployment`, `conditional`, `out-of-scope`; does not enable or disable obligations |
| `appliesWhen` | Array of `{setting, equals}` strings, interpreted as all-of contextual prerequisites; non-empty only for conditional scope, never evaluated |
| `dependsOn` | Array of `{id, relation, reason}`; relation is `interpretation`, `trust-premise` or `conditional-mitigation` |
| `inferenceGuard` | Array of `{from, to, reason}` specifying forbidden inferences between named concepts; report metadata, not an inference engine |
| `maintainerDecisionRequired` | Boolean advisory flag; never fails CI, grants approval or closes a residual |
| `notes` | Required scope limits, gap/ambiguity rationale or review context |

Evidence records contain:

| Field | Contract |
|---|---|
| `path` | Existing test or vector file within repository |
| `selector` | `{type: "test" | "vector", id}`: exact test name or top-level vector ID, unique in the selected file |
| `kind` | `unit`, `vector`, `integration`, `adversarial`, `cross-runtime` |
| `negative` | Human-reviewed adverse-input or noninterference evidence, not inferred from a filename |
| `portable` | True only for a vector demonstrating the selected portable semantics |
| `runner` | `{path, contains, command, runtime}`: reviewed execution route, existing runner file and exact binding text |
| `supports` | Precisely what the assertion demonstrates, including restricted scope |

Runner bindings for tests identify a compiled test filename in the package
script, or the core `dist/test/*.test.js` glob. Vector bindings identify the
corpus filename in its consumer. Commands and semantic connection to consumers
are curated; the checker validates references and bindings, not arbitrary shell
control flow. It does not infer a successful run from a command string.

Test selectors recognize direct `test("literal name", callback)` declarations
via the TypeScript AST. Comments/string mentions, `.skip`, `.todo`, dynamic
names and option-bearing declarations are deliberately excluded. Supporting
other test forms requires an explicit parser extension with tests. This parser
does not prove a callback runs in every environment or inspect assertion logic.
Implementation symbols establish location only; they need not be public exports.
Paths must be repository-relative, resolve to regular files, and stay inside the
repository after symlink resolution.

## Evidence strength and failure policy

Capabilities are derived independently from validated mappings:

| Capability | Required mapped evidence |
|---|---|
| `TRACEABLE` | Implementation declaration |
| `TESTED` | Implementation plus executable evidence reference |
| `INTEGRATION_TESTED` | Implementation plus integration evidence |
| `ADVERSARIAL_TESTED` | Implementation plus an explicitly negative case |
| `CONFORMANCE_TESTED` | Implementation plus explicitly portable vector evidence |

The names describe the **declared evidence scope**, not test execution by this
command. Integration does not imply adversarial evidence. Conformance does not
imply integration. Negative integration tests carry both dimensions rather than
being renamed pure adversarial unit tests. Portable does not mean cross-runtime;
a portable vector can have only a TypeScript consumer. The initial registry
conservatively declares portable conformance only for its independently exercised
canonicalization, SignedKRL and Profile-C cases.

Missing files, removed symbols/test names/vector IDs, changed source
heading/excerpt, duplicate IDs, malformed records, invalid classifications,
unsatisfied required levels, required negatives and inconsistent portable
declarations fail with an ID, code and actionable detail. There is no repair or
regeneration mode. `--registry path` permits explicit temporary inventories for
self-tests; normal CI always reads the tracked registry.

Existing gaps do not prevent structural PASS when their required levels are
explicitly empty. They remain visible as REVIEW entries with rationale. This is
an acknowledged evidence debt, not a waiver of the normative requirement.
Removing required evidence from a mapped claim fails. Changing the requirements
or editing any state dimension is an auditable registry edit requiring human review.
Security-critical claims without any negative evidence are always reported,
even when no negative is required (e.g. positive determinism evidence).

## Independent states, dependencies and corpus locks

Normative interpretation, evidence disposition and scope are independent axes.
An ambiguous requirement may have mapped tests; a specified requirement may have
an evidence gap. A deferred or out-of-scope disposition never suppresses existing
`requiredLevels`, `negativeRequired` or `portableRequired`. Evidence capability
calculation is unchanged and never inherits support from dependencies.

`dependsOn` resolves registry IDs after all records have been read, permitting
forward references. Missing IDs, duplicate edges and self references are
structural errors. Context cycles are allowed: no traversal propagates proof,
requirements, resolution or failures. Dependencies on unresolved locks are
reported but do not make a valid dependent claim fail.

Corpus locks require `source.role=context`, `strength=not-applicable`, empty
`requiredLevels` and false `negativeRequired`/`portableRequired`. Attempting to
turn a lock into an executable obligation is a structural schema error. A valid
unresolved lock has no such obligations and passes. Optional implementation or
evidence references, if later curated, still undergo normal reference checks;
they neither resolve the lock nor count as normative conformance coverage.

- `CANON-ESC-001`: maintainer-supplied unresolved ID; no repository definition
  was found. The canonicalization string rule supplies context only. Exact lock
  meaning is deferred, with no escaping policy or corpus change inferred.
- `RT-TRUST-1`: audit residual on state-provider integrity. Existing state
  requirements remain specified while the residual stays an external trust
  concern. Profile-C hash equality does not establish provider honesty.
- `RT-TRUST-2`: conditional residual. `appliesWhen` records all four documented
  closure prerequisites: `signed_required`, `verifyKrl`, `KrlWatermarkStore`,
  `SignedKrlCache`. These describe the closure context, not observed deployment
  configuration. Compatibility modes retain risk. Neither a signature test nor
  a false decision-required flag closes this lock.

A contextual excerpt inside `docs/spec` does not become a normative source and
does not suppress advisory discovery. The report shows all three dimensions,
conditions, dependency reasons and forbidden inferences; it separates locks
from the original 26 requirement records. Structural PASS is not semantic proof,
whole-protocol conformance, lock resolution or maintainer approval.

## Normative inventory and corpus boundary

`docs/spec/README.md` and `SPEC.md` identify `docs/spec/**` as normative;
`SPEC.md` itself is a companion overview. Inspected sources include:

- Core: `eta-core-v1.md`, `canonicalization-v1.md`, `trusted-time-v1.md`.
- Artifacts: `authorization-v1.md`, `delegation-v1.md`, `signed-krl-v1.md`.
- Enforcement: `pep-gateway-v1.md`.
- Verification: `verification-v1.md`, including its pending envelope section.
- Interoperability: `external-provider-profile.md`.
- Deployment obligations: `state-provider-requirements.md`.
- Conformance: `conformance-v1.md` and `test-vectors-v1.md`.

Status must be read per document/section. In particular,
`test-vectors-v1.md` calls its JSON source normative but calls its Markdown
non-normative for readability; its publication notes are also stale. The checker
does not promote all text in a normative directory into a requirement. Envelope
verification's unfinished dedicated spec is not treated as a completed contract.

| Surface | Current relationship and consumer |
|---|---|
| `docs/spec/test-vectors/canonicalization-v1.json` | Explicit normative source of truth; root TS, Go and Python harnesses |
| `docs/spec/test-vectors/authorization-v1.json` | Locked normative corpus consumed by standalone `scripts/verify-authorization-vectors.mjs`; its preimage excludes the whole signature and is not the package verifier's two-encoding implementation |
| `docs/spec/test-vectors/pep-vectors-v1.json` | Normative PEP cases consumed by standalone `scripts/verify-pep-vectors.mjs`; not execution of the guard package gateway |
| `docs/spec/test-vectors/delegation-vectors-v1.json` | Present and referenced by verification spec; standalone delegation harness; older publication notes still say pending |
| `docs/spec/test-vectors/profile-c-state-verification.json` | Portable hash comparison and selected Encoding B semantics; root Go/Python harnesses; does not exercise TypeScript guard callbacks, CAS or provider honesty |
| `docs/spec/test-vectors/signed-krl-v1.json` | Portable KRL corpus with `KRL_*` IDs; root Go/Python independent verification |
| `packages/conformance/vectors/**` | Package runner exercises Core APIs plus fixture logic. Richer verifier/state/delegation/key-lifecycle/clock/trusted-time surfaces; not interchangeable with the docs corpus |

Package SignedKRL uses `krl-001` etc.; docs SignedKRL uses `KRL_SIGNED_VALID`
etc. All eight Profile-C IDs belong to one docs-authoritative logical corpus; the
package representation is now generated and checked under #290. Its consumers
remain distinct runtime implementations, not independent corpus authorities. The package runner also has its own canonicalization helper;
its mere use cannot demonstrate all `canonicalization-v1` parsing rules.
The separate `packages/conformance/go-harness` adapter surface is not what root
`pnpm test:vectors:go` executes. No distinct corpora were unified. Only the secondary Profile-C representation
is deterministically regenerated; see [corpus authority](../../conformance/corpus-authority.md).

## Initial inventory and manual audit

The 26 migrated requirement records span all nine categories: 20 have implementation and
executable mappings; six remain unmapped. Twelve require integration, 18 require
negative evidence, and five have declared portable conformance evidence. There
are 19 portable classifications, five implementation-specific enforcement
classifications and two deployment assumptions. None of the 26 requirements uses
the documentation-only classification; the three additional contextual corpus
locks use it. See [INVENTORY.md](INVENTORY.md)
for the per-claim implementation and evidence mapping snapshot.

Manual review examined assertions, not just test names: A-1/A-2/A-3/A-4 check
that execute was not called; IB-2 compares distinct actions; RS-1 proves exactly
one execution across replay; RS-3 shares a replay store; SB-2 checks blocked
execution on mismatched state. Core canonicalization C-P2/C-P6 are unit property
tests, not integration. Trusted-time cases exercise engine issuance/freshness;
the determinism test compares complete authorization objects. Vector IDs were
checked against their actual adverse input/mode and expected result.

Known gaps and ambiguities:

- `CANON-003`: raw duplicate-key parsing lacks a direct Core mapping. Object
  canonicalization's NFC collision detection is a different property.
- `DELEGATION-AUDIT-001`: no direct mapping found for the specified
  `DELEGATION_EXECUTION`/`DELEGATION_DENIED` hash-chained PEP events. General
  boundary callbacks are not equivalent evidence.
- `VERIFY-ORDER-001`: verification §5 requires signature before expiry;
  AuthorizationV1 §10 requires expiry before signature. Core accumulates/sorts
  violations, so its ordering tests cannot prove both normative sequences.
- `ETA-SIGNING-001`: ETA excludes the entire signature field; AuthorizationV1
  specifies nested alg/kid retention and encoding-specific domain separation.
- `PEP-DEPLOY-001` and `STATE-TRUST-001`: real deployment non-bypassability and
  coherent/authoritative provider state need external deployment evidence.

Additional inspection findings are advisory, not silently invented claims:

- `verifyAuthorization` and `verifySignedKrl` have ambient-time fallbacks;
  verification §4 specifies explicit injected `now`. Register the exact strict
  API requirement and determine intended applicability before changing behavior.
- `expectedIssuer`/`expectedPolicyId` are valid generic comparison options when
  established independently. Issuer-policy authorization provenance is not
  proved by comparing scalar fields, nor by comparing parent and child policy
  IDs. The inventory makes neither inference.
- Tests for provenance, Redis/CAS behavior, API surfaces, transport behavior and
  general property families are not automatically normative claims. The advisory
  command lists statically named tests without registry mappings; an unmapped
  test may still implement a real requirement. It is not necessarily orphaned.
- `gateway.vectors.test.ts` is absent from the guard package's explicit default
  test list; `gateway.enforcement.test.ts` is now included. Root `test:vectors:pep` runs a
  standalone harness. Do not claim those gateway tests execute in the existing
  default suite just because their files exist.

## Public claims for maintainer review

The findings below were recorded during initial review. #290 corrects the
SPEC.md coverage summary and conformance guides; see the current corpus-authority
map for authoritative consumer scope. Historical findings do not assert those
statements remain uncorrected.

- `SPEC.md:3` says locked canonicalization, authorization, PEP and delegation
  vectors pass across TypeScript, Go and Python CI harnesses. Root Go/Python
  actually cover canonicalization, Profile-C and SignedKRL (28 cases per
  language), not the complete authorization/PEP/delegation surface.
- `SPEC.md:71` says only canonicalization vectors are published. Authorization,
  PEP and delegation JSON files now exist. `test-vectors-v1.md` has similarly
  stale delegation publication wording.
- `README.md:204` already states the narrower cross-language scope accurately.
  Broad phrases such as “Verification works across runtimes” should be read
  with that limitation rather than as whole-protocol independent verification.
- Core README statements about preventing all side effects require a correctly
  deployed enforcement boundary; the library cannot prove arbitrary deployment
  topology. Guard README's “through the reviewed enforcement boundary” wording
  better expresses the tested scope.
- Package conformance README's older SignedKRL paragraph says there is no
  cross-language integration, while its later coverage distinction describes
  the newer root harness coverage. These refer to different stages/surfaces and
  need editorial reconciliation.

## Drift, limitations and follow-up

`--advisory` scans uppercase MUST/REQUIRED/SHOULD lines and lists unmapped static
tests. It is deterministic but heuristic: multiline prose, inherited normative
strength, quoted examples, overlapping claims and dynamic tests make it
incomplete and noisy. Its counts never affect CI. It does not assert a total
count of all protocol requirements.

Stable names and excerpts expose removed evidence and selected prose drift.
Changes within a test body, assertion weakening, skipped enclosing suites,
implementation logic changes, runner control flow changes and specification
changes outside registered excerpts still require review and ordinary tests.
No logical implication from assertion to requirement is mechanically proven.
The initial inventory is useful but partial; its coverage ratios apply only to
registered claims. No test-run attestation, whole-protocol conformance badge or
signature-to-premise-trust implication is generated.

Recommended separate issues (not implemented here): reconcile normative signing
and ordering conflicts; investigate duplicate-aware parsing and delegation audit
evidence; review explicit-time fallback applicability; fix stale public coverage
statements; make gateway test scheduling explicit; expand the curated inventory
and adverse cases; collect deployment-specific replay/state/topology evidence;
review the separate corpus-unification proposal without assuming equivalence.

## Result evidence scope

`verify:spec-claims --json` includes a structural-only `evidenceScope`: no corpus
cases are executed, `coveredClaims` is empty and every registry record is in
`excludedClaims`. This preserves the existing structural gate and inference
guards. Runtime conformance reports use exact registry runner/selector mappings;
covered entries carry their bounded `supports` text. Exclusions are computed from
the registry, including new unmapped records. See
[the evidence-scope contract](../../conformance/evidence-scope.md).
