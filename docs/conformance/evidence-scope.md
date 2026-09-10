# Conformance evidence scope (#324)

A PASS applies only to its declared `evidenceScope`. This unsigned report records
selected evidence; it is not whole-protocol conformance, a deployment certificate,
an assurance class, or proof that an execution boundary cannot be bypassed.
Corpus ownership and expected-value provenance remain distinct, as established by
[the Phase 1 provenance audit](corpus-provenance-audit.md).

## Output inventory and report boundaries

| Existing surface | Existing result | Scope binding |
|---|---|---|
| Package `validate.ts` / `oxdeai-conformance` | Per-assertion PASS/FAIL; aggregate count and exit status | Final JSON `{ result, passed, failures, evidenceScope }`; `--json` suppresses stdout diagnostics. Only IDs observed by assertion checks are recorded. |
| `runTrustedTimeConformance` | Returned `{ active, passed, failed, pending, failures }` | Adds `evidenceScope`, including actual caller-supplied input digest and active/passed IDs. Pending cases are not executed. |
| Dedicated trusted-time CLI | Summary and exit status | JSON `{ result, ...summary }`, including the library scope. Supports `--json`. |
| Root TS/JS, Go, Python and Rust conformance commands | Native assertion logs / Cargo tests and exit status | `scripts/conformance/run.mjs` runs the existing commands and emits `{ result, executions, evidenceScope }`. `--json` sends child logs to stderr. |
| `verify:spec-claims --json` | `{ issues, rows }` describing structural traceability | Adds `evidenceScope` with `kind: structural-only`; covers no executable claims. `--registry` exclusions use the supplied registry. |
| `verify:corpus-authority --json` | `{ result, scope, inventory }` | Adds structural-only `evidenceScope`; inventory is not executed corpus coverage. |
| Profile-C projection check | Representation consistency PASS | Appends a structural-only scoped JSON report. No execution coverage. |
| Internal adapter RPC, Core/Rust artifact verification results, unit-test/TAP diagnostics | `{ ok, output }`, artifact statuses, test framework output | These are operations/diagnostics, not conformance reports. No protocol result format is changed. The optional package Go adapter driver remains diagnostic-only and blocked by #306 with its bundled adapter. |

The official `test:vectors:*` and `test:rust` commands retain the underlying tests
and failing exit codes. Python retains its stop-on-first-failed-command behavior.
Rust CI retains its direct `cargo test --locked` gate; scoped reporting is not a
required Rust CI artifact. The optional `test:rust` command emits a scoped report.
Direct legacy harness commands print
explicit diagnostic-only summaries; use the official command to obtain the
machine-readable report. A per-case PASS line or a raw Cargo/TAP test result must
not be promoted into a broader conformance report.

There is no new signed artifact, assurance classification, receipt, trust service,
claims registry schema, or replay-store behavior.

## Version 1 contract

The scope is built by
[`evidenceScope.mjs`](../../packages/conformance/src/evidenceScope.mjs).
JSON object fields are emitted in a fixed order; identifier arrays and mappings
are sorted. Counts and PASS/FAIL retain their existing meaning.

```ts
type EvidenceScope = {
  version: 1;
  kind: "execution" | "structural-only";
  consumers: { path: string; runtime: string }[];
  corpora: {
    id: string;                 // logical corpus, not a second Profile-C copy
    representation: string;    // exact registry representation used
    consumer: string;
    runtime: string;
    sha256: string;             // deterministic, recursively key-sorted JSON
    registeredContent: boolean;
    caseIds: string[];          // observed executed cases
    passedCaseIds: string[];
    matchedCaseIds: string[];   // passing, exact registered content + binding
  }[];
  coveredClaims: {
    id: string;
    evidence: {
      corpus: string;
      representation: string;
      caseId: string;
      consumer: string;
      runtime: string;
      supports: string;        // registry's bounded evidence statement
    }[];
  }[];
  excludedClaims: string[];
  corpusProvenance: {
    corpus: string;
    classification: "reference-generated" | "mixed";
    specDerived?: { caseId: string; field: "status"; value: "error" }[];
    remainder?: "reference-generated";
  }[];
  assumptions: string[];
  limitations: string[];
  source: {
    revision: string | null;
    workingTreeDirty: boolean | null;
    artifacts: { [repositoryRelativePath: string]: string }; // SHA-256 bytes
  };
};
```

`source.artifacts` identifies the claims registry, corpus registry, provenance
audit, corpus representations, governing specifications, consumer source files
and registered support files. `source.revision` is the metadata capture revision;
null means unavailable. A dirty capture is not a claim of a clean release build.
These identifiers are not authenticated build provenance or a complete dependency
manifest. `corpora[].sha256` identifies parsed input including caller mutations;
source hashes identify the exact captured file bytes.

In the checkout, reports read current repository metadata. Package builds also
bundle `dist/evidence-metadata.json` for installation outside the checkout. This
contains registry metadata, hashes and case fingerprints, not regenerated vector
expectations. Installed reports use that snapshot and identify its revision and
artifacts; they cannot claim to describe later changes to the upstream registry.
An unavailable registry prevents a scoped report rather than silently treating
all claims as covered. Structural validation errors still fail their gates.

## Mechanical coverage and exclusions

Coverage requires all of the following:

1. An execution report, not structural validation.
2. A specified, mapped, in-scope requirement without unresolved applicability or
   a required maintainer decision.
3. A registry `vector`/`cross-runtime` reference with an exact representation,
   selector ID, runner source path and runtime match.
4. A non-blocked verifier binding in the corpus registry.
5. Actual passing case observations and input content matching the registered
   representation. Modified root context/keys as well as modified vectors prevent
   claim coverage; a reused ID is insufficient.

`coveredClaims` means **only the listed evidence supports statements** were
exercised. It does not mean all assertions, runtime stages or evidence levels
needed to establish the entire claim have been demonstrated. Registry inference
guards remain applicable. Dependencies are never traversed to manufacture
coverage, and no enforcement coverage is inferred from artifact verification.

`excludedClaims` is computed from **all registry record IDs minus covered IDs**.
This intentionally conservative universe includes deployment requirements,
conditional/unresolved records and contextual corpus locks; an exclusion is not
a test failure or a newly imposed implementation obligation. New unmapped claims
are excluded automatically. Deleting a mapping removes its coverage automatically.
No second exclusion inventory is maintained.

No new semantic mappings are introduced. In particular:

- Go cannot inherit the Python runner's mappings despite consuming the same data.
- Package Profile-C cannot inherit mappings to the docs representation.
- Trusted-time library/CLI execution cannot inherit mappings to Core unit tests.
- Docs authorization/PEP/delegation and the Rust example do not gain mappings
  merely because their cases look similar to registered package/guard evidence.
- Corpus locks, unresolved requirements, deployment assumptions and unexecuted
  guard/Core tests stay excluded.

The wrapper is explicitly a **legacy diagnostic adapter** for runners that have
no structured result output. Package/library and structural reports already emit
structured results and do not use this parser. The adapter observes per-vector
PASS/FAIL lines emitted by the
existing runners; it does not infer execution merely from a manifest entry or a
zero exit code. Coverage requires a complete, recognized, unambiguous result set
for the invoked runner and a successful child exit. Missing, malformed, unknown,
duplicate or contradictory result diagnostics grant no coverage. Ordinary
diagnostic prose is ignored. A zero exit with unrecognized output remains a
process PASS with no covered claims, preserving the gate's exit semantics. Rust records its single fixture when the named bundled-fixture
test actually appears in Cargo output, and marks it passed only on command
success. This is trusted local runner bookkeeping, not verification of arbitrary
third-party logs. No coverage is granted from an issuer-declared assurance class.

## Provenance and freeze limitations

The current audit table is the source for corpus provenance. It yields 23
`reference-generated` corpora and one `mixed` corpus. The mixed entry records
only the three canonicalization rejection `status: error` outcomes as
`spec-derived`; positive bytes/hashes and exact error-code expectations remain
`reference-generated`. These are audit classifications, not an additional list
of cases executed by the current report. No `independently-derived` provenance
has been demonstrated. Missing/unrecognized audit rows default conservatively
to `reference-generated` rather than promoting authority.

Independent corpus consumption does not prove independent derivation. Neither
cross-language agreement nor a passing reference-generated fixture establishes
independent normative authority. Signed does not mean true; structural PASS does
not mean semantic proof; tested does not mean all claims covered. Earlier-stage
evidence cannot prove later-stage properties absent their explicit execution.

#254 must retain the registry/audit snapshot identity, selected consumer/runtime
and case coverage, excluded records, actual test results, clean-build status and
any unresolved deployment/applicability premises. It must distinguish current
checkout evidence from a packaged metadata snapshot and preserve the report's
unsigned/local-runner trust assumption. This change neither clears S_freeze nor
adds deployment or non-bypassability evidence.

## Validation at implementation time

Base: `3143412d88505c3b404663b563d961ca87303957`; no commit made.
The registry currently contains 30 records. Package execution covers selected
supports statements for 10, excluding 20; Python covers 5, excluding 25. Go,
standalone TS/JS, Rust, trusted-time and structural reports cover none under the
existing exact runner mappings and exclude all 30. These counts describe this
validation run, not a maintained coverage inventory.

| Exact command (from repository root) | Result |
|---|---|
| `pnpm --filter @oxdeai/conformance test` | PASS: 29 tests, including 12 new scope tests |
| `pnpm typecheck > /tmp/324-typecheck.log 2>&1` | PASS: repository typecheck and protocol builds |
| `npm run test:spec-claims` | PASS: 43 tests; required gates unchanged |
| `npm run verify:spec-claims -- --json > /tmp/324-claims.json` | PASS: structural scope, all 30 records excluded |
| `pnpm test:corpus-authority` | PASS: 27 tests, including isolated CLI drift rejection |
| `node scripts/corpus/verify-authority.mjs --json > /tmp/324-corpus.json` | PASS: 24 authorities; structural scope only |
| `node scripts/corpus/profile-c.mjs --check > /tmp/324-projection.log` | PASS: exact projection; structural scope only |
| `pnpm -C packages/conformance validate > /tmp/324-validate.log 2>&1` | PASS: unchanged 262 assertions |
| `pnpm -C packages/conformance validate:trusted-time > /tmp/324-trusted-time.log 2>&1` | PASS: 44 active/passed, zero failed/pending |
| `node packages/conformance/dist/src/validate.js --json > /tmp/324-package.json` | PASS: 18 representations, 148 observed cases |
| `node scripts/conformance/run.mjs ts --json > /tmp/324-ts.json` | PASS: 11 cases |
| `node scripts/conformance/run.mjs auth --json > /tmp/324-auth.json` | PASS: 12 cases |
| `node scripts/conformance/run.mjs pep --json > /tmp/324-pep.json` | PASS: 9 cases |
| `node scripts/conformance/run.mjs delegation --json > /tmp/324-delegation.json` | PASS: 12 cases |
| `node scripts/conformance/run.mjs py --json > /tmp/324-python.json` | PASS: 28 cases across 3 corpora |
| `node scripts/conformance/run.mjs go --json > /tmp/324-go.json` | PASS: 28 cases across 3 corpora |
| `node scripts/conformance/run.mjs rust --json > /tmp/324-rust.json` | PASS: 4 fixture tests and 3 clock-input tests; 1 corpus fixture recorded |
| `git diff --check` | PASS |

The new tests exercise exact mapping, synthetic unmapped claims, deleted mappings,
changed vectors/root context, wrong consumers/runtimes, failed and pending cases,
ambiguous/conditional/deployment exclusions, deterministic ordering, structural
non-coverage, #325 provenance, returned PASS/FAIL semantics, JSON CLI output,
installed snapshot loading and child failure exit preservation. The existing
isolated projection test fixture now includes the reporting module/snapshot;
its divergence rejection assertion remains required.

Initial sandbox subprocess restrictions required rerunning child-process tests
with execution permission. The initial isolated projection test also identified
its missing new reporting dependency; its fixture was corrected and all 27 tests
then passed. No gate was disabled or made advisory.

Byte comparisons against `git show 3143412:<path>` confirmed all 26 registered
representation/support files plus both registries and the #325 audit (29 files)
are unchanged. No repository corpus or expected value was modified or regenerated.
Only metadata fingerprints/snapshots were generated; in-memory/scratch negative
test mutations do not alter repository fixtures.

### Changed files

- `docs/conformance/evidence-scope.md`
- `docs/spec/conformance/conformance-v1.md`
- `docs/verification/spec-claims/README.md`
- `go-harness/canonicalization_verify.go`
- `package.json`
- `packages/conformance/README.md`
- `packages/conformance/go-harness/README.md`
- `packages/conformance/go-harness/main.go`
- `packages/conformance/package.json`
- `packages/conformance/scripts/build-evidence-metadata.mjs`
- `packages/conformance/src/evidenceScope.mjs`
- `packages/conformance/src/evidenceScope.test.ts`
- `packages/conformance/src/trustedTimeConformance.ts`
- `packages/conformance/src/validate-trusted-time.ts`
- `packages/conformance/src/validate.ts`
- `packages/conformance/tsconfig.json`
- `python-harness/verify_canonicalization_vectors.py`
- `python-harness/verify_profile_c_vectors.py`
- `python-harness/verify_signed_krl_vectors.py`
- `scripts/conformance/run.mjs`
- `scripts/corpus/corpus.test.mjs`
- `scripts/corpus/profile-c.mjs`
- `scripts/corpus/verify-authority.mjs`
- `scripts/spec-claims/verify.mjs`
- `scripts/verify-authorization-vectors.mjs`
- `scripts/verify-canonicalization-vectors.ts`
- `scripts/verify-delegation-vectors.mjs`
- `scripts/verify-pep-vectors.mjs`

### Minimal hardening validation

Rust CI is unchanged from the base: direct `cargo test --locked`, without a Node
setup/reporting step. The optional Rust report remains available outside that gate.

- `pnpm --filter @oxdeai/conformance test > /tmp/324-hardening-tests.log 2>&1`: PASS, 29 tests. The new diagnostic-adapter test checks missing, unrecognized, malformed, partial, unknown-ID and contradictory output against the mapped Python surface. Exit zero stays zero with no covered claims; the existing exit-seven test still passes.
- `cargo test --locked` (in `examples/rust-verifier`): PASS, 4 fixture tests and 3 clock-input tests.
- `pnpm test:vectors:all > /tmp/324-hardening-vectors.log 2>&1`: PASS for all existing TS/JS, trusted-time, Go and Python gates. Valid Python evidence retains its 5 mapped claims.
- `node scripts/conformance/run.mjs rust --json > /tmp/324-hardening-rust.json`: PASS for the optional scoped report.
- `git diff --exit-code -- .github/workflows/ci.yml` and `git diff --check`: PASS.

Native PASS/FAIL exit semantics are unchanged; diagnostic recognition only narrows
coverage metadata. No language harness was rewritten and no commit was made.
