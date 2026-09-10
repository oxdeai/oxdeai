# Phase 1 corpus provenance audit (#325)

Audited repository base: `178ee48fa4f0fbaa9afa5aa80cc9acc62e7deff8`, branch
`audit/325-corpus-provenance-phase1`. Scope: all **24 logical corpora** in
[corpus-authority.json](corpus-authority.json), including its supplemental and
implementation-specific corpora. This is a source/provenance audit, not a new
execution report or a change to corpus ownership, normative specifications or
runtime behavior.

## 1. Rule

```text
specification
    ↓
normative expectation
    ↓
reference implementation may PASS or FAIL
```

If the specification says X and an independently justified normative vector
expects X, a reference implementation producing Y must FAIL. The expectation
must remain authoritative when it disagrees with the implementation.

```text
reference implementation
    ↓
generated expected value
    ↓
other implementation reproduces it
```

The second chain demonstrates agreement with a generated value, not independent
normative authority. A declared authoritative file selects which representation
owns the data; it does not establish the provenance of that data. In particular,
the registry's `generated: false` means an editable authority representation,
not proof that its expectations were manually derived from the specification.

## 2. Classification criteria

- **spec-derived**: a specific expectation has a demonstrated derivation from
  governing normative text without using reference output as its oracle. A direct
  MUST/MUST NOT rejection rule can justify the rejection outcome even when other
  fields of the same fixture lack that provenance.
- **independently-derived**: repository evidence documents production of the
  expected value by an independent method that does not reuse reference
  implementation or shared implementation logic. An independently written
  consumer that merely checks an existing fixture is insufficient.
- **reference-generated**: the expectation is produced by reference/shared
  implementation logic, **or** stronger provenance is not demonstrated. In the
  latter case this is a conservative classification, not a claim to know an
  undocumented author's actual generation procedure.

Absence of demonstrated stronger provenance => **reference-generated**.
`unknown` is not an acceptable final freeze classification. Agreement with a spec
rule, a descriptive comment, a committed constant, and a passing test are not by
themselves a record of independent expectation production. Section 4 explicitly
supplies the narrow rejection derivations accepted in this audit.

## 3. Corpus-by-corpus table

Each corpus ID links to its **authoritative representation**; the spec column
follows the registry. The sole secondary is
[package Profile-C](../../packages/conformance/vectors/profile-c-state-verification.json),
which belongs to the same `profile-c` corpus and is not counted again.
All unseparated expected fields in a row receive that row's classification.
“No writer located” means the inspected repository sources/history do not
establish an expectation-producing writer; it does not mean the file was hand-derived.

Source shorthand (read, never executed to generate fixtures):

- **G**: [canonicalization generator](../../scripts/generate-canonicalization-vectors.ts),
  `main`, `canonicalizeToJson`, `sha256Hex`.
- **E**: [package extractor](../../packages/conformance/scripts/extract-vectors.ts).
  Its header explicitly says it generates against `@oxdeai/core`; named functions
  below distinguish expectation extraction from input-only maintenance.
- **P**: [Profile-C projection](../../scripts/corpus/profile-c.mjs), `project`, `MODES`.
  It preserves signed bytes/hashes, maps outcome to status, and adds diagnostics;
  it does not derive the authority's outcomes or sign artifacts.
- **V**: [package validator](../../packages/conformance/src/validate.ts), whose
  `coreAdapter` and case builders use `@oxdeai/core` and local fixture helpers.
- **T**: [trusted-time runner](../../packages/conformance/src/trustedTimeConformance.ts).
- **D/A**: [optional Go driver](../../packages/conformance/go-harness/main.go) /
  [Python adapter](../../packages/conformance/go-harness/adapter_python.py).
  D delegates operations; it is not a Go verifier. A indexes the absent
  `authorization-payload` `input.intent_id` at import and has several frozen
  expected-result lookup operations. The registry marks this route blocked
  (#306); source presence is not passing independent verification evidence.

| Corpus / authority | Governing spec | Expected-value origin / generator | Independent consumer(s), and other consumers | Provenance class | Rationale |
|---|---|---|---|---|---|
| [docs-canonicalization-v1](../../docs/spec/test-vectors/canonicalization-v1.json) | [canonicalization-v1.md](../../docs/spec/core/canonicalization-v1.md) | G computes eight positive byte/hash pairs; preserves three error fixtures. | Go + Python reconstruct canonical bytes/hashes from JSON; TS script and guard also consume. | Mixed: spec-derived rejection outcomes; reference-generated remainder. | G and TS verifier duplicate canonicalization logic; no independent positive derivation. See §4 for rejection/code split. |
| [docs-authorization-v1](../../docs/spec/test-vectors/authorization-v1.json) | [authorization-v1.md](../../docs/spec/artifacts/authorization-v1.md) | Committed decisions/errors, action/state hashes and signatures; no writer/derivation record located. | Local JS verifier + guard; PEP verifier loads these as inputs. No registered independent-language consumer. | reference-generated | JS reconstructs preimages locally (explicitly to match fixtures); guard uses Core. Neither establishes the origin of committed values. |
| [docs-pep-vectors-v1](../../docs/spec/test-vectors/pep-vectors-v1.json) | [pep-gateway-v1.md](../../docs/spec/enforcement/pep-gateway-v1.md) | Committed HTTP status/decision/executed tuples; authorization_ref points into docs authorization fixtures. No writer located. | Local JS evaluator + guard; no independent-language consumer. | reference-generated | Evaluator hard-codes gateway scenarios; guard covers 7/9, deferring two snapshot cases. No independent derivation of complete tuples. |
| [docs-delegation-vectors-v1](../../docs/spec/test-vectors/delegation-vectors-v1.json) | [delegation-v1.md](../../docs/spec/artifacts/delegation-v1.md) | Committed outcomes/errors, parent hashes and signatures; no writer located. | Local JS delegation verifier; no independent-language consumer. | reference-generated | Local canonicalization/hash/crypto consumption does not establish how signed fixtures and expected errors were derived. |
| [profile-c](../../docs/spec/test-vectors/profile-c-state-verification.json) | [external-provider-profile.md](../../docs/spec/interoperability/external-provider-profile.md) | Docs: committed outcome labels; modes 006–008 also commit state hashes/signatures. No authority writer located. P projects to package status and mode-specific reason. | Go + Python reconstruct hashes and Encoding B preimages; V consumes package projection. | reference-generated | Independent verification is demonstrated in source, independent expectation production is not. P copies artifacts; diagnostic strings originate in its MODES table. |
| [docs-signed-krl-v1](../../docs/spec/test-vectors/signed-krl-v1.json) | [signed-krl-v1.md](../../docs/spec/artifacts/signed-krl-v1.md) | Committed status/code tuples and signed envelopes; no writer located. | Go + Python reconstruct KRL payload/domain/preimage and verify committed Ed25519 signatures. | reference-generated | Metadata describes deterministic signatures and independent consumers, not an independent generation procedure. Docs/package KRL remain distinct. |
| [package-audit-chain](../../packages/conformance/vectors/audit-chain.json) | [verification-v1.md](../../docs/spec/verification/verification-v1.md) | E.extractAuditChain: Core engine events, local canonical JSON and SHA-256 produce genesis/head/mutation hashes. | V; optional D (driver only). No demonstrated independent verifier. | reference-generated | E and V use the same local chain construction over reference events; expected hashes are computed, not independently derived. |
| [package-audit-verification](../../packages/conformance/vectors/audit-verification.json) | [verification-v1.md](../../docs/spec/verification/verification-v1.md) | Committed status/violation arrays (including messages/order); no expectation writer located. V.buildAuditVerificationCases constructs cases. | V; D/A blocked. | reference-generated | V calls Core verifyAuditEvents; A contains frozen expected-result lookups. Neither documents independent tuple derivation. |
| [package-authorization-payload](../../packages/conformance/vectors/authorization-payload.json) | [authorization-v1.md](../../docs/spec/artifacts/authorization-v1.md) | E.extractAuthorizationPayload: PolicyEngine.evaluatePure produces hashes, issuance/expiry and HMAC signature; local authSigningPayload emits canonical preimage. | V; D/A blocked. | reference-generated | Generator and verifier share Core engine/fixture secret and payload construction. A returns stored values; arithmetic annotations do not establish historical independent derivation. |
| [package-authorization-signature-verification](../../packages/conformance/vectors/authorization-signature-verification.json) | [authorization-v1.md](../../docs/spec/artifacts/authorization-v1.md) | Committed mode/status/violation arrays; no expectation writer located. V signs/rebuilds A/B artifacts at consumption time. | V; D/A blocked. | reference-generated | V uses Core signing/verifying plus local Encoding B signing. Runtime artifact generation is not a separately derived expected-result oracle. |
| [package-authorization-verification](../../packages/conformance/vectors/authorization-verification.json) | [authorization-v1.md](../../docs/spec/artifacts/authorization-v1.md) | Committed authorization inputs and status/violation tuples; no writer located. | V; D driver only, blocked. | reference-generated | Core verifyAuthorization is the active adapter; no derivation record for complete expectations/messages. |
| [package-clock-semantics-verification](../../packages/conformance/vectors/clock-semantics-verification.json) | [authorization-v1.md](../../docs/spec/artifacts/authorization-v1.md) | Committed temporal cases/status/violation tuples; no writer located. | V only. | reference-generated | Clock boundary rules motivate cases, but no independent provenance of full stored tuples is demonstrated. |
| [package-delegation-chain-verification](../../packages/conformance/vectors/delegation-chain-verification.json) | [delegation-v1.md](../../docs/spec/artifacts/delegation-v1.md) | Committed mode/status/violation tuples. E.extractDelegationChainVerificationInputs adds Core-signed inputs while preserving expected. | V; D/A blocked; E maintenance reader/writer. | reference-generated | Do not attribute expected generation to the current extractor: it preserves expected. V rebuilds cases by position using Core; independent derivation remains undocumented. |
| [package-delegation-parent-hash](../../packages/conformance/vectors/delegation-parent-hash.json) | [delegation-v1.md](../../docs/spec/artifacts/delegation-v1.md) | E.extractDelegationParentHash: Core-signed parent, local canonicalJson and SHA-256 produce parent_auth_hash. | V; D driver only, blocked. | reference-generated | V uses matching local parent serialization/hash construction. Independent normative parent bytes/hash derivation is not shown. |
| [package-delegation-signature-verification](../../packages/conformance/vectors/delegation-signature-verification.json) | [delegation-v1.md](../../docs/spec/artifacts/delegation-v1.md) | Committed mode/status/violation tuples. E.extractDelegationSignatureVerificationInputs refreshes Core-signed inputs, preserves expected. | V; D/A blocked; E maintenance reader/writer. | reference-generated | Input extraction is not expectation extraction. V constructs/signs/verifies with Core; no independent expected-tuple derivation. |
| [package-delegation-verification](../../packages/conformance/vectors/delegation-verification.json) | [delegation-v1.md](../../docs/spec/artifacts/delegation-v1.md) | Committed delegation inputs and status/violation tuples; no expectation writer located. | V; D driver only, blocked. | reference-generated | V calls Core verifyDelegation. Full messages/order and expected results have no demonstrated independent derivation. |
| [package-envelope-signature-verification](../../packages/conformance/vectors/envelope-signature-verification.json) | [verification-v1.md](../../docs/spec/verification/verification-v1.md) | Committed modes/status/violations; no expectation writer located. V builds envelopes/snapshots and signatures. | V; D/A blocked. | reference-generated | V uses Core encode/sign/verify helpers; A includes frozen lookups. Signed inputs built during verification do not prove expected-value provenance. |
| [package-envelope-verification](../../packages/conformance/vectors/envelope-verification.json) | [verification-v1.md](../../docs/spec/verification/verification-v1.md) | E.extractEnvelopeVerification records verifyEnvelope results: status, violations and positive policy/state/audit hashes. | V; D/A blocked. | reference-generated | E and V share Core envelope/state codecs and verification; expected outputs come directly from reference verification. |
| [package-intent-hash](../../packages/conformance/vectors/intent-hash.json) | [canonicalization-v1.md](../../docs/spec/core/canonicalization-v1.md) | E.extractIntentHash calls Core sha256HexFromJson on bindingIntentProjection. | V; D driver only, blocked. | reference-generated | Core hash routine and matching binding projection are reused; optional adapter source does not establish independent expected-hash generation. |
| [package-key-lifecycle-verification](../../packages/conformance/vectors/key-lifecycle-verification.json) | [authorization-v1.md](../../docs/spec/artifacts/authorization-v1.md) | Committed mode/status/violation tuples; no writer located. V constructs/signs authorization and key-state variants. | V only. | reference-generated | Core signing and verifyAuthorization produce actual results; expected tuple derivation is not documented. |
| [package-signed-krl-verification](../../packages/conformance/vectors/signed-krl-verification.json) | [signed-krl-v1.md](../../docs/spec/artifacts/signed-krl-v1.md) | Committed mode/status/violation tuples; no expectation writer located. V.signValidKrl builds signed envelopes at runtime. | V only. | reference-generated | Core signedKrlSigningPayload, signEd25519 and verifySignedKrl are reused in the consumer. Portable docs artifacts do not give these distinct fixtures independent provenance. |
| [package-snapshot-hash](../../packages/conformance/vectors/snapshot-hash.json) | [verification-v1.md](../../docs/spec/verification/verification-v1.md) | E.extractSnapshotHash: Core encode/decodeCanonicalState and verifySnapshot produce snapshot_base64/state_hash. | V; D/A blocked. | reference-generated | The same Core codec/verifier supplies extraction and validation. A reads frozen snapshot expectations. |
| [package-trusted-time](../../packages/conformance/vectors/trusted-time.json) | [trusted-time-v1.md](../../docs/spec/core/trusted-time-v1.md) | Committed decisions/reasons, timestamps, sequence state and exception expectations; no writer located. | V; dedicated validate-trusted-time.ts and trustedTimeConformance.test.ts call T. No Go/Python engine consumer. | reference-generated | T imports Core PolicyEngine, signing and verification. Spec formulas explain intent but do not document independent origin of the complete heterogeneous expectations, including runtime errors. |
| [rust-authorization-example](../../examples/rust-verifier/auth_case.json) | [authorization-v1.md](../../docs/spec/artifacts/authorization-v1.md) | Committed auth_case.json signature/hash fields, supporting keyset.json; expected statuses/codes live in Rust tests. No fixture writer located. | Rust reconstructs signing payload/preimage and verifies with its own implementation. | reference-generated | Four tests consume/mutate one committed artifact. No independent provenance for that artifact or full fixture/test expectation set is demonstrated. |

### Consumer locations and independence boundary

The following completes the locations behind the table's consumer descriptions.
Package V/D/A bindings are specified per corpus above and in the registry;
maintenance E is not an independent verifier.

| Surface | Consumer locations | Independent reconstruction established by source |
|---|---|---|
| Docs canonicalization | [TS](../../scripts/verify-canonicalization-vectors.ts), [Go](../../go-harness/canonicalization_verify.go), [Python](../../python-harness/verify_canonicalization_vectors.py), [guard](../../packages/guard/src/test/gateway.vectors.test.ts) | Go/Python parse inputs and recompute canonical JSON/hash locally. G and TS contain duplicated canonicalization logic rather than independent generation. |
| Docs authorization / PEP | [authorization JS](../../scripts/verify-authorization-vectors.mjs), [PEP JS](../../scripts/verify-pep-vectors.mjs), [guard](../../packages/guard/src/test/gateway.vectors.test.ts) | JS uses local canonicalization/Node crypto; guard uses Core. PEP loads authorization fixtures as dependencies. Local verification is not a record of their generation. |
| Docs delegation | [delegation JS](../../scripts/verify-delegation-vectors.mjs) | Locally rebuilds canonical parent hash and signature input; no independent-language producer identified. |
| Profile-C | [Go](../../go-harness/profile_c_verify.go), [Python](../../python-harness/verify_profile_c_vectors.py), V | Modes 001–005 compute state comparisons locally; 006–008 reconstruct Encoding B preimages, verify committed signatures, and recompute committed/live hashes. No expected-value writer is identified by these consumers. |
| Docs SignedKRL | [Go](../../go-harness/signed_krl_verify.go), [Python](../../python-harness/verify_signed_krl_vectors.py) | Rebuild payload excluding only `signature.sig`, canonicalize, prepend `OXDEAI_KRL_V1\n`, and verify with Go crypto / Python's [libcrypto helper](../../python-harness/ed25519_utils.py). No TypeScript-produced intermediate preimage is required to consume the fixture. |
| Trusted-time | V, [dedicated validator](../../packages/conformance/src/validate-trusted-time.ts), [tests](../../packages/conformance/src/trustedTimeConformance.test.ts), T | All use T/Core; no independent engine reconstruction established. |
| Rust example | [tests](../../examples/rust-verifier/tests/verify_authorization.rs), [verifier](../../examples/rust-verifier/src/verify_authorization.rs), [canonicalizer](../../examples/rust-verifier/src/canonical.rs), [supporting keyset](../../examples/rust-verifier/keyset.json) | Reconstructs its bundled artifact's preimage and checks signature/expiry; does not consume either vector tree. |

Independent reconstruction here concerns **consumption/verification only**.
Neither independent language code nor a standard crypto library demonstrates
independent origin of the committed expected bytes, hashes, signatures or
outcomes. Some V cases even rebuild and sign inputs at runtime rather than use
all committed input fields (notably delegation chain/signature and envelope
cases). This is a consumer limitation, not a reason to rewrite fixtures here.

### Count interpretation

- **23 corpora** have only `reference-generated` classifications in this audit.
- **1 mixed corpus**, `docs-canonicalization-v1`: three rejection outcomes are
  `spec-derived`; eight positive fixtures and the three exact error-code
  expectations are conservatively `reference-generated`.
- **0 wholly spec-derived corpora; 0 independently-derived corpora/expectations
  demonstrated.** All 24 contain expectations classified `reference-generated`;
  therefore a single conservative corpus-level roll-up would be 24 in that class.

These are corpus counts plus an explicit canonicalization field split, not
counts of runtime assertions or an assertion that every other rejection outcome
is impossible to derive from the spec. Other complete expectation sets retain
the conservative classification because independent derivation of those sets
has not been established. Normative motivation alone does not promote their
hashes, signatures, exact violation messages or ordering.

## 4. Canonicalization rejection audit

The authoritative file has **11 cases: eight positive, three rejection**.
G's `main` returns error vectors unchanged; it computes only positive canonical
JSON and SHA-256 fields. Thus G is not evidence that the error fixtures were
originally generated by executing its rejection paths.

The independent derivation of the three rejection outcomes is direct:

| Case / input | Exact governing requirement | Audited classification |
|---|---|---|
| `i1-float-rejected`: `{"value":1.5}` | [Canonicalization §6](../spec/core/canonicalization-v1.md#6-serialization-rules-normative): “Floating-point values and `NaN`/`±Inf` MUST be rejected.” | `status: error` is **spec-derived**: 1.5 is fractional. |
| `i3-string-timestamp-rejected`: `{"ts":"2026-04-03T12:00:00Z"}` | [Canonicalization §6](../spec/core/canonicalization-v1.md#6-serialization-rules-normative): “Timestamps: if the object key is exactly `"ts"`, the value MUST be an integer within the safe range; otherwise canonicalization MUST fail.” | `status: error` is **spec-derived**: the value is a string, not an integer. |
| `i4-float-timestamp-rejected`: `{"ts":1712448000.5}` | Same §6 timestamp requirement; the §6 floating-point rejection requirement also applies. | `status: error` is **spec-derived**: the timestamp is non-integral. |

**Exact error codes are a separate expectation.** The committed values are
`FLOAT_NOT_ALLOWED`, `INVALID_TIMESTAMP`, `INVALID_TIMESTAMP`, respectively.
[§7 and §7.1](../spec/core/canonicalization-v1.md#7-error-codes-normative) explicitly
state: “The error codes above are SHOULD-level interoperability recommendations.
The requirement to reject the corresponding invalid inputs is MUST-level.”
The spellings have textual support as recommendations, but the MUST-level
rejection proof does not establish a mandatory exact diagnostic or original
independent derivation of those fields. They retain `reference-generated`
classification under the conservative rule. In particular, this audit does not
infer a MUST-level error-precedence rule for the float timestamp.
[Conformance §3.2](../spec/conformance/conformance-v1.md#32-canonicalization-tests)
requires matching codes where a vector makes them normative; designation of a
fixture as normative does not independently prove how its code was derived.
This audit changes neither the fixture assertions nor that conformance contract.

There are **no committed canonicalization rejection cases** in this corpus for
duplicate keys, unsupported runtime types, unsafe integers, invalid UTF-8 or
other structurally invalid inputs. Do not count implemented rejection branches
or required test classes as existing vectors:

- [§5](../spec/core/canonicalization-v1.md#5-input-parsing-requirements) requires
  duplicate detection during parsing and rejection of inputs that cannot be
  deterministically parsed; §6 explicitly says to reject duplicates after NFC
  normalization. No duplicate-key fixture is present; do not infer more about
  raw-parser behavior than these clauses say.
- §6 requires rejection of functions, symbols and `undefined`;
  [§9](../spec/core/canonicalization-v1.md#9-forbidden-types) lists additional
  forbidden runtime types. No such fixture is present. JSON input cannot directly
  carry many of these runtime values.
- §5 requires invalid UTF-8 to cause failure; §6/§10 constrain numeric integers.
  `v5-safe-integer` and `v6-bigint-as-string` are positive examples, not unsafe
  numeric rejection tests. The latter supplies a JSON string, not runtime BigInt.

The eight positive fixtures remain `reference-generated` even where their
serialization looks readily derivable: the repository supplies G's implemented
computation, not an independent derivation record for those committed byte/hash
pairs. No positive expected value was recomputed or replaced for this audit.

## 5. Evidence limitations

Independent corpus consumption does not prove independent expectation derivation.
Multiple-language agreement does not prove specification correctness. A passing
corpus cannot prove more authority than its provenance permits. Generated
expected values must not be presented as independently normative without evidence.

The audit inspected the registry, specifications, committed expectations,
generator/consumer sources and relevant file history. For example, commits
`ada998d` (portable Profile-C/KRL), `85dfe95` (Encoding B) and `9b71e21` (Rust
artifacts) introduce fixtures/consumers but do not supply a separate independent
expected-value production record. Historical package refreezes and E's explicit
Core dependencies reinforce the need to distinguish freeze stability from
provenance. Missing writers are recorded as evidence gaps, never as proof of
manual authorship or independent generation.

Specific unresolved gaps are the original derivation of docs authorization,
PEP, delegation, Profile-C and SignedKRL expectations/artifacts; the Rust artifact;
and package expectations lacking a current extraction path. Complete negative
result tuples can include implementation-specific messages/order and assumptions
about earlier signature/hash checks. Their normative motivation is not blanket
proof of the tuples' provenance. Trusted-time includes spec-motivated arithmetic
and rejection scenarios alongside TypeScript configuration/error expectations;
no independent production record for that complete set was found.

Profile-C's projection adds no independent evidence. Existing descriptions that
call the docs/package KRL files mirrors do not override the registry's distinct
corpus ownership. The optional package adapter is blocked and contains lookup
paths; it is not additional passing language evidence. The unresolved
CANON-ESC-001 limitation in [the authority document](corpus-authority.md#canon-esc-001-boundary)
is unchanged. No runtime suite was rerun to infer provenance.

## 6. Freeze impact

For #254 `S_freeze`, this audit supports a bounded inventory/provenance statement:
24 registered corpora have identified authorities and consumer paths; three
canonicalization rejection outcomes are directly justified by normative MUST
rules; the remaining audited expectation sets retain the conservative
`reference-generated` classification. Registry/projection checks establish
representation consistency, not independent normative authority.

Freeze evidence may cite separately executed runtime results as agreement with
those committed fixtures, scoped to actual consumers and cases. It must not claim
independent normative corpus authority for `reference-generated` expectations,
count Profile-C twice, or treat a reference/corpus disagreement as automatically
a defect in an independent consumer. The governing specification remains the
basis for resolving a disagreement.

Phase 1 records this limitation; it does not remediate corpus independence,
upgrade spec-claim evidence levels, clear unrelated freeze gates, or establish
unqualified 2.0 readiness. Acceptance of the bounded limitation is distinct from
completion of future remediation.

## 7. Post-2.0 remediation candidates

- Manually spec-derived expectations with reviewable derivations.
- Independent generators that do not reuse reference implementation logic.
- Normative rejection vectors directly traceable to MUST/MUST NOT text.
- Adversarial vectors intentionally capable of failing the reference implementation.

## Validation record

Exact validation commands run from the repository root:

```sh
node scripts/corpus/verify-authority.mjs
node scripts/corpus/profile-c.mjs --check
python3 /tmp/verify-325-audit.py
git diff --check
git status --short
```

Both repository validators passed. The audit-specific scratch Python check
passed: exactly 24 unique registry rows, correct authority/spec links, 23
`reference-generated` rows and one mixed row, no final `unknown` classification,
all local file links resolving, and no trailing whitespace. Its first run had a
column-index error in the scratch checker; correcting that checker required no
change to the audit classifications or repository data.

The scratch check also compared all **26 registered representation/support
files** directly against `git show 178ee48:<path>` and found byte equality. It
checked that no tracked file differs from that base and the sole untracked
repository addition is this document. The script is validation tooling in
`/tmp`, not a new repository test or provenance schema.

Source inspection used `cat`, `sed`, `rg`, JSON inventory reads, `git log` and
`git show`; no extraction/generation command or runtime conformance suite was
executed. No corpus contents or expected values were modified or regenerated.
No commit was made.
