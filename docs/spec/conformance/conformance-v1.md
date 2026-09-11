# ETA Conformance Specification v1

## 1. Purpose

This specification defines the conformance requirements for Execution-Time Authorization (ETA) implementations.

ETA conformance is intended to establish that independent implementations:

- behave deterministically within the conformance surfaces they implement
- apply OxDeAI canonicalization rules consistently
- fail closed on invalid, unverifiable, or ambiguous authorization inputs
- produce verifiable and reproducible authorization artifacts and outcomes
- enforce the authorization boundary so that execution cannot proceed without valid authorization
- produce compatible results across independent implementations that claim the same conformance surface

Conformance is evaluated against the normative specifications and official conformance vectors identified by this document.

---

## 2. Conformance Definition

An implementation is ETA-conformant for a declared conformance surface if and only if it satisfies every mandatory requirement applicable to that surface.

The core conformance categories are:

1. deterministic evaluation
2. canonicalization compliance
3. fail-closed behavior
4. non-bypassable enforcement
5. artifact correctness and verification
6. cross-implementation consistency

Failure of any mandatory requirement applicable to the declared surface results in non-conformance for that surface.

An implementation MUST NOT claim support for a category, profile, artifact, or runtime surface that it does not actually implement.

Unsupported categories MUST be reported as unsupported, not emulated solely to claim parity.

---

## 3. Conformance Test Categories

### 3.1 Determinism Tests

**Goal:** identical trusted inputs produce identical observable authorization results.

Test:

Run authorization repeatedly with identical:

```text
(intent, authoritative state, policy, trusted evaluation inputs)
```

as applicable to the tested surface.

Requirements:

- the decision MUST be identical
- deterministic reason-code output MUST be identical
- when an artifact is deterministically produced from identical inputs, its canonical representation MUST be byte-identical
- hashes over identical canonical representations MUST be identical

Failure conditions include:

- decision drift
- reason-code drift where ordering is normative
- canonical-byte mismatch
- hash mismatch
- deterministic artifact mismatch

Determinism requirements do not authorize an implementation to re-read mutable ambient state or clocks when the underlying specification requires those values to be explicit evaluation inputs.

---

### 3.2 Canonicalization Tests

**Goal:** ensure stable canonical representation across conforming implementations.

Required test classes include:

- object key reordering
- nested structures
- Unicode NFC normalization
- integer boundary handling
- floating-number rejection
- duplicate-key rejection

Requirements:

- equivalent valid inputs MUST produce identical canonical bytes
- canonical JSON MUST match the normative expected value
- SHA-256 output MUST match where defined by the vector
- invalid canonicalization inputs MUST fail closed
- expected canonicalization error codes MUST match where the vector makes the code normative

The normative portable canonicalization vector source is:

```text
docs/spec/test-vectors/canonicalization-v1.json
```

---

### 3.3 Fail-Closed Tests

**Goal:** ensure that invalid, unverifiable, ambiguous, or unsupported conditions cannot result in authorized execution.

Representative injected failures include:

- missing required policy or trusted configuration
- malformed protocol input
- canonicalization failure
- artifact verification failure
- unknown signing key
- inactive signing key
- unresolved issuer or trust configuration
- ambiguous key resolution
- invalid trusted state
- invalid required configuration

Requirement:

```text
failure or ambiguity
-> no valid authorization outcome
-> no execution
```

Where the governing specification defines a protocol `DENY`, the implementation MUST return `DENY`.

Where the governing specification requires refusal before policy evaluation, such as invalid mandatory configuration, the implementation MUST refuse evaluation rather than coercing the condition into an `ALLOW` or fabricating a policy `DENY`.

No fail-closed condition may result in execution.

---

### 3.4 PEP Gateway Boundary Tests

**Goal:** prove that execution cannot bypass the authorization boundary.

Required tests include:

- direct access to a protected upstream execution path without the required internal authorization context MUST be rejected
- the gateway MUST expose the structured authorization behavior defined by `pep-gateway-v1`
- an authorization artifact that fails required verification MUST NOT reach the protected upstream
- replay of a consumed `auth_id` MUST be denied where the profile requires authorization replay protection

For the reference PEP gateway surface, direct unauthorized upstream access MUST return the gateway-defined rejection response, including HTTP `403` where specified by `pep-gateway-v1`.

Passing artifact-verification tests alone is insufficient to establish PEP non-bypassability.

The execution boundary itself MUST be exercised.

---

### 3.5 Authorization Verification Tests

**Goal:** ensure that `AuthorizationV1` artifacts are accepted only after all applicable verification requirements succeed.

Applicable checks include:

- artifact structure
- signature
- signing-key resolution and lifecycle
- audience binding
- expiry
- `intent_hash`
- policy binding
- required trust configuration
- other profile-specific verification requirements

Any verification failure MUST invalidate the authorization.

An invalid authorization MUST NOT authorize execution.

---

### 3.6 Authorization Binding Tests

**Goal:** prove that an authorization cannot be reused outside the exact authority it represents.

Required tests include attempts to reuse an authorization with:

- modified intent
- incompatible execution context
- a different policy where policy binding applies
- a different audience where audience binding applies
- other values that are cryptographically or normatively bound by the artifact

Requirements:

- a changed bound value MUST invalidate verification
- a valid authorization MUST NOT be transferable to an incompatible execution request

A state-binding claim MUST only be made where the relevant specification actually commits the authorization to that state or to a normative state-derived value.

Conformance MUST NOT infer bindings that the artifact does not encode.

---

### 3.7 Replay Protection Tests

**Goal:** verify replay resistance where replay protection is normative for the tested artifact or execution profile.

For authorization execution:

```text
first valid consumption
-> may execute

subsequent prohibited reuse
-> MUST NOT execute
```

Replay tests MUST use the replay identifier and replay scope defined by the relevant artifact or profile.

Three boundaries MUST remain distinct:

1. **Implementation conformance:** authenticate/verify before authoritative replay
   mutation; consume before protected execution; unauthenticated input MUST NOT
   mutate trusted replay state. Required replay-state unavailability or an
   indeterminate result MUST prevent protected execution.
2. **Normative store contract:** atomic consume permits at most one success for
   the same identifier/domain under concurrency, retains consumed IDs throughout
   their possible acceptance window, and never treats store failure as success.
   No backend technology is mandated; see [verification §4.3](../verification/verification-v1.md#43-replay-store-contract-and-deployment-boundary).
3. **Deployment compliance:** restart persistence, replica sharing/visibility,
   persistence configuration, topology, HA/SLA and recovery guarantees require
   deployment-specific evidence. Generic conformance MUST NOT be presented as
   proof of these properties.

The replay domain MUST be declared/configured; local code cannot infer every
valid deployment boundary. “Same security history implies the same decision” is
only meaningful with the same trusted inputs and available, authoritative replay
state. Loss or unavailability of required history MUST fail closed rather than
reconstructing a permissive decision from missing state.

Consumed means entitlement spent, not effect completed. A crash after consume
and before effect can spend an authorization without execution. The current
corpus does not prove crash/restart behavior, arbitrary concurrent interleavings
or deployment persistence. Guard tests cover selected shared-instance and error
paths; the Redis unit tests use an in-memory fake and selected concurrency/TTL
cases. Neither those tests nor portable replay vectors certify a deployed
backend's durability. They do not weaken its required store contract.

Replay semantics MUST NOT be generalized across artifacts.

For example, the presence of an optional nonce in an artifact does not establish replay protection unless its specification defines the required replay-state behavior.

---

### 3.8 Artifact Verification Tests

**Goal:** ensure that artifacts can be independently authenticated and validated.

Applicable tests include:

- signature verification
- canonical signing-input reconstruction
- cryptographic hash binding
- issuer and signing-key resolution
- key lifecycle validation
- mutation of signed payload fields
- malformed artifact input

Requirements:

- tampered artifacts MUST fail verification
- correctly formed and validly signed artifacts MUST verify successfully when all other applicable conditions hold
- implementations MUST reproduce artifact-specific signing and encoding rules exactly

Signing rules from one artifact family MUST NOT be assumed to apply to another artifact family.

---

### 3.9 Delegation Tests

This category applies only to implementations that claim `DelegationV1` support.

**Goal:** ensure delegated authority never exceeds its valid parent authority.

Applicable requirements include:

- the delegation MUST be signed and verifiable
- the parent `AuthorizationV1` MUST be valid
- delegated scope MUST be strictly narrowing according to `delegation-v1`
- parent binding MUST succeed
- policy binding MUST succeed
- the single-hop invariant MUST be enforced
- applicable expiry rules MUST be enforced
- any verification or narrowing failure MUST prevent execution

An implementation that does not implement DelegationV1 MUST report the category as unsupported rather than passing it through a stub or emulation.

---

### 3.10 Cross-Implementation Tests

**Goal:** establish portable behavior across independent implementations.

Current implementation families may include:

- TypeScript
- Go
- Python
- other independent implementations added later

For every conformance surface jointly claimed by two or more implementations, applicable portable vectors MUST produce the same normative outputs.

Depending on the vector category, this can include:

- identical canonical bytes
- identical expected hash
- identical verification result
- identical normative reason code
- identical deterministic artifact representation

Cross-language equality is required only for semantics defined as portable by the corresponding specification.

Implementations MUST NOT fabricate support for unavailable runtime surfaces merely to report cross-language parity.

---

### 3.11 Non-Bypassability Tests

**Goal:** establish that no protected execution path exists without valid authorization.

This is a critical conformance category.

Required adversarial scenarios include:

- direct execution without authorization
- skipped authorization step
- partial artifact verification
- invalid authorization presented to the executor
- replay where replay rejection is required
- failure between authorization verification and execution-boundary admission

Requirement:

```text
no valid authorization
-> no protected execution
```

Any protected execution that occurs without satisfying the required authorization boundary is a conformance failure.

---

## 4. Official Conformance Vector Sources

A conformant implementation MUST pass all active official vectors applicable to the conformance surfaces it claims.

Normative or profile-defined vector sources currently include:

```text
docs/spec/test-vectors/canonicalization-v1.json
docs/spec/test-vectors/authorization-v1.json
docs/spec/test-vectors/pep-vectors-v1.json
docs/spec/test-vectors/signed-krl-v1.json
packages/conformance/vectors/trusted-time.json
```

Artifact-specific specifications MAY designate an additional normative portable source and implementation-specific mirrors.

Where another normative specification designates a vector file as the source of truth for that artifact, that designation is incorporated into ETA conformance for implementations claiming that artifact.

### 4.1 Vector requirements

Official vector suites MUST include the cases required by their governing specification, including applicable:

- valid cases
- invalid cases
- boundary cases
- malformed cases
- adversarial cases

A vector MUST define enough information to determine its normative expected behavior.

Depending on category, this may include:

- input
- canonical output
- expected hash
- expected decision
- expected reason code
- expected verification result
- expected state transition

Fields that do not apply to a particular vector category are not required merely for schema uniformity.

---

## 5. Runnable Conformance Harnesses

Implementations SHOULD provide runnable harnesses that consume the applicable official vectors and exit non-zero on any active-vector mismatch.

Current repository entry points include:

```text
pnpm test:vectors:ts
pnpm test:vectors:go
pnpm test:vectors:py
pnpm test:vectors:auth
pnpm test:vectors:pep
pnpm test:vectors:trusted-time
pnpm test:vectors:all
```

Repository commands are implementation metadata rather than portable protocol semantics.

For a harness that claims conformance over a vector category:

- every applicable active vector MUST execute
- every mismatch against a normative expected result MUST cause a non-zero result
- malformed vector data MUST NOT silently count as passing
- skipped required vectors MUST NOT count as passing

---

## 6. Trusted-Time Vector Schema

The trusted-time corpus:

```text
packages/conformance/vectors/trusted-time.json
```

uses strict schema version:

```text
1.0.0
```

and a category-discriminated `vectors` collection.

Each vector MUST contain:

- an ID unique within the corpus
- an explicit `active` or `pending` status
- a description
- category-specific input
- category-specific expected behavior

A pending vector MUST contain a non-empty:

```text
blocked_by
```

Pending vectors MUST be reported separately.

Pending vectors MUST NOT count as passing.

### 6.1 Explicit clock domains

Trusted-time vectors MUST use explicit clock-domain names where applicable, including:

- `intent_timestamp`
- `evaluation_time`
- `authorization_issued_at`
- `authorization_expiry`
- `nonce_first_seen_time`
- `velocity_window_start`
- `tool_window_start`
- `verifier_time`

Generic or overloaded timestamp fields are forbidden by the trusted-time vector schema.

This prevents vector schemas from erasing distinctions between untrusted intent time and trusted evaluation or verification time.

### 6.2 Trusted-time corpus validation

Before executing trusted-time vectors, the TypeScript reference runner rejects:

- duplicate vector IDs
- unknown categories
- unknown fields
- malformed status values
- unsupported public reason codes
- malformed protocol-second values
- unsafe protocol-second integers

Active vectors execute against the applicable Core reference surfaces.

Active trusted-time vectors are release-blocking through the repository validation paths that include them.

### 6.3 Stateful tool-window coverage

The active `tool_window` category exercises stateful tool-call sequences through the Core policy evaluation surface.

Coverage includes:

- trusted window creation
- caller timestamp non-interference
- denial without quota consumption
- exact-boundary expiry
- backward trusted-time handling
- malformed persisted state
- exact state propagation
- deterministic repeated execution

---

## 7. Language and Runtime Coverage

Conformance coverage MUST be reported by actual implementation surface.

The current TypeScript reference implementation executes all active trusted-time categories defined by its conformance runner.

Current Go and Python harnesses claim only the surfaces they actually implement, including applicable:

- canonicalization
- supported authorization verification profiles
- SignedKRL verification

They do not expose the TypeScript `PolicyEngine` runtime surfaces required for:

- policy freshness evaluation
- authorization issuance
- stateful replay evaluation
- velocity evaluation
- tool-window evaluation
- standalone trusted-time authorization surfaces not implemented in those runtimes

Unsupported runtime categories MUST NOT be emulated solely to claim parity.

All implementations MUST enforce the protocol numeric domain, including the JavaScript safe-integer bound, in every category they claim.

---

## 8. Pending and Incomplete Conformance Coverage

Locked portable vectors currently exist for the surfaces designated by their governing specifications.

DelegationV1 is currently validated through code-level harnesses rather than a complete locked portable vector corpus.

Additional locked delegation vectors MAY be introduced in a future conformance version.

The absence of a portable vector suite MUST be reported as an evidence limitation.

It MUST NOT be converted into a claim that cross-language conformance has been established.

Pending vectors and unsupported categories never count as successful conformance evidence.

---

## 9. Verification Ordering

Verification behavior MUST be deterministic.

Where a governing specification defines a normative verification order, implementations MUST preserve its observable semantics.

Where official vectors define the expected reason code for an overlapping-failure case, a conforming implementation MUST produce that expected result.

Implementations MUST NOT:

- short-circuit inconsistently across identical inputs
- produce non-deterministic reason sets
- reorder checks in a way that changes a normative externally observable result

This specification does not invent a verification order for artifacts whose governing specification leaves the order unspecified.

---

## 10. Failure Semantics

Any unresolved protocol ambiguity at a security boundary MUST fail closed.

Examples include:

- parsing uncertainty
- canonicalization failure
- key resolution failure
- multiple conflicting key matches
- undefined required behavior
- invalid trusted state
- invalid mandatory trust configuration

Fail-closed means:

```text
the condition cannot authorize execution
```

The exact failure representation is determined by the governing specification.

It may be:

- a protocol `DENY`
- an artifact-verification failure
- a gateway rejection
- refusal to evaluate because required configuration is invalid

An implementation MUST NOT fabricate an `ALLOW`, silently normalize an invalid security-critical condition, or execute through an unresolved ambiguity.

---

## 11. Reference and Independent Implementations

A conformant ETA ecosystem MUST provide:

- at least one maintained reference implementation
- independently implemented verification coverage in at least two implementation languages for portable surfaces claimed as cross-language
- reproducible conformance harnesses
- official portable vectors for the claims represented as cross-language conformance

The reference implementation is not permitted to override the normative specifications or normative vectors.

Where reference code, prose specification, and normative vector evidence disagree, the disagreement MUST be reported and resolved rather than silently treating implementation behavior as the protocol definition.

Independent harnesses SHOULD reconstruct portable cryptographic inputs independently rather than consuming intermediate values generated by the reference implementation.

---

## 12. Conformance Output

A conformance run MUST report:

- pass/fail by applicable test category
- failed vector identifiers
- unsupported categories
- pending vectors
- reproducible result data sufficient to investigate mismatches

Where logs are produced for deterministic conformance results, their normative result content MUST be reproducible.

Non-semantic runtime metadata such as wall-clock duration, process IDs, or filesystem paths need not be byte-identical.

Optional output MAY include:

- hash of a normalized conformance result
- CI integration metadata
- implementation version
- source revision
- conformance profile identifier

---

## 13. Minimal Conformance Criteria

An implementation MAY claim ETA conformance only when:

- 100% of required active vectors applicable to its declared surface pass
- no required active vector is silently skipped
- no unresolved deterministic mismatch exists
- no protected execution bypass exists for the claimed enforcement surface
- every applicable invalid or ambiguous condition fails closed
- unsupported categories are declared honestly
- pending vectors are not represented as passing evidence

A successful conformance run for one surface MUST NOT be generalized into conformance for unsupported surfaces.

Examples:

```text
canonicalization conformance
!= PEP enforcement conformance
```

and:

```text
artifact verification conformance
!= non-bypassability proof
```

---

## 14. Security Guarantees and Non-Guarantees

Successful conformance provides evidence, within the tested and declared surface, of:

- deterministic protocol behavior
- canonical byte stability where applicable
- artifact integrity verification
- required cryptographic binding
- fail-closed handling
- replay resistance where replay protection is normative and tested
- enforcement integrity where the execution boundary is actually exercised
- cross-implementation compatibility for jointly supported portable surfaces

Conformance does NOT by itself guarantee:

- correctness of application policy logic
- correctness or truth of external authoritative state
- absence of misuse that remains valid under the configured policy
- operating-system or runtime security outside the authorization boundary
- security properties belonging to an unsupported profile
- availability or freshness properties not defined by the relevant artifact
- non-bypassability when only a pure verifier has been tested

Conformance evidence MUST NOT be used to claim properties outside the tested normative surface.

---

## 15. Invariant Summary

ETA conformance links the following properties:

```text
normative input
-> canonical representation
-> stable bytes
-> stable cryptographic binding
-> deterministic authorization / verification result
-> valid artifact where applicable
-> enforcement at the execution boundary
```

For every protected execution path:

```text
valid required authorization
-> execution MAY proceed

missing, invalid, unverifiable, or ambiguous required authorization
-> NO EXECUTION
```

The top-level enforcement invariant is:

```text
No valid authorization
-> no protected execution path
```

Conformance evidence for an earlier stage of the chain MUST NOT be interpreted as proof that later stages are enforced unless those stages are themselves exercised by the applicable conformance surface.
## Scoped conformance evidence

Repository conformance reports MUST bind PASS/FAIL to an explicit machine-readable
`evidenceScope`, as defined in [the evidence-scope contract](../../conformance/evidence-scope.md).
A PASS applies only to the declared consumers, runtimes and exercised cases.
`coveredClaims` identifies only the explicitly mapped evidence supports statements;
it MUST NOT imply all obligations or evidence levels of a claim were demonstrated.
`excludedClaims` MUST be derived from the registered claim inventory minus the
claims supported by that selected evidence. Unmapped or ambiguous evidence MUST
NOT silently acquire coverage. Exclusion alone is not a test failure.

Corpus provenance bounds authority: reproducing reference-generated expected
values MUST NOT be presented as independent normative derivation. Structural
validation MUST NOT imply semantic proof. Evidence scope MUST NOT imply deployment
properties, non-bypassability or later execution stages unless those properties
were specifically exercised and mapped. Legacy assertion logs and internal
artifact verification responses are not scoped conformance reports.
