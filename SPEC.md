# OxDeAI Specification (v1.3.0)

 See: docs/spec/core/eta-core-v1.md for the minimal Execution-Time Authorization profile. Canonicalization, authorization, PEP and delegation have distinct checked-in vector/harness surfaces. Root Go and Python CI validators consume canonicalization, Profile-C and SignedKRL; authorization/PEP/delegation corpus coverage is TypeScript/JavaScript-only. Profile-C has one docs authority and a generated package representation; see docs/conformance/corpus-authority.md. AuthorizationV1, PEP Gateway, and DelegationV1 are specified as Stable normative artifacts. SPEC overall remains v1.3.0.
 

> **Status of this document:** This root `SPEC.md` is a versioned index and overview of the
> specification. The normative protocol definitions live in `docs/spec/**`. If any statement
> in this file conflicts with `docs/spec/**`, the documents under `docs/spec/**` are authoritative.

Other documents (e.g. under /protocol) are companion references and must not be treated as normative.

This document defines the OxDeAI execution authorization protocol.

OxDeAI is a portable, language-agnostic protocol for deterministic pre-execution authorization and post-execution evidence verification in autonomous systems.

Artifact stability is defined per artifact. The SPEC version (v1.3.0) does not imply instability of individual artifacts. AuthorizationV1, DelegationV1, and the PEP Gateway are Stable normative artifacts as defined in docs/spec/**.

## Document Model

* `docs/spec/**` → normative (protocol definitions)
* `docs/**` → non-normative (guides, architecture, examples)

If a conflict exists, `docs/spec/**` is authoritative.

## Specification Index

### Core

* `docs/spec/core/canonicalization-v1.md`
* `docs/spec/core/eta-core-v1.md`

### Artifacts

* `docs/spec/artifacts/authorization-v1.md`
* `docs/spec/artifacts/delegation-v1.md`

### Enforcement

* `docs/spec/enforcement/pep-gateway-v1.md`

### Verification

* `docs/spec/verification/verification-v1.md`

### Conformance

* `docs/spec/conformance/conformance-v1.md`
* `docs/spec/conformance/test-vectors-v1.md`

The protocol defines:

- portable authorization artifacts
- deterministic policy evaluation requirements
- canonical signing and verification rules
- a relying-party execution contract
- verifiable evidence artifacts

OxDeAI separates authorization decision logic from execution.
A Policy Decision Point (PDP) evaluates whether an action is allowed.
A Policy Enforcement Point (PEP) verifies authorization artifacts and executes the action only if verification succeeds.

The TypeScript implementation in this repository is the reference implementation of this protocol, but conformant implementations MAY exist in any language if they reproduce the same artifacts and verification behavior.

```
No valid authorization
→ no execution path
```

Normative protocol text uses RFC 2119 terms: MUST, MUST NOT, SHOULD, SHOULD NOT, MAY.

Note: current corpus authorities, publication status and actual consumers are listed in docs/conformance/corpus-authority.md. Existing delegation harness vectors are not a claim of a complete portable delegation corpus.

## 1. Scope

OxDeAI defines deterministic pre-execution authorization and post-execution evidence verification for autonomous systems.

The 2.0 reference implementation implements the pre-execution authorization boundary (AuthorizationV1, DelegationV1, PEP Gateway). Post-execution evidence verification is a protocol-defined direction; `ExecutionReceiptV1` remains planned and is not part of the stable 2.0 implementation surface (see Protocol Status in README.md).

A conformant implementation MUST produce deterministic outputs for equivalent inputs and MUST enforce the relying-party verification contract before execution occurs.

The protocol defines portable artifacts that can be issued by one system and verified by another, including across language runtimes or infrastructure boundaries.

OxDeAI is protocol-first:

- this repository provides the reference implementation
- other implementations MAY exist in other languages
- conformance is defined by protocol artifacts and verification behavior

Implementations are compliant if they reproduce the protocol artifacts defined in this specification and satisfy the conformance vectors for the targeted version profile.

## 2. Core Artifacts

OxDeAI defines the following first-class protocol artifacts.
These artifacts are language-independent and MUST be interpreted identically across compliant implementations.

- Intent
- CanonicalState snapshot
- AuthorizationV1
- DelegationV1
- Audit events (hash chained)
- VerificationEnvelopeV1
- VerificationResult
- KeySet

## 3. Determinism Requirements

Determinism is a core protocol invariant.

For identical `(intent, state, policy configuration)` inputs, a conformant implementation MUST produce identical authorization decisions and identical signed artifacts.

Implementations MUST use canonical encoding for signed and hashed payloads.
Verification ordering and violation ordering MUST be deterministic.
Policy-critical logic MUST NOT depend on ambient randomness.
Malformed or ambiguous artifacts (including canonicalization failure) MUST be treated as DENY/fail-closed.

### 3.1 Evaluation Semantics

The core evaluation model is:

```
(intent, state, policy) → deterministic decision
```

The following requirements govern this model:

- `state` MUST be an explicit, discrete input to evaluation.
- `state` MUST be deterministic for a given evaluation: the same `state` value MUST produce the same decision when paired with the same `intent` and `policy`.
- Evaluation MUST NOT depend on implicit or external mutable context.
- Evaluation MUST be side-effect-free with respect to the input `state`.

Implementations MAY maintain an internal mutable working copy of `state` during evaluation to accumulate module deltas. Implementations MUST NOT mutate the input `state` object through any such internal working state.

### 3.2 Policy Version Consistency

`state.policy_version` MUST equal the `policy_version` under which evaluation is performed.

If a mismatch is detected, evaluation MUST fail with:

```
POLICY_VERSION_MISMATCH
```

This check MUST be performed before any policy module runs. A `POLICY_VERSION_MISMATCH` denial is a structural evaluation failure, not a policy decision.

This invariant ensures that authorization artifacts are issued only under the policy version that was in effect when the intent was evaluated, preventing replay of artifacts across incompatible policy versions.

### 3.3 Invariant I5 - Evaluation Isolation

Concurrent evaluations MUST NOT share a mutable state object.

The `state` input to evaluation MUST be treated as an immutable snapshot for the duration of that evaluation. Implementations MUST ensure that each evaluation receives an isolated state instance. Sharing a mutable state object across concurrent evaluations is a protocol violation.

**Rationale.** Evaluation semantics are defined as a pure function of `(intent, state, policy)`. If multiple concurrent evaluations share and mutate the same state object, the outcome of each evaluation becomes dependent on execution order and timing, violating the determinism requirement in Section 3.

**Implications:**

- Implementations MAY internally derive a working copy of state per evaluation.
- Callers MUST provide an isolated snapshot per evaluation call.
- Concurrent evaluations MUST NOT produce cross-call side effects on shared state.

Violation of this invariant results in undefined behavior: evaluations may produce non-deterministic decisions for identical inputs.

## Multi-Language Implementation Profile

OxDeAI artifacts are language-agnostic protocol artifacts.
Compliant implementations MAY be written in any language.

### Normative Requirements

- Implementations MUST use protocol-defined canonical JSON rules.
- Implementations MUST reconstruct identical signing input bytes for signed artifacts.
- Implementations MUST verify Ed25519 signatures over the canonical payload and domain format defined by this protocol.
- Implementations MUST fail closed on:
  - malformed payloads
  - unsupported algorithms
  - unknown key ids
  - signature mismatch
  - verification ambiguity

### Reference Implementation and Compliance

The TypeScript implementation is the reference implementation.
Other implementations are compliant if they satisfy this specification and pass conformance vectors for the targeted version profile.

### Implementer Checklist

Compliant verifier behavior SHOULD include this sequence:

1. Parse artifact and validate required fields.
2. Canonicalize payload deterministically.
3. Reconstruct signing input bytes exactly.
4. Verify signature and key resolution (`alg`, `kid`, issuer trust context).
5. Validate issuer/audience/policy binding constraints.
6. Validate expiry and decision semantics (`ALLOW` when required).
7. Fail closed on any malformed or ambiguous verification state.

## 4. Authorization Artifact (AuthorizationV1)

`AuthorizationV1` is the primary authorization artifact defined by the OxDeAI protocol.

It represents a deterministic authorization decision issued by a Policy Decision Point (PDP) and verified by a relying party, also referred to as a Policy Enforcement Point (PEP).

`AuthorizationV1` is a portable protocol artifact, not an implementation detail.
It is designed to be verifiable independently of the system that produced it.

### Definition

`AuthorizationV1` is a portable authorization artifact issued by the OxDeAI Policy Decision Point (PDP) to permit a specific action under a specific policy state.
It is consumed by a relying party, also referred to as a Policy Enforcement Point (PEP), and MUST be verified before execution.

`AuthorizationV1` is a first-class protocol artifact. It represents a decision bound to identity, audience, intent, state, policy context, and time.

### Mandatory Fields (v1.2)

An `AuthorizationV1` artifact MUST include all of the following fields:

- `auth_id`
- `issuer`
- `audience`
- `intent_hash`
- `state_hash`
- `policy_id` (may be named `policy_version` in artifacts; issuer and verifier MUST use a consistent field name)
- `decision`
- `issued_at`
- `expiry`
- `alg`
- `kid`
- `signature`

Optional extension fields MAY include:

- `nonce`
- `capability`

Implementations MAY carry additional metadata only if such metadata does not change the semantics of mandatory fields.

### Field Semantics

- `auth_id`: Unique authorization identifier for this artifact instance.
- `issuer`: Identifier of the authorization issuer and trust domain.
- `audience`: Identifier of the relying party for which this authorization is valid.
- `intent_hash`: Canonical hash of the intended action to be executed.
- `state_hash`: Hash of the policy state snapshot against which authorization was granted.
- `policy_id`: Identifier of the policy configuration used for evaluation.
- `decision`: Authorization outcome (`ALLOW` or `DENY`).
- `issued_at`: Issuance time as Unix timestamp (seconds).
- `expiry`: Expiration time as Unix timestamp (seconds).
- `alg`: Signature algorithm identifier.
- `kid`: Key identifier used to select the verification key.
- `signature`: Cryptographic signature over the canonical authorization payload.

### Security Properties

`AuthorizationV1` has the following protocol properties:

- Single-use: `auth_id` MUST be treated as consumable exactly once by the relying party.
- Issuer-bound: validity is scoped to a trusted `issuer`.
- Audience-bound: validity is scoped to the designated `audience`.
- Intent-bound: validity is scoped to the exact `intent_hash`.
- State-bound: validity is scoped to the exact `state_hash`.
- Short-lived: validity is bounded by `issued_at` and `expiry`; expired artifacts are invalid.

These properties are mandatory protocol constraints, not operational recommendations.

### Normative Relying-Party Obligations

Before execution, a relying party MUST verify all of the following:

1. `decision == "ALLOW"`.
2. The authorization has not expired (`expiry` is in the future under verifier time policy).
3. `issuer` is trusted for the current trust context.
4. `audience` matches the current relying-party identity.
5. `intent_hash` matches the exact action about to be executed.
6. `state_hash` binding is respected by the execution context.
7. `policy_id` matches the expected policy context.
8. `auth_id` has not already been consumed.
9. `alg` is supported and permitted by local algorithm policy.
10. `kid` resolves to a trusted verification key for the expected issuer.
11. `signature` validates against the canonical payload and resolved key.

If any verification step fails, execution MUST NOT occur.
If verification state is ambiguous (for example, unresolved trust state, inconsistent key material, or parse ambiguity), verification MUST fail closed.
A reused `auth_id` MUST be rejected.

### Non-Forgeable Verification (v1.2)

Non-forgeable verification ensures that authorization artifacts can be validated independently of the issuing system.

Verification MUST depend only on the artifact contents, canonical payload rules, and trusted verification keys.
No verifier may rely on implicit runtime state or undocumented side channels.

In v1.2, `AuthorizationV1` MUST support public-key verification via `alg`, `kid`, and `signature`.

For signed verification:

- The signature MUST be computed over the canonicalized AuthorizationV1 object using `canonicalization-v1` rules, **excluding** the `signature` field value.
- Different artifact classes MUST use distinct signing domains to prevent cross-artifact signature confusion.
- Unsupported algorithms MUST fail closed.
- Canonicalization for authorization payloads MUST follow `docs/spec/core/canonicalization-v1.md`.

Verifiers MUST NOT accept unsigned substitutions for artifacts that require signature validation under local policy.

### Compatibility

Older pre-v1.2 authorization paths MAY exist for backward compatibility.
When legacy paths are supported, they SHOULD be explicitly mode-scoped and MUST NOT be confused with public-key verification mode.
Public-key verifiable `AuthorizationV1` is the preferred v1.2 form.

### Minimal Artifact Example

```json
{
  "auth_id": "auth_01JY7K8Z4V3QH6N2M9P0R1S2T3",
  "issuer": "oxdeai.pdp.prod.eu-1",
  "audience": "payments.api.eu-1",
  "intent_hash": "9f3e5c6ad7a4a2f8a2d93f0f31c65a88f95d7dbef4c9f9e30d5f0f6ce7f4a1b2",
  "state_hash": "4e2b7f1a3d8c6e90b5f3a9d7c1e2f4a6b8d0c2e4f6a8b0c1d3e5f7a9b1c3d5e7",
  "policy_id": "policy_prod_payments_v42",
  "decision": "ALLOW",
  "issued_at": 1770001200,
  "expiry": 1770001260,
  "alg": "Ed25519",
  "kid": "2026-01-main",
  "signature": "Wm9NQjN4d0M1N1dXQ0x4eFZ4Qm5hV2xQbUQ3SzdqQ0x0QnI0U2pQeQ=="
}
```

## 5. Delegation Artifact (DelegationV1)

`DelegationV1` is a signed delegation artifact that allows a principal holding a valid `AuthorizationV1` to delegate authority to a child agent, with scope equal to or more restrictive than the parent's.

`DelegationV1` is locally verifiable without any control-plane interaction.
It is cryptographically bound to the parent `AuthorizationV1` by hash and MUST be verified as a complete chain by the relying party.

`DelegationV1` extends the OxDeAI protocol with delegated agent authorization.
It does not replace `AuthorizationV1`; it derives from it.

### 5.1 Purpose

`DelegationV1` enables a principal that has been authorized by the PDP to sub-authorize a child agent for a narrower set of actions, within the same policy context and time window, without requiring a new PDP evaluation.

The relying party verifies the complete chain - parent `AuthorizationV1` and child `DelegationV1` - before permitting execution.

### 5.2 Mandatory Fields

A `DelegationV1` artifact MUST include all of the following fields:

- `delegation_id`
- `issuer`
- `audience`
- `parent_auth_hash`
- `delegator`
- `delegatee`
- `scope`
- `policy_id`
- `issued_at`
- `expiry`
- `alg`
- `kid`
- `signature`

### 5.3 Field Semantics

- `delegation_id`: Unique identifier for this delegation artifact instance.
- `issuer`: Identifier of the principal that signed the delegation. It selects the KeySet used to verify `signature` (Section 5.8, step 12). It is not required to equal `parent.audience`; the authority binding to the parent is carried by `delegator`. Which issuers a relying party accepts as delegation signers for a given `delegator` is a local trust decision of the relying party, made in addition to key selection (Section 11).
- `audience`: Intended audience for the delegation (typically the delegatee identifier).
- `parent_auth_hash`: SHA-256 hex digest of the canonical parent `AuthorizationV1`, including its `signature` field. Used for cryptographic hash binding to the parent.
- `delegator`: Identifier of the principal granting authority. MUST equal `parent.audience`.
- `delegatee`: Identifier of the agent receiving delegated authority.
- `scope`: Declared authority granted to the delegatee. Its effective scope MUST be equal to or more restrictive than the supplied parent scope. Sub-fields are defined in Section 5.4.
- `policy_id`: Policy context identifier. MUST equal `parent.policy_id`.
- `issued_at`: Issuance time as Unix timestamp (seconds).
- `expiry`: Expiration time as Unix timestamp (seconds). MUST be less than or equal to `parent.expiry`.
- `alg`: Signature algorithm identifier. MUST be `Ed25519` in v1.3.
- `kid`: Key identifier used to select the verification key.
- `signature`: Ed25519 signature over the canonical delegation payload, using the `OXDEAI_DELEGATION_V1` signing domain.

### 5.4 Scope Sub-Fields

The `scope` object MAY carry any combination of `tools`, `max_amount`, `max_actions`, and `max_depth`. For each field, the verifier MUST resolve the effective child scope as follows:

- If the child explicitly supplies a value, use that value.
- If the child omits the field and `parentScope` constrains it, inherit the parent value.
- If neither the child nor `parentScope` constrains the field, it remains unconstrained.

Resolution occurs at verification time, before narrowing comparisons, and MUST NOT modify the signed `DelegationV1` artifact. The following rules refer to the effective child scope:

- `tools`: array of permitted tool or action names. When effective tools are defined, the child agent MUST only execute actions whose name appears in that array.
- `max_amount`: maximum permitted amount for a single action (bigint). Its effective value MUST be less than or equal to `parentScope.max_amount` when the parent constrains that field.
- `max_actions`: optional declared action-count ceiling used for delegation scope narrowing. Its effective value MUST be less than or equal to `parentScope.max_actions` when the parent constrains that field. The current implementation does not count or consume delegated actions against this field at runtime.
- `max_depth`: optional declared depth ceiling used for scope inheritance and narrowing. Its effective value MUST be less than or equal to `parentScope.max_depth` when the parent constrains that field. The current implementation does not track runtime recursion depth against this field; multi-hop delegation remains prohibited (Section 5.7).

A relying party MAY impose additional constraints beyond those in the effective child scope.

### 5.5 Security Properties

`DelegationV1` has the following protocol properties:

- Single-use: `delegation_id` MUST be treated as consumable exactly once by the relying party.
- Delegator-bound: validity is scoped to the delegating principal identified by `delegator`, which MUST equal `parent.audience`. The signature binds the artifact to a key trusted for `issuer`.
- Audience-bound: validity is scoped to the designated `delegatee`.
- Parent-bound: validity is cryptographically bound to a specific parent `AuthorizationV1` via `parent_auth_hash`. A delegation presented with a mismatched parent MUST be rejected.
- Policy-bound: `policy_id` MUST equal `parent.policy_id`. Cross-policy delegation is prohibited.
- Narrowing-only: effective delegated scope MUST NOT exceed the supplied `parentScope` in any parent-constrained dimension.
- Short-lived: `expiry` MUST be less than or equal to `parent.expiry`. A delegation cannot outlive its parent.
- Non-forgeable: `signature` MUST validate under the `OXDEAI_DELEGATION_V1` signing domain and the delegating principal's key.

These properties are mandatory protocol constraints, not operational recommendations.

### 5.6 Narrowing-Only Invariant

A `DelegationV1` MUST NOT expand authority relative to the supplied `parentScope`. Equality is valid.

Verifiers MUST resolve the effective child scope using Section 5.4 before comparing each field constrained by `parentScope`:

- `scope.tools`: the effective child set MUST be a subset of `parentScope.tools`.
- `scope.max_amount`: the effective child value MUST be less than or equal to `parentScope.max_amount`.
- `scope.max_actions`: the effective child value MUST be less than or equal to `parentScope.max_actions`.
- `scope.max_depth`: the effective child value MUST be less than or equal to `parentScope.max_depth`.

Separately, the top-level delegation `expiry` MUST be less than or equal to `parent.expiry`.

Verifiers MUST enforce these invariants. Scope widening is a protocol violation and MUST be rejected.

`parentScope` is supplied by the caller/integrator, not derived from the parent `AuthorizationV1`. Verification proves narrowing against the supplied scope; it does not independently establish that this scope represents an external authoritative grant.
When the parent scope is not supplied to the verifier, the narrowing invariant is the deployer's responsibility.
Verifiers SHOULD require explicit parent scope when scope enforcement is a security requirement.

### 5.7 One-Hop Constraint

`DelegationV1` is a single-hop delegation mechanism.

A `DelegationV1` parent MUST be an `AuthorizationV1`.
A `DelegationV1` MUST NOT be used as the parent of another `DelegationV1`.
Re-delegation chains are not permitted in this protocol version.

Verifiers MUST detect and reject multi-hop delegation attempts.
Specifically, a verifier MUST reject any `DelegationV1` whose presented parent artifact contains a `delegation_id` field, as this indicates the parent is itself a `DelegationV1`.

### 5.8 Normative Verifier Obligations

A relying party verifying a `DelegationV1` MUST perform all of the following checks in order.
If any check fails, execution MUST NOT occur.

**Chain integrity checks (evaluated against the parent `AuthorizationV1`):**

1. Verify the parent `AuthorizationV1` is itself a valid `AuthorizationV1` artifact (all Section 4 relying-party obligations apply to the parent).
2. Verify the parent artifact is an `AuthorizationV1` and not a `DelegationV1` (one-hop enforcement).
3. Compute the SHA-256 hex digest of the canonical parent `AuthorizationV1` (including its `signature` field) and verify it equals `delegation.parent_auth_hash`.
4. Verify `delegation.delegator` equals `parent.audience`.
5. Verify `delegation.policy_id` equals `parent.policy_id`.
6. Verify `delegation.expiry` is less than or equal to `parent.expiry`.
7. Verify the parent has not expired at the time of verification.

**Delegation-level checks:**

8. Verify `delegation.expiry` is strictly greater than the current verification time. An artifact where `expiry <= now` MUST be rejected.
9. Verify `delegation.delegatee` matches the expected delegatee for the current execution context, when a specific delegatee is required.
10. Verify the delegation scope does not exceed the parent scope (narrowing-only invariant, Section 5.6).
11. Verify `delegation.alg` is `Ed25519` and is permitted by local algorithm policy.
12. Resolve a trusted verification key from `(delegation.issuer, delegation.kid, delegation.alg)` using the key selection rules in Section 11.
13. Verify `delegation.signature` over the canonical delegation payload using the `OXDEAI_DELEGATION_V1` signing domain (Section 8.4).
14. Verify `delegation_id` has not already been consumed (replay protection).

**Fail-closed behavior:**

If verification state is ambiguous, if required trusted key material is absent, or if any check produces an indeterminate result, the verifier MUST fail closed.
Execution MUST NOT proceed unless all checks succeed.

### 5.9 Compatibility Note

`DelegationV1` is a stable artifact in the current protocol profile.
Relying parties that do not use delegation MAY reject `DelegationV1` artifacts.
Implementations that do support delegation MUST implement the full verification obligations in Section 5.8.

`DelegationV1` extends `AuthorizationV1` without replacing it.
A deployment that does not use delegation continues to use `AuthorizationV1` exclusively.
`DelegationV1` verification is additive and does not alter the semantics of `AuthorizationV1`.

### 5.10 Minimal Artifact Example

```json
{
  "delegation_id": "del_01JZ4X9K2V8QM7R3P5T0Y6W1U2",
  "issuer": "agent-A",
  "audience": "agent-B",
  "parent_auth_hash": "9a3f5c8b2d1e4f7a9c0b3e6d8f2a5c7e9b1d4f6a8c0e2b5d7f9a1c3e5b7d9f1a3",
  "delegator": "agent-A",
  "delegatee": "agent-B",
  "scope": {
    "tools": ["provision_gpu"],
    "max_amount": 300000000
  },
  "policy_id": "policy_prod_infra_v7",
  "issued_at": 1770001200,
  "expiry": 1770001260,
  "alg": "Ed25519",
  "kid": "agent-a-key-2026-01",
  "signature": "4rQ9Xm2kPzJv7wN5aT8sL3cF1bY6eH0dU9oR4iW2nK8="
}
```

## 6. Non-Forgeable Verification (v1.2)

### 6.1 Algorithm Profile

`Ed25519` is the preferred public-key verification algorithm for v1.2 artifacts.
New v1.2 signed artifacts MUST include `alg`, `kid`, and `signature`.

### 6.2 Signed Payload Rules

The signed payload MUST use canonical encoding.
The `signature` field MUST NOT be included in its own signing payload.
Any mutation of signed fields MUST invalidate signature verification.

### 6.3 Verifier Fail-Closed Requirements

Verifiers MUST fail closed on:

- unknown or unsupported `alg`
- unknown `kid`
- malformed `signature`
- missing required signed fields
- issuer mismatch
- audience mismatch
- policy mismatch when configured
- expiry failure

A verifier MUST NOT accept ambiguous trust state.

### 6.4 Legacy Compatibility Path

Legacy shared-secret artifacts MAY be supported for backward compatibility.
If supported, verifier mode MUST be explicit and documented as legacy.
Public-key verification SHOULD be used for third-party verification.

## 7. Domain Separation

Signatures for different artifact classes MUST use distinct signing domains.
At minimum, implementations MUST support distinct domains:

- `OXDEAI_AUTH_V1`
- `OXDEAI_ENVELOPE_V1`
- `OXDEAI_CHECKPOINT_V1`
- `OXDEAI_DELEGATION_V1`

A signer MUST compute signature input as:

`domain_separator || canonical_payload_bytes`

Artifact classes MUST NOT share signing domains.
This prevents cross-artifact signature confusion.

## 8. Canonical Signing Format

Canonical signing ensures cross-language interoperability.

All conformant implementations MUST produce identical signing input bytes for identical artifact payloads, regardless of programming language or runtime environment.

### 1. Purpose

OxDeAI requires a deterministic, language-independent canonical signing format for all signed artifacts.
For identical artifact content, compliant implementations MUST produce identical signing input bytes.
Cross-language signature interoperability depends on this property.

### 2. Signed Artifact Classes

The following artifact classes are signed in v1.3:

- `AuthorizationV1`
- `DelegationV1`
- `VerificationEnvelopeV1`

Checkpoint artifacts MAY be signed when that profile is enabled.

Each signed artifact class MUST use a distinct signing domain.

### 3. Canonical Payload Rules

Before signing, an artifact payload MUST be converted to the protocol canonical JSON representation.

Canonical payload requirements:

- Object keys MUST be sorted deterministically.
- Source-code field order or runtime object insertion order MUST NOT affect output.
- Insignificant whitespace MUST NOT be included.
- Payload text MUST be UTF-8 encoded.
- Numeric and bigint values MUST use the protocol canonical representation.
- Implementations MUST NOT use language-native object/binary serializers as signing format.
- Implementations MUST NOT sign pretty-printed JSON.
- Implementations MUST NOT sign runtime-dependent binary encodings unless explicitly defined by this protocol.

### 4. Domain Separation

The following domain strings are mandatory:

- `OXDEAI_AUTH_V1` - for `AuthorizationV1` artifacts
- `OXDEAI_ENVELOPE_V1` - for `VerificationEnvelopeV1` artifacts
- `OXDEAI_DELEGATION_V1` - for `DelegationV1` artifacts

If checkpoint signing is used, `OXDEAI_CHECKPOINT_V1` MUST be used for that class.

Signatures for different artifact classes MUST use different domain strings.
A verifier MUST reject a signature when the domain does not match the artifact class.
Domain separation prevents cross-artifact signature confusion.

In particular, a `DelegationV1` signature MUST NOT be accepted as a valid `AuthorizationV1` signature, and vice versa.

### 5. Signing Input Construction

Signing input bytes are constructed as:

`SIGNING_INPUT = DOMAIN_UTF8 || 0x0A || CANONICAL_PAYLOAD_UTF8`

Where:

- `DOMAIN_UTF8` is the UTF-8 encoding of the domain string.
- `0x0A` is one byte with value newline.
- `CANONICAL_PAYLOAD_UTF8` is the UTF-8 encoding of the canonical JSON payload.

Compliant implementations MUST use exactly this construction.

### 6. Signature Exclusion Rule

The `signature` field MUST NOT be included in the canonical payload that is signed.

All required artifact fields other than `signature` MUST be included in the signed payload.
For v1.2 `AuthorizationV1`, this includes `alg` and `kid`.
For `DelegationV1`, this includes all mandatory fields defined in Section 5.2 except `signature`.

Transport-specific metadata not defined by this protocol MUST NOT be included in the signed payload.

### 7. Encoding Requirements

- Canonical payload bytes MUST be UTF-8.
- Signing input bytes MUST be byte-for-byte reproducible across implementations.
- Implementations MUST NOT depend on locale, platform, or runtime defaults.
- Implementations MUST preserve exact protocol field values.

If signatures are represented as base64 or hex for transport, that encoding is a representation layer only and is not part of signing input construction.

### 8. Verification Requirements

A verifier MUST:

1. Determine artifact class and required signing domain.
2. Reconstruct canonical payload using the same canonical JSON rules.
3. Reconstruct signing input using the same domain and separator.
4. Verify signature against that exact byte sequence.

Verification MUST fail if:

- canonical payload cannot be reconstructed deterministically
- required signed fields are missing
- artifact class/domain is unsupported
- reconstructed bytes differ from signer-intended canonical form

### 9. Failure Handling

The following conditions MUST fail closed:

- malformed canonical payload
- unknown artifact type or domain
- unknown or unsupported algorithm
- ambiguous serialization state

Verification ambiguity MUST NOT be treated as success.

### 10. Minimal Example

Example artifact class: `AuthorizationV1`

Domain string:

```text
OXDEAI_AUTH_V1
```

Example canonical JSON payload (excluding `signature`):

```json
{"alg":"Ed25519","audience":"payments.api.eu-1","auth_id":"auth_01JY7K8Z4V3QH6N2M9P0R1S2T3","decision":"ALLOW","expiry":1770001260,"intent_hash":"9f3e5c6ad7a4a2f8a2d93f0f31c65a88f95d7dbef4c9f9e30d5f0f6ce7f4a1b2","issued_at":1770001200,"issuer":"oxdeai.pdp.prod.eu-1","kid":"2026-01-main","policy_id":"policy_prod_payments_v42","state_hash":"4e2b7f1a3d8c6e90b5f3a9d7c1e2f4a6b8d0c2e4f6a8b0c1d3e5f7a9b1c3d5e7"}
```

Conceptual signing input construction:

```text
UTF8("OXDEAI_AUTH_V1") || 0x0A || UTF8(<canonical-json-payload-above>)
```

Example artifact class: `DelegationV1`

Domain string:

```text
OXDEAI_DELEGATION_V1
```

Conceptual signing input construction:

```text
UTF8("OXDEAI_DELEGATION_V1") || 0x0A || UTF8(<canonical-delegation-payload>)
```

## 9. Verification Envelope Signing

VerificationEnvelopeV1 MAY carry signature metadata (`issuer`, `alg`, `kid`, `signature`).
If signature metadata is present, verifiers MUST validate it under the same fail-closed rules.
If a verifier runs in signature-required mode, missing envelope signature MUST fail closed.

## 10. Relying Party Contract

A Relying Party, also referred to as a Policy Enforcement Point (PEP), is the system responsible for executing external actions after verifying an authorization artifact.

The relying party enforces the OxDeAI execution authorization boundary.

Before executing any action, the relying party MUST verify the authorization artifact according to the rules defined in this section.
This section covers both direct `AuthorizationV1` verification and delegated `DelegationV1` chain verification.

### 1. Definition

A **Relying Party** (Policy Enforcement Point, **PEP**) is the system that receives an authorization artifact and decides whether an external action may execute.
Examples include tool wrappers, compute provisioning services, payment gateways, API execution layers, and orchestration runtimes.

The relying party is the enforcement boundary for OxDeAI authorization decisions.
It MUST enforce this contract before action execution.

### 2. Verification Requirements - Direct Authorization Path

When the relying party receives an `AuthorizationV1` artifact without a `DelegationV1`:

Before executing any action, a relying party MUST verify:

1. `decision` equals `ALLOW`.
2. The authorization has not expired.
3. `issuer` is trusted.
4. `audience` matches the current relying party identity.
5. `policy_id` matches the expected policy context.
6. `intent_hash` matches the exact action about to execute.
7. `state_hash` binding is respected by the execution context.
8. `auth_id` has not already been consumed.
9. `alg` is supported by verifier policy.
10. `kid` resolves to a trusted verification key.
11. `signature` is valid for the canonical signed payload.

If any verification step fails, the relying party MUST reject the action.

### 3. Verification Requirements - Delegation Path

When the relying party receives a `DelegationV1` artifact and its associated parent `AuthorizationV1`:

The relying party MUST perform the full chain verification sequence defined in Section 5.8.

In addition to the chain verification, the relying party MUST verify that the proposed action falls within the effective child scope (Section 5.4):

- When the effective child scope constrains `tools`, the action name MUST appear in the effective `tools` set.
- When the effective child scope constrains `max_amount`, the action amount MUST NOT exceed the effective `max_amount`.

If any chain or scope check fails, the relying party MUST reject the action.

The delegation path is a local, control-plane-free verification.
The relying party MUST NOT require a live call to the PDP to verify a `DelegationV1` chain.

### 4. Authorization Consumption

`AuthorizationV1` MUST be treated as single-use.

After successful execution, the relying party MUST record `auth_id` as consumed in durable or equivalently reliable replay state.
Any subsequent attempt to reuse the same `auth_id` MUST be rejected.

`delegation_id` MUST be treated as single-use.

After successful execution under a `DelegationV1`, the relying party MUST record `delegation_id` as consumed.
Any subsequent attempt to reuse the same `delegation_id` MUST be rejected.

Single-use consumption is required to prevent replay and reduce time-of-check/time-of-use (TOCTOU) abuse.

### 5. Execution Preconditions

Execution MUST NOT occur unless all of the following are true:

**For direct authorization:**

- Authorization verification succeeds.
- Authorization is not expired at decision time.
- Verified `intent_hash` matches the intended action.
- Verified `audience` matches the current relying party.

**For delegation:**

- All chain verification checks pass (Section 5.8).
- The proposed action is within the delegation scope.
- Parent `AuthorizationV1` is valid and not expired.
- Delegation is not expired.

Authorization MUST be verified immediately before execution.

### 6. Failure Handling

The relying party MUST treat each of the following as authorization failure:

**Direct authorization failures:**

- malformed authorization artifact
- unknown issuer
- unknown `kid`
- unsupported `alg`
- invalid signature
- expired authorization
- reused `auth_id`
- intent mismatch
- audience mismatch

**Delegation-specific failures:**

- malformed delegation artifact
- `parent_auth_hash` mismatch
- `delegator` does not match `parent.audience`
- `policy_id` mismatch with parent
- delegation `expiry` exceeds `parent.expiry`
- delegation expired
- delegatee mismatch
- scope violation (action not in `scope.tools`, amount exceeds `scope.max_amount`)
- invalid delegation signature
- multi-hop delegation attempt (`DELEGATION_MULTIHOP_DENIED`)
- reused `delegation_id`
- unknown delegation signing key

Authorization ambiguity MUST result in denial (fail closed).

### 7. Security Considerations

This contract enforces:

- replay protection via single-use `auth_id` and `delegation_id`
- intent binding via `intent_hash`
- state binding via `state_hash`
- trust boundaries via `issuer` and `audience`
- forgery resistance via signature verification
- reduced reuse window via short TTL (`issued_at`/`expiry`)
- scope confinement via delegation narrowing invariants
- chain integrity via `parent_auth_hash` binding
- depth confinement via one-hop enforcement

These checks collectively mitigate replay attacks, authorization forgery, scope escalation, and TOCTOU drift between verification and execution.

#### State Isolation and Concurrency

Sharing mutable state across concurrent evaluations can lead to:

- non-deterministic authorization decisions
- cross-request interference
- incorrect DENY outcomes due to cross-call budget or replay mutations

Implementations MUST enforce state isolation per evaluation to preserve the protocol guarantees in Section 3.3. Each evaluation call MUST receive an isolated state snapshot.

### 8. Minimal Verification Flow - Direct Authorization

```text
1. Receive AuthorizationV1 artifact.
2. Resolve verification key from (issuer, kid, alg) and verify signature.
3. Verify issuer trust and audience equality.
4. Verify decision == ALLOW and expiry is in the future.
5. Compute requested action intent hash and compare to intent_hash.
6. Verify policy_id and state_hash bindings for current context.
7. Check auth_id is not consumed.
8. Execute action.
9. Mark auth_id as consumed.
```

### 9. Minimal Verification Flow - Delegation Path

```text
1. Receive DelegationV1 artifact and its parent AuthorizationV1.
2. Verify parent AuthorizationV1 (all steps in flow above, steps 1–7).
3. Verify parent is AuthorizationV1, not DelegationV1 (one-hop enforcement).
4. Compute SHA-256 of canonical parent AuthorizationV1 and compare to delegation.parent_auth_hash.
5. Verify delegation.delegator == parent.audience.
6. Verify delegation.policy_id == parent.policy_id.
7. Verify delegation.expiry <= parent.expiry.
8. Verify delegation.expiry > now.
9. Verify delegation.delegatee matches expected agent.
10. Verify scope narrowing constraints (Section 5.6).
11. Resolve delegation signing key from (delegation.issuer, delegation.kid, delegation.alg).
12. Verify delegation.signature using OXDEAI_DELEGATION_V1 domain.
13. Verify proposed action is within the effective child scope (tools, max_amount), including inherited parent constraints.
14. Check delegation_id is not consumed.
15. Execute action.
16. Mark delegation_id as consumed.
```

## 11. KeySet and Key Rotation Model

The KeySet model provides deterministic resolution of verification keys for authorization artifacts.

This model enables independent verification of OxDeAI artifacts without requiring online access to the issuing system.

### 1. Purpose

OxDeAI signed-artifact verification depends on deterministic resolution of a trusted public key from the tuple:

- `issuer`
- `kid`
- `alg`

The KeySet model defines a deterministic representation of trusted verification keys.
This model is required for non-forgeable verification in v1.2.

### 2. KeySet Definition

A **KeySet** is a structured representation of verification keys for exactly one issuer.

A KeySet object MUST contain:

- `issuer`
- `version`
- `keys`

Field meanings:

- `issuer`: identifier of the entity that issues signed artifacts.
- `version`: version or revision identifier of the KeySet.
- `keys`: collection of verification keys associated with that issuer.

A KeySet MUST correspond to exactly one issuer.
A verifier MUST NOT treat a KeySet as valid for any other issuer.

### 3. Key Entry Definition

Each KeySet key entry MUST contain:

- `kid`
- `alg`
- `public_key`

A key entry MAY also contain:

- `status`
- `not_before`
- `not_after`

Field meanings:

- `kid`: key identifier.
- `alg`: signature algorithm identifier.
- `public_key`: public verification key material.
- `status`: optional lifecycle state (for example, active, retired, revoked).
- `not_before`: optional lower bound on key validity time.
- `not_after`: optional upper bound on key validity time.

Within a KeySet, `kid` MUST be unique.
`alg` MUST identify the verification algorithm unambiguously.
`public_key` MUST be encoded in the format required by the active protocol profile.

### 4. Key Selection Rules

When verifying a signed artifact, a verifier MUST:

1. Identify the artifact `issuer`.
2. Locate a trusted KeySet for that issuer.
3. Select a key entry whose `kid` equals the artifact `kid`.
4. Confirm the key entry `alg` equals the artifact `alg`.
5. Verify the signature using the selected `public_key`.

Verification MUST fail if:

- no trusted KeySet exists for the issuer
- no matching `kid` exists
- `alg` does not match

These conditions are fail-closed requirements.

For `DelegationV1` verification, the `issuer` in the artifact is the delegating principal (equal to `parent.audience`), not the original PDP issuer.
The verifier MUST hold a trusted KeySet for this delegation issuer separately from the PDP KeySet.

### 5. Issuer Trust Model

Issuer trust is an external security decision made by the verifier environment.

A verifier MUST trust issuers explicitly.
Untrusted issuers MUST NOT be accepted.
Issuer equality comparison MUST be exact.
A trusted key from one issuer MUST NOT be reused for another issuer.

The core protocol does not require online issuer-trust discovery.
Offline or preconfigured issuer trust is valid in v1.2.

### 6. Key Rotation Rules

Issuers SHOULD support key rotation without unnecessarily invalidating still-valid artifacts.
Multiple active keys MAY exist simultaneously for one issuer.
`kid` MUST distinguish rotated keys.
Newly issued artifacts SHOULD reference the currently active key via `kid`.
Verifiers MUST use the `kid` carried in the artifact and MUST NOT guess a latest key.

Rotation MUST NOT rely on implicit key ordering.

### 7. Validity Windows

Key validity windows are optional key-entry constraints.

- If `not_before` is present, a verifier MUST reject use of that key before that instant.
- If `not_after` is present, a verifier MUST reject use of that key after that instant.
- If windows are absent, the key has no protocol-defined time bound.

Key validity windows are distinct from artifact `expiry`.
Artifact expiry and key validity MUST be evaluated independently.

### 8. Failure Handling

Verification MUST fail closed when:

- issuer is unknown
- `kid` is unknown
- `alg` is unsupported
- key entry is malformed
- key validity windows fail
- multiple ambiguous matching keys exist
- `public_key` cannot be decoded
- trust state is ambiguous

Ambiguity MUST NOT be treated as success.

### 9. Minimal Example

```json
{
  "issuer": "oxdeai.pdp.prod.eu-1",
  "version": "2026-01",
  "keys": [
    {
      "kid": "2026-01-main",
      "alg": "Ed25519",
      "public_key": "MCowBQYDK2VwAyEAq7n1h7vJmV1b8v1z9fP0vQ8sQv1w8mR7Q3v0cV0YQ6k=",
      "not_before": 1767225600,
      "not_after": 1798761600
    }
  ]
}
```

## 12. KeySet Distribution (v1 baseline)

Key distribution is external to the core protocol.

The base protocol assumes:

- Verifiers MUST have access to trusted KeySets per issuer.
- KeySets MAY be provisioned statically or retrieved from a well-known endpoint.
- Unknown issuer or unknown `kid` MUST fail closed.

Recommended HTTP discovery format:

```text
GET /.well-known/oxdeai-keyset.json
```

A verifier MAY cache KeySets.
A verifier MUST fail closed if:

- issuer is unknown
- `kid` is unknown
- key cannot be resolved

Dynamic discovery is OPTIONAL and not required for protocol compliance.

---

## 13. Cross-Organization Verification Model

OxDeAI supports verification across trust boundaries.

A relying party MUST:

1. Maintain a set of trusted issuers.
2. Resolve verification keys using `(issuer, kid, alg)`.
3. Verify artifacts locally without contacting the issuer.

The protocol does not require:

- a shared control plane
- runtime trust in the issuer
- synchronous validation

Trust is explicit and externally configured.

Verification ambiguity MUST result in denial.

---

## 14. Replay and TOCTOU Resistance

OxDeAI artifacts are designed to minimize replay and time-of-check/time-of-use (TOCTOU) risks in distributed execution environments.

OxDeAI mitigates replay and check/use drift by combining:

- single-use `auth_id` and `delegation_id`
- short TTL (`issued_at`/`expiry`)
- intent binding (`intent_hash`)
- state binding (`state_hash`)
- issuer and audience binding
- parent hash binding (`parent_auth_hash`) for delegated authorization

Relying parties MUST enforce single-use state for `auth_id`.
Relying parties that support delegation MUST enforce single-use state for `delegation_id`.
Relying parties SHOULD minimize check-to-execute latency.
If execution context changes after verification, execution SHOULD be re-verified.

## 15. Compatibility and Upgrade Notes

v1.2 adds non-forgeable public-key verification as the preferred path.

v1.3 adds `DelegationV1` as a stable protocol artifact for delegated agent authorization.

Compatibility requirements:

- Implementations MAY support legacy artifacts.
- If legacy mode is supported, verifiers MUST distinguish legacy mode from public-key mode.
- Public-key mode SHOULD be default for third-party verification.
- Future versions MAY strengthen envelope-signing and key-distribution requirements.

### DelegationV1 Compatibility

`DelegationV1` is a stable artifact introduced in v1.3.

- Relying parties that do not use delegation MAY reject `DelegationV1` artifacts without violating protocol conformance.
- Implementations claiming v1.3 delegation support MUST implement the full verification obligations defined in Section 5.8.
- `DelegationV1` does not alter the semantics or structure of `AuthorizationV1`. Existing v1.2 compliant implementations continue to operate correctly without modification.
- A verifier that accepts `DelegationV1` MUST also hold appropriate trusted KeySets for delegation issuers, which are distinct from PDP-issuer KeySets.
- Multi-hop delegation (chaining `DelegationV1` from `DelegationV1`) is not supported. Implementations MUST NOT support or accept multi-hop chains.

## 16. Conformance Requirement

Protocol conformance is determined by artifact compatibility and verification behavior.

An implementation is compliant if it reproduces the protocol artifacts defined in this specification and passes the conformance vectors for the targeted version profile.

A conformant implementation MUST reproduce expected conformance vectors for its targeted profile.
Violation ordering in `VerificationResult` MUST be deterministic.

For v1.3 delegation conformance, implementations MUST additionally satisfy delegation-specific conformance vectors covering the narrowing-only invariant, one-hop enforcement, parent hash binding, and fail-closed behavior for all `DELEGATION_*` violation codes.
