# Verification Specification v1

**Status:** Stable (Normative Specification for verification semantics; artifact statuses defined in their respective specs)  
**Version:** v1.1.0
**Non-normative sources of truth:** None - this file is normative for verification behavior. Canonical artifact definitions remain in `docs/spec/authorization-v1.md`, `delegation-v1.md`, `pep-gateway-v1.md`, and `canonicalization-v1.md`.

## 1. Scope

This specification defines the mandatory verification semantics for OxDeAI artifacts:

- `AuthorizationV1`
- `DelegationV1` and the parent/child chain
- PEP gateway boundary verification (pre-execution gate)
- Verification envelopes (post-execution evidence) - pending full envelope spec; apply general verification rules here

## 2. Dependencies

- `canonicalization-v1.md` - all hashes and signature preimages **MUST** use canonicalization-v1.
- `authorization-v1.md`
- `delegation-v1.md`
- `pep-gateway-v1.md`
- `conformance-v1.md` - deterministic ordering and fail-closed doctrine.

## 3. Decision Surface

- Protocol decisions: `ALLOW` or `DENY`.
- Deterministic error/reason codes **MUST** be emitted as defined in the relevant artifact specs (e.g., `INVALID_SIGNATURE`, `INTENT_HASH_MISMATCH`, `DELEGATION_SCOPE_VIOLATION`, `DELEGATION_MULTIHOP_DENIED`, etc.).
- Interface summaries such as `ok | invalid | inconclusive` are optional UI layers; they **MUST NOT** replace the underlying ALLOW/DENY decision.

## 4. Common Inputs

Verifiers **MUST** operate on explicit, injected inputs:

- `artifact` (AuthorizationV1, DelegationV1, envelope, etc.)
- `now` (unix seconds) - **MUST NOT** rely on ambient wall-clock inside verification logic.
- `trustedKeySets` (issuer-scoped public keys). In strict mode, absence of `trustedKeySets` **MUST** fail closed.
- `audience` expected by the relying party.
- `replayStore` (for `auth_id` / `delegation_id`) when replay protection is enforced.
- Optional `expectedDelegatee`/`expectedPolicyId` when required by integration.

### 4.1 Provenance of `expected*` Values

An `expected*` verification value **MUST** originate from trusted configuration
established independently of the artifact being verified and independently of the
component that produced that artifact for the current operation. It **MUST NOT**
be derived from the artifact being verified, from an artifact carried by it, or
from the producer that created the artifact in the same call.

This rule constrains **provenance only**. It does **NOT** make `expectedPolicyId`,
`expectedIssuer`, `expectedDelegatee`, or any other optional expectation
mandatory. Every such value remains optional and configured per integration; the
rule defines only what qualifies as a valid trust source when one *is* configured.

A value that fails this provenance test **MUST NOT** be configured at all, rather
than being configured from a non-independent source. Recomputing an expectation
from the same producer that emitted the artifact restates that producer's own
derivation and establishes no independent constraint, so it does not satisfy this
rule even though the two values are compared.

### 4.2 Side Effects Relative to Authentication

Input that has not been authenticated **MUST NOT** cause durable mutation of
trusted security state.

A durable mutation is any write a verifier or enforcement boundary makes that
outlives the current request and can affect a later authorization decision —
replay-store consumption is the canonical example. Authentication here means the
artifact's signature has been verified against configured trust anchors; a
structural or presence check is not authentication. Here “durable” means surviving
this request, including a write to an in-memory store; it does not assert restart
persistence or require a particular persistence technology.

This rule constrains **the ordering of side effects relative to authentication**.
It does **NOT** make any store operation mandatory and does **NOT** prescribe a
store implementation. The ordering of checks *within* AuthorizationV1
verification, including the requirement that replay consumption comes after
every other check, is fixed by §5.

The operative consequence is that unauthenticated input MUST NOT leave trusted
replay state that can deny a later legitimate presentation. Where a boundary both authenticates and consumes
a single-use identifier, the consume **MUST** follow successful authentication and
**MUST** still precede the protected side effect. Atomicity of the consume is a
property of the store operation, not of where it is called, so moving it after
authentication does not weaken replay protection: two concurrent presentations of
the same identifier permit at most one successful consume within the declared
replay domain, and neither may execute without successful consumption. Store
unavailability can prevent both from executing.

### 4.3 Replay-Store Contract and Deployment Boundary

Where an artifact or execution profile requires replay resistance:

- The replay identifier and domain MUST be declared/configured. All boundaries
  accepting the same entitlement within that domain MUST participate in its
  consumption contract. Local code cannot infer every valid deployment boundary.
- Consume MUST atomically check and spend the entitlement: at most one consume
  for the same identifier/domain may succeed under concurrency while that
  entitlement remains protected. Atomicity is a store contract, not evidence of
  backend durability. No backend technology is mandated.
- Consumed identifiers MUST remain unavailable for reuse while the protected
  authorization could otherwise still be accepted in that domain. Eviction or
  TTL policy MUST account for the domain's acceptance window and verifier clocks.
- Store failure, unavailability or an indeterminate required replay result MUST
  NOT become permissive success. Without a definitive successful consume, the
  boundary MUST NOT perform the protected side effect.

Consumption means **entitlement spent**, not **effect completed**. A crash after
consume and before the effect may spend the authorization without the effect
occurring. A later denial, CAS conflict, hook failure or partial sequence of
consumes does not imply rollback of a prior successful consume. This contract
provides no transaction between replay state and the external effect.

Implementation conformance checks ordering and fail-closed behavior against this
contract. Restart persistence, replica sharing/visibility, backend persistence
configuration, topology correctness, HA/SLA and recovery guarantees require
separate deployment evidence. Restart resistance is a deployment property;
generic conformance does not establish it. This separation does not permit a
replay-resistant deployment to accept an identifier whose required consumption
history is unavailable or indeterminate.


## 5. AuthorizationV1 Verification (Required Ordering)

This section is the **single reference sequence** for AuthorizationV1
verification. `authorization-v1.md` §10, `pep-gateway-v1.md` §10.1 and §12.2,
and `conformance-v1.md` §9 refer to it. Where another normative document lists
these checks in a different order, this section governs the order.

**Preconditions (verifier configuration, not artifact properties).** A trusted
`now` MUST be supplied. In strict mode, `trustedKeySets` MUST be supplied. If a
precondition is not met, the verifier MUST fail closed. This is a configuration
error, not an artifact verification result: it carries no determining code
(§9), and its reason code is not normative.

| Step | Check | Code on failure |
|---|---|---|
| 1 | Parse: the artifact is a JSON object | `AUTH_MISSING_FIELD` |
| 2 | Field integrity: closed field set, required fields and their types (`authorization-v1.md` §5 "Signed field set", §6), except the expiry fields, which are resolved at step 5 | `AUTH_MISSING_FIELD`, or `AUTH_SIGNATURE_INVALID` where `authorization-v1.md` §5 assigns it (unknown field, `authorization_id` ≠ `auth_id`) |
| 3 | `auth_id` is Unicode NFC-normalized | `AUTH_ID_NONCANONICAL` |
| 4 | `decision` equals `"ALLOW"` | `AUTH_DECISION_INVALID` |
| 5 | Wire encoding and algorithm: identify the encoding from `alg`; apply the signature-shape and ambiguity rules; resolve the effective expiry, which depends on the signature shape (`authorization-v1.md` §5 "Expiry field resolution", §13) | `AUTH_ALG_UNSUPPORTED`, `AUTH_MISSING_FIELD` or `AUTH_SIGNATURE_INVALID`, as `authorization-v1.md` §5 assigns |
| 6 | Expected issuer, when `expectedIssuer` is configured | `AUTH_ISSUER_MISMATCH` |
| 7 | Issuer authority, when trusted `(issuer, policy_id)` pairs are configured: the artifact's pair MUST be one of them | `AUTH_ISSUER_POLICY_NOT_AUTHORIZED` |
| 8 | Key resolution: `kid` is resolved **only within the key sets of the artifact's `issuer`**. An issuer with no trusted key set, or a `kid` absent from that issuer's key sets, fails this step | `AUTH_KID_UNKNOWN` |
| 9 | Key validity at the verification time (status and validity window of the resolved key) | `AUTH_KEY_INACTIVE` |
| 10 | Signature over the preimage defined in `authorization-v1.md` §5 | `AUTH_SIGNATURE_INVALID` |
| 11 | Expiry: valid iff `now < effectiveExpiry` (**strict zero tolerance**, `authorization-v1.md` §17) | `AUTH_EXPIRED` |
| 12 | `issued_at` future-plausibility: `issued_at <= verificationTime + maxFutureIssuedAtSkewSeconds`, compared only against the trusted `verificationTime`, never `Intent.timestamp` (`authorization-v1.md` §17.2) | `AUTH_ISSUED_AT_IMPLAUSIBLE` |
| 13 | Audience matches the verifier's expected audience | `AUTH_AUDIENCE_MISMATCH` |
| 14 | Policy, when `expectedPolicyId` is configured | `AUTH_POLICY_ID_MISMATCH` |
| 15 | Boundary binding, at an enforcement boundary: `intent_hash` equals `SHA-256(canonicalization-v1(action))`; state binding when applicable | as defined in `pep-gateway-v1.md` |
| 16 | Replay: the `auth_id` is not already consumed; at an enforcement boundary, it is consumed atomically (§4.2, §4.3) | `AUTH_REPLAY` |

Recognizing the issuer (steps 6 to 8) does not authenticate the artifact. No
field is authenticated before step 10 passes. Step 8 MUST NOT search the key
sets of any other issuer.

Step 16 MUST be the last step. An enforcement boundary MUST NOT consume the
`auth_id` unless every preceding step, including the boundary binding of step
15, has passed. A request whose action does not match `intent_hash` MUST
therefore leave the authorization unconsumed.

Any failure **MUST** yield `DENY`. Execution **MUST NOT** occur.

## 6. Delegation Verification (Chain)

Input: `parent AuthorizationV1`, `delegation DelegationV1`, `action`, `trustedKeySets`, `now`, optional `consumedDelegationIds`.

Required steps (in order):
1. Parent type check: parent **MUST NOT** be a `DelegationV1` → else `DELEGATION_MULTIHOP_DENIED`.
2. Verify parent AuthorizationV1 per §5 (all steps).
3. Delegation structural + alg check (`Ed25519`).
4. Delegation signature over canonicalized payload excluding `signature` (canonicalization-v1); key via `kid`/`alg`/issuer in `trustedKeySets`.
5. Parent hash binding: `parent_auth_hash == SHA256(canonical(parent))` → else `DELEGATION_PARENT_HASH_MISMATCH`.
6. Delegator binding: `delegation.delegator == parent.audience`.
7. Policy binding: `delegation.policy_id == parent.policy_id`.
8. Expiry ceiling: `delegation.expiry <= parent.expiry` and `delegation.expiry > now`; else `DELEGATION_EXPIRED` or `DELEGATION_SCOPE_WIDENING`.
   Temporal validity: `delegation.expiry > delegation.issued_at`, else `DELEGATION_TEMPORAL_INVALID`; `delegation.issued_at <= verificationTime + maxFutureIssuedAtSkewSeconds`, else `DELEGATION_ISSUED_AT_IMPLAUSIBLE` (same contract as step 6 of §5).
9. Scope narrowing (the supplied parent scope is first validated with the same type rules as the child scope; a malformed ceiling such as NaN, Infinity, a fraction or a negative value is `DELEGATION_SCOPE_VIOLATION`):
   - `scope.tools` subset of parent tools.
   - `scope.max_amount` ≤ parent amount (if present).
10. Action scope check:
    - `action.tool` in `scope.tools` (if defined).
    - `action.params.amount` ≤ `scope.max_amount` (if defined).
11. Delegatee match: if an expected delegatee is provided, it **MUST** equal `delegation.delegatee`; else `DELEGATION_DELEGATEE_MISMATCH`.
12. Replay: `delegation_id` not previously consumed; else `DELEGATION_REPLAY`.

Any violation **MUST** return `DENY` with the precise reason code. Success returns `ALLOW`.

## 7. PEP Gateway Verification

PEP **MUST**:
- Perform Authorization (and Delegation chain, if present) verification per §§5–6 before execution.
- Enforce fail-closed: any verification failure → HTTP 403 with structured `DENY` and reason code.
- Upstream error mapping follows `pep-gateway-v1.md` (e.g., 502 for upstream error, 504 for timeout). These HTTP statuses do **not** override the protocol decision surface (still DENY when applicable).

Direct upstream calls without the internal token MUST be rejected (403).

## 8. Verification Envelope (Pending Full Spec)

Until a dedicated envelope spec is finalized:
- Treat envelope verification as:
  - Validate canonical snapshot hash and audit chain integrity.
  - If signed, verify signature with canonicalization-v1 and domain separation.
  - Return ALLOW/DENY with reason codes; `ok/invalid/inconclusive` may be exposed as UI summaries only.
- Envelope verification does **not** grant execution authority; it is post-execution evidence validation.

## 9. Determinism and Ordering

### 9.1 Verdict and determining code

For an invalid AuthorizationV1, the **determining code** is the code of the
first step of §5 that fails, taken in step order.

The normative outputs of AuthorizationV1 verification are the **verdict**
(valid or invalid, and therefore `ALLOW` or `DENY`) and, for an invalid
artifact, the **determining code**. Two conforming implementations MUST produce
the same verdict and the same determining code for identical inputs.

An implementation MAY stop at the first failing step. An implementation MAY
also evaluate further steps and report additional codes.

A conforming implementation MUST be able to identify the determining code of
any invalid result. It MAY do so either as the first entry of an ordered report,
or in a dedicated field (for example `primary_reason_code`). It MAY expose the
dedicated field only when the caller requests it. Where a dedicated field is
used, the order of the reported codes is not normative, and the first reported
code is not necessarily the determining code.

Additional codes are diagnostics. Their presence, multiplicity and order are
not normative, and they MUST NOT be presented as the determining code.

Verifier configuration errors (§5 "Preconditions", reported at no step) have no
determining code. An invalid result caused only by such errors carries none.

This section changes no ordering of side effects: §4.2 still forbids any
durable mutation before authentication, and §5 step 16 keeps replay
consumption last.

The determining code is defined by step, not by code value. The same code can
arise at more than one step (for example `AUTH_SIGNATURE_INVALID` at step 2 and
at step 10).

### 9.2 Delegation

Delegation verification (§6) MUST follow the order of §6.

### 9.3 Fail closed

Any ambiguity (missing inputs, unresolved keys, absent `now`, absent `trustedKeySets` in strict mode) **MUST** fail closed (DENY).

## 10. Conformance and Vectors

- Implementations **MUST** pass the locked vectors:
  - `docs/spec/test-vectors/canonicalization-v1.json`
  - `docs/spec/test-vectors/authorization-v1.json`
  - `docs/spec/test-vectors/pep-vectors-v1.json`
  - `docs/spec/test-vectors/delegation-vectors-v1.json`
  - `docs/spec/test-vectors/authorization-wire-encoding-v1.json`
  - `docs/spec/test-vectors/authorization-precedence-v1.json`
- Additional verification vectors MAY be added in future versions; passing official vectors is required for conformance.
- For AuthorizationV1 vectors, conformance is assessed on the verdict and the determining code (§9.1). Additional diagnostic codes are not compared.

## 11. Non-Bypassability

- Execution MUST NOT proceed without successful verification per this spec.
- Any execution path that bypasses verification is **NON-CONFORMANT**.
