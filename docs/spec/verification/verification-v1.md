# Verification Specification v1

**Status:** Stable (Normative Specification for verification semantics; artifact statuses defined in their respective specs)  
**Version:** v1.0.0  
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
It does **NOT** make any store operation mandatory, does **NOT** prescribe a store
implementation, and does **NOT** dictate the ordering of checks *within*
verification — that is a separate question.

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

1. Structural validation (required fields, types).
2. Algorithm support (`alg` == `Ed25519`).
3. Key resolution via `issuer`, `kid`, `alg` in `trustedKeySets` (strict mode).
4. Signature check over canonicalized payload excluding `signature` (canonicalization-v1).
5. Expiry: `now < expiry` (**strict zero tolerance** — `now >= expiry` → `AUTH_EXPIRED`, no grace period; see `authorization-v1.md §17`).
6. `issued_at` future-plausibility: `issued_at <= verificationTime + maxFutureIssuedAtSkewSeconds` → else `AUTH_ISSUED_AT_IMPLAUSIBLE`; compared only against the trusted `verificationTime`, never `Intent.timestamp` (see `authorization-v1.md §17.2`).
7. Audience match.
8. Intent hash match to the proposed action (`intent_hash`).
9. Replay check on `auth_id` (if replay store present).

Any failure **MUST** yield `DENY` with the corresponding reason code.

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
9. Scope narrowing:
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

- Check ordering **MUST** follow the sequences in §§5–6 to ensure deterministic results across implementations.
- Implementations MUST NOT short-circuit in ways that alter observable reason ordering from these lists.
- Any ambiguity (missing inputs, unresolved keys, absent `now`, absent `trustedKeySets` in strict mode) **MUST** fail closed (DENY).

## 10. Conformance and Vectors

- Implementations **MUST** pass the locked vectors:
  - `docs/spec/test-vectors/canonicalization-v1.json`
  - `docs/spec/test-vectors/authorization-v1.json`
  - `docs/spec/test-vectors/pep-vectors-v1.json`
  - `docs/spec/test-vectors/delegation-vectors-v1.json`
- Additional verification vectors MAY be added in future versions; passing official vectors is required for conformance.

## 11. Non-Bypassability

- Execution MUST NOT proceed without successful verification per this spec.
- Any execution path that bypasses verification is **NON-CONFORMANT**.
