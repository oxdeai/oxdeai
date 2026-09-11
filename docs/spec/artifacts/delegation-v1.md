# DelegationV1 Specification

**Status:** Stable (Normative Specification)
**Version:** v1.3.0
**Depends on:** `canonicalization-v1`, `AuthorizationV1`

---

## 1. Overview

`DelegationV1` is a protocol artifact that allows a principal holding a valid `AuthorizationV1` to delegate authority to a second principal (the delegatee), with scope equal to or more restrictive than the parent scope.

The delegatee may present `DelegationV1` to a Policy Enforcement Point (PEP) as a substitute authorization credential, subject to scope and expiry constraints that are at most as permissive as the parent `AuthorizationV1`.

Key properties:

- **Derived** - must reference a valid parent `AuthorizationV1`
- **Strictly narrowing** - scope may only be equal to or more restrictive than the parent
- **Single-hop** - no re-delegation; a `DelegationV1` cannot itself be delegated
- **Locally verifiable** - no control plane required at verification time
- **Signed** - Ed25519, same signing model as `AuthorizationV1`
- **Fail-closed** - any verification ambiguity MUST result in DENY

---

## 2. JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12",
  "$id": "https://oxdeai.dev/schemas/delegation-v1.json",
  "title": "DelegationV1",
  "type": "object",
  "required": [
    "delegation_id",
    "issuer",
    "delegator",
    "delegatee",
    "parent_auth_hash",
    "scope",
    "policy_id",
    "issued_at",
    "expiry",
    "alg",
    "kid",
    "signature"
  ],
  "additionalProperties": false,
  "properties": {
    "delegation_id": {
      "type": "string",
      "description": "Unique identifier for this delegation artifact. MUST be globally unique. Recommended: UUID v4."
    },
    "issuer": {
      "type": "string",
      "description": "Identity of the system that produced this artifact (e.g. agent runtime ID)."
    },
    "delegator": {
      "type": "string",
      "description": "Identity of the principal delegating authority. MUST match the audience of the parent AuthorizationV1."
    },
    "delegatee": {
      "type": "string",
      "description": "Identity of the principal receiving delegated authority."
    },
    "parent_auth_hash": {
      "type": "string",
      "description": "SHA-256 hex digest of the canonical encoding of the parent AuthorizationV1. Binds this delegation to a specific parent artifact."
    },
    "scope": {
      "type": "object",
      "description": "Declared delegated scope. Effective fields MUST be equal to or more restrictive than the corresponding caller-supplied parentScope constraints. Omission is resolved uniformly under Section 4.1.",
      "additionalProperties": false,
      "properties": {
        "tools": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Optional tool allowlist. The effective value MUST be a subset of parentScope.tools when defined. Omission inherits parentScope.tools if defined; otherwise tools remain unconstrained."
        },
        "max_amount": {
          "type": "number",
          "description": "Optional maximum spend per action. The effective value MUST be ≤ parentScope.max_amount when defined. Omission inherits parentScope.max_amount if defined; otherwise amount remains unconstrained."
        },
        "max_actions": {
          "type": "integer",
          "description": "Optional declared action-count ceiling used for inheritance and narrowing against parentScope.max_actions when defined. The current implementation does not count or consume delegated actions against this field at runtime."
        },
        "max_depth": {
          "type": "integer",
          "description": "Optional declared depth ceiling used for inheritance and narrowing against parentScope.max_depth when defined. It does not provide runtime recursion-depth enforcement; multi-hop delegation remains prohibited."
        }
      }
    },
    "policy_id": {
      "type": "string",
      "description": "Policy identity. MUST match the policy_id of the parent AuthorizationV1."
    },
    "issued_at": {
      "type": "integer",
      "description": "Unix timestamp (seconds) at which this delegation was issued."
    },
    "expiry": {
      "type": "integer",
      "description": "Unix timestamp (seconds) at which this delegation expires. MUST be ≤ parent AuthorizationV1 expiry."
    },
    "alg": {
      "type": "string",
      "enum": ["Ed25519"],
      "description": "Signing algorithm. Only Ed25519 is supported."
    },
    "kid": {
      "type": "string",
      "description": "Key ID used to sign this artifact. MUST resolve in the issuer's KeySet."
    },
    "signature": {
      "type": "string",
      "description": "Base64url-encoded Ed25519 signature over the canonical signing input."
    }
  }
}
```

---

## 3. Canonical Signing Input

The signature MUST be computed over the following canonical input, using the same domain-separated format as `AuthorizationV1`:

```
OXDEAI_DELEGATION_V1\n<canonical_json>
```

Where `<canonical_json>` is the deterministic JSON encoding of the `DelegationV1` object **excluding** the `signature` field, with:

- keys sorted lexicographically at every nesting level
- no insignificant whitespace
- no `undefined` or `null` values for optional absent fields (omit the key entirely)

Implementations MUST produce identical byte sequences for identical inputs.

---

## 4. Invariants

### 4.1 Scope Narrowing

A `DelegationV1` MUST NOT expand authority relative to the supplied
`parentScope`. This holds uniformly for all four optional `DelegationScope`
fields: `tools`, `max_amount`, `max_actions`, and `max_depth`. Equality is
valid.

**Omission semantics.** A scope field the child omits is not "unconstrained."
It resolves to an *effective* value before narrowing is checked:

```
effectiveChild.field =
  rawChild.field       if the child explicitly supplies it
  parentScope.field    if the child omits it AND parentScope constrains it
  unconstrained         only if neither side constrains it
```

This resolution MUST be performed before any narrowing comparison. A
verifier that skips the comparison entirely when the child field is absent —
rather than resolving it against the parent first — does not satisfy this
invariant, even if it never accepts a field the child *explicitly* sets to a
wider value than the parent's.

| Field | Rule |
|---|---|
| `scope.tools` | Effective child tools MUST be a subset of `parentScope.tools` when defined. Omitted child tools inherit that constraint unchanged; an explicitly supplied child list is compared against it as given. Equal sets are valid. |
| `scope.max_amount` | Effective child `max_amount` MUST be ≤ `parentScope.max_amount` when defined. Equality is valid. |
| `scope.max_actions` | Effective child `max_actions` MUST be ≤ `parentScope.max_actions` when defined. Equality is valid. |
| `scope.max_depth` | Effective child `max_depth` MUST be ≤ `parentScope.max_depth` when defined. Equality is valid. |
| `policy_id` | MUST equal parent `policy_id` |
| `expiry` | MUST be ≤ parent `expiry` |

Violation of any narrowing rule MUST result in DENY. Verification MUST NOT proceed past the first narrowing failure.

**Declared scope and action enforcement.** The guard checks proposed actions
against the effective `tools` and `max_amount` constraints, including inherited
parent constraints. `max_actions` participates in inheritance and narrowing;
the current implementation does not count delegated actions or consume an
action quota against it. `max_depth` also participates in declared scope
inheritance and narrowing; it does not add runtime recursion-depth enforcement
beyond the protocol's single-hop restriction.

**Resolution is verification-time only.** Effective-scope resolution is
performed by the verifier, not the issuer. `createDelegation` (or an
equivalent issuer-side constructor) continues to sign exactly the raw scope
the caller supplies — an omitted field stays absent from the signed
`DelegationV1` artifact. Implementations MUST NOT materialize inherited
fields into the signed artifact; doing so would change the canonical signing
bytes of every delegation that currently omits a field, which is unnecessary
to close the gap this section addresses.

**Multi-hop is out of scope.** This resolution rule operates on exactly one
`(child scope, parent scope)` pair. It does not define or require any
behavior for a delegation chain longer than one hop — see §5 Step 4, which
already denies a `DelegationV1` presented as another delegation's parent.

**Residual trust boundary.** `parentScope` is supplied by the verifying
party's caller (the deployment/integrator), not derived from a field on the
parent `AuthorizationV1` artifact itself — the wire format has no native
`tools`/`max_amount`/`max_actions`/`max_depth` fields to read it from.
This section defines correct narrowing against whatever `parentScope` is
supplied; it does not establish that the supplied `parentScope` accurately
reflects an external or independently authoritative grant. That remains a
deployment responsibility outside this specification's scope.

### 4.2 Delegator Binding

The `delegator` field MUST exactly match the `audience` field of the parent `AuthorizationV1`.

If the parent has no `audience`, verification MUST fail closed (DENY).

### 4.3 Expiry

`expiry` MUST be:
- a valid integer timestamp in seconds
- strictly greater than `issued_at`
- less than or equal to parent `AuthorizationV1` expiry

### 4.4 Single-Hop Enforcement

A `DelegationV1` artifact MUST NOT be used as the parent of another `DelegationV1`. The PEP MUST reject any chain where the parent artifact is itself a delegation.

### 4.5 Replay Protection

`delegation_id` is the replay nonce. Implementations that track consumed delegation IDs MUST reject a `DelegationV1` whose `delegation_id` has been previously seen in the same policy scope.

The optional `consumed_ids` input describes standalone artifact verification; it
does not waive replay resistance required by an execution profile. Implementations
that do not track consumed IDs MUST document that limitation and MUST NOT claim
replay-resistant execution on that basis. A PEP whose profile requires replay
resistance MUST enforce the [replay-store contract](../verification/verification-v1.md#43-replay-store-contract-and-deployment-boundary)
in its declared/configured replay domain. Fail-closed behavior is REQUIRED if
required replay state is unavailable or ambiguous.

Whether separate `delegation_id` consumption is required is determined by the
declared artifact/execution profile and replay model. An implementation MUST NOT
omit replay tracking required by that profile merely because another identifier
is consumed. Unavailable or indeterminate required replay state MUST block
protected execution.

As implementation behavior, the current TypeScript Guard always consumes the
parent `auth_id`, including when its store lacks `consumeDelegationId`. This is
not a general protocol rule permitting `delegation_id` tracking to be omitted,
and does not authorize repeated use of a parent for distinct delegations.
Optional tracking is not a deployment durability claim.

### 4.6 Fail-Closed Conditions

Verification MUST return DENY if any of the following are true:

- signature is invalid or unverifiable
- `kid` does not resolve in the issuer's KeySet
- parent `AuthorizationV1` cannot be resolved or its hash does not match `parent_auth_hash`
- parent `AuthorizationV1` is itself expired
- any scope narrowing invariant is violated
- `delegator` does not match parent `audience`
- `policy_id` does not match parent `policy_id`
- `expiry` has passed at verification time
- `delegation_id` has been previously consumed (if replay tracking is active)
- the artifact is structurally malformed
- Suggested denial reasons: `invalid_signature`, `unknown_kid`, `parent_auth_hash_mismatch`, `scope_violation`, `audience_mismatch`, `policy_mismatch`, `expired`, `replay`.

---

## 5. Verification Algorithm

Inputs:
- `delegation`: the `DelegationV1` artifact to verify
- `parent_auth`: the resolved `AuthorizationV1` referenced by `parent_auth_hash`
- `keyset`: the issuer's `KeySet`
- `now`: current timestamp in seconds (injected, not ambient)
- `consumed_ids`: optional set of previously seen delegation IDs
- `parentScope`: optional `DelegationScope` supplied separately by the
  verifying party's caller as the parent constraint input for scope
  narrowing (§4.1). It is **not** derived from `parent_auth` — the
  `AuthorizationV1` wire format has no native `tools`/`max_amount`/
  `max_actions`/`max_depth` fields to derive it from. When `parentScope` is
  absent, Step 9 is skipped because it has nothing to narrow against.
  Proving narrowing against a supplied `parentScope` does not by itself
  establish that `parentScope` reflects an external, independently
  authoritative grant — see the residual trust boundary in §4.1.

Returns: `ALLOW` or `DENY` with a reason list.
Canonicalization: all `canonicalJson(...)` calls use `canonicalization-v1` rules.

```
function verifyDelegation(delegation, parent_auth, keyset, now, consumed_ids?, parentScope?):

  // Step 1: Structural validation
  if delegation is missing required fields:
    return DENY("malformed artifact")

  // Step 2: Signature verification
  key = keyset.resolve(delegation.kid)
  if key is null:
    return DENY("unknown kid")

  signing_input = "OXDEAI_DELEGATION_V1\n" + canonicalJson(delegation without signature) // canonicalization-v1
  if not Ed25519.verify(key, signing_input, delegation.signature):
    return DENY("invalid signature")

  // Step 3: Resolve and bind parent authorization
  computed_hash = SHA256(canonicalJson(parent_auth)) // canonicalization-v1
  if computed_hash != delegation.parent_auth_hash:
    return DENY("parent_auth_hash mismatch")

  // Step 4: Validate parent is a raw AuthorizationV1 (not a DelegationV1)
  if parent_auth.type == "DelegationV1":
    return DENY("multi-hop delegation not permitted")

  // Step 5: Validate parent expiry
  if parent_auth.expiry < now:
    return DENY("parent authorization expired")

  // Step 6: Validate delegator binding
  if delegation.delegator != parent_auth.audience:
    return DENY("delegator does not match parent audience")

  // Step 7: Validate policy binding
  if delegation.policy_id != parent_auth.policy_id:
    return DENY("policy_id mismatch")

  // Step 8: Validate delegation expiry
  if delegation.expiry > parent_auth.expiry:
    return DENY("expiry exceeds parent expiry")
  if delegation.expiry < delegation.issued_at:
    return DENY("expiry before issued_at")
  if delegation.expiry < now:
    return DENY("delegation expired")

  // Step 9: Resolve effective scope, then validate narrowing.
  //
  // An omitted delegation.scope sub-field is NOT unconstrained when parentScope
  // constrains it. It inherits the parent's value first. Comparison always
  // runs against the resolved effective value, never against the raw
  // (possibly absent) child field directly.
  // Skip this step when parentScope is absent; scope authority then remains
  // a deployment responsibility. If neither side sets a field, it remains unset.
  if parentScope is provided:
    effective_tools       = delegation.scope.tools       ?? parentScope.tools
    effective_max_amount  = delegation.scope.max_amount  ?? parentScope.max_amount
    effective_max_actions = delegation.scope.max_actions ?? parentScope.max_actions
    effective_max_depth   = delegation.scope.max_depth   ?? parentScope.max_depth

    if parentScope.tools is set:
      if not effective_tools ⊆ parentScope.tools:
        return DENY("tool scope exceeds parent tools")

    if parentScope.max_amount is set:
      if effective_max_amount > parentScope.max_amount:
        return DENY("max_amount exceeds parent max_amount")

    if parentScope.max_actions is set:
      if effective_max_actions > parentScope.max_actions:
        return DENY("max_actions exceeds parent max_actions")

    if parentScope.max_depth is set:
      if effective_max_depth > parentScope.max_depth:
        return DENY("max_depth exceeds parent max_depth")

  // Step 10: Replay check
  if consumed_ids is provided AND delegation.delegation_id in consumed_ids:
    return DENY("delegation_id already consumed")

  return ALLOW
```

---

## 6. PEP Contract

A PEP that accepts `DelegationV1` as an authorization credential MUST:

1. Resolve the parent `AuthorizationV1` locally (from cache or request context - no live control plane call)
2. Run the full verification algorithm above
3. After successful verification/authentication, atomically consume the required replay entitlement under §4.5; unavailable or indeterminate required replay state MUST block execution
4. Execute the action only if verification returns `ALLOW` and required consumption succeeds
5. Record a delegation audit event referencing both `delegation_id` and `parent_auth_hash`

A consumed entitlement is not a completed action. Failure or crash between steps
3 and 4 can spend it without execution; restart persistence is a deployment
property, not proof supplied by this verification algorithm.

A PEP MUST NOT:

- execute on a `DelegationV1` that has not passed full verification
- accept a `DelegationV1` whose parent cannot be resolved
- accept a scope claim without comparing against the resolved parent

---

## 7. Audit Event

On `ALLOW`, the PEP MUST emit an audit event of the form:

```json
{
  "type": "DELEGATION_EXECUTION",
  "delegation_id": "<delegation_id>",
  "parent_auth_hash": "<parent_auth_hash>",
  "delegatee": "<delegatee>",
  "policy_id": "<policy_id>",
  "timestamp": "<unix ms>",
  "decision": "ALLOW"
}
```

On `DENY`, the PEP MUST emit:

```json
{
  "type": "DELEGATION_DENIED",
  "delegation_id": "<delegation_id or null>",
  "reason": "<reason string>",
  "timestamp": "<unix ms>",
  "decision": "DENY"
}
```

Both events MUST be included in the hash-chained audit log.

---

## 8. What Is Explicitly Out of Scope

| Feature | Status |
|---|---|
| Multi-hop delegation chains | Not supported (single hop only) |
| Revocation system | Not included (stateless model) |
| Federation across trust domains | Not included |
| Dynamic scope expansion | Prohibited by invariant |
| Delegation of delegation | Prohibited by §4.4 |

---

## 9. Relationship to AuthorizationV1

| Property | AuthorizationV1 | DelegationV1 |
|---|---|---|
| Issued by | PDP | Delegating principal |
| Verified by | PEP | PEP |
| Depends on | policy state | parent AuthorizationV1 |
| Scope | defined by policy | subset of parent |
| Re-issuable | no | no |
| Multi-hop | n/a | prohibited |
| Signing | Ed25519 | Ed25519 |

---

## 10. References

- [OxDeAI Specification](../../../SPEC.md)
- [AuthorizationV1 schema](../../../SPEC.md#4-authorizationv1)
- [KeySet Distribution](../../../SPEC.md#11-keyset-distribution-v1-baseline)
- [Cross-Organization Verification Model](../../../SPEC.md#12-cross-organization-verification-model)
- [Roadmap: v2.x Delegated Agent Authorization (shipped)](../../../ROADMAP.md)
