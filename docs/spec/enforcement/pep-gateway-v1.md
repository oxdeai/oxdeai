# OxDeAI PEP Gateway Specification v1

**Status:** Stable (Normative Specification)
**Category:** Standards Track

---

## 1. Introduction

This document specifies the **Policy Enforcement Point (PEP) Gateway** for OxDeAI-compatible systems.

The PEP Gateway enforces a **non-bypassable execution authorization boundary** between untrusted action proposals and side-effecting systems.

The core invariant is:

> **No valid authorization → No execution path**

This specification defines mandatory behaviors for systems claiming conformance.

---

## 2. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 3. Scope

This specification defines:

* PEP Gateway architectural role
* Trust model
* Request and verification requirements
* Execution control semantics
* Replay protection
* Deployment constraints

This specification does NOT define:

* Policy language
* Agent runtime behavior
* Orchestration systems
* Sandboxing mechanisms

---

## 4. Architectural Role

### 4.1 Execution Boundary

The PEP Gateway **MUST** act as the **sole execution boundary** for protected actions.

A protected action **MUST NOT** be executable without passing through the PEP Gateway.

---

### 4.2 System Positioning

The gateway operates between:

* **Untrusted proposal sources** (e.g., agents, LLM outputs)
* **Trusted execution targets** (e.g., APIs, infrastructure, databases)

---

### 4.3 Execution Flow

```text
Proposal → Gateway → Verification → Decision → Execution (if allowed)
```

---

## 5. Core Invariant

The following invariant is **REQUIRED**:

> A protected action **MUST NOT** be reachable without valid authorization verified by the PEP Gateway.

---

## 6. Request / Response Contract (normative profile)

Transport: HTTP/1.1 or HTTP/2

### 6.1 Endpoint
`POST /execute`

### 6.2 Request Body
```json
{
  "action": <canonicalizable object>,
  "authorization": <AuthorizationV1 object>
}
```

### 6.3 Response Bodies
- 200 OK (ALLOW):
```json
{
  "ok": true,
  "decision": "ALLOW",
  "executed": true,
  "auth_id": "...",
  "intent_hash": "...",
  "upstream_result": <object>
}
```
- 403 Forbidden (DENY):
```json
{
  "ok": false,
  "decision": "DENY",
  "reason": "<string>"
}
```

### 6.4 Verification Requirements
- Canonicalize `action` using `canonicalization-v1`; compute `intent_hash`; MUST match `authorization.intent_hash`.
- Verify signature of AuthorizationV1 (`alg`, `kid`), audience, expiry, issuer trust config; fail closed.
- Enforce replay protection on `auth_id` (single-use or bounded window).
- Reject if any step fails; MUST NOT forward to upstream.

### 6.5 Upstream Call
- PEP MUST be the sole caller of upstream.
- PEP MUST inject the internal header `x-internal-executor-token` with the shared secret known only to PEP and upstream.
- Upstream MUST reject requests missing/invalid `x-internal-executor-token`.

### 6.6 Error Semantics
- Any parsing/canonicalization/verification error → 403 with `reason`.
- Upstream execution failure/invalid response → 502 Bad Gateway (MUST NOT report executed=true).
- Upstream timeout → 504 Gateway Timeout.
- Gateway-local unexpected failure → 500 Internal Server Error (MUST be rare; still MUST NOT report executed=true).

Any system violating this invariant is **NON-CONFORMANT**.

---

## 6. Trust Model

### 6.1 Trusted Components

The following components **MUST** be trusted:

* PEP Gateway runtime
* Authorization verification implementation
* Trusted key/issuer store
* Replay protection state store
* Upstream execution connector

---

### 6.2 Untrusted Components

The following components **MUST** be treated as untrusted:

* LLM outputs
* Agent reasoning
* Tool invocation proposals
* Client-side logic
* Non-cryptographically bound metadata

---

### 6.3 Trust Rule

The gateway **MUST** treat all incoming actions as untrusted until verification succeeds.

---

## 7. Non-Bypassability

### 7.1 Requirement

The PEP Gateway **MUST** be deployed such that:

* Execution targets **MUST NOT** be directly reachable by agents
* All execution requests **MUST** pass through the gateway
* Authorization verification **MUST** be mandatory

---

### 7.2 Failure Condition

If a system allows execution without gateway verification, it is **NON-CONFORMANT**.

---

### 7.3 Prohibited Pattern

An agent that *can* call a target directly, even if instructed not to, **MUST** be considered a bypass.

---

## 8. Deployment Profiles

### 8.1 HTTP Gateway

The gateway **MUST** be the exclusive entry point for protected HTTP endpoints.

---

### 8.2 Sidecar Proxy

The system **MUST** enforce network controls preventing bypass of the sidecar.

Credentials **MUST** be held by the gateway, not the agent.

---

### 8.3 Local Executor

Execution capabilities **MUST** be restricted to the gateway process.

Agents **MUST NOT** directly access execution primitives.

---

## 9. Request Model

### 9.1 Required Fields

A request **MUST** include:

* Action payload
* Authorization artifact
* Execution context (if required)

---

### 9.2 Binding Requirement

The gateway **MUST NOT** execute an action unless it matches the authorization binding exactly.

---

## 10. Authorization Verification

### 10.1 Mandatory Checks

The gateway **MUST** verify:

* Artifact structure validity
* Signature validity
* Trusted issuer
* Audience match
* Decision equals `ALLOW`
* Expiration validity
* Intent hash match
* Policy context match
* Replay protection
* State binding (if applicable)

---

### 10.2 Failure Semantics

If any verification step fails, the gateway:

* **MUST** return `DENY`
* **MUST NOT** execute the action

---

## 11. Intent Binding

The gateway **MUST** enforce exact intent matching.

Execution **MUST** be denied if any of the following differ:

* Action type
* Tool identifier
* Parameters
* Target
* Canonical representation

Intent comparison **MUST** be deterministic.

---

## 12. Replay Protection

### 12.1 Requirement

The gateway **MUST** enforce replay resistance.

---

### 12.2 Minimum Model

* Unique authorization identifier (`auth_id`)
* Atomic consumption tracking in a declared/configured replay domain
* Retention of consumed IDs while their authorizations could otherwise still be accepted

The gateway MUST authenticate/verify before authoritative replay mutation and
consume before the protected side effect. Unauthenticated input MUST NOT mutate
trusted replay state. Required replay-state failure, unavailability or an
indeterminate consume result MUST block execution; it MUST NOT become permissive
success. The [store contract](../verification/verification-v1.md#43-replay-store-contract-and-deployment-boundary)
mandates atomicity and retention, not a backend technology.

“Tracking” does not itself prove restart persistence, replica sharing, backend
persistence settings, topology correctness, HA/SLA or recovery guarantees. Those
are deployment properties. A successful consume spends the authorization; it does
not prove execution completed or even started. A crash between consume and effect
may leave a spent authorization with no effect.

---

### 12.3 Behavior

Re-use of an authorization:

* **MUST** result in `DENY`
* **MUST NOT** execute

---

## 13. State Binding

If state binding is required:

* The gateway **MUST** validate state consistency
* The gateway **MUST** deny execution if state cannot be verified

---

## 14. Fail-Closed Semantics

### 14.1 Requirement

The gateway **MUST** fail closed in all ambiguous situations.

---

### 14.2 Conditions

Including but not limited to:

* Verifier unavailable
* Invalid artifact
* Signature failure
* Unknown issuer
* Replay uncertainty
* State ambiguity

---

### 14.3 Rule

> Uncertainty **MUST** result in `DENY`

---

## 15. Credential Separation

### 15.1 Requirement

Execution credentials:

* **MUST** be held by the gateway or trusted executor
* **MUST NOT** be accessible to agents

---

### 15.2 Security Property

This ensures non-bypassability of the execution boundary.

---

## 16. Execution Contract

If authorization succeeds:

* The gateway **MAY** execute the action upstream

---

### 16.1 Requirements

Execution **MUST** preserve:

* Correlation identifier
* Authorization identifier
* Audit linkage
* Action identity

---

## 17. Audit and Evidence

The gateway **SHOULD** produce execution evidence including:

* Action
* Authorization
* Verification result
* Execution outcome

---

Evidence **MAY** be packaged as:

* Signed logs
* Execution receipts
* Verification envelopes

---

## 18. Error Semantics

The gateway **MUST** return structured denial responses including:

* Decision (`DENY`)
* Machine-readable reason code
* Human-readable reason
* Correlation identifier

---

The gateway **MUST NOT** leak sensitive verification data.

---

## 19. Performance Considerations

Verification latency **SHOULD** be bounded.

However:

* Correctness **MUST** take precedence over performance
* Fail-closed semantics **MUST NOT** be weakened

---

## 20. Conformance

A system is **CONFORMANT** if:

* Execution is only reachable through the gateway
* Authorization is mandatory
* Failures result in denial
* Intent binding is enforced
* Replay protection is enforced
* Credentials are isolated

---

## 21. Non-Conformance

A system is **NON-CONFORMANT** if it:

* Allows direct execution bypass
* Uses advisory-only verification
* Defaults to fail-open
* Exposes execution credentials to agents

---

## 22. Security Properties

A conformant PEP Gateway provides:

* Mandatory authorization
* Fail-closed enforcement
* Replay resistance
* Deterministic execution control

---

It does NOT provide:

* Sandboxing
* Model alignment
* Content safety
* Host integrity

---

## 23. Execution Flow

### 23.1 Allow Path

1. Agent submits action + authorization
2. Gateway verifies authorization
3. Gateway validates intent, state, replay
4. Gateway returns `ALLOW`
5. Gateway executes action

---

### 23.2 Deny Path

1. Agent submits request
2. Verification fails
3. Gateway returns `DENY`
4. No execution occurs

---

## 24. Invariant Summary

```text
proposal
→ verification
→ ALLOW
→ execution
```

If any step fails:

```text
DENY
→ no execution
```

---

## 25. Core Requirement

> **No valid authorization → No execution path**

---

## 26. Future Work (Non-Normative)

The following items are identified as **future extensions** to strengthen the specification.
This section is **non-normative** and does not affect current conformance requirements.

### 26.1 Authorization Schema Formalization

The specification SHOULD be extended with a **fully normative definition of AuthorizationV1**, including:

* Canonical schema definition
* Field-level constraints
* Cryptographic binding requirements
* Cross-language determinism guarantees

---

### 26.2 Threat Model Definition

A formal **threat model** SHOULD be introduced, covering:

* Replay attacks
* Authorization forgery attempts
* Canonicalization inconsistencies
* TOCTOU (time-of-check vs time-of-use) risks
* Key compromise scenarios

A STRIDE-like or equivalent structured model is RECOMMENDED.

---

### 26.3 Conformance Test Suite

A standardized **conformance test suite** SHOULD be defined to:

* Validate gateway implementations
* Ensure deterministic verification behavior
* Test replay protection guarantees
* Validate fail-closed semantics

This suite SHOULD be usable across multiple languages and runtimes.

---

### 26.4 Multi-Document Specification

The specification MAY evolve into a multi-document standard:

* **Core Specification** (protocol invariants)
* **Gateway Specification** (this document)
* **Authorization Specification** (AuthorizationV1 schema and rules)
* **Verification Specification** (verification semantics and APIs)

This separation would improve modularity, clarity, and independent evolution.

---

## 27. State Provider Requirements

### 27.1 Normative requirement

Deployments using `OxDeAIGuard` with Profile C - live-state re-verification through `computeStateHash` - **MUST** satisfy the minimum state provider integrity requirements defined in `docs/spec/state-provider-requirements.md`.

For Profile A/B deployments, these requirements are **best-practice guidance** unless the deployment introduces state-dependent enforcement equivalent to Profile C.

### 27.2 Trust boundary

`getState()` is trusted input to the guard. The PEP verifies:

```
computeStateHash(liveState) === authorization.state_hash
```

This proves hash consistency between the authorization artifact and the live state object. It does not prove that the state provider served honest state. See `docs/spec/state-provider-requirements.md §1` for the full trust boundary definition.

---
