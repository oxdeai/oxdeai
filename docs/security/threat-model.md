# OxDeAI Threat Model

## Status

Non-normative (developer documentation)





This document is a companion reference (non-normative). For the canonical normative specification, see [SPEC.md](../../SPEC.md) and `docs/spec/`; artifact status is defined there.

# OxDeAI Threat Model

This document captures the protocol threat model for OxDeAI.
All hashes and signature preimages MUST use `canonicalization-v1`; protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs.

Reference:
- Primary protocol spec: [SPEC.md](../../SPEC.md)
- Protocol overview: [Protocol overview](../protocol/overview.md)
- Conformance guidance (fail-closed, deterministic ordering): [docs/spec/conformance/conformance-v1.md](../spec/conformance/conformance-v1.md)
- Delegation invariants and replay/multi-hop constraints: [docs/spec/artifacts/delegation-v1.md](../spec/artifacts/delegation-v1.md)

## Covered Risks
- Replay abuse
- Runaway execution/tool loops
- Concurrency explosion
- Silent budget drain
- Recursive planning escalation

### DelegationV1 threat surface (v1.3+)
- **Authority escalation** - delegatee claims tools/amounts/depth beyond what the parent authorization permits; mitigated by strictly narrowing scope enforcement at the PEP
- **Parent hash forgery** - delegation claims binding to a parent authorization it was not issued under; mitigated by `parent_auth_hash = SHA256(canonical_json(parent))` verified at chain-check time
- **Delegator spoofing** - delegation claims a delegator that does not match `parent.audience`; caught by delegator-match check before inner verification
- **Re-delegation / multi-hop escalation** - `DelegationV1` re-delegating authority from another `DelegationV1`; blocked by single-hop constraint (multi-hop denied if parent has `delegation_id`)
- **Delegation replay** - reusing a consumed `delegation_id`; mitigated by replay check against `consumedDelegationIds`
- **Expired delegation abuse** - presenting a delegation after its `expiry`; caught by expiry check at verification time with explicit `now` injection
- **Signature forgery** - presenting a delegation with a tampered payload or forged signature; mitigated by Ed25519 domain-separated canonical signature verification when `trustedKeySets` is provided
- **Key substitution** - presenting a delegation with a `kid` not in the trusted keyset for the issuer; caught by `DELEGATION_KID_UNKNOWN`

### Enforcement-boundary input and configuration (`@oxdeai/guard`)
- **Request mutation between verification and dispatch** - a caller changing the action or authorization (plain mutation, accessor, `Proxy`) after it was checked; mitigated by one plain-data snapshot taken before any security decision in `createPepGatewayExecutor` and on the guard delegation path. Non-plain input is denied before replay consumption.
- **Malformed replay-store answers** - a store resolving anything other than the boolean `true` or `false`; denied as `REPLAY_STORE_UNAVAILABLE` at every consume site. A denial does not prove the id was left unconsumed.
- **Post-construction configuration changes** - mutating the deployer's config object after construction; `createSecureGuard` and `createPepGatewayExecutor` capture their security configuration at construction. The low-level `OxDeAIGuard` reads its configuration per request by design (see Deployment assumptions).
- **Prototype pollution reaching configuration** - inherited option values on `Object.prototype` / `Array.prototype` / `Function.prototype`; `createSecureGuard` refuses to construct when they are present before, during or at the end of construction.

## Security Goals
- Deterministic, fail-closed policy decisions
- Pre-execution authorization boundary (fail-closed)
- Tamper-evident audit chain
- Verifiable protocol artifacts
- Delegation authority strictly bounded by parent authorization scope and expiry

## Deployment assumptions

These are conditions the deployment must provide. OxDeAI does not establish them, and
a passing test suite does not show that a given deployment meets them. Details and
safe/unsafe claims: [2.0 residual scope](../audits/2.0-residual-scope.md) §9 and §14-§18.

- **Single enforced path.** Every route to the protected side effect goes through the
  Guard or PEP; alternate routes are not protected (residual scope §9).
- **Trusted enforcement process.** No attacker-controlled code runs inside the
  Guard/PEP process. Untrusted agents, tools and plugins run outside it (IR-03,
  residual scope §14).
- **Trusted configuration object.** The configuration, including getters, `Proxy`
  traps and callbacks it contains, is supplied by the deployer. With the low-level
  `OxDeAIGuard`, it must also stay unchanged by untrusted code for the guard's
  lifetime (residual scope §15).
- **Transport limits.** Request size and parsing limits are enforced before the PEP
  HTTP server (residual scope §16).
- **Replay domain.** Multi-instance or restart-durable deployments configure a
  shared, atomic, durable replay store; the process-local store only protects one
  process lifetime (residual scope §17).

## Out of Scope
- Business logic correctness of downstream systems
- Key custody / wallet infrastructure
- Host runtime compromise, including attacker-controlled code executing inside the Guard/PEP process (IR-03: partial hardening only, see residual scope §14)
- Multi-hop delegation (not supported in current protocol line)
- Cross-org trust federation / revocation mesh
