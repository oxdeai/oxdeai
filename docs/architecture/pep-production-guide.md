# Production PEP Wiring Guide

## Status

Non-normative (developer documentation)






Non-normative guide. Normative specs are in `SPEC.md` and `docs/spec/`; artifact status is defined there (AuthorizationV1/DelegationV1/PEP Stable; VerificationEnvelope pending; ExecutionReceipt planned). All hashes and signature preimages MUST use `canonicalization-v1`. Protocol decisions are ALLOW/DENY with deterministic error codes defined in the specs; any `ok/invalid/inconclusive` labels are interface summaries only. Locked vectors: `docs/spec/test-vectors/canonicalization-v1.json`, `authorization-v1.json`, `pep-vectors-v1.json`, `delegation-vectors-v1.json`.

This guide describes a minimal production wiring pattern for a Policy Enforcement Point (PEP) using OxDeAI.

Reference architecture:
- [`docs/adapter-reference-architecture.md`](../adapters/adapter-reference-architecture.md)
- [`docs/adapter-contract.md`](../adapters/adapter-contract.md)
- diagram workflow: [`docs/diagrams/README.md`](../diagrams/README.md)

## Scope

Applies to services that execute external side effects (tools, provisioning, payments, API calls) and must enforce OxDeAI authorization before execution.

Upstream runtimes MAY reach the PEP through structured tool calls, CLI-style command execution, MCP/server-mediated invocation, or framework-specific adapters.
Any adapter layer between those action surfaces and OxDeAI is responsible for deterministic normalization into intent before policy evaluation.
OxDeAI remains the authorization layer at the execution boundary; it does not define the upstream action-expression interface.

## Shared Adapter Contract Relation

The shared adapter contract is documented in [`docs/adapter-contract.md`](../adapters/adapter-contract.md).

For production PEP wiring, that contract implies:

- normalization happens before policy evaluation
- PEP enforcement happens before side effects
- the refusal path MUST remain explicit
- audit emission SHOULD remain consistent with the evaluated intent, state, and authorization context

## Required Inputs

- Trusted issuer configuration
- Trusted audience identifier for the current service
- Trusted KeySet(s) for signature verification
- Current expected `policy_id` context
- Consumed authorization store (`auth_id` single-use tracking)

## Enforcement Sequence

Before executing an external action, the PEP MUST:

1. Parse authorization artifact and reject malformed payloads.
2. Verify signature and key resolution (`alg`, `kid`, trusted issuer keyset).
3. Verify issuer and audience binding.
4. Verify `decision == ALLOW`.
5. Verify not expired (`expiry > now`).
6. Verify policy binding (`policy_id` equals expected policy context).
7. Verify intent binding (`intent_hash` equals hash of the exact action about to execute).
8. Verify state binding (`state_hash` matches required state snapshot context).
9. Verify replay protection (`auth_id` not previously consumed).

If any step fails, execution MUST NOT occur.

## Execution and Consumption

After successful completion of all preceding verification checks:

1. Atomically consume `auth_id` after boundary binding (step 15), as the last verification step (step 16) in `docs/spec/verification/verification-v1.md` §5.
2. Execute the side effect only after successful consumption.
3. Persist execution/audit evidence as required by your environment.

If required consumption fails, is unavailable, or its outcome is indeterminate, execution MUST NOT proceed. Consumed identifiers MUST remain unavailable for reuse throughout the applicable acceptance window, accounting for verifier clocks (`docs/spec/verification/verification-v1.md` §4.3). Restart persistence and backend durability require separate deployment evidence; implementation conformance does not establish them, and no backend technology is mandated. Consumption does not form an atomic transaction with the protected side effect and does not prove execution occurred.

## Failure Policy

PEP implementations SHOULD fail closed for:

- unknown issuer
- unknown `kid`
- unsupported `alg`
- invalid signature
- policy mismatch
- audience mismatch
- replayed `auth_id`
- verification ambiguity

## Minimal SDK Pattern

Use `@oxdeai/sdk` guard boundary:

- PDP: `PolicyEngine.evaluatePure(...)`
- PEP: `createGuard(...)` callback boundary

`createGuard()` gates the callback on the engine's `ALLOW` decision and, by default, an engine-level HMAC binding check (`verifyAuthorization: false` disables that check). It does not itself atomically consume `auth_id`. A deployment requiring replay-resistant execution MUST enforce the required atomic consumption at its execution boundary before the protected side effect.

## Operational Notes

- Keep authorization TTL short.
- Keep consumed authorization storage scoped by issuer/audience/policy context.
- Rotate signing keys with explicit `kid` and validity windows.
- Monitor verification failures and replay rejections as security signals.
