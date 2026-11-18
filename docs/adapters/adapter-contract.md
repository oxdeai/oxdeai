# Shared Adapter Contract

## Status

Non-normative (developer documentation)






This document defines the shared v1.4 adapter contract for OxDeAI integrations.

It is an integration contract for adapters and runtime wiring.
It is not a protocol artifact and does not change OxDeAI protocol semantics, artifact formats, or verifier APIs.

## Purpose

The adapter contract standardizes integration behavior across runtimes so that different action surfaces can be normalized, authorized, executed or refused, and audited in a consistent way.

Its purpose is to make third-party integrations comparable without redefining the core OxDeAI protocol contract:

`(intent, state, policy) -> deterministic decision`

## Scope

This contract covers:

- proposed action input
- normalization into intent
- authorization gate
- execute/refuse outcome
- audit emission

## Non-goals

This contract does not:

- redefine protocol semantics
- define framework-specific runtime APIs
- mandate one universal raw action format across all frameworks
- introduce new protocol artifacts

## Canonical Flow

```text
raw action surface
  -> adapter normalization
  -> intent + state
  -> PDP evaluation
  -> AuthorizationV1 on ALLOW
  -> PEP verification gate
  -> execute or refuse
  -> audit emission
  -> optional envelope packaging
```

## Shared Adapter Responsibilities

Adapters implementing this contract MUST:

1. Accept a runtime/framework-specific proposed action.
2. Normalize that proposed action deterministically into OxDeAI intent.
3. Provide the current policy state used for evaluation.
4. Invoke the OxDeAI PDP over normalized `intent` and current `state`.
5. Enforce `verifyAuthorization(...)` before any external side effect executes.
6. Emit auditable decision and execution/refusal records.
7. Preserve deterministic and reproducible integration behavior for the same evaluated situation.

## Proposed Action Input

The adapter input is a proposed action originating from a runtime-specific action surface.

Raw input MAY come from:

- typed tool calls
- CLI-style command execution
- workflow or task nodes
- MCP/server-mediated invocation
- framework-specific adapters

The raw action format is runtime-specific.
The contract does not require one universal raw action schema.

Normalization from raw proposed action to intent MUST remain deterministic.

## Normalized Intent Requirements

The normalized intent used by the adapter SHOULD preserve at least:

- stable action type
- stable target or resource identity where applicable
- the binding fields needed for policy evaluation
- deterministic serialization inputs used for hashing and authorization binding

This contract does not define a new protocol schema for intent.
It defines integration expectations for how adapters prepare intent before evaluation.

Equivalent external actions SHOULD map to equivalent intent representations within the adapter implementation.

## Authorization Gate

The shared authorization step is:

1. The adapter submits normalized `intent` and current `state` to the PDP.
2. The PDP returns `ALLOW` or `DENY`.
3. On `ALLOW`, `AuthorizationV1` MAY be emitted.
4. On `DENY`, the external side effect MUST NOT execute.

This contract does not redefine `AuthorizationV1`.
It defines when and how adapters are expected to rely on the existing authorization boundary.

## Execute / Refuse Contract

Adapters SHOULD expose execution outcomes in a way that keeps authorization and replay reasoning understandable.

The shared conceptual outcomes are:

- authorized execution path
- refused execution path
- failure before execution
- failure after execution attempt

The exact runtime-facing return type MAY vary by framework.
What matters is that the adapter preserves a clear distinction between:

- action proposed
- action authorized
- action refused
- action attempted
- action completed or failed

### Execution binding (ACT-1)

The action that executes must be the action that was authorized.
The framework input (tool call, action object) is caller-owned and can change while authorization is awaited.
The runtime adapters therefore pass the protected tool the verified action: the deep-frozen `ProposedAction` snapshot that `@oxdeai/guard` evaluated, bound to the authorization and handed unchanged to `beforeExecute` and `onDecision`:

```ts
await guard(toolCall, (verified) => executeTool(verified.name, verified.args));
```

An executor that ignores this argument and reads the original input (`() => executeTool(toolCall)`) still runs, for backward compatibility, but is not covered by the binding.
Unsupported action input (Proxies, accessors, class instances and other non-plain data) is rejected before evaluation, replay consumption and state writes.
This binding does not protect against malicious code running inside the enforcement process itself.

## Audit Emission

Minimum integration expectations:

- the authorization decision SHOULD be auditable
- execution or refusal outcome SHOULD be auditable
- audit records SHOULD maintain deterministic linkage to intent, state, and authorization context
- adapters SHOULD support later envelope construction where applicable

This contract does not define new audit event types.
It defines integration expectations around consistent audit handling.

## Cross-Adapter Reproducibility

Equivalent integration scenarios SHOULD produce comparable authorization and audit outcomes across adapters, even when raw runtime action formats differ.

The goal is not byte-identical raw runtime input.
The goal is reproducible normalization, authorization behavior, and auditable execution/refusal outcomes at the OxDeAI boundary.

## Minimal Conformance Scenario

The recommended minimum validation scenario for an adapter is:

- `ALLOW`
- `ALLOW`
- `DENY`
- `verifyEnvelope() => ok`

This scenario is intended to demonstrate that:

- normalization is deterministic
- authorization gating is enforced
- refusal paths remain explicit
- emitted audit evidence is sufficient for later verification

## Non-Normative Conceptual Shape

The following shape is documentation guidance only.
It is not a protocol type definition.

```ts
type ProposedAction = unknown;

type AdapterEvaluationInput = {
  intent: unknown;
  state: unknown;
};

type AdapterDecision =
  | { kind: "allow"; authorization: unknown }
  | { kind: "deny"; reason?: string };

type AdapterExecutionOutcome =
  | { kind: "executed"; result?: unknown }
  | { kind: "refused"; reason?: string };
```
