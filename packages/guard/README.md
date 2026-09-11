# @oxdeai/guard
Policy Enforcement Point for the OxDeAI execution-time authorization protocol.
Verifies AuthorizationV1 locally, fail-closed.
No valid authorization, no execution through the reviewed enforcement boundary.

Current `@oxdeai/guard` package line: **2.0.0**. See [`CHANGELOG.md`](./CHANGELOG.md)
for the full breaking-change list. `expectedAudience` and `trustedKeySets` are
now required, `getState`/`setState` are versioned/CAS, and `createSecureGuard`
is new in this release.

This package exposes two entry points:

- **`OxDeAIGuard`**: the lower-level guard API (documented first, below).
- **`createSecureGuard`**: the Tier 1 secure path, built on top of `OxDeAIGuard`,
  which additionally reconciles proposer-declared identity against a
  server-established `TrustedExecutionContext`. See
  [Tier 1 secure path](#tier-1-secure-path).

---

## Why this package exists

Every runtime adapter (LangGraph, CrewAI, OpenAI Agents SDK, OpenClaw, custom agents etc.)
needs to enforce the same authorization boundary. Without a shared PEP layer,
each adapter re-implements authorization logic, creating divergence and security
gaps.

`@oxdeai/guard` provides that shared layer:

- **One place** for all PEP logic: adapters stay thin.
- **Fail-closed**: ambiguous state, missing artifacts, or evaluation errors
  block execution.
- **No runtime-specific code**: pure TypeScript, no LangGraph/CrewAI/OpenAI
  imports.

---

## Installation

```sh
pnpm add @oxdeai/guard @oxdeai/core
```

---

## Basic usage

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";

// Build the guard once per agent session.
const guard = OxDeAIGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => { state, version } | Promise<{ state, version }>
  setState,    // (state, expectedVersion) => boolean | Promise<boolean>  (CAS)
  expectedAudience: "agent-xyz", // required: must match engine's authorization_audience
  trustedKeySets: [myKeySet],    // required: KeySets used to verify Ed25519 signatures
});

// Call it before every tool execution.
const result = await guard(
  {
    name: "provision_gpu",
    args: { asset: "a100", region: "us-east-1" },
    estimatedCost: 500,
    resourceType: "gpu",
    context: {
      agent_id: "agent-xyz",
      target: "gpu-pool-us-east-1",
    },
  },
  async () => provisionGpu("a100", "us-east-1")
);
```

The `execute` callback is **only invoked when the policy engine returns ALLOW
and the authorization artifact passes cryptographic verification**. On DENY,
`OxDeAIDenyError` is thrown and execution never reaches the callback.

**Ordering:** the CAS `setState(nextState, expectedVersion)` commit happens
before `execute()` is invoked, not after. This blocks execution on a
concurrent-modification conflict before any side effect runs. It does not
mean the guard confirms `execute()` succeeded before committing state: a
failure inside `execute()` after the commit does not roll the state commit
back. See [Known limits](#known-limits).

---

## Custom action-to-intent mapping

The default normalizer converts a `ProposedAction` to an OxDeAI `Intent` using
heuristics (cost → amount, resourceType → action_type, etc.). For production
deployments you should supply a custom mapper that expresses your domain model
precisely:

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";
import { buildIntent } from "@oxdeai/sdk";

const guard = OxDeAIGuard({
  engine,
  getState,
  setState,
  expectedAudience: "agent-xyz",
  trustedKeySets: [myKeySet],
  mapActionToIntent(action) {
    return buildIntent({
      agent_id: action.context?.agent_id as string,
      action_type: "PROVISION",
      asset: action.args.asset as string,
      target: action.args.region as string,
      amount: BigInt(Math.round((action.estimatedCost ?? 0) * 1_000_000)),
      nonce: BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER)),
      intent_id: crypto.randomUUID(),
      timestamp: action.timestampSeconds ?? Math.floor(Date.now() / 1000),
    });
  },
});
```

---

## Lifecycle hooks

```typescript
OxDeAIGuard({
  engine,
  getState,
  setState,
  expectedAudience: "agent-xyz",
  trustedKeySets: [myKeySet],

  // Called after authorization but before execution.
  async beforeExecute(action, authorization) {
    logger.info("executing", { action: action.name, auth_id: authorization.auth_id });
  },

  // Called after a completed policy decision: a valid ALLOW (once the
  // protected callback has returned) or a valid DENY. Errors here are
  // swallowed.
  async onDecision({ action, decision, authorization, reasons }) {
    auditLog.write({ action: action.name, decision, reasons });
  },

  // Called for a rejection raised at the guard boundary BEFORE execute()
  // starts and that never produced a policy decision: an unbranded trusted
  // context, a provenance conflict, a delegation replay, a state-hash
  // mismatch, a CAS conflict. Disjoint from onDecision: a rejection is
  // reported on exactly one of the two hooks, never both. Errors here are
  // swallowed.
  async onBoundaryEvent({ stage, boundaryFailure, policyEvaluated }) {
    auditLog.write({ stage, boundaryFailure, policyEvaluated });
  },
});
```

Neither hook reports the outcome of the protected `execute()` callback itself.
Once `execute()` has started, the guard has already permitted the action; a
failure inside the callback is the caller's own outcome, not a guard decision,
and is not represented on either stream (see
[Known limits](#known-limits)).

---

## Tier 1 secure path

`OxDeAIGuard` (above) trusts whatever `agent_id`, `tool`, and `depth` the
caller's `ProposedAction`/`Intent` declares. `createSecureGuard` closes that
gap for deployments that can authenticate the caller and resolve the route
before evaluation: it reconciles the proposer's declared identity against a
server-established `TrustedExecutionContext`, and fails closed on conflict,
before the policy engine ever runs.

```typescript
import { createSecureGuard, createTrustedExecutionContext } from "@oxdeai/guard";

const guard = createSecureGuard(
  {
    engine,
    getState,
    setState,
    expectedAudience: "agent-xyz",
    trustedKeySets: [myKeySet],
  },
  { tenancy: "single-tenant" } // or "multi-tenant": required, never defaulted
);

// Constructed by the PEP AFTER authenticating the caller and resolving the
// protected route. Never deserialize this from proposer-controlled request
// JSON. It is a separate positional argument precisely so there is no place
// in the request payload to put a forged one.
const trustedContext = createTrustedExecutionContext({
  principalId: authenticatedPrincipal.id,
  agentId: authenticatedPrincipal.agentId,
  adapterId: "http-adapter",
  depth: currentCallDepth, // required, never defaulted: no implicit "root call" fallback
});

const result = await guard(
  trustedContext,
  {
    name: "provision_gpu",
    args: { asset: "a100", region: "us-east-1" },
    estimatedCost: 500,
    resourceType: "gpu",
    context: { target: "gpu-pool-us-east-1" },
  },
  async () => provisionGpu("a100", "us-east-1")
);
```

`TrustedExecutionContext` carries trusted/derived execution premises
(`principalId`, `agentId`, `adapterId`, `depth`, and optionally `tenantId`,
`tool`, `routeClassification`): values the PEP itself established, not values
the proposer supplied. For each reconciled field:

- proposer claim **absent** → the trusted premise is used;
- proposer claim **matches** the trusted premise → used, recorded as matched;
- proposer claim **conflicts** with the trusted premise → reconciliation fails
  closed, throwing `OxDeAIProvenanceConflictError` before the engine runs;
  `execute` is never called.

`OxDeAIGuard` remains available, unchanged, as the lower-level API. Use it
directly when the deployment cannot yet establish a `TrustedExecutionContext`
(no authenticated caller identity, no resolved route). `createSecureGuard` is
built on top of it: the shared enforcement body (state read, evaluation,
authorization verification, replay consumption, hash binding, CAS,
execution ordering) is identical; the two entry points differ only in how the
evaluated intent's provenance is established.

---

## Security invariants

| Condition | Outcome |
|---|---|
| Engine returns DENY | `OxDeAIDenyError` thrown, execute not called |
| ALLOW without authorization artifact | `OxDeAIAuthorizationError` thrown |
| ALLOW without nextState | `OxDeAIAuthorizationError` thrown |
| `verifyAuthorization` fails | `OxDeAIAuthorizationError` thrown |
| Normalization fails | `OxDeAINormalizationError` thrown |
| `evaluatePure` throws | `OxDeAIAuthorizationError` thrown (fail-closed) |
| Delegation chain verification fails | `OxDeAIDelegationError` thrown, execute not called |
| Delegation scope widens or expiry exceeds parent | `OxDeAIDelegationError` thrown |
| In-scope delegation action | `execute` called; `setState` not called on delegation path |
| (Tier 1 only) proposer claim conflicts with `TrustedExecutionContext` | `OxDeAIProvenanceConflictError` thrown, execute not called |

**There is no code path that executes without a valid, verified authorization.**
This is a claim about the guard boundary itself. See
[Known limits](#known-limits) for what it does not cover (state-source
authority, external-resource TOCTOU, post-execution-start failures).

---

## Replay store: contract and deployment requirements

The guard verifies/authenticates before authoritative replay mutation and consumes
required replay entitlements before protected execution. The parent `auth_id` is
always consumed; `delegation_id` tracking is used when the store provides it.

The [normative store contract](../../docs/spec/verification/verification-v1.md#43-replay-store-contract-and-deployment-boundary)
requires at most one successful consume per identifier in a declared replay domain,
retention while the authorization could otherwise still be accepted, and no protected
execution when required replay state is unavailable or indeterminate. No backend
technology is mandated. Configure the domain through store namespace/routing and
ensure all accepting boundaries participate; local code cannot infer that topology.

Consumption spends authorization; it does not prove execution completed. A crash
between consume and effect can spend the authorization without producing the effect.
Generic conformance does not certify restart persistence, replica visibility, backend
persistence configuration, topology correctness, HA/SLA, or recovery guarantees.

### Default: in-memory (one store instance lifetime)

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";
// No replayStore config → createInMemoryReplayStore() used automatically.
```

Replay protection is limited to the lifetime and users of this store instance. State is:
- lost on process restart
- not shared across instances (horizontal scaling allows cross-instance replay)

A deployment accepting still-valid artifacts across restarts or separate store instances
must preserve authoritative consumption history or block execution when it is missing.

### Redis backend

```typescript
import { OxDeAIGuard, createRedisReplayStore } from "@oxdeai/guard";
import Redis from "ioredis"; // or node-redis v4

const redis = new Redis({ host: "redis.internal", port: 6379 });

const guard = OxDeAIGuard({
  engine,
  getState,
  setState,
  expectedAudience: "agent-xyz",
  trustedKeySets: [myKeySet],
  replayStore: createRedisReplayStore({ client: redis }),
});
```

`SET key value NX EX ttl` provides atomic consume in the authoritative Redis
keyspace: at most one concurrent caller succeeds for a retained key. Existing keys
return `null` and cause replay denial. This command alone does not establish
restart durability or safe replica/failover behavior; those require deployment evidence.

**Key schema:**

| Artifact | Redis key |
|---|---|
| `AuthorizationV1` | `replay:auth:<auth_id>` |
| `DelegationV1` | `replay:delegation:<delegation_id>` |

**TTL:** derived from artifact `expiry`: `max(1, expiry - now)`. Keys
auto-evict; this is safe only if every verifier in the replay domain can no longer
accept the artifact at eviction. The adapter uses local wall time with no skew buffer;
see [TTL alignment](../../docs/architecture/replay-store-ttl-alignment.md).

**Fail-closed:** if Redis is unavailable (network failure, timeout, restart),
`consumeAuthId` throws. The guard catches this and raises
`OxDeAIAuthorizationError: Replay store unavailable`, blocking execution.
There is no fallback to memory and no best-effort path.

### node-redis v4 adapter

```typescript
import { createClient } from "redis";
import type { RedisClient } from "@oxdeai/guard";

const nodeRedis = createClient({ url: "redis://redis.internal:6379" });
await nodeRedis.connect();

// Adapt the node-redis v4 API to the RedisClient interface.
const client: RedisClient = {
  set: (key, value, _nx, _ex, ttl) =>
    nodeRedis.set(key, value, { NX: true, EX: ttl }),
};

const guard = OxDeAIGuard({
  // ...
  replayStore: createRedisReplayStore({ client }),
});
```

### Custom backends

Implement `ReplayStore` directly for DynamoDB, Postgres, or any store that
satisfies the atomicity, retention, domain, and failure contract above:

```typescript
import type { ReplayStore } from "@oxdeai/guard";

const myStore: ReplayStore = {
  async consumeAuthId(authId, { expiry }) {
    // Must be atomic. Return true = first use, false = replay, throw = fail-closed.
    return await db.setIfAbsent(`auth:${authId}`, expiry);
  },
};
```

---

## Error classes

| Class | When thrown |
|---|---|
| `OxDeAIDenyError` | Policy DENY, inspect `.reasons` for violation codes |
| `OxDeAIAuthorizationError` | Missing/invalid authorization artifact |
| `OxDeAIGuardConfigurationError` | Misconfigured guard (programming error) |
| `OxDeAINormalizationError` | ProposedAction cannot be converted to an Intent |
| `OxDeAIDelegationError` | Delegation chain invalid, expired, out-of-scope, or parent hash mismatch |

---

## Delegation execution path

When a sub-agent presents a `DelegationV1` chain, pass it in `opts.delegation`:

```typescript
const result = await guard(action, execute, {
  delegation: { delegation: delegationChain, parentAuth },
});
```

The guard verifies the full delegation chain before policy evaluation:

- Parent `auth_id` hash matches `delegationParentHash`
- Scope does not widen relative to parent (budget, tools, expiry)
- Signatures are valid at every link

On any violation, `OxDeAIDelegationError` is thrown and `execute` is never
called. `setState` is also not called on the delegation path: the scope is
committed by the parent authorization.

Property-based coverage: G-D1 (allow path), G-D2 (all invalid classes fail
closed), G-D3 (wrong parent hash mismatch).

---

## Default normalizer: field mapping

| `ProposedAction` field | Maps to `Intent` field | Default when absent |
|---|---|---|
| `context.agent_id` (**required**) | `agent_id` | throws |
| `name` | `action_type` (heuristic) | `"PROVISION"` |
| `resourceType` | `action_type` (overrides name) | - |
| `estimatedCost` | `amount` (× 1 000 000, bigint) | `0n` |
| `timestampSeconds` | `timestamp` | `Date.now() / 1000` |
| `context.target` | `target` | `action.name` |
| `context.intent_id` | `intent_id` | random hex |
| `context.nonce` | `nonce` | random bigint |
| `args` (sorted JSON) | `metadata_hash` (sha256 hex) | - |

---

## Architecture boundary

`@oxdeai/guard` is **the only place** where universal PEP logic should live.

- Do **not** add LangGraph / CrewAI / OpenAI / runtime-specific imports here.
- Runtime adapter packages must remain **thin bindings** that call `OxDeAIGuard`.
- Do **not** duplicate authorization checks inside adapters.

---

## Known limits

The invariants above describe the guard boundary itself: what happens between
a proposed action arriving and `execute()` being invoked. They do not extend
past that boundary. Full detail, including exactly what 2.0 does and does not
target:

- [`docs/audits/2.0-residual-scope.md`](../../docs/audits/2.0-residual-scope.md)
- [`docs/audits/external-review-scope-v2.md`](../../docs/audits/external-review-scope-v2.md)

- **Evaluator/state authority.** `createSecureGuard` reconciles trusted
  *evaluator-input* identity (`agent_id`, `tool`, `depth`), not state or policy
  authority. `getState()` remains a deployment-supplied function; the guard's
  only check against it is hash consistency (`state_hash` binding) plus CAS
  version-conflict detection. Neither proves the state source is honest,
  current, or non-compromised.
- **External-resource TOCTOU.** The guard's CAS/state-version check protects
  OxDeAI's own policy-state transition. It does not serialize mutation of an
  external resource that the protected `execute()` callback goes on to touch.
  an authorization can be issued against one resource version and the resource
  can change before `execute()` runs, with OxDeAI's own state CAS succeeding
  regardless.
- **Post-execution-start audit semantics.** `onDecision` and `onBoundaryEvent`
  together account for everything up through a successful `ALLOW` or a valid
  `DENY`. Once `execute()` has started, a failure inside the callback is not
  represented as an `onDecision` record or an `onBoundaryEvent`. It is the
  caller's own outcome, and the current lifecycle produces no final decision
  record for it on either stream.

None of these are claimed as solved by 2.0. Do not describe this package as
guaranteeing state-source authority, generic external-resource TOCTOU safety,
or complete post-execution-start audit coverage.

---

## See also

- [Adapter stack architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/adapter-stack.md)
- [Adapter reference architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-reference-architecture.md)
- [Adapter release notes](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-stack-release-notes.md)
- [Root README](https://github.com/oxdeai/oxdeai/blob/main/README.md)
