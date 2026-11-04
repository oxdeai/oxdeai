# @oxdeai/guard
Policy Enforcement Point for the OxDeAI execution-time authorization protocol.
Verifies AuthorizationV1 locally, fail-closed.
No valid authorization, no execution through the configured enforcement boundary.

Current `@oxdeai/guard` package line: **2.0.3**. See [`CHANGELOG.md`](./CHANGELOG.md)
for release details. 2.0.3 pins `@oxdeai/core@2.0.2`; 2.0.1 binds
`DelegationV1.delegatee` to the acting agent;
the 2.0 line requires `expectedAudience` and `trustedKeySets`, uses
versioned/CAS `getState`/`setState`, and introduced `createSecureGuard`.

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

// Call it before every tool execution. The callback executes the same
// arguments object that was authorized.
const request = Object.freeze({ asset: "a100", region: "us-east-1" });
const result = await guard(
  {
    name: "provision_gpu",
    args: request,
    estimatedCost: 500,
    resourceType: "gpu",
    context: {
      agent_id: "agent-xyz", // trusted only if your code sets it; see below
      target: "gpu-pool-us-east-1",
    },
  },
  async () => provisionGpu(request)
);
```

On this (non-delegation) path, the `execute` callback is **only invoked when the
policy engine returns ALLOW and the authorization artifact passes cryptographic
verification**. On DENY, `OxDeAIDenyError` is thrown and execution never reaches
the callback.

**Identity on the low-level path.** `OxDeAIGuard` evaluates whatever
`action.context.agent_id` it receives. That value is a trusted identity only if
your integration sets it from an authenticated, server-side source (the
framework adapters set it from their deployment `agentId`). A value taken from a
request body, tool call, or model output is a proposer claim, not an identity.
When the caller can be authenticated, use
[`createSecureGuard`](#tier-1-secure-path) instead.

**Cost.** The default normalizer turns `estimatedCost` into the evaluated
`amount`. When `estimatedCost` is absent the amount is `0n`, so budget and
per-action caps do not constrain the call. For cost-bearing actions, derive the
amount explicitly and fail closed when it is missing (see
[Custom action-to-intent mapping](#custom-action-to-intent-mapping)).

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
precisely. The mapper must make authorization and execution operate on the
**same validated arguments**: the amount comes from those arguments or from a
trusted pricing source, never from a separate proposer-supplied estimate, and a
missing or unknown cost-bearing value fails closed.

```typescript
import type { Intent } from "@oxdeai/core";
import {
  createSecureGuard,
  defaultNormalizeAction,
  OxDeAINormalizationError,
  type ProposedAction,
} from "@oxdeai/guard";

// Deployer-controlled pricing in fixed-point micro-units (1 unit = 1_000_000n).
// Never read from the request.
const GPU_PRICE_MICROS = new Map<string, bigint>([
  ["a100", 2_500_000_000n],
  ["h100", 4_000_000_000n],
]);
const REGIONS = new Set(["us-east-1", "eu-west-1"]);

export function toIntent(action: ProposedAction): Intent {
  const { asset, region } = action.args;
  const price = typeof asset === "string" ? GPU_PRICE_MICROS.get(asset) : undefined;
  if (action.name !== "provision_gpu" || price === undefined || typeof region !== "string" || !REGIONS.has(region)) {
    throw new OxDeAINormalizationError("provision_gpu requires a known asset and region");
  }
  // defaultNormalizeAction supplies agent_id (reconciled against the
  // TrustedExecutionContext by createSecureGuard), a fresh intent_id and nonce,
  // and metadata_hash = sha256 of the sorted args, which binds every argument.
  return { ...defaultNormalizeAction(action), action_type: "PROVISION", amount: price, target: region };
}

const guard = createSecureGuard(
  {
    engine,
    getState,
    setState,
    expectedAudience: "agent-xyz",
    trustedKeySets: [myKeySet],
    mapActionToIntent: toIntent,
  },
  { tenancy: "single-tenant" }
);

// Validate once, freeze, then authorize and execute the same object.
const request = Object.freeze({ asset: "a100", region: "us-east-1" });
await guard(trustedContext, { name: "provision_gpu", args: request }, async () => provisionGpu(request));
```

An unknown asset or region throws `OxDeAINormalizationError` before the policy
engine runs, and `execute` is never called. There is no zero-cost fallback.
Identity comes from `trustedContext` (see [Tier 1 secure path](#tier-1-secure-path)):
`createSecureGuard` fills `agent_id` from it and rejects a conflicting proposer
claim. Do not derive `agent_id` from `action.context` in a mapper used with the
low-level `OxDeAIGuard` unless your code, not the proposer, set that value.

On the delegation path the policy engine does not run, so the guard applies the
engine's amount contract itself: the mapped `amount` must be a non-negative
`bigint`, otherwise the call fails with `OxDeAINormalizationError` (boundary
code `NORMALIZATION_FAILURE`) before any verification, replay consumption or
execution.

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

const request = Object.freeze({ asset: "a100", region: "us-east-1" });
const result = await guard(
  trustedContext,
  {
    name: "provision_gpu",
    args: request,
    estimatedCost: 500,
    resourceType: "gpu",
    context: { target: "gpu-pool-us-east-1" },
  },
  async () => provisionGpu(request)
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
| `delegation.delegatee` differs from the acting `agent_id` (guard ≥ 2.0.1) | `OxDeAIDelegationError` thrown, execute not called, nothing consumed |
| No `trustedDelegationAuthorities` configured on a delegation call | `OxDeAIGuardConfigurationError` thrown, execute not called |
| `trustedDelegationSigners` configured and the delegation's `(delegator, issuer)` is not listed | `OxDeAIDelegationError` thrown, execute not called, nothing consumed |
| `trustedDelegationSigners` set to a non-array or a malformed entry | `OxDeAIGuardConfigurationError` thrown at construction |
| Revocation required but no provider configured | `OxDeAIDelegationError`, boundary code `DELEGATION_REVOCATION_UNAVAILABLE`; execution blocked |
| Revocation provider unavailable or response indeterminate | `OxDeAIDelegationError`, boundary code `DELEGATION_REVOCATION_UNAVAILABLE`; execution blocked |
| Revocation provider returns `REVOKED` | `OxDeAIDelegationError`, boundary code `DELEGATION_REVOKED`; execution blocked |
| Revocation provider returns `ACTIVE` | Revocation gate passed; remaining execution checks still apply |
| In-scope delegation action | `execute` called only after all enabled checks succeed; `PolicyEngine` not evaluated; `setState` not called on delegation path |
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

### Replay protection posture (`replayProtection`)

Declare the replay domain explicitly with `replayProtection`:

```typescript
import { OxDeAIGuard, createRedisReplayStore } from "@oxdeai/guard";

// Single-process / development: acknowledge the process-local in-memory store.
new OxDeAIGuard({ /* ... */, replayProtection: { mode: "process-local" } });

// Multi-instance / restart-durable: provide a shared backend you operate.
new OxDeAIGuard({ /* ... */, replayProtection: { mode: "shared", store: createRedisReplayStore({ client: redis }) } });
```

Construction rules (fail closed on an unsafe or ambiguous posture):

| Configuration | Result |
|---|---|
| neither `replayProtection` nor `replayStore` | process-local store **plus a one-time migration warning** (transitional) |
| `{mode:"process-local"}` | in-memory store, no warning |
| `{mode:"shared", store}` with a custom backend | uses the store as given |
| `{mode:"shared"}` without a store | rejected at construction (also a TypeScript error) |
| `{mode:"shared", store: <the built-in in-memory store>}` | rejected: the built-in store is process-local |
| both `replayProtection` and `replayStore` | rejected as ambiguous |
| legacy `replayStore` alone | honored (deprecated; prefer `replayProtection`) |

**Enforcement vs durability.** OxDeAI enforces this *configuration* contract. Declaring
`mode:"shared"` does **not** establish that the supplied store is actually atomic, shared
across your instances, or restart-durable - those remain your operational obligation.
OxDeAI only verifies that a `shared` store is present and is not its own process-local
built-in; it makes no durability claim about an arbitrary custom store.

### Default: in-memory (one store instance lifetime)

```typescript
import { OxDeAIGuard } from "@oxdeai/guard";
// No replayProtection/replayStore config → process-local in-memory store + a
// one-time migration warning. Prefer an explicit replayProtection posture.
```

Replay protection is then limited to the lifetime and users of this store instance. State is:
- lost on process restart
- not shared across instances (horizontal scaling allows cross-instance replay)

A deployment accepting still-valid artifacts across restarts or separate store instances
must preserve authoritative consumption history or block execution when it is missing.

> Migration note: a future (separately approved) strict release will require an explicit
> `replayProtection` posture and reject an undeclared configuration at construction. This
> transitional release only warns. Set `replayProtection` now to be forward-compatible.

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

A parent agent holding an `AuthorizationV1` can delegate a narrower scope to
exactly one child agent with a `DelegationV1`. The child presents both artifacts
through `opts.delegation`. A `DelegationV1` is a signed grant; it does not prove
who is presenting it. The acting identity must come from a
`TrustedExecutionContext`, and the guard requires:

```text
delegation.delegatee === trusted execution identity (intent.agent_id)
```

```typescript
import { createDelegation } from "@oxdeai/core";
import { createSecureGuard, createTrustedExecutionContext } from "@oxdeai/guard";

// Parent side: agent-A (the audience of parentAuth) delegates to agent-B only.
// The delegation is signed by agent-A's own key; its issuer defaults to parentAuth.audience.
const delegation = createDelegation(
  parentAuth,
  {
    delegatee: "agent-B",
    scope: { tools: ["provision_gpu"], max_amount: 3_000_000_000n }, // strictly narrower than parentScope
    expiry: parentAuth.expiry, // cannot exceed the parent
    kid: "agent-A-k1",
  },
  agentAPrivateKeyPem
);

// Child side: the PEP that executes on agent-B's behalf.
const guard = createSecureGuard(
  {
    engine,
    getState,
    setState,
    expectedAudience: "agent-A", // parentAuth.audience, i.e. the delegator
    trustedKeySets: [pdpKeySet, agentAKeySet], // parentAuth signer and delegation signer
    trustedDelegationAuthorities: [{ issuer: "oxdeai.policy-engine", policyId }], // required
    mapActionToIntent: toIntent, // explicit amount; see "Custom action-to-intent mapping"
  },
  { tenancy: "single-tenant" }
);

// Built after authenticating the caller. Never taken from the request body.
const childContext = createTrustedExecutionContext({
  principalId: authenticatedPrincipal.id,
  agentId: authenticatedPrincipal.agentId, // must equal delegation.delegatee
  adapterId: "http-adapter",
  depth: currentCallDepth,
});

const request = Object.freeze({ asset: "a100", region: "us-east-1" });
await guard(childContext, { name: "provision_gpu", args: request }, async () => provisionGpu(request), {
  delegation: {
    delegation,
    parentAuth,
    // The parent's own authority ceiling, from deployer configuration, not from the request.
    parentScope: { tools: ["provision_gpu"], max_amount: 10_000_000_000n },
  },
});
```

**What the delegation path does**, in order, when `opts.delegation` is present:

1. Reads state (`getState()`) and normalizes the action; delegation requires a
   non-empty normalized `agent_id`. It then takes one immutable snapshot of
   `opts.delegation` (`delegation`, `parentAuth`, `parentScope`); every later
   step reads only the snapshot, never the caller's objects. The input must be
   plain data: plain objects and dense arrays whose own properties are
   enumerable data properties, with string, number, bigint, boolean, null or
   undefined leaves (what `createDelegation`, `signAuthorizationEd25519` and a
   JSON decode produce). A Proxy, an accessor (getter) property, a class
   instance, a cycle or a non-enumerable/symbol property is rejected
   (`OxDeAIAuthorizationError`, boundary code `DELEGATION_INPUT_INVALID`) before
   verification and before any replay state is consumed. `beforeExecute` and
   `onDecision` receive the frozen snapshot objects.
2. Fails closed if `trustedDelegationAuthorities` is not configured
   (`OxDeAIGuardConfigurationError`). An empty list is valid configuration that
   authorizes no delegation root.
3. Fails closed if `parentScope` is missing or malformed: `tools` must be an
   array of strings, `max_amount` a non-negative `bigint`, and `max_actions` /
   `max_depth` non-negative integers (NaN, Infinity, fractional and negative
   ceilings are rejected).
4. Verifies `parentAuth` in strict mode: signature against `trustedKeySets`,
   `expectedAudience`, expiry, and its `(issuer, policy_id)` pair against
   `trustedDelegationAuthorities` (`OxDeAIAuthorityError` when authority is the
   only defect).
5. Verifies the delegation chain: parent hash binding, parent and delegation
   expiry, delegation expiry not exceeding the parent, `delegator` equal to
   `parentAuth.audience`, policy binding, delegation signature, scope narrowing
   against `parentScope`, single hop, and (guard ≥ 2.0.1) `delegatee` equal to
   the acting `agent_id`. When `trustedDelegationSigners` is configured, the
   delegation's `(delegator, issuer)` pair must also be listed (see
   [Delegation signer authority](#delegation-signer-authority-opt-in)).
6. Checks the action against the effective delegation scope: `action.name` must
   be in `scope.tools`, and the normalized `amount` must not exceed
   `scope.max_amount`.
7. If `delegationRevocationProvider` is configured, queries it with an immutable
   key derived from the verified delegation: `delegationId`, `issuer`,
   `delegator`, and `parentAuthHash`. Only an explicit `ACTIVE` response permits
   continuation. `REVOKED` denies with `DELEGATION_REVOKED`; provider failures,
   malformed responses, or indeterminate results deny with
   `DELEGATION_REVOCATION_UNAVAILABLE`. If no provider is configured and
   `requireDelegationRevocation` is true, execution is denied with
   `DELEGATION_REVOCATION_UNAVAILABLE`.
8. Consumes `delegation_id` (when the replay store supports it), then the parent
   `auth_id`.
9. Runs `beforeExecute`, then `execute()`, then reports `onDecision` (ALLOW).

Any failure in steps 1 to 7 throws before replay consumption, state mutation, or
execution. After a rejected presentation (for example by the wrong agent), the
unconsumed artifacts remain usable by the real delegatee.

**What the delegation path does not do.** It does **not** evaluate the
`PolicyEngine`: kill switches, budgets, action-type allowlists, velocity and the
other policy modules are not applied to delegated execution, and no policy
decision or authorization is issued for it. The delegation chain and the
effective delegation scope are the constraints. `setState` is not called, so no
policy state is committed. Because the parent `auth_id` is consumed, a parent
authorization backs at most one delegated execution within a replay domain.

### Delegation revocation (F4-C, opt-in)

`@oxdeai/guard` supports an authoritative revocation check for delegated
execution. This is a guard-side enforcement extension; the signed `DelegationV1`
format is unchanged.

```typescript
const guard = createSecureGuard({
  // Existing required guard configuration:
  engine,
  getState,
  setState,
  expectedAudience: "agent-A",
  trustedKeySets,
  trustedDelegationAuthorities,

  requireDelegationRevocation: true,
  delegationRevocationProvider: {
    async check(key) {
      // Query the deployment's authoritative revocation state using the
      // verified delegation identity. Do not use stale cached ACTIVE results.
      const revoked = await revocationStore.isRevoked(key);
      return { status: revoked ? "REVOKED" : "ACTIVE" };
    },
  },
  { tenancy: "single-tenant" }
);
```

The provider receives a frozen `DelegationRevocationKey` containing
`delegationId`, `issuer`, `delegator`, and `parentAuthHash`. Its `check()` method
must return a promise resolving to `{ status: "ACTIVE" }` or
`{ status: "REVOKED" }`. The backing `revocationStore` above is illustrative;
the application must supply an authoritative implementation.

- With a provider, every delegated execution requires an explicit `ACTIVE`
  result, even when `requireDelegationRevocation` is false.
- With `requireDelegationRevocation: true` and no provider, delegated execution
  fails closed (`DELEGATION_REVOCATION_UNAVAILABLE`).
- With neither option configured, legacy delegation behavior is preserved.
- Invalid configuration fails at construction. Provider errors, malformed
  responses, and indeterminate status fail closed before replay consumption.
- Direct (non-delegated) authorization is not subject to this revocation check.
- Rejection emits a boundary event with the corresponding failure code.

**Security boundary and limitations:** the check occurs after delegation
verification and scope enforcement, before replay consumption and protected
execution. It does not cancel execution already started, and it does not make
the revocation lookup and external side effect atomic. The provider must
consult sufficiently current, authoritative state; stale `ACTIVE` caching can
permit execution after revocation. Distributed deployments must account for
consistency, availability, and revocation propagation latency. This mechanism
revokes delegation grants, not signing keys; SignedKRLV1 is a separate concern.

### SignedKRLV1 signing-key revocation (F4-LOT-C, opt-in)

`@oxdeai/guard` supports optional SignedKRLV1 signing-key revocation
enforcement for delegated execution. The SignedKRLV1 artifact and its
cryptographic verification rules remain unchanged.

Configure `revocation` with:

- `trustedKrlKeySets`: trusted KRL signing keys, separate from the
  authorization and delegation signing-key trust domain.
- `scopes`: mappings from each KRL publisher (`krlIssuer`) to the
  authorization/delegation key issuers (`keyIssuers`) it may revoke.
- `provider`: a trusted function returning the current signed KRL
  envelopes, exactly one for each configured KRL publisher.
- `watermarkStore`: a required store implementing atomic, monotonic
  per-publisher version and digest acceptance.

When enabled, the Guard verifies KRL evidence before replay consumption
and protected execution. Missing, invalid, expired, conflicting, or
rolled-back evidence denies execution. A verified revocation of either
the parent authorization signing key or delegation signing key also
denies execution.

If no revocation configuration is supplied, existing Guard behavior is
preserved. Direct non-delegated execution is not covered by this
extension.

The provided `createInMemoryKrlWatermarkStore()` is process-local.
It does not provide restart durability or distributed consistency.
Production deployments requiring those properties must provide a
shared, durable, atomic store.

Watermark acceptance across multiple KRL issuers is not transactional.
A failed later acceptance blocks execution but may leave earlier
watermarks advanced.

Revocation checks do not cancel execution already in progress and
are not atomic with external side effects.

**Trust-set requirements when `revocation` is configured.** SignedKRLV1
revokes key IDs (`revoked_kids`), so a kid must denote exactly one key.
With `revocation` set, the Guard enforces on `trustedKeySets`, comparing
keys by canonical identity (SPKI DER), not by PEM text, so line endings,
base64 wrapping and base64-wrapped PEM do not matter:

- Every entry is a parseable Ed25519 public key. Other algorithms,
  private-key material and unparseable keys are rejected.
- No key is also a trusted KRL signing key (`trustedKrlKeySets`), under
  any issuer or kid.
- One public key has exactly one `(issuer, kid)` identity, within and
  across issuers. Rotate by adding new key material under a new kid; do
  not re-label existing material.
- One `(issuer, kid)` has one registration. An exact duplicate (same key
  and lifecycle fields) is tolerated; a conflicting one is rejected.

A violation fails construction with `OxDeAIGuardConfigurationError`.

**Changing trust after construction.** The Guard retains the array passed
as `config.trustedKeySets` (or, for a single `KeySet`, an array it creates
around that object) and the `KeySet` objects in it. It does not copy them.

- *In-place mutation* (adding, removing or replacing entries of that
  array, or changing fields of its `KeySet` and key objects) takes effect
  for later requests. This is how to rotate keys.
- *Reassigning* the property (`config.trustedKeySets = [...]`) is **not**
  observed when `revocation` is configured: every verification keeps
  using the retained array. A key removed only by reassignment therefore
  stays trusted. Rotate in place instead.

With `revocation` configured, each protected verification (parent
authorization, delegation chain, the post-await parent confirmation, and
direct authorization) copies the retained trust state into a frozen
snapshot, validates it, and verifies against that snapshot only. Later
changes to the live objects, including changes made by caller code that
runs during verification, cannot affect a decision already validated. A
violation introduced after construction denies that request with
`OxDeAIGuardConfigurationError` (boundary code
`AUTHORIZATION_VERIFICATION_FAILED`) before replay consumption,
`beforeExecute` and execution. Trust objects must be plain data: a Proxy,
accessor property or class instance in the trust set denies the request.

Without `revocation`, none of these checks apply and trust-set behavior
is unchanged: parent and direct authorization verify against the
retained array (in-place mutation observed, reassignment not), while
delegation-chain signature verification reads `config.trustedKeySets`
on each request (reassignment observed).

The Guard cannot detect key material that a KRL revoked under one kid
and that is later registered under a fresh kid in a configuration where
the old kid no longer appears: it keeps no key-material history. KRL
publishers and trust-store operators must not re-register revoked keys.

This mechanism revokes signing keys. It is separate from the existing
F4-C delegation-grant revocation provider.

### Delegation signer authority (opt-in)

A valid delegation signature proves only that a key in `trustedKeySets` for the
claimed `issuer` signed the artifact. It does **not** prove that this issuer
may delegate on behalf of the `delegator` (the parent's audience). **By
default the guard does not check this:** any key present in `trustedKeySets`,
for any purpose, can sign a delegation of another agent's parent authorization
and the guard will execute it.

`trustedDelegationSigners` enables the check. It is a different option from
`trustedDelegationAuthorities`, which authorizes the *parent* authorization:

```text
trustedDelegationAuthorities  [{ issuer, policyId }]    which parent may root a delegation (required)
trustedDelegationSigners      [{ delegator, issuer }]   which issuer may sign a delegation for which delegator (opt-in)
```

```text
undefined  -> not enforced (default, unchanged)
[]         -> enforced; no delegation signer is authorized (every delegation call is denied)
[pairs]    -> enforced; (delegation.delegator, delegation.issuer) must be listed exactly
```

For the example above, where agent-A signs its own delegations, set
`trustedDelegationSigners: [{ delegator: "agent-A", issuer: "agent-A" }]`. A
central issuer that signs delegations for agent-A is listed as
`{ delegator: "agent-A", issuer: "<central issuer>" }`. A rejection is an
`OxDeAIDelegationError` (core code `DELEGATION_SIGNER_NOT_AUTHORIZED`) raised
before replay consumption and before `execute()`. A value that is not an array
of `{ delegator, issuer }` with non-empty strings is rejected at construction
with `OxDeAIGuardConfigurationError`; it never silently disables the check.

Scope: this guard's in-process delegation path only. The HTTP PEP gateway and
the framework adapters do not accept delegations.

**Versions.** `@oxdeai/guard@2.0.0` does not bind `delegatee` to the acting
agent: any presenter holding valid artifacts can execute. Upgrade to 2.0.1 or
later. On the low-level `OxDeAIGuard`, the binding compares against the
normalized `action.context.agent_id`, which is a trusted identity only if your
code set it from an authenticated source (see
[Basic usage](#basic-usage)); prefer `createSecureGuard` for delegation.

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

The fallbacks above are silent. An action without `estimatedCost` is evaluated
at amount `0n`, and a name that matches no heuristic (for example
`charge_wallet`) is classified `PROVISION`, not `PAYMENT`. `args` are bound
through `metadata_hash` but are never read as the amount. For cost-bearing or
payment actions, supply a `mapActionToIntent` that sets `action_type` and
`amount` explicitly from the validated arguments and throws when they are
missing.

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
