# @oxdeai/guard
Policy Enforcement Point for the OxDeAI execution-time authorization protocol.
Verifies AuthorizationV1 locally, fail-closed.
No valid authorization, no execution through the configured enforcement boundary.

Current `@oxdeai/guard` package line: **2.0.4**. See [`CHANGELOG.md`](./CHANGELOG.md)
for release details. 2.0.4 pins `@oxdeai/core@2.0.3` and changes the PEP gateway
response contract (three-state `outcome`, `executed: boolean | null`; see
[PEP gateway execution outcome](#pep-gateway-execution-outcome)); 2.0.1 binds
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
| In-scope delegation action | `execute` called; `PolicyEngine` not evaluated; `setState` not called on delegation path |
| (Tier 1 only) proposer claim conflicts with `TrustedExecutionContext` | `OxDeAIProvenanceConflictError` thrown, execute not called |

**There is no code path that executes without a valid, verified authorization.**
This is a claim about the guard boundary itself. See
[Known limits](#known-limits) for what it does not cover (state-source
authority, external-resource TOCTOU, post-execution-start failures).

---

## HTTP PEP gateway and protected upstream: request handling

`createPepGatewayHttpServer` and `createProtectedUpstreamHttpServer` apply the
following rules to every request.

**Bounded bodies (`maxBodyBytes`).** Both servers accept a `maxBodyBytes`
option: default `1_048_576` (1 MiB), allowed range `1_024`-`67_108_864`. Other
values are rejected at construction.

- A declared `Content-Length` above the limit is rejected before the body is
  read; a chunked body is rejected as soon as it exceeds the limit.
- An oversized body is never truncated and parsed: the partial buffer is
  discarded, even if its prefix happens to be valid JSON.
- Gateway: 403 `{ decision: "DENY", outcome: "NOT_DISPATCHED", executed: false,
  reason: "BODY_TOO_LARGE" }`. The executor is not invoked and replay state is
  not touched. Protected upstream: 413 `{ error: "BODY_TOO_LARGE" }`;
  `execute` is not called.
- `createPepGatewayExecutor` (in-process) receives already-parsed input and
  ignores `maxBodyBytes`.
- The legacy gateway forwards `JSON.stringify(action.params ?? action)` to the
  upstream. For valid UTF-8 input this is no larger than the inbound request;
  invalid UTF-8 is decoded with replacement characters and can grow up to 3x.
  If clients may send arbitrary bytes, set the upstream's `maxBodyBytes` to at
  least 3x the gateway's. A 413 from the upstream is reported by the gateway as
  `INDETERMINATE` (the authorization is spent).

**Token before body.** The protected upstream checks
`x-internal-executor-token` from the headers before reading the body. The
comparison is constant-time (`hasValidInternalExecutorToken` uses the same
check). A missing, duplicated or wrong token gets 403 and the body is not read.
An empty `expectedToken` is rejected at construction.

**Graceful early rejection.** When a response is sent before the request body
has been read (oversized body, invalid token, unknown path with a body), the
server sends the complete response with `Connection: close`, then reads and
discards at most 64 KiB or 2 s of the remaining upload before closing the
connection, so the client reliably receives the status instead of a reset.
Nothing read during that drain is parsed or dispatched. Bodiless requests
(for example `GET /healthz`) keep normal keep-alive behaviour.

**Custom `hashAction` (deprecated).** By default the gateway binds the whole
action: `intent_hash` must equal `sha256HexFromJson(action)`. If you supply
`hashAction`, a request is accepted only when it returns exactly that same
whole-action hash; anything else (a projection that omits fields, a prefixed
or otherwise different digest, a non-string such as a Promise) is denied with
403 `ACTION_HASH_UNCOVERED` before authorization verification and without
touching replay state, so no field of the action can reach the upstream
without being covered by `authorization.intent_hash`. There is no option to
disable this check. `hashAction: null` or `undefined` means "use the default";
any other non-function is rejected at construction. The function is captured
once at construction. Supplying it emits a one-time `DeprecationWarning`
(code `OXDEAI_DEP_HASH_ACTION`); under `node --throw-deprecation` that warning
is thrown at construction. `hashAction` will be removed in the next major
release: present exactly the object that was hashed into `intent_hash` and
omit the option.

**Coverage and Unicode normalization.** Coverage is defined by
`canonicalization-v1`, which normalizes strings to NFC and orders keys. Two
actions that differ only in Unicode normalization form therefore have the same
`intent_hash`, while the gateway forwards the request's raw strings. Upstreams
that compare strings should normalize to NFC. (Rejecting non-NFC input in
legacy mode is planned for a major release.)

---

**In-process executor input (INVREG-F01/F02).** `createPepGatewayExecutor`
takes one deep-frozen plain-data snapshot of the request before any security
decision. Action hashing, authorization verification, intent binding, replay
consumption, upstream dispatch and the response body all read only that
snapshot, so mutating the caller's object during the awaited replay consume no
longer changes what is sent upstream, and an accessor or `Proxy` on `auth_id`
can no longer consume one signed authorization under several identifiers.
Input that is not plain data (Proxy, accessor properties, class instances,
`Date`, `Map`, `Buffer` and typed arrays, functions, symbol keys, sparse arrays,
cycles, objects from another realm) is denied with
`INVALID_REQUEST_INPUT:<path>: <reason>` before replay consumption. JSON-decoded
input (the HTTP gateway) is unaffected. The upstream executor receives its own
mutable deep copy of the verified action (GW-COMP-01) and is called with the
options object as `this`.

**Configuration read once (INVREG-F05).** `trustedAuthorizationAuthorities` is
validated and copied at construction; later mutation of the caller's array no
longer widens issuer-policy authority, and a malformed entry fails
construction. `expectedAudience`, `internalExecutorToken` and `executeUpstream`
are also read once. In-place `trustedKeySets` rotation and replay-store state
remain live.

**Strict replay result (RR-01, gateway).** The gateway dispatches only when
`consumeAuthId` resolves to the boolean `true`. `false` is `AUTH_REPLAY`; any
other answer (`"OK"`, `1`, `"true"`, objects) is denied as
`REPLAY_STORE_UNAVAILABLE:INVALID_RESULT`. A store that returns a raw Redis
`SET NX` reply must be changed to return a boolean; the built-in stores already
do. On the 2.0.x line this strict check applies to the gateway only.

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

## PEP gateway execution outcome

`createPepGatewayExecutor` and `createPepGatewayHttpServer` report what happened
to a request with a three-state `outcome` in the response body. It is the field
to branch on.

| `outcome` | Meaning | `executed` | `decision` | HTTP |
| --- | --- | --- | --- | --- |
| `NOT_DISPATCHED` | Denied before dispatch. The upstream was never called, so no side effect is possible. | `false` | `DENY` | 403 |
| `EXECUTED` | The upstream confirmed success. | `true` | `ALLOW` | 200 |
| `INDETERMINATE` | The request was dispatched and its outcome is unknown: timeout, transport error, thrown executor, or any non-success status. A side effect cannot be ruled out. | `null` | `ALLOW` | 502 or 504 |

`executed: false` means a confirmed non-execution and nothing else. Before
2.0.4 the gateway also reported it for dispatched requests that failed or timed
out, although the upstream may already have acted (H-1).

Three rules for callers:

- **Branch on `outcome`, never on the truthiness of `executed`.** `null` is
  falsy, so `if (!body.executed) retry()` retries an `INDETERMINATE` request and
  can execute the action twice. If you must use `executed`, compare it strictly:
  `body.executed === false`.
- **Do not retry an `INDETERMINATE` request automatically**, and do not request
  a new authorization for the same action until you have reconciled with the
  upstream. An idempotency key derived from `auth_id` makes that reconciliation
  possible. Retrying on `ok: false` or on an HTTP 5xx status is unsafe for the
  same reason.
- **`decision: "UNKNOWN"`** appears only when the HTTP handler hits an internal
  fault after parsing and cannot tell whether dispatch occurred. It always comes
  with `outcome: "INDETERMINATE"` and `executed: null`. Treat it as "no decision
  was reached", never as `ALLOW` or `DENY`.

`EXECUTED` means the upstream confirmed success under the configured success
contract; by default that is an integer 2xx status, so a 3xx is
`INDETERMINATE`. Supply `isUpstreamSuccess` (an `UpstreamSuccessContract`) when
your upstream signals success differently. `EXECUTED` is the upstream's answer
at this boundary. It is not proof that a business effect was durably committed.

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
   non-empty normalized `agent_id`.
2. Fails closed if `trustedDelegationAuthorities` is not configured
   (`OxDeAIGuardConfigurationError`). An empty list is valid configuration that
   authorizes no delegation root.
3. Fails closed if `parentScope` is missing or malformed.
4. Verifies `parentAuth` in strict mode: signature against `trustedKeySets`,
   `expectedAudience`, expiry, and its `(issuer, policy_id)` pair against
   `trustedDelegationAuthorities` (`OxDeAIAuthorityError` when authority is the
   only defect).
5. Verifies the delegation chain: parent hash binding, parent and delegation
   expiry, delegation expiry not exceeding the parent, `delegator` equal to
   `parentAuth.audience`, policy binding, delegation signature, scope narrowing
   against `parentScope`, single hop, and (guard ≥ 2.0.1) `delegatee` equal to
   the acting `agent_id`.
6. Checks the action against the effective delegation scope: `action.name` must
   be in `scope.tools`, and the normalized `amount` must not exceed
   `scope.max_amount`.
7. Consumes `delegation_id` (when the replay store supports it), then the parent
   `auth_id`.
8. Runs `beforeExecute`, then `execute()`, then reports `onDecision` (ALLOW).

Any failure in steps 1 to 6 throws before replay consumption, state mutation, or
execution. After a rejected presentation (for example by the wrong agent), the
unconsumed artifacts remain usable by the real delegatee.

**What the delegation path does not do.** It does **not** evaluate the
`PolicyEngine`: kill switches, budgets, action-type allowlists, velocity and the
other policy modules are not applied to delegated execution, and no policy
decision or authorization is issued for it. The delegation chain and the
effective delegation scope are the constraints. `setState` is not called, so no
policy state is committed. Because the parent `auth_id` is consumed, a parent
authorization backs at most one delegated execution within a replay domain.

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
