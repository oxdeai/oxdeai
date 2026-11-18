# @oxdeai/langgraph
LangGraph adapter for the OxDeAI execution-time authorization protocol.
Maps LangGraph tool calls to @oxdeai/guard; verification stays local and fail-closed.

---

## What this package does

LangGraph tool calls (`{ name, args, id }`) carry no agent identity and use
a different shape from OxDeAI's `ProposedAction`. This adapter:

1. Injects `agentId` from config into every call (tool calls carry no agent identity)
2. Maps `toolCall.id` → `context.intent_id`
3. Passes the resulting `ProposedAction` to `OxDeAIGuard`

Everything else - policy evaluation, authorization verification, state
persistence, fail-closed behavior - happens inside `@oxdeai/guard`.

---

## Installation

```sh
pnpm add @oxdeai/langgraph @oxdeai/core
```

---

## Usage

```ts
import { createLangGraphGuard } from "@oxdeai/langgraph";

const guard = createLangGraphGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => { state, version } | Promise<{ state, version }>
  setState,    // (state, expectedVersion) => boolean | Promise<boolean>  (CAS)
  agentId: "gpu-agent-1",
  trustedKeySets: [myKeySet], // required, passed through to OxDeAIGuard
});

// In your LangGraph tool node:
const result = await guard(
  { name: "provision_gpu", args: { asset: "a100", region: "us-east-1" }, id: "call-xyz" },
  (verified) => provisionGpu(verified.args.asset as string, verified.args.region as string)
);
```

The `execute` callback is only invoked when the policy engine returns ALLOW
**and** the authorization artifact passes verification. On DENY, `OxDeAIDenyError`
is thrown and the callback is never called.

### Execution binding

The `execute` callback receives the **verified action**: the deep-frozen
`ProposedAction` snapshot that the guard evaluated and bound to the
authorization (`args` comes from `toolCall.args`). Read the tool name and arguments
from this argument, not from `toolCall`. The original input is caller-owned and
can change while authorization is awaited; the snapshot cannot.

- A zero-argument callback such as `() => executeTool(toolCall)` still compiles
  and runs, for backward compatibility, but it is **not** covered by this
  binding. Migrate it to `(verified) => ...`.
- The adapter reads each field of `toolCall` once, when the guard is called.
  Proxies, accessors and other non-plain values anywhere in the action it
  builds (including everything under `args`) are rejected with
  `OxDeAINormalizationError` before policy evaluation, replay consumption and
  state writes.
- The binding does not protect against malicious code running in the same
  process as the guard.

---

## With estimated cost

Attach `estimatedCost` and `resourceType` directly on the tool call to give
the default normalizer richer context:

```ts
await guard(
  {
    name: "provision_gpu",
    args: { asset: "a100", region: "us-east-1" },
    id: "call-xyz",
    estimatedCost: 500,
    resourceType: "gpu",
  },
  (verified) => provisionGpu(verified.args.asset as string, verified.args.region as string)
);
```

---

## With a custom intent mapper

Use `mapActionToIntent` when you need full control over how a tool call maps
to an OxDeAI `Intent` (e.g. to set a precise `amount`, `asset`, or `target`):

```ts
import { createLangGraphGuard } from "@oxdeai/langgraph";

const guard = createLangGraphGuard({
  engine,
  getState,
  setState,
  agentId: "gpu-agent-1",
  trustedKeySets: [myKeySet],
  mapActionToIntent(action) {
    // action.name, action.args, action.context.agent_id and intent_id are available
    return buildProvisionIntent(action.args.asset as string, action.args.region as string);
  },
});
```

---

## Error handling

```ts
import {
  OxDeAIDenyError,
  OxDeAIAuthorizationError,
  OxDeAINormalizationError,
} from "@oxdeai/langgraph";

try {
  await guard(toolCall, execute);
} catch (err) {
  if (err instanceof OxDeAIDenyError) {
    // Policy denied - err.reasons contains the violation codes
    console.error("denied:", err.reasons);
  } else if (err instanceof OxDeAIAuthorizationError) {
    // Authorization artifact missing or invalid - hard security failure
    throw err;
  }
}
```

---

## Deterministic boundary semantics

This adapter preserves the same deterministic, offline-verifiable boundary
semantics as every other OxDeAI protocol demo:

- **No Authorization = no execution**, even on ALLOW
- **DENY** blocks the execute callback before it is called
- **State (CAS) commit happens before `execute()` runs**, not after; a failure
  inside `execute()` does not roll the state commit back
- **Envelope verification** remains offline and deterministic

All of this is guaranteed by `@oxdeai/guard`, this package adds nothing on top.
See [`@oxdeai/guard` Known limits](../guard/README.md#known-limits) for what
this boundary does not cover (evaluator/state authority, external-resource
TOCTOU, post-execution-start audit semantics).

---

## Trust profile

**Declared.**

This adapter integrates the lower-level `OxDeAIGuard` boundary. `agent_id` is
fixed by deployment configuration (`config.agentId`) and is not proposer-controlled;
the same value is bound as `expectedAudience`, so an authorization issued for a
different audience fails closed.

Tool identity and recursion depth are **not** established from a
`TrustedExecutionContext` on this path. The default adapter normalization does not
populate `intent.tool` or `intent.depth`, so `ToolAmplificationModule` and
`RecursionDepthModule` do not constrain execution here. The adapter deliberately
does not derive `intent.tool` from the proposer-supplied tool-call name: doing so
would activate the module against a value the caller controls, which is weaker than
leaving it unset.

Deployments that require authenticated Tier 1 evaluator-input provenance should
establish trusted execution context at an authenticating PEP (where a principal is
actually authenticated and the route is resolved) and integrate `createSecureGuard`
from `@oxdeai/guard` there. A framework adapter has no authenticated principal of its
own, so it cannot construct that context honestly.

Replay protection defaults to a per-guard in-memory store. Multi-process or
restart-durable deployments must pass an explicit `replayStore`; see
`createRedisReplayStore` in `@oxdeai/guard`.

Wire `onBoundaryEvent` alongside `onDecision` to observe guard-boundary rejections
(replay, CAS conflict, hash-binding failure). The two streams are disjoint: a
boundary rejection produces no decision record.

---

## Architecture boundary

This package is a **thin binding only**. Do not add:

- Authorization logic
- Policy evaluation logic
- `verifyAuthorization` calls
- Runtime security semantics beyond the ToolCall → ProposedAction mapping

All of that lives in `@oxdeai/guard`.

---

## Cross-adapter validation

This adapter is cross-validated by `@oxdeai/compat` against the OpenAI Agents
SDK and CrewAI adapters. Equivalent intents produce identical decisions,
authorization artifacts, and denial reasons across all three runtimes.

| Test | What it proves |
|------|----------------|
| CA-1 | Same intent + isolated state → same ALLOW/DENY decision across all adapters |
| CA-6 | Per-action cap boundary: `amount == cap` → ALLOW (inclusive) |
| CA-7 | Per-action cap exceeded: `amount > cap` → DENY + `PER_ACTION_CAP_EXCEEDED` |
| CA-8 | PBT sweep: seeded variation, same decision + evidence across all adapters |
| CA-9 | Nonce replay → DENY + `REPLAY_NONCE` across all adapters |
| CA-10 | Concurrent isolation: 30 parallel calls, all ALLOW with isolated state |

See [`packages/compat/src/test/cross-adapter.test.ts`](../compat/src/test/cross-adapter.test.ts)
and [`docs/testing/delegation-pbt.md`](../../docs/testing/delegation-pbt.md).

---

## See also

- [LangGraph integration guide](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/langgraph.md)
- [Adapter stack architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/integrations/adapter-stack.md)
- [Adapter reference architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-reference-architecture.md)
- [Root README](https://github.com/oxdeai/oxdeai/blob/main/README.md)

The execution-binding contract requires an `@oxdeai/guard` release that includes ACT-1 (`^2.0.5` on the 2.0.x line). Framework identifiers are captured once during translation. Top-level framework getters and Proxies may run during translation; only the constructed action is subject to Guard plain-data validation.
