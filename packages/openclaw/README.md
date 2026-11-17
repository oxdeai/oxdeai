# @oxdeai/openclaw
Shape adapter that maps OpenClaw-style actions to @oxdeai/guard. It registers no OpenClaw hook; only actions
you route through it are authorized. No authorization, no execution.

---

## What this package does

OpenClaw actions (`{ name, args, step_id, workflow_id }`) carry no agent
identity and use a different shape from OxDeAI's `ProposedAction`. This adapter:

1. Injects `agentId` from config into every call (action calls carry no agent identity)
2. Maps `action.step_id` → `context.intent_id` (the per-step identifier)
3. Carries `action.workflow_id` → `context.workflow_id` (parent workflow context)
4. Passes the resulting `ProposedAction` to `OxDeAIGuard`

Everything else - policy evaluation, authorization verification, state
persistence, fail-closed behavior - happens inside `@oxdeai/guard`.

---

## Integration level

This package is a **shape adapter**, not a native OpenClaw integration:

- It does not depend on or import OpenClaw. Its input is a plain object with the OpenClaw action fields
  (`{ name, args, step_id, workflow_id }`).
- It registers no OpenClaw hook, callback or middleware. Nothing is intercepted automatically.
- Enforcement covers only the calls your code passes to the returned guard function, with the tool run
  inside `execute`. Any other path that runs the tool is not authorized by OxDeAI.
- Compatibility with a specific OpenClaw release's objects is not tested in this repository.
- The repository example ([`examples/openclaw`](https://github.com/oxdeai/oxdeai/tree/main/examples/openclaw))
  uses OpenClaw-shaped actions without an OpenClaw runtime.
- No native OpenClaw enforcement integration is published.

---

## Installation

```sh
pnpm add @oxdeai/openclaw @oxdeai/core
```

---

## Usage

```ts
import { createOpenClawGuard } from "@oxdeai/openclaw";

const guard = createOpenClawGuard({
  engine,      // PolicyEngine from @oxdeai/core
  getState,    // () => { state, version } | Promise<{ state, version }>
  setState,    // (state, expectedVersion) => boolean | Promise<boolean>  (CAS)
  agentId: "gpu-agent-1",
  trustedKeySets: [myKeySet], // required, passed through to OxDeAIGuard
});

// In your OpenClaw action dispatcher:
await guard(
  {
    name: "provision_gpu",
    args: { asset: "a100", region: "us-east-1" },
    step_id: "step-1",
    workflow_id: "openclaw-gpu-demo",
  },
  (verified) => provisionGpu(verified.args.asset as string, verified.args.region as string)
);
```

The `execute` callback is only invoked when the policy engine returns ALLOW
**and** the authorization artifact passes verification. On DENY, `OxDeAIDenyError`
is thrown and the callback is never called.

### Execution binding

The `execute` callback receives the **verified action**: the deep-frozen
`ProposedAction` snapshot that the guard evaluated and bound to the
authorization (`args` comes from `action.args`). Read the tool name and arguments
from this argument, not from `action`. The original input is caller-owned and
can change while authorization is awaited; the snapshot cannot.

- A zero-argument callback such as `() => executeAction(action)` still compiles
  and runs, for backward compatibility, but it is **not** covered by this
  binding. Migrate it to `(verified) => ...`.
- The adapter reads each field of `action` once, when the guard is called.
  Proxies, accessors and other non-plain values anywhere in the action it
  builds (including everything under `args`) are rejected with
  `OxDeAINormalizationError` before policy evaluation, replay consumption and
  state writes.
- The binding does not protect against malicious code running in the same
  process as the guard.

---

## With a custom intent mapper

Use `mapActionToIntent` when you need full control over how an action maps
to an OxDeAI `Intent`:

```ts
const guard = createOpenClawGuard({
  engine,
  getState,
  setState,
  agentId: "gpu-agent-1",
  trustedKeySets: [myKeySet],
  mapActionToIntent(action) {
    // action.name, action.args, action.context.agent_id,
    // action.context.intent_id (from step_id) and workflow_id are available
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
} from "@oxdeai/openclaw";

try {
  await guard(action, execute);
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
- Runtime security semantics beyond the Action → ProposedAction mapping

All of that lives in `@oxdeai/guard`.

---

## See also

- [OpenClaw demo README](https://github.com/oxdeai/oxdeai/blob/main/examples/openclaw/README.md)
- [Adapter reference architecture](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-reference-architecture.md)
- [Adapter stack release notes](https://github.com/oxdeai/oxdeai/blob/main/docs/adapters/adapter-stack-release-notes.md)
- [Root README](https://github.com/oxdeai/oxdeai/blob/main/README.md)

---

## Run the in-process guard demo

This repository ships a runnable OpenClaw demo that uses `@oxdeai/openclaw` in-process (no external gateway). It shows two ALLOWs followed by a DENY (budget exceeded); DENY blocks execution.

```bash
export OXDEAI_ENGINE_SECRET=test-secret-must-be-at-least-32-chars!!
pnpm -C examples/openclaw build
node examples/openclaw/dist/run.js
```

Expected:
- Call 1: ALLOW → executes
- Call 2: ALLOW → executes
- Call 3: DENY  → execute callback not called (BUDGET_EXCEEDED)

Demo:

![OpenClaw guard demo](../../docs/media/openclaw-guard-demo.gif)

> Tip: if `OXDEAI_ENGINE_SECRET` is unset, the demo falls back to a bundled demo secret. Set your own secret for non-demo use.

The execution-binding contract requires `@oxdeai/guard ^2.0.5`. Framework identifiers are captured once during translation. Top-level framework getters and Proxies may run during translation; only the constructed action is subject to Guard plain-data validation.
