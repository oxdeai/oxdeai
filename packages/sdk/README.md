# @oxdeai/sdk
Developer toolkit for the OxDeAI execution-time authorization protocol (ETA).
Builds intents/states and guard boundaries that fail closed at execution.

## Status

Release policy note: OxDeAI uses package-scoped versions and package-scoped tags. `@oxdeai/sdk` has its own package version line; coordinated release commits do not imply shared package versions across `core`, `sdk`, or `conformance`. See [`docs/release/RELEASE.md`](../../docs/release/RELEASE.md).

Current `@oxdeai/sdk` package line: **2.0.1**. `export * from "@oxdeai/core"`
re-exports core's 2.0 surface, so every core 2.0 breaking change (in particular
the required `evaluationTime` argument and the now-required
`maxClockSkewSeconds` / `maxIntentAgeSeconds` engine options) is a consumer-visible
change here too. See [`CHANGELOG.md`](./CHANGELOG.md) for the full list.

The SDK is an integration surface and does not redefine protocol semantics.

## What It Adds

- Intent/state builder helpers
- Typed client wrapper for common flow: evaluate + persist + verify
- Public guard API for callback-boundary enforcement (`createGuard`)
- Runtime adapters (in-memory and file-based)

## Architecture Overview

![PDP and PEP flow](../../docs/diagrams/pdp-pep-flow.svg)

OxDeAI SDK sits at the runtime integration boundary:

- runtime/adapter proposes action input
- PDP evaluates policy and emits `AuthorizationV1` on `ALLOW`
- PEP callback gate executes only after authorization enforcement

Diagram source/editing policy:
- [`docs/diagrams/README.md`](../../docs/diagrams/README.md)

## Guard API

The SDK exposes its own framework-agnostic guard boundary, built directly on
`OxDeAIClient`'s in-process `stateAdapter`/`auditAdapter`/`clock`:

```ts
const guard = createGuard({ engine, stateAdapter, auditAdapter, clock });
const result = await guard(intent, async ({ authorization }) => {
  return executeTool(authorization);
});
```

The callback runs only when OxDeAI returns `ALLOW` and authorization enforcement passes.
On `DENY` (or failed auth verification), the callback is not executed.

This keeps PDP/PEP separation explicit:

- PDP: `PolicyEngine.evaluatePure(...)` decides
- PEP: guard callback boundary enforces execute-or-refuse

**`createGuard` is not the canonical universal PEP.** It is a convenience
boundary scoped to the SDK's own in-process adapters, useful for prototypes,
scripts, and simple single-process integrations. It does not implement
versioned/CAS state commits, a pluggable replay store, delegation, or trusted
execution-context provenance reconciliation.

**[`@oxdeai/guard`](../guard/README.md) is the dedicated enforcement-boundary
package for the 2.0 architecture.** `OxDeAIGuard` and the Tier 1
`createSecureGuard` path are what production deployments should use. It is a
separate package specifically so that every runtime adapter (LangGraph,
CrewAI, OpenAI Agents SDK, OpenClaw, custom agents) shares one PEP
implementation instead of each re-implementing this boundary. Prefer
`@oxdeai/guard` for anything beyond a single-process prototype; treat the
SDK's `createGuard` as the lower-level/legacy-compatible path it is.

OxDeAI sits below agent frameworks (OpenAI tools, LangGraph, others) as the deterministic authorization boundary.

## Quick Example

```ts
import { PolicyEngine, RECOMMENDED_TRUSTED_TIME_PROFILE } from "@oxdeai/core";
import {
  OxDeAIClient,
  createGuard,
  buildState,
  buildIntent,
  InMemoryStateAdapter,
  InMemoryAuditAdapter
} from "@oxdeai/sdk";

const engine = new PolicyEngine({
  policy_version: "v1",
  engine_secret: "example-secret-must-be-32-chars!",
  authorization_ttl_seconds: 120,
  ...RECOMMENDED_TRUSTED_TIME_PROFILE // maxClockSkewSeconds / maxIntentAgeSeconds: required, no default
});

const stateAdapter = new InMemoryStateAdapter(
  buildState({
    policy_version: "v1",
    agent_id: "agent-1",
    allow_action_types: ["PROVISION"],
    allow_targets: ["us-east-1"]
  })
);

const auditAdapter = new InMemoryAuditAdapter();

const client = new OxDeAIClient({
  engine,
  stateAdapter,
  auditAdapter,
  clock: { now: () => 1770000000 }
});

const intent = buildIntent({
  intent_id: "intent-1",
  agent_id: "agent-1",
  action_type: "PROVISION",
  amount: 320n,
  target: "us-east-1",
  nonce: 1n
});

const result = await client.evaluateAndCommit(intent);

const guard = createGuard({
  engine,
  stateAdapter,
  auditAdapter,
  clock: { now: () => 1770000000 }
});

await guard(intent, async () => {
  // execute side effect only when ALLOW + auth checks pass
  return { ok: true };
});
```

## Verification Time

Authorization verification has two clock domains, and they are not interchangeable:

| Value | Trust |
| --- | --- |
| `intent.timestamp` | Untrusted. Supplied by the agent. |
| verifier time | Trusted. Supplied by the execution boundary. |

The SDK takes verifier time from the trusted `clock` passed to `OxDeAIClient` and `createGuard`,
never from the intent. A caller that already holds a trusted time from the execution boundary can
pass it explicitly:

```ts
await client.verifyAuthorization(intent, authorization, {
  verificationTime: trustedClock.now()
});
```

Deriving verifier time from `intent.timestamp` compares an authorization against a deadline the
same untrusted value produced, so expiry can never be enforced. `clock` defaults to
`Date.now() / 1000`; supply a `ClockAdapter` when the host has an independently trusted time source.

## Main Exports

- `buildIntent`, `buildState`
- `OxDeAIClient`
- `createGuard`
- `InMemoryStateAdapter`, `InMemoryAuditAdapter`
- `JsonFileStateAdapter`, `NdjsonFileAuditAdapter`

## Scripts

```bash
pnpm -C packages/sdk build
pnpm -C packages/sdk test
```
