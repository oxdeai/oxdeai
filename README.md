# OxDeAI

[![CI](https://github.com/oxdeai/oxdeai/actions/workflows/ci.yml/badge.svg)](https://github.com/oxdeai/oxdeai/actions/workflows/ci.yml)

Execution authorization for AI agents.
No valid authorization, no execution through the reviewed enforcement boundary.

Deterministic boundary:
(intent, state, policy) → ALLOW | DENY

No authorization → no execution.

Agents propose actions.  
OxDeAI decides if they are allowed to execute.  
No valid authorization → execution is unreachable.

Authorization is evaluated before any side effect is reachable.

## Core Model

OxDeAI introduces an explicit decision phase:

```text
proposal → authorization → execution
```

```text
(intent, state, policy) → deterministic decision
```

* `intent`: proposed action
* `state`: evaluation context
* `policy`: rule set

If `ALLOW` → emits **AuthorizationV1**
If `DENY` → execution is unreachable

## Core Invariants

- No authorization → no execution
- (intent, state, policy) → deterministic ALLOW | DENY
- Same input → same decision
- Verification failure → fail closed

---

## Execution Boundary

OxDeAI enforces a strict invariant at the reviewed enforcement boundary:

> **No valid authorization, no execution through the reviewed enforcement boundary.**

A tool call routed through the PEP Gateway:

* has its authorization verified before execution
* has its intent hash checked against canonical input
* is subject to replay protection
* fails closed by default

This holds for calls that go through the boundary. It does not by itself make
every possible call path in a deployment non-bypassable: see
[Scope and limits](#scope-and-limits).

---

## Scope and limits

The guarantees above apply to the reviewed enforcement boundary
(`@oxdeai/guard`), not to a deployment as a whole. A deployment is only as
strong as its weakest unreviewed call path.

Current, authoritative scope and residual-limit documents for the 2.0 line:

- [`docs/audits/2.0-residual-scope.md`](./docs/audits/2.0-residual-scope.md): what 2.0 targets and what remains out of scope (evaluator/state authority, external-resource TOCTOU, post-execution-start audit semantics).
- [`docs/audits/external-review-scope-v2.md`](./docs/audits/external-review-scope-v2.md): the current external review scope.

`docs/audits/protocol-audit-post-interoperability.md` is a historical snapshot
dated 2026-06-04 and is not a current-state reference.

---

## Non-Bypassable Execution Demo

The agent cannot call tools directly.
All execution goes through a **PEP Gateway**.

```text
Agent → Gateway → Protected Upstream
       ↘ direct call → 403
```

### Expected outcomes

* `ALLOW` → executed
* `DENY` → blocked
* `REPLAY` → blocked
* `BYPASS` → rejected

> **No valid authorization → no execution path**

![Terminal Demo](./docs/media/non-bypassable-split-v2.gif)
---

### Run it

```bash
export UPSTREAM_EXECUTOR_TOKEN=demo-internal-token

node examples/non-bypassable-demo/protected-upstream.mjs
node examples/non-bypassable-demo/pep-gateway.mjs
node examples/non-bypassable-demo/agent.mjs
```

---

## Why This Matters

Without an execution boundary:

* retries duplicate side effects
* budgets leak
* permissions drift
* control lives inside the model loop

You are relying on **best-effort enforcement**.

**OxDeAI makes execution conditional.**

---

## Positioning

Most agent systems control behavior.

OxDeAI controls execution.

Without an execution boundary, unauthorized or unintended execution is not prevented.

## Applicability

OxDeAI is not a replacement for inline PDP/PEP authorization.

Inline or sidecar policy evaluation (OPA, Cedar, Cerbos) is the simpler
baseline and should generally be preferred.

A detachable authorization artifact is justified in two cases:

* **Independent verification**: the party that must verify the authorization
  is not the party that ran the decision point or controls the enforcement log
  (counterparty, auditor, regulator). Decision logs are evidence the operator
  produced about the operator's own enforcement.
* **Unreachable premises**: the executor cannot reach the authoritative
  inputs required to re-evaluate locally, across a separate trust/network zone
  or third-party boundary.

Topology alone does not justify it. Separate processes or multiple enforcement
points are solved by placing a decision point next to the executor.

When neither condition applies, do not make the decision detachable.

This boundary came out of a public exchange with a Cerbos maintainer:
[r/AskNetsec thread](https://www.reddit.com/r/AskNetsec/comments/1vkh8za/) · [applicability discussion](docs/architecture/why-oxdeai.md#applicability)

---

## How It Works

1. Agent proposes an action
2. OxDeAI evaluates `(intent, state, policy)`
3. `ALLOW` → AuthorizationV1 issued
4. Gateway verifies authorization
5. Execution becomes reachable

`DENY` → blocked before any side effect

---

## What This Prevents

* unintended execution
* duplicate or replayed actions
* budget overruns
* permission leakage
* non-reproducible decisions

---

## Why This Is Different

* Prompt guardrails → probabilistic
* Monitoring → after execution
* **OxDeAI → deterministic, before execution**

Logs explain what happened.
Authorization artifacts prove what was allowed.

---

## Determinism & Proof

OxDeAI is validated through **verifiable invariants**, not claims:

* frozen canonicalization vectors
* cross-language verification on canonicalization, Profile-C state verification and SignedKRLV1 (TypeScript / Go / Python); other surfaces are TypeScript-only
* conformance suite (CI validated)
* cross-adapter equivalence

```bash
pnpm test:vectors:all
```

All implementations produce **identical canonical bytes and hashes**.

---

## Specification

OxDeAI is a protocol composed of:

* **Canonicalization** → deterministic bytes
* **ETA Core** → decision function
* **Conformance** → verification rules
* **PEP Gateway** → enforcement boundary

→ **Implementation paths**
- [`packages/core/src/`](./packages/core/src)
- [`packages/conformance/`](./packages/conformance)
- [`docs/spec/`](./docs/spec)

## Document Model

- `docs/spec/**` - normative protocol definitions
- `docs/**` - non-normative guides and examples; if there is a conflict, `docs/spec/**` wins

---

## Trust Model

OxDeAI is **not a global authority**.

* Any system can issue authorization
* Signature ≠ trust
* Trust is configured by the verifier

```ts
verifyAuthorization(auth, {
  mode: "strict",
  trustedKeySets: [...],
});
```

> No trust configuration → fail closed

| Concept        | Controlled by |
| -------------- | ------------- |
| Issuer         | Any system    |
| Trusted keys   | Verifier      |
| Execution gate | OxDeAI        |

---

## Release Security Checks (CI)

The repository uses two separate blocking checks:

* **Security Policy Boundary** - a reproducible check of the repo-local
  policy-boundary attack harness.
* **Security Advisory Gate** - freshness-dependent security evidence produced
  from mutable external advisory data and the repository vulnerability policy.

The advisory gate can emit a hash-bound release-evidence record tied to the
candidate SHA, lockfile, and retained advisory input. That record is not an
OxDeAI runtime authorization artifact or an `ExecutionReceiptV1`. See
[`docs/security/SECURITY-GATE.md`](./docs/security/SECURITY-GATE.md).

---

## Quick Start

Prerequisites:

- Node.js 20+
- pnpm 9+

```bash
git clone https://github.com/oxdeai/oxdeai.git
cd oxdeai
pnpm install
pnpm build

export OXDEAI_ENGINE_SECRET='test-secret-must-be-at-least-32-chars!!'
pnpm -C examples/openclaw start
```

Runs the OpenClaw-shaped demo: scripted OpenClaw-style actions pass through `@oxdeai/openclaw`
and the guard (ALLOW, ALLOW, DENY). No OpenClaw runtime is involved.

---

## Delegated Authorization

Delegation behaves like a capability system:

```text
parent → AuthorizationV1 (budget=1000)
        ↓
   DelegationV1 (max=300)
        ↓
child → verifyDelegationChain() → execute / DENY
```

Properties:

* strictly narrowing
* single-hop
* locally verifiable
* cryptographically bound (Ed25519)

---

## Guarantees

* deterministic evaluation
* fail-closed execution
* replay protection
* evaluation isolation
* cross-runtime equivalence

---

## Benchmarks

The synthetic protected-path benchmark measures policy evaluation,
authorization verification, envelope verification, and deterministic in-memory
tool work against the same tool work without OxDeAI checks. Current results are
host- and runtime-specific and contain noise/outlier warnings, so no stable
per-action overhead is claimed. See the
[benchmark summary](./bench/BENCHMARK_SUMMARY.md) for exact observations and
limitations.

---

## Adapter Ecosystem

Three integration levels are distinguished. Only the first two exist today.

**1. Shape adapters (published TypeScript packages).** `@oxdeai/langgraph`, `@oxdeai/openai-agents`,
`@oxdeai/openclaw`, `@oxdeai/crewai` and `@oxdeai/autogen` map a framework-shaped tool call to
`@oxdeai/guard`. They depend on no framework package and register no framework hook. Only calls your
code routes through the returned guard function are authorized. CrewAI and AutoGen are Python
frameworks; their packages are TypeScript bindings for the tool-call shape, and no Python adapter is
published.

**2. Real framework examples.**

* [`examples/langgraph`](./examples/langgraph): a real `@langchain/langgraph` `StateGraph` proposes
  tool calls; `@oxdeai/langgraph` enforces them in application code after the graph returns.
* [`examples/openai-tools`](./examples/openai-tools): `demo:openai` sends real Chat Completions tool
  calls through the `openai` SDK (requires `OPENAI_API_KEY`) and enforces them with `@oxdeai/core`
  directly. The default `start`/`demo` run uses scripted calls and makes no API request.

The CrewAI, AutoGen, OpenAI Agents SDK and OpenClaw examples are framework-shaped and do not run
those frameworks.

**3. Native enforcement integrations.** These would be framework hooks or middleware that intercept every
tool call automatically. **None is implemented.**

On the shared scenario, all shape adapters produce identical outcomes:

```text
ALLOW / ALLOW / DENY / verifyEnvelope() => ok
```

---

## What OxDeAI Is

* execution authorization protocol
* deterministic decision layer
* pre-execution enforcement
* cryptographic authorization artifacts

---

## What OxDeAI Is Not

* not an agent framework
* not a prompt guardrail
* not a monitoring system
* not heuristic runtime logic
* not a replacement for inline PDP/PEP authorization

---

## Protocol Status

| Artifact               | Status  |
| ---------------------- | ------- |
| AuthorizationV1        | Stable  |
| DelegationV1           | Stable  |
| VerificationEnvelopeV1 | Draft   |
| ExecutionReceiptV1     | Planned |

---

## Multi-language Support

Artifacts are portable:

* TypeScript (reference)
* Go
* Python

Verification works across runtimes.

---

## Why This Exists

Agents moved from **answering → acting**.

Execution is now the **risk surface**.

* Prompt guardrails shape behavior
* OxDeAI controls execution

```text
Probabilistic control < Deterministic authorization
```

---

## Contributing

* [CONTRIBUTING.md](./CONTRIBUTING.md)
* [`docs/spec`](./docs/spec)
* [`packages/conformance`](./packages/conformance)

---

## TL;DR

Agents propose actions.
OxDeAI decides if they can execute.

> **No authorization → no execution.**
