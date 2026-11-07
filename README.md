# OxDeAI

[![CI](https://github.com/oxdeai/oxdeai/actions/workflows/ci.yml/badge.svg)](https://github.com/oxdeai/oxdeai/actions/workflows/ci.yml)

**OxDeAI is a deterministic execution authorization protocol for AI agents.**
Agents propose actions. Each action is authorized by a policy decision, and that
authorization is then verified independently before anything executes, at a
protected enforcement boundary.

> **No valid authorization, no execution through the enforced boundary.**

OxDeAI is not an agent framework, a prompt guardrail or a monitoring platform.
It does not replace OPA, Cedar or Cerbos either (see [When to use it](#when-to-use-it)).

## Quick Start

**Prerequisites:** Node.js ≥ 20 (CI uses the version specified in [`.node-version`](./.node-version)) and pnpm ≥ 10.34.5.

The demo runs entirely on localhost using a test key. No external services or production credentials are required.

```bash
git clone https://github.com/oxdeai/oxdeai.git
cd oxdeai
corepack enable
pnpm install --frozen-lockfile
pnpm build:protocol
pnpm demo
```

The executable demo starts a protected upstream and a PEP Gateway, then verifies HTTP responses and actual upstream side effects.

### Expected results

| Scenario | HTTP | Expected behavior |
| --- | --- | --- |
| `ALLOW` | `200` | Valid authorization; action executed exactly once |
| `NOT_COVERED` | `403` | Intent hash mismatch; rejected by the Gateway without execution |
| `REPLAY` | `403` | `AUTH_REPLAY`; previously consumed authorization cannot execute again |
| `BYPASS` | `403` | Direct upstream request rejected due to missing or invalid internal executor token |

Expected output:

```text
ALLOW        200  executed                 side effects +1  ✓
NOT_COVERED  403  INTENT_HASH_MISMATCH     side effects +0  ✓
REPLAY       403  AUTH_REPLAY              side effects +0  ✓
BYPASS       403  missing or invalid internal executor token side effects +0  ✓

All 4 scenarios behaved as expected. Total side effects: 1
```

**Important:** `NOT_COVERED` demonstrates a Gateway verification failure, not a policy `DENY` decision from the PDP. The demo validates enforcement for requests passing through the protected boundary; it does not establish that every possible execution path in an arbitrary deployment is non-bypassable.

The command exits with a nonzero status if any assertion fails.

For the multi-process example, see [`examples/non-bypassable-demo`](./examples/non-bypassable-demo).

## How it works

```text
agent ──proposes──▶ PDP: (canonical intent, trusted state, policy)
                     │
                     ├──▶ ALLOW + signed AuthorizationV1
                     └──▶ DENY  (no artifact issued)

agent ──action + AuthorizationV1──▶ PEP (enforcement boundary) ──▶ protected tool
                                     │
                                     ├── Ed25519 signature, trusted keys
                                     ├── issuer/policy authority
                                     ├── audience, expiry
                                     ├── intent hash = exact action
                                     └── single use (auth_id consumed)

Demo deployment: only the PEP holds the upstream executor token.
```

1. **Decide.** The policy engine evaluates `(intent, state, policy)`.
   For identical canonical intent, trusted state and policy inputs,
   the deterministic decision function produces the same result.
   `ALLOW` produces an [`AuthorizationV1`](./docs/spec/artifacts/authorization-v1.md)
   bound to the intent hash, the state hash, the audience and an expiry.
2. **Verify.** The enforcement point re-checks the artifact against its own
   configuration: which keys it trusts, which issuer/policy pairs may authorize
   it, and its audience. A valid signature alone is not trust.
3. **Execute or refuse.** The tool runs only when verification passes, and each
   `auth_id` is consumed once. On any verification failure, the action is
   refused.

A parent authorization can hand a narrower scope to another agent through a
single-hop [`DelegationV1`](./docs/spec/artifacts/delegation-v1.md).

## When to use it

Inline or sidecar policy evaluation (OPA, Cedar, Cerbos) is simpler, and is the
better choice when the executor can evaluate policy itself. A detachable,
signed authorization is justified when:

- **independent verification is required**: the party that must check the
  decision (a counterparty, auditor or separate executor) is not the operator of
  the decision point; or
- **the authoritative inputs are unavailable to the executor**: policy or state
  lives across a trust, network or third-party boundary.

Separate processes alone do not justify it; putting a decision point next to
the executor solves that. See
[Why OxDeAI: applicability](./docs/architecture/why-oxdeai.md#applicability).

## Security guarantees and limits

**What is specified and tested,** for calls that go through the enforced boundary
(`@oxdeai/guard`):

- deterministic decisions for identical canonical intent, trusted state and policy inputs;
- authorization verified before execution, bound to the exact action by its intent hash;
- issuer/policy authority and trusted keys configured by the verifier;
- single use of each `auth_id` within the configured replay store;
- refusal when verification fails, or when the replay store throws, rejects or
  answers anything other than the boolean `true` (first use) or `false` (replay).
  A refusal does not prove the `auth_id` was left unconsumed.

**What OxDeAI does not guarantee by itself:**

- **Other call paths.** A tool reachable by another path is not protected. The
  deployment must make the boundary the only path, for example with the
  executor token shown in the demo.
- **Trust inputs.** Correct policy, state inputs and key management. A valid
  signature proves who signed, not that the signer should be trusted.
- **Replay scope.** Replay protection is process-local unless you configure a
  shared, durable store (`replayProtection: { mode: "shared", store }`).
- **Opt-in controls.** Delegation revocation (SignedKRLV1) and delegation signer
  authority are off unless you configure them.
- **What an authorization is.** It is not proof that the action happened.
  Execution receipts (`ExecutionReceiptV1`) are planned and do not exist yet.
- **Cross-language coverage.** Go and Python harnesses cover only some surfaces
  (canonicalization, Profile-C state verification, SignedKRLV1). Everything else
  is verified in TypeScript only.
- **Configuration lifecycle.** `createSecureGuard` and `createPepGatewayExecutor`
  capture and validate their security configuration at construction; later
  changes to the caller's config object have no effect, except in-place updates
  to the `trustedKeySets` array (key rotation) and the own state of the replay
  store and revocation providers, which stay live. The low-level
  `OxDeAIGuard` reads its configuration on each request, so the config object
  must stay under the deployer's control. See the
  [Guard README](./packages/guard/README.md#secure-guard-configuration-is-captured-at-construction).
- **Trusted-process integrity (IR-03).** OxDeAI does not protect against
  arbitrary attacker-controlled JavaScript executing inside the trusted
  Guard/PEP process. Partial hardening exists against inherited Promise
  thenable manipulation, but a timed in-process attack remains a documented
  residual risk. Untrusted agents, tools and plugins must execute outside
  the trusted enforcement process.

Scope and residual limits: [2.0 residual scope](./docs/audits/2.0-residual-scope.md) ·
[external review scope](./docs/audits/external-review-scope-v2.md) ·
[threat model](./docs/security/threat-model.md). Report vulnerabilities privately:
[SECURITY.md](./SECURITY.md).

## Protocol status

| Specification | Status |
| --- | --- |
| [AuthorizationV1](./docs/spec/artifacts/authorization-v1.md), [DelegationV1](./docs/spec/artifacts/delegation-v1.md) | Stable |
| [PEP Gateway](./docs/spec/enforcement/pep-gateway-v1.md), [Verification](./docs/spec/verification/verification-v1.md) | Stable |
| [SignedKRLV1](./docs/spec/artifacts/signed-krl-v1.md) | Draft |
| VerificationEnvelopeV1 | Draft: codec and verifier in `@oxdeai/core`; no specification in `docs/spec/` yet ([overview](./docs/protocol/overview.md)) |
| ExecutionReceiptV1 | Planned |

Normative text lives in [`docs/spec/`](./docs/spec). If anything elsewhere in `docs/` conflicts with it, `docs/spec/` wins.

## Documentation and integrations

- **Specification:** [`docs/spec/`](./docs/spec) ([canonicalization](./docs/spec/core/canonicalization-v1.md), [decision core](./docs/spec/core/eta-core-v1.md), [conformance](./docs/spec/conformance/conformance-v1.md))
- **Conformance:** [`packages/conformance`](./packages/conformance) and [test vectors](./docs/spec/test-vectors). Run `pnpm test:vectors:ts` (TypeScript only), or `pnpm test:vectors:all`, which also needs Go and Python.
- **Packages:** [`@oxdeai/core`](./packages/core) (decision, artifacts, verification) and [`@oxdeai/guard`](./packages/guard) (enforcement boundary, PEP gateway)
- **Adapters (TypeScript):** LangGraph, OpenAI Agents SDK, OpenClaw. CrewAI and AutoGen have adapter-shape bindings. See [`examples/`](./examples).
- **More examples:** [`examples/openclaw`](./examples/openclaw) (a budget-based policy `DENY`) · [`examples/delegation`](./examples/delegation)
- **Performance:** [benchmark summary](./bench/BENCHMARK_SUMMARY.md). Results depend on the host, so no fixed per-action overhead is claimed.
- **Release security checks:** [`docs/security/SECURITY-GATE.md`](./docs/security/SECURITY-GATE.md)

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md), [GOVERNANCE.md](./GOVERNANCE.md) and the
[Code of Conduct](./CODE_OF_CONDUCT.md). Protocol changes need an issue discussion, a
spec update in `docs/spec/`, and tests or vectors where applicable.

Licensed under [Apache-2.0](./LICENSE).
