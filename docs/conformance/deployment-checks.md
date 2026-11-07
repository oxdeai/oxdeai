# Deployment checks

**Status:** non-normative tooling. Not protocol conformance.

Protocol conformance (`pnpm -C packages/conformance validate`, the `test:vectors:*`
commands) shows that an implementation computes the specified results for the
checked-in corpora. It says nothing about how a particular deployment is wired.
`runDeploymentChecks` in `@oxdeai/conformance/deployment` tests some of the
deployment assumptions listed in
[`docs/security/threat-model.md`](../security/threat-model.md) and
[`docs/audits/2.0-residual-scope.md`](../audits/2.0-residual-scope.md), using
probes that the deployer writes against their own system.

## Outcomes

| Outcome | Meaning |
|---|---|
| `PASS` | The probe produced positive, attributable evidence of the expected behavior. |
| `FAIL` | A verified violation: an observed protected side effect, an execution the deployment reported, a body processed past the declared limit, replay state shown not to be shared, or a topology claim contradicted by the handles. |
| `NOT_TESTED` | No evidence either way: no probe, a missing or failed positive control, a transport error, a timeout, a 5xx or other service failure, a probe that threw, an unattributed response, missing or in-process topology evidence. |

The aggregate `result` is:

- `FAIL` if any check is `FAIL`;
- `PASS` only if every check is `PASS` **and** the provenance is complete;
- `INCOMPLETE` otherwise.

`NOT_TESTED` is never counted as `PASS`. The report has `kind: "deployment"` and
is never merged into a conformance report or its `evidenceScope`.

## Checks

| Id | Probe | PASS when |
|---|---|---|
| `DEP-CONTROL` | `control()`: one legitimate request through the boundary to the protected resource | it executed exactly once. |
| `DEP-REQUEST-SIZE` | `requestSize.send(n)`, `requestSize.health()` | All of the following hold: <ul><li>`health()` is true before the probe;</li><li>a body of exactly `limitBytes` gets a non-5xx answer that is not `413`;</li><li>a body of `limitBytes + 1` gets `413` **with `attributedTo`** naming the declared limit;</li><li>`health()` is still true afterwards.</li></ul> |
| `DEP-REPLAY-RESULT` | `replay.handles[0]` | consuming a fresh id answers the boolean `true`, then the boolean `false`. |
| `DEP-REPLAY-SHARED` | `replay.handles[0..1]` plus `replay.topology` | All of the following hold: <ul><li>A then B answers `true` then `false`;</li><li>`concurrency` parallel consumes of one id answer exactly one `true`;</li><li>the topology is attested as `independent-processes` or `independent-connections`, with distinct instance and connection identifiers and an `evidenceRef`.</li></ul> |
| `DEP-REPLAY-ERROR` | `replayError()`: a valid request while the store is made to fail | refused (4xx), no protected side effect, and `control()` executes exactly once afterwards. |
| `DEP-AUTHORITY` | `authority()`: a validly signed authorization from an untrusted issuer/policy | same as above. |
| `DEP-DELEGATION-SIGNER` | `delegationSigner()` and `delegationControl()` | `delegationControl()` (an authorized delegation) executes once before and once after, and a delegation signed by a key trusted for its `issuer`, but whose `(delegator, issuer)` pair is not authorized, is refused with no side effect. |
| `DEP-REVOCATION` | `revocation()`: a revoked key or delegation where revocation is required | refused, no side effect, control afterwards. |
| `DEP-CONFIG-IMMUTABLE` | `configImmutability()`: a request that only passes if a post-construction config change were honored | refused, no side effect, control afterwards. |
| `DEP-BYPASS` | `bypass()`: a direct call to the protected resource | refused, no side effect, control afterwards. |

### Refusal observations

Refusal probes return `{ outcome, sideEffects, status?, reason? }`.

`outcome` is one of:

- `refused`
- `executed`
- `service_error`
- `transport_error`
- `timeout`

`sideEffects` must come from the deployer's own instrumentation of the protected
resource (for example a counter in a test double of the upstream), not from the
enforcement point's response.

How observations are scored:

- Any side effect is `FAIL`, whatever the outcome.
- A `refused` outcome with a 5xx status counts as a service failure.
- A refusal is credited only if the positive control still executes exactly once
  afterwards. A service that crashed, or a protected upstream that went away,
  therefore cannot pass a refusal check.

### Request size

A connection close, reset or timeout on the oversized request is not evidence of a
size limit; it could equally be a crash or a network fault. The check therefore
requires all of the following:

- an explicit `413`;
- an attribution (`attributedTo`) that the probe established, for example from a
  marker header or a dedicated error page of the ingress;
- a passing health check after the probe.

A service that becomes unhealthy after the oversized request is `FAIL`.

### Shared replay

Two handles are not evidence of two instances. The deployer attests the topology:

- `kind`
- two `instanceIds`
- two `connectionIds`
- an `evidenceRef`

How the topology is scored:

- **Recorded but not verified.** The checker records the attestation and checks it
  for consistency.
- **Contradictions are `FAIL`.** Examples: one object passed twice under an
  independence claim, or one connection id for both handles.
- **Missing, incomplete or `in-process` topology is `NOT_TESTED`.** Behavior that
  merely looks shared within one process proves nothing about separate instances.
- **State shown not to be shared is `FAIL`** whatever the topology says.

### Delegation signer authority (DIV-01)

`issuer` names the signing key's KeySet; `delegator` must equal the parent's
audience. Which issuers may sign delegations for which delegator is opt-in
configuration:

- `trustedDelegationAuthorities` in `verifyDelegationChain`;
- `trustedDelegationSigners` in `@oxdeai/guard`.

Without it, any issuer with a trusted KeySet can sign a delegation, and
`DEP-DELEGATION-SIGNER` is expected to **FAIL**. That is the documented default,
and this check makes it visible for a given deployment. A deployment that does not
use delegation leaves the probe out and gets `NOT_TESTED`.

## Provenance

The optional second argument, `DeploymentRunContext`, supplies:

- **`deploymentId`** and **`probeSetId`**: required for an aggregate `PASS`.
- **Per-check `probeId` / `evidenceRef`**: optional.
- **A clock**, for reproducible tests.

The report records them together with `executedAt` (ISO 8601) and the attested
replay topology kind and `evidenceRef`.

Only identifiers matching `[A-Za-z0-9._:/@#+=-]{1,128}` are echoed. Refusal
reasons must match `[A-Za-z0-9_.:-]{1,64}`. Anything else, as well as probe
exception messages, is replaced or omitted, so credentials, tokens and payloads do
not reach the report.

## Limits

- **Probe scope.** The checks see only what the probes observe, when they run.
  They do not find routes, configurations or time windows the deployer did not
  probe.
- **Deployer attestations.** Topology, size-limit attribution and side-effect
  counts are the deployer's. The checker detects contradictions but cannot prove
  the attestations.
- **Real ids and effects.** Replay probes consume real ids in the store they are
  given. The positive controls perform real protected effects: one per run, plus
  one after each refusal probe. Use a reserved `idPrefix` and a non-production
  environment where possible.
- **`DEP-CONFIG-IMMUTABLE`.** Meaningful for `createSecureGuard` and
  `createPepGatewayExecutor`. The low-level `OxDeAIGuard` reads its configuration
  per request by design, so it is expected to fail this check.
- **Not tested.** In-process attacker resistance (IR-03), key custody and durable
  KRL watermarks.
- **Not a certification.** A full `PASS` is evidence about the probed deployment
  only. It does not change any protocol conformance result.

## Example

```ts
import { runDeploymentChecks } from "@oxdeai/conformance/deployment";

const report = await runDeploymentChecks(
  {
    control: async () => ({ executed: await sendLegitimateRequestAndCountEffects() }),
    requestSize: {
      limitBytes: 1_048_576,
      send: (n) => postBodyOfSize(n), // returns { kind: "response", status, attributedTo? } | { kind: "transport_error" } | { kind: "timeout" }
      health: () => gatewayHealthy(),
    },
    replay: {
      handles: [storeViaPepA, storeViaPepB],
      idPrefix: "depcheck-",
      topology: {
        kind: "independent-processes",
        instanceIds: ["pep-a", "pep-b"],
        connectionIds: ["redis-1", "redis-2"],
        evidenceRef: "run-123/topology.json",
      },
    },
    bypass: async () => {
      const before = upstreamEffects();
      const res = await callUpstreamDirectly();
      return { outcome: classify(res), status: res.status, sideEffects: upstreamEffects() - before };
    },
  },
  { deploymentId: "payments-pep/staging", probeSetId: "depcheck@3" },
);
if (report.result !== "PASS") process.exitCode = 1;
```
