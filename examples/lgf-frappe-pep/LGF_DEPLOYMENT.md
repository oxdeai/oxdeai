# LGF Platform Layer - OxDeAI PEP Sidecar Deployment

Status: Reference documentation
Related issues: #141, #142, #143, #148, #149
Scope: LGF sidecar deployment model for a generic OxDeAI PEP
Validated action: `frappe.helpdesk.create_ticket`

## Architecture Overview

The OxDeAI PEP runs as a sidecar within the LGF Platform Layer. It sits between the caller (agent, OpenWebUI, or other client) and the target platform (Frappe, ERPNext, Nextcloud, OpenProject, or any platform LGF manages).

```text
[Agent / caller]
      |
      v
[OxDeAI PEP sidecar]
      |
      | verifies AuthorizationV1
      | verifies intent_hash
      | checks policy result
      | claims auth_id in replay backend
      v
[LGF-injected platform adapter / tooling]
      |
      v
[Target platform: Frappe / ERPNext / Nextcloud / OpenProject / etc.]
```

The PEP enforces a single invariant:

> No valid authorization → no execution path.

The PEP does not know the target platform's internal semantics. Platform-specific adapter logic, credentials, and routing are injected by LGF at deployment time.

## Adapter Boundary

The runtime now exposes an explicit platform adapter boundary.

PEP owns:

* AuthorizationV1 verification
* intent hash binding
* replay protection
* policy enforcement
* fail-closed execution gating
* observe/enforce mode behavior
* health and graceful shutdown

Adapter owns:

* target-platform API invocation
* target-platform request formatting
* target-platform response parsing
* target-platform-specific side effects
* target-platform runtime configuration

Current adapter:

```text
Frappe Helpdesk
```

Current limitation: this is a first adapter-boundary extraction. The packaged sidecar still uses the current example runtime and still expects Frappe-oriented adapter configuration such as `FRAPPE_BASE_URL`. Full dynamic adapter loading and additional platform adapters remain future work.

## Responsibility Boundary

### LGF owns

* Container topology and orchestration
* Ingress and routing rules
* Secret injection and rotation
* Runtime configuration files and environment variables
* Service exposure (ports, TLS termination, network policy)
* Image lifecycle (pull, tag, upgrade, rollback)
* Runtime configuration and secret injection for the deployed PEP
* Network and platform routing around the deployed PEP
* Future mounted config volumes (`/etc/oxdeai/`) when that interface is implemented
* Platform adapter deployment/injection as additional adapters are implemented
* Replay backend provisioning (currently Redis; mounted persistence remains future work)
* Network-level bypass prevention (ensuring callers cannot reach the target platform without passing through the PEP)

### OxDeAI owns

* AuthorizationV1 verification (Ed25519 signature, structural validation)
* Issuer and audience validation
* Expiration validation
* Intent hash binding (canonicalization + SHA-256 comparison)
* Policy result enforcement (ALLOW / DENY)
* Replay protection (auth_id consumption via pluggable backend)
* Enforce / observe mode behavior
* Fail-closed execution guarantees
* Decision logging (structured, secret-free)
* Graceful runtime shutdown on `SIGTERM` / `SIGINT`

## Image Strategy

### Generic OxDeAI PEP

The long-term target is a generic OxDeAI PEP OCI artifact. The current reference runtime accepts configuration through environment variables. Mounted runtime configuration is a planned interface and is not consumed by the current implementation. The image does not embed platform credentials or signing private keys.

The current packaging target is:

```text
ghcr.io/oxdeai/oxdeai-pep-sidecar:lgf-sidecar-poc
```

Published digest:

```text
ghcr.io/oxdeai/oxdeai-pep-sidecar@sha256:19086e7972484852efe998f8a3f0982125a16e3911ea068af52829b8ee746e53
```

Local build:

```bash
docker build -t oxdeai-pep-sidecar:local -f examples/lgf-frappe-pep/Dockerfile .
```

The image is suitable for GHCR publishing, but GHCR push remains a manual release step.

Published image pull command:

```bash
docker pull ghcr.io/oxdeai/oxdeai-pep-sidecar:lgf-sidecar-poc
```

Current limitation: this is the first generic-sidecar packaging step. The implementation source still lives in `examples/lgf-frappe-pep`, and the runtime still expects Frappe-oriented adapter configuration such as `FRAPPE_BASE_URL`. That means the packaging is generic and secret-free, but full adapter extraction is still future work.

### Frappe-specific PoC image

The Frappe PoC image is a validated reference implementation:

```text
ghcr.io/oxdeai/oxdeai-pep-frappe:lgf-poc
```

This image embeds a minimal Frappe Helpdesk adapter that creates HD Ticket resources via the Frappe REST API. It was used to validate the OxDeAI boundary against a live LGF-managed Frappe bench.

The Frappe PoC image is not the required long-term image shape. It demonstrates:

* AuthorizationV1 issuance and verification
* intent hash binding
* replay protection
* enforce / observe mode
* fail-closed behavior on upstream errors
* structured decision logging

The current generic sidecar packages the Frappe-oriented reference runtime
behind the `PlatformAdapter` boundary. Runtime adapter selection and additional
LGF-injected platform adapters remain future work.

### Generic sidecar runtime behavior

The packaged sidecar image:

* exposes the PEP HTTP listener on port `3000`
* provides `/healthz`
* supports `REPLAY_STORE=memory`
* supports `REPLAY_STORE=redis` with runtime `REDIS_URL`
* preserves graceful `SIGTERM` / `SIGINT` shutdown
* does not bake in Frappe credentials, LGF credentials, signing private keys, Redis credentials, or local `/tmp` secret files

Example local run:

```bash
docker run --rm -p 8080:3000 \
  -e OXDEAI_MODE=observe \
  -e EXPECTED_AUDIENCE=pep-sidecar.local \
  -e FRAPPE_BASE_URL=https://example.invalid \
  -e REPLAY_STORE=memory \
  -e SIGNING_PRIVATE_KEY_PEM="<runtime-injected-private-key-pem>" \
  oxdeai-pep-sidecar:local
```

Health check:

```bash
curl -fsS http://127.0.0.1:8080/healthz
```

Observed result from the pulled GHCR image:

```json
{"ok":true,"status":"healthy","mode":"observe"}
```

## Runtime Configuration Contract

The current reference PEP is configured through environment variables.

This section describes the configuration interface actually consumed by
`src/config.ts`.

Mounted trusted-keyset, policy, action-map, and runtime configuration files
described later in this document are a **planned interface** and are **not
currently loaded by the runtime**.

### Environment variables implemented by the current runtime

| Variable | Requirement | Description |
|----------|-------------|-------------|
| `OXDEAI_MODE` | required | `enforce` or `observe` |
| `EXPECTED_AUDIENCE` | required | Audience required by AuthorizationV1 verification |
| `FRAPPE_BASE_URL` | required by current Frappe runtime | Frappe REST API base URL; this requirement is adapter-specific, not a generic PEP protocol requirement |
| `FRAPPE_API_KEY` | required in `enforce` | Frappe API key, runtime-injected |
| `FRAPPE_API_SECRET` | required in `enforce` | Frappe API secret, runtime-injected |
| `SIGNING_PRIVATE_KEY_PEM` | required | Ed25519 private key used to issue AuthorizationV1 artifacts |
| `SIGNING_KID` | optional | Signing key identifier; default `lgf-frappe-pep-key-1` |
| `ISSUER` | optional | Authorization issuer; default `oxdeai.lgf-frappe-pep` |
| `AUTHORIZATION_TTL_SECONDS` | optional | Authorization TTL; default `60` |
| `REPLAY_STORE` | optional | Replay backend: `memory` or `redis`; default `memory` |
| `REDIS_URL` | required when `REPLAY_STORE=redis` | Redis connection URL |
| `REPLAY_KEY_PREFIX` | optional | Redis replay-key prefix; default `oxdeai:pep:replay` |
| `REPLAY_TTL_SKEW_SECONDS` | optional | Additional replay TTL skew; default `60` |
| `PORT` | optional | HTTP listener port; default `3000` |

The current runtime supports only:

```text
REPLAY_STORE=memory
REPLAY_STORE=redis
````

A `mounted` replay backend is not implemented.

### Current trust-configuration provenance

The reference PEP does not currently load trusted keysets, policy definitions,
or action maps from mounted files.

For the current implementation:

* the Ed25519 public key used for AuthorizationV1 verification is derived from
  the runtime-injected `SIGNING_PRIVATE_KEY_PEM`;
* the trusted keyset passed to `verifyAuthorization()` is constructed by the
  PEP from that derived public key, `ISSUER`, and `SIGNING_KID`;
* the trusted authorization-authority pair is constructed from the configured
  issuer and the locally defined `POLICY_ID`;
* `POLICY_ID` comes from the current policy implementation;
* the expected audience comes from `EXPECTED_AUDIENCE`;
* replay configuration comes from `REPLAY_STORE` and the associated Redis
  settings when Redis is selected.

A valid signature and an allowed `(issuer, policy_id)` authority pair are
separate requirements in the current execution path.

### Configuration categories

* **Required PEP runtime configuration**:
  `OXDEAI_MODE`, `EXPECTED_AUDIENCE`, `SIGNING_PRIVATE_KEY_PEM`.
* **Current Frappe adapter configuration**:
  `FRAPPE_BASE_URL`.
* **Enforce-mode platform secrets**:
  `FRAPPE_API_KEY`, `FRAPPE_API_SECRET`.
* **Optional deployment configuration**:
  `ISSUER`, `SIGNING_KID`, `AUTHORIZATION_TTL_SECONDS`, `PORT`.
* **Replay configuration**:
  `REPLAY_STORE`, `REDIS_URL`, `REPLAY_KEY_PREFIX`,
  `REPLAY_TTL_SKEW_SECONDS`.
* **Planned configuration interfaces**:
  mounted trusted-keyset, policy, action-map, and runtime files.

Secrets must be injected at runtime and must not be baked into images or
written to logs.

### Example current runtime configuration

```env
OXDEAI_MODE=enforce
EXPECTED_AUDIENCE=PEP-frappe.lgf.oxdeai.dev

ISSUER=oxdeai.lgf-frappe-pep
AUTHORIZATION_TTL_SECONDS=60
SIGNING_KID=lgf-frappe-pep-key-1

REPLAY_STORE=memory

FRAPPE_BASE_URL=<frappe-base-url>
FRAPPE_API_KEY=<runtime-injected-secret>
FRAPPE_API_SECRET=<runtime-injected-secret>

SIGNING_PRIVATE_KEY_PEM=<runtime-injected-secret>

PORT=3000
```

For Redis-backed replay:

```env
REPLAY_STORE=redis
REDIS_URL=redis://<redis-host>:6379
REPLAY_KEY_PREFIX=oxdeai:pep:replay
REPLAY_TTL_SKEW_SECONDS=60
```

## Planned Mounted Runtime Config — Not Yet Implemented

The following mounted-file model describes a possible future generic PEP
configuration interface.

**The current reference runtime does not read these files and does not honor
environment variables pointing to them.**

They must therefore not be treated as active trust inputs or deployment
controls for the current reference PEP.

A future implementation may introduce a layout such as:

```text
/etc/oxdeai/
  trusted-keysets.json
  policy.json
  action-map.json
  runtime.json
```

Possible responsibilities would include:

* `trusted-keysets.json` — externally managed Ed25519 verification keys;
* `policy.json` — externally managed action policy;
* `action-map.json` — mapping protected actions to selected platform adapters;
* `runtime.json` — optional runtime settings.

The exact schemas, precedence rules, validation behavior, and trust semantics
for these files are not part of the current executable contract and must not be
inferred from this reference documentation.

The current executable source of truth remains `src/config.ts` together with
the current policy and authorization implementation.

## Replay Persistence

Replay protection prevents a consumed AuthorizationV1 from being used a second time. The PEP delegates replay state to a pluggable backend.

### Backend options

| Backend | Scope | Restart-safe | Multi-replica | Use case |
|---------|-------|-------------|---------------|----------|
| `memory` | single process | no | no | local dev, single-process PoC |
| `redis` | shared | yes | yes | multi-replica or restart-safe deployment |
| `mounted` | single node | yes | no | single-node LGF bench without Redis (not yet implemented) |

The replay backend is an implementation detail behind the PEP. It does not affect the authorization protocol or the decision semantics.

### Live Redis test coverage

This repository includes a live Redis integration test for the replay backend:

```bash
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml up -d redis
REDIS_URL=redis://127.0.0.1:6379 pnpm -C examples/lgf-frappe-pep test:redis
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml down
```

This test runs the real PEP server against a real Redis service and a fake target-platform adapter.

It proves:

* first execution claims the replay key and executes once
* second submission of the same `AuthorizationV1` is denied with `AUTH_REPLAY`
* replay keys use the configured prefix
* replay keys have positive TTL
* Redis outage fails closed with `REPLAY_STORE_UNAVAILABLE`

It does **not** require live Frappe, LGF-managed infrastructure, or deployment secrets.

This same replay integration test now also runs in CI in the `pep-redis-replay` job in [.github/workflows/ci.yml](/home/ange/OxDeAI-core/.github/workflows/ci.yml:93) against a real `redis:7-alpine` service.

The CI job keeps the same contract as the local Docker Compose flow:

* no live Frappe dependency
* no LGF infrastructure dependency
* no secrets required
* replay denial remains validated with `AUTH_REPLAY`
* outage denial remains validated with `REPLAY_STORE_UNAVAILABLE`

## Graceful Shutdown

The PEP runtime registers `SIGTERM` and `SIGINT` handlers in the main process entrypoint.

On shutdown request it:

* logs a structured shutdown event with mode, replay store type, port, signal, and shutdown status
* stops accepting new HTTP connections
* closes active connections through the existing server shutdown path
* disconnects owned Redis clients on the Redis replay path
* exits `0` on successful shutdown
* exits non-zero if shutdown fails unexpectedly

Shutdown is idempotent. Multiple signals do not double-run cleanup or double-disconnect Redis.

This is operational hardening for sidecar deployment. It does not change authorization, replay, or policy semantics.

### Configuration

Memory (default):

```env
REPLAY_STORE=memory
```

Redis:

```env
REPLAY_STORE=redis
REDIS_URL=redis://redis:6379
REPLAY_KEY_PREFIX=oxdeai:pep:replay
REPLAY_TTL_SKEW_SECONDS=60
```

When `REPLAY_STORE=redis`, `REDIS_URL` is required. The PEP will fail to start without it.

The PEP creates an ioredis client from `REDIS_URL` on startup and disconnects it on shutdown. The Redis URL may contain credentials (`redis://user:password@host:port`); these are redacted in startup logs.

### Key format

Redis keys use a stable namespaced format:

```text
<REPLAY_KEY_PREFIX>:<issuer>:<audience>:<auth_id>
```

Stored values contain only non-secret metadata (`claimed_at`, `issuer`, `audience`). No signing keys, API credentials, or raw AuthorizationV1 artifacts are stored.

### TTL

Replay keys expire after the authorization validity window plus a configurable safety buffer:

```text
ttl = (expiry - now) + REPLAY_TTL_SKEW_SECONDS
```

Default skew: 60 seconds. Replay entries do not persist forever.

### Constraints

* The PEP must fail closed if a required replay backend is unavailable.
* The replay backend must support atomic check-and-consume to prevent race conditions.
* Redis uses `SET key value NX EX ttl` for atomic single-use claiming.
* The in-memory backend is acceptable only for local dev and single-process PoC scenarios. It loses state on restart.
* Redis or equivalent shared persistence is required for deployments where replay protection must survive restarts or span multiple replicas.

The replay backend choice must not force platform-specific images. All backends are injected through configuration, not compiled into the image.

## Enforce vs Observe Mode

### Enforce mode

`OXDEAI_MODE=enforce`

* Valid AuthorizationV1 with passing verification may execute the target-platform action.
* Invalid AuthorizationV1 must deny. No execution occurs.
* Replayed auth_id must deny. No execution occurs.
* Replay backend unavailable must deny if replay is configured as required.
* Target-platform side effects occur only after all verification steps pass.
* Target-platform credentials are used only in enforce mode.

### Observe mode

`OXDEAI_MODE=observe`

* The PEP evaluates the authorization and logs the decision.
* The PEP does not call the target platform. No side effects occur.
* Useful for integration rollout, config validation, and dry-run testing.
* Observe mode must not be described as protected execution.

The PEP startup log and healthz response always include the active mode.

## Failure Behavior

The PEP fails closed on all error conditions. No execution path exists without valid authorization.

| Condition | Result | Side effect |
|-----------|--------|-------------|
| Invalid AuthorizationV1 (structural) | DENY | none |
| Invalid Ed25519 signature | DENY | none |
| Expired AuthorizationV1 | DENY | none |
| Audience mismatch | DENY | none |
| Issuer mismatch | DENY | none |
| Intent hash mismatch | DENY | none |
| Replay detected (auth_id already consumed) | DENY | none |
| Required replay backend unavailable | DENY | none |
| Target-platform upstream error | no false success | DENY with reason |
| Malformed upstream response | no false success | DENY with reason |
| Missing authorization on /execute | DENY | none |
| Unsupported protected action | DENY | none |
| Policy-denied action | DENY (at /authorize) | no authorization issued |

Internal error details are logged to the container log only. They are never returned to the HTTP caller.

## Pull and Run Examples

### Pull the Frappe PoC image

```bash
docker pull ghcr.io/oxdeai/oxdeai-pep-frappe:lgf-poc
```

### Run the Frappe PoC image

```bash
docker run --rm -p 3099:3000 \
  --env-file <runtime-env-file> \
  -e "SIGNING_PRIVATE_KEY_PEM=<runtime-injected-private-key>" \
  ghcr.io/oxdeai/oxdeai-pep-frappe:lgf-poc
```

Replace `<runtime-env-file>` with the path to your deployment env file (outside the repo tree). Replace `<runtime-injected-private-key>` with the Ed25519 private key PEM.

### Health check

```bash
curl -s http://localhost:3099/healthz | jq .
```

### Authorize

```bash
curl -s -X POST http://localhost:3099/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "source_bench": "openwebui-dev",
    "target_bench": "frappe",
    "agent_or_tool_context": "erp-assistant",
    "user_identity": "user@example.com",
    "session_id": "example-session",
    "action": {
      "type": "EXECUTE",
      "tool": "frappe.helpdesk.create_ticket",
      "params": {
        "subject": "Example ticket",
        "description": "Example description.",
        "priority": "Low"
      }
    }
  }' | jq '{ ok, decision, mode, auth_id, intent_hash, policy_id }'
```

### Execute

```bash
# Use the authorization artifact from the /authorize response.
# Do not paste raw authorization artifacts into public locations.
curl -s -X POST http://localhost:3099/execute \
  -H 'Content-Type: application/json' \
  -d '{
    "envelope": { ... },
    "authorization": { ... }
  }' | jq '{ ok, decision, mode, frappe_ticket_id }'
```

## Scope and Limitations

This documentation covers the sidecar deployment model validated by the LGF/Frappe Helpdesk PoC.

### Validated

* One protected action: `frappe.helpdesk.create_ticket`
* AuthorizationV1 issuance and verification
* Intent hash binding
* Replay protection (in-memory and Redis backends)
* Enforce and observe modes
* Fail-closed behavior on upstream errors
* Frappe numeric ticket ID normalization

### Not validated or claimed

* Full Frappe governance
* Full ERPNext governance
* Production readiness
* Mounted-volume replay persistence
* Kubernetes manifests or Helm charts
* LGF production automation
* Multi-action policy evaluation
* Issuer/verifier separation
* Key rotation
* Generic PEP image (not yet published)
* Non-Frappe target platforms (Nextcloud, OpenProject, etc.)

## Related

* #141 - PoC definition (LGF/Frappe boundary exploration)
* #142 - Boundary contract documentation
* #143 - PEP container implementation
* #148 - Pluggable replay persistence
* #149 - LGF Platform Layer sidecar documentation (this document)
