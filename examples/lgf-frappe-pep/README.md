# OxDeAI PEP - LGF Frappe Helpdesk PoC

Minimal OxDeAI Policy Enforcement Point for the LGF-managed Frappe Helpdesk PoC.

Protected action: `frappe.helpdesk.create_ticket`

Core invariant: **No valid authorization → no execution path.**

## PEP vs adapter boundary

The runtime now has an explicit platform adapter boundary.

PEP owns:

* authorization verification
* intent hash binding
* replay protection
* policy enforcement
* fail-closed execution gating
* observe/enforce behavior
* health and graceful shutdown behavior

Adapter owns:

* target-platform API call
* target-platform request formatting
* target-platform response parsing
* target-platform-specific side effects
* target-platform runtime configuration

Current adapter:

```text
Frappe Helpdesk
```

Current limitation: this is a first adapter-boundary extraction. It is not yet a dynamic adapter registry or plugin system. The generic sidecar image still packages the current example runtime, and additional platform adapters remain future work.

## Endpoints

* `GET /healthz` - container health
* `POST /authorize` - evaluate policy, issue AuthorizationV1 for allowed actions
* `POST /execute` - verify AuthorizationV1, call Frappe if valid (enforce mode only)

## Graceful shutdown

The runtime now installs explicit `SIGTERM` and `SIGINT` handlers.

On shutdown request it:

* logs a structured, non-secret shutdown event
* stops accepting new HTTP connections
* closes active HTTP connections through the existing `server.shutdown()` path
* disconnects an owned Redis replay client when `REPLAY_STORE=redis`
* exits cleanly on successful shutdown

This is operational hardening for the sidecar runtime. It does not change authorization semantics.

## Quick start

See [LIVE_VALIDATION.md](LIVE_VALIDATION.md) for local build, run, and validation instructions.

## Generic sidecar image

This repository now packages the runtime as a generic-sidecar OCI image using:

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

Local run in memory replay mode:

```bash
SIGNING_PRIVATE_KEY_PEM="$(node -e "const { generateKeyPairSync } = require('node:crypto'); const { privateKey } = generateKeyPairSync('ed25519'); process.stdout.write(privateKey.export({ type: 'pkcs8', format: 'pem' }));")"

docker run --rm -p 8080:3000 \
  -e OXDEAI_MODE=observe \
  -e EXPECTED_AUDIENCE=pep-sidecar.local \
  -e FRAPPE_BASE_URL=https://example.invalid \
  -e REPLAY_STORE=memory \
  -e SIGNING_PRIVATE_KEY_PEM="$SIGNING_PRIVATE_KEY_PEM" \
  -e PORT=3000 \
  oxdeai-pep-sidecar:local
```

Health check:

```bash
curl -fsS http://127.0.0.1:8080/healthz
```

Redis replay mode is also runtime-configured:

```bash
docker run --rm -p 8080:3000 \
  -e OXDEAI_MODE=observe \
  -e EXPECTED_AUDIENCE=pep-sidecar.local \
  -e FRAPPE_BASE_URL=https://example.invalid \
  -e REPLAY_STORE=redis \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  -e SIGNING_PRIVATE_KEY_PEM="$SIGNING_PRIVATE_KEY_PEM" \
  oxdeai-pep-sidecar:local
```

GHCR publish commands are prepared but not run automatically:

```bash
docker tag oxdeai-pep-sidecar:local ghcr.io/oxdeai/oxdeai-pep-sidecar:lgf-sidecar-poc
docker push ghcr.io/oxdeai/oxdeai-pep-sidecar:lgf-sidecar-poc
docker pull ghcr.io/oxdeai/oxdeai-pep-sidecar:lgf-sidecar-poc
```

Published image pull-test command:

```bash
docker pull ghcr.io/oxdeai/oxdeai-pep-sidecar:lgf-sidecar-poc
```

Published image health result:

```json
{"ok":true,"status":"healthy","mode":"observe"}
```

Current limitation: this is the first generic-sidecar packaging step. The packaged runtime still comes from the `examples/lgf-frappe-pep` implementation source and still expects Frappe-oriented adapter configuration such as `FRAPPE_BASE_URL`. No live Frappe credentials are baked into the image, but a fuller extraction of platform adapter configuration remains future work.

## Replay-store result contract

The PEP treats the replay store's answer as a strict boolean (RR-01):

* only the literal boolean `true` (first consumption) permits execution
* boolean `false` is a replay and is denied with `AUTH_REPLAY`
* any other answer (`"OK"`, `"false"`, `1`, `{}`, `null`, `undefined`, ...) is a replay-store failure and is denied with `REPLAY_STORE_UNAVAILABLE`, the same as a store that throws

The target-platform adapter is never called on a denial. A custom store must return a boolean; the built-in memory and Redis stores do. `test/replay-strict-result.test.ts` covers each value.

## Live Redis replay integration test

This example includes a live Redis integration test for the PEP replay persistence path.

What it proves:

* first execution succeeds once with `REPLAY_STORE=redis`
* replayed `AuthorizationV1` is denied with `AUTH_REPLAY`
* the target-platform adapter is not called on replay
* the Redis replay key uses the configured prefix
* the Redis replay key has a positive bounded TTL
* Redis outage fails closed with `REPLAY_STORE_UNAVAILABLE`

What it does **not** require:

* live Frappe
* LGF infrastructure
* API keys or secrets
* signing-key files on disk

The test uses the real PEP server plus a fake Frappe adapter that counts side effects.

Run locally:

```bash
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml up -d redis
REDIS_URL=redis://127.0.0.1:6379 pnpm -C examples/lgf-frappe-pep test:redis
docker compose -f examples/lgf-frappe-pep/docker-compose.redis.yml down
```

The replay backend is one implementation detail behind the PEP boundary. Redis here is used only to validate replay persistence behavior.

CI now runs this same test in the `pep-redis-replay` job in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) against a real `redis:7-alpine` service.

That CI job:

* uses a real Redis service, not mocks
* runs the existing `pnpm --filter @oxdeai/example-lgf-frappe-pep test:redis` command
* does not require live Frappe
* does not require LGF infrastructure
* does not require secrets

## LGF deployment

See [LGF_DEPLOYMENT.md](LGF_DEPLOYMENT.md) for the LGF Platform Layer sidecar deployment model, responsibility boundaries, runtime configuration contract, and failure behavior.

## Related issues

* #141 - PoC definition
* #142 - Boundary contract documentation
* #143 - PEP container implementation
* #148 - Pluggable replay persistence
* #149 - LGF Platform Layer sidecar documentation
