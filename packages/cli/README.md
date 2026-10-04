# @oxdeai/cli
CLI for the OxDeAI execution-time authorization protocol.
Runs local verification and artifact inspection; no valid authorization means execution should not proceed.

`@oxdeai/cli` is a thin Node.js wrapper around `@oxdeai/core` verification and local state workflows. It is framework-agnostic and intended for local policy operations, artifact inspection, and deterministic verification.

## Version and registry status

This repository's `packages/cli/package.json` version is `0.3.1`, which pins
`@oxdeai/core@2.0.1` (see [`CHANGELOG.md`](./CHANGELOG.md)). Since `0.3.0` the
CLI enforces a valid `engine_secret` on the validation path and requires an
explicit `--trusted-keyset` (or `--mode best-effort`) on strict `verify` entry
points; `0.2.4` and earlier do neither. Commands below describe the `0.3.x`
behavior.

## Quickstart

### End users

Install the CLI:

```bash
npm install -g @oxdeai/cli
```

This installs the latest published version. To run the behavior in this
repository, use the local monorepo workflow instead (see "Local monorepo
contributors").

`build`, `verify auth`, and `launch dry-run` require a trusted engine secret:

```bash
export OXDEAI_ENGINE_SECRET='test-secret-must-be-at-least-32-chars!!'
```

Basic commands:

```bash
oxdeai --help
oxdeai --version
oxdeai verify snap
oxdeai verify envelope
oxdeai build snapshot
oxdeai verify all
oxdeai inspect snapshot --file .oxdeai/snapshot.bin
oxdeai doctor
```

### Local monorepo contributors

Build the package from the repo root:

```bash
pnpm -C packages/cli build
```

Run the CLI from the monorepo root:

```bash
pnpm oxdeai --help
pnpm oxdeai --version
pnpm oxdeai verify snap --file packages/cli/.oxdeai/snapshot.bin --json
```

Run it from inside `packages/cli`:

```bash
pnpm build
node dist/main.js --help
node dist/main.js verify snap --file .oxdeai/snapshot.bin --json
```

For a local global-style workflow:

```bash
cd packages/cli
npm link
oxdeai --help
```

## Command Surface

- `oxdeai build`
- `oxdeai verify`
- `oxdeai inspect`
- `oxdeai doctor`
- `oxdeai paths`
- `oxdeai auth`
- `oxdeai examples`
- `oxdeai replay`

Legacy helper commands are still available (`init`, `launch`, `state`, `audit`, `verify-audit`, `make-envelope`, `verify-envelope`, `snapshot-hash`) for local development workflows.

## Core Commands

### build

Builds a canonical snapshot verification payload from state. Requires
`OXDEAI_ENGINE_SECRET` (see Quickstart).

```bash
oxdeai build snapshot
oxdeai build --state .oxdeai/state.json --out .oxdeai/snapshot.bin --json
```

### verify

Verifies one artifact kind at a time:

- `snapshot`
- `audit`
- `envelope`
- `authorization`

Examples:

```bash
oxdeai verify snap
oxdeai verify audit
oxdeai verify envelope
oxdeai verify auth --file authorization.json --expected-issuer oxdeai://issuer --expected-audience rp://tool-gateway --json
oxdeai verify --kind snapshot --file snapshot.bin --json
oxdeai verify --kind audit --file audit.ndjson --mode strict --json
oxdeai verify --kind envelope --file envelope.bin --trusted-keyset keyset.json --require-signature --json
oxdeai verify --kind authorization --file authorization.json --expected-issuer oxdeai://issuer --expected-audience rp://tool-gateway --json
```

`verify auth` does not assume a default file. Pass `--file <authorization.json>` explicitly.

### inspect

Inspects local protocol artifacts without changing them.

```bash
oxdeai inspect snapshot --file .oxdeai/snapshot.bin
oxdeai inspect audit --file .oxdeai/audit.ndjson
oxdeai inspect envelope --file .oxdeai/envelope.bin
oxdeai inspect auth --file authorization.json
```

### verify all

Runs snapshot, audit, and envelope verification together using local defaults.

```bash
oxdeai verify all
```

### auth

Creates and inspects authorization artifacts for local relying-party tests.
`auth create` requires `OXDEAI_ENGINE_SECRET`; `auth inspect` does not.

```bash
oxdeai auth create PROVISION 100 us-east-1 --agent agent-1 --nonce 1 --out authorization.json --json
oxdeai auth inspect --file authorization.json
```

### doctor and paths

Shows local path defaults and checks whether expected files exist.

```bash
oxdeai paths
oxdeai doctor
```

### examples init

Writes a starter local state file and clears the audit log.

```bash
oxdeai examples init
```

### launch dry-run

Evaluates an action without mutating local state or audit files. Requires
`OXDEAI_ENGINE_SECRET`.

```bash
oxdeai launch dry-run PROVISION 100 us-east-1 --agent agent-1 --nonce 1 --json
```

### replay

Protocol-aware stub. The current implementation (`packages/cli/src/main.ts`)
reports itself as `@oxdeai/cli v0.2.x` in this message; that string has not
been updated to match this package's own `package.json` version (`0.3.1`). It returns a clear unsupported response and points users to
deterministic audit verification (`verify --kind audit`).

## Output and Exit Codes

- Human-readable output by default
- Machine-readable output with `--json`

Exit codes:

- `0` = verification `ok` / command success
- `1` = verification `invalid` or malformed input/runtime failure
- `2` = usage/flag parsing error
- `3` = verification `inconclusive`

## Troubleshooting

- If `oxdeai: command not found`, the package is not installed or linked globally yet. Use `npm install -g @oxdeai/cli` or `npm link` from `packages/cli`.
- In the monorepo, prefer `pnpm oxdeai ...` from the repo root or `node dist/main.js ...` from `packages/cli`. `pnpm exec oxdeai` is not the primary local workflow here.
- Default local file paths are `.oxdeai/state.json` and `.oxdeai/audit.ndjson`. Pass `--state`, `--audit`, `--file`, or `--out` explicitly if you are working outside that layout.

## PDP / PEP Boundary

The CLI does not replace a runtime PEP. It is intended for deterministic protocol artifact handling, validation, and local operational tooling around the OxDeAI PDP/PEP model.
