# Changelog

All notable changes to `@oxdeai/openclaw` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

> This file starts at 2.0.0. Versions 1.0.0 and 1.0.1 were published without a
> changelog; the 2.0.0 entry below reconstructs the delta from the published
> `@oxdeai/openclaw@1.0.1` npm artifact.

---

## [2.0.0] - 2026-09-25

**Baseline for this entry:** the published `@oxdeai/openclaw@1.0.1` npm artifact
(2026-03-19). The version was set to `1.0.1` at `8797931`; the packed
`dist/types.d.ts` of that artifact is used as the authoritative comparison surface.

> ⚠️ The published `1.0.1` artifact declares `"@oxdeai/core": "workspace:*"` and
> `"@oxdeai/guard": "workspace:*"`, so **it cannot be installed standalone from the
> public registry**. That is a defect of the historical release process, not of the
> source. See **Packaging** below.

### Breaking

- **Requires `@oxdeai/core` 2.0 and `@oxdeai/guard` 2.0.** Both dependencies move
  to a major line with breaking API and runtime-semantic changes; see those packages'
  changelogs.
- **`getState` now returns versioned state** — `{ state, version }` rather than
  `State`. A store returning no version fails closed.
- **`setState` is now compare-and-set** — `(state, expectedVersion) => boolean`
  rather than `(state) => void`. Returning `false` blocks execution.
- **`strict?: boolean` removed from `OpenClawGuardConfig`.** The field was declared but never
  read, and never reached the guard. It was inherited from the `@oxdeai/guard@1.0.1`
  config shape, where it was also inert. Nothing replaces it — it was not a security
  control, and presenting it as one was the problem.
- **`expectedAudience` is enforced by the guard.** The adapter derives it from
  `config.agentId`, so no caller change is required, but an authorization whose
  audience does not match that agent identity now fails closed.

### Added

Configuration forwarded through to `OxDeAIGuard`. These were supported by the guard
but unreachable through this adapter:

- **`replayStore`** — durable `auth_id` / `delegation_id` tracking. Without it the
  guard creates a per-instance in-memory store, so in a horizontally scaled or
  restart-prone deployment replay protection did not hold across processes and the
  adapter offered no way to fix that.
- **`onBoundaryEvent`** — the guard-boundary audit stream. It is disjoint from
  `onDecision`, so replay rejections, CAS conflicts and hash-binding failures
  previously produced **no audit record at all** for adapter consumers.
- **`computeStateHash`** — custom live-state hash strategy, required when
  authorizations are issued by an external provider whose state canonicalization
  differs from the core engine's.
- `trustedKeySets` is exposed on the adapter config for strict authorization
  verification.

### Trust profile

Unchanged and now documented explicitly in the README: **declared**.

This adapter integrates the lower-level `OxDeAIGuard` boundary. `agent_id` is fixed
by deployment configuration and is not proposer-controlled. Tool identity and
recursion depth are **not** established from a `TrustedExecutionContext`:
`intent.tool` and `intent.depth` are not populated by the default normalization, so
`ToolAmplificationModule` and `RecursionDepthModule` do not constrain this path.

This release makes **no Tier 1 evaluator-input provenance claim**. Deployments
requiring it should establish trusted execution context at an authenticating PEP and
integrate `createSecureGuard` from `@oxdeai/guard` there. A `createSecureGuard`
adapter entry point is tracked as future work; a framework adapter has no
authenticated principal of its own and cannot construct that context honestly.

### Packaging

- **Workspace dependencies now use `workspace:^`**, so the packed artifact declares
  `^2.0.0` ranges instead of the exact pin `workspace:*` resolves to. This fixes
  standalone installation and lets the adapter tolerate a compatible guard or core
  patch without a republish.
- An explicit `files` field is declared. The artifact no longer ships `src/`,
  `tsconfig.json` or compiled test files.
- `prepack` now rebuilds before packing, so a stale `dist/` cannot be published.
- `repository` (with `directory`), `homepage` and `bugs` are declared for npm
  provenance.
- This changelog file was added; the package previously shipped none.
