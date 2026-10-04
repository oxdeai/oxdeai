# Changelog

All notable changes to `@oxdeai/guard` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [2.0.2] - 2026-10-04

Dependency release of `@oxdeai/guard`. It packs against `@oxdeai/core@2.0.1`
(exact dependency). No runtime source, public API or type declaration change
since 2.0.1.

### Security

- Pins `@oxdeai/core@2.0.1`, which fixes replay nonce retention and capacity
  eviction (GHSA-48xw-c298-546r). The guard evaluates with the caller-supplied
  `PolicyEngine`, so the fix applies only when that engine comes from
  `@oxdeai/core@2.0.1`; check with `npm ls @oxdeai/core`.
- In 2.0.1 Core reports replay-capacity exhaustion as `VELOCITY_EXCEEDED`; the
  guard surfaces it unchanged through `OxDeAIDenyError.reasons`.

## [2.0.1] - 2026-09-29

Patch release of `@oxdeai/guard`. It packs against `@oxdeai/core@2.0.0` (exact
dependency) and does not change the public API or type declarations. The only
runtime behavior change since 2.0.0 is the delegation recipient binding below.

### Security

- Delegated execution binds `DelegationV1.delegatee` to the normalized acting
  `intent.agent_id` (#350). A genuinely signed delegation presented by any other
  agent is rejected with `OxDeAIDelegationError` before replay consumption, state
  mutation or execution, and the artifact remains usable by its real delegatee.
  Delegation calls also require a non-empty normalized `agent_id`, including when
  a custom `mapActionToIntent` is configured. `@oxdeai/guard@2.0.0` does not
  perform this check.

### Documentation

- README: the delegation section no longer claims the chain is verified "before
  policy evaluation". The delegation path does not evaluate the `PolicyEngine`;
  the delegation chain and effective delegation scope are its constraints. The
  example now uses `createSecureGuard`, `createTrustedExecutionContext`,
  `trustedDelegationAuthorities` and the required `parentScope`.
- README: the custom mapper example derives identity from the trusted context,
  prices the action from a deployer-controlled table, binds all arguments through
  `metadata_hash`, and executes the same validated arguments it authorized. The
  low-level path documents that `action.context.agent_id` is trusted only when the
  integration sets it from an authenticated source, and that a missing
  `estimatedCost` evaluates at amount `0n`.
- CHANGELOG: corrected the 2.0.0 enforcement-ordering entry below.

---

## [2.0.0] - 2026-09-25

**Baseline for this entry:** the published `@oxdeai/guard@1.0.1` npm artifact
(2026-03-19). The version was set to `1.0.1` at `8797931` and remained so until
`273f3ba`, so the published artifact originates in that range; its packed
`dist/types.d.ts` is used as the authoritative comparison surface.

> ⚠️ `1.0.2` and `1.0.3` appear in this changelog and in Git tags but **were never
> published to npm**. `1.0.1` is the last released artifact, and it is the baseline
> used here. The `guard-v1.0.3` tag is retained as historical record and is not a
> release.
>
> ⚠️ The published `1.0.1` artifact also declares `"@oxdeai/core": "workspace:*"`
> and therefore cannot be installed standalone from the public registry. That is a
> defect of the historical release process, not of the source; see **Packaging**.

### Breaking

- **`getState` now returns versioned state.**
  ```diff
  - getState: () => State | Promise<State>
  + getState: () => VersionedState | Promise<VersionedState>   // { state, version }
  ```
  A store that returns no `version` fails closed before evaluation — the CAS
  invariant cannot be enforced without one.
- **`setState` is now compare-and-set and must report success.**
  ```diff
  - setState: (state: State) => void | Promise<void>
  + setState: (state: State, expectedVersion: StateVersion) => boolean | Promise<boolean>
  ```
  It must atomically verify that the persisted version still equals
  `expectedVersion` before committing. Returning `false` raises
  `OxDeAIConflictError` and blocks execution. An implementation that ignores
  `expectedVersion` and always returns `true` silently removes the protection.
- **`expectedAudience` is required.** Construction throws
  `OxDeAIGuardConfigurationError` when it is absent. There is no default and no
  fallback. It must equal the engine's `authorization_audience`.
- **`trustedKeySets` is required for the verification path.** Construction throws
  when absent or empty. A valid signature from an unconfigured issuer still fails
  closed.
- **`strict?: boolean` was removed from `OxDeAIGuardConfig`.** It had no effect.
- **`beforeExecute` and `GuardDecisionRecord` now carry `AuthorizationV1`** rather
  than the internal `Authorization` shape.

### Added

- **`createSecureGuard`** — the Tier 1 secure entry point. It differs from
  `OxDeAIGuard` in exactly one respect: how the evaluated intent's provenance is
  established. Everything after that — state read, evaluation, verification, replay
  consumption, hash binding, CAS, execution ordering — is the same enforcement body,
  reached by delegation rather than reimplementation.
- **`createTrustedExecutionContext`** / `isTrustedExecutionContext` /
  `TrustedExecutionContext`. The returned context carries a non-enumerable runtime
  brand, so a value deserialized from request JSON is rejected. The brand is
  **misuse resistance, not authentication**: it proves construction happened, not
  that the caller was authorized. `depth` is required and never defaulted.
- **Provenance reconciliation** — `reconcileWithTrustedContext`, `ClaimProvenance`,
  `ProvenanceRecord`, `ReconciliationResult`, `ReconciliationOptions`. Proposer
  claims never override derived premises; a conflict fails closed before evaluation
  with `OxDeAIProvenanceConflictError`, and per-field outcomes (`absent`, `matched`,
  `conflict`, `unverified`) are recorded for audit.
- **Explicit tenancy posture** — `SecureGuardOptions.tenancy` is required and never
  defaulted. A `multi-tenant` deployment whose route did not resolve a `tenantId`
  fails closed rather than evaluating in an ambiguous namespace.
- **`onBoundaryEvent`** — an audit stream for guard-boundary rejections raised
  before `execute()` starts, with `GuardBoundaryStage`, `GuardBoundaryFailure`,
  `GuardBoundaryAuditEvent` and `GuardBoundaryEventHook`. It is **disjoint** from
  `onDecision`: a valid policy DENY is reported to `onDecision` only, every other
  boundary rejection to `onBoundaryEvent` only, and no rejection appears on both.
  A deployment auditing only `onDecision` cannot see attempted identity or tool
  substitutions.
- **Delegation enforcement** — `GuardDelegationInput`, `GuardCallOptions`,
  `OxDeAIDelegationError`. Full chain verification before execution: parent hash
  binding, scope narrowing, expiry ceiling, delegator identity, policy binding and
  signature verification. `parentScope` is required; a missing or malformed scope
  fails closed before chain verification.
- **Pluggable replay store** — `ReplayStore`, `createInMemoryReplayStore`,
  `createRedisReplayStore`. The default in-memory store is single-process only.
  Stores must be fail-closed: throw rather than return a permissive result.
- **Pluggable state-hash strategy** — `computeStateHash`, for authorizations issued
  by a provider whose state canonicalization differs from the core engine's.
- **PEP gateway surface** — `createPepGatewayExecutor`,
  `createPepGatewayHttpServer`, `createHttpUpstreamExecutor`,
  `createProtectedUpstreamHttpServer`, `protectUpstreamExecution`,
  `hasValidInternalExecutorToken`, `INTERNAL_EXECUTOR_TOKEN_HEADER`.
- `defaultNormalizeAction`, `StateVersion`, `VersionedState`, `OxDeAIConflictError`.

### Security hardening

- Execution is gated on an ordered fail-closed sequence: state load → normalize →
  evaluate → require authorization and `nextState` → strict verification →
  `intent_hash` binding → `state_hash` binding → consume `auth_id` → CAS commit →
  `beforeExecute` → `execute()`. A failure before the `auth_id` consume leaves no
  replay entry, state commit or side effect. Consumption is irreversible: a
  failure after it (CAS conflict, `beforeExecute` error, or a failure inside
  `execute()`) leaves the `auth_id` spent, and a failure inside `execute()` does
  not roll back the CAS commit. *(Corrected after release: this entry originally
  listed the `auth_id` consume before verification and claimed no side effects on
  any failure; the ordering above is what 2.0.0 implements.)*
- `intent_hash` is recomputed from the normalized intent and compared with the
  artifact commitment. A canonicalization failure and a computed mismatch are
  treated as the same audit fact.
- `state_hash` is verified against the live execution-time snapshot; absent,
  uncomputable and unequal are all a binding failure.
- CAS commit happens **before** `execute()`, so a concurrent state change blocks the
  side effect rather than being detected after it.
- `auth_id` and `delegation_id` are each consumed with an atomic check-and-set
  before execution, after every verification they depend on; a replay store that
  is unavailable throws and the guard denies. On the delegation path
  `delegation_id` is consumed first, then the parent `auth_id`.
- Authorization verification runs in strict mode with
  `requireSignatureVerification`, bound to `expectedAudience`, `expectedIssuer` and
  `expectedPolicyId`.

### Trust-profile note

`OxDeAIGuard` remains a supported lower-level API and is **not** deprecated. It
carries no Tier 1 evaluator-input provenance guarantee: `agent_id`, `depth` and
`tool` are whatever the caller supplies. Only `createSecureGuard` — or an
integration independently enforcing the same boundary — may claim Tier 1 provenance.

`createSecureGuard` establishes trusted evaluator **inputs** only. It does not make
state or policy authoritative: `getState` / `setState` and the engine's policy
configuration are still supplied by the deployment. An authoritative versioned state
provider is separate work (#197).

### Known scope limits

- The `evaluationTime` passed to the engine is sampled from the process wall clock
  at the evaluation boundary. It is not independently trusted or monotonic;
  reliable PEP-side clock capture remains deferred.
- Guard state CAS protects OxDeAI policy state. It does **not** provide TOCTOU
  safety for mutations of arbitrary external resources inside `execute()`; that
  requires a resource-side atomic version precondition (#253).
- A protected callback that throws after `execute()` has started currently produces
  neither a decision record nor a boundary event (#238).

### Packaging

- `prepack` now rebuilds before packing.
- `repository.directory` is declared for npm provenance.

---

## [1.0.2] - 2026-03-20

### Added

- DelegationV1 enforcement integrated into the PEP boundary.
- Full delegation chain verification before execution: parent hash binding, scope narrowing (tools, max_amount), expiry ceiling, delegator identity, policy binding.
- `GuardDelegationInput` type (`delegation` + `parentAuth`) for child-agent execution path.
- `GuardCallOptions` — optional third argument to the guard function; supports `delegation` for the delegation path.
- `OxDeAIDelegationError` — thrown on any delegation chain violation; `execute` is never called.
- `trustedKeySets` and `requireDelegationSignatureVerification` config options for Ed25519 signature enforcement on delegation artifacts.
- `consumedDelegationIds` config option for replay protection on the delegation path.
- TOCTOU, determinism, and enforcement-boundary test coverage (G-D1–G-D3 property tests).

### Notes

- `setState` is not called on the delegation path — the parent authorization's state is authoritative.
- Protocol stack alignment: `@oxdeai/core@1.5.0`.

---

## [1.0.1] - 2026-03-16

### Changed

- Apache-2.0 license added to package metadata.
- External documentation links changed from relative to absolute GitHub URLs.
- Protocol stack alignment with `@oxdeai/core@1.5.0`.

---

## [1.0.0] - 2026-03-15

### Added

- Initial release of `@oxdeai/guard` — universal Policy Enforcement Point (PEP) for the OxDeAI ecosystem.
- `OxDeAIGuard` factory: runtime-agnostic guard function enforcing authorization before any tool execution.
- Fail-closed security invariants: DENY throws `OxDeAIDenyError`; missing/invalid authorization throws `OxDeAIAuthorizationError`; normalization failure throws `OxDeAINormalizationError`.
- Default action normalizer (`defaultNormalizeAction`) mapping `ProposedAction` fields to `Intent`.
- `mapActionToIntent` hook for custom domain-specific intent mapping.
- `beforeExecute` and `onDecision` lifecycle hooks for auditing and observability.
- `strict` mode flag for hard failure on missing optional fields.
- Protocol stack alignment: `@oxdeai/core@1.3.x`.
