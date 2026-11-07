# Changelog

All notable changes to `@oxdeai/guard` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [Unreleased]

### Security

- INVREG-F01/F02: `createPepGatewayExecutor` now takes one deep-frozen
  plain-data snapshot of the request before any security decision. Action
  hashing, authorization verification, intent binding, replay consumption,
  upstream dispatch and the response body all read only that snapshot.
  Previously the executor re-read the caller's live request object: a plain
  mutation during the awaited replay consume changed the action sent upstream
  after its hash was verified, and an accessor or Proxy on `auth_id` let one
  single-use signed authorization be consumed under different identifiers and
  executed more than once. Request input that is not plain data (Proxy,
  accessor properties, class instances, `Date`, `Map`, `Buffer`/typed arrays,
  functions, symbol keys, sparse arrays, cycles, and objects or arrays created
  in another realm such as a `vm` context) is now denied with
  `INVALID_REQUEST_INPUT:<path>: <reason>` before replay consumption; such
  values were previously hashed as their enumerable own keys while the original
  value was dispatched. The upstream executor receives a fresh mutable copy of
  the verified snapshot (see GW-COMP-01), never the caller's object.
  JSON-decoded input (the HTTP gateway) is unaffected, and the action hash and
  signed payload formats are unchanged.
- INVREG-F05: `trustedAuthorizationAuthorities` is validated and copied at
  executor construction; later mutation of the caller's array or entries no
  longer widens issuer-policy authority. A malformed entry (not a plain
  `{ issuer, policyId }` object with non-empty strings) now fails construction
  instead of silently never matching. `expectedAudience`,
  `internalExecutorToken` and `executeUpstream` are likewise read once at
  construction. To change authorities, construct a new executor. In-place
  `trustedKeySets` rotation and replay-store state remain live.
- RR-01: replay-store answers are now checked as strict booleans at every
  consume site: the `OxDeAIGuard` / `createSecureGuard` direct path, both
  delegation-path sites (`consumeDelegationId` and the parent
  `consumeAuthId`), and `createPepGatewayExecutor`. Only `true` lets execution
  proceed, and `false` is a replay denial. Previously any truthy value
  (`"false"`, `"true"`, `1`, `"OK"`, `{}`, `[]`) counted as a successful
  first consume, so a store violating the `Promise<boolean>` contract let one
  authorization execute repeatedly. Any non-boolean answer is now denied
  under the existing `REPLAY_STORE_UNAVAILABLE` category (gateway reason
  `REPLAY_STORE_UNAVAILABLE:INVALID_RESULT`). No new public failure code was
  added. **Compatibility:** a custom store that resolves `1` / `"OK"` instead
  of `true` now denies every request. Return a boolean (the built-in
  in-memory and Redis stores already do). A denial does not prove that the id
  was left unconsumed: a store may record the id before answering. The replay
  store call still has no timeout; a consume that never settles leaves the
  request pending and never executes.
- GW-COMP-01: `createPepGatewayExecutor` again calls `executeUpstream` with the
  options object as `this`, as before INVREG-F05, so method-style executors
  that use `this` work again. The function is still captured at construction:
  reassigning `options.executeUpstream` afterwards has no effect. The executor
  now receives its own mutable deep copy of the verified action,
  value-identical to the hashed action. It may modify that copy, as before
  INVREG-F01, without affecting the response binding or the caller's object.
  The copy is made before replay consumption, so it cannot burn an
  authorization.
- F4-AUD-01: `createSecureGuard` now captures and validates its configuration
  at construction. It previously rebuilt the shared body from the caller's
  live `config` on every call, so mutating that object after construction
  (pushing a pair into `trustedDelegationSigners`, setting `revocation` or
  `delegationRevocationProvider` to `undefined`, replacing `provider.check`)
  widened signer authority or disabled revocation enforcement. Signer and
  parent authority lists are now frozen copies, the F4-C provider's `check` is
  bound at construction, the SignedKRLV1 configuration is resolved and frozen
  once, and hooks and other options are fixed at their construction values.
  Provider and store *state* is still read per call, so revocation updates
  take effect; in-place mutation of the retained `trustedKeySets` array (key
  rotation) is still observed, reassigning `config.trustedKeySets` is not.
  Invalid configuration now fails at `createSecureGuard()` instead of on the
  first call.
- REV-R1 / REV-R2: the construction-time capture reads every
  `OxDeAIGuardConfig` option by name, once, through ordinary property access.
  An earlier form of the F4-AUD-01 capture copied the config with
  `{ ...config }`, which keeps only own enumerable properties. With it, a
  `replayProtection: {mode:"shared", store}` or legacy `replayStore` supplied
  as an inherited, non-enumerable, getter or `Proxy`-provided property was
  dropped, and the guard silently fell back to a process-local store
  (cross-instance replay accepted). `requireExplicitReplayProtection` and
  replay-conflict detection were ignored in the same way, and so were
  `trustedDelegationSigners`, `delegationRevocationProvider` /
  `requireDelegationRevocation` and `revocation`. The same forms were
  already not enforced before F4-AUD-01, because the per-call shared body was
  built with the same spread. Nested security members (`replayProtection.mode`
  and `.store`, signer and authority entries, provider `check`, SignedKRLV1
  members) are now read once each. A throwing getter or `Proxy` trap fails
  construction with `OxDeAIGuardConfigurationError`. The resolved replay
  store's methods are bound at construction; its identity and state are
  unchanged. Function-valued options run with the deployer's config object as
  `this`.
- RV-01 / RV-02: the capture's per-option handlers are looked up in a `Map`.
  An earlier form looked them up on an ordinary object, so a function on a
  polluted `Object.prototype` was called with the deployer's value and its
  result adopted (for example, a substituted `trustedKeySets` or
  `replayStore`). `createSecureGuard` now refuses to construct when
  `Object.prototype` (or, for the names read there, `Array.prototype` /
  `Function.prototype`) carries a property named after an option or a member
  the capture reads. All captured data is held as own properties, so later
  pollution cannot change the captured configuration. (It can still reach
  values returned by callbacks at request time; see IR-03 below.) The replay store's methods are read once, before
  the replay posture is validated, and a getter that throws is now an
  `OxDeAIGuardConfigurationError` in both `shared` and legacy modes. That
  includes a legacy store, which previously failed only on the first call.
- F4-AUD-03 (`@oxdeai/core`, reached through the guard delegation path):
  delegation scope narrowing used `parent.tools.includes(t)` per child tool,
  O(N × M), before the delegation signature is checked and on caller-supplied
  `parentScope`. It now uses a `Set` (O(N + M) expected) with identical
  results, violation codes and messages. Measured on Node 24: a ≈1 MiB
  pathological input (N = 40 000, M = 80 000) blocked the event loop for
  ≈6.6 s before and ≈19 ms after. The guard still does not bound input size;
  enforce request-size limits at the transport.
- IR-01: the RV-01 prototype-pollution check ran once, before the
  configuration was read. A deployer getter or `Proxy` trap run during that
  read could pollute `Object.prototype` after the check, and later reads of an
  omitted option then inherited the polluted value. For example, a
  `replayStore` that always answers `true` made one authorization execute
  twice, and a polluted ACTIVE `delegationRevocationProvider` satisfied
  `requireDelegationRevocation`. The check now runs again after the last
  option is read and once more when `createSecureGuard` construction
  completes, so such pollution fails construction with
  `OxDeAIGuardConfigurationError`.
- IR-02 (`@oxdeai/core`, follow-up to F4-AUD-03): the scope-narrowing `Set`
  was built with `new Set(parent.tools)`, which iterates through
  `Symbol.iterator`, while scope validation and the former `includes` read by
  index. A `parentScope.tools` array with a custom own iterator could yield a
  tool held at no index and make it count as authorized (`ok: true` where the
  baseline gives `DELEGATION_SCOPE_VIOLATION`). The `Set` is now filled by
  index, which restores baseline results for these inputs and stays linear.
  Not reachable through the guard: `snapshotPlainData` rejects arrays with
  extra own properties. Only direct callers of `verifyDelegationChain` that
  pass live objects were affected.
- **IR-03 — Partial hardening:** a function on `Object.prototype.then` or
  `Array.prototype.then` is called by promise resolution whenever a promise
  settles with a plain object
  or array, and decides what it settles with. It could turn an F4-C `REVOKED`
  answer into `ACTIVE`, a denying `getState()` state into a permissive one, or
  the current SignedKRLV1 list into an older, validly signed one, and the
  request executed. `getState()`, the F4-C `check()` and the SignedKRLV1
  `provider()` results are now obtained without promise resolution when they
  are plain values. Genuine promises are awaited. A `then` on either prototype
  before the call, right after it returns, or after its promise settles is
  refused: `getState` with stage `STATE_LOAD` / `UNCLASSIFIED`, F4-C with
  `DELEGATION_REVOCATION_UNAVAILABLE`, KRL with
  `REVOCATION_STATE_UNAVAILABLE`, always before replay consumption and
  `execute()`. Revocation denials are now prototype-less objects, so they
  cannot be swapped for "nothing revoked" on the way through the guard. No
  public type or failure code changed. **Compatibility:** any `then` on
  `Object.prototype` / `Array.prototype`, including a non-callable one, now
  denies these requests. **Limitation:** in-process code that installs a
  `then` and removes it again while an `async` callback is pending after an
  internal `await` is not detected. The substitution happens inside the
  callback's own promise, before the guard sees the value. This requires
  arbitrary code execution in the process and is outside the threat model; a
  `todo` test records it (README "Callback results and inherited `then`").

- F4-C: adds opt-in delegation revocation enforcement to `OxDeAIGuard`
  through `delegationRevocationProvider` and
  `requireDelegationRevocation`. A verified delegation must receive an
  explicit `ACTIVE` result before replay consumption and execution.
  `REVOKED` denies with `DELEGATION_REVOKED`; unavailable or indeterminate
  revocation state denies with `DELEGATION_REVOCATION_UNAVAILABLE`.
  Missing required providers and malformed configuration fail closed.
  Direct authorization and the signed `DelegationV1` format are unchanged.
  The check is not atomic with external execution and does not cancel
  already-started operations.

- F4-1/F4-2: new opt-in `trustedDelegationSigners: DelegationAuthority[]` option
  enforces delegation signer authority on the delegation path by forwarding it to
  core `verifyDelegationChain`. When configured, a delegation whose
  `(delegator, issuer)` pair is not listed is rejected (`OxDeAIDelegationError`,
  core `DELEGATION_SIGNER_NOT_AUTHORIZED`) before replay consumption and
  execution; `[]` denies every delegation; a malformed value fails at
  construction. Behavior without the option is unchanged: signer authority is
  not enforced. `trustedDelegationAuthorities` keeps its meaning (parent
  `(issuer, policyId)` authority).
- F4-R8-01 (supersedes F4-R6-02): the delegation path now takes one immutable
  plain-data snapshot of `opts.delegation` before verification, and signature
  verification, scope enforcement, action binding and replay consumption all
  read only that snapshot. Previously an accessor or Proxy on the caller's
  in-process object could show the signed value to verification and a
  different value to enforcement or consumption, allowing execution above the
  signed `max_amount` and repeated execution of one signed delegation.
  Inputs outside the plain-data model (Proxy, getter, class instance, cycle,
  non-enumerable or symbol property) are now rejected with
  `DELEGATION_INPUT_INVALID` before any replay state is consumed. Plain inputs
  behave as before. `opts.delegation` is also read only once per call.
- F4-R8-04: the delegation path now rejects a normalized `intent.amount` that is
  not a non-negative `bigint` (`OxDeAINormalizationError`,
  `NORMALIZATION_FAILURE`), matching the engine path's `INTENT_AMOUNT_INVALID`.
  Previously a custom `mapActionToIntent` returning a negative amount passed
  every `max_amount` comparison and executed.
- F4-R6-06/C9 (Guard side): `parentScope` validation now rejects NaN, Infinity,
  fractional and negative `max_actions` / `max_depth`, negative `max_amount`
  and non-string `tools` entries (`DELEGATION_INPUT_INVALID`), consistent with
  core's child-scope rules. Valid ceilings, including zero, are unchanged.

### Fixed

- AUD-OBS-02: `createSecureGuard` combined with `replayProtection` failed every
  call with "Ambiguous replay configuration", because the resolved store was
  forwarded alongside the caller's `replayProtection`. The secure path now
  forwards only the store it resolved at construction: `process-local` uses
  one in-memory store for the secure guard's lifetime, `shared` uses the
  configured store, and a legacy `replayStore` is still honored. Conflicting
  or invalid replay configuration is still rejected at construction; strict
  mode is unchanged.

### Documentation

- README: secure-guard configuration capture (option-by-option table),
  provider identity versus provider state, replay modes on the secure path,
  `parentScope` provenance (not a signed claim), and transport-level input-size
  responsibility.
- README: replay-store result contract (only `true` proceeds; `false` is a
  replay; anything else is `REPLAY_STORE_UNAVAILABLE`), callback results and
  inherited `then` (IR-03) with its supported trust boundary, IR-01, and an
  "In-process JavaScript compromise" known limit. Corrected the statement
  that pollution after construction cannot affect the guard: it does not
  change the captured configuration, but callback results are a separate
  surface (IR-03).

## [2.0.3] - 2026-10-19

### Security

- Dependency security release. Pins @oxdeai/core@2.0.2 (GHSA-7pwh-fv57-77jg). No guard runtime source or public API change.

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
