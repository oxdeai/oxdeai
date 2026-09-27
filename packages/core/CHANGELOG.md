# Changelog

All notable changes to `@oxdeai/core` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [2.0.0] - 2026-09-25

**Baseline for this entry:** the published `@oxdeai/core@1.7.0` npm artifact
(2026-04-01). Its packed public surface matches the source at tag `core-v1.7.0`
(`409ff44`), so that commit is used as the provable comparison point. Entries below
describe the consumer-visible delta between that artifact and the current candidate.

> ⚠️ `1.7.0` was published and then further modified on `main` without a version
> bump, so the version number `1.7.0` no longer uniquely identifies an artifact.
> `2.0.0` re-establishes that guarantee. Nothing between the published `1.7.0` and
> this release should be treated as a released version.

### Breaking

- **`evaluationTime` is now a required argument on every evaluation entry point.**
  There is no implicit wall-clock fallback and no derivation from `intent.timestamp`.
  ```diff
  - engine.evaluate(intent, state)
  + engine.evaluate(intent, state, evaluationTime)

  - engine.evaluatePure(intent, state, opts?)
  + engine.evaluatePure(intent, state, evaluationTime, opts?)

  - engine.simulateSequence(intents, opts?)
  + engine.simulateSequence(intents, evaluationTime, opts?)
  ```
  Note that `opts` moved from the third to the fourth positional parameter on
  `evaluatePure`, and from the second to the third on `simulateSequence`. A call
  site that passes `opts` in the old position now passes it as `evaluationTime`
  and fails validation rather than silently misbehaving.
- **`EngineOptions.maxClockSkewSeconds` and `EngineOptions.maxIntentAgeSeconds` are
  now required.** A `PolicyEngine` constructed without an explicit trusted-time
  policy no longer starts. `RECOMMENDED_TRUSTED_TIME_PROFILE` supplies conformant
  values, but a deployment must opt into it explicitly — it is a recommended
  profile, not a default.
- **`evaluationTime` is validated, not coerced.** `NaN`, `Infinity`, non-integers
  and out-of-range values are rejected via `assertProtocolSeconds` instead of being
  normalized.
- **`PolicyEngine.verifyAuthorization` now returns the named type
  `EngineAuthorizationVerificationResult`.** The result gained `signatureVerified`,
  `verificationMode` and `verificationCoverage` alongside `valid` / `reason`. Code
  that structurally matched the previous anonymous return type still compiles;
  code that re-declared it will not.
- **The public `AuthorizationV1` artifact boundary is separated from the engine's
  internal representation.** Internal HMAC-binding fields are no longer part of the
  published artifact surface; use `toPublicAuthorizationV1` to obtain the wire form.
- **`auth_id` is the canonical authorization identifier.** Reads are reconciled with
  the legacy `authorization_id` field rather than the two being treated as
  interchangeable.

### Security hardening

- Replay-window eviction, velocity windows and tool-call windows are all driven from
  the trusted `evaluationTime` rather than from proposer-supplied `intent.timestamp`.
  A caller can no longer reset its own quota by choosing a favourable timestamp that
  still passes freshness.
- Authorization `issued_at` / `expiry` are minted from the trusted evaluation time.
- Implausible future authorization issuance is rejected; the bound is exported as
  `DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS`.
- Tool-call enforcement is derived from trusted policy state. `intent.tool_call` is
  explicitly treated as a self-declared, agent-controlled field and does not
  influence the decision; `intent.tool` is used only as a lookup key that must
  resolve against trusted state.
- Negative `intent.amount` values are rejected instead of flowing into budget and
  velocity arithmetic.
- Expired concurrency leases are reclaimed and released leases removed, so a crashed
  or abandoned execution no longer consumes concurrency budget indefinitely.
- Runtime state numeric-leaf validation was hardened; malformed or type-confused
  state leaves produce a deterministic `STATE_INVALID` denial rather than being
  coerced.
- `canonicalization-v1` and normative `AuthorizationV1` verification are enforced at
  the verification boundary.

### Added

- `RECOMMENDED_TRUSTED_TIME_PROFILE` — conformant `maxClockSkewSeconds` /
  `maxIntentAgeSeconds` values matching `docs/spec/core/trusted-time-v1.md` §5.
- Deterministic trusted-time freshness verifier and its dedicated reason codes.
- `SignedKRLV1` protocol artifact, with `verifySignedKrl` and
  `signedKrlSigningPayload`, plus the `signed-krl` type exports.
- `toPublicAuthorizationV1` and `DEFAULT_MAX_FUTURE_ISSUED_AT_SKEW_SECONDS`.
- Signature-verification status and coverage are surfaced on authorization results
  (`signatureVerified`, `verificationMode`, `verificationCoverage`), so a caller can
  distinguish "verified and valid" from "valid under a weaker coverage mode".
- `EngineAuthorizationVerificationResult` is exported.

### Changed

- `PolicyEngine.verifyAuthorization` is documented as **limited scope**: it
  authenticates only the engine-HMAC field subset. Relying parties enforcing an
  authorization issued by another party must use the standalone strict verifier with
  explicit `trustedKeySets`.
- HMAC-SHA256 authorization verification is deprecated in favour of Ed25519.
- The Sift `AuthorizationV1` wire encoding is accepted at the verification boundary.
- Audit-chain genesis was aligned and conformance vectors refrozen accordingly.

### Fixed

- Core public-API surface is shape-aware at the guard boundary, so an incompatible
  engine shape is rejected at construction rather than at first evaluation.

### Packaging

- The published tarball no longer ships `dist/test` or `dist/dev`. The `1.7.0`
  artifact shipped 102 compiled test files and a development subprocess helper.
- `prepack` now rebuilds before packing, so a stale `dist/` cannot be published.
- `repository.directory` is declared for npm provenance.

---

## [1.7.0] - 2026-03-29

### Added

- `createVerifier` with explicit `trustedKeySets` parameter as the canonical PEP-side trust entry point.
- `TRUSTED_KEYSETS_REQUIRED` violation — strict mode now fails closed when no keyset is configured, rather than returning inconclusive silently.
- Trust boundary diagram (`docs/diagrams/trust-boundary.svg`) and `## Trust Boundary` section in `packages/core/README.md`.

### Changed

- CLI `verify` commands (all 4 strict entry points) now require `--trusted-keyset` in strict mode or explicit `--mode best-effort`; missing keyset produces an actionable error rather than a silent inconclusive result.
- `@oxdeai/sdk@1.3.2`: JSDoc on `createGuard`, `GuardOptions.verifyAuthorization`, and `verifyCurrentArtifacts` now explicitly distinguish the engine-level HMAC check (PDP) from PEP-side issuer trust via `createVerifier`.

### Fixed

- Conformance validator no longer reads `OXDEAI_ENGINE_SECRET` from the environment — both `extract-vectors` and `validate` now unconditionally use `CONFORMANCE_ENGINE_SECRET`, making the suite deterministic regardless of shell environment.

### Notes

- No breaking changes to existing `AuthorizationV1`, `DelegationV1`, or stateless verification semantics.
- `createVerifier` was already available; this release makes it the documented, tested, and CLI-enforced primary entry point for relying-party verification.

---

## [1.6.1] - 2026-03-25

### Fixed

- `deepMerge` was mutating nested objects of the base argument via shallow-spread aliasing, silently violating the documented non-mutating contract. Nested plain objects are now shallow-copied before recursing.

### Added

- Property-based decision-path tests (D-1–D-6): determinism for equivalent inputs, no input-state mutation, cross-clone stability, key-order insensitivity, cross-process decision determinism, strict-mode explicit-input enforcement.

### Notes

- Version 1.6.0 was tagged in the repository but not published to npm.
- Version 1.6.1 is the first published release on the 1.6 line.
- No protocol semantic change from the current 1.6 protocol surface. This is a correctness, safety, and validation hardening release, including determinism guarantees, non-mutating evaluation, and verification fixes.

---

##  [1.6.0] - 2026-03-22

### Added

- DelegationV1 - first-class authorization artifact for scoped delegation from a parent AuthorizationV1
- verifyDelegation(...) stateless verifier
- verifyDelegationChain(...) chain verification support
- delegationParentHash - cryptographic binding to parent AuthorizationV1
- delegation conformance vectors (D-P1–D-P5)
- cross-adapter delegation validation (G-D1–G-D3)

### Changed

- Protocol model clarified to (intent, state, policy) in documentation (no API changes)
- DelegationV1 promoted from design concept to stable protocol artifact

### Notes

- No breaking changes to existing AuthorizationV1 semantics
- Stateless verification surface remains backward compatible
- Existing integrations continue to function without modification

## [1.5.0] - 2026-03-19

### Changed

- Execution authorization framing: replaced "economic and operational constraints" with "execution authorization" throughout package description, keywords, and documentation.
- Package description updated on npm to reflect protocol-first positioning.
- Keywords: replaced `economic-containment` and `agent-economics` with `authorization-artifact` and `fail-closed`.

### Notes

- `@oxdeai/core@1.5.0` corresponds to the v1.5 Developer Experience milestone.
- Protocol semantics, artifact encoding, and verification API are unchanged from `1.3.x`.
- `@oxdeai/sdk` and `@oxdeai/conformance` remain at `1.3.1` (no protocol changes).
- Adapter packages (`@oxdeai/guard`, `@oxdeai/langgraph`, `@oxdeai/openai-agents`, `@oxdeai/crewai`, `@oxdeai/autogen`, `@oxdeai/openclaw`) released at `1.0.1`.

---

## [1.3.1] - 2026-03-08

### Changed

- Patch release aligned with `@oxdeai/sdk@1.3.1` and `@oxdeai/conformance@1.3.1`.
- Documentation and release metadata updates.

---

## [1.3.0] - 2026-03-08

### Changed

- Synchronized protocol stack release metadata for the v1.3 line (`core`, `sdk`, `conformance`).
- Release/process documentation alignment for coordinated protocol publication and provenance.

### Notes

- `@oxdeai/core@1.3.0` is released together with:
  - `@oxdeai/sdk@1.3.0`
  - `@oxdeai/conformance@1.3.0`
- Tooling (`@oxdeai/cli`) remains on its own version line.
- No intentional protocol semantic break from `1.2.x`.

---

## [1.2.0] - 2026-03-08

### Added

- Protocol milestone: non-forgeable verification with Ed25519 signatures.
- Authorization signature fields and verification support for `alg` and `kid`.
- Issuer-scoped KeySet model for trusted key resolution.
- Public verifier API: `verifyAuthorization(...)`.
- Canonical signing input and domain-separated signature verification paths.

### Changed

- `verifyEnvelope(...)` enhanced to validate signed envelope metadata in strict fail-closed flows.
- Conformance alignment updated for signature-verification vectors and deterministic validation ordering.

### Notes

- `@oxdeai/core@1.2.0` is part of the synchronized protocol stack release with:
  - `@oxdeai/sdk@1.2.0`
  - `@oxdeai/conformance@1.2.0`
- This is a protocol milestone release; tooling (`@oxdeai/cli`) remains on its own version line.

---

## [1.0.3] - 2026-03-06

### Changed

- Documentation refresh for protocol/spec alignment in the `v1.0.x` line.
- Release/process guidance tightened for deterministic verification workflows.

### Notes

- Patch release only; no intentional protocol semantic changes vs `1.0.2`.
- Snapshot/envelope `formatVersion` and stateless verifier result semantics remain unchanged.

---

## [1.0.2] - 2026-03-05

### Added

- Published protocol JSON Schemas for core artifacts:
  - `Intent`
  - `CanonicalState`
  - `Authorization`
  - `AuditEvent` / audit log list
  - `VerificationEnvelopeV1`
  - `VerificationResult`
- Schema validation utilities under `src/schemas`.
- Schema validation script: `pnpm -C packages/core schema:validate`.

### Changed

- Verification/schema handling refined to keep deterministic validation behavior aligned with existing protocol semantics.
- Protocol and integration documentation updated (`protocol/` companion docs).

### Notes

- Patch release only; no intentional protocol-breaking changes vs `1.0.1`.

---

## [1.0.1] - 2026-03-05

### Changed

- Documentation and release metadata updates for post-1.0 protocol stability.
- Clarified status wording to reflect stable verification surface continuity after `1.0.0`.

---

## [1.0.0] - 2026-03-04

Protocol stability release.

### Added

- Stable stateless verification API.
- Verification Envelope specification.
- Unified VerificationResult schema.
- Protocol documentation (`docs/protocol.md`).

### Changed

- Project status upgraded from pre-release to stable protocol library.

### Notes

This release freezes:

- verification API surface
- envelope encoding format
- verification result schema
- deterministic invariants

---

## [0.9.3] - 2026-03-04

Documentation release before v1.0.

### Added
- Protocol documentation.
- Verification Envelope specification.
- Minimal example script for envelope verification.
- Deterministic invariants documentation.

### Changed
- README expanded with stateless verification API and protocol concepts.

### Notes
- No runtime behavior changes.

---

## [0.9.2] - 2026-03-04
### Added
- Verification Envelope codec (`encodeEnvelope` / `decodeEnvelope`).
- Pure verifier `verifyEnvelope(...)` composing snapshot + audit verification.

### Changed
- Unified verification results to `VerificationResult` shape across stateless verifiers.
- Deterministic violation ordering (stable sort).

---

## [0.9.1] - 2026-03-04
### Added
- Pure verifier `verifyAuditEvents(...)` for audit chain validation (stateless).

### Changed
- Replay verification helper renamed to avoid export collision (`verifyReplayEvents`).

---

## [0.9.0] - 2026-03-03
### Added
- Pure verifier `verifySnapshot(snapshotBytes, opts?)` (stateless snapshot integrity check).

---

## [0.8.0] - 2026-03-03

**Host Integration Adapters**

v0.8.0 introduces first-class host integration primitives to @oxdeai/core without weakening its deterministic guarantees. The engine now supports pluggable StateStore and AuditSink interfaces, along with minimal in-memory and file-based reference adapters. PolicyEngine wiring ensures ordered audit delivery (sync and async) while preserving fully synchronous, deterministic evaluation semantics. State persistence is explicit (commitState, flushState) and does not affect decision outcomes. Deterministic identifiers (policyId, stateHash, auditHeadHash) remain stable across processes, and integration hooks introduce no entropy or behavioral drift. This release makes the engine production-integrable while keeping containment logic strictly deterministic.

### Added
- Adapter interfaces: `StateStore` and `AuditSink`.
- Reference adapters: `InMemoryStateStore`, `InMemoryAuditSink`, `FileStateStore`, `FileAuditSink`.
- Optional PolicyEngine integration hooks: `auditSink`, `stateStore`, `autoPersist`, plus `flushAudit()` / `commitState()` / `flushState()`.

### Tests
- Adapter integration tests validating sink event ordering for sync and async sinks.

---

## [0.7.1] - 2026-03-03

### Added
- Cross-process determinism test (spawn child process) to validate reproducible fingerprints.

---

## [0.7.0] - 2026-03-03

### Added
- `verifyAuditEvents(...)` stateless audit verification for offline audit traces.
- Strict verification mode returning `"inconclusive"` without state anchors.
- Optional `STATE_CHECKPOINT` audit events (stateHash only).
- `checkpoint_every_n_events` engine option.

### Security
- Strict mode refuses to certify traces without deterministic anchors.
- PolicyId consistency enforced across event streams.
- Offline recomputation of audit hash chain.

### Verification
- Chain continuity validation (GENESIS → headHash).
- Monotonic timestamp enforcement.
- Policy binding validation.
- Checkpoint stateHash format validation (64-hex).


---

## [0.6.1] - 2026-03-03

### Changed
- Documentation updates (README): added snapshot section, badge, and clarified roadmap positioning.

---

## [0.6.0] - 2026-03-03

### Added
- Versioned canonical snapshot format (`formatVersion: 1`) with schema validation.
- Deterministic module snapshot payloads (canonical JSON) replacing v8 byte snapshots.
- Property-based test suite for determinism invariants (seeded, no deps).

### Changed
- `CanonicalState` schema: `modules` replaces `moduleStates`; snapshot payloads are JSON.
- Authorization binding now uses canonical engine `stateHash` (normalized) for snapshot determinism.
- Tool amplification snapshot import tolerates `tool: null` (canonical undefined normalization).

### Invariants
- Snapshot `export → encode → decode → import` preserves `stateHash`.
- Equivalent key insertion orders produce identical per-module and global state hashes.
- Replay and decision sequences match before/after snapshot import.

---

## [0.5.1] - 2026-03-03

### Changed

* README rewritten for clarity and infra positioning.
* Added “Show me the invariant” deterministic snippet.
* Updated roadmap to reflect post-v0.5 direction (v0.6 snapshot hardening, v0.7 replay verification, v0.8 adapters).

### Documentation

* Clarified deterministic guarantees (`policyId`, `stateHash`, `auditHeadHash`).
* Reframed project positioning as deterministic economic containment.
* Removed outdated roadmap references (v0.3-era notes).

---

## [0.5.0] - 2026-02-27

### Added

- Canonical state snapshot layer:
  - `CanonicalState`
  - `createCanonicalState`
  - `withModuleState`
  - `encodeCanonicalState` / `decodeCanonicalState`
- Deterministic `computeStateHash()` derived from module state codecs.
- Content-addressed `computePolicyId()`:
  - Stable module ordering
  - Canonicalized engine configuration
  - SHA-256 over canonical payload.
- Stateless audit verification surface for deterministic offline audit validation.
- Strict determinism mode:
  - `Date.now()` fallback disallowed when `strictDeterminism` is enabled.
- Signature-stripped canonical intent identity:
  - `intentHash(intent)` excludes signature.
  - `verifyAuthorization()` aligned to canonical intent identity.

### Changed

- Audit chain canonicalization now binds `policyId` (null-normalized) into hash computation.
- State type exports made explicit (no wildcard re-export).
- Root export surface tightened:
  - Removed wildcard `utils` export.
  - Removed duplicate replay/determinism exports.
- Module ordering normalized via sorted registry when computing snapshots and state hashes.

### Security

- Deterministic triple guaranteed across runs:
  - `policyId`
  - `stateHash`
  - `auditHeadHash`
- Canonical JSON hardened:
  - Sorted keys
  - BigInt normalization
  - undefined normalization
  - Explicit UTF-8 hashing.
- Intent identity separated from signature proof to prevent hash fragmentation across signature encodings.
- Strict-mode clock injection required for reproducible authorization validation.

### Invariants

- Same engine version + module set + deterministic opts => identical `policyId`.
- Same state => identical `stateHash`.
- Same event sequence + `policyId` => identical audit head hash.
- Signature presence does not alter intent identity.

---

## [0.4.3] - 2026-02-27

### Fixed
- Test suite aligned to `evaluatePure()` using shared `makeState` / `makeIntent` helpers.
- Helper typing hardened so overrides remain valid (State/tool_limits merge, Intent RELEASE shape).

---

## [0.4.0] - 2026-02-27

### Added

- ToolAmplificationModule (deterministic tool/API call cap per agent per window).
- `tool_call` and `tool` fields in Intent for explicit tool accounting.
- `tool_limits` in State for tool-call window enforcement.
- ReplayModule (state-based replay protection).
- ConcurrencyModule (active authorization tracking).
- RecursionDepthModule (bounded agent depth).
- `evaluatePure()` returning `{ nextState }` for deterministic simulation.

### Changed

- `evaluate()` now acts as `evaluatePure + commit`.
- Budget and Velocity modules return `stateDelta`.
- State validation extended to include replay, concurrency, recursion, tool limits.

### Security

- Deterministic containment of:
  - Budget overflow
  - Tool-call amplification
  - Recursion depth escalation
  - Concurrency explosion
  - Replay abuse

---

## [0.2.2] - 2026-02-27

### Added

- `evaluatePure()` – deterministic evaluation returning `{ nextState }` without mutating input state.
- Replay protection moved fully into state via `ReplayModule` (nonce window tracking).
- `RecursionDepthModule` – per-agent max depth invariant.
- `ConcurrencyModule` – per-agent concurrency cap.
- Authorization-bound `RELEASE` lifecycle:
  - `Intent.type: "EXECUTE" | "RELEASE"`
  - `RELEASE` requires valid `authorization_id`
  - Concurrency slots are tied to active authorizations.
- `stateDelta` support in modules for deterministic state transitions.
- `active_auths` structure in state for concurrency ownership tracking.

### Changed

- `evaluate()` now acts as a backward-compatible wrapper over `evaluatePure()` and commits `nextState`.
- Concurrency lifecycle is now explicit and state-driven.
- State validation extended to include replay, recursion, and concurrency structures.

### Security

- Release spoofing prevented via authorization-bound concurrency slots.
- Replay protection fully deterministic and persisted in policy state.
- All invariants evaluated before commit.
- Fail-closed behavior preserved.

---

## [0.2.0] - 2026-02-26

### Added

- BudgetModule with per-period cap.
- Per-action cap enforcement.
- VelocityModule (windowed rate limiting).
- KillSwitchModule (global and per-agent).
- AllowlistModule (action / asset / target allowlists).
- Signed authorizations (HMAC-based).
- Hash-chained audit log.

---

## [0.1.x]

Initial release.
Basic deterministic policy engine with budget and velocity controls.
