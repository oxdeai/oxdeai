# Changelog

All notable changes to `@oxdeai/conformance` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [2.0.1] - 2026-10-04

Dependency release of `@oxdeai/conformance`. It packs against
`@oxdeai/core@2.0.1` (exact dependency). The vector corpus is unchanged.

### Security

- Pins `@oxdeai/core@2.0.1` (GHSA-48xw-c298-546r).

## [2.0.0] - 2026-09-25

**Baseline for this entry:** the published `@oxdeai/conformance@1.3.1` npm artifact
(2026-03-08).

> ⚠️ `1.5.0` appears in this changelog and as the Git tag `conformance-v1.5.0` but
> **was never published to npm**. `1.3.1` is the last released artifact and is the
> baseline used here. The `1.5.0` entry below is retained as historical record of
> the source change, not of a release.

The vector corpus is this package's public contract, and it has roughly doubled
since the last published artifact.

### Breaking

- **The suite now targets the `@oxdeai/core` 2.0 line.** The dependency is an exact
  pin, so a build of this package validates the 2.0 protocol surface and cannot be
  used to validate a `core@1.x` implementation. Implementers tracking the 1.x line
  must stay on `@oxdeai/conformance@1.3.1`.
- Vector regeneration under the trusted-time engine changed expected values wherever
  a vector's evaluation depended on time. Existing vector expectations captured
  against the 1.3.1 engine will not match.

### Added

Nine vector families that did not exist in the published `1.3.1` artifact:

- `trusted-time.json` — trusted-time freshness semantics
- `clock-semantics-verification.json`
- `delegation-verification.json`, `delegation-chain-verification.json`,
  `delegation-parent-hash.json`, `delegation-signature-verification.json`
- `signed-krl-verification.json` — `SignedKRLV1`
- `key-lifecycle-verification.json`
- `profile-c-state-verification.json`

Also added: the `validate:trusted-time` entry point and the trusted-time conformance
runner.

### Changed

- The validator no longer reads `OXDEAI_ENGINE_SECRET` from the environment; both
  `extract-vectors` and `validate` use `CONFORMANCE_ENGINE_SECRET` unconditionally,
  so the suite is deterministic regardless of shell environment.
- Delegation chain and signature verification run on an independent recomputation
  path rather than through an engine call.

### Packaging

- An explicit `files` field is declared. The artifact now ships `vectors/`, the
  compiled validator, README, CHANGELOG and LICENSE only. It no longer ships
  TypeScript sources, `tsconfig.json`, the Go/Python harness directory, or compiled
  test files — the harnesses remain in the repository and are run from source.
- `prepack` now rebuilds before packing.
- `repository` (with `directory`), `homepage` and `bugs` are declared for npm
  provenance.

---

## [1.5.0] - 2026-03-30

### Changed

- Secret constant made deterministic; `engine_secret` env var override removed from validator.
- Conformance vectors regenerated with 32-char secret to meet enforced minimum-length requirement.
- `envelope-001` hashes updated after `deepMerge` non-mutation correction in `@oxdeai/core`.
- DelegationV1 chain and signature verification moved to independent recomputation path (no engine call).

### Notes

- Protocol vector behavior has changed from `1.4.0` — vectors are not backward-compatible with the `1.4.x` line.
- Protocol stack alignment: `@oxdeai/core@1.6.1`, `@oxdeai/sdk@1.3.2`.

---

## [1.4.0] - 2026-03-25

### Changed

- Version-line release alignment for `@oxdeai/conformance@1.4.0`.
- Package metadata updated for the `1.4.x` publication line.

### Notes

- No conformance vector or validator semantic changes from `1.3.1`.
- Frozen protocol behavior remains unchanged; this release keeps the package line current with the published metadata.

---

## [1.3.1] - 2026-03-08

### Changed

- Metadata-only packaging fix for npm consumers.
- Published dependency metadata now uses `@oxdeai/core@^1.3.0` directly (no workspace protocol spec in package metadata).

### Notes

- No vector or validator semantic changes from `1.3.0`.

---

## [1.3.0] - 2026-03-08

### Changed

- Protocol-stack release alignment to the v1.3 line with synchronized versioning.
- Conformance package publication metadata updated to target `@oxdeai/core@^1.3.0`.

### Notes

- `@oxdeai/conformance@1.3.0` is released together with:
  - `@oxdeai/core@1.3.0`
  - `@oxdeai/sdk@1.3.0`
- Validator behavior and vector semantics remain aligned with the existing deterministic protocol guarantees from `1.2.x`.

---

## [1.2.0] - 2026-03-08

### Added

- Protocol milestone vectors for non-forgeable verification.
- Authorization signature verification coverage (Ed25519, `alg`, `kid`, tamper/unknown-key/unknown-alg cases).
- Envelope signature verification coverage with deterministic fail-closed outcomes.

### Changed

- Validator alignment with `verifyAuthorization(...)` and enhanced `verifyEnvelope(...)` behaviors.
- Deterministic conformance output expanded for v1.2 protocol-stack verification paths.

### Notes

- `@oxdeai/conformance@1.2.0` is released together with:
  - `@oxdeai/core@1.2.0`
  - `@oxdeai/sdk@1.2.0`
- `@oxdeai/cli` remains on a separate tooling version line.
