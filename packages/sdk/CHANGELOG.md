# Changelog

All notable changes to `@oxdeai/sdk` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [2.0.1] - 2026-10-04

Dependency release of `@oxdeai/sdk`. It packs against `@oxdeai/core@2.0.1`
(exact dependency). No SDK source, public API or type declaration change.

### Security

- Pins `@oxdeai/core@2.0.1` (GHSA-48xw-c298-546r). Because the SDK re-exports
  `@oxdeai/core`, a `PolicyEngine` imported from `@oxdeai/sdk@2.0.0` is the
  affected `core@2.0.0` engine; upgrade to this release.

## [2.0.0] - 2026-09-25

**Baseline for this entry:** the published `@oxdeai/sdk@1.3.3` npm artifact
(2026-04-23), compared file-by-file against the current candidate.

> ⚠️ `1.3.3` was published and then further modified on `main` without a version
> bump: the published `dist/guard.js` and `dist/client.js` differ from the current
> source at the same version number. `2.0.0` restores the guarantee that a version
> identifies an artifact.

The SDK's own module list is unchanged. The major is not cosmetic dependency
tracking — it reflects two real consumer-visible changes plus the re-exported core
surface.

### Breaking

- **`export * from "@oxdeai/core"` re-exports core's 2.0 surface.** Every core
  breaking change is therefore an SDK breaking change for consumers importing
  `PolicyEngine` and friends from `@oxdeai/sdk`. See the `@oxdeai/core` 2.0.0 entry
  — in particular the required `evaluationTime` argument and the now-required
  `maxClockSkewSeconds` / `maxIntentAgeSeconds` engine options.
- **`Authorization` is replaced by `AuthorizationV1`** in the public type surface of
  `client.d.ts`, `guard.d.ts` and `types.d.ts`. Code that annotated these values with
  the internal `Authorization` type no longer compiles.

### Security hardening

- **Verifier time is taken from the trusted clock, never from `intent.timestamp`.**
  Previously `OxDeAIClient.verifyAuthorization` and the SDK guard passed
  `intent.timestamp` as "now". Because that value is proposer-supplied and
  hash-bound into the authorization at issuance, the expiry comparison was pinned to
  issuance time and **the authorization never expired**. Both paths now sample the
  clock boundary once per evaluation and reuse that single sample for the timestamp
  fallback, for `evaluationTime`, and for verification.

  This changes runtime behaviour for existing callers: artifacts that previously
  verified indefinitely will now correctly be rejected once expired.

  Note that the SDK clock defaults to `Date.now() / 1000` unless the caller supplies
  an independent `ClockAdapter`. A supplied value is not automatically independently
  trusted time.

### Added

- `OxDeAIClient.verifyAuthorization` accepts an optional third argument
  `{ verificationTime?: number }` for callers that already hold a verification time
  from their trusted execution boundary. Additive; existing two-argument calls
  continue to work.

### Changed

- `OxDeAIClient.verifyAuthorization` documents that it inherits the **limited scope**
  of `PolicyEngine.verifyAuthorization`: it authenticates only the engine-HMAC field
  subset. Relying parties enforcing an authorization issued by an external party must
  use the strict standalone verifier with explicit `trustedKeySets`.

### Packaging

- `license`, `repository` (with `directory`), `homepage` and `bugs` are now declared;
  the published `1.3.3` artifact carried none of them, which blocks npm provenance.
- `prepack` now rebuilds before packing.

---

## 1.3.3

- Fix package publish contents: exclude src and test artifacts from the published tarball.

## [1.3.2] - 2026-03-30

### Security

- `engine_secret` minimum-length and entropy requirements now enforced at runtime — insecure defaults removed.
- Timing-safe HMAC comparison (`timingSafeEqual`) applied in domain verification.

### Added

- Explicit verifier trust boundary with strict-mode enforcement in the trust model.
- DelegationV1 protocol artifact: full implementation, verification, and conformance vectors (139 assertions).

### Fixed

- `deepMerge` is now non-mutating; property-based tests added.
- `tool_limits` marked required in `State` type, aligning type with runtime behavior.
- PolicyEngine output types exported; decision-path property surfaced correctly.
- TypeScript type error for `engine_secret` resolved across examples and packages.
- Conformance vectors regenerated with 32-char secret and CI environment aligned.

### Changed

- Protocol-stack version alignment with:
  - `@oxdeai/core@1.6.1`
  - `@oxdeai/conformance@1.4.0`
- Trust boundary made explicit across SDK and documentation.

### Notes

- `@oxdeai/cli` remains on a separate tooling version line.

---

## [1.3.1] - 2026-03-08

### Changed

- Metadata-only packaging fix for npm consumers.
- Published dependency metadata now uses `@oxdeai/core@^1.3.0` directly (no workspace protocol spec in package metadata).

### Notes

- No runtime or protocol-semantics changes from `1.3.0`.

---

## [1.3.0] - 2026-03-08

### Added

- Stable public guard API for callback-boundary enforcement (`createGuard`).
- Guard-focused test coverage for allow/deny execution behavior and authorization enforcement.

### Changed

- SDK integration documentation updated for the v1.3 adoption layer.
- Protocol-stack version alignment with:
  - `@oxdeai/core@1.3.0`
  - `@oxdeai/conformance@1.3.0`

### Notes

- `@oxdeai/cli` remains on a separate tooling version line.
- No intentional protocol semantic break from `1.2.x`.

---

## [1.2.0] - 2026-03-08

### Added

- Protocol-stack alignment with OxDeAI non-forgeable verification milestone.
- SDK compatibility with AuthorizationV1 signature fields (`alg`, `kid`) and KeySet-based verification options surfaced from `@oxdeai/core`.

### Changed

- Integration flow documentation and examples aligned to the v1.2 protocol stack behavior.
- Client usage remains deterministic and protocol-compatible with stateless verification APIs.

### Notes

- `@oxdeai/sdk@1.2.0` is released together with:
  - `@oxdeai/core@1.2.0`
  - `@oxdeai/conformance@1.2.0`
- `@oxdeai/cli` remains on a separate tooling version line.
