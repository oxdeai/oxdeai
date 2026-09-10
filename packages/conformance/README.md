# @oxdeai/conformance
Conformance vectors and validator for the OxDeAI execution-time authorization protocol.
Ensures implementations reproduce deterministic AuthorizationV1 artifacts and boundary verification (fail-closed).

## Purpose
`@oxdeai/conformance` verifies that an implementation matches the frozen protocol behavior for a specific version.

Passing validation means the implementation reproduces expected deterministic artifacts (hashes, statuses, and verification outputs) from frozen vectors.

## Version Coupling
- `@oxdeai/conformance@2.0.0` targets `@oxdeai/core@2.0.0` behavior.
- Use matching major/minor protocol versions when validating.

## Included Vector Sets

### Core protocol (pre-v1.3)
- `intent-hash.json`
- `authorization-payload.json`
- `snapshot-hash.json`
- `audit-chain.json`
- `audit-verification.json`
- `envelope-verification.json`
- `authorization-verification.json`
- `authorization-signature-verification.json`
- `envelope-signature-verification.json`

### DelegationV1 (v1.3+)
- `delegation-parent-hash.json` - `delegation_parent_hash = SHA256(canonical_json(AuthorizationV1))`; key-order invariance (I1)
- `delegation-verification.json` - `verifyDelegation()` field-level checks: expiry, scope narrowing, delegatee, policy, replay, trust-missing
- `delegation-chain-verification.json` - `verifyDelegationChain()` chain checks: hash binding, delegator, parent expiry, expiry ceiling, single-hop, policy binding
- `delegation-signature-verification.json` - Ed25519 signature path: valid, tampered sig, wrong kid, tampered field, expired

### Profile C - Semantic State Verification (v1.5+)

- `profile-c-state-verification.json` - models selected Profile-C state-hash comparisons (guard step 10), separately from actual guard integration: `computeStateHash(liveState)` compared against the committed `state_hash` in the authorization.

Eight vectors covering:

| Vector | Mode | Expected outcome |
|--------|------|-----------------|
| `profile-c-001` | `live-state-match` | `ok` - same state at signing and verification |
| `profile-c-002` | `live-state-mismatch` | `state-hash-mismatch` - state advanced between signing and execution |
| `profile-c-003` | `hash-strategy-mismatch` | `state-hash-mismatch` - provider hash committed, Core algorithm at verification |
| `profile-c-004` | `compute-throws` | `compute-error` - `computeStateHash` throws; execution blocked fail-closed |
| `profile-c-005` | `toctou-stale-state` | `state-hash-mismatch` - TOCTOU: state advanced since authorization was issued |
| `profile-c-006` | `encoding-b-live-state-match` | `ok` - Encoding B (Sift-compatible) + matching state |
| `profile-c-007` | `encoding-b-live-state-mismatch` | `state-hash-mismatch` - Encoding B + stale state |
| `profile-c-008` | `encoding-b-hash-strategy-mismatch` | `state-hash-mismatch` - Encoding B + strategy mismatch |

Two hash strategies modelled:

| Strategy | Algorithm |
|----------|-----------|
| `core` | `sha256HexFromJson` (Core-native) |
| `provider` | SHA-256 of `"PROVIDER:" + canonicalJson(state)` (simulates external provider hash) |

Encoding B vectors (`profile-c-006` through `profile-c-008`) exercise the Sift-compatible wire format (`alg="ed25519"`, `expires_at`, base64url signature) combined with live-state semantic verification.

### Key Lifecycle (v1.5+)

- `key-lifecycle-verification.json` - exercises `keyIsActiveAt`, `findKeyInKeySets`, and `AUTH_KEY_INACTIVE` / `AUTH_KID_UNKNOWN` enforcement across all key status and time-window states.

Ten vectors covering:

| Vector | Mode | Expected outcome |
|--------|------|-----------------|
| `key-lifecycle-001` | `key-active` | `ok` - active key, no time constraints |
| `key-lifecycle-002` | `key-revoked` | `AUTH_KEY_INACTIVE` - revoked key rejected |
| `key-lifecycle-003` | `key-not-before-future` | `AUTH_KEY_INACTIVE` - key not yet active |
| `key-lifecycle-004` | `key-not-after-past` | `AUTH_KEY_INACTIVE` - validity window expired |
| `key-lifecycle-005` | `key-valid-window` | `ok` - explicit `not_before`/`not_after` window active |
| `key-lifecycle-006` | `key-expired-window` | `AUTH_KEY_INACTIVE` - `not_after` in the past |
| `key-lifecycle-007` | `key-retired-within-window` | `ok` - retired key accepted during dual-sign overlap window |
| `key-lifecycle-008` | `key-retired-past-window` | `AUTH_KEY_INACTIVE` - retired key, window closed |
| `key-lifecycle-009` | `key-revoked-valid-window` | `AUTH_KEY_INACTIVE` - revocation overrides valid time window |
| `key-lifecycle-010` | `wrong-kid-known-issuer` | `AUTH_KID_UNKNOWN` - correct issuer, unknown kid |

### Clock Semantics (v1.5+)

- `clock-semantics-verification.json` - exercises strict zero-tolerance expiry enforcement (`now < expiry`) and `issued_at` informational-only semantics for both wire encodings.

Five vectors covering:

| Vector | Mode | Expected outcome |
|--------|------|-----------------|
| `clock-001` | `last-valid-second` | `ok` - `now = expiry - 1`, last valid second |
| `clock-002` | `one-past-expiry` | `AUTH_EXPIRED` - `now = expiry + 1`, no grace period |
| `clock-003` | `verifier-clock-behind` | `ok` - `now < issued_at`, `issued_at` not enforced as lower bound |
| `clock-004` | `encoding-b-last-valid-second` | `ok` - Encoding B (`expires_at`), `now = expires_at - 1` |
| `clock-005` | `encoding-b-verifier-clock-behind` | `ok` - Encoding B, `now < issued_at` |

Clock model: **strict zero tolerance**. Valid iff `now < expiry`. No skew parameter, no grace period. Issuers must build delivery latency into the expiry window. See `authorization-v1.md §17`.

### SignedKRLV1 Verification (v1.6+)

- `signed-krl-verification.json` - exercises `verifySignedKrl` across all verification paths for the `SignedKRLV1` protocol artifact.

Nine vectors covering:

| Vector | Mode | Expected outcome |
|--------|------|-----------------|
| `krl-001` | `valid` | `ok` - signature verifies, not expired |
| `krl-002` | `invalid-signature` | `KRL_SIG_INVALID` - tampered signature |
| `krl-003` | `expired` | `KRL_EXPIRED` - `now >= not_after` (strict zero-tolerance) |
| `krl-004` | `malformed-revoked-kids` | `KRL_MALFORMED` - `revoked_kids` is a string, not an array |
| `krl-005` | `duplicate-revoked-kids` | `KRL_MALFORMED` - duplicate entries in `revoked_kids` |
| `krl-006` | `unknown-signing-kid` | `KRL_UNKNOWN_SIGNING_KID` - kid not in trusted KRL signing key set |
| `krl-007` | `signing-key-inactive` | `KRL_SIGNING_KEY_INACTIVE` - key found but `keyIsActiveAt` returns false |
| `krl-008` | `unsupported-alg` | `KRL_UNSUPPORTED_ALG` - `signature.alg != "Ed25519"` |
| `krl-009` | `version-regression` | `KRL_VERSION_REGRESSION` - `krl_version` less than previous accepted value |

Signing domain: `OXDEAI_KRL_V1`. KRL signing fixture key (`krl-2026-01`, issuer `krl.issuer`) is distinct from the AuthorizationV1 / DelegationV1 signing fixture key to exercise trust-domain separation.

**Coverage scope:** TypeScript / `@oxdeai/core` conformance runner. The separate docs SignedKRL corpus is consumed by the root Go/Python harnesses. These are distinct corpora, not a projection or mirror.

### Trusted-Time Semantics (v2.0+)

- `trusted-time.json` - exercises the trusted-time freshness gate (`docs/spec/core/trusted-time-v1.md`) end to end: issuance, velocity, tool-window, and replay evaluation under trusted `evaluationTime`, plus protocol-domain and malformed-input rejection.

44 vectors, 1 assertion each, run via a dedicated `runTrustedTimeConformance` harness (`src/trustedTimeConformance.ts`) rather than the generic vector-comparison path used by the sets above.

Current validator assertion count: `262` (re-run `pnpm -C packages/conformance validate` for the live figure before relying on this number).

### Adapter ops required for DelegationV1

| Op | Input | Output | Independence |
|----|-------|--------|--------------|
| `delegation_parent_hash` | `{ parent: AuthorizationV1 }` | `{ parent_auth_hash: hex }` | Full - SHA256 + canonical JSON |
| `verify_delegation` | `{ delegation: DelegationV1, opts }` | `{ status, violations, policyId }` | Full - no crypto required |
| `verify_delegation_chain` | `{ parent, delegation, opts }` (inline) | `{ status, violations }` | Full - hash recomputation + structural checks |
| `verify_delegation_signature` | `{ parent, delegation, opts }` (inline) | `{ status, violations }` | Full - chain checks + Ed25519 via test key material |
| `verify_delegation_chain_case` | `{ id: string }` | `{ status, violations }` | Lookup (frozen) |
| `verify_delegation_signature_case` | `{ id: string }` | `{ status, violations }` | Lookup (frozen) |

The optional `packages/conformance/go-harness` driver (not root vector CI; Python adapter blocked by #306) uses `verify_delegation_chain` and `verify_delegation_signature`
with inline `input` from the vector files. Those operations are designed to recompute
`SHA256(canonical_json(parent))`, perform the chain-level structural checks,
and (for signature cases) perform Ed25519 verification using the test key
material embedded in `opts.trustedKeySets`. Lookup ops are retained for
compatibility but not used by the harness runners.

### Coverage distinction

The `Cross-language?` column reports what `pnpm test:vectors:go` and
`pnpm test:vectors:py` actually execute, not what is portable in principle.
Those commands exercise three corpora: canonicalization-v1 (11 vectors),
Profile-C state verification (8), and SignedKRLV1 (9) - 28 assertions per
language. Everything else is TypeScript-only today.

| Layer | What it covers | Cross-language? |
|-------|---------------|-----------------|
| `delegation-parent-hash.json` | Hash stability, I1 key-order invariance | TypeScript only - portable in principle (SHA256 + canonical JSON), but not exercised by `test:vectors:go` |
| `delegation-verification.json` | Field checks, expiry, scope, replay, trust-missing | TypeScript only - portable in principle (no crypto required), but not exercised by `test:vectors:go` |
| `delegation-chain-verification.json` | Chain structural checks (hash binding, delegator, expiry ceiling, policy) | TypeScript only - Go and Python adapters exist in `go-harness/` but are not exercised by `test:vectors:go`; the Python adapter fails at import (#306) |
| `delegation-signature-verification.json` | Ed25519 verification path | TypeScript only - Go and Python adapters exist in `go-harness/` but are not exercised by `test:vectors:go`; the Python adapter fails at import (#306) |
| `key-lifecycle-verification.json` | Key status (active/revoked/retired), `not_before`/`not_after` windows, wrong-kid rejection | TypeScript only - portable across any `verifyAuthorization` implementation, but `validate.ts` is its only consumer |
| `clock-semantics-verification.json` | Strict zero-tolerance expiry, `issued_at` informational, Encoding A + B boundary pins | TypeScript only - portable, no crypto required, but `validate.ts` is its only consumer |
| `trusted-time.json` | Trusted-time freshness gate: issuance, velocity, tool-window, replay under `evaluationTime`; protocol-domain and malformed-input rejection | TypeScript only (dedicated `runTrustedTimeConformance` harness) |
| `profile-c-state-verification.json` | Generated Profile-C representation; preserved signed fixtures and expected-result projection | TypeScript consumes this projection; Go/Python consume the docs authority. Same eight cases, not independent corpora. |
| `delegation.property.test.ts` (D-P1–D-P5) | PBT over scope / hash / mutation | TypeScript only |
| `guard.delegation.property.test.ts` (G-D1–G-D3) | Guard PEP delegation path | TypeScript only |
| `cross-adapter.test.ts` (CA-1–CA-10) | Cross-adapter equivalence, I6 | TypeScript only |

## Usage
From repo root:

```bash
pnpm -C packages/conformance extract
pnpm -C packages/conformance validate
```

Expected success output includes:

```text
Conformance passed: 262 assertions
```

(This figure moves as vectors are added. Treat the live `pnpm validate` output
as authoritative, not this number.)

## Adapter Contract
The validator is built around a pluggable adapter (`ConformanceAdapter`) so non-TypeScript runtimes can be checked against the same vectors.

An adapter must provide deterministic implementations for:
- canonical serialization used by vectors
- intent hashing
- authorization generation checks
- snapshot encoding + snapshot verification
- envelope verification

Reference adapter: `@oxdeai/core` (implemented in `src/validate.ts`).

## Verification Artifact Scope

![Verification envelope flow](../../docs/diagrams/verification-envelope-flow.svg)

Conformance checks deterministic behavior for artifacts and verifiers used in this flow (snapshot, audit, authorization, envelope, and verification status outputs).

Diagram source/editing policy:
- [`docs/diagrams/README.md`](../../docs/diagrams/README.md)

## Profile-C authority and generated representation

`vectors/profile-c-state-verification.json` is generated solely from
`docs/spec/test-vectors/profile-c-state-verification.json`. Edit the authority,
then run `pnpm project:profile-c` from the repository root.
`pnpm verify:corpus-authority` checks semantic and exact-byte consistency without
writing files. Build/prepack use the committed projection and do not copy either
vector tree. See [corpus authority](../../docs/conformance/corpus-authority.md).
The remaining package corpora retain their own frozen authorities.

## Freeze Policy
Vectors are frozen per protocol version.

- Do not regenerate vectors for the same protocol version after behavior changes.
- Any behavior-impacting change requires a new protocol/versioned vector release.
- Regeneration is allowed only when intentionally producing a new version baseline.

## Interoperability Profiles

OxDeAI defines three interoperability profiles. Conformance coverage maps directly to profile requirements:

| Profile | Description | Vector sets required |
|---------|-------------|----------------------|
| A | Core-native `AuthorizationV1` | Core protocol + DelegationV1 |
| B | External provider wire-compatible (Encoding A and Encoding B accepted) | Core + authorization-signature vectors |
| C | Semantic state verification via `computeStateHash` | Core + DelegationV1 + Profile C state vectors (selected cases, not full deployment proof) |

Profile C now has **executable conformance coverage** via `profile-c-state-verification.json` (15 assertions).

Key lifecycle enforcement (Profile A/B/C) is covered by `key-lifecycle-verification.json` (20 assertions): active, revoked, retired (within/past window), `not_before`/`not_after` time windows, and wrong-kid rejection.

Clock semantics (all profiles) are covered by `clock-semantics-verification.json` (10 assertions): strict zero-tolerance expiry, `issued_at` informational-only, Encoding A and Encoding B boundary pins.

See [External Provider Interoperability Profile](../../docs/spec/interoperability/external-provider-profile.md) for the full profile specification, wire encoding reference, and fail-closed rules.

## Using OxDeAI Conformance from Other Languages

Conformance vectors are the behavioral truth source for protocol compatibility.

Rust, Go, and Python implementations should validate their verifier/engine behavior against these vectors.
Passing conformance means the implementation is behaviorally aligned with the OxDeAI protocol profile for that version line, including executable interoperability coverage where applicable.

Profile C vectors (`profile-c-state-verification.json`) require a `computeStateHash` integration point. Cross-language harnesses must supply a compatible hash function to exercise those vectors.

Related implementer docs:

- [`docs/verification/multi-language.md`](../../docs/verification/multi-language.md)
- [`docs/conformance/conformance-vectors.md`](../../docs/conformance/conformance-vectors.md)
- [`docs/spec/interoperability/external-provider-profile.md`](../../docs/spec/interoperability/external-provider-profile.md)
- [`packages/conformance/go-harness`](./go-harness)

## Scoped results

Conformance PASS is limited to the declared `evidenceScope`. The package validator
emits `{ result, passed, failures, evidenceScope }`; after building, run
`node dist/src/validate.js --json` for JSON-only stdout. The dedicated trusted-time
CLI also accepts `--json`, and `runTrustedTimeConformance` adds `evidenceScope` to
its returned summary. Existing counts and failure exit codes are unchanged.

Coverage uses exact registry evidence mappings and actual passing cases;
`excludedClaims` is the registry complement, not a handwritten list. Coverage
means only the listed `supports` statements, never whole-protocol conformance or
proof of all claim obligations. Reference-generated expectations remain bounded
by the #325 provenance audit. No assurance class or signed attestation is added.

Builds bundle a metadata snapshot so installed packages can report explicit
exclusions and source identifiers without the repository checkout. See
[the schema and limitations](../../docs/conformance/evidence-scope.md), including
snapshot freshness, direct diagnostic harnesses and deployment exclusions.
