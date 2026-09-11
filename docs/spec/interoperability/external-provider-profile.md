# OxDeAI External Provider Interoperability Profile

**Version:** 1.0
**Status:** Non-normative (developer documentation)
**Category:** Interoperability Guidance

---

This document defines interoperability profiles for external authorization providers integrated
with OxDeAI execution boundaries. It specifies what a provider must implement to be
OxDeAI-compatible and what the verifier must enforce.

**Core invariant:**

```text
provider ambiguity → not interoperable → DENY → no execution
```

## Related Documents

- [AuthorizationV1 specification](../artifacts/authorization-v1.md) - accepted wire encodings (normative)
- [PEP Gateway specification](../enforcement/pep-gateway-v1.md) - enforcement contract (normative)
- [Threat model: external providers](../../architecture/threat-model-external-providers.md)
- [Key custody and rotation guide](../../architecture/key-custody-and-rotation.md)
- [Replay-store TTL alignment guide](../../architecture/replay-store-ttl-alignment.md)

---

## 1. Scope

This document covers:

- compatibility levels for external authorization providers
- provider responsibilities (what an adapter must produce)
- verifier responsibilities (what Core/Guard/PEP must enforce)
- interoperability matrix across known integration patterns
- conformance vector coverage per profile
- fail-closed rules for all ambiguous cases

This document does NOT:

- define a new `AuthorizationV1` version
- change `canonicalization-v1`
- require online provider verification
- replace governance systems
- guarantee policy correctness
- solve identity management
- mandate a specific replay-store backend
- introduce runtime coordination services

---

## 2. Profiles

Three compatibility profiles are defined. Each is cumulative: Profile C requires all of Profile B, which requires all of Profile A.

```text
Profile A ⊂ Profile B ⊂ Profile C

Profile A - Core-native AuthorizationV1
  Valid ALLOW artifact, Ed25519 signature, expiry, replay, intent binding.
  State binding via signature integrity only (state_hash is signed but not
  re-verified against live state at the gateway level).

Profile B - External provider wire-compatible
  Extends Profile A with Sift-compatible wire encoding and adapter trust model.
  Gateway-level only: signature integrity protects state_hash.

Profile C - Full semantic state verification
  Extends Profile B with live-state re-verification using a pluggable
  computeStateHash strategy. Requires OxDeAIGuard (not just PEP gateway).
```

---

### 2.1 Profile A - Core-native AuthorizationV1

**Summary:** The provider uses Core-native encoding. The verifier applies all standard checks.
This is the default integration path for providers using `@oxdeai/core`.

#### 2.1.1 Provider Requirements

| Requirement | Specification |
|---|---|
| Artifact type | `AuthorizationV1` |
| Wire encoding | Encoding A (Core-native) - see §3.1 |
| `decision` | Must be `"ALLOW"` |
| `issuer` | Non-empty string; must match a `KeySet.issuer` in verifier's `trustedKeySets` |
| `audience` | Non-empty string; must match verifier's `expectedAudience` |
| `auth_id` | Non-empty, globally unique, single-use string; MUST be cryptographically random or UUID |
| `issued_at` | Integer unix seconds at time of issuance |
| `expiry` | Integer unix seconds; must be > `issued_at` |
| `intent_hash` | SHA-256 hex of canonicalized intent bytes (`canonicalization-v1`) |
| `state_hash` | SHA-256 hex of canonicalized state bytes; signed into the artifact |
| `policy_id` | String identifying the policy used for the decision |
| Signing algorithm | `Ed25519` |
| `signature.alg` | `"Ed25519"` (capitalized, exact) |
| `signature.kid` | Matches a `KeySetKey.kid` in verifier's `trustedKeySets` |
| Signing preimage | `"OXDEAI_AUTH_V1\n"` + `canonicalJson(payload_without_sig_bytes)` |
| Signature encoding | Standard base64 (RFC 4648 §4) |
| Key lifecycle | Keys must be present in `trustedKeySets` before signing; rotated per key custody guide |

#### 2.1.2 Verifier Requirements

| Check | Enforcement | Failure code |
|---|---|---|
| Artifact structure | Required fields present and non-empty | `AUTH_MISSING_FIELD` |
| Algorithm recognized | `alg` ∈ `{"Ed25519", "ed25519"}` | `AUTH_ALG_UNSUPPORTED` |
| Key found | `kid` + `issuer` resolves to active key in `trustedKeySets` | `AUTH_KID_UNKNOWN` |
| Issuer matches | `authorization.issuer` == `expectedIssuer` (if configured) | `AUTH_ISSUER_MISMATCH` |
| Audience matches | `authorization.audience` == `expectedAudience` | `AUTH_AUDIENCE_MISMATCH` |
| Expiry valid | Effective expiry present and `now < expiry` | `AUTH_EXPIRED` / `AUTH_MISSING_FIELD` |
| Signature valid | Ed25519 over domain-prefixed canonical preimage | `AUTH_SIGNATURE_INVALID` |
| Decision is ALLOW | `authorization.decision == "ALLOW"` | Reject |
| Replay consumed | `consumeAuthId(auth_id, { expiry })` returns `true` | `AUTH_REPLAY` |
| Intent hash matches | `intentHash(action)` == `authorization.intent_hash` | `INTENT_HASH_MISMATCH` |
| State hash signed | `state_hash` covered by Ed25519 signature; tampering detected | `AUTH_SIGNATURE_INVALID` |

#### 2.1.3 State Binding at Profile A

Profile A enforces state_hash integrity via signature: any post-issuance tamper of `state_hash`
breaks the Ed25519 signature. However, the verifier does NOT re-verify `state_hash` against live
state - there is no live-state access at the gateway level. Profile A is suitable when the
issuing policy engine is the sole source of state truth.

#### 2.1.4 Fail-Closed Behavior

Any verification step failure → DENY → no execution. There is no partial acceptance.
Exception during signature verification → DENY. Replay store exception → DENY.

---

### 2.2 Profile B - External Provider Wire-Compatible

**Summary:** The provider uses Sift-compatible encoding or another accepted external encoding.
The verifier accepts both Encoding A and Encoding B. The trust root is the adapter's Ed25519 key,
not the external provider's internal signing infrastructure.

Profile B is a strict superset of Profile A. A Profile B-capable verifier accepts Profile A artifacts.

#### 2.2.1 Additional Provider Requirements (beyond Profile A)

| Requirement | Specification |
|---|---|
| Wire encoding | Encoding B (Sift-compatible) - see §3.2 - OR Encoding A |
| `expires_at` | May be used instead of `expiry` (see §3.3 expiry resolution) |
| `signature.alg` | `"ed25519"` (lowercase) - OR `"Ed25519"` for Encoding A |
| Signature encoding | Base64url (RFC 4648 §5) for `sig` field - OR standard base64 |
| Signing preimage | `canonicalJson(payload_without_sig_bytes)` (no domain prefix) for Encoding B |
| Adapter identity | Provider output must be re-signed by an adapter Ed25519 key listed in `trustedKeySets`; the external provider's receipt-signing key is NOT the OxDeAI trust root |
| `state_hash` | Computed by the adapter using a defined canonicalization function (e.g., `siftCanonicalJsonHash`); the function used must be documented and stable |

#### 2.2.2 Additional Verifier Requirements (beyond Profile A)

| Check | Enforcement |
|---|---|
| Encoding B algorithm | Accept `"ed25519"` (lowercase) in addition to `"Ed25519"` |
| Expiry fallback | If `expiry` absent, use `expires_at`; reject if neither present |
| Signature decoding | Auto-detect base64url by presence of `-` or `_` in `sig`; otherwise standard base64 |
| Signing preimage (Encoding B) | Reconstruct canonical JSON without domain prefix; verify with Ed25519 |
| Adapter trust root | Verify adapter's public key in `trustedKeySets`, not external provider's key |

#### 2.2.3 Trust Boundary at Profile B

```text
External provider receipt → Adapter verifies receipt → Adapter signs AuthorizationV1
                                                              ↓
                                              Verifier checks adapter's Ed25519 signature
                                              against trustedKeySets (OxDeAI trust root)
```

The OxDeAI trust root is the adapter key, not the external provider. A compromised external
provider cannot produce a guard-passing authorization without the adapter's Ed25519 private key.

#### 2.2.4 State Binding at Profile B

Same as Profile A: `state_hash` is protected by signature integrity. The adapter computes
`state_hash` using its own canonicalization function. The verifier does not re-compute
`state_hash` from live state at Profile B - only signature integrity is enforced.

#### 2.2.5 KRL Integrity at Profile B

Profile B requires verifying the external provider's receipt-signing key is not revoked.
A KRL (Key Revocation List) maintained by the provider records revoked `kid` values.

**KRL transport integrity options:**

| Option | Integrity guarantee | Status |
|--------|---------------------|--------|
| `unsigned_legacy` | Transport security (HTTPS) only | **Deprecated** - emits `process.emitWarning(DEP_OXDEAI_KRL_UNSIGNED_LEGACY)`; will be removed in a future release |
| `signed_preferred` with unsigned fallback | Transport security for unsigned KRLs; cryptographic for signed KRLs | **Transition mode** - not the permanent production posture; emits a once-per-instance `console.warn` when unsigned fallback is active |
| `signed_required` | Cryptographic - `SignedKRLV1` verified via `verifySignedKrl` | **Production target** |

**Migration.** `signed_required` is the production target. `signed_preferred` is a temporary migration bridge. `unsigned_legacy` is deprecated and will be removed. See `packages/sift/README.md` (Migration guide) for step-by-step migration instructions. Full RT-TRUST-2 closure requires `signed_required` + `verifyKrl` + `KrlWatermarkStore` + `SignedKrlCache`; compatibility modes retain residual transport-trust risk.

**`SignedKRLV1` specification.** `SignedKRLV1` is a provider-neutral OxDeAI protocol artifact
defined in `docs/spec/artifacts/signed-krl-v1.md`. It carries a `revoked_kids` list signed
with an Ed25519 key whose trust is configured statically at the verifier - independent of
transport security.

**Signing domain.** `OXDEAI_KRL_V1\n` + `canonicalJson(signingPayload)` - using OxDeAI
canonicalization-v1, not Sift canonicalization.

**Trust domain separation.**

```text
Sift provider receipt-signing key  ≠  OxDeAI AuthorizationV1 signing key
                                   ≠  KRL signing key
```

All three are distinct key pairs. The KRL signing key is configured statically in the
adapter (via `trustedKeySets` passed to `verifyKrl`), not fetched from the provider at
verification time.

**Fail-closed KRL behavior in `signed_preferred`:**

- KRL body has no `signature` key → unsigned fallback (accepted; `lastIntegrity: "unsigned_fallback"`)
- KRL body has any `signature` key → signed path (must verify via `verifyKrl`)
- Signed path without `verifyKrl` configured → refresh fails closed (no unsigned fallback)
- Malformed/partial `signature` field → signed path → fails closed

**Residual limitations (Profile B with `unsigned_legacy` or `signed_preferred` unsigned fallback):**
A compromised transport path can return a modified KRL that omits revoked kids.
Unknown and revoked kids still fail closed, but suppressed revocations bypass the revocation
check. This risk is only closed by deploying `signed_required` mode.

**KRL reason-code ownership.** `SiftHttpKeyStore` surfaces two sets of codes:

*Sift-local mode/contract codes* (NOT from `@oxdeai/core`):

| Code | Trigger |
|------|---------|
| `KRL_UNSIGNED_IN_SIGNED_REQUIRED` | Unsigned KRL rejected in `signed_required` before `verifyKrl` is called |
| `KRL_MISSING_VERIFY_CALLBACK` | KRL has a `signature` field but no `verifyKrl` configured |
| `KRL_VERIFY_CALLBACK_ERROR` | `verifyKrl` callback threw unexpectedly |
| `KRL_VERIFY_RESULT_INCOMPLETE` | `verifyKrl` returned `ok: true` without `accepted` metadata |
| `KRL_WATERMARK_LOAD_FAILED` | *(Phase A, #117)* `KrlWatermarkStore.list()` failed before verification; refresh fails closed before `verifyKrl` is called |
| `KRL_WATERMARK_PERSIST_FAILED` | *(Phase A, #117)* Signed KRL verified but `KrlWatermarkStore.set()` failed; refresh fails closed before cache swap |

**Last-known-good signed-KRL cache (Phase B, #117).** `SignedKrlCache` is an opt-in interface that stores signed KRL payloads for cold-start and fetch-failure resilience. A cached payload is **never trusted without re-verification** through the configured `verifyKrl` callback. LKG re-verification uses existing reason codes; no new codes are introduced. LKG write is best-effort and non-fatal after durable watermark persistence. `krlStatus.lkgCacheActive` and `lkgVerifiedAt` surface LKG state without exposing payload or key material. `RT-TRUST-2` is closeable when `signed_required` + `KrlWatermarkStore` + `SignedKrlCache` are all configured; without all three, residual risks remain.

*Core KRL codes* (passed through from `verifyKrl` as opaque strings):
`KRL_MALFORMED`, `KRL_SIG_INVALID`, `KRL_EXPIRED`, `KRL_UNSUPPORTED_ALG`,
`KRL_UNKNOWN_SIGNING_KID`, `KRL_SIGNING_KEY_INACTIVE`, `KRL_VERSION_REGRESSION`.

**Cross-language SignedKRLV1 conformance.** The Go harness now independently verifies
all 9 SignedKRLV1 portable vectors (`docs/spec/test-vectors/signed-krl-v1.json`) using
Go's `crypto/ed25519` standard library. Each vector contains a committed `SignedKRLV1`
artifact; the harness reconstructs the `OXDEAI_KRL_V1` signing preimage independently
using canonicalization-v1 and verifies the Ed25519 signature without consuming any
TypeScript-generated intermediate artifact. Python cross-language coverage is also complete - `python-harness/verify_signed_krl_vectors.py` uses ctypes + libcrypto for independent Ed25519 verification.

---

### 2.3 Profile C - Full Semantic State Verification

**Summary:** Extends Profile B with live-state re-verification. The verifier re-computes
`state_hash` from the live state snapshot using the same canonicalization function the
provider used at signing time. Requires `OxDeAIGuard` (not `createPepGatewayExecutor`).

Profile C requires:

- `OxDeAIGuard` with `getState` and `setState` configured
- `computeStateHash` configured to match the provider's signing-time algorithm

#### 2.3.1 Additional Provider Requirements (beyond Profile B)

| Requirement | Specification |
|---|---|
| `state_hash` algorithm | Must be documented, stable, and deterministic for ASCII-safe state content |
| Algorithm disclosure | The canonicalization function name and version must be communicated to the verifier operator at deployment time |

#### 2.3.2 Additional Verifier Requirements (beyond Profile B)

| Check | Enforcement |
|---|---|
| `computeStateHash` configured | Must match provider's signing-time algorithm |
| Live-state hash match | `computeStateHash(state)` == `authorization.state_hash` | `OxDeAIAuthorizationError` |
| CAS commit | State committed atomically after verification, before execution |
| `computeStateHash` throws | Caught; wrapped in `OxDeAIAuthorizationError` → DENY |

#### 2.3.3 Hash Strategy Alignment Requirement

```text
REQUIRED: computeStateHash at verification == hash function used by provider at signing

MISCONFIGURED (fail-closed, but blocks legitimate execution):
  Provider signed with siftCanonicalJsonHash
  Verifier uses engine.computeStateHash (Core default)
  → deterministic mismatch → DENY every time
```

The guard cannot detect whether a state_hash mismatch is due to actual state change or
wrong hash strategy - both produce DENY. Deployers must ensure alignment.

**Hash strategy alignment is necessary but not sufficient for Profile C compliance.** A deployment that correctly aligns `computeStateHash` but does not satisfy the minimum state provider integrity requirements defined in `docs/spec/state-provider-requirements.md` retains the RT-TRUST-1 residual risk: the guard verifies that the live state object hashes correctly against the authorization artifact, but cannot verify that the state provider is honest, current, or authoritative. State provider integrity requirements are minimum compliance for Profile C deployments.

#### 2.3.4 Cross-language conformance

Go and Python harnesses now validate **all 8 Profile C vectors** independently via
`docs/spec/test-vectors/profile-c-state-verification.json`:

- **Modes 001–005** (state-hash semantics): canonicalization-v1 + SHA-256 only
- **Modes 006–008** (Encoding B): additionally require independent Encoding B
  AuthorizationV1 signature verification (`alg: "ed25519"` lowercase, `expires_at`,
  base64url signature, **no domain prefix**)

For Encoding B modes, each harness:
1. Independently reconstructs the signing payload from the committed artifact
   (all fields + `signature.{alg,kid}`, excluding `signature.sig`)
2. Computes `canonicalJson(signingPayload)` - no domain prefix (distinct from
   SignedKRLV1 which uses `OXDEAI_KRL_V1\n`)
3. Verifies the Ed25519 signature (Go: `crypto/ed25519`; Python: `ctypes + libcrypto`)
4. Cross-checks independently-computed `committedHash` against committed `auth.state_hash`
   (byte-equivalence proof - any divergence is a harness canonicalization bug)
5. Compares `liveHash` vs `committedHash` for the state-hash outcome

No protocol semantics were changed. This is conformance coverage, not a runtime security change.

#### 2.3.5 Distinguishing Profile B and Profile C

| Concern | Profile B | Profile C |
|---|---|---|
| `state_hash` tampering | Detected (signature) | Detected (signature + live re-verify) |
| Stale state from TOCTOU | Not detected | Detected (live re-verify) |
| Wrong hash strategy | Not detected | Causes DENY (misconfiguration) |
| Requires live state access | No | Yes (`getState`) |
| Supported by | `createPepGatewayExecutor`, `OxDeAIGuard` | `OxDeAIGuard` only |

---

## 3. Wire Encoding Reference

### 3.1 Encoding A - Core-native

See [`docs/spec/artifacts/authorization-v1.md §5.1`](../artifacts/authorization-v1.md) for the normative definition.

```json
{
  "auth_id": "...",
  "issuer": "...",
  "audience": "...",
  "decision": "ALLOW",
  "intent_hash": "<lowercase hex sha256>",
  "state_hash":  "<lowercase hex sha256>",
  "policy_id":   "...",
  "issued_at":   1712448000,
  "expiry":      1712448060,
  "alg":         "Ed25519",
  "kid":         "...",
  "signature":   "<base64-string>"
}
```

Or with nested signature object:

```json
{
  "signature": { "alg": "Ed25519", "kid": "...", "sig": "<base64-string>" }
}
```

### 3.2 Encoding B - Sift-compatible

```json
{
  "auth_id":     "...",
  "issuer":      "...",
  "audience":    "...",
  "decision":    "ALLOW",
  "intent_hash": "<lowercase hex sha256>",
  "state_hash":  "<lowercase hex sha256>",
  "policy_id":   "...",
  "issued_at":   1712448000,
  "expires_at":  1712448060,
  "signature": {
    "alg": "ed25519",
    "kid": "...",
    "sig": "<base64url-string>"
  }
}
```

### 3.3 Expiry Field Resolution

Verifiers MUST resolve effective expiry as:

1. If `expiry` present and integer: use `expiry`
2. Else if `expires_at` present and integer: use `expires_at`
3. Else: reject with `AUTH_MISSING_FIELD`

### 3.4 Rejected Encodings

The following are explicitly rejected. No fallback, no partial acceptance:

| Value | Rejection reason | Error code |
|---|---|---|
| `alg: "EdDSA"` | Different algorithm family | `AUTH_ALG_UNSUPPORTED` |
| `alg: "ED25519"` | All-caps variant; not accepted | `AUTH_ALG_UNSUPPORTED` |
| `alg: "ed448"` | Different curve | `AUTH_ALG_UNSUPPORTED` |
| Any other `alg` string | Not a recognized identifier | `AUTH_ALG_UNSUPPORTED` |
| Neither `expiry` nor `expires_at` | Missing required field | `AUTH_MISSING_FIELD` |
| `decision` != `"ALLOW"` | Non-ALLOW decisions not valid for execution | Reject |

---

## 4. Provider Responsibilities

A provider or adapter claiming OxDeAI interoperability MUST:

### 4.1 Artifact Production

- Produce a structurally valid `AuthorizationV1` with all required semantic fields
- Set `decision: "ALLOW"` only when the authorization is meant to permit execution
- Produce `auth_id` values that are:
  - globally unique (collision probability negligible)
  - cryptographically random or UUID-based
  - single-use (the provider must not reuse `auth_id` values)

### 4.2 Deterministic Signing Payload

- Produce a deterministic canonical signing payload per the chosen encoding
- For Encoding A: `"OXDEAI_AUTH_V1\n"` + `canonicalJson(payload_without_sig_bytes)`
- For Encoding B: `canonicalJson(payload_without_sig_bytes)` (no prefix)
- Key ordering in the canonical JSON must follow `canonicalization-v1` (sorted keys)

### 4.3 Key Identity and Lifecycle

- Assign a stable `kid` to each signing key
- Publish the public key under the same `kid` and `issuer` to all verifiers before signing
- Rotate keys per the [key custody and rotation guide](../../architecture/key-custody-and-rotation.md)
- Never reuse a revoked `kid`

### 4.4 Expiry Semantics

- Set `expiry` (or `expires_at`) to an absolute Unix timestamp in the future relative to `issued_at`
- Do not issue authorizations with expiry in the past
- Size expiry windows to accommodate expected delivery and execution latency plus clock skew buffer

### 4.5 Intent Hash

- Compute `intent_hash` = SHA-256 hex of `canonicalJson(intent)` per `canonicalization-v1`
- The intent object canonicalized must be semantically identical to the action the guard will recompute at verification time
- Do not include fields that the verifier will not have access to

### 4.6 State Hash

- Compute `state_hash` using a documented, stable, deterministic canonicalization function
- Document and communicate the function name/version to verifier operators
- For Profile C: the function must be configured as `computeStateHash` at the guard

### 4.7 Replay Safety

- Never issue the same `auth_id` twice
- Declare/configure the replay domain and retain consumed IDs while any verifier
  in that domain could otherwise still accept the authorization.
- `max(1, expiry − now)` is the current Redis adapter's TTL calculation, not a
  generic clock-skew or durability guarantee. Validate its alignment with all
  verifier clocks/acceptance windows; see the non-normative
  [TTL guide](../../architecture/replay-store-ttl-alignment.md).
- Profiles A/B/C require atomic, fail-closed consumption before protected
  execution under [verification §4.3](../verification/verification-v1.md#43-replay-store-contract-and-deployment-boundary).
  Unavailable/indeterminate required replay state MUST block execution.
- Consumption spends the entitlement; it does not prove an effect occurred.
  Restart resistance, replica visibility and recovery require deployment evidence.

---

## 5. Verifier Responsibilities

A verifier claiming OxDeAI compliance MUST enforce, in order:

| Step | Check | Required for |
|---|---|---|
| 1 | Algorithm recognized (`"Ed25519"` or `"ed25519"` only) | Profile A, B, C |
| 2 | `kid` + `issuer` resolves to active key in `trustedKeySets` | Profile A, B, C |
| 3 | `audience` matches `expectedAudience` | Profile A, B, C |
| 4 | `issuer` matches `expectedIssuer` (if configured) | Profile A, B, C |
| 5 | Effective expiry present and `now < expiry` | Profile A, B, C |
| 6 | Ed25519 signature verifies against canonical preimage | Profile A, B, C |
| 7 | `decision == "ALLOW"` | Profile A, B, C |
| 8 | `auth_id` consumed atomically (replay store) | Profile A, B, C |
| 9 | `intent_hash` matches recomputed intent hash | Profile A, B, C |
| 10 | `state_hash` matches `computeStateHash(state)` | Profile C only |
| 11 | CAS state commit before execution | Profile C only |

Any step failure MUST result in DENY with no execution. Steps MUST NOT be skipped or reordered.

### 5.1 `trustedKeySets` Handling

- Reject any authorization whose `issuer` is not present in `trustedKeySets`
- Reject any authorization whose `kid` is not present in the issuer's keyset
- Reject any authorization whose key has `status: "revoked"`
- Reject any authorization presented before a key's `not_before` or after its `not_after`
- Empty `trustedKeySets` → hard failure at guard construction; no verifications proceed

### 5.2 Ambiguity Handling

Any ambiguity → DENY:

- Two keys with the same `kid` in one issuer's keyset → first match wins; deployer must ensure uniqueness
- Neither `expiry` nor `expires_at` present → reject
- Unrecognized `alg` value → reject
- `computeStateHash` throws → reject

---

## 6. Interoperability Matrix

| Integration pattern | Wire encoding | Signing preimage | Sig encoding | Replay | State verification | Required guard | Production readiness |
|---|---|---|---|---|---|---|---|
| Core-native (Profile A) | Encoding A | Domain-prefixed | Base64 | `consumeAuthId` | Signature integrity only | `createPepGatewayExecutor` or `OxDeAIGuard` | Production |
| Sift adapter (Profile B) | Encoding B | No prefix | Base64url | `consumeAuthId` | Signature integrity only | `createPepGatewayExecutor` or `OxDeAIGuard` | Production |
| Sift + live state (Profile C) | Encoding B | No prefix | Base64url | `consumeAuthId` | Signature + `siftCanonicalJsonHash` | `OxDeAIGuard` + `computeStateHash` | Production |
| Core + live state (Profile C, Core) | Encoding A | Domain-prefixed | Base64 | `consumeAuthId` | Signature + `engine.computeStateHash` | `OxDeAIGuard` | Production |
| Gateway-only (no live state) | A or B | A or B | A or B | `consumeAuthId` | Signature integrity only | `createPepGatewayExecutor` | Production (reduced state guarantees) |
| Development / test | A or B | A or B | A or B | In-memory store | Signature or none | Any | Development only |

### Notes

- `createPepGatewayExecutor` supports Profiles A and B (gateway-level only; no live-state access)
- `OxDeAIGuard` supports Profiles A, B, and C (with `computeStateHash` for B and C)
- Profile C requires `OxDeAIGuard`, `getState`, `setState`, and `computeStateHash` correctly configured
- An in-memory store can exercise the implementation contract within its instance
  lifetime. It does not establish replay protection across process restarts or
  separate store instances.
- “Production” in this integration matrix describes an available integration
  surface, not certification of replay-store durability, topology, replica
  visibility, backend persistence configuration, HA/SLA or recovery. Deployment
  suitability must be assessed against the declared replay domain.

---

## 7. Conformance Vector Coverage

The following table maps verification checks to existing conformance vectors and marks gaps.

### 7.1 Covered by Existing Vectors

| Check | Vector file | Vector ID(s) | Profile |
|---|---|---|---|
| Valid Core-native authorization | `authorization-signature-verification.json` | `authorization-sig-001` | A |
| Invalid signature | `authorization-signature-verification.json` | `authorization-sig-002` | A |
| Wrong `kid` | `authorization-signature-verification.json` | `authorization-sig-003` | A |
| Wrong issuer | `authorization-signature-verification.json` | `authorization-sig-004` | A |
| Wrong audience | `authorization-signature-verification.json` | `authorization-sig-005` | A |
| Tampered field | `authorization-signature-verification.json` | `authorization-sig-006` | A |
| Expired authorization | `authorization-signature-verification.json` | `authorization-sig-007` | A |
| Replay (`auth_id` reuse) | `authorization-signature-verification.json` | `authorization-sig-008` | A |
| Unknown algorithm | `authorization-signature-verification.json` | `authorization-sig-009` | A |
| Valid Sift wire format (Encoding B) | `authorization-signature-verification.json` | `authorization-sig-010` | B |
| Unsupported alg `"EdDSA"` | `authorization-signature-verification.json` | `authorization-sig-011` | A, B |
| Unsupported alg `"ED25519"` | `authorization-signature-verification.json` | `authorization-sig-012` | A, B |
| `expires_at` accepted (no `expiry`) | `authorization-verification.json` | `authorization-verify-009` | B |
| `expires_at` expired | `authorization-verification.json` | `authorization-verify-010` | B |
| Intent hash mismatch | `intent-hash.json` | intent-hash vectors | A, B, C |
| State hash mismatch | `guard.state-binding.test.ts` | SB-2, SB-6, SB-10, SB-12 | C |
| `computeStateHash` throws | `guard.state-binding.test.ts` | SB-4, SB-7, SB-13 | C |
| Pluggable `computeStateHash` match | `guard.state-binding.test.ts` | SB-9, SB-11 | C |
| Revoked key (status) | `packages/core/src/crypto/signatures.ts` (`keyIsActiveAt`) | Unit coverage | A, B |
| Sift → Guard full integration | `guard-integration.test.ts` | GUARD/ALLOW, GUARD/DENY, etc. | B |

### 7.2 Required Future Vectors

The following checks are enforced by the implementation but lack standalone conformance vectors. They are marked as **required future vectors** for cross-implementation conformance testing.

| Check | Status | Notes |
|---|---|---|
| Valid Profile C authorization (live state match) | Required future vector | Covered by guard tests but not a standalone portable vector |
| Profile C state hash mismatch (TOCTOU) | Required future vector | Covered by SB-6 in guard tests |
| Profile C hash strategy mismatch | Required future vector | Covered by SB-12 in guard tests |
| Revoked key (`status: "revoked"`) in portable vector format | Required future vector | `keyIsActiveAt` tested in unit; no conformance vector file |
| Key `not_before` future activation | Required future vector | Enforced; no vector |
| Key `not_after` expiration | Required future vector | Enforced; no vector |
| `decision` ≠ `"ALLOW"` rejected | Required future vector | Enforced; no isolated vector |
| Both `expiry` and `expires_at` present (precedence) | Required future vector | Spec defines `expiry` takes precedence; no vector |
| Profile B adapter trust separation | Required future vector | Integration tested but not as portable vector |

---

## 8. Fail-Closed Rules

All of the following conditions MUST result in DENY with no execution. There is no fallback,
no partial acceptance, and no advisory-only path.

| Condition | Error / behavior | Enforcement point |
|---|---|---|
| Unknown `alg` string | `AUTH_ALG_UNSUPPORTED` | Verifier step 1 |
| `alg: "EdDSA"` | `AUTH_ALG_UNSUPPORTED` | Verifier step 1 |
| `alg: "ED25519"` (all-caps) | `AUTH_ALG_UNSUPPORTED` | Verifier step 1 |
| Unknown `kid` or `issuer` | `AUTH_KID_UNKNOWN` / `AUTH_ISSUER_MISMATCH` | Verifier step 2 |
| Key `status: "revoked"` | `AUTH_KID_UNKNOWN` | Verifier step 2 |
| Key `not_before` not yet reached | `AUTH_KID_UNKNOWN` | Verifier step 2 |
| Key `not_after` exceeded | `AUTH_KID_UNKNOWN` | Verifier step 2 |
| Audience mismatch | `AUTH_AUDIENCE_MISMATCH` | Verifier step 3 |
| Issuer mismatch | `AUTH_ISSUER_MISMATCH` | Verifier step 4 |
| Neither `expiry` nor `expires_at` | `AUTH_MISSING_FIELD` | Verifier step 5 |
| Authorization expired | `AUTH_EXPIRED` | Verifier step 5 |
| Signature invalid | `AUTH_SIGNATURE_INVALID` | Verifier step 6 |
| `decision` ≠ `"ALLOW"` | Reject | Verifier step 7 |
| `auth_id` replay | `AUTH_REPLAY` | Verifier step 8 |
| Replay store throws | `OxDeAIAuthorizationError` | Verifier step 8 |
| Intent hash mismatch | `INTENT_HASH_MISMATCH` | Verifier step 9 |
| `state_hash` mismatch (live) | `OxDeAIAuthorizationError` | Verifier step 10 (Profile C) |
| `computeStateHash` throws | `OxDeAIAuthorizationError` | Verifier step 10 (Profile C) |
| CAS state conflict | `OxDeAIConflictError` | Verifier step 11 (Profile C) |
| `trustedKeySets` empty at construction | Hard failure | Guard construction |
| Unknown provider profile / ambiguous encoding | `AUTH_ALG_UNSUPPORTED` | Verifier step 1 |

---

## 9. Deployment Guidance by Profile

### Profile A: Core-native

- Use `@oxdeai/core`'s `signAuthorizationEd25519` or equivalent
- Configure `expectedAudience` at the guard
- At boundaries that accept an externally supplied `AuthorizationV1` (PEP gateway,
  delegation `parentAuth`), implementations **MUST** configure issuer-policy authority
  as complete `(issuer, policyId)` pairs. A trusted signing key is not policy authority:
  a valid signature only proves that a trusted key for the *claimed* issuer signed the
  artifact (#301). Missing authority configuration **MUST** fail closed.
- Use a replay store satisfying the atomicity, retention and fail-closed contract
  for the declared replay domain; assess restart and cross-instance guarantees
  separately for the deployment. No backend technology is mandated.
- No `computeStateHash` configuration needed

### Profile B: External provider wire-compatible

- Adapter produces `AuthorizationV1` in Encoding B format
- Adapter's Ed25519 public key published in `trustedKeySets` under the adapter's `issuer` label
- External provider receipt trust root is separate from OxDeAI trust root
- `computeStateHash` not required (signature integrity protects `state_hash`)
- Use `createPepGatewayExecutor` or `OxDeAIGuard`

### Profile C: Full semantic state verification

- All Profile B requirements plus:
- `OxDeAIGuard` with `getState`, `setState` configured
- `computeStateHash` configured to match the provider's signing-time algorithm
- Deployer must align `computeStateHash` with provider's algorithm (e.g., `siftCanonicalJsonHash` for Sift adapter)
- Verify alignment before production deployment: test that `computeStateHash(state)` == `authorization.state_hash` for a known authorization

---

## 10. Provider Onboarding Checklist

```
ARTIFACT PRODUCTION
[ ] AuthorizationV1 artifact structure correct (all required fields)
[ ] decision: "ALLOW" set only for permitted executions
[ ] auth_id is cryptographically random and globally unique

WIRE ENCODING
[ ] Profile A: alg="Ed25519", expiry, base64 sig, domain-prefixed preimage
[ ] Profile B: alg="ed25519", expires_at, base64url sig, no domain prefix

KEY SETUP
[ ] Ed25519 keypair generated and private key secured
[ ] Public key published to trustedKeySets before signing
[ ] kid is unique and stable; not reused after revocation

INTENT AND STATE
[ ] intent_hash computed from canonicalized intent per canonicalization-v1
[ ] state_hash algorithm documented and communicated to verifier operator
[ ] Profile C: computeStateHash configured at guard to match signing algorithm

REPLAY SAFETY
[ ] auth_id values never reused
[ ] Expiry window sized for delivery + execution latency + clock skew

INTEGRATION TESTING
[ ] Valid authorization passes guard
[ ] Tampered state_hash rejected (AUTH_SIGNATURE_INVALID)
[ ] Replay rejected (AUTH_REPLAY)
[ ] Intent mismatch rejected (INTENT_HASH_MISMATCH)
[ ] Expired authorization rejected (AUTH_EXPIRED)
[ ] Wrong audience rejected (AUTH_AUDIENCE_MISMATCH)
```
