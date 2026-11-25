# Sift Integration

Sift as governance layer, OxDeAI as execution authorization boundary.

---

## 1. Architecture

Sift is a policy decision layer. It produces Ed25519-signed receipts for ALLOW/DENY decisions.
OxDeAI is an execution enforcement layer. It requires `AuthorizationV1` before any side effect executes.

These are distinct responsibilities. A Sift receipt is not `AuthorizationV1`. It cannot trigger execution directly. The adapter is the only component that may translate a Sift receipt into `AuthorizationV1`, and only after local verification, deterministic normalization, and explicit state and audience binding.

```text
Agent
  │
  ▼
Sift                                    ← governance decision
  │  Ed25519-signed receipt
  ▼
Sift→OxDeAI adapter                     ← verify, normalize, bind
  │  verified + normalized + bound inputs
  ▼
OxDeAI PDP / Authorization Issuer       ← issues AuthorizationV1
  │  AuthorizationV1
  ▼
PEP Gateway                             ← non-bypassable enforcement boundary
  │
  ▼
Execution
```

Nothing upstream of the PEP Gateway can authorize execution.

---

## 2. Integration Model

### Step-by-step flow

1. **Agent requests authorization from Sift.**
   The agent submits a proposed action (tool, parameters, context) to Sift.

2. **Sift returns a signed receipt.**
   The receipt contains the decision (`ALLOW`/`DENY`), action metadata, nonce, and timestamp.
   It is signed with an Ed25519 key identified by a `kid` that corresponds to an entry in the Sift JWKS endpoint.

3. **Adapter verifies the receipt signature locally.**
   The adapter MUST verify the Ed25519 signature against a trusted Sift public key before any transformation occurs.
   The public key is a raw 32-byte Ed25519 key obtained by decoding the JWKS `x` field (base64url, no padding) for the matching `kid`.
   Verification MUST be performed locally. The adapter MUST NOT call a remote `/verify-receipt` endpoint at execution time.

4. **Adapter validates receipt fields.**
   - `decision == ALLOW` — any non-ALLOW value MUST halt the flow immediately
   - freshness — `timestamp` MUST be within the adapter's configured bounded window
   - replay protection — the mapped `auth_id` MUST NOT have been previously consumed

5. **Adapter normalizes intent deterministically.**
   The adapter MUST transform Sift receipt fields into a deterministic OxDeAI intent object conforming to canonicalization-v1.
   Normalization MUST be deterministic: equivalent Sift receipts MUST produce byte-identical canonical intent.

6. **Adapter derives and hashes state.**
   The adapter MUST derive a deterministic policy state snapshot and compute `state_hash` over its canonical form.
   Sift receipts carry no state context. The adapter MUST supply this from the execution environment.

7. **Adapter binds audience.**
   The adapter MUST inject the audience identifier for the target PEP Gateway.
   Sift receipts carry no audience binding. The adapter MUST supply this from trusted configuration.

8. **Adapter issues `AuthorizationV1`.**
   After all verification, normalization, state derivation, and binding steps succeed, the adapter MUST produce an `AuthorizationV1` artifact.
   `AuthorizationV1` is the only artifact the PEP Gateway accepts to authorize execution.

9. **PEP Gateway verifies `AuthorizationV1`.**
   The PEP verifies signature, audience, expiry, intent binding, state binding, policy binding, and replay protection.

10. **Execution is allowed or denied.**
    Execution occurs only if all PEP verification steps pass. Any failure MUST produce DENY and MUST NOT allow execution.

### Invariant

> No valid `AuthorizationV1` → no execution path.

A Sift receipt MUST NOT directly authorize execution. A receipt alone cannot trigger execution under any condition.

---

## 3. Field Mapping: Sift → OxDeAI

| Sift field      | OxDeAI mapping                  | Notes / Required Adapter Logic                                                                      |
|-----------------|----------------------------------|------------------------------------------------------------------------------------------------------|
| `action`        | `intent.action`                 | Requires deterministic normalization to a stable OxDeAI action type                                 |
| `tool`          | `intent.tool`                   | Direct mapping if stable and unambiguous; MUST be validated before use                              |
| `decision`      | validation gate only             | Only `ALLOW` proceeds to normalization; all other values MUST result in DENY before `AuthorizationV1` issuance |
| `nonce`         | replay input / `auth_id` mapping | MUST be explicitly mapped to `auth_id`; Sift and OxDeAI replay semantics are not identical         |
| `timestamp`     | freshness input / `issued_at` derivation | Requires a bounded freshness policy; stale receipts MUST be rejected                     |
| `receipt_hash`  | integrity input only             | NOT equivalent to OxDeAI `intent_hash`; equivalence requires the adapter to define and prove the mapping |

### Gaps the adapter MUST fill

**Audience** — Sift receipts carry no audience binding. Without it, an `AuthorizationV1` issued for one service could be replayed against another. The adapter MUST inject the trusted audience identifier from its own configuration before issuing `AuthorizationV1`.

**State binding** — Sift receipts carry no policy state reference. Without it, a receipt issued under one policy state could be replayed after state has changed. The adapter MUST derive, canonicalize, and hash the current execution-relevant policy state and bind it as `state_hash`.

**Canonical intent** — Sift action fields are not in OxDeAI canonical form. The adapter MUST normalize them into deterministic canonical bytes under canonicalization-v1 before computing `intent_hash`. Canonicalization failure MUST produce DENY.

---

## Receipt Verification (Normative)

- The adapter MUST verify the Sift receipt locally using Ed25519 and the tenant public key.
- The adapter MUST verify the integrity of the signed receipt payload **before** any transformation, normalization, or field extraction occurs.
- The adapter MUST NOT mutate, reinterpret, or normalize signed receipt fields prior to signature and integrity verification. Verification operates over the original signed payload.
- The adapter MUST NOT call `/verify-receipt` or any remote Sift endpoint in the runtime execution path. Remote verification introduces a network dependency that would produce indeterminate outcomes on failure, violating the fail-closed invariant.
- The following conditions MUST result in DENY and MUST NOT proceed to `AuthorizationV1` issuance:

| Condition                         | Required behavior   |
|-----------------------------------|----------------------|
| Invalid Ed25519 signature         | DENY, no execution  |
| Unknown or untrusted key          | DENY, no execution  |
| Revoked key (KRL check required)  | DENY, no execution  |
| Malformed receipt payload         | DENY, no execution  |
| `receipt_hash` integrity mismatch | DENY, no execution  |
| Verification ambiguity            | DENY, no execution  |

### Receipt hash integrity

`receipt_hash` MUST be computed over the canonical JSON payload with:

- `signature` excluded
- `receipt_hash` excluded

Canonicalization requirements (Sift wire format):

- lexicographic key ordering
- no whitespace between tokens
- `ensure_ascii=True` — every UTF-16 code unit above U+007F is escaped as `\uXXXX` (lowercase four-digit hex); supplementary characters (U+10000+) are encoded as two `\uXXXX` surrogate escapes each
- UTF-8 encoding of the resulting ASCII-only string

Equivalent to Python:
```python
json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
```

The adapter MUST:

1. recompute the hash locally
2. compare with the provided `receipt_hash`
3. only proceed if they match

### Signature verification scope

The Ed25519 signature is verified over the canonical payload with:

- `signature` excluded
- `receipt_hash` INCLUDED

This enforces the sequence:

```text
payload → integrity check (receipt_hash) → signature verification
```

The adapter MUST NOT:
- verify signature before validating `receipt_hash`
- mutate payload before verification

The signature is a raw Ed25519 signature over the UTF-8 bytes of the Sift-canonical JSON of the signed scope.
It is encoded as base64url without padding (RFC 4648 §5).

### Verification ordering

The adapter MUST perform verification in the following order:

1. Structural validation (field presence, types)
2. Version check (supported receipt_version values)
3. `receipt_hash` integrity validation
4. Ed25519 signature verification
5. Semantic validation (decision, freshness, replay prechecks, etc.)

The adapter MUST NOT proceed to a later step if an earlier step fails.
Integrity and authenticity checks MUST complete before any semantic interpretation of receipt fields.

### Key management and JWKS/KRL surface

The adapter verifies Sift receipts using trusted Ed25519 public keys distributed via the Sift JWKS endpoint.

**Key format.** Sift public keys are raw 32-byte Ed25519 key material encoded as the `x` field in a JWKS entry (RFC 8037 OKP). No PEM wrapper is required or expected at this boundary.

JWKS entry shape:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "alg": "EdDSA",
  "use": "sig",
  "kid": "<key-id>",
  "x": "<base64url-no-padding 32-byte raw public key>"
}
```

The `alg: "EdDSA"` field is JWKS metadata for key-discovery tooling. It is distinct from the `AuthorizationV1.signature.alg` runtime literal (see §4). Do not conflate these two surfaces.

**`kid` resolution.** The `kid` identifying the signing key is present in the receipt. The adapter MUST use it to select the correct JWKS entry. The adapter MUST NOT guess or fall back to an arbitrary key.

**KRL enforcement.** The Sift verifier contract provides a Key Revocation List (KRL). The adapter MUST check the KRL before trusting any key:

1. Extract `kid` from the receipt.
2. Check `kid` against the KRL. If revoked → DENY immediately; do not proceed to signature verification.
3. Look up the JWKS entry for `kid`. If not found → attempt a JWKS refresh (cache may be stale). Retry once.
4. If still not found after refresh → DENY. Do not guess.
5. Decode `x` (base64url → 32 bytes) and verify the signature.

**Minimum requirements:**

- support multiple active keys identified by `kid`
- check the KRL before trusting any key
- refresh JWKS on unknown `kid` before failing closed
- fail closed if the key cannot be resolved after refresh
- no fallback guessing
- deterministic key selection

**KRL payload integrity limitation.**

`SiftHttpKeyStore` checks whether a `kid` appears in the fetched KRL, but does NOT verify a cryptographic signature over the KRL payload itself.

KRL payload integrity therefore depends on transport security (HTTPS to a trusted endpoint). A compromised intermediary — a CDN edge, a stale unsigned cache, or a man-in-the-middle — could return a modified KRL that omits specific revoked kids, allowing a revoked Sift signing key to pass the revocation check.

Unknown and revoked kids still fail closed:
- `kid` in `revoked_kids` → `REVOKED_KID` immediately
- `kid` not found after one refresh attempt → `UNKNOWN_KID` (no guessing)

Production deployments that require cryptographic revocation integrity MUST wait for the Sift protocol to define and publish a KRL signing contract. Until that contract exists, revocation guarantees depend on the trustworthiness of the transport and the hosting endpoint.

**Do not assert that KRL revocation is cryptographically enforced end-to-end without a signed KRL contract from Sift.**

---

## Intent Normalization (Normative)

- The adapter MUST transform the Sift receipt into a deterministic OxDeAI intent object.
- The normalization output MUST be canonicalizable under canonicalization-v1. It MUST produce stable, key-order-independent canonical bytes for identical inputs.
- The normalization output MUST exclude non-deterministic metadata (e.g., request timestamps, trace IDs, session tokens) unless such metadata is explicitly part of the intended action and is required for policy evaluation.
- The adapter MUST define the exact transformation from Sift fields to OxDeAI intent fields. This mapping MUST be fixed and version-controlled. Differing normalization logic across implementations would produce different `intent_hash` values for the same Sift receipt, making PEP intent binding unreliable. This MUST be prohibited.
- If the adapter cannot deterministically derive intent from the receipt and execution request, it MUST DENY.

Example canonical intent shape:

```json
{
  "type": "EXECUTE",
  "tool": "<receipt.tool>",
  "params": {
    "amount": 500,
    "currency": "USD",
    "destination": "acct_9f3a"
  }
}
```

`intent_hash` is computed as SHA-256 over the Sift-canonical JSON bytes of this object (ensure_ascii=True, sort_keys). It is NOT derived from `receipt_hash` unless the adapter's normalization contract explicitly defines and proves that relationship.

---

## Parameter Binding Guarantee

### What Sift signs

A Sift receipt is an Ed25519-signed attestation that a specific **tool** (identified by `receipt.tool`) matched a specific **policy** (identified by `receipt.policy_matched`) for a specific **action** (identified by `receipt.action`) at a given point in time.

**Sift receipts do NOT include parameter values. Sift's signature does NOT cover the specific parameters submitted for evaluation.**

### What `intent_hash` commits to

`AuthorizationV1.intent_hash` is the SHA-256 of the Sift-canonical JSON of the intent object supplied by the adapter. That intent object contains `type`, `tool`, and `params`.

The `params` are **supplied by the adapter from the execution context** — they are NOT extracted from the Sift receipt.

Therefore:

```text
intent_hash commits to:  adapter-supplied params
                         (what the adapter says will be executed)

NOT to:                  params that Sift evaluated
                         (what Sift was actually asked about)
```

### Security boundary

A mismatch between the parameters Sift evaluated and the parameters the adapter supplies is **NOT detectable from the receipt alone**. The PEP detects a mismatch only if it independently recomputes `intent_hash` from the actual execution call at the moment of execution and finds a hash collision — which it will, if params differ between authorization issuance and execution. But the PEP cannot determine what Sift originally approved.

This means:

- Sift provides **action-level authorization**: it approves `tool X` under `policy Y`.
- Sift does NOT provide **parameter-level cryptographic binding**: it does not prove that specific parameter values were approved.

### Invariant

> **Parameter mismatch between Sift evaluation and execution is NOT detectable from the receipt alone.**

The adapter is responsible for ensuring that the params it injects into the intent faithfully represent the params it intends to execute. There is no protocol-level mechanism to verify this at the Sift receipt boundary.

### Security warning

If parameter-level guarantees are required by the deployment's threat model, Sift MUST be extended to include a `params_hash` field (SHA-256 of Sift-canonical params) in the signed receipt payload. The adapter MUST then verify:

```text
params_hash == SHA-256(sift_canonical(adapter_params))
```

before calling `normalizeIntent`. Without this, parameter-level enforcement relies entirely on the adapter's own integrity.

**Do not treat `AuthorizationV1.intent_hash` as evidence that Sift evaluated the specific parameter values bound by that hash.**

### Future extension path (DO NOT IMPLEMENT until Sift protocol adds support)

When Sift adds `params_hash` to the signed receipt:

```json
{
  "params_hash": "<sha256-hex of sift_canonical(params)>",
  ...
}
```

The adapter MUST add a verification step between `verifyReceipt` and `normalizeIntent`:

```text
recompute = sha256(sift_canonical(adapter_params))
assert recompute == receipt.params_hash  → DENY if mismatch
```

Until that field exists in the Sift receipt contract, this check cannot be performed and the parameter binding gap remains.

---

## State Binding (Normative)

- The adapter MUST produce a deterministic state snapshot for `AuthorizationV1.state_hash`.
- The state snapshot MUST represent the execution-relevant context at the time of authorization. Examples of execution-relevant state include:
  - available budget or spending capacity
  - account or permission state
  - resource quota or rate-limit counters
  - prior execution or consumption history relevant to policy
- The state snapshot MUST be canonicalized under canonicalization-v1 (ensure_ascii=True) before hashing. The same state content MUST produce the same `state_hash` regardless of field insertion order.
- If the required state cannot be deterministically derived, validated, or hashed, the adapter MUST DENY.
- State ambiguity MUST NOT fall back to receipt-only authorization. There is no partial state binding.

---

## Audience Binding

- The adapter MUST set `AuthorizationV1.audience` to the specific PEP Gateway identifier or execution boundary identifier for which the authorization is valid.
- The audience value MUST be explicit, deterministic, and sourced from trusted adapter configuration. It MUST NOT be derived from the Sift receipt.
- The PEP Gateway MUST enforce exact audience matching. The presented `AuthorizationV1.audience` MUST equal the PEP's own configured identifier.
- Audience mismatch MUST result in DENY and MUST NOT allow execution.
- Sift does not provide native audience binding in the receipt contract. This binding is introduced entirely by the OxDeAI adapter during `AuthorizationV1` issuance.

---

## Time Validation

- The adapter MUST validate receipt freshness using explicit, bounded time rules before proceeding.
- The adapter MUST define a maximum acceptable receipt age window. This window is a security parameter and MUST be configurable per deployment. If the Sift receipt contract does not provide sufficient expiry semantics, the adapter MUST define and enforce its own bounded freshness policy.
- If receipt freshness cannot be determined deterministically (e.g., missing or unparseable `timestamp`), the adapter MUST DENY.
- Stale, expired, or time-ambiguous receipts MUST NOT be converted into `AuthorizationV1`.
- `AuthorizationV1.expires_at` MUST be set to a short absolute TTL derived from `issued_at`. The PEP Gateway enforces `expires_at > now` independently.

### Freshness window

The adapter enforces a bounded freshness window on Sift receipts.

- Default: 30 seconds
- MUST be configurable per deployment
- MUST be treated as a security parameter, not a convenience value

A shorter window reduces replay exposure but increases sensitivity to clock skew and network latency.

The adapter MUST reject:
- stale receipts (age > configured window)
- receipts too far in the future (beyond allowed clock skew)

---

## Replay Protection Mapping

- The Sift `nonce` MUST be mapped into the OxDeAI replay model. This mapping MUST be explicit and defined by the adapter.
- `AuthorizationV1.auth_id` MUST be unique and single-use.
- The adapter MUST define how the Sift `nonce` maps to `auth_id`. Sift replay semantics and OxDeAI replay semantics are not identical: Sift may apply receipt-level deduplication, while OxDeAI enforces authorization-level single-use at the PEP boundary. The adapter MUST close this gap explicitly and MUST NOT assume the two are equivalent.
- The adapter MAY perform a pre-issuance replay precheck against a local duplicate cache to reduce obvious replay attempts. This precheck is advisory only and is not authoritative enforcement.
- The PEP Gateway MUST perform authoritative single-use enforcement. The PEP MUST atomically consume `auth_id` after all preceding verification checks, including boundary binding (step 15), as the last verification step (step 16) in `docs/spec/verification/verification-v1.md` §5, and before execution. If required consumption fails, is unavailable, or its outcome is indeterminate, execution MUST NOT proceed. Adapter-side replay prechecks are insufficient by themselves and MUST NOT be treated as authoritative.
- Reuse of the same `auth_id` at the PEP MUST result in DENY.
- Any replay uncertainty MUST result in DENY.

---

## Execution Invariant

- A Sift receipt MUST NOT directly authorize execution.
- Only a valid `AuthorizationV1` verified by the PEP Gateway MAY enable execution.
- Any system that executes on the basis of a Sift receipt alone is **non-conformant** with OxDeAI.
- If `AuthorizationV1` is absent, invalid, expired, replayed, audience-mismatched, intent-mismatched, state-mismatched, or unverifiable for any reason, execution MUST NOT occur.

---

## 4. Authorization Issuance

`AuthorizationV1` MUST be generated by the adapter only after ALL of the following have succeeded:

- receipt signature verified locally (Ed25519 over Sift-canonical bytes, base64url-decoded)
- `receipt_hash` integrity confirmed
- `kid` checked against KRL; not revoked
- `decision == ALLOW`
- receipt freshness confirmed within bounded window
- `auth_id` prechecked for obvious replay at adapter (advisory, if implemented)
- intent normalized, canonicalized (ensure_ascii=True), and `intent_hash` computed
- state derived, canonicalized (ensure_ascii=True), and `state_hash` computed
- audience injected from trusted configuration

If any prerequisite fails, the adapter MUST NOT produce `AuthorizationV1` and MUST return DENY.

### Required fields in `AuthorizationV1`

| Field              | Source                                                                              |
|--------------------|-------------------------------------------------------------------------------------|
| `intent_hash`      | SHA-256 of Sift-canonical JSON bytes of the normalized intent (ensure_ascii=True)   |
| `state_hash`       | SHA-256 of Sift-canonical JSON bytes of the normalized state (ensure_ascii=True)    |
| `audience`         | Injected by adapter from trusted configuration                                      |
| `expires_at`       | Adapter-configured bounded TTL from `issued_at` (Unix seconds)                     |
| `auth_id`          | Explicitly mapped from Sift `nonce` per adapter contract                            |
| `decision`         | `"ALLOW"`                                                                           |
| `policy_id`        | Mapped from `receipt.policy_matched`                                                |
| `issuer`           | OxDeAI authorization issuer identity                                                |
| `signature.alg`    | `"ed25519"` — Sift contract runtime literal (lowercase); distinct from JWKS `alg: "EdDSA"` |
| `signature.kid`    | Key identifier, nested in `signature`; identifies the issuer signing key            |
| `signature.sig`    | Base64url-no-padding Ed25519 signature over the Sift-canonical signing payload      |

A canonicalization failure at any field MUST produce DENY and MUST NOT produce a partial `AuthorizationV1`.

### Authorization signing preimage

The signing preimage for `signature.sig` is the `AuthorizationV1` payload with `signature.sig` **omitted entirely**. `signature.alg` and `signature.kid` MUST be present in the preimage.

```text
signingPayload = AuthorizationV1 MINUS signature.sig
                 (signature.alg and signature.kid are INCLUDED)
```

The signer canonicalizes `signingPayload` under the Sift contract (ensure_ascii=True, sort_keys) and signs the resulting UTF-8 bytes with Ed25519. The resulting signature is base64url-encoded without padding and placed in `signature.sig`.

The PEP Gateway reconstructs the same `signingPayload` to verify the signature. Any discrepancy in preimage construction between issuer and verifier will cause signature verification to fail.

---

## 5. PEP Enforcement

The PEP Gateway is the only path to execution. It is non-bypassable.

### PEP verification sequence

Before executing any side effect, the PEP MUST verify, in order:

1. Parse `AuthorizationV1` and reject malformed payloads.
2. Verify signature — resolve `signature.kid` against the trusted issuer keyset; verify the Ed25519 signature over the reconstructed signing payload (authorization minus `signature.sig`; `signature.alg` and `signature.kid` present).
3. Verify issuer and audience binding — exact match required.
4. Verify `decision == ALLOW`.
5. Verify not expired (`expires_at > floor(now / 1000)`).
6. Verify policy binding (`policy_id` matches expected policy context).
7. Verify intent binding (`intent_hash` equals SHA-256 of the Sift-canonical form of the exact action about to execute).
8. Verify state binding (`state_hash` matches SHA-256 of the current canonical state snapshot).
9. Verify replay protection (`auth_id` not previously consumed).

If any step fails, execution MUST NOT occur.

After successful completion of all preceding verification checks:
1. Atomically consume `auth_id` after boundary binding (step 15), as the last verification step (step 16) in `docs/spec/verification/verification-v1.md` §5 — the consumed record MUST be durable.
2. Execute the side effect only after successful consumption.
3. Emit audit evidence.

If required consumption fails, is unavailable, or its outcome is indeterminate, execution MUST NOT proceed. Consumption does not form an atomic transaction with the protected side effect and does not prove execution occurred.

### Upstream isolation

The upstream agent, Sift, and the adapter MUST NOT have a direct path to the execution target.
The PEP Gateway is the sole execution entry point.

### Issuer Trust Model

- The PEP Gateway MUST verify `AuthorizationV1` using a configured trusted key set.
- The `issuer` field alone is not sufficient to establish trust.
- Key resolution MUST use (`issuer`, `signature.kid`, `signature.alg`) against the trusted key set.
- If the issuer is unknown or the key is not trusted, verification MUST fail and result in DENY.

No implicit trust is allowed.

---

## 6. Security Properties

| Property                           | Description                                                                         |
|------------------------------------|-------------------------------------------------------------------------------------|
| Fail-closed                        | Any ambiguity or failure produces DENY; no fallback execution path exists           |
| Non-bypassable enforcement         | All execution passes through PEP Gateway; no upstream path to execution             |
| Deterministic verification         | Same inputs produce identical verification outcome (I1, I3, I4)                     |
| Replay resistance                  | `auth_id` is single-use; authoritatively enforced at PEP; adapter precheck is advisory only |
| Separation of decision/enforcement | Sift decides; OxDeAI enforces; neither can substitute for the other                |
| Local-only verification            | No network dependency in the enforcement path                                       |
| Canonical binding                  | `intent_hash` and `state_hash` bind execution to a specific verified context        |
| Audience isolation                 | `AuthorizationV1` is bound to a single PEP; cross-service replay is rejected        |

---

## 7. Limitations and Gaps

Sift receipts do not provide the following. The adapter MUST compensate for each.

| Gap                           | Risk without compensation                                                                           | Adapter requirement                                                                                      |
|-------------------------------|------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| No audience binding           | Receipt replayed against unintended service                                                         | Inject audience from trusted adapter configuration                                                       |
| No state binding              | Receipt replayed after state change (budget consumed, permission revoked)                           | Derive, canonicalize, and hash execution-relevant state                                                  |
| **No parameter binding**      | **Adapter can inject params different from what Sift evaluated; `intent_hash` binds adapter params, NOT Sift-evaluated params** | **Adapter MUST ensure injected params match intended execution; see §"Parameter Binding Guarantee"** |
| No canonical intent form      | Intent ambiguity; `intent_hash` inconsistency across implementations                               | Normalize Sift fields to canonical OxDeAI intent under canonicalization-v1                               |
| No OxDeAI replay contract     | Sift nonce deduplication ≠ OxDeAI `auth_id` single-use enforcement                                 | Explicitly map nonce to `auth_id`; enforce consumption at PEP                                            |
| No bounded expiry contract    | Stale receipt converted to long-lived `AuthorizationV1`                                             | Define and enforce adapter-side bounded freshness window                                                 |

---

## 8. Example Flow

### Input: Sift receipt

```json
{
  "receipt_version": "1.0",
  "tenant_id": "tenant-abc",
  "agent_id": "agent-xyz",
  "action": "call_tool",
  "tool": "payments_api",
  "decision": "ALLOW",
  "risk_tier": 1,
  "nonce": "b3c4d5e6-1234-5678-abcd-ef0123456789",
  "timestamp": "2026-04-15T12:00:00.000Z",
  "policy_matched": "payments-policy-v4",
  "receipt_hash": "aabbcc...",
  "signature": "<base64url-no-padding Ed25519 signature>"
}
```

### Adapter processing (success path)

```text
1. Structural validation
   → all required fields present; types valid

2. Version check
   → receipt_version "1.0" supported

3. Recompute receipt_hash over sift_canonical(receipt MINUS signature AND receipt_hash)
   → matches provided receipt_hash

4. Resolve kid → check KRL (not revoked) → decode JWKS x → 32-byte raw key
   Verify Ed25519 signature over sift_canonical(receipt MINUS signature, WITH receipt_hash)
   → valid

5. Check decision == ALLOW
   → pass

6. Check timestamp freshness: age = 12s < 30s window
   → pass

7. Precheck mapped auth_id "b3c4d5e6-..." against duplicate cache (advisory)
   → not seen; proceed (authoritative single-use enforcement occurs at PEP)

8. Normalize intent to canonical OxDeAI form:
   {
     "type": "EXECUTE",
     "tool": "payments_api",
     "params": { "amount": 500, "currency": "USD", "destination": "acct_9f3a" }
   }
   → sift_canonical (ensure_ascii=True, sort_keys)
   → intent_hash: sha256:1122dd...

9. Derive state snapshot from execution environment:
   { "available_budget": 10000, "account_status": "active", "prior_transfers_today": 2 }
   → sift_canonical (ensure_ascii=True, sort_keys)
   → state_hash: sha256:334455...

10. Inject audience from adapter config: "payments-service-prod"

11. Issue AuthorizationV1
```

### `AuthorizationV1` issued by adapter

```json
{
  "version": "AuthorizationV1",
  "decision": "ALLOW",
  "issuer": "did:example:oxdeai-issuer-1",
  "audience": "payments-service-prod",
  "auth_id": "b3c4d5e6-1234-5678-abcd-ef0123456789",
  "policy_id": "payments-policy-v4",
  "intent_hash": "1122dd...",
  "state_hash": "334455...",
  "issued_at": 1744574412,
  "expires_at": 1744574442,
  "signature": {
    "alg": "ed25519",
    "kid": "2026-rot-01",
    "sig": "<base64url-no-padding Ed25519 signature over signing payload>"
  }
}
```

Note: `signature.alg` is the Sift contract runtime literal `"ed25519"` (lowercase). This is distinct from the JWKS entry field `"alg": "EdDSA"` used for key-discovery metadata. The `kid` is nested inside `signature`, not at the top level of `AuthorizationV1`.

### PEP Gateway verification (success path)

```text
1. Parse AuthorizationV1                     → ok
2. Resolve signature.kid against issuer keyset;
   verify Ed25519 sig over signing payload
   (AuthorizationV1 minus signature.sig;
    signature.alg and signature.kid present)  → valid
3. Verify audience                            → "payments-service-prod" == own identifier → match
4. Verify decision == ALLOW                   → pass
5. Verify expires_at > now                    → 1744574442 > 1744574415 → pass
6. Verify policy_id                           → "payments-policy-v4" == expected → match
7. Verify intent_hash                         → sha256(sift_canonical(action)) == 1122dd... → match
8. Verify state_hash                          → sha256(sift_canonical(state)) == 334455... → match
9. Verify auth_id not consumed                → not consumed → pass; persist as consumed

→ EXECUTE
```

### Failure paths

Each of the following independently terminates in DENY with no execution:

```text
Invalid Ed25519 signature
  → adapter: DENY → NO EXECUTION

Revoked kid (KRL check)
  → adapter: DENY → NO EXECUTION

receipt_hash mismatch
  → adapter: DENY → NO EXECUTION

Receipt timestamp outside freshness window
  → adapter: DENY → NO EXECUTION

auth_id seen in adapter duplicate cache (advisory precheck, if implemented)
  → adapter: DENY → NO EXECUTION

State derivation failure (state unavailable or non-deterministic)
  → adapter: DENY → NO EXECUTION

Canonicalization error during intent normalization
  → adapter: DENY → NO EXECUTION

auth_id already consumed at PEP (replay at enforcement boundary)
  → PEP: DENY → NO EXECUTION

intent_hash mismatch at PEP (action differs from what was authorized)
  → PEP: DENY → NO EXECUTION

audience mismatch at PEP
  → PEP: DENY → NO EXECUTION

AuthorizationV1 absent
  → PEP: DENY → NO EXECUTION
```

---

## 9. Summary

Sift decides. OxDeAI enforces.

Execution requires `AuthorizationV1`. A Sift receipt is a governance decision artifact. It is not an authorization artifact. The adapter translates between them — but only after verifying the receipt locally (Ed25519 over Sift-canonical bytes; `kid` checked against the KRL; JWKS key resolved by `kid`), normalizing intent deterministically (Sift-canonical JSON, ensure_ascii=True), deriving and hashing state, injecting audience, and mapping replay identity. Each of these steps is mandatory and non-delegable.

The PEP Gateway is the only path to execution. Any failure at any verification step produces DENY. There is no partial authorization and no fallback execution path.
