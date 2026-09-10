# Go Conformance Harness (Adapter Protocol)

Actual runtime coverage is documented in [corpus authority](../../../docs/conformance/corpus-authority.md). Root Go/Python
validators cover canonicalization, Profile-C and SignedKRL only. The optional
package Go driver is separate and requires an adapter; its bundled Python adapter
fails at import (#306) and supplies no passing coverage. Rust tests consume only
`examples/rust-verifier/auth_case.json` and its key fixture, not either vector tree.


This harness reads OxDeAI conformance vectors from `packages/conformance/vectors` and prints PASS/FAIL assertions similar to the TypeScript validator.

It is intended for Rust/Go/Python native implementations that want protocol-aligned validation without depending on the TypeScript runtime directly.

## Status

- Harness runner: implemented in Go (`main.go`)
- Adapter implementation: provided by you (any language) via a simple stdin/stdout JSON protocol

## Run

From `packages/conformance/go-harness`:

```bash
go run ./main.go --adapter-bin ./your-adapter --vectors ../vectors
```

You can pass adapter arguments with repeated `--adapter-arg`:

```bash
go run ./main.go --adapter-bin ./your-adapter --adapter-arg --mode --adapter-arg strict --vectors ../vectors
```

## Adapter Protocol

The harness sends one JSON request to the adapter process stdin and expects one JSON response on stdout.

### Request

```json
{
  "op": "intent_hash",
  "input": { "intent": { "...": "..." } }
}
```

### Response

```json
{
  "ok": true,
  "output": { "hash": "..." }
}
```

Error response:

```json
{
  "ok": false,
  "error": "explanation"
}
```

## Required `op` values

### Core protocol
- `intent_hash`
- `evaluate_authorization`
- `encode_snapshot`
- `verify_snapshot`
- `canonical_json`
- `verify_authorization`
- `verify_audit_case`
- `verify_envelope_case`
- `verify_authorization_signature_case`
- `verify_envelope_signature_case`

### DelegationV1
- `delegation_parent_hash`
- `verify_delegation`
- `verify_delegation_chain_case`
- `verify_delegation_signature_case`

## Output fields by operation

### `intent_hash`
- output: `{ "hash": "<hex>" }`

### `evaluate_authorization`
- output:
  - `authorization` object (must include at least `intent_hash`, `state_hash`, `expires_at`, `signature`)
  - `canonical_signing_payload` string

### `encode_snapshot`
- output:
  - `snapshot_base64`
  - `policy_id`

### `verify_snapshot`
- output:
  - `status`
  - `stateHash`
  - `policyId` (optional)
  - `violations`

### `verify_authorization` / `verify_audit_case` / `verify_envelope_case` / signature-case ops
- output:
  - `status`
  - `violations`
  - optional: `policyId`, `stateHash`, `auditHeadHash` when relevant

### `delegation_parent_hash`
- input: `{ parent: AuthorizationV1 }`
- output: `{ parent_auth_hash: "<sha256 hex>" }`

### `verify_delegation`
- input: `{ delegation: DelegationV1, opts: VerifyDelegationOptions }`
- output: `{ status, violations, policyId }`

### `verify_delegation_chain`
- input: `{ parent: AuthorizationV1, delegation: DelegationV1, opts }` (inline from vector)
- output: `{ status, violations }`
- Adapter independently recomputes `SHA256(canonical_json(parent))` and runs all chain-level structural checks

### `verify_delegation_signature`
- input: `{ parent: AuthorizationV1, delegation: DelegationV1, opts }` (inline, opts includes `trustedKeySets`)
- output: `{ status, violations }`
- Adapter runs chain checks then performs Ed25519 verification using `opts.trustedKeySets`

### `verify_delegation_chain_case` / `verify_delegation_signature_case`
- input: `{ id: "<case-id>" }`
- output: `{ status, violations }` (lookup against frozen vector file, retained for compatibility)

## Notes

- The harness itself does not redefine protocol semantics.
- Vectors remain the behavioral truth source.
- A native implementation is considered aligned when it reproduces expected vector outcomes.

The adapter's `{ ok, output }` messages and this optional driver's assertions are
operation diagnostics, not scoped conformance reports. They establish no claim
coverage or independent normative authority. Official root Go/Python commands
emit the [scoped report](../../../docs/conformance/evidence-scope.md); this optional
adapter route remains blocked by #306 and is not counted as passing evidence.
