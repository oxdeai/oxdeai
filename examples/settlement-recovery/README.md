# Settlement-recovery profile (sr-001–sr-014)

Synthetic public fixtures for the admission step after `verifyAuthorization`. This profile does not alter `verifyAuthorization` or the AuthorizationV1 contract. No file under `packages/core` changes.

`admit` is the admission entry point. From `UNSEEN`, before any lease record is allocated, it requires both of these, in order:

1. strict `verifyAuthorization` (signature verification required, fixture issuer `oxdeai.policy-engine`, audience `merchant-gateway`, public key, clock `now` = `1730000030` seconds);
2. presented-intent equality: `sha256HexFromJson` of the presented intent against the signed `intent_hash`.

`verifyAuthorization` has no presented-intent argument. A mismatch is `AUTH_INTENT_MISMATCH`. If either check fails, `admit` does not create or mutate lease state. Fixture key material is one public key, `kid` `sandbox-sr-1`, algorithm `Ed25519`. sr-013 and sr-014 reuse the sr-001 signed artifact (public key only; no new signature).

The lease is a `Map` inside the runner. The runner records a status code on the admission result and asserts that number. The fourteen cases assert status 200, 403, 409, 422, 502, and 504. `AUTH_INTENT_MISMATCH` is asserted on sr-006 (secondary intent), sr-007 (presented intent against an existing settled lease), and sr-013 (presented intent from `UNSEEN`).

## Run

```bash
pnpm install --frozen-lockfile
pnpm test:settlement-recovery
```

`pnpm test:settlement-recovery` builds `@oxdeai/core` and runs these fourteen checks. `pnpm --filter @oxdeai/core test` is the unchanged core suite: 525 tests, including 10 AuthorizationV1 wire vectors.

The JSON fixture is LF (`.gitattributes`).

## What the runner asserts

Every case checks `signatureVerified`, verifier success, verifier violation codes, the binding code, lease transitions, final state, epoch, recovered transaction hash, extension code, and the recorded status.

| Case | Asserted outcome |
| --- | --- |
| sr-001 `settle` | Verification succeeds and the presented intent matches. The lease moves UNSEEN → LEASED → SETTLED at epoch 1 and keeps the recovered tx. Status 200. The runner then changes one character of that signature and expects `AUTH_SIGNATURE_INVALID`. |
| sr-002 `abort-before-send` | Verification succeeds. Recovery opens epoch 2, then the lease commits `FAILED_FINAL` with `LEASE_ABORTED_NO_SETTLEMENT`. No recovered tx. Status 422. |
| sr-003 `recover-confirmed` | Verification succeeds. Recovery opens epoch 2 and commits `SETTLED` with the recovered tx. Status 200. |
| sr-004 `hold-pending` | Verification succeeds. Recovery leaves `RECOVERY_PENDING` at epoch 2 with `SETTLEMENT_UNCERTAIN`. No recovered tx. Status 504. |
| sr-005 `coalesce` | Verification succeeds. A second acquire while the lease is held returns `IN_FLIGHT`. After commit to `SETTLED` at epoch 1, another acquire returns `COALESCED_SETTLED` and the same tx. Status 200. |
| sr-006 `reject-mutated` | Verification succeeds and the primary intent matches. The secondary intent is `AUTH_INTENT_MISMATCH`. Acquiring it returns `REPLAY_REJECTED` / `AUTH_REPLAYED`. The original lease still commits `SETTLED`. Status 409. |
| sr-007 `replay-settled` | The lease starts `SETTLED`. Verification still succeeds. The presented intent is `AUTH_INTENT_MISMATCH`. The runner reports `AUTH_REPLAYED`, leaves the lease `SETTLED` at epoch 1, and returns the existing tx. Status 422. |
| sr-008 `fence-epoch` | Verification succeeds. Recovery opens epoch 2. A commit at epoch 1 fails with `STALE_LEASE_EPOCH`. A commit at the current epoch settles and keeps the tx. Status 200. |
| sr-009 `settle-after-short-expiry` | Expiry is still after the fixture clock, so verification succeeds. Recovery opens epoch 2 and commits `SETTLED` with the recovered tx. Status 200. |
| sr-010 `reject-expired` | Verification fails with `AUTH_EXPIRED`. The lease stays `UNSEEN` at epoch 0. Status 422. |
| sr-011 `block-after-verify` | Verification succeeds. The lease commits `FAILED_FINAL` at epoch 1 with `COMPLIANCE_BLOCKED`. Status 403. |
| sr-012 `hold-partial` | Verification succeeds. Recovery leaves `RECOVERY_PENDING` at epoch 2 with `PARTIAL_SETTLEMENT_DRIFT` and records the partial tx hash. Status 502. |
| sr-013 `reject-intent-mismatch` | Starts `UNSEEN`. Verification succeeds. The presented intent does not match the bound `intent_hash`, so `admit` returns `AUTH_INTENT_MISMATCH` and does not allocate a lease. The map stays empty. Status 422. |
| sr-014 `reject-tampered-signature` | Starts `UNSEEN`. The runner flips one byte of the signature and sends that payload through `admit` (not a direct verifier-only call). Verification fails closed with `AUTH_SIGNATURE_INVALID`. No lease entry and no state transition. Status 422. |
