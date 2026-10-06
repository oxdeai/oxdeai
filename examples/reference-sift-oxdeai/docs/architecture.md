# Wednesday Sift × OxDeAI counter sandbox

This example demonstrates sequential execution against a synthetic counter.
The upstream owns an in-memory counter. Its detached `readCounter()` snapshot,
not an HTTP success flag, is the effect oracle. An accepted POST to `/execute`
with the internal executor token increments the counter exactly once.
`setCounterForTest()` is an in-process trusted test handle, not an HTTP reset API.
Fresh test harnesses isolate counters, replay stores, servers and signing keys.

## Reference path

Mock Sift signed receipt → `SiftAdapter.adapt()` → receipt verification →
`normalizeIntent()` and `normalizeState()` → `receiptToAuthorization()` →
Ed25519 signing → reference PEP gateway → protected upstream counter.

The authorization-time state is the upstream snapshot `{counter: n}` normalized
with existing Sift `normalizeState`. The authorization hashes that object with
existing `siftCanonicalJsonHash`. At execution time, `PepConfig.getExecutionState`
obtains a fresh snapshot from the same upstream store. The gateway normalizes
and hashes it identically. Request `state` remains accepted for compatibility
but is never authoritative. Accessor errors and invalid state fail closed.

The check order is parse, signature, issuer, audience, decision, expiry, policy,
intent hash, live state hash, replay consumption, then upstream request.
The production `createPepGatewayExecutor` tests remain separate: that API does
not retrieve live state. This example does not change production packages.

## Sequential scope

There is a race window between live-state read and the upstream effect. Neither
state verification nor replay consumption is a transaction with counter mutation.
No concurrency safety, CAS semantics, atomic state-check plus effect commit, or
production durability is claimed. Replay consumption can succeed without an
effect if the downstream request fails; it is not rolled back.

The harness replay store is test/in-memory only. It does not survive process
restart or provide distributed protection. A shared Map is not durable storage.
The adapter retains its transition `signed_preferred` KRL configuration.

Sift receipts bind tool identity and governance fields, not parameter values.
The adapter's authorization commits to the parameters supplied at issuance.
Parameter changes after issuance are rejected; changes between Sift evaluation
and adapter issuance are not protected by this receipt contract.

## Validation

With frozen workspace dependencies installed, build the example's dependencies:
`pnpm --filter @oxdeai/example-reference-sift^... build`.
Run `pnpm -C examples/reference-sift-oxdeai test` for its build and three test files.
