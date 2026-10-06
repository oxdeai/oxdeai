# Sandbox invariants

## Counter effect oracle

`apps/upstream/server.ts` owns `{counter: n}`. Tests read detached snapshots
before and after requests. An accepted execution increments once. Rejections
must leave the counter unchanged. Direct requests without the internal token
return `FORBIDDEN`. Reset/mutation is available only through a trusted test handle.

## Intent and live-state binding

The reference gateway compares `siftCanonicalJsonHash(intent)` with `intent_hash`:
post-authorization parameter changes return `INTENT_HASH_MISMATCH`.
It independently obtains state via the deployer-configured accessor, normalizes
it with Sift `normalizeState`, and compares `siftCanonicalJsonHash(state)` with
`state_hash`. Stale state returns `STATE_HASH_MISMATCH`, including when the caller
supplies a matching stale request snapshot. Accessor failure or invalid state
also returns `STATE_HASH_MISMATCH`, before replay consumption or execution.
No new hashing format is introduced.

## Replay order

Replay consumption occurs after intent and live-state binding. When an execution
changes a bound counter from 0 to 1, presenting the same authorization again
returns `STATE_HASH_MISMATCH` before the replay store. The isolated replay test
first observes 0 → 1, restores 0 through the trusted test handle without resetting
the replay store, and then proves a second consume attempt returns
`REPLAY_DETECTED` without a second effect. This reset is deliberate test setup.
Store failure returns HTTP 500 `REPLAY_STORE_ERROR` with zero effect.

## Other preserved checks

Signature verification precedes issuer, audience, expiry, policy and binding
checks. Wrong signed audience returns `AUDIENCE_MISMATCH`; expiration returns
`EXPIRED`. A Sift DENY receipt returns adapter `DENY_DECISION`, so no authorization
is submitted. HTTP failure statuses vary by layer; not all failures are 403.

## Parameter-binding boundary

The same Sift receipt accepts different adapter-supplied parameters. Each new
authorization binds its own intent, while `auth_id` remains the receipt nonce.
The pre-issuance mutation test documents this accepted behavior rather than
claiming that Sift approved those specific parameter values.

## Limits

Sequential only: no concurrency, production durability, CAS, or atomic
state-check plus effect commit guarantee. Replay stores are test/in-memory only.
State can change after the gateway reads it and before upstream mutation.
Consumed authorizations can have no effect if downstream execution fails.
