# Counter sandbox threat model

The untrusted caller submits intent, request state and signed authorization.
The gateway's configured state accessor reads the actual upstream counter;
caller state cannot substitute the execution snapshot. Post-issuance intent
mutation, stale live state, same-state auth-ID replay, and direct access without
the internal executor token are tested using actual counter observations.

The adapter signing key, gateway configuration, upstream store and internal
executor token are trusted in this local example. Test-only counter mutation
is an in-process handle and is never exposed as a normal HTTP capability.
The mock Sift service issues requested decisions; it does not demonstrate real
parameter-aware policy evaluation. Its receipts have no signed parameter hash.
Changes between evaluation and adapter issuance remain outside the binding guarantee.

This is a sequential sandbox, not production infrastructure. State read →
verification → upstream effect contains a race window. Concurrent requests with
different valid authorizations may pass against the same snapshot. There is no
CAS, atomic state-check plus effect commit, or concurrency guarantee. Replay
consumption and effects are separate: upstream failure can burn an auth ID with
no effect, and consumption is not rolled back.

Counters and replay records are in-memory/test-only, with no production durability
or distributed/restart protection. Ordinary replay after a counter increment
fails state binding first; a trusted-reset test separately exercises replay
consumption. The reset restores state only and preserves consumed auth IDs.
The adapter's existing transition KRL mode remains unchanged.
