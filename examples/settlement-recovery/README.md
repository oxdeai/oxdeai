# Settlement recovery sandbox

Synthetic payloads only.

`pnpm --filter @oxdeai/core test` runs the full `@oxdeai/core` suite. That suite is 525 tests, including 10 AuthorizationV1 wire vectors.

`pnpm test:settlement-recovery` runs the 12 settlement-recovery / replay scenarios in this directory.
