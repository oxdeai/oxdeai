# RELEASE-FINALIZATION-01: dist-tag finalization (maintainers)

The previous `promote()` applied every `latest` tag before verifying any, with
no per-package reconciliation, no promotion-specific consent, no `next`
removal and no persisted distinction between promotion and completion. It is
retired: it still validates state and phase, then fails with
`PROMOTION_BATCH_RETIRED` before consulting any transport.

Finalization lives in `scripts/release-2.0/release-finalization.mjs`:

    READY_TO_PROMOTE -> PROMOTING_LATEST -> PROMOTED -> REMOVING_NEXT -> FINALIZED

`promoteLatest()` and `removeNext()` act on one selected package per call and
perform at most one remote effect. Each validates state, the unmodified
manifest digest, the release registry, the package's membership in the
publication selection and its own consent receipt before any observation.
It then observes the tag independently, skips the effect when the tag already
conforms, persists a `finalizationAttempt` before the effect, and re-observes
afterwards. Transport results are ignored; only observations count.

`verifyLatestPromotion()` observes every selected `latest` before `PROMOTED`.
Every `removeNext()` call re-observes all selected `latest` tags first, so
removal never starts or continues on drift. `verifyFinalization()` observes
`latest` = frozen version and `next` absent for every selected package. It is
the only path to `FINALIZED`, and it writes `state.finalization`, which binds
release id, manifest digest, registry, the selected packages and a digest.

Failure semantics:

- Malformed, absent or contradictory observations (wrong registry, package or
  tag, extra fields, thrown errors) fail closed with `DIST_TAG_STATE_UNDETERMINED`.
- A `latest` other than the frozen version is a conflict unless the promotion
  receipt names that exact version in `replaces` (or `null` for an absent tag).
  That is the only replacement policy. A `next` pointing elsewhere is never removed.
- Pre-effect failures change nothing on disk. Post-effect failures persist a
  `finalizationBlocker`. If the outcome is unknown, the attempt is kept as well.
  While either exists, only the same package and operation may proceed. A retry
  re-observes and converges without repeating an effect that already landed.

Consent: `promotion-authorization` (tag `latest`, operation `dist-tag-add`,
`replaces`) and `next-removal-authorization` (tag `next`, operation
`dist-tag-rm`) each bind release id, manifest digest, selected package, version,
integrity and registry exactly. Kinds never substitute for each other or for
`publication-authorization`. `AuthorizationV1` is untouched and not used. These
are consent checks supplied by trusted calling code. They are not signatures or
freshness proofs, and they are not replay-proof tokens.

Compatibility: `MANIFEST_VERSION`, `STATE_VERSION` and the receipt versions
remain 1. The new phases and fields are additive. Historical states, including
`PROMOTED` states written by the retired batch, validate unchanged and are never
reported as finalized. Such a state can only move to `REMOVING_NEXT` after a
fresh observation of every selected `latest`. Legacy all-package manifests
finalize all ten packages under the same rules. F2/CLI-1 manifests finalize
exactly the five selected packages; excluded packages are never observed or
changed, and state carrying finalization evidence for them is rejected.

Not included: no real dist-tag transport, no CLI subcommand, no npm process.
`distTagTransport` must be injected by a separately authorized caller.

## Validation (2026-10-20)

Initial checkout verified clean at `fix/release-finalization-01`,
`73933436f66d635e45e08fad4e79746142786912`.

- Baseline: 11 build-dependent tests failed for missing local dependencies.
  `pnpm install --offline --frozen-lockfile --ignore-scripts` restored them with
  no network access and no lockfile change. After that, 599/599 tests passed.
- `node --test --test-concurrency=1 scripts/release-2.0/release-finalization.test.mjs`:
  122 passed.
- Six deliberate guard mutations were each caught by at least two tests, then
  reverted: always reapply, no latest gate, no latest conflict check, no next
  conflict check, trusting the effect without re-observation, and no
  persisted attempt.
- `node --test --test-concurrency=1 scripts/release-2.0/*.test.mjs`: 721 tests,
  720 passed, zero failures, one skipped. The skip is the real clean-source
  PRECHECK/PACK/VERIFY_LOCAL test, skipped because the change is uncommitted;
  it verified that PACK refuses the dirty tree. It must be rerun after a commit.
  `git diff --check` passed.
- One existing test changed meaning: the eight promotion-transport modes in
  `orchestrator.test.mjs` now assert retirement with zero apply/observe calls.
  No other test or release gate was removed.

No npm publish or dist-tag command, registry access, git tag, GitHub release,
GHSA change, commit or push was performed.
