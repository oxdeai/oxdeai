# R3 release reconciliation on `main` (maintainers)

The R3 security release was published to npm on 2026-11-18 from the 2.0.x
maintenance branch (`security/r3-release-stabilization`, commit `448804a`). The
ten published tarballs are byte-identical to the official PACK of `448804a`.
`main` received the ACT-1 fix separately (`c140deb`, merged in `a5a0944`). This
change brings `main` in line with what is published, so that `main` can be the
source of the next release.

## Published baseline

| Package | Published | Dependencies as published |
|---|---|---|
| `@oxdeai/core` | 2.0.3 | none |
| `@oxdeai/guard` | 2.0.5 | `@oxdeai/core` `2.0.3` (exact) |
| `@oxdeai/sdk` | 2.0.3 | `@oxdeai/core` `2.0.3` (exact) |
| `@oxdeai/conformance` | 2.0.4 | `@oxdeai/core` `2.0.3` (exact) |
| `@oxdeai/cli` | 0.3.3 | `@oxdeai/core` `2.0.3` (exact) |
| `@oxdeai/autogen`, `crewai`, `langgraph`, `openai-agents`, `openclaw` | 2.0.1 | `@oxdeai/core` `^2.0.3`, `@oxdeai/guard` `^2.0.5` |

`@oxdeai/guard` 2.0.4 and `@oxdeai/conformance` 2.0.3 were never published.
Their CHANGELOG entries are kept and marked "Not published".

## What changed on `main`

- Package versions and workspace dependency declarations now produce the
  published manifests. The adapters declare `@oxdeai/guard` as `workspace:^2.0.5`.
- The R3 release tooling is restored: the Guard security floor in the packed
  artifact gate, release completeness and scope validation, and their tests
  (see [`R3-STABILIZATION.md`](./R3-STABILIZATION.md)).
- **Published-version floor.** `scripts/release-2.0/published-baseline.json`
  records the latest published version and integrity of each package. PRECHECK
  refuses any POLICY version that is not strictly greater
  (`RELEASE_VERSION_ALREADY_PUBLISHED`, `RELEASE_VERSION_DOWNGRADE`,
  `RELEASE_VERSION_BASELINE_MISSING`) before it writes a receipt. On this
  commit PRECHECK therefore refuses to release: the next release must raise the
  versions in POLICY and the package manifests. Update the baseline only after a
  publication has been verified on the registry.
- **`latest` promotion floor.** `promoteLatest()` re-reads `latest` from the
  registry at promotion time and refuses, before any effect and even with an
  explicit promotion consent, a candidate that is not strictly greater than it
  under SemVer (`LATEST_NOT_ADVANCING`), a prerelease (`LATEST_PRERELEASE_REFUSED`),
  or a candidate whose version, read from the frozen tarball (integrity checked
  against the manifest), differs from the manifest or POLICY
  (`TARBALL_VERSION_MISMATCH`, `TARBALL_INTEGRITY_MISMATCH`, `TARBALL_UNREADABLE`).
  An unavailable registry or a `latest` that is not a SemVer version fails closed
  (`DIST_TAG_STATE_UNDETERMINED`). When `latest` already points to the candidate
  (a resumed run whose effect landed), no effect is performed.
- Mandatory CI tests (`docs/conformance/required-tests.json`) include the ACT-1,
  OBS-E, H-1, INVREG, RR-01, S2, S3 and S4 regression tests and the five adapter
  execution-binding suites that R3 made mandatory, plus the `main`-only ACT-1
  reconciliation suite. Nothing was removed and no floor was lowered.
- CHANGELOGs record the 2026-11-18 releases. `[Unreleased]` keeps the changes
  that exist only on `main`.

## Source differences from the published packages

`main` is not the published source. It also contains changes that were never
published (for example SignedKRLV1 revocation, `secureConfig`, explicit replay
protection, strict replay results at every guard consume site, and the
conformance `deployment` export). These are listed under `[Unreleased]` and will
ship in the next release with new versions. The ACT-1 guard change and the
adapter execution-binding code are identical to the published code apart from
comments. The delegation-input snapshot (OBS-E on 2.0.x, F4-R8-01 on `main`)
uses the same `snapshotPlainData` helper; `main` adds stricter scope and
replay-result checks around it.

## Separate decision: exact core pin (#409)

`@oxdeai/guard` pins `@oxdeai/core` exactly while the adapters use a caret range.
This is how 2.0.5 and the adapters were published, so it is kept unchanged here.
Whether to change it is tracked in #409.
