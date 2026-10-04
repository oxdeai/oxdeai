# Changelog

All notable changes to `@oxdeai/cli` will be documented in this file.

The format is based on Keep a Changelog.
This project follows Semantic Versioning.

---

## [0.3.1] - 2026-10-04

Dependency release of `@oxdeai/cli`. It packs against `@oxdeai/core@2.0.1`
(exact dependency). No CLI source change.

### Security

- Pins `@oxdeai/core@2.0.1` (GHSA-48xw-c298-546r). The CLI constructs its own
  `PolicyEngine`, so `@oxdeai/cli@0.3.0` evaluates with the affected
  `core@2.0.0`.

## [0.3.0] - 2026-09-25

**Baseline for this entry:** the published `@oxdeai/cli@0.2.4` npm artifact
(2026-03-12). The Git tag `cli-v0.2.4` (`3614d94`) carries the same date, so the
baseline is provable for this package.

Pre-1.0, so a minor bump carries the breaking change.

### Breaking

- **Depends on the `@oxdeai/core` 2.0 line.** Behaviour that follows from core's
  trusted-time work is inherited by the CLI's build/verify/replay paths.
- **A valid `engine_secret` is enforced on the validation path.** Insecure defaults
  were removed; a run that previously succeeded with an absent or too-short secret
  now fails with an actionable error rather than proceeding.
- **Strict-mode verification requires an explicit trust anchor.** The four strict
  `verify` entry points require `--trusted-keyset`, or an explicit
  `--mode best-effort`. A missing keyset produces an actionable error instead of a
  silent inconclusive result.

### Fixed

- Deterministic `init` behaviour restored.
- `oxdeai` with no command exits 0 and prints usage to stdout.

### Packaging

- `license`, `repository` (with `directory`), `homepage` and `bugs` are now declared;
  the published `0.2.4` artifact carried none of them, which blocks npm provenance.
- The existing `prepack` build step is unchanged.

---

## [0.2.4] - 2026-03-19

### Fixed

- No-command invocation (`oxdeai` with no arguments) now exits with code 0 and prints usage to stdout instead of stderr. Eliminates spurious `ELIFECYCLE` error from pnpm.

---

## [0.2.4] - 2026-03-12

### Changed

- Follow-up CLI usability patch release after `0.2.3`.
- Clarified authorization shorthand behavior so `oxdeai verify auth` fails with actionable `--file` guidance instead of reading empty stdin.

### Notes

- Patch release only.
- No protocol semantics or `@oxdeai/core` runtime behavior changes.

---

## [0.2.3] - 2026-03-12

### Added

- Standard CLI help support:
  - `oxdeai --help`
  - `oxdeai -h`
  - `oxdeai help`
  - subcommand help such as `oxdeai verify --help`
- Standard CLI version support:
  - `oxdeai --version`
  - `oxdeai -v`
- Positional shorthand command forms for common local workflows:
  - `oxdeai verify snap`
  - `oxdeai verify audit`
  - `oxdeai verify envelope`
  - `oxdeai verify auth`
  - `oxdeai build snapshot`
- Post-build executable entrypoint handling for the published CLI bin target.

### Changed

- Improved monorepo developer workflow with clearer local CLI execution paths.
- Improved README quickstart for:
  - npm users
  - local contributors
  - linked/global CLI workflows
- Improved top-level CLI error handling and usage guidance for unsupported flags and command misuse.
- Fixed direct execution detection so linked/global `oxdeai` works correctly through symlinked bin paths.
- Authorization shorthand now fails with actionable guidance when `--file` is omitted.

### Notes

- CLI usability and packaging release only.
- No protocol semantics or `@oxdeai/core` runtime behavior changes.

---

## [0.2.2] - 2026-03-08

### Changed

- Corrected published dependency metadata to use `@oxdeai/core@^1.3.0` directly.
- Removed ineffective workspace dependency publication workaround from `0.2.1`.

### Notes

- Metadata-only release. No runtime or CLI command behavior changes.

---

## [0.2.1] - 2026-03-08

### Changed

- Metadata-only packaging fix for npm consumers.
- Added `publishConfig.dependencies` mapping so published package uses `@oxdeai/core@^1.3.0` instead of workspace protocol metadata.

### Notes

- No runtime, command surface, or protocol-semantics changes from `0.2.0`.

---

## [0.2.0] - 2026-03-08

### Added

- Unified `verify` command support for:
  - `snapshot`
  - `audit`
  - `envelope`
  - `authorization`
- Support for authorization/envelope verification options:
  - expected issuer/audience/policy
  - trusted keyset input
  - signature verification requirement toggles
- Machine-readable and human-readable output paths with consistent command summaries.
- Dedicated CLI README with command surface, examples, and exit code contract.

### Changed

- Stabilized tooling command surface around:
  - `oxdeai build`
  - `oxdeai verify`
  - `oxdeai replay` (protocol-aware explicit stub)
- Normalized verification exit codes:
  - `0` = `ok`
  - `1` = `invalid` / malformed runtime failure
  - `2` = usage error
  - `3` = `inconclusive`
- Expanded CLI tests for authorization verification and malformed-input fail-closed behavior.

### Notes

- `@oxdeai/cli` is a tooling release line and is versioned independently from the protocol stack.
- Protocol compatibility claims are defined by:
  - `@oxdeai/core`
  - `@oxdeai/sdk`
  - `@oxdeai/conformance`
