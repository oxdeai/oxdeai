# Reproducible Release Packaging

## Status

Normative for release packaging (#344). Applies to every publishable package
under `packages/*` (`private !== true`).

## Invariant

A release tarball is a function of exactly:

1. the source tree at one clean, exact Git revision;
2. `pnpm-lock.yaml` at that revision;
3. the pinned release toolchain (below).

Packing the same revision twice, on the same machine or on an independent one,
must produce byte-identical tarballs for every publishable package. A release
tarball is still produced **once**: the frozen-artifact rule below is unchanged.

## Release toolchain

| Tool | Pin | Source of truth | Enforced by |
|---|---|---|---|
| Node.js | `22.9.0` | `.node-version` | `orchestrator.mjs pack`, `reproducible-pack.mjs`, CI `release-reproducibility` and `packed-artifact-consumer-gate` (`node-version-file`) |
| pnpm | `10.34.5` | root `package.json` `packageManager` | same; `pnpm/action-setup` and corepack read `packageManager` |
| Build tools (TypeScript, API Extractor, ...) | as locked | `pnpm-lock.yaml` | `pnpm install --frozen-lockfile` |
| Pack-time manifest hook | as committed | `.pnpmfile.cjs` (checksum in `pnpm-lock.yaml`) | frozen install refuses a hook that differs from the lockfile |

Both pins must lie inside the root `engines` ranges; `scripts/release-2.0/toolchain.mjs`
refuses a ranged, missing or out-of-range pin.

The `pnpm` that matters is the one on `PATH`: the pack transport spawns it and every
package's `prepack: pnpm build` runs it. A machine whose global `pnpm` differs
from the pin is refused, even if `npx pnpm@10.34.5` was used for the outer command.

Node 22.9.0 is the toolchain that produced and re-verified the frozen 2.0.1
artifacts. Changing either pin is allowed only together with a
`verify:reproducible-pack --compare` run proving byte identity against the previous
toolchain, or with an explicit statement that hashes change.

## What determines tarball bytes

Established by experiment on 2bdbb33 (issue #344 evidence):

| Input | Status | Control |
|---|---|---|
| Source files at the revision | required input | clean exact revision, checked by PACK before and after packing |
| `dist/` build output | **was** nondeterministic: `core` and `conformance` built without clearing `dist/`, so leftover gitignored files (including `dist/tsdoc-metadata.json` from an earlier `api:check`) were packed | every publishable package's `prepack` (the lifecycle `pnpm pack` runs) starts from an empty `dist/` and rebuilds it. `core` and `conformance` clear `dist/` in `prepack` rather than `build`, so a parallel `pnpm -r` run that rebuilds them never deletes declarations other packages are compiling against |
| Order of rewritten `workspace:` dependencies | **was** nondeterministic: pnpm 10 inserts rewritten dependencies in async completion order, so packages with two workspace dependencies (all adapters) were packed as `{core, guard}` or `{guard, core}` | `.pnpmfile.cjs` `beforePacking` restores the source manifest order; fails the pack if names differ |
| `packages/conformance/dist/evidence-metadata.json` | intended repository metadata, see below | revision and dirty state are inputs, not noise |
| pnpm tar headers | normalized by pnpm: fixed mtime (1985-10-26), mode 0644, uid/gid 0, deterministic entry order (by extension, then path; independent of directory order) | none needed |
| `TZ`, locale (`LANG`/`LC_ALL`), `umask` | no effect observed | none needed |
| Node.js 20.18.1 / 22.9.0 / 22.22.0 / 24.11.1 | no effect observed | pinned anyway (provenance) |
| outer pnpm 9.15.9 / 10.20.0 / 10.34.5 / 10.34.6 | no effect observed for single-workspace-dependency packages | pinned anyway |

## Repository metadata in distributable artifacts

Only `@oxdeai/conformance` embeds repository metadata, in
`dist/evidence-metadata.json` `source` (see `docs/conformance/evidence-scope.md`):

| Field | Permitted value in a release tarball |
|---|---|
| `source.revision` | the exact 40-hex revision being released |
| `source.workingTreeDirty` | `false` |
| `source.artifacts` | SHA-256 of the registered source files at that revision |

`S_freeze` requires `revision === candidate SHA` and `workingTreeDirty === false`.
These fields are evidence, so they are never normalized or removed: a package
packed from a dirty tree **should** differ, and PACK refuses to produce it.

Forbidden in any distributable file: build timestamps or dates, host or user
names, absolute paths, environment variables, branch names, and tool-version
metadata not determined by the lockfile.

## Procedure

From a clean checkout of the revision, on the pinned toolchain:

```bash
pnpm install --frozen-lockfile
pnpm verify:reproducible-pack --runs 5 --out /tmp/repro-a/packs --report /tmp/repro-a/report.json
```

The command refuses a dirty checkout, an unpinned toolchain, fewer than two runs,
or an existing output directory. It fails if any package produced more than one
hash, and if the checkout changed during the runs. It never publishes and never
touches a release directory.

Cross-environment check: repeat in an independent environment (separate host or
container image, fresh clone, fresh pnpm store) and compare:

```bash
git bundle create oxdeai.bundle <branch-at-revision>
# in the other environment, after cloning the bundle and checking out the revision:
pnpm install --frozen-lockfile
pnpm verify:reproducible-pack --runs 5 --compare /path/to/repro-a/report.json
```

`--compare` fails unless the revision and every package's SHA-256 are identical.

CI runs `pnpm test:release` and `pnpm verify:reproducible-pack --runs 3` on every
push (`release-reproducibility` job).

## Frozen artifacts: no repack after VERIFY_LOCAL

- The local CLI order is `precheck`, then `pack`, then `verify-local`, all with the
  same `--release-dir`. `precheck` persists its observations (source revision,
  clean-tree result, package set, versions and `package.json` digests, POLICY digest)
  as `local-precheck.json` in that directory. `pack` consumes that receipt and binds
  it into the release manifest and state; it fails closed if the receipt is absent,
  malformed, stale, or does not match the candidate it is about to pack.
  `verify-local` and readiness use the bound receipt. Callers must not synthesize or
  reconstruct historical `localPrecheck` evidence. This is evidence continuity for
  readiness/provenance only: readiness is not authorization, and authorization is
  not execution. `precheck` and `pack` both refuse a release directory that already
  holds release evidence, so an existing frozen release identity is never
  re-prechecked, regenerated or repacked as a recovery mechanism.
- A release is packed exactly once by `node scripts/release-2.0/orchestrator.mjs pack`,
  which observes the checkout itself: clean, at exactly `sourceRevision`, before
  packing and again after the last tarball. If the checkout changed, no manifest is
  written and the release directory can never be completed.
- Reproducibility tarballs are evidence only. They are never entered into a release
  manifest, verified for publication, or published.
- After `VERIFY_LOCAL`, resume, publication and recovery use the original tarballs.
  Reproducibility makes a lost tarball reconstructible for comparison; it does not
  authorize replacing a frozen artifact.
- Already published or frozen 2.0.x artifacts are not regenerated by this procedure.
  Note that from this change on, `@oxdeai/core` tarballs no longer contain
  `dist/tsdoc-metadata.json` (2.0.0 and 2.0.1 do, because it was left in `dist/` by
  an earlier `api:check`).
