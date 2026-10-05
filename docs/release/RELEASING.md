# Releasing OxDeAI Packages

## Status

Normative release runbook.

This runbook implements the package-scoped release policy in `docs/release/RELEASE.md`.

## Active Model

OxDeAI releases packages independently with package-scoped versions and package-scoped tags.

Allowed new release tags:

```text
core-vX.Y.Z
sdk-vX.Y.Z
conformance-vX.Y.Z
guard-vX.Y.Z
cli-vX.Y.Z
langgraph-vX.Y.Z
crewai-vX.Y.Z
autogen-vX.Y.Z
openai-agents-vX.Y.Z
openclaw-vX.Y.Z
```

Global `vX.Y.Z` tags are legacy for package releases. Do not create them for normal package releases.

Multiple package tags may point to the same commit when the releases are coordinated. That does not imply shared package versions.

## Reproducible Packaging

Release tarballs must be byte-for-byte reproducible from a clean revision on the
pinned toolchain (Node in `.node-version`, pnpm in `packageManager`). Inputs, the
`pnpm verify:reproducible-pack` procedure, cross-environment comparison and the
no-repack rule are defined in [`REPRODUCIBLE-BUILDS.md`](./REPRODUCIBLE-BUILDS.md).

## Preflight

From the repository root:

```bash
git fetch origin --tags --prune
git status -sb
pnpm install --frozen-lockfile
pnpm release:preflight --package core
```

The working tree must be clean before tagging or publishing.

The preflight package value is the short package name:

```text
core
sdk
conformance
guard
cli
```

The default preflight is local-only. Add `--check-npm` when network access is available and the release is close to publication:

```bash
pnpm release:preflight --package core --check-npm
```

The preflight validates:

- package exists and is configured for release
- package name matches the release policy
- `package.json` version is valid
- planned tag is package-scoped and matches `package.json`
- planned tag does not already exist locally
- worktree is clean
- `pnpm-lock.yaml` exists and has no uncommitted drift
- changelog contains the target version
- optional GitHub release metadata matches the planned tag
- optional npm check confirms the version is not already published

Examples:

```bash
pnpm release:preflight --package core
pnpm release:preflight --package core --tag core-v1.7.1
pnpm release:preflight --package core --check-npm
pnpm release:preflight --package core --github-release-tag core-v1.7.1 --github-release-title "core v1.7.1"
```

Example pass:

```text
PASS package.json version is X.Y.Z: 1.7.1
PASS tag uses package-scoped naming: core-v1.7.1
PASS changelog contains target version: packages/core/CHANGELOG.md 1.7.1
Release preflight PASSED
```

Example failure: tag mismatch.

```bash
pnpm release:preflight --package core --tag sdk-v1.7.1
```

```text
FAIL tag uses package-scoped naming: sdk-v1.7.1
FAIL tag version matches package.json version: sdk-v1.7.1 expected core-v1.7.1
Release preflight FAILED
```

Example failure: missing changelog entry.

```text
FAIL changelog contains target version: packages/core/CHANGELOG.md 1.7.1
Release preflight FAILED
```

Example failure: dirty worktree.

```text
FAIL git worktree is clean: M packages/core/package.json
Release preflight FAILED
```

Example failure: npm version conflict.

```bash
pnpm release:preflight --package core --check-npm
```

```text
FAIL npm package version is not already published: @oxdeai/core@1.7.0
Release preflight FAILED
```

Check existing tags and releases:

```bash
pnpm tags:audit
git tag --sort=-creatordate | head -30
gh release list --limit 30
```

Check current npm versions:

```bash
npm view @oxdeai/core version --registry=https://registry.npmjs.org
npm view @oxdeai/sdk version --registry=https://registry.npmjs.org
npm view @oxdeai/conformance version --registry=https://registry.npmjs.org
npm view @oxdeai/guard version --registry=https://registry.npmjs.org
npm view @oxdeai/cli version --registry=https://registry.npmjs.org
```

## Single-Package Release Steps

Replace the example package values with the package being released.

Example:

```text
package: @oxdeai/core
path: packages/core
version: 1.7.1
tag: core-v1.7.1
```

1. Update the package version.

```bash
pnpm -C packages/core version 1.7.1 --no-git-tag-version
pnpm install --no-frozen-lockfile
```

2. Update the package changelog.

```text
packages/core/CHANGELOG.md
```

3. Run validation gates.

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
pnpm -C packages/core api:check
pnpm -C packages/core api:fingerprint:check
```

For other packages, use the package-specific gates in `docs/release/RELEASE.md`.

4. Review release diff.

```bash
git diff --stat
git diff -- packages/core/package.json packages/core/CHANGELOG.md pnpm-lock.yaml
```

5. Commit release changes.

```bash
git add packages/core/package.json packages/core/CHANGELOG.md pnpm-lock.yaml
git commit -m "chore(release): core v1.7.1"
```

6. Create the package-scoped tag.

```bash
git tag -a core-v1.7.1 -m "core v1.7.1"
```

Use `git tag -s` instead of `-a` when signing is available.

7. Push the commit and tag.

```bash
git push origin main
git push origin core-v1.7.1
```

8. Pack and publish from the tagged commit.

```bash
git show --no-patch --decorate core-v1.7.1
pnpm -C packages/core pack --pack-destination /tmp
pnpm -C packages/core publish --access public --registry=https://registry.npmjs.org
```

9. Verify npm publication.

```bash
npm view @oxdeai/core version --registry=https://registry.npmjs.org
npm view @oxdeai/core@1.7.1 dist.tarball --registry=https://registry.npmjs.org
```

10. Create the GitHub release.

```bash
gh release create core-v1.7.1 --title "core v1.7.1" --notes-file /tmp/core-v1.7.1-release-notes.md
```

The release notes must include package name, version, tag, npm package/version, changelog summary, validation commands run, and security notes if relevant.

## Coordinated Multi-Package Release Steps

Use this when multiple packages should release from the same commit.

1. Choose each package's own next version.

Example:

```text
@oxdeai/core         1.7.1  core-v1.7.1
@oxdeai/sdk          1.3.3  sdk-v1.3.3
@oxdeai/conformance  1.5.1  conformance-v1.5.1
@oxdeai/guard        1.0.3  guard-v1.0.3
```

2. Bump each package version without creating tags.

```bash
pnpm -C packages/core version 1.7.1 --no-git-tag-version
pnpm -C packages/sdk version 1.3.3 --no-git-tag-version
pnpm -C packages/conformance version 1.5.1 --no-git-tag-version
pnpm -C packages/guard version 1.0.3 --no-git-tag-version
pnpm install --no-frozen-lockfile
```

3. Update each released package's changelog.

4. Run all required repository-wide and package-specific gates.

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
pnpm -C packages/core api:check
pnpm -C packages/core api:fingerprint:check
pnpm -C packages/conformance validate
pnpm -C packages/guard test
```

5. Commit once.

```bash
git add packages/core/package.json packages/sdk/package.json packages/conformance/package.json packages/guard/package.json
git add packages/core/CHANGELOG.md packages/sdk/CHANGELOG.md packages/conformance/CHANGELOG.md packages/guard/CHANGELOG.md pnpm-lock.yaml
git commit -m "chore(release): coordinated package release"
```

6. Create one package-scoped tag per released package on that commit.

```bash
git tag -a core-v1.7.1 -m "core v1.7.1"
git tag -a sdk-v1.3.3 -m "sdk v1.3.3"
git tag -a conformance-v1.5.1 -m "conformance v1.5.1"
git tag -a guard-v1.0.3 -m "guard v1.0.3"
```

7. Push the commit and tags.

```bash
git push origin main
git push origin core-v1.7.1 sdk-v1.3.3 conformance-v1.5.1 guard-v1.0.3
```

8. Publish each package from the tagged commit.

```bash
pnpm -C packages/core publish --access public --registry=https://registry.npmjs.org
pnpm -C packages/sdk publish --access public --registry=https://registry.npmjs.org
pnpm -C packages/conformance publish --access public --registry=https://registry.npmjs.org
pnpm -C packages/guard publish --access public --registry=https://registry.npmjs.org
```

9. Verify each npm version.

```bash
npm view @oxdeai/core version --registry=https://registry.npmjs.org
npm view @oxdeai/sdk version --registry=https://registry.npmjs.org
npm view @oxdeai/conformance version --registry=https://registry.npmjs.org
npm view @oxdeai/guard version --registry=https://registry.npmjs.org
```

10. Create one GitHub release per package tag.

## GitHub Releases

GitHub releases are required for public npm package releases.

Use the package-scoped tag as the release tag and the package name/version as the title.

Example:

```bash
gh release view core-v1.7.1
gh release create core-v1.7.1 --title "core v1.7.1" --notes-file /tmp/core-v1.7.1-release-notes.md
```

## Failure Handling

If npm publish fails before any package is published, fix the release process and retry from the same tagged commit if package contents do not change.

If package contents must change, bump to a new version and create a new tag.

If one package in a coordinated release publishes and another fails, do not rewrite the successful release. Fix the failed package with a new version if contents must change, and document the partial recovery.

Never move a pushed release tag to hide a bad release.
