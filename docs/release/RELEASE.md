# OxDeAI Release Policy

## Status

Normative maintainer policy.

Last updated: 2026-04-22

This document is the source of truth for OxDeAI release governance. `docs/release/RELEASING.md` is the executable runbook for this policy. Announcement files under `docs/release/` are communication drafts only and do not define release policy.

## 1. Release Model

OxDeAI uses package-scoped versions and package-scoped release tags.

Each published package owns its own version line. A release of one package does not imply that any other package has the same version or must be published.

Multiple package releases may be coordinated on the same Git commit. In that case, each released package still gets its own version, tag, changelog entry, npm publication, and GitHub release record.

A coordinated release commit does not create a shared package version line.

## 2. Released Packages

Supported package-scoped release tag prefixes:

| npm package | package path | tag prefix |
|---|---|---|
| `@oxdeai/core` | `packages/core` | `core-vX.Y.Z` |
| `@oxdeai/sdk` | `packages/sdk` | `sdk-vX.Y.Z` |
| `@oxdeai/conformance` | `packages/conformance` | `conformance-vX.Y.Z` |
| `@oxdeai/guard` | `packages/guard` | `guard-vX.Y.Z` |
| `@oxdeai/cli` | `packages/cli` | `cli-vX.Y.Z` |
| `@oxdeai/langgraph` | `packages/langgraph` | `langgraph-vX.Y.Z` |
| `@oxdeai/crewai` | `packages/crewai` | `crewai-vX.Y.Z` |
| `@oxdeai/autogen` | `packages/autogen` | `autogen-vX.Y.Z` |
| `@oxdeai/openai-agents` | `packages/openai-agents` | `openai-agents-vX.Y.Z` |
| `@oxdeai/openclaw` | `packages/openclaw` | `openclaw-vX.Y.Z` |

Other packages in `packages/` must not be released publicly unless their package-scoped tag prefix, changelog requirement, validation gates, and npm publish target are added to this policy first.

Examples, demos, benchmarks, and internal tests do not define release status.

## 3. Tag Policy

All new package releases must use package-scoped tags:

```text
<package-prefix>-v<package.json version>
```

Allowed active prefixes:

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

Rules:

- The tag version must exactly match the released package's `package.json` version.
- The tag must point to the exact commit used for npm publication.
- Prefer annotated tags. Sign tags with `-s` when maintainer signing is available.
- Multiple package-scoped tags may point to the same commit.
- A package-scoped tag must not be reused or moved after publication.

Global `vX.Y.Z` tags are legacy. Do not create new global `vX.Y.Z` tags for package releases.

Global tags may only be introduced for a separately documented compatibility bundle or top-level announcement. Such a bundle tag must not replace package-scoped release tags and must include an explicit manifest mapping package names, package versions, package tags, npm versions, and the Git commit.

The historical shared prefix `adapters-vX.Y.Z` is retired. A single tag covering all five adapter
packages cannot satisfy the rule that a tag version exactly matches one package's `package.json`
version, so it must not be created again. The existing `adapters-v1.0.0` and `adapters-v1.0.1`
tags are retained as historical record and must not be moved or deleted. From the 2.0 line onward,
each adapter uses its own package-scoped prefix as listed above.

Any other historical or suspicious prefix must not be reused unless this policy is updated first.

Historical documentation and changelog entries may mention coordinated global `vX.Y.Z` releases or shared protocol-stack version lines. Those entries explain past releases only. They are not current release policy.

## 4. Versioning Rules

Each released package follows SemVer on its own version line.

Patch releases should be backward compatible for that package.

Minor releases may add backward-compatible features for that package.

Major releases are required for breaking changes in that package's public API, protocol-facing behavior, or documented runtime semantics.

For protocol-facing packages, breaking changes include changes to:

- canonicalization behavior
- hashing or signature binding
- `AuthorizationV1` semantics
- verification result semantics
- PEP enforcement semantics
- stable test-vector meaning
- documented public API symbols

The current package-scoped model does not require `core`, `sdk`, and `conformance` to share one version number.

## 5. Coordinated Release Commits

Maintainers may release multiple packages from one commit when changes are intentionally coordinated.

For each package in a coordinated release:

- bump that package's `package.json` version
- update that package's changelog
- create that package's tag
- publish that package to npm
- create that package's GitHub release
- verify that package's npm version

Example: one commit may carry all of these tags:

```text
core-v1.7.0
sdk-v1.3.2
conformance-v1.5.0
guard-v1.0.2
```

Those tags on one commit mean the releases were coordinated. They do not mean the packages share a version line.

### Core dependency compatibility

A release of `@oxdeai/core` MAY ship independently only when every supported
published integration remains compatible with the new Core version under the
dependency ranges consumers actually receive.

If a supported package pins Core to an exact version and exchanges Core-owned
public types across its package boundary, a Core release that would otherwise
cause consumers to install incompatible Core copies MUST be coordinated with
that dependent package.

Before releasing Core independently, maintainers MUST verify the packed
dependency topology and a consumer-level integration using the documented
public API. Dependency compatibility MUST be selected explicitly; it must not
be inferred from workspace protocol declarations alone.

## 6. Changelog Requirements

Every released package must have a changelog entry before tagging.

Existing changelog paths:

- `packages/core/CHANGELOG.md`
- `packages/sdk/CHANGELOG.md`
- `packages/conformance/CHANGELOG.md`
- `packages/guard/CHANGELOG.md`
- `packages/cli/CHANGELOG.md`

The changelog entry must include:

- package name
- package version
- release date
- user-visible changes
- security-relevant changes, if any
- breaking changes, if any
- migration notes, if needed

If a package does not have a changelog, add one before its first public release and update this policy.

## 7. Required Validation Gates

Run the release preflight before every public package release:

```bash
pnpm release:preflight --package <package-short-name>
```

Use `--check-npm` before publishing when network access is available:

```bash
pnpm release:preflight --package <package-short-name> --check-npm
```

Run the repository-wide gates before every public package release:

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

Run package-specific gates for every package being released:

| Package | Required gates |
|---|---|
| `@oxdeai/core` | `pnpm -C packages/core api:check`; `pnpm -C packages/core api:fingerprint:check` |
| `@oxdeai/sdk` | covered by repository-wide build/test unless package-specific gates are added |
| `@oxdeai/conformance` | `pnpm -C packages/conformance validate` |
| `@oxdeai/guard` | `pnpm -C packages/guard test` |
| `@oxdeai/cli` | package build/test plus CLI smoke checks when CLI behavior changes |

Run demos or smoke checks when the release changes demoed behavior, CLI flows, PEP enforcement, adapters, or public examples.

All required gates must pass before tags are created and before npm publication.

## 8. API and Conformance Baselines

Update baselines only when the underlying change is intentional and reviewed.

For `@oxdeai/core` API changes:

```bash
pnpm -C packages/core api:report
pnpm -C packages/core api:fingerprint
pnpm -C packages/core api:check
pnpm -C packages/core api:fingerprint:check
```

Review these files before committing baseline changes:

- `packages/core/temp/core.api.md`
- `packages/core/etc/core.api.md`
- `packages/core/API_FINGERPRINT`

Generated files under `temp/` are inspection outputs. Commit only the intended baseline files required by the package's API process.

For conformance changes:

```bash
pnpm -C packages/conformance extract
pnpm -C packages/conformance validate
```

Conformance vectors are protocol artifacts. Do not regenerate or edit vectors for a release unless the vector change is intentional, reviewed, and described in the changelog or release notes for the affected package.

## 9. npm Publication Requirements

Publish only from the committed and tagged state.

Before publishing each package:

```bash
npm view <package-name> version --registry=https://registry.npmjs.org
pnpm -C <package-path> pack --pack-destination /tmp
```

Inspect the package tarball when package contents changed.

Publish with npm public registry targeting:

```bash
pnpm -C <package-path> publish --access public --registry=https://registry.npmjs.org
```

If npm provenance is required by the maintainer's environment, use the registry-supported provenance flag and document that in the release notes or release issue. Do not publish from an uncommitted or untagged state.

After publishing:

```bash
npm view <package-name> version --registry=https://registry.npmjs.org
npm view <package-name>@<version> dist.tarball --registry=https://registry.npmjs.org
```

The npm version must match the package's `package.json` and package-scoped Git tag.

## 10. GitHub Release Requirements

GitHub releases are required for public npm package releases.

Create one GitHub release per package-scoped tag.

The GitHub release must include:

- package name
- package version
- Git tag
- npm package/version
- changelog summary or link
- validation commands run
- security notes, if any
- compatibility notes, if any

For coordinated releases, it is acceptable to create multiple GitHub releases pointing to tags on the same commit. A single top-level announcement may be added, but it does not replace the package-scoped GitHub releases.

## 11. Failed Release and Partial Publish Recovery

Git tags and npm publications are immutable release evidence.

If a tag was created but npm publish did not occur:

1. Do not move the tag if it was pushed.
2. Fix only release-process issues that do not change package contents, then publish from the tagged commit.
3. If package contents must change, create a new version and a new tag.

If one package in a coordinated release publishes successfully and another fails:

1. Do not unpublish or rewrite the successful package except under npm's emergency rules.
2. Fix the failed package with a new version if package contents must change.
3. Document the partial release and recovery in the failed package's changelog/GitHub release.
4. Verify the final npm/GitHub/tag mapping after recovery.

If a bad package was published:

1. Publish a new corrective version.
2. Mark the bad GitHub release with a warning.
3. Do not move or reuse the original tag.

## 12. Security and Provenance

- Published versions must correspond to committed and tagged repository state.
- Do not commit secrets, OTPs, private keys, or production signing material.
- Test signing material must be clearly test-only.
- Security-relevant changes must be mentioned in the package changelog and GitHub release.
- Follow coordinated disclosure guidance in `docs/security/SECURITY.md`.

## 13. Compatibility Bundles

A compatibility bundle is optional and separate from package releases.

Use a compatibility bundle only when maintainers need to announce that a set of independently versioned packages is known to work together.

A compatibility bundle must include a manifest with:

- bundle name
- bundle date
- Git commit
- package names
- package versions
- package-scoped tags
- npm package URLs or versions
- validation commands run

A compatibility bundle may use a global tag only if the manifest exists before the tag is created. The global tag must not be named in a way that implies shared package versions unless the manifest explicitly says so.

## 14. Tag Hygiene

Use:

```bash
pnpm tags:audit
pnpm tags:cleanup:dry
```

Do not delete or rewrite remote release tags without maintainer approval and a written recovery note.
