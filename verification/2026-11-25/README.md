# Independent rebuild of the OxDeAI npm release (2026-11-25)

**Verdict: reproducible.** All ten `@oxdeai/*` packages served by npm rebuild byte for byte
from the signed release commit `448804a378148cbddd5544bad4dadff41e9f96f6`.

Verifier: Daniel Andrei R. Garcia (WalletScrutiny).\
Machine: Linux x86_64, rootless Podman 4.9.3, a different machine from the maintainer's.\
Method: offline container build from the signed commit, `pnpm pack` twice per package, and a
byte-for-byte comparison with the tarball the npm registry serves.

## Results (build 2)

| Package | Version | Tag | sha256 (published = rebuilt, both packs) |
|---|---|---|---|
| @oxdeai/core | 2.0.3 | core-v2.0.3 | `8fca13954d697e72a0dee217cd39af6107f85fb34c49ac74a8b8897be1307d90` |
| @oxdeai/guard | 2.0.5 | guard-v2.0.5 | `6a26b597789b506f041f5e4ab792482aa7116e956359d84c514e982f6e5662fa` |
| @oxdeai/sdk | 2.0.3 | sdk-v2.0.3 | `e387ac22dbc086d34a96b37d75d9789215ae70f1d1b91cf65c019bbbe7740333` |
| @oxdeai/cli | 0.3.3 | cli-v0.3.3 | `9007cb43ea5f5a7c4c9f3cb5012a4b06ace06422a297a5e93adacb01edf0f79e` |
| @oxdeai/conformance | 2.0.4 | conformance-v2.0.4 | `fab6c618c40b96bba726d56d418998954b0f5676cf40cb4585c90f1ae6eacbaa` |
| @oxdeai/langgraph | 2.0.1 | langgraph-v2.0.1 | `ba1736d34ef039e7fc2fca5743c6edd4e403302e6968bc966d7d5edb7d0acf87` |
| @oxdeai/openai-agents | 2.0.1 | openai-agents-v2.0.1 | `a529ac0a68ce573fd573289f14d84d2b97b3d141c509864227ceddd35808f094` |
| @oxdeai/crewai | 2.0.1 | crewai-v2.0.1 | `b1a12db7f336de3f6c81bf3bc16793cf01ffd07fab9554c4faf272b195726e3e` |
| @oxdeai/autogen | 2.0.1 | autogen-v2.0.1 | `5cfc71090a0262bee023a3c1b4d06d0652e7ad823d161da1cb408405201a3607` |
| @oxdeai/openclaw | 2.0.1 | openclaw-v2.0.1 | `c1c39f3fe1c5a3f8c73d69e83a0e717dfbe3763b6658848d166020e3cff4989c` |

Also checked:

- All ten annotated tags point to the release commit. The tags are not signed.
- The commit has a good SSH signature for `docybo69@gmail.com`, ED25519 key
  `SHA256:E5dyFP+A6+AzPuTX4ALLPGXBRWGjcUXLCY1GGzJ6nC4` (key supplied by the maintainer).
- Each registry tarball matches the maintainer's sha256 and the registry's `dist.integrity`.
- After the build, the checkout had no changed or untracked files.

Full output: [build-2/summary.txt](build-2/summary.txt), [build-2/results.json](build-2/results.json),
[build-2/build.log](build-2/build.log), and the recording [casts/3-build-2.cast](casts/3-build-2.cast).

## Build 1: one difference, caused by our environment

The first run built from a `git archive` export in an image without `git`. Nine packages matched.
`@oxdeai/conformance` differed in one file, `dist/evidence-metadata.json`
([diff](build-1/conformance-evidence-metadata.diff)):

```diff
-    "revision": "448804a378148cbddd5544bad4dadff41e9f96f6",
-    "workingTreeDirty": false,
+    "revision": null,
+    "workingTreeDirty": null,
```

The conformance build runs `git rev-parse HEAD` and `git status` (`packages/conformance/src/evidenceScope.mjs`)
and records `null` when git is unavailable. Build 2 adds git to the image and builds from a real
checkout of the commit, and the package then matches. This is not a defect in the release. Note that
the conformance tarball depends on building from a git checkout, not a source export.
Recording: [casts/2-build-1.cast](casts/2-build-1.cast).

## How the build is isolated

The build runs OxDeAI's code, so it runs in a locked-down container:

- rootless Podman, no network, read-only root filesystem, uid 65534, no capabilities, no-new-privileges
- 3 GB memory, 2 CPUs, 160 processes, 10-minute limit
- no writable host mount: the packs come back as a size-limited tar stream
- terminal control characters are stripped from the build output shown on screen

Dependencies are downloaded beforehand by `stage-oxdeai-store.sh` (`pnpm fetch`). That networked
container receives only `pnpm-lock.yaml` and `pnpm-workspace.yaml`, runs no OxDeAI code and no install
scripts, and refuses any lockfile entry that is not a registry package pinned by sha512. All 196 are.

## Reproduce it

Requirements: Linux x86_64, rootless Podman, git, Python 3, npm (only to fetch the toolchain).

```bash
# Toolchain: Node 22.23.4 and pnpm 10.34.5 from npm (hashes are pinned in the scripts)
npm install --prefix /tmp/oxdeai-tools-20261125 --registry=https://registry.npmjs.org \
  --ignore-scripts --no-audit --no-fund node-linux-x64@22.23.4 pnpm@10.34.5

# The scripts expect a clone named "oxdeai" next to their own folder
mkdir work && cp -r scripts/* work/ && git clone https://github.com/oxdeai/oxdeai.git oxdeai

cd work
./make-oxdeai-build-image.sh        # one-time: base image + git; pin the printed ID as image=
./reproduce-oxdeai-release.sh --test-isolation
./stage-oxdeai-store.sh
OXDEAI_STORE=$PWD/pnpm-store ./reproduce-oxdeai-release.sh
```

The base image is a local `eclipse-temurin:17-jre` (Ubuntu 26.04), pinned by image ID
`sha256:3ef798d5f15a0b81f3a2fb7cfdd5bc8274bf48aa562c5862410b0637754712a7`. On another machine,
use any glibc-based Linux image and replace the IDs in `make-oxdeai-build-image.sh` and
`reproduce-oxdeai-release.sh`. Node and pnpm come from the mounted toolchain, not from the image.

Script hashes for build 2: `reproduce-oxdeai-release.sh`
`4ecd125f0dfc7a198b684fdebbe3414faf2fef33d63a2eb5773db387d6c2a0f9`, `release-evidence.py`
`f9a88c2a5077727df50102dd5eb168b08092647f40aa1feb35d254dea7e5feef`.

## Limitations

- Node and pnpm are npm packages pinned by hash. They are not checked against upstream signatures.
- Dependencies come from the npm registry, checked by pnpm against the signed commit's lockfile.
  This shows the tarballs match source and lockfile. It does not audit the dependencies or toolchain.
- pnpm did not run dependency install scripts (canvas, esbuild, puppeteer), and the build did not need them.
- One build on one machine. Both packs come from the same build, so they show pack stability only.
- Only the ten current `latest` versions are covered.
- npm has no provenance attestation and no `gitHead` for these versions, so this rebuild is
  what links each tarball to the commit.

## Recordings

Play with `asciinema play casts/<file>`:

1. [1-isolation-test.cast](casts/1-isolation-test.cast): container isolation test
2. [2-build-1.cast](casts/2-build-1.cast): build 1 (earlier script version; build output went to a log)
3. [3-build-2.cast](casts/3-build-2.cast): build 2, everything on screen
