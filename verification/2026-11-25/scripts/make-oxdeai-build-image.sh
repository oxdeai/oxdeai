#!/usr/bin/env bash
# One-time setup: derive the OxDeAI build image by adding git to the pinned base.
# @oxdeai/conformance runs `git rev-parse HEAD` and `git status` at build time and
# records both in dist/evidence-metadata.json, so the build needs a real git.
# Network is used only for apt (Ubuntu's signed archive). No OxDeAI code runs here.
set -euo pipefail
umask 077
# Local eclipse-temurin:17-jre (Ubuntu 26.04) image ID, as used for build 1.
base=sha256:3ef798d5f15a0b81f3a2fb7cfdd5bc8274bf48aa562c5862410b0637754712a7
tag=localhost/oxdeai-build-git:20261125
pod=(podman --remote=false)
[[ $("${pod[@]}" info --format '{{.Host.Security.Rootless}}') == true ]] || { echo 'Rootless Podman required' >&2; exit 2; }
ctx=$(mktemp -d)
trap 'rm -rf -- "$ctx"' EXIT
cat > "$ctx/Containerfile" <<EOF
FROM $base
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends git \\
 && rm -rf /var/lib/apt/lists/* \\
 && git --version
EOF
"${pod[@]}" build --pull=never --cap-drop=ALL --cap-add=CHOWN,DAC_OVERRIDE,FOWNER,SETUID,SETGID \
  --tag "$tag" --file "$ctx/Containerfile" "$ctx"
id=$("${pod[@]}" image inspect --format '{{.Id}}' "$tag")
ver=$("${pod[@]}" run --rm --pull=never --network=none --entrypoint=/usr/bin/git "sha256:$id" --version)
echo "Image: $tag"
echo "Image ID: sha256:$id"
echo "git: $ver"
echo "Pin this ID as 'image=' in reproduce-oxdeai-release.sh."
