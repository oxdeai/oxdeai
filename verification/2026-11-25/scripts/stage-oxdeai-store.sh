#!/usr/bin/env bash
# Stage the offline pnpm 10 dependency store for reproduce-oxdeai-release.sh.
# Fetch only: the networked container gets two data files from the signed commit,
# pnpm-lock.yaml and pnpm-workspace.yaml. No OxDeAI code runs here (.pnpmfile.cjs
# is ignored), no build, no install scripts. pnpm checks every package against
# the sha512 integrity in the lockfile and downloads only from registry.npmjs.org.
set -euo pipefail
umask 077
base=$(cd -- "$(dirname -- "$0")" && pwd)
commit=448804a378148cbddd5544bad4dadff41e9f96f6
# Same local eclipse-temurin:17-jre image ID as the release runner.
image=sha256:3ef798d5f15a0b81f3a2fb7cfdd5bc8274bf48aa562c5862410b0637754712a7
toolroot=${OXDEAI_TOOLS:-/tmp/oxdeai-tools-20261125}
repo="$base/../oxdeai"
store="$base/pnpm-store"
case "$#:${1:-}" in
  0:) ;;
  1:--help) echo "Usage: $0"
    echo "Downloads the dependencies of commit $commit into $store."
    echo "Then run: OXDEAI_STORE=$store ./reproduce-oxdeai-release.sh"
    exit 0 ;;
  *) echo "Invalid arguments. See --help." >&2; exit 2 ;;
esac
[[ ! -e $store ]] || { echo "$store already exists. Move it aside for a fresh store." >&2; exit 2; }
pod=(podman --remote=false)
[[ $("${pod[@]}" info --format '{{.Host.Security.Rootless}}') == true ]] || { echo 'Rootless Podman required' >&2; exit 2; }
nodebin=$(realpath -e "$toolroot/node_modules/node-linux-x64/bin/node")
pnpm=$(realpath -e "$toolroot/node_modules/pnpm")
# Pinned tool hashes (node-linux-x64 22.23.4 binary, pnpm 10.34.5 package), recorded 2026-11-25.
# The pnpm hash covers every file of the package (sorted "sha256  path" list, hashed).
pnpm_tree() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | cut -d' ' -f1; }
[[ $(sha256sum < "$nodebin" | cut -d' ' -f1) == 94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90 \
  && -z $(find "$pnpm" -type l) \
  && $(pnpm_tree "$pnpm") == 0379640d85555dc5099c657809fcea63197198e4f48861e9dee36e8e1098211e ]] \
  || { echo 'Node or pnpm in OXDEAI_TOOLS does not match the pinned hash.' >&2; exit 2; }

# Staging dir next to the final store, so the store moves in place without copying.
stage=$(mktemp -d "$base/stage-XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/inputs" "$stage/store" "$stage/work"
for f in pnpm-lock.yaml pnpm-workspace.yaml; do
  git -C "$repo" show "$commit:$f" > "$stage/inputs/$f"
done
chmod 755 "$stage" "$stage/inputs"
chmod 644 "$stage/inputs/"*
# Refuse anything that could redirect where packages come from.
if git -C "$repo" ls-tree -r --name-only "$commit" | grep -Eq '(^|/)\.(npmrc|yarnrc)'; then
  echo 'The release commit contains an .npmrc or .yarnrc; review it before fetching.' >&2; exit 2
fi
if grep -Ev '^(packages:|  - "[A-Za-z0-9_*/.-]+")$' "$stage/inputs/pnpm-workspace.yaml" | grep -q .; then
  echo 'pnpm-workspace.yaml holds more than the package list; review it before fetching.' >&2; exit 2
fi
lock="$stage/inputs/pnpm-lock.yaml"
total=$(grep -c 'resolution:' "$lock" || true)
registry=$(grep -cE 'resolution: \{integrity: sha512-[A-Za-z0-9+/]+={0,2}\}$' "$lock" || true)
if [[ $total -eq 0 || $total -ne $registry ]] || grep -Eq 'tarball:|git\+|github:|directory:' "$lock"; then
  echo "Lockfile has non-registry or unhashed sources ($registry of $total registry sha512)." >&2; exit 2
fi
echo "[OK] Lockfile: $total of $total packages pinned to registry sha512 hashes"
echo "Lockfile sha256: $(sha256sum < "$lock" | cut -d' ' -f1)"

# keep-id: files land owned by you, not a subordinate UID.
"${pod[@]}" run --rm --pull=never --userns=keep-id --user="$(id -u):$(id -g)" \
  --cap-drop=ALL --security-opt=no-new-privileges --read-only --read-only-tmpfs=false \
  --image-volume=ignore --http-proxy=false --log-driver=none \
  --memory=3g --memory-swap=3g --cpus=2 --pids-limit=160 --timeout=1800 --shm-size=1m \
  --tmpfs=/scratch:rw,nosuid,nodev,size=1g,mode=1777 \
  --volume="$stage/inputs:/inputs:ro" --volume="$stage/store:/store:rw" \
  --volume="$stage/work:/work:rw" \
  --volume="$nodebin:/opt/bin/node:ro" --volume="$pnpm:/opt/pnpm:ro" \
  --entrypoint=/usr/bin/env "$image" -i HOME=/scratch/home TMPDIR=/scratch/tmp \
  PATH=/scratch/bin:/opt/bin:/usr/bin:/bin CI=true /bin/sh -eu -c '
    mkdir -p "$HOME" "$TMPDIR" /scratch/bin
    ln -s /opt/pnpm/bin/pnpm.cjs /scratch/bin/pnpm
    test "$(node --version)" = v22.23.4
    test "$(pnpm --version)" = 10.34.5
    cp /inputs/pnpm-lock.yaml /inputs/pnpm-workspace.yaml /work/
    cd /work
    pnpm fetch --store-dir /store --ignore-scripts --ignore-pnpmfile \
      --registry=https://registry.npmjs.org/
  '
[[ -d $stage/store/v10 ]] || { echo 'Fetch finished but no v10 store was written.' >&2; exit 2; }
# The release runner reads the store as an unprivileged container user.
chmod -R go+rX,go-w "$stage/store"
mv "$stage/store" "$store"
echo "Store: $store ($(du -sh "$store" | cut -f1))"
echo "Next: OXDEAI_STORE=$store ./reproduce-oxdeai-release.sh"
