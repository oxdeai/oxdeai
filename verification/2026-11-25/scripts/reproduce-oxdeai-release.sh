#!/usr/bin/env bash
# OxDeAI release reproducibility check: rebuild every @oxdeai package of the signed
# release commit offline in a locked-down container and compare it byte for byte
# with the tarball on the npm registry. Prints a summary at the end.
set -euo pipefail
umask 077
base=$(cd -- "$(dirname -- "$0")" && pwd)
commit=448804a378148cbddd5544bad4dadff41e9f96f6
# Built by make-oxdeai-build-image.sh: the eclipse-temurin:17-jre base below plus git 2.53.0.
# conformance records `git rev-parse HEAD` and a clean-tree flag, so the build needs git.
image=sha256:c07736e3c2494b8505205e8f0384fa7fbdd82162ec87f00fb215d7833a4d1f4b
image_tag=localhost/oxdeai-build-git:20261125
base_image=sha256:3ef798d5f15a0b81f3a2fb7cfdd5bc8274bf48aa562c5862410b0637754712a7
started=$SECONDS
toolroot=${OXDEAI_TOOLS:-/tmp/oxdeai-tools-20261125}
repo="$base/../oxdeai"
pkg=
fixture=false
case "$#:${1:-}" in
  0:) ;;
  1:--test-isolation) fixture=true ;;
  2:--package) pkg=$2; [[ -n $pkg ]] || exit 2 ;;
  1:--help) echo "Usage: $0 [--test-isolation | --package @oxdeai/NAME]"
    echo "For a rebuild, set OXDEAI_STORE to a dedicated, pre-staged pnpm 10 store for this release."
    echo "OXDEAI_TOOLS may point to a directory containing node_modules/{node-linux-x64,pnpm}."
    exit 0 ;;
  *) echo "Invalid arguments. See --help." >&2; exit 2 ;;
esac
pod=(podman --remote=false)
[[ $("${pod[@]}" info --format '{{.Host.Security.Rootless}}') == true ]] || { echo 'Rootless Podman required' >&2; exit 2; }
# Keep preflight inputs separate from the host-only sentinel and all evidence.
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir "$tmp/inputs"
touch "$tmp/host-only" "$tmp/inputs/probe"
awk -F '\t' -v name="$pkg" 'NR>1 && (name=="" || $1==name)' "$base/release-packages.tsv" > "$tmp/inputs/selected.tsv"
[[ -s "$tmp/inputs/selected.tsv" ]] || { echo 'Unknown package' >&2; exit 2; }
nodebin=$(realpath -e "$toolroot/node_modules/node-linux-x64/bin/node")
pnpm=$(realpath -e "$toolroot/node_modules/pnpm")
# Pinned tool hashes (node-linux-x64 22.23.4 binary, pnpm 10.34.5 package), recorded 2026-11-25.
# The pnpm hash covers every file of the package (sorted "sha256  path" list, hashed).
pnpm_tree() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) | sha256sum | cut -d' ' -f1; }
[[ $(sha256sum < "$nodebin" | cut -d' ' -f1) == 94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90 \
  && -z $(find "$pnpm" -type l) \
  && $(pnpm_tree "$pnpm") == 0379640d85555dc5099c657809fcea63197198e4f48861e9dee36e8e1098211e ]] \
  || { echo 'Node or pnpm in OXDEAI_TOOLS does not match the pinned hash.' >&2; exit 2; }
limits=(--pull=never --network=none --user=65534:65534 --cap-drop=ALL
  --security-opt=no-new-privileges --read-only --read-only-tmpfs=false
  --image-volume=ignore --http-proxy=false --log-driver=none
  --memory=3g --memory-swap=3g --cpus=2 --pids-limit=160
  --ulimit=fsize=134217728:134217728 --timeout=600 --shm-size=1m
  --tmpfs=/scratch:rw,nosuid,nodev,size=2g,mode=1777
  --volume="$tmp/inputs:/inputs:ro" --volume="$nodebin:/opt/bin/node:ro"
  --volume="$pnpm:/opt/pnpm:ro" --entrypoint=/usr/bin/env)
container() {
  "${pod[@]}" run --rm "${limits[@]}" "$image" -i HOME=/scratch/home TMPDIR=/scratch/tmp \
    PATH=/scratch/bin:/opt/bin:/usr/bin:/bin CI=true /bin/sh -eu -c "$1" sh "${@:2}"
}
preflight='
  test "$(id -u)" = 65534
  mkdir -p "$HOME" "$TMPDIR" /scratch/bin
  ln -s /opt/pnpm/bin/pnpm.cjs /scratch/bin/pnpm
  test "$(node --version)" = v22.23.4
  test "$(pnpm --version)" = 10.34.5
  test ! -e "$1" && test ! -S /var/run/docker.sock || exit 1
  if (echo x > /inputs/probe) 2>/dev/null; then exit 1; fi
  if (echo x > /root-write-probe) 2>/dev/null; then exit 1; fi
  grep -Eq "^CapEff:[[:space:]]+0+$" /proc/self/status
  grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/self/status
  test "$(cat /sys/fs/cgroup/memory.max)" = 3221225472
  test "$(cat /sys/fs/cgroup/pids.max)" = 160
  awk "{exit !(\$1 > 0 && \$1 <= 2 * \$2)}" /sys/fs/cgroup/cpu.max
  node /inputs/network.cjs
'
cat > "$tmp/inputs/network.cjs" <<'JS'
const fs = require("node:fs");
const net = require("node:net");
if (fs.readdirSync("/sys/class/net").some(name => name !== "lo")) process.exit(1);
const socket = net.connect(443, "192.0.2.1");
socket.setTimeout(1000, () => process.exit(1));
socket.on("connect", () => process.exit(1));
socket.on("error", error => process.exit(["ENETUNREACH","EHOSTUNREACH"].includes(error.code) ? 0 : 1));
JS
chmod 755 "$tmp/inputs"
chmod 644 "$tmp/inputs/"*.{cjs,tsv}
chmod 666 "$tmp/inputs/probe" "$tmp/host-only"
step() { echo; echo "======================================================"; echo "$*"
  echo "======================================================"; }
step "OxDeAI release reproducibility check"
echo "commit:   $commit"
echo "packages: $(wc -l < "$tmp/inputs/selected.tsv") from release-packages.tsv"
echo "image:    $image_tag $image"
step "1. Container isolation test (no OxDeAI code)"
container "$preflight" "$tmp/host-only"
echo '[OK] Isolation fixture passed.'
if "$fixture"; then exit 0; fi
if [[ -z ${OXDEAI_STORE:-} || ! -d $OXDEAI_STORE/v10 ]]; then
  echo 'Build paused. A dedicated offline pnpm 10 dependency store (OXDEAI_STORE/v10) is required.' >&2
  echo 'Run ./stage-oxdeai-store.sh first.' >&2
  exit 2
fi
store=$(realpath -e "$OXDEAI_STORE/v10")
step "2. Release tags and commit signature"
tagcount=0
while IFS=$'\t' read -r name ver tag dir sha sri; do
  [[ $(git -C "$repo" rev-parse --verify "refs/tags/$tag^{commit}") == "$commit" ]] \
    || { echo "[ERROR] $tag does not point to $commit" >&2; exit 1; }
  echo "[OK] $tag -> $commit"
  tagcount=$((tagcount + 1))
done < <(tail -n +2 "$base/release-packages.tsv")
signer_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID5u52moj1MkCbjavhi6HEIvNdNVpR13lvHGb4GModgU'
echo "docybo69@gmail.com $signer_key" > "$tmp/allowed_signers"
signature=$(git -C "$repo" -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$tmp/allowed_signers" \
  verify-commit "$commit" 2>&1) || { echo "$signature" >&2; echo '[ERROR] Commit signature check failed' >&2; exit 1; }
echo "$signature"
signer_fpr=$(ssh-keygen -lf - <<< "$signer_key" | awk '{print $2}')
# A git bundle of the first release tag (the commit and its history). The container
# fetches it into a fresh repository, so git inside reports the real commit.
first_tag=$(awk -F '\t' 'NR==2{print $3}' "$base/release-packages.tsv")
git -C "$repo" bundle create "$tmp/inputs/source.bundle" "refs/tags/$first_tag" 2>/dev/null
chmod 644 "$tmp/inputs/source.bundle"
mkdir -p "$base/runs"
run=$(mktemp -d "$base/runs/release-XXXXXXXX")
cp "$tmp/inputs/selected.tsv" "$run/selected.tsv"
printf '%s\n' "$commit" "$image" > "$run/source-and-image.txt"
step "3. Published npm tarballs (reference)"
echo "Evidence: $run"
python3 -I "$base/release-evidence.py" fetch "$run"
limits+=(--volume="$store:/dependencies/v10:ro")
# No writable host mount. Only a size-limited tar stream crosses back.
build='
  mkdir -p /scratch/export /scratch/bin "$HOME" "$TMPDIR"
  ln -s /opt/pnpm/bin/pnpm.cjs /scratch/bin/pnpm
  export GIT_CONFIG_NOSYSTEM=1
  git init --quiet /scratch/src
  cd /scratch/src
  git -c transfer.fsckObjects=true fetch --quiet /inputs/source.bundle "refs/tags/$2:refs/tags/$2"
  git -c advice.detachedHead=false checkout --quiet --detach "$1"
  test "$(git rev-parse HEAD)" = "$1"
  echo "Source: clean checkout of $(git rev-parse HEAD), git $(git --version | cut -d" " -f3)" >&2
  cp -R /dependencies /scratch/store
  chmod -R u+w /scratch/store
  pnpm install --offline --frozen-lockfile --store-dir /scratch/store >&2
  pnpm build >&2
  while read -r name ver tag dir sha sri; do
    slug=${name#@oxdeai/}
    for pass in 1 2; do
      dest=/scratch/export/$pass/$slug
      mkdir -p "$dest"
      (cd "$dir" && pnpm pack --pack-destination "$dest") >&2 || { rm -f -- "$dest"/*.tgz; continue; }
    done
  done < /inputs/selected.tsv
  echo "Working tree after build: $(git status --porcelain --untracked-files=normal | wc -l) changed entries" >&2
  cd /scratch/export
  tar -cf - 1 2
'
step "4. Offline build and pack (output below is from the container)"
# Packs go to output.tar; build messages go to build.log and, with terminal
# control characters removed, to the screen. Both are size-limited.
build_ok=true
(ulimit -f 131072; container "$build" "$commit" "$first_tag" 2>&1 > "$run/output.tar" | tee "$run/build.log" \
  | python3 -I "$base/release-evidence.py" sanitize) || build_ok=false
compare_rc=2
if "$build_ok"; then
  step "5. Comparison"
  compare_rc=0
  (ulimit -v 524288; ulimit -t 45; timeout 60 python3 -I "$base/release-evidence.py" compare "$run") || compare_rc=$?
else
  echo "[ERROR] Build incomplete. See $run/build.log" >&2
fi
elapsed=$((SECONDS - started))
{
  echo "commit=$commit"
  echo "tags=$tagcount of $(($(wc -l < "$base/release-packages.tsv") - 1)) annotated tags point to this commit"
  echo "commit_signature=[OK] $(head -n 1 <<< "$signature")"
  echo "signer=docybo69@gmail.com ssh-ed25519 $signer_fpr"
  echo "script_sha256=$(sha256sum < "$base/reproduce-oxdeai-release.sh" | cut -d' ' -f1)"
  echo "helper_sha256=$(sha256sum < "$base/release-evidence.py" | cut -d' ' -f1)"
  echo "image=$image"
  echo "image_tag=$image_tag"
  echo "base_image=$base_image"
  echo "node_sha256=$(sha256sum < "$nodebin" | cut -d' ' -f1)"
  echo "pnpm_sha256=$(pnpm_tree "$pnpm")"
  echo "lockfile_sha256=$(git -C "$repo" show "$commit:pnpm-lock.yaml" | sha256sum | cut -d' ' -f1)"
  echo "store=$store ($(du -sh "$store" | cut -f1))"
  echo "elapsed=$((elapsed / 60))m $((elapsed % 60))s"
} > "$run/facts.txt"
step "VERIFICATION SUMMARY"
python3 -I "$base/release-evidence.py" summary "$run" || true
echo "Evidence: $run"
echo "Build log: $run/build.log"
exit "$compare_rc"
