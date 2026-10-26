#!/usr/bin/env bash
# Build libkrun from source at a pinned tag in a sibling container and fetch the
# pinned prebuilt libkrunfw release. Output: $OUT/lib/{libkrun.so.1,libkrunfw.so.5}.
#
# Environment:
#   OUT    output dir (default: <worktree>/.tmp/vm-spike)
#   IMAGE  build image (default: ai-agent/gino-vm-spike:1.96, built from vm/spike/Dockerfile)
set -euo pipefail

LIBKRUN_TAG=v1.19.7
LIBKRUN_COMMIT=43b2f5aadeebb90f42053c9df2ec8b16583e554f
LIBKRUNFW_TAG=v5.6.2
LIBKRUNFW_SHA256=016c32ddb2a28aa300382cab33352d63a41a901eb36ee8d1ca24b389791c8b91

WT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
OUT="${OUT:-$WT/.tmp/vm-spike}"
IMAGE="${IMAGE:-ai-agent/gino-vm-spike:1.96}"
CARGO_REGISTRY="${CARGO_REGISTRY-/srv/station/root/.cargo/registry}"
CARGO_GIT="${CARGO_GIT-/srv/station/root/.cargo/git}"

if [[ -e "$OUT/lib/libkrun.so.1" && -e "$OUT/lib/libkrunfw.so.5" ]]; then
  echo "build-libkrun: $OUT/lib already populated"
  exit 0
fi

mkdir -p "$OUT/src" "$OUT/lib" "$OUT/dl"
src="$OUT/src/libkrun"
if [[ ! -d "$src/.git" ]]; then
  git clone -q --depth 1 --branch "$LIBKRUN_TAG" https://github.com/containers/libkrun.git "$src"
fi
head="$(git -C "$src" rev-parse HEAD)"
[[ "$head" == "$LIBKRUN_COMMIT" ]] || { echo "build-libkrun: $LIBKRUN_TAG is $head, expected $LIBKRUN_COMMIT" >&2; exit 1; }

docker build -q --label ai-agent=true -t "$IMAGE" "$WT/vm/spike" >/dev/null

mounts=(-v "$OUT:$OUT")
[[ -n "$CARGO_REGISTRY" ]] && mounts+=(-v "$CARGO_REGISTRY:/usr/local/cargo/registry")
[[ -n "$CARGO_GIT" ]] && mounts+=(-v "$CARGO_GIT:/usr/local/cargo/git")

docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-vm-spike-libkrun-$$" \
  "${mounts[@]}" \
  -w "$src" \
  -e CARGO_TERM_COLOR=never \
  "$IMAGE" bash -c "make NET=1 -j\"\$(nproc)\" && cp -L target/release/libkrun.so.1.19.7 '$OUT/lib/libkrun.so.1' && chown -R $(id -u):$(id -g) target '$OUT/lib'"

tgz="$OUT/dl/libkrunfw-x86_64-$LIBKRUNFW_TAG.tgz"
curl -fsSL -o "$tgz" "https://github.com/containers/libkrunfw/releases/download/$LIBKRUNFW_TAG/libkrunfw-x86_64.tgz"
echo "$LIBKRUNFW_SHA256  $tgz" | sha256sum -c --quiet
tar -xzf "$tgz" -C "$OUT/dl"
cp -L "$OUT/dl/lib/x86_64-linux-gnu/libkrunfw.so.5" "$OUT/lib/libkrunfw.so.5"

echo "build-libkrun: libkrun $LIBKRUN_TAG ($LIBKRUN_COMMIT), libkrunfw $LIBKRUNFW_TAG -> $OUT/lib"
