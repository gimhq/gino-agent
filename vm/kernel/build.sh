#!/usr/bin/env bash
# Build the guest kernel in a sibling container: the pinned 6.12 LTS tarball from
# cdn.kernel.org (sha256-verified), `make tinyconfig`, the config-x86_64 fragment merged
# with scripts/kconfig/merge_config.sh, `make olddefconfig`, then `make vmlinux`.
# Output: $OUT/vmlinux, an uncompressed ELF image for krun_set_kernel with
# KRUN_KERNEL_FORMAT_ELF (1), plus $OUT/config (the resolved .config) and
# $OUT/fragment.sha256. Skips the build when they exist for the current fragment.
#
# Environment:
#   OUT    output dir (default: <worktree>/.tmp/vm/kernel)
#   SRC    download and build dir (default: <worktree>/.tmp/vm/src/kernel)
#   IMAGE  build image, built from vm/kernel/Dockerfile
#          (default: ai-agent/gino-vm-kernel-build:bookworm)
set -euo pipefail

KERNEL_VERSION=6.12.114
KERNEL_SHA256=7a8589912bd7a8adb07fed074283652cf482a35facef8954554654f0154b4af3
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"

for tool in docker git curl sha256sum; do
  command -v "$tool" >/dev/null || { echo "kernel: $tool is required" >&2; exit 2; }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$WT/.tmp/vm/kernel}"
SRC="${SRC:-$WT/.tmp/vm/src/kernel}"
IMAGE="${IMAGE:-ai-agent/gino-vm-kernel-build:bookworm}"

fragment_sha="$(sha256sum "$HERE/config-x86_64" | cut -d' ' -f1)"
if [[ -f "$OUT/vmlinux" && -f "$OUT/config" && "$(cat "$OUT/fragment.sha256" 2>/dev/null)" == "$fragment_sha" ]]; then
  echo "kernel: $OUT/vmlinux already built"
  exit 0
fi

mkdir -p "$OUT" "$SRC"
tarball="$SRC/linux-$KERNEL_VERSION.tar.xz"
tree="$SRC/linux-$KERNEL_VERSION"
if ! echo "$KERNEL_SHA256  $tarball" | sha256sum -c --status 2>/dev/null; then
  curl -fsSL -o "$tarball.part" "$KERNEL_URL"
  echo "$KERNEL_SHA256  $tarball.part" | sha256sum -c --quiet
  mv "$tarball.part" "$tarball"
fi
cp "$HERE/config-x86_64" "$SRC/config-x86_64"

docker build -q --label ai-agent=true -t "$IMAGE" "$HERE" >/dev/null

read -r -d '' inner <<'INNER' || true
set -euo pipefail
if [[ ! -f "$TREE/Makefile" ]]; then
  rm -rf "$TREE"
  tar -xJf "$TARBALL" -C "$(dirname "$TREE")"
fi
cd "$TREE"
make ARCH=x86_64 tinyconfig >/dev/null
scripts/kconfig/merge_config.sh -m .config "$FRAGMENT" >/dev/null
make ARCH=x86_64 olddefconfig >/dev/null
missing=()
while IFS= read -r line; do
  if [[ "$line" =~ ^(CONFIG_[A-Za-z0-9_]+)=(.*)$ ]]; then
    grep -qxF "$line" .config || missing+=("$line")
  elif [[ "$line" =~ ^#\ (CONFIG_[A-Za-z0-9_]+)\ is\ not\ set$ ]]; then
    ! grep -q "^${BASH_REMATCH[1]}=" .config || missing+=("$line")
  fi
done <"$FRAGMENT"
[[ ${#missing[@]} -eq 0 ]] || { printf 'kernel: not in the resolved .config: %s\n' "${missing[@]}" >&2; exit 1; }
make ARCH=x86_64 -j"$(nproc)" vmlinux
install -m 0644 vmlinux "$OUT/vmlinux"
install -m 0644 .config "$OUT/config"
INNER

docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-vm-kernel-$$" \
  --user "$(id -u):$(id -g)" \
  -v "$SRC:$SRC" -v "$OUT:$OUT" \
  -e HOME=/tmp \
  -e TARBALL="$tarball" -e TREE="$tree" -e FRAGMENT="$SRC/config-x86_64" -e OUT="$OUT" \
  -e KBUILD_BUILD_USER=gino -e KBUILD_BUILD_HOST=gino \
  "$IMAGE" bash -c "$inner"

echo "$fragment_sha" > "$OUT/fragment.sha256"
echo "kernel: linux $KERNEL_VERSION -> $OUT/vmlinux"
