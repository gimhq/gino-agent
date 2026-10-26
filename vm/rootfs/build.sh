#!/usr/bin/env bash
# Build the guest root image from vm/rootfs/Dockerfile and write it as an ext4 base image.
# Outputs in $OUT: rootfs.ext4 (the base image, raw ext4), rootfs.image (image ID) and
# rootfs.versions (pinned and installed versions). Re-running with an unchanged image keeps the
# existing output.
#
# Environment:
#   OUT       output dir (default: <worktree>/.tmp/vm/rootfs)
#   VERSION   image tag (default: first 12 hex chars of the Dockerfile's sha256)
#   HEADROOM  free space added to the tree size, in MiB (default: 512)
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="$(git -C "$DIR" rev-parse --show-toplevel)"
OUT="${OUT:-$WT/.tmp/vm/rootfs}"
VERSION="${VERSION:-$(sha256sum "$DIR/Dockerfile" | cut -c1-12)}"
HEADROOM="${HEADROOM:-512}"
IMAGE="ai-agent/gino-vm-rootfs:$VERSION"

docker build --provenance=false --label ai-agent=true -t "$IMAGE" "$DIR"
image_id="$(docker image inspect --format '{{.Id}}' "$IMAGE")"

if [[ -f "$OUT/rootfs.ext4" && "$(cat "$OUT/rootfs.image" 2>/dev/null)" == "$image_id" ]]; then
  echo "build-rootfs: $OUT/rootfs.ext4 already holds $image_id"
  exit 0
fi
if [[ -e "$OUT" && ! -f "$OUT/rootfs.image" && -n "$(ls -A "$OUT")" ]]; then
  echo "build-rootfs: $OUT exists and was not written by this script" >&2
  exit 1
fi
mkdir -p "$OUT"

cid="$(docker create --label ai-agent=true --name "ai-agent-gino-vm-rootfs-$$" "$IMAGE" /bin/true)"
staging="$OUT/.staging-$$"
trap 'docker rm -f "$cid" >/dev/null; rm -rf "$staging"' EXIT
mkdir -p "$staging/tree"
docker export "$cid" | tar -x -C "$staging/tree"

# mke2fs -d copies the tree with its owners and modes; a fixed UUID, hash seed and clock keep
# the image stable for one image ID.
uuid="$(printf '%s' "$image_id" | sha256sum | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12}).*/\1-\2-\3-\4-\5/')"
size_mib=$(( $(du -sm "$staging/tree" | cut -f1) * 11 / 10 + HEADROOM ))
docker run --rm --label ai-agent=true --name "ai-agent-gino-vm-mkfs-$$" \
  -v "$staging:/work" -e E2FSPROGS_FAKE_TIME=1 \
  "$IMAGE" mkfs.ext4 -q -F -L gino-root -U "$uuid" -E "hash_seed=$uuid,root_owner=0:0" \
    -d /work/tree /work/rootfs.ext4 "${size_mib}M"
mv "$staging/rootfs.ext4" "$OUT/rootfs.ext4"

echo "$image_id" > "$OUT/rootfs.image"
{
  echo "image=$IMAGE"
  echo "image_id=$image_id"
  sed -n 's/^FROM \(.*\)$/base=\1/p; s/^ARG \(\(CLAUDE\|DOCKER\|CONTAINERD\|BUILDX\|COMPOSE\)_[A-Z0-9_]*=.*\)$/\1/p' "$DIR/Dockerfile"
  docker run --rm --label ai-agent=true "$IMAGE" \
    sh -c 'echo "claude=$(claude --version)"; dpkg-query -W -f "\${Package}=\${Version}\n"'
} > "$OUT/rootfs.versions"
echo "build-rootfs: $image_id -> $OUT/rootfs.ext4 (${size_mib} MiB)"
