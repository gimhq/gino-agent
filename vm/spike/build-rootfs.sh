#!/usr/bin/env bash
# Export a Debian bookworm slim image into a root directory for the guest.
# Output: $OUT/rootfs (spike-guest is copied in by build-spike.sh).
#
# Environment:
#   OUT    output dir (default: <worktree>/.tmp/vm-spike)
#   BASE   base image (default: debian:bookworm-slim)
set -euo pipefail

WT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
OUT="${OUT:-$WT/.tmp/vm-spike}"
BASE="${BASE:-debian:bookworm-slim}"

if [[ -x "$OUT/rootfs/bin/sh" ]]; then
  echo "build-rootfs: $OUT/rootfs already populated"
  exit 0
fi

docker pull -q "$BASE" >/dev/null
digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$BASE")"
cid="$(docker create --label ai-agent=true --name "ai-agent-gino-vm-spike-rootfs-$$" "$BASE" /bin/true)"
trap 'docker rm -f "$cid" >/dev/null' EXIT
mkdir -p "$OUT/rootfs"
docker export "$cid" | tar -x -C "$OUT/rootfs"
echo "$digest" > "$OUT/rootfs.digest"
echo "build-rootfs: $digest -> $OUT/rootfs"
