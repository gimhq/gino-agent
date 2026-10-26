#!/usr/bin/env bash
# Build gino-vmm with libkrun compiled in (static musl binary, no NEEDED entries) in a
# sibling container: `cargo build --profile dist --locked --target x86_64-unknown-linux-musl`
# in gino-vmm/ (mounted read-only). Output: $OUT/gino-vmm. Cargo rebuilds only what changed.
#
# Environment:
#   OUT             output dir (default: <worktree>/.tmp/vm/bin)
#   TARGET_DIR      cargo target dir (default: <worktree>/.tmp/vm/target)
#   IMAGE           build image, built from vm/vmm/Dockerfile
#                   (default: ai-agent/gino-vmm-build:1.96)
#   CARGO_REGISTRY  host dir mounted as the container's cargo registry cache
#                   (default: /srv/station/root/.cargo/registry; empty = no mount)
#   CARGO_GIT       host dir mounted as the container's cargo git checkout cache
#                   (default: /srv/station/root/.cargo/git; empty = no mount)
set -euo pipefail

TARGET=x86_64-unknown-linux-musl

for tool in docker git; do
  command -v "$tool" >/dev/null || { echo "vmm: $tool is required" >&2; exit 2; }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$WT/.tmp/vm/bin}"
TARGET_DIR="${TARGET_DIR:-$WT/.tmp/vm/target}"
IMAGE="${IMAGE:-ai-agent/gino-vmm-build:1.96}"
CARGO_REGISTRY="${CARGO_REGISTRY-/srv/station/root/.cargo/registry}"
CARGO_GIT="${CARGO_GIT-/srv/station/root/.cargo/git}"

docker build -q --label ai-agent=true -t "$IMAGE" "$HERE" >/dev/null

mkdir -p "$OUT" "$TARGET_DIR"
mounts=(-v "$WT/gino-vmm:$WT/gino-vmm:ro" -v "$TARGET_DIR:$TARGET_DIR" -v "$OUT:$OUT")
[[ -n "$CARGO_REGISTRY" ]] && mounts+=(-v "$CARGO_REGISTRY:/usr/local/cargo/registry")
[[ -n "$CARGO_GIT" ]] && mounts+=(-v "$CARGO_GIT:/usr/local/cargo/git")

read -r -d '' inner <<'INNER' || true
set -euo pipefail
cargo build --profile dist --locked --target "$TARGET"
bin="$CARGO_TARGET_DIR/$TARGET/dist/gino-vmm"
needed="$(readelf -d "$bin" | grep '(NEEDED)' || true)"
[[ -z "$needed" ]] || { printf 'vmm: %s is not static:\n%s\n' "$bin" "$needed" >&2; exit 1; }
install -m 0755 "$bin" "$OUT/gino-vmm"
chown -R "$OWNER" "$CARGO_TARGET_DIR" "$OUT/gino-vmm"
INNER

docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-vmm-build-$$" \
  "${mounts[@]}" \
  -w "$WT/gino-vmm" \
  -e CARGO_TERM_COLOR=never -e CARGO_TARGET_DIR="$TARGET_DIR" \
  -e TARGET="$TARGET" -e OUT="$OUT" -e OWNER="$(id -u):$(id -g)" \
  "$IMAGE" bash -c "$inner"

echo "vmm: $OUT/gino-vmm"
