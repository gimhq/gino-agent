#!/usr/bin/env bash
# Build the spike binaries in a sibling container: spike-vmm and spike-host (dynamic),
# spike-guest (static glibc) and the guest/ scripts copied into the guest root. Output: $OUT/bin.
#
# Environment:
#   OUT    output dir (default: <worktree>/.tmp/vm-spike)
#   IMAGE  build image (default: ai-agent/gino-vm-spike:1.96)
set -euo pipefail

WT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
OUT="${OUT:-$WT/.tmp/vm-spike}"
IMAGE="${IMAGE:-ai-agent/gino-vm-spike:1.96}"
CARGO_REGISTRY="${CARGO_REGISTRY-/srv/station/root/.cargo/registry}"
CARGO_GIT="${CARGO_GIT-/srv/station/root/.cargo/git}"
SPIKE="$WT/vm/spike"

docker build -q --label ai-agent=true -t "$IMAGE" "$SPIKE" >/dev/null
mkdir -p "$OUT/bin" "$OUT/target"

mounts=(-v "$SPIKE:$SPIKE" -v "$OUT:$OUT")
[[ -n "$CARGO_REGISTRY" ]] && mounts+=(-v "$CARGO_REGISTRY:/usr/local/cargo/registry")
[[ -n "$CARGO_GIT" ]] && mounts+=(-v "$CARGO_GIT:/usr/local/cargo/git")

read -r -d '' inner <<'IN' || true
set -euo pipefail
cargo build --release --locked --bin spike-vmm --bin spike-host
RUSTFLAGS='-C target-feature=+crt-static' \
  cargo build --release --locked --target x86_64-unknown-linux-gnu --bin spike-guest
cp "$CARGO_TARGET_DIR/release/spike-vmm" "$CARGO_TARGET_DIR/release/spike-host" \
  "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/spike-guest" "$BIN/"
chown -R "$OWNER" "$CARGO_TARGET_DIR" "$BIN"
IN

docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-vm-spike-build-$$" \
  "${mounts[@]}" \
  -w "$SPIKE" \
  -e CARGO_TERM_COLOR=never \
  -e CARGO_TARGET_DIR="$OUT/target" \
  -e BIN="$OUT/bin" \
  -e OWNER="$(id -u):$(id -g)" \
  "$IMAGE" bash -c "$inner"

if [[ -d "$OUT/rootfs" ]]; then
  install -D -m 0755 "$OUT/bin/spike-guest" "$OUT/rootfs/usr/local/bin/spike-guest"
  install -d "$OUT/rootfs/usr/local/lib/spike"
  install -m 0755 "$SPIKE"/guest/*.sh "$OUT/rootfs/usr/local/lib/spike/"
fi
echo "build-spike: $OUT/bin"
