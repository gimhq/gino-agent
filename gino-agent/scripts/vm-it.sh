#!/usr/bin/env bash
# Run the KVM integration tests of `vm` isolation (tests/vm.rs and the ignored
# `kvm_*` unit tests of src/sandbox/vm.rs) in sibling containers.
#
# Steps: build (or reuse) the guest kernel, the guest root image and the
# static gino-vmm binary with the vm/*/build.sh scripts; build the gino-agent
# test binaries; copy the root image to a test image that adds
# `/usr/local/sbin/{claude,codex}` dispatchers (they exec
# `$GINO_IT_FAKES/<name>` when the test shares such a fake engine, else the
# real binary), owned by uid 1000 so the daemons hard-link it as their base
# instead of copying it; then run the ignored tests as uid 1000 with /dev/kvm
# (their workspaces on the same mount as the image), and the no-KVM
# fail-closed test once more without the device.
#
# The run container sits on its own network with a public-style subnet, so the
# `full` network scenario has a public destination to reach.
#
# Environment:
#   AGENT_IMAGE     gino-agent build and test run image
#                   (default: ai-agent/gino-agent-gates:1.96)
#   PUBLIC_SUBNET   subnet of the run network (default: 192.88.99.0/24)
#   PUBLIC_IP       the run container's address in it (default: 192.88.99.10)
#   FILTER          test name filter for tests/vm.rs (default: all)
#   CARGO_REGISTRY  host dir mounted as the container's cargo registry cache
#                   (default: /srv/station/root/.cargo/registry; empty = no mount)
#   CARGO_GIT       host dir mounted as the container's cargo git checkout cache
#                   (default: /srv/station/root/.cargo/git; empty = no mount)
set -euo pipefail

for tool in docker git; do
  command -v "$tool" >/dev/null || { echo "vm-it: $tool is required" >&2; exit 2; }
done
[[ -c /dev/kvm ]] || { echo "vm-it: /dev/kvm is missing" >&2; exit 2; }

WT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
VM="$WT/.tmp/vm"
AGENT_IMAGE="${AGENT_IMAGE:-ai-agent/gino-agent-gates:1.96}"
PUBLIC_SUBNET="${PUBLIC_SUBNET:-192.88.99.0/24}"
PUBLIC_IP="${PUBLIC_IP:-192.88.99.10}"
FILTER="${FILTER:-}"
CARGO_REGISTRY="${CARGO_REGISTRY-/srv/station/root/.cargo/registry}"
CARGO_GIT="${CARGO_GIT-/srv/station/root/.cargo/git}"
AGENT_TARGET="$VM/agent-target"
ROOTFS_IT="$VM/rootfs-it.ext4"
LOGS="$WT/.tmp/vm-it-logs"

TMP="$VM/it-$$"
NET="ai-agent-gino-vm-it-$$"
mkdir -p "$TMP/state"
cleanup() {
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

docker image inspect "$AGENT_IMAGE" >/dev/null 2>&1 \
  || { echo "vm-it: image $AGENT_IMAGE is missing (set AGENT_IMAGE)" >&2; exit 2; }

# Guest artifacts and gino-vmm; each script skips work already done.
OUT="$VM/kernel" "$WT/vm/kernel/build.sh"
OUT="$VM/rootfs" "$WT/vm/rootfs/build.sh"
OUT="$VM/bin" CARGO_REGISTRY="$CARGO_REGISTRY" CARGO_GIT="$CARGO_GIT" "$WT/vm/vmm/build.sh"

cache=()
[[ -n "$CARGO_REGISTRY" ]] && cache+=(-v "$CARGO_REGISTRY:/usr/local/cargo/registry")
[[ -n "$CARGO_GIT" ]] && cache+=(-v "$CARGO_GIT:/usr/local/cargo/git")

# The gino-agent test binaries, statically linked: the guest runs the agent binary
# from a boot root that holds nothing else.
mkdir -p "$AGENT_TARGET"
docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-vm-it-build-agent-$$" \
  "${cache[@]}" \
  -v "$WT:$WT" \
  -w "$WT/gino-agent" \
  -e CARGO_TERM_COLOR=never -e CARGO_TARGET_DIR="$AGENT_TARGET" -e OUT="$TMP/bins" \
  -e RUSTFLAGS="-C target-feature=+crt-static" \
  "$AGENT_IMAGE" bash -c '
    set -euo pipefail
    cargo test --release --locked --target x86_64-unknown-linux-gnu --lib --test vm --no-run 2>&1 | tee /tmp/build.log
    {
      echo "lib=$(sed -n "s/.*Executable unittests src\/lib.rs (\(.*\))$/\1/p" /tmp/build.log | tail -1)"
      echo "vm=$(sed -n "s/.*Executable tests\/vm.rs (\(.*\))$/\1/p" /tmp/build.log | tail -1)"
    } > "$OUT"'
lib_bin="$(sed -n 's/^lib=//p' "$TMP/bins")"
vm_bin="$(sed -n 's/^vm=//p' "$TMP/bins")"
[[ -n "$lib_bin" && -n "$vm_bin" ]] || { echo "vm-it: test binaries not found" >&2; exit 1; }
agent="$AGENT_TARGET/x86_64-unknown-linux-gnu/release/gino-agent"

# The test image: a copy of the root image plus the fake-engine dispatchers.
stamp="$(cat "$VM/rootfs/rootfs.image")"
if [[ ! -f "$ROOTFS_IT.image" || "$(cat "$ROOTFS_IT.image")" != "$stamp" ]]; then
  rm -f "$ROOTFS_IT" "$ROOTFS_IT.image"
  rootfs_image="$(sed -n 's/^image=//p' "$VM/rootfs/rootfs.versions")"
  docker run --rm \
    --label ai-agent=true \
    --name "ai-agent-gino-vm-it-image-$$" \
    -v "$VM:$VM" \
    -e SRC="$VM/rootfs/rootfs.ext4" -e DEST="$ROOTFS_IT" \
    "$rootfs_image" bash -c '
      set -euo pipefail
      cp --sparse=always "$SRC" "$DEST.tmp"
      for engine in claude codex; do
        printf "%s\n" "#!/bin/sh" \
          "if [ -n \"\${GINO_IT_FAKES:-}\" ] && [ -x \"\$GINO_IT_FAKES/$engine\" ]; then" \
          "  exec \"\$GINO_IT_FAKES/$engine\" \"\$@\"" \
          "fi" \
          "exec /usr/local/bin/$engine \"\$@\"" > "/tmp/$engine"
        debugfs -w -R "write /tmp/$engine /usr/local/sbin/$engine" "$DEST.tmp" >/dev/null
        debugfs -w -R "sif /usr/local/sbin/$engine mode 0100755" "$DEST.tmp" >/dev/null
      done
      chown 1000:1000 "$DEST.tmp"
      mv "$DEST.tmp" "$DEST"'
  echo "$stamp" > "$ROOTFS_IT.image"
fi

rm -rf "$LOGS"
mkdir -p "$LOGS"
chown 1000:1000 "$TMP/state" "$LOGS"
docker network create --label ai-agent=true --subnet "$PUBLIC_SUBNET" "$NET" >/dev/null

run_tests() {
  local name="$1"
  shift
  docker run --rm --init \
    --label ai-agent=true \
    --name "ai-agent-gino-vm-it-$name-$$" \
    --user 1000:1000 \
    --network "$NET" --ip "$PUBLIC_IP" \
    -v "$WT:$WT:ro" \
    -v "$VM:$VM" \
    -v "$LOGS:$LOGS" \
    -e HOME="$TMP/state" \
    -e TMPDIR="$TMP/state" \
    -e GINO_VM_TESTS=1 \
    -e GINO_VM_KERNEL="$VM/kernel/vmlinux" \
    -e GINO_VM_ROOTFS="$ROOTFS_IT" \
    -e GINO_VM_VMM="$VM/bin/gino-vmm" \
    -e GINO_VM_AGENT="$agent" \
    -e GINO_VM_PUBLIC_IP="$PUBLIC_IP" \
    -e GINO_VM_IT_LOGS="$LOGS" \
    "$@"
}

status=0
kvm=(--device /dev/kvm --group-add "$(stat -c %g /dev/kvm)")
echo "== kvm unit tests"
run_tests lib "${kvm[@]}" "$AGENT_IMAGE" "$lib_bin" --ignored --test-threads=1 kvm_ || status=$?
if [[ "$status" -eq 0 ]]; then
  echo "== tests/vm.rs"
  # shellcheck disable=SC2086
  run_tests vm "${kvm[@]}" "$AGENT_IMAGE" "$vm_bin" --ignored --test-threads=1 $FILTER || status=$?
fi
if [[ "$status" -eq 0 ]]; then
  echo "== tests/vm.rs without /dev/kvm"
  run_tests nokvm -e GINO_VM_NO_KVM=1 "$AGENT_IMAGE" \
    "$vm_bin" --ignored --exact vm_without_kvm_access_fails_closed || status=$?
fi

if [[ "$status" -eq 0 ]]; then
  echo "vm-it: all VM scenarios passed"
else
  echo "vm-it: FAILED (exit $status); daemon logs in $LOGS" >&2
fi
exit "$status"
