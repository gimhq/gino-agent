#!/usr/bin/env bash
# VM smoke test, end to end: builds gino-vmm (libkrun compiled in), the guest kernel and the
# guest root with the vm/*/build.sh scripts (each skips work already done), then, in a
# sibling container with /dev/kvm as uid 1000 and no libkrun library anywhere, runs
# `gino-vmm --probe` and checks its line, boots the self-built kernel through gino-vmm from an
# empty boot root holding the image's static busybox, attaches the root image read-only as
# /dev/vda, runs a guest script that mounts it and prints `uname -r`, the root filesystem type
# and `claude --version` from inside it, checks the output and the gino-vmm exit status and
# prints a PASS/FAIL summary.
#
# Environment:
#   OUT             gino-vmm output dir (default: <worktree>/.tmp/vm/bin)
#   KERNEL_DIR      kernel output dir (default: <worktree>/.tmp/vm/kernel)
#   ROOTFS_DIR      guest root image dir (default: <worktree>/.tmp/vm/rootfs)
#   TARGET_DIR      gino-vmm cargo target dir (default: <worktree>/.tmp/vm/target)
#   IMAGE           gino-vmm build image, built from vm/vmm/Dockerfile
#                   (default: ai-agent/gino-vmm-build:1.96)
#   RUN_IMAGE       image running gino-vmm (default: debian:bookworm-slim)
#   VCPUS           guest vCPUs (default: 1)
#   MEMORY_MIB      guest memory (default: 512)
#   TIMEOUT         seconds before the VM run is killed and counted as failed (default: 120)
#   CARGO_REGISTRY  host dir mounted as the container's cargo registry cache
#                   (default: /srv/station/root/.cargo/registry; empty = no mount)
#   CARGO_GIT       host dir mounted as the container's cargo git checkout cache
#                   (default: /srv/station/root/.cargo/git; empty = no mount)
set -euo pipefail

for tool in docker git jq; do
  command -v "$tool" >/dev/null || { echo "smoke: $tool is required" >&2; exit 2; }
done
[[ -c /dev/kvm ]] || { echo "smoke: /dev/kvm is missing" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="$(git -C "$HERE" rev-parse --show-toplevel)"
OUT="${OUT:-$WT/.tmp/vm/bin}"
KERNEL_DIR="${KERNEL_DIR:-$WT/.tmp/vm/kernel}"
ROOTFS_DIR="${ROOTFS_DIR:-$WT/.tmp/vm/rootfs}"
TARGET_DIR="${TARGET_DIR:-$WT/.tmp/vm/target}"
IMAGE="${IMAGE:-ai-agent/gino-vmm-build:1.96}"
RUN_IMAGE="${RUN_IMAGE:-debian:bookworm-slim}"
VCPUS="${VCPUS:-1}"
MEMORY_MIB="${MEMORY_MIB:-512}"
TIMEOUT="${TIMEOUT:-120}"
CARGO_REGISTRY="${CARGO_REGISTRY-/srv/station/root/.cargo/registry}"
CARGO_GIT="${CARGO_GIT-/srv/station/root/.cargo/git}"

TMP="$WT/.tmp/vm-smoke-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

OUT="$OUT" TARGET_DIR="$TARGET_DIR" IMAGE="$IMAGE" CARGO_REGISTRY="$CARGO_REGISTRY" \
  CARGO_GIT="$CARGO_GIT" "$HERE/vmm/build.sh"
OUT="$KERNEL_DIR" "$HERE/kernel/build.sh"
OUT="$ROOTFS_DIR" "$HERE/rootfs/build.sh"
VMM="$OUT/gino-vmm"

run_args=(
  --label ai-agent=true
  --device /dev/kvm
  --group-add "$(stat -c %g /dev/kvm)"
  --user 1000:1000
  -v "$OUT:$OUT:ro"
)

# init.krun creates its mount points in the boot root, as the VMM user.
mkdir -p "$TMP/boot"
chown 1000:1000 "$TMP/boot"
rootfs_image="$(sed -n 's/^image=//p' "$ROOTFS_DIR/rootfs.versions")"
docker run --rm --label ai-agent=true --name "ai-agent-gino-vm-smoke-busybox-$$" \
  -v "$ROOTFS_DIR:/rootfs:ro" -v "$TMP:/out" "$rootfs_image" \
  debugfs -R "dump /usr/bin/busybox /out/busybox" /rootfs/rootfs.ext4 >/dev/null
chmod 0755 "$TMP/busybox"

cat >"$TMP/smoke-guest.sh" <<'GUEST'
B=/busybox
$B mkdir -p /newroot
$B mount -t ext4 -o ro /dev/vda /newroot || exit 1
$B mount -t proc proc /newroot/proc
$B mount -t devtmpfs dev /newroot/dev
$B mount -t tmpfs tmp /newroot/tmp
echo "SMOKE uname=$($B uname -r)"
echo "SMOKE rootfs=$($B awk '$2 == "/newroot" {print $3}' /proc/mounts)"
echo "SMOKE claude=$($B chroot /newroot /usr/bin/env PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp claude --version 2>&1)"
GUEST

jq -nc \
  --arg kernel "$KERNEL_DIR/vmlinux" \
  --arg boot "$TMP/boot" \
  --arg disk "$ROOTFS_DIR/rootfs.ext4" \
  --arg busybox "$TMP/busybox" \
  --arg script "$TMP/smoke-guest.sh" \
  --argjson vcpus "$VCPUS" \
  --argjson mem "$MEMORY_MIB" \
  '{
    kernel: {path: $kernel, format: "elf"},
    rootDir: $boot,
    disks: [{id: "root", path: $disk, format: "raw", readOnly: true}],
    overlayFiles: [
      {hostPath: $busybox, guestPath: "/busybox"},
      {hostPath: $script, guestPath: "/smoke-guest.sh"}
    ],
    vcpus: $vcpus,
    memoryMib: $mem,
    exec: {path: "/busybox", args: ["sh", "/smoke-guest.sh"], env: {}, workdir: "/"}
  }' >"$TMP/spec.json"

echo "== probe"
probe_status=0
probe="$(docker run --rm "${run_args[@]}" --name "ai-agent-gino-vm-smoke-probe-$$" \
  "$RUN_IMAGE" sh -c 'find / -xdev -name "libkrun*" 2>/dev/null | sed "s/^/SMOKE libkrun-file=/"; "$0" --probe' "$VMM")" \
  || probe_status=$?
echo "$probe"
libkrun_files="$(grep -c '^SMOKE libkrun-file=' <<<"$probe" || true)"
probe_line="$(grep -v '^SMOKE ' <<<"$probe" || true)"

echo "== guest output"
status=0
docker run --rm -i "${run_args[@]}" \
  --name "ai-agent-gino-vm-smoke-run-$$" \
  -v "$KERNEL_DIR:$KERNEL_DIR:ro" \
  -v "$ROOTFS_DIR:$ROOTFS_DIR:ro" \
  -v "$TMP:$TMP" \
  "$RUN_IMAGE" bash -c '
    t0=${EPOCHREALTIME/./}
    timeout "$1" "$0"
    status=$?
    echo "SMOKE elapsed-ms=$(( (${EPOCHREALTIME/./} - t0) / 1000 ))"
    exit "$status"' "$VMM" "$TIMEOUT" <"$TMP/spec.json" 2>&1 | tee "$TMP/output.log" || status=$?

kernel_release="$(sed -n 's/^SMOKE uname=//p' "$TMP/output.log" | tr -d '\r')"
root_fs="$(sed -n 's/^SMOKE rootfs=//p' "$TMP/output.log" | tr -d '\r')"
claude_version="$(sed -n 's/^SMOKE claude=//p' "$TMP/output.log" | tr -d '\r')"
elapsed="$(sed -n 's/^SMOKE elapsed-ms=//p' "$TMP/output.log")"

failures=()
[[ "$probe_status" -eq 0 ]] || failures+=("gino-vmm --probe exit status $probe_status")
[[ "$probe_line" =~ ^gino-vmm\ [0-9]+\.[0-9]+\.[0-9]+\ libkrun\ 1\.19\.7$ ]] \
  || failures+=("probe line '$probe_line'")
[[ "$libkrun_files" -eq 0 ]] || failures+=("$libkrun_files libkrun* files in the run container")
if [[ "$status" -eq 124 ]]; then
  failures+=("no exit within ${TIMEOUT}s")
elif [[ "$status" -ne 0 ]]; then
  failures+=("gino-vmm exit status $status")
fi
[[ "$kernel_release" == *gino* ]] || failures+=("kernel release '$kernel_release' lacks 'gino'")
[[ "$root_fs" == ext4 ]] || failures+=("root filesystem '$root_fs' is not ext4")
[[ "$claude_version" =~ [0-9]+\.[0-9]+\.[0-9]+ ]] || failures+=("claude version '$claude_version'")

echo
echo "== summary"
echo "probe: $probe_line"
echo "kernel: $kernel_release"
echo "root fs: $root_fs"
echo "claude: $claude_version"
echo "gino-vmm exit: $status (VMM start to exit: ${elapsed:-?} ms)"
if [[ ${#failures[@]} -eq 0 ]]; then
  echo "PASS"
else
  printf 'FAIL: %s\n' "${failures[@]}"
  exit 1
fi
