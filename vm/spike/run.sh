#!/usr/bin/env bash
# Phase 0 VM spike, end to end: builds libkrun + libkrunfw, the guest root and the spike
# binaries, then runs every criterion in a sibling container with /dev/kvm as a non-root
# user (uid 1000) and prints the SUMMARY lines.
#
# Environment:
#   OUT    output dir (default: <worktree>/.tmp/vm-spike)
#   RUNS   boot latency runs (default: 7)
#   IMAGE  runner image (default: ai-agent/gino-vm-spike:1.96)
set -euo pipefail

for tool in docker git curl sha256sum; do
  command -v "$tool" >/dev/null || { echo "run: $tool is required" >&2; exit 2; }
done
[[ -c /dev/kvm ]] || { echo "run: /dev/kvm is missing" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WT="$(git -C "$HERE" rev-parse --show-toplevel)"
export OUT="${OUT:-$WT/.tmp/vm-spike}"
RUNS="${RUNS:-7}"
IMAGE="${IMAGE:-ai-agent/gino-vm-spike:1.96}"

"$HERE/build-libkrun.sh"
"$HERE/build-rootfs.sh"
"$HERE/build-spike.sh"

RUN="$OUT/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RUN"
chown 1000:1000 "$RUN"
kvm_gid="$(stat -c %g /dev/kvm)"

docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-vm-spike-run-$$" \
  --device /dev/kvm \
  --user 1000:1000 \
  --group-add "$kvm_gid" \
  -v "$OUT:$OUT" \
  -v "$HERE:$HERE:ro" \
  "$IMAGE" bash "$HERE/run-inner.sh" "$OUT" "$RUN" "$RUNS" | tee "$RUN/output.log"

echo
echo "== summary (full log: $RUN/output.log)"
echo "versions: $(grep -E '^LIBKRUN(FW)?_(TAG|COMMIT)=' "$HERE/build-libkrun.sh" | tr '\n' ' ')rootfs=$(cat "$OUT/rootfs.digest") host-kernel=$(uname -r)"
grep '^SUMMARY ' "$RUN/output.log" | sed 's/^SUMMARY //'
