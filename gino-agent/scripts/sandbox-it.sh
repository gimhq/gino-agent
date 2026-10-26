#!/usr/bin/env bash
# Run the privileged engine-sandbox integration tests (tests/sandbox.rs) in a
# sibling container: the build runs as root, the tests as a non-root user,
# because bubblewrap must be started by an unprivileged user.
#
# Environment:
#   IMAGE           container image with the Rust toolchain and bubblewrap
#                   (default: ai-agent/gino-agent-gates:1.96)
#   CARGO_REGISTRY  host dir mounted as the container's cargo registry cache
#                   (default: /srv/station/root/.cargo/registry; empty = no mount)
#   CARGO_GIT       host dir mounted as the container's cargo git checkout cache
#                   (default: /srv/station/root/.cargo/git; empty = no mount)
#   SECCOMP_URL     base seccomp profile to extend
set -euo pipefail

IMAGE="${IMAGE:-ai-agent/gino-agent-gates:1.96}"
CARGO_REGISTRY="${CARGO_REGISTRY-/srv/station/root/.cargo/registry}"
CARGO_GIT="${CARGO_GIT-/srv/station/root/.cargo/git}"
SECCOMP_URL="${SECCOMP_URL:-https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json}"

for tool in docker curl jq git; do
  command -v "$tool" >/dev/null || { echo "sandbox-it: $tool is required" >&2; exit 2; }
done

WT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
TMP="$WT/.tmp/sandbox-it-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# The default profile denies the namespace and mount syscalls bubblewrap needs
# without CAP_SYS_ADMIN; replace their rules with an unconditional allow.
curl -fsSL "$SECCOMP_URL" -o "$TMP/default.json"
jq --argjson names '["unshare","clone","clone3","mount","umount2","pivot_root","setns"]' '
  .syscalls |= map(.names -= $names | select(.names | length > 0))
  | .syscalls += [{ names: $names, action: "SCMP_ACT_ALLOW" }]
' "$TMP/default.json" > "$TMP/seccomp.json"

mounts=(-v "$WT:$WT")
if [[ -n "$CARGO_REGISTRY" ]]; then
  mounts+=(-v "$CARGO_REGISTRY:/usr/local/cargo/registry")
fi
if [[ -n "$CARGO_GIT" ]]; then
  mounts+=(-v "$CARGO_GIT:/usr/local/cargo/git")
fi

# Build as root, then run the ignored sandbox tests as uid 1000.
read -r -d '' inner <<'EOF' || true
set -euo pipefail
cargo test --release --locked --test sandbox --no-run 2>&1 | tee /tmp/build.log
bin="$(sed -n 's/.*Executable tests\/sandbox.rs (\(.*\))$/\1/p' /tmp/build.log | tail -1)"
[[ -n "$bin" ]] || { echo "sandbox-it: test binary not found" >&2; exit 1; }
id -u 1000 >/dev/null 2>&1 || useradd -m -u 1000 sandbox-it
home="$(getent passwd 1000 | cut -d: -f6)"
exec setpriv --reuid=1000 --regid=1000 --init-groups \
  env HOME="$home" USER="$(id -un 1000)" "$bin" --ignored --test-threads=1
EOF

status=0
docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-sandbox-it-$$" \
  --security-opt "seccomp=$TMP/seccomp.json" \
  --security-opt apparmor=unconfined \
  --security-opt systempaths=unconfined \
  --device /dev/net/tun \
  "${mounts[@]}" \
  -w "$WT/gino-agent" \
  -e CARGO_TERM_COLOR=never \
  -e GINO_SANDBOX_IT=1 \
  "$IMAGE" bash -c "$inner" || status=$?

if [[ "$status" -eq 0 ]]; then
  echo "sandbox-it: all sandbox scenarios passed"
else
  echo "sandbox-it: FAILED (exit $status)" >&2
fi
exit "$status"
