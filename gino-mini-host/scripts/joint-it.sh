#!/usr/bin/env bash
# Run the joint suite (tests/joint.rs): the real gino-agent against mini-host, one scenario per
# protocol surface. Builds the agent in release mode, then runs the ignored joint tests with
# GINO_AGENT_BIN pointing at it, in a sibling container.
#
# Environment:
#   IMAGE           container image with the Rust toolchain, bash and jq
#                   (default: ai-agent/gino-agent-gates:1.96)
#   AGENT_BIN       an agent binary to test instead of building one (a path inside the repo)
#   CARGO_REGISTRY  host dir mounted as the container's cargo registry cache
#                   (default: /srv/station/root/.cargo/registry; empty = no mount)
#   CARGO_GIT       host dir mounted as the container's cargo git checkout cache
#                   (default: /srv/station/root/.cargo/git; empty = no mount)
#   FILTER          test name filter (default: all)
set -euo pipefail
IMAGE="${IMAGE:-ai-agent/gino-agent-gates:1.96}"
CARGO_REGISTRY="${CARGO_REGISTRY-/srv/station/root/.cargo/registry}"
CARGO_GIT="${CARGO_GIT-/srv/station/root/.cargo/git}"
command -v docker >/dev/null || { echo "joint-it: docker is required" >&2; exit 2; }
WT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"

mounts=(-v "$WT:$WT")
[[ -n "$CARGO_REGISTRY" ]] && mounts+=(-v "$CARGO_REGISTRY:/usr/local/cargo/registry")
[[ -n "$CARGO_GIT" ]] && mounts+=(-v "$CARGO_GIT:/usr/local/cargo/git")

read -r -d '' inner <<'INNER' || true
set -euo pipefail
if [[ -z "${AGENT_BIN:-}" ]]; then
  (cd "$WT/gino-agent" && cargo build --release --locked)
  AGENT_BIN="$WT/gino-agent/target/release/gino-agent"
fi
cd "$WT/gino-mini-host"
GINO_AGENT_BIN="$AGENT_BIN" cargo test --release --locked --test joint -- --ignored ${FILTER:-}
INNER

status=0
docker run --rm \
  --label ai-agent=true \
  --name "ai-agent-gino-joint-it-$$" \
  "${mounts[@]}" \
  -w "$WT" \
  -e WT="$WT" \
  -e AGENT_BIN="${AGENT_BIN:-}" \
  -e FILTER="${FILTER:-}" \
  -e CARGO_TERM_COLOR=never \
  "$IMAGE" bash -c "$inner" || status=$?

if [[ "$status" -eq 0 ]]; then
  echo "joint-it: all joint scenarios passed"
else
  echo "joint-it: FAILED (exit $status)" >&2
fi
exit "$status"
