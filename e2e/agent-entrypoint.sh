#!/bin/sh
# Entrypoint for the agent test image. Runs as root: the fake engines ignore all
# flags, so the real Claude CLI's root refusal does not apply.
set -eu

mkdir -p "${GINO_WORKSPACE_DIR:-/workspace}"
exec /app/gino-agent "$@"
