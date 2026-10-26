#!/usr/bin/env bash
# Rebuilds the wasm package with gino-e2ee/scripts/build-wasm.sh and fails if
# it differs from the committed wasm/ directory. Needs the build tools of
# gino-e2ee/docker/wasm.Dockerfile.
set -euo pipefail

cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bash ../../gino-e2ee/scripts/build-wasm.sh "$tmp"
if ! diff -r "$tmp" wasm; then
    echo "wasm/ is stale: run 'bun run build:wasm' and commit the result" >&2
    exit 1
fi
echo "wasm/ matches the build"
