#!/usr/bin/env bash
# Builds the gino-e2ee wasm package into OUT_DIR: cargo (wasm32, `wasm`
# profile) + wasm-bindgen (`--target web`), then wasm-opt -Oz when available.
# Requires the wasm32-unknown-unknown target and wasm-bindgen-cli at the exact
# version of the `wasm-bindgen` crate in Cargo.lock. Source and registry paths
# are remapped so the output does not depend on the checkout location; with
# the same toolchain, wasm-bindgen-cli and binaryen (docker/wasm.Dockerfile)
# the output is byte for byte reproducible.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUT_DIR" >&2
    exit 2
fi
out=$(realpath -m "$1")
cd "$(dirname "$0")/.."

want=$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/"/, "", $3); print $3 }' Cargo.lock)
have=$(wasm-bindgen --version | awk '{ print $2 }')
if [ "$want" != "$have" ]; then
    echo "wasm-bindgen-cli $have does not match the wasm-bindgen crate $want" >&2
    exit 1
fi

cargo_home=${CARGO_HOME:-$HOME/.cargo}
RUSTFLAGS="--remap-path-prefix=$PWD=/gino-e2ee --remap-path-prefix=$cargo_home=/cargo" \
    cargo build --locked --lib --target wasm32-unknown-unknown --profile wasm
wasm-bindgen --target web --out-dir "$out" \
    target/wasm32-unknown-unknown/wasm/gino_e2ee.wasm

if command -v wasm-opt >/dev/null 2>&1; then
    # The features rustc enables by default for wasm32-unknown-unknown.
    wasm-opt -Oz \
        --enable-bulk-memory --enable-multivalue --enable-mutable-globals \
        --enable-nontrapping-float-to-int --enable-reference-types --enable-sign-ext \
        -o "$out/gino_e2ee_bg.wasm" "$out/gino_e2ee_bg.wasm"
fi
