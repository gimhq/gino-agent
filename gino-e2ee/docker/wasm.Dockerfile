# Build image for the gino-e2ee wasm package (scripts/build-wasm.sh).
FROM rust:1.96-bookworm

# The crate's pinned toolchain (rust-toolchain.toml) with the wasm32 target.
RUN rustup toolchain install 1.96.0 --profile minimal \
        --component rustfmt,clippy --target wasm32-unknown-unknown

# Must equal the `wasm-bindgen` crate version in Cargo.toml.
ARG WASM_BINDGEN_VERSION=0.2.129
RUN cargo install --locked wasm-bindgen-cli --version "${WASM_BINDGEN_VERSION}" \
    && rm -rf /usr/local/cargo/registry

ARG BINARYEN_VERSION=133
RUN curl -fsSL -o /tmp/binaryen.tar.gz \
        "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-x86_64-linux.tar.gz" \
    && curl -fsSL -o /tmp/binaryen.tar.gz.sha256 \
        "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-x86_64-linux.tar.gz.sha256" \
    && echo "$(cut -d' ' -f1 /tmp/binaryen.tar.gz.sha256)  /tmp/binaryen.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/binaryen.tar.gz -C /opt \
    && ln -s "/opt/binaryen-version_${BINARYEN_VERSION}/bin/wasm-opt" /usr/local/bin/wasm-opt \
    && rm /tmp/binaryen.tar.gz /tmp/binaryen.tar.gz.sha256
