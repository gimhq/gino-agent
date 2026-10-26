FROM rust:1.96.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends libclang-dev clang \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add rustfmt clippy
