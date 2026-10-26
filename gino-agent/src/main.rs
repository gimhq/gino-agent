#![forbid(unsafe_code)]

//! Thin binary entry point for `gino-agent`. All logic lives in the library
//! crate so it can be unit- and doc-tested; see [`gino_agent::run`].

fn main() -> anyhow::Result<()> {
    gino_agent::run()
}
