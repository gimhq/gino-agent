//! The libkrun release compiled into this binary. libkrun has no version query, so the version
//! is a constant kept in step with the `libkrun` entry in Cargo.lock by a unit test.

/// libkrun release, reported by `gino-vmm --probe`.
pub const LIBKRUN_VERSION: &str = "1.19.7";
/// Upstream commit of [`LIBKRUN_VERSION`], pinned in Cargo.toml.
#[cfg(test)]
const LIBKRUN_COMMIT: &str = "43b2f5aadeebb90f42053c9df2ec8b16583e554f";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_locked_libkrun() {
        let entry = format!(
            "name = \"libkrun\"\nversion = \"{LIBKRUN_VERSION}\"\n\
             source = \"git+https://github.com/containers/libkrun.git?rev={LIBKRUN_COMMIT}#{LIBKRUN_COMMIT}\"\n"
        );
        assert!(
            include_str!("../Cargo.lock").contains(&entry),
            "Cargo.lock lacks:\n{entry}"
        );
    }
}
