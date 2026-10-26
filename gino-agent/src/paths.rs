//! Shared path-component safety: the single validator every subsystem uses
//! before joining an attacker-influenced name under a local directory.
//! Callers wrap [`UnsafeName`] in their
//! own domain error (`From` impls live beside those error types).

/// A name rejected by [`safe_component`]: used as a path component it could
/// escape its parent directory.
#[derive(Debug)]
pub(crate) struct UnsafeName {
    /// The offending (attacker-influenced) name.
    pub(crate) name: String,
}

/// Validate an attacker-influenced `name` down to a single safe path component:
/// reject empties, `.`/`..`, NULs and separators (`/`/`\`), so the caller can
/// join it under a fixed directory without `../`/absolute-path escape. Returns
/// the name borrowed on success.
pub(crate) fn safe_component(name: &str) -> Result<&str, UnsafeName> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('\0')
        || name.contains('/')
        || name.contains('\\')
    {
        return Err(UnsafeName {
            name: name.to_owned(),
        });
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::safe_component;

    #[test]
    fn safe_component_rejects_traversal_and_absolute_paths() {
        for bad in [
            "../escape",
            "/etc/passwd",
            "..",
            ".",
            "",
            "a/b",
            "a\\b",
            "x\0y",
        ] {
            assert!(
                safe_component(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn safe_component_accepts_plain_names() {
        for good in [
            "report.txt",
            "data-1.json",
            "a_b.csv",
            "naïve.txt",
            "CLAUDE.md",
            "demo-skill",
            "my_config.json",
        ] {
            assert_eq!(safe_component(good).unwrap(), good);
        }
    }
}
