//! Engine config & skills provisioning — the pure-filesystem content-addressed
//! store + symlink materialization primitives (agent-architecture §9b).
//!
//! This module owns the **byte/bundle → store** and **store → symlink** seam, and
//! nothing else: NO DB, NO network/fetch, NO reconcile orchestration. The
//! reconcile engine ([`reconcile`]) drives these primitives — it fetches +
//! verifies bytes out-of-band (reusing the §9 attachment cache), then:
//!
//! * materializes them into the store ([`store::materialize_file`] /
//!   [`store::materialize_dir`]) at `store/<name>/<sha256[:12]>` — a single FILE
//!   for `kind=file`, a DIRECTORY (unpacked uncompressed tar) for `kind=dir`,
//!   content-addressed and idempotent; and
//! * loads them by **symlink** ([`store::link`]) — `<scope-root>/<target>` points
//!   into the store entry (zero-copy; update = repoint, §2).
//!
//! Safety: `target` is host-influenced, so [`safe_link_path`] confines every link
//! under its scope root (rejecting absolute / `..` / `.` / empty / NUL),
//! the store `name` is sanitized to a single safe component (the shared
//! [`crate::paths::safe_component`]), and tar unpack refuses any member that
//! escapes the store dir.

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

pub(crate) mod reconcile;
pub(crate) mod store;

// The reconcile engine ties the store + DB + fetch seam together; the runner
// (5a global wiring) drives `Provisioner` and supplies the `BlobFetcher`
// (the shared `AttachmentManager` impl).
pub(crate) use reconcile::{BlobFetcher, Provisioner};

/// Length of the git-style short store id (`sha256[:12]`).
const SHORT_ID_LEN: usize = 12;

/// Errors raised by the provisioning store/symlink layer. Byte content is never
/// included — only paths/names/hashes.
#[derive(Debug, Error)]
pub(crate) enum ProvisioningError {
    /// A link `target` is unsafe (absolute / `..` / `.` / empty / NUL) — it could
    /// escape the scope root.
    #[error("unsafe link target {target:?}")]
    UnsafeTarget { target: String },
    /// A store `name` is unsafe (empty / `.` / `..` / separators / NUL) — it could
    /// escape the store root as a path component.
    #[error("unsafe store name {name:?}")]
    UnsafeName { name: String },
    /// A tar member's path is absolute or contains `..` — it would escape the
    /// store dir on unpack, so the whole bundle is rejected.
    #[error("tar member escapes the store dir: {member:?}")]
    UnsafeMember { member: String },
    /// The uncompressed-tar bundle could not be read/unpacked.
    #[error("tar unpack failed: {reason}")]
    Unpack { reason: String },
    /// An out-of-band blob fetch (download + integrity verify) failed. The reason
    /// is the attachment-layer error rendered as text — the reconcile engine is
    /// decoupled from [`crate::attachments::AttachmentError`] via the
    /// [`reconcile::BlobFetcher`] seam.
    #[error("provisioning blob fetch failed: {reason}")]
    Fetch { reason: String },
    /// A store entry exists but does not match the declared `kind` (a corrupt /
    /// wrong-kind store path was passed to [`store::link`]).
    #[error("store entry at {path:?} is not a {expected}")]
    StoreKindMismatch {
        expected: &'static str,
        path: PathBuf,
    },
    /// A filesystem error while materializing / linking.
    #[error("provisioning filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// A manifest (`config_entries`) DB operation failed during reconcile / GC /
    /// repair.
    #[error("provisioning manifest error: {0}")]
    Db(#[from] crate::db::DbError),
}

/// The git-style short store id — the first [`SHORT_ID_LEN`] characters of the
/// full lowercase-hex `sha256`. Length-guarded: a shorter (e.g. malformed) input
/// is returned whole rather than panicking on a slice boundary.
pub(crate) fn short_id(sha256: &str) -> &str {
    match sha256.char_indices().nth(SHORT_ID_LEN) {
        Some((idx, _)) => &sha256[..idx],
        None => sha256,
    }
}

impl From<crate::paths::UnsafeName> for ProvisioningError {
    fn from(err: crate::paths::UnsafeName) -> Self {
        ProvisioningError::UnsafeName { name: err.name }
    }
}

/// Resolve a host-influenced `target` to a concrete link path under `scope_root`,
/// confining it inside that root.
///
/// Unlike a store `name`, a `target` MAY contain `/` separators (e.g.
/// `.claude/skills/demo`); nested *normal* components are allowed. Rejected:
/// an empty target, a NUL, an absolute path, and any `..` / `.` / root / prefix
/// component (so the join can never climb above or jump outside `scope_root`).
pub(crate) fn safe_link_path(
    scope_root: &Path,
    target: &str,
) -> Result<PathBuf, ProvisioningError> {
    let reject = || ProvisioningError::UnsafeTarget {
        target: target.to_owned(),
    };
    if target.is_empty() || target.contains('\0') {
        return Err(reject());
    }
    let candidate = Path::new(target);
    if candidate.is_absolute() {
        return Err(reject());
    }
    for component in candidate.components() {
        match component {
            // A nested directory or filename component — the only safe kind.
            Component::Normal(part) if !part.is_empty() => {}
            // `..` / `.` / a root (`/`) / a Windows prefix (`C:`) — all escape.
            _ => return Err(reject()),
        }
    }
    let resolved = scope_root.join(candidate);
    // Belt-and-suspenders: having rejected every traversal component above, the
    // join is guaranteed to stay under `scope_root` — assert + re-check the
    // invariant so a future change to the loop can never silently weaken it.
    debug_assert!(resolved.starts_with(scope_root));
    if !resolved.starts_with(scope_root) {
        return Err(reject());
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::{ProvisioningError, safe_link_path, short_id};

    #[test]
    fn short_id_is_first_twelve_chars() {
        // sha256("abc") — 64 hex chars; short id = first 12.
        let sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(short_id(sha), &sha[..12]);
        assert_eq!(short_id(sha).len(), 12);
        // A shorter input is returned whole, never sliced past its end.
        assert_eq!(short_id("abc"), "abc");
        assert_eq!(short_id(""), "");
    }

    #[test]
    fn safe_link_path_rejects_traversal_and_absolute() {
        let root = std::path::Path::new("/scope/root");
        for bad in [
            "../escape",
            "/etc/passwd",
            "a/../../b",
            "",
            ".",
            "..",
            "x\0y",
        ] {
            assert!(
                matches!(
                    safe_link_path(root, bad),
                    Err(ProvisioningError::UnsafeTarget { .. })
                ),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn safe_link_path_accepts_nested_targets_under_root() {
        let root = std::path::Path::new("/scope/root");
        for good in [
            "CLAUDE.md",
            "AGENTS.md",
            ".claude/skills/demo",
            "skills/demo",
        ] {
            let resolved = safe_link_path(root, good).unwrap();
            assert_eq!(resolved, root.join(good));
            assert!(resolved.starts_with(root));
        }
    }

    #[test]
    fn unsafe_store_name_maps_to_the_provisioning_error() {
        // The validation itself lives in `crate::paths::safe_component` (and is
        // pinned there); this pins the store-facing error mapping.
        let err: ProvisioningError = crate::paths::safe_component("a/b").unwrap_err().into();
        assert!(matches!(err, ProvisioningError::UnsafeName { .. }));
    }
}
