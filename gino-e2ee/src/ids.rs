//! Group ids (spec §2.3) and key fingerprints (spec §3.5).

use sha2::{Digest, Sha256};

use crate::Error;

/// Domain label of the group id hash.
const GROUP_LABEL: &[u8] = b"gino-e2ee/v1 group";

/// `SHA-256("gino-e2ee/v1 group" || len16(P) || P || len16(S) || S)` for the
/// profile id `P` and the scope id `S`. An invalid profile id or scope id is
/// `malformed`.
pub fn group_id(profile: &str, scope: &str) -> Result<[u8; 32], Error> {
    if !is_profile_id(profile) || scope.is_empty() || scope.contains('|') {
        return Err(Error::Malformed);
    }
    let profile_len = u16::try_from(profile.len()).map_err(|_| Error::Malformed)?;
    let scope_len = u16::try_from(scope.len()).map_err(|_| Error::Malformed)?;
    let mut hasher = Sha256::new();
    hasher.update(GROUP_LABEL);
    hasher.update(profile_len.to_be_bytes());
    hasher.update(profile);
    hasher.update(scope_len.to_be_bytes());
    hasher.update(scope);
    Ok(hasher.finalize().into())
}

/// Whether `id` matches `^[a-z0-9]+(\.[a-z0-9-]+)*\.v[0-9]+$`.
fn is_profile_id(id: &str) -> bool {
    let Some((head, version)) = id.rsplit_once(".v") else {
        return false;
    };
    let is_lower_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let mut segments = head.split('.');
    let first_ok = segments
        .next()
        .is_some_and(|s| !s.is_empty() && s.bytes().all(is_lower_alnum));
    first_ok
        && segments.all(|s| !s.is_empty() && s.bytes().all(|b| is_lower_alnum(b) || b == b'-'))
        && !version.is_empty()
        && version.bytes().all(|b| b.is_ascii_digit())
}

/// The canonical fingerprint of an Ed25519 public key: lower-case hex of its
/// SHA-256 (64 characters).
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    crate::hex(&Sha256::digest(public_key))
}

/// The display form of a fingerprint: 16 groups of 4 characters joined by
/// single spaces.
pub fn fingerprint_display(public_key: &[u8; 32]) -> String {
    let canonical = fingerprint(public_key);
    let groups: Vec<&str> = (0..canonical.len())
        .step_by(4)
        .filter_map(|i| canonical.get(i..i + 4))
        .collect();
    groups.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_ids() {
        for id in ["gino.task-content.v1", "a.v0", "x1.b-c.d.v12"] {
            assert!(is_profile_id(id), "{id}");
        }
        for id in [
            "",
            "v1",
            ".v1",
            "gino.v",
            "Gino.v1",
            "gino..x.v1",
            "gino.x.v1a",
            "-a.v1",
            "gino-x.v1",
        ] {
            assert!(!is_profile_id(id), "{id}");
        }
    }

    #[test]
    fn group_id_rejects_bad_input() {
        assert!(group_id("gino.task-content.v1", "t-1").is_ok());
        assert_eq!(group_id("bad", "t-1"), Err(Error::Malformed));
        assert_eq!(
            group_id("gino.task-content.v1", "a|b"),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn fingerprint_forms() {
        let display = fingerprint_display(&[0; 32]);
        assert_eq!(display.len(), 64 + 15);
        assert_eq!(display.replace(' ', ""), fingerprint(&[0; 32]));
    }
}
