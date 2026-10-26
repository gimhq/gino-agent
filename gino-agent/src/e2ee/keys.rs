//! The runner's e2ee key files and the at-rest sealing of e2ee state.
//!
//! Both keys are 32 random bytes in their own file in the state directory
//! (the directory of the agent DB), created with mode `0600` and refused when
//! the mode is wider, the length is not 32 bytes or the path is not a regular
//! file. The bytes are held in a [`SecretBox`] and never printed.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use openmls_traits::random::OpenMlsRand as _;
use openmls_traits::types::AeadType;
use secrecy::zeroize::Zeroize as _;
use secrecy::{ExposeSecret as _, SecretBox};
use thiserror::Error;

/// Length of both key files.
pub(crate) const KEY_LEN: usize = 32;
/// Format byte of a sealed at-rest blob.
const SEALED_VERSION: u8 = 1;
/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;
/// AES-256-GCM tag length.
const TAG_LEN: usize = 16;

/// A 32-byte secret read from (or created as) a key file.
pub(crate) type KeyBytes = SecretBox<[u8; KEY_LEN]>;

/// A key file that cannot be used. Messages carry the path and the reason,
/// never the content.
#[derive(Debug, Error)]
pub(crate) enum KeyFileError {
    #[error("e2ee key file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "e2ee key file {} has mode {mode:04o}; it must not be accessible by group or others \
         (expected 0600)",
        path.display()
    )]
    Permissions { path: PathBuf, mode: u32 },
    #[error("e2ee key file {} holds {len} bytes; expected {KEY_LEN}", path.display())]
    Length { path: PathBuf, len: u64 },
    #[error("e2ee key file {} is not a regular file", path.display())]
    NotAFile { path: PathBuf },
    #[error("generating an e2ee key failed")]
    Random,
}

/// Load the key at `path`, or create it from OS-seeded randomness when the
/// file does not exist.
pub(crate) fn load_or_create(path: &Path) -> Result<KeyBytes, KeyFileError> {
    match open_no_follow(OpenOptions::new().read(true), path) {
        Ok(mut file) => read_key(path, &mut file),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => create_key(path),
        Err(source) => Err(KeyFileError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

fn open_no_follow(options: &mut OpenOptions, path: &Path) -> std::io::Result<File> {
    options
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(path)
}

fn read_key(path: &Path, file: &mut File) -> Result<KeyBytes, KeyFileError> {
    let io = |source| KeyFileError::Io {
        path: path.to_owned(),
        source,
    };
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() {
        return Err(KeyFileError::NotAFile {
            path: path.to_owned(),
        });
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(KeyFileError::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    if metadata.len() != KEY_LEN as u64 {
        return Err(KeyFileError::Length {
            path: path.to_owned(),
            len: metadata.len(),
        });
    }
    let mut read = Ok(());
    let key = SecretBox::init_with_mut(|bytes: &mut [u8; KEY_LEN]| {
        read = file.read_exact(bytes);
    });
    read.map_err(io)?;
    Ok(key)
}

/// Write a fresh key to a temp file created `0600`, then rename it into
/// place, so a crash never leaves a short key file behind.
fn create_key(path: &Path) -> Result<KeyBytes, KeyFileError> {
    let io = |source| KeyFileError::Io {
        path: path.to_owned(),
        source,
    };
    let mut random = RustCrypto::default()
        .random_array::<KEY_LEN>()
        .map_err(|_| KeyFileError::Random)?;
    let key = SecretBox::new(Box::new(random));
    random.zeroize();

    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    match std::fs::remove_file(&temp) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io(err)),
    }
    let mut file = open_no_follow(
        OpenOptions::new().write(true).create_new(true).mode(0o600),
        &temp,
    )
    .map_err(io)?;
    file.write_all(key.expose_secret()).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::rename(&temp, path).map_err(io)?;
    if let Some(dir) = path.parent() {
        File::open(dir).and_then(|dir| dir.sync_all()).map_err(io)?;
    }
    Ok(key)
}

/// A sealed blob failed to open: wrong key, wrong label, truncated or
/// tampered.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("e2ee state blob does not open under the at-rest key")]
pub(crate) struct OpenError;

/// A blob could not be sealed.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("sealing e2ee state at rest failed")]
pub(crate) struct SealError;

/// The at-rest key: AES-256-GCM over e2ee state stored in the agent DB.
///
/// A sealed blob is `0x01 || nonce (12) || ciphertext || tag (16)` with a
/// random nonce and the caller's label as the AAD, so a blob stored under one
/// label never opens under another.
pub(crate) struct AtRestKey {
    key: KeyBytes,
    crypto: RustCrypto,
}

impl std::fmt::Debug for AtRestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtRestKey").finish_non_exhaustive()
    }
}

impl AtRestKey {
    pub(crate) fn new(key: KeyBytes) -> Self {
        Self {
            key,
            crypto: RustCrypto::default(),
        }
    }

    /// Seal `plaintext` under `label`.
    pub(crate) fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let nonce = self
            .crypto
            .random_array::<NONCE_LEN>()
            .map_err(|_| SealError)?;
        let ciphertext = self
            .crypto
            .aead_encrypt(
                AeadType::Aes256Gcm,
                self.key.expose_secret(),
                plaintext,
                &nonce,
                label.as_bytes(),
            )
            .map_err(|_| SealError)?;
        let mut sealed = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        sealed.push(SEALED_VERSION);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Open a blob sealed under `label`.
    pub(crate) fn open(&self, label: &str, sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        let (&version, rest) = sealed.split_first().ok_or(OpenError)?;
        if version != SEALED_VERSION || rest.len() < NONCE_LEN + TAG_LEN {
            return Err(OpenError);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        self.crypto
            .aead_decrypt(
                AeadType::Aes256Gcm,
                self.key.expose_secret(),
                ciphertext,
                nonce,
                label.as_bytes(),
            )
            .map_err(|_| OpenError)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use secrecy::ExposeSecret as _;

    use super::{AtRestKey, KEY_LEN, KeyFileError, OpenError, SecretBox, load_or_create};

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn key_file_is_created_0600_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e2ee-identity.key");
        let first = load_or_create(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), first.expose_secret());
        assert!(!dir.path().join("e2ee-identity.key.tmp").exists());
        let second = load_or_create(&path).unwrap();
        assert_eq!(first.expose_secret(), second.expose_secret());
        let other = load_or_create(&dir.path().join("e2ee-state.key")).unwrap();
        assert_ne!(first.expose_secret(), other.expose_secret());
    }

    #[test]
    fn wide_permissions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        load_or_create(&path).unwrap();
        for wide in [0o640, 0o604, 0o660, 0o644] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(wide)).unwrap();
            let err = load_or_create(&path).unwrap_err();
            assert!(
                matches!(err, KeyFileError::Permissions { mode, .. } if mode == wide),
                "{err}"
            );
            assert!(err.to_string().contains("0600"), "{err}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(load_or_create(&path).is_ok());
    }

    #[test]
    fn wrong_length_and_non_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for len in [0, 31, 33, 64] {
            let path = dir.path().join(format!("k{len}"));
            std::fs::write(&path, vec![7; len]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let err = load_or_create(&path).unwrap_err();
            assert!(
                matches!(err, KeyFileError::Length { len: got, .. } if got == len as u64),
                "{err}"
            );
        }
        let sub = dir.path().join("dir");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            load_or_create(&sub).unwrap_err(),
            KeyFileError::NotAFile { .. }
        ));
        let target = dir.path().join("target");
        load_or_create(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            load_or_create(&link).unwrap_err(),
            KeyFileError::Io { .. }
        ));
    }

    #[test]
    fn errors_never_carry_key_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        std::fs::write(&path, b"0123456789abcdef0123456789abcdef").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_or_create(&path).unwrap_err();
        assert!(!format!("{err} {err:?}").contains("0123456789abcdef"));
    }

    fn at_rest() -> AtRestKey {
        AtRestKey::new(SecretBox::new(Box::new([5; KEY_LEN])))
    }

    #[test]
    fn at_rest_seal_open_round_trip() {
        let key = at_rest();
        let sealed = key.seal("e2ee_key_packages", b"snapshot bytes").unwrap();
        assert_eq!(sealed.len(), 1 + 12 + 14 + 16);
        assert_ne!(&sealed[13..27], b"snapshot bytes");
        assert_eq!(
            key.open("e2ee_key_packages", &sealed).unwrap(),
            b"snapshot bytes"
        );
        // Random nonces: sealing twice gives different blobs.
        assert_ne!(
            sealed,
            key.seal("e2ee_key_packages", b"snapshot bytes").unwrap()
        );
        assert_eq!(key.open("l", &key.seal("l", b"").unwrap()).unwrap(), b"");
    }

    #[test]
    fn at_rest_open_fails_on_wrong_label_key_or_tampering() {
        let key = at_rest();
        let sealed = key.seal("e2ee_groups:t-1", b"state").unwrap();
        assert_eq!(key.open("e2ee_groups:t-2", &sealed), Err(OpenError));
        let other = AtRestKey::new(SecretBox::new(Box::new([6; KEY_LEN])));
        assert_eq!(other.open("e2ee_groups:t-1", &sealed), Err(OpenError));
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(key.open("e2ee_groups:t-1", &tampered), Err(OpenError));
        let mut version = sealed.clone();
        version[0] = 2;
        assert_eq!(key.open("e2ee_groups:t-1", &version), Err(OpenError));
        for len in [0, 1, 12, 28] {
            assert_eq!(key.open("e2ee_groups:t-1", &sealed[..len]), Err(OpenError));
        }
    }

    #[test]
    fn at_rest_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", at_rest()), "AtRestKey { .. }");
    }
}
