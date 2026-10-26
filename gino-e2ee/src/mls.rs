//! MLS profile (spec §2): suite, group context extensions, capabilities,
//! group configurations, the OpenMLS provider and the group-layer error.

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

use crate::{Error, HistoryPolicy};

/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`).
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Group context extension type of the profile id.
pub const PROFILE_EXTENSION: u16 = 0xF0E1;
/// Group context extension type of the history policy.
pub const POLICY_EXTENSION: u16 = 0xF0E2;
/// Exporter label of the content key `k_e`.
pub(crate) const CONTENT_LABEL: &str = "gino-e2ee/v1 content";
/// Exporter label of the drop seed `d_e`.
pub(crate) const DROP_LABEL: &str = "gino-e2ee/v1 drop";

/// A group-layer failure: a spec §11 code, or a local sequencing condition
/// that is not reported as an `encryption_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupError {
    /// A §11 failure.
    #[error(transparent)]
    E2ee(#[from] Error),
    /// A log entry skips entries after the last applied `seq`.
    #[error("log gap: expected seq {expected}, got {got}")]
    Gap { expected: u64, got: u64 },
    /// A commit is pending DS acceptance; settle it first.
    #[error("commit pending")]
    CommitPending,
    /// There is no pending commit to settle.
    #[error("no pending commit")]
    NoPendingCommit,
    /// The state could not be read or written.
    #[error("storage")]
    Storage,
}

impl GroupError {
    /// The §11 failure, if this is one.
    pub fn encryption_error(&self) -> Option<Error> {
        match self {
            Self::E2ee(error) => Some(*error),
            _ => None,
        }
    }
}

/// Leaf capabilities of every group creator and KeyPackage (spec §2.5).
/// `last_resort` is listed so last-resort KeyPackages validate (OpenMLS
/// requires every KeyPackage extension in the leaf capabilities).
pub(crate) fn capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[CIPHERSUITE]),
        Some(&[
            ExtensionType::Unknown(PROFILE_EXTENSION),
            ExtensionType::Unknown(POLICY_EXTENSION),
            ExtensionType::LastResort,
        ]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// The full group context extension list: required capabilities, profile
/// id and history policy (spec §2.4, §2.5).
pub(crate) fn group_context_extensions(
    profile: &str,
    policy: HistoryPolicy,
) -> Result<Extensions<GroupContext>, Error> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[
                ExtensionType::Unknown(PROFILE_EXTENSION),
                ExtensionType::Unknown(POLICY_EXTENSION),
            ],
            &[],
            &[],
        )),
        Extension::Unknown(
            PROFILE_EXTENSION,
            UnknownExtension(profile.as_bytes().to_vec()),
        ),
        Extension::Unknown(POLICY_EXTENSION, UnknownExtension(policy.encode())),
    ])
    .map_err(|_| Error::Malformed)
}

/// The profile id and history policy of a group context; either missing or
/// invalid is `malformed`.
pub(crate) fn profile_and_policy(
    extensions: &Extensions<GroupContext>,
) -> Result<(String, HistoryPolicy), Error> {
    let mut profile = None;
    let mut policy = None;
    for extension in extensions.iter() {
        match extension {
            Extension::Unknown(PROFILE_EXTENSION, UnknownExtension(data)) => {
                profile = Some(String::from_utf8(data.clone()).map_err(|_| Error::Malformed)?);
            }
            Extension::Unknown(POLICY_EXTENSION, UnknownExtension(data)) => {
                policy = Some(HistoryPolicy::decode(data)?);
            }
            _ => {}
        }
    }
    profile.zip(policy).ok_or(Error::Malformed)
}

pub(crate) fn create_config(extensions: Extensions<GroupContext>) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities())
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .with_group_context_extensions(extensions)
        .build()
}

pub(crate) fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}

/// Checks a leaf's BasicCredential: its identity is the raw 32-byte Ed25519
/// key and equals the signature key (spec §2.2); otherwise `malformed`.
pub(crate) fn check_credential(credential: &Credential, signature_key: &[u8]) -> Result<(), Error> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| Error::Malformed)?;
    if basic.identity().len() == 32 && basic.identity() == signature_key {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

/// TLS serialization of an outgoing `MLSMessage`.
pub(crate) fn serialize(message: &MlsMessageOut) -> Result<Vec<u8>, Error> {
    message
        .tls_serialize_detached()
        .map_err(|_| Error::SealFailed)
}

/// Parses a TLS-serialized `MLSMessage`.
pub(crate) fn deserialize(bytes: &[u8]) -> Result<MlsMessageIn, Error> {
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Error::Malformed)
}

/// OpenMLS provider over RustCrypto and an in-memory key-value store.
#[derive(Debug, Default)]
pub(crate) struct Provider {
    pub(crate) crypto: RustCrypto,
    pub(crate) storage: MemoryStorage,
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }

    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }

    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}
