//! Party identity (spec §2.2) and KeyPackages (spec §2.7).

use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::*;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::storage::StorageProvider as _;

use crate::mls::{CIPHERSUITE, Provider, capabilities, check_credential, deserialize, serialize};
use crate::state::{restore_storage, snapshot_storage};
use crate::{Error, GroupError};

/// A party's Ed25519 identity: the 32-byte seed (RFC 8032), which never
/// leaves the party, and its public key, which is the BasicCredential
/// identity and the leaf signature key.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &crate::hex(&self.public_key()))
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// A fresh identity from `rng`.
    pub fn generate(rng: &impl OpenMlsRand) -> Result<Self, Error> {
        let seed = rng.random_array::<32>().map_err(|_| Error::SealFailed)?;
        Ok(Self::from_seed(&seed))
    }

    /// The identity of a 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte Ed25519 seed.
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// The raw 32-byte Ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub(crate) fn credential(&self) -> CredentialWithKey {
        let public = self.public_key().to_vec();
        CredentialWithKey {
            credential: BasicCredential::new(public.clone()).into(),
            signature_key: public.into(),
        }
    }
}

impl Signer for Identity {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.signing.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// A party's KeyPackage private keys, kept until a Welcome consumes them.
///
/// One-time KeyPackages are deleted when a Welcome uses them; the
/// last-resort KeyPackage stays.
#[derive(Debug, Default)]
pub struct KeyPackageStore {
    provider: Provider,
}

impl KeyPackageStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates a KeyPackage of `identity` (TLS-serialized `MLSMessage`)
    /// and keeps its private keys. `last_resort` adds the `last_resort`
    /// extension. The lifetime is the OpenMLS default (spec §2.7).
    pub fn generate(&self, identity: &Identity, last_resort: bool) -> Result<Vec<u8>, Error> {
        let mut builder = KeyPackage::builder().leaf_node_capabilities(capabilities());
        if last_resort {
            builder = builder.mark_as_last_resort();
        }
        let bundle = builder
            .build(CIPHERSUITE, &self.provider, identity, identity.credential())
            .map_err(|_| Error::SealFailed)?;
        serialize(&MlsMessageOut::from(bundle.key_package().clone()))
    }

    /// The private bundle of a KeyPackage named by its reference.
    pub(crate) fn bundle(&self, reference: &KeyPackageRef) -> Option<KeyPackageBundle> {
        self.provider.storage.key_package(reference).ok().flatten()
    }

    /// Deletes a used one-time KeyPackage.
    pub(crate) fn consume(&self, reference: &KeyPackageRef) -> Result<(), GroupError> {
        self.provider
            .storage
            .delete_key_package(reference)
            .map_err(|_| GroupError::Storage)
    }

    /// The store as opaque bytes.
    pub fn snapshot(&self) -> Result<Vec<u8>, GroupError> {
        snapshot_storage(&self.provider.storage)
    }

    /// A store from [`KeyPackageStore::snapshot`] bytes.
    pub fn restore(snapshot: &[u8]) -> Result<Self, GroupError> {
        let store = Self::default();
        restore_storage(&store.provider.storage, snapshot)?;
        Ok(store)
    }
}

/// Parses and validates a KeyPackage before it is added: the signatures,
/// the lifetime, the capabilities (spec §2.5 via OpenMLS), suite `0x0001`
/// and the credential rule of spec §2.2.
pub(crate) fn validate_key_package(
    crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
    bytes: &[u8],
) -> Result<KeyPackage, Error> {
    let MlsMessageBodyIn::KeyPackage(key_package) = deserialize(bytes)?.extract() else {
        return Err(Error::Malformed);
    };
    let key_package = key_package
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(|_| Error::Malformed)?;
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(Error::UnsupportedSuite);
    }
    let leaf = key_package.leaf_node();
    check_credential(leaf.credential(), leaf.signature_key().as_slice())?;
    Ok(key_package)
}
