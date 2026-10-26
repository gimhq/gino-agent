//! Two-party MLS fixtures shared by the integration tests.

#![allow(dead_code, clippy::expect_used, clippy::panic)]

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::{Signer, SignerError};

pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const CONTENT_LABEL: &str = "gino-e2ee/v1 content";
pub const DROP_LABEL: &str = "gino-e2ee/v1 drop";
pub const SCOPE_ID: &[u8] = b"task:01J9Z0SYNTHETICSCOPE";

/// OpenMLS provider over RustCrypto and a replaceable in-memory store.
#[derive(Debug, Default)]
pub struct Provider {
    pub crypto: RustCrypto,
    pub storage: MemoryStorage,
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

/// Ed25519 signer over a raw private key, signing through the crypto provider.
#[derive(Debug)]
pub struct Ed25519Signer {
    crypto: RustCrypto,
    private: Vec<u8>,
    pub public: Vec<u8>,
}

impl Ed25519Signer {
    pub fn generate() -> Self {
        let crypto = RustCrypto::default();
        let (private, public) = crypto
            .signature_key_gen(SignatureScheme::ED25519)
            .expect("ed25519 key generation");
        Self {
            crypto,
            private,
            public,
        }
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        self.crypto
            .sign(SignatureScheme::ED25519, payload, &self.private)
            .map_err(|_| SignerError::SigningError)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// One party: its provider (crypto + group state), signer and credential.
#[derive(Debug)]
pub struct Member {
    pub provider: Provider,
    pub signer: Ed25519Signer,
    pub credential: CredentialWithKey,
}

impl Member {
    pub fn new(identity: &str) -> Self {
        let signer = Ed25519Signer::generate();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.as_bytes().to_vec()).into(),
            signature_key: signer.public.clone().into(),
        };
        Self {
            provider: Provider::default(),
            signer,
            credential,
        }
    }

    pub fn key_package(&self, capabilities: Capabilities) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .expect("key package")
            .key_package()
            .clone()
    }

    pub fn create_group(&self, config: &MlsGroupCreateConfig) -> MlsGroup {
        MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            config,
            GroupId::from_slice(SCOPE_ID),
            self.credential.clone(),
        )
        .expect("create group")
    }

    pub fn join(&self, welcome: &MlsMessageOut, config: &MlsGroupJoinConfig) -> MlsGroup {
        let MlsMessageBodyIn::Welcome(welcome) = wire(welcome).extract() else {
            panic!("not a Welcome");
        };
        StagedWelcome::new_from_welcome(&self.provider, config, welcome, None)
            .expect("stage welcome")
            .into_group(&self.provider)
            .expect("join group")
    }

    /// Processes a Commit from another member and merges it.
    pub fn apply_commit(&self, group: &mut MlsGroup, commit: &MlsMessageOut) {
        let message = wire(commit)
            .try_into_protocol_message()
            .expect("protocol message");
        let processed = group
            .process_message(&self.provider, message)
            .expect("process commit");
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not a commit");
        };
        group
            .merge_staged_commit(&self.provider, *staged)
            .expect("merge commit");
    }

    /// Processes an application message from another member.
    pub fn open_application(&self, group: &mut MlsGroup, message: &MlsMessageOut) -> Vec<u8> {
        let message = wire(message)
            .try_into_protocol_message()
            .expect("protocol message");
        let processed = group
            .process_message(&self.provider, message)
            .expect("process application message");
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            panic!("not an application message");
        };
        message.into_bytes()
    }

    pub fn content_key(&self, group: &MlsGroup) -> Vec<u8> {
        group
            .export_secret(self.provider.crypto(), CONTENT_LABEL, SCOPE_ID, 32)
            .expect("export secret")
    }
}

/// Round-trips an outgoing message through its wire encoding.
pub fn wire(message: &MlsMessageOut) -> MlsMessageIn {
    let bytes = message.tls_serialize_detached().expect("serialize");
    MlsMessageIn::tls_deserialize_exact(bytes).expect("deserialize")
}

pub fn create_config(capabilities: Capabilities) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(capabilities)
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .build()
}

/// Creator A and joiner B in one group at epoch 1.
pub fn two_member_group(
    capabilities: &Capabilities,
    config: &MlsGroupCreateConfig,
) -> (Member, MlsGroup, Member, MlsGroup) {
    let alice = Member::new("alice");
    let bob = Member::new("bob");
    let mut alice_group = alice.create_group(config);
    let (_commit, welcome, _info) = alice_group
        .add_members(
            &alice.provider,
            &alice.signer,
            &[bob.key_package(capabilities.clone())],
        )
        .expect("add member");
    alice_group
        .merge_pending_commit(&alice.provider)
        .expect("merge add");
    let bob_group = bob.join(&welcome, config.join_config());
    (alice, alice_group, bob, bob_group)
}
