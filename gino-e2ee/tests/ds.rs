//! Keyless Delivery Service inspection of KeyPackages, commits, proposals
//! and Welcomes produced by the MLS group layer.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

use gino_e2ee::{
    Error, HistoryPolicy, Identity, InspectError, KeyHistoryOffer, KeyHistoryRecord,
    KeyPackageStore, MemoryKeyCache, MessageContent, POLICY_EXTENSION, PROFILE_EXTENSION,
    ScopeGroup, inspect_key_package, inspect_message, welcome_recipients,
};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, CredentialWithKey, ExtensionType, KeyPackage,
    LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;

const PROFILE: &str = "gino.task-content.v1";
const SCOPE: &str = "t-1";

type Group = ScopeGroup<MemoryKeyCache>;

struct Party {
    identity: Identity,
    key_packages: KeyPackageStore,
}

impl Party {
    fn new() -> Self {
        Self {
            identity: Identity::generate(&RustCrypto::default()).unwrap(),
            key_packages: KeyPackageStore::new(),
        }
    }

    fn key_package(&self) -> Vec<u8> {
        self.key_packages.generate(&self.identity, false).unwrap()
    }

    fn create(&self) -> Group {
        ScopeGroup::create(
            &self.identity,
            PROFILE,
            SCOPE,
            HistoryPolicy::Full,
            MemoryKeyCache::default(),
        )
        .unwrap()
    }

    fn join(&self, welcome: &[u8], seq: u64) -> Group {
        ScopeGroup::join(
            &self.key_packages,
            PROFILE,
            SCOPE,
            welcome,
            seq,
            MemoryKeyCache::default(),
        )
        .unwrap()
    }
}

/// The KeyPackageRef OpenMLS computes for a serialized KeyPackage.
fn openmls_ref(bytes: &[u8]) -> Vec<u8> {
    let MlsMessageBodyIn::KeyPackage(key_package) = MlsMessageIn::tls_deserialize_exact(bytes)
        .unwrap()
        .extract()
    else {
        panic!("not a KeyPackage");
    };
    let crypto = RustCrypto::default();
    let key_package = key_package
        .validate(&crypto, ProtocolVersion::Mls10)
        .unwrap();
    key_package.hash_ref(&crypto).unwrap().as_slice().to_vec()
}

/// A KeyPackage of `identity` built directly with OpenMLS.
fn raw_key_package(
    identity: &Identity,
    ciphersuite: Ciphersuite,
    capabilities: Capabilities,
) -> Vec<u8> {
    let public = identity.public_key().to_vec();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(public.clone()).into(),
        signature_key: public.into(),
    };
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            ciphersuite,
            &common::Provider::default(),
            identity,
            credential,
        )
        .unwrap();
    MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .unwrap()
}

fn profile_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[
            ExtensionType::Unknown(PROFILE_EXTENSION),
            ExtensionType::Unknown(POLICY_EXTENSION),
        ]),
        None,
        None,
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn code(result: Result<impl std::fmt::Debug, InspectError>) -> Error {
    result.unwrap_err().error
}

#[test]
fn valid_key_packages() {
    let party = Party::new();
    for last_resort in [false, true] {
        let bytes = party
            .key_packages
            .generate(&party.identity, last_resort)
            .unwrap();
        let info = inspect_key_package(&bytes, now()).unwrap();
        assert_eq!(info.reference, openmls_ref(&bytes));
        assert_eq!(info.public_key, party.identity.public_key());
        assert_eq!(info.last_resort, last_resort);
        assert!(info.not_before <= now() && now() <= info.not_after);
    }
}

#[test]
fn key_package_lifetime_uses_now() {
    let bytes = Party::new().key_package();
    let info = inspect_key_package(&bytes, now()).unwrap();
    assert!(inspect_key_package(&bytes, info.not_before).is_ok());
    assert!(inspect_key_package(&bytes, info.not_after).is_ok());
    let early = inspect_key_package(&bytes, info.not_before - 1).unwrap_err();
    assert_eq!(early.error, Error::Malformed);
    assert_eq!(early.reason, "KeyPackage not yet valid");
    let late = inspect_key_package(&bytes, info.not_after + 1).unwrap_err();
    assert_eq!(late.error, Error::Malformed);
    assert_eq!(late.reason, "KeyPackage expired");
}

#[test]
fn key_package_rejections() {
    let party = Party::new();
    let bytes = party.key_package();

    // The KeyPackage signature is its last field.
    let mut bad_signature = bytes.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        code(inspect_key_package(&bad_signature, now())),
        Error::Malformed
    );

    let mut tampered = bytes.clone();
    tampered[bytes.len() / 2] ^= 1;
    assert_eq!(
        code(inspect_key_package(&tampered, now())),
        Error::Malformed
    );

    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        code(inspect_key_package(truncated, now())),
        Error::Malformed
    );
    assert_eq!(code(inspect_key_package(&[], now())), Error::Malformed);

    let wrong_suite = raw_key_package(
        &party.identity,
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        profile_capabilities(),
    );
    assert_eq!(
        code(inspect_key_package(&wrong_suite, now())),
        Error::UnsupportedSuite
    );

    let no_capabilities = raw_key_package(
        &party.identity,
        gino_e2ee::CIPHERSUITE,
        Capabilities::default(),
    );
    let error = inspect_key_package(&no_capabilities, now()).unwrap_err();
    assert_eq!(error.error, Error::Malformed);
    assert_eq!(error.reason, "missing required capabilities");

    // The profile capabilities alone are enough.
    let minimal = raw_key_package(
        &party.identity,
        gino_e2ee::CIPHERSUITE,
        profile_capabilities(),
    );
    assert!(inspect_key_package(&minimal, now()).is_ok());
}

#[test]
fn key_package_rejects_other_messages() {
    let alice = Party::new();
    let bob = Party::new();
    let mut group = alice.create();
    let unit = group
        .add_members(&alice.identity, &[bob.key_package()], None)
        .unwrap();
    let error = inspect_key_package(&unit.commit, now()).unwrap_err();
    assert_eq!(error.error, Error::Malformed);
    assert_eq!(error.reason, "not a KeyPackage");
}

#[test]
fn add_remove_and_update_commits() {
    let alice = Party::new();
    let bob = Party::new();
    let carol = Party::new();
    let mut alice_group = alice.create();
    let bob_key_package = bob.key_package();
    let carol_key_package = carol.key_package();
    let bob_ref = inspect_key_package(&bob_key_package, now())
        .unwrap()
        .reference;
    let carol_ref = inspect_key_package(&carol_key_package, now())
        .unwrap()
        .reference;

    let add = alice_group
        .add_members(&alice.identity, &[bob_key_package, carol_key_package], None)
        .unwrap();
    let info = inspect_message(&add.commit).unwrap();
    assert_eq!(info.group_id, alice_group.group_id());
    assert_eq!(info.epoch, 0);
    assert_eq!(info.content_type, MessageContent::Commit);
    assert_eq!(info.sender_leaf, 0);
    assert_eq!(info.adds, vec![bob_ref.clone(), carol_ref.clone()]);
    assert!(info.removes.is_empty());
    assert!(info.proposal_refs.is_empty());
    assert!(info.updates_path);

    let welcome = add.welcome.as_deref().unwrap();
    let mut recipients = welcome_recipients(welcome).unwrap();
    recipients.sort();
    let mut expected = vec![bob_ref, carol_ref];
    expected.sort();
    assert_eq!(recipients, expected);

    alice_group.commit_accepted(1).unwrap();
    let mut bob_group = bob.join(welcome, 1);

    let update = bob_group.self_update(&bob.identity).unwrap();
    let info = inspect_message(&update.commit).unwrap();
    assert_eq!(info.epoch, 1);
    assert_eq!(info.content_type, MessageContent::Commit);
    assert_eq!(info.sender_leaf, 1);
    assert!(info.adds.is_empty() && info.removes.is_empty());
    assert!(info.updates_path);
    bob_group.commit_rejected().unwrap();

    let remove = alice_group
        .remove_members(&alice.identity, &[carol.identity.public_key()])
        .unwrap();
    let info = inspect_message(&remove.commit).unwrap();
    assert_eq!(info.epoch, 1);
    assert_eq!(info.sender_leaf, 0);
    assert_eq!(info.removes, vec![2]);
    assert!(info.adds.is_empty());
    assert!(remove.welcome.is_none());
}

#[test]
fn proposals_and_commits_by_reference() {
    let capabilities = Capabilities::default();
    let config = common::create_config(capabilities.clone());
    let (alice, mut alice_group, _bob, _bob_group) =
        common::two_member_group(&capabilities, &config);
    let (proposal, proposal_ref) = alice_group
        .propose_remove_member(&alice.provider, &alice.signer, LeafNodeIndex::new(1))
        .unwrap();
    let info = inspect_message(&proposal.tls_serialize_detached().unwrap()).unwrap();
    assert_eq!(info.content_type, MessageContent::Proposal);
    assert_eq!(info.epoch, 1);
    assert_eq!(info.sender_leaf, 0);
    assert_eq!(info.removes, vec![1]);
    assert!(!info.updates_path);

    let (commit, _, _) = alice_group
        .commit_to_pending_proposals(&alice.provider, &alice.signer)
        .unwrap();
    let info = inspect_message(&commit.tls_serialize_detached().unwrap()).unwrap();
    assert_eq!(info.content_type, MessageContent::Commit);
    assert_eq!(info.proposal_refs, vec![proposal_ref.as_slice().to_vec()]);
    assert!(info.removes.is_empty());
}

#[test]
fn message_rejections() {
    let alice = Party::new();
    let bob = Party::new();
    let mut group = alice.create();
    let key_package = bob.key_package();
    let unit = group
        .add_members(
            &alice.identity,
            std::slice::from_ref(&key_package),
            Some(KeyHistoryOffer {
                from_epoch: 0,
                sealed: false,
            }),
        )
        .unwrap();
    let [KeyHistoryRecord::Message(private)] = unit.key_history.as_slice() else {
        panic!("expected one key-history message");
    };
    let welcome = unit.welcome.as_deref().unwrap();

    for (bytes, reason) in [
        (
            private.as_slice(),
            "expected a PublicMessage, got a PrivateMessage",
        ),
        (welcome, "expected a PublicMessage, got a Welcome"),
        (
            key_package.as_slice(),
            "expected a PublicMessage, got a KeyPackage",
        ),
        (&unit.commit[..unit.commit.len() - 1], "not an MLSMessage"),
    ] {
        let error = inspect_message(bytes).unwrap_err();
        assert_eq!(error.error, Error::Malformed);
        assert_eq!(error.reason, reason);
    }

    assert_eq!(code(welcome_recipients(&unit.commit)), Error::Malformed);
    assert_eq!(code(welcome_recipients(&key_package)), Error::Malformed);
    assert_eq!(code(welcome_recipients(&[0, 1])), Error::Malformed);
}
