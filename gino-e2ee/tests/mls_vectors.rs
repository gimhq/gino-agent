//! RFC 9420 interoperability test vectors (mlswg/mls-implementations,
//! `tests/vectors/`, suite `0x0001` subset) against this build of OpenMLS
//! and its RustCrypto provider:
//!
//! - `key-schedule.json`: OpenMLS's own known-answer runner (every epoch
//!   secret, the external key pair and the exporter);
//! - `crypto-basics.json`: the labelled primitives of RFC 9420 §5 through
//!   the provider (`ExpandWithLabel`, `DeriveSecret`, `DeriveTreeSecret`,
//!   `RefHash`, `SignWithLabel`, `EncryptWithLabel`);
//! - `welcome.json`: OpenMLS decrypts the group secrets and the GroupInfo
//!   with the KeyPackage's init key, and the GroupInfo signature verifies;
//! - `messages.json`: every MLSMessage, ratchet tree and proposal encoding
//!   OpenMLS exposes round-trips byte for byte (`group_secrets`, `commit`
//!   and `group_context_extensions_proposal` have no public decoder; the
//!   ReInit proposals are refused, see [`REFUSED_PLACEMENT`]).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use openmls::prelude::tls_codec::{self, Deserialize as _, Serialize as _, VLBytes};
use openmls::prelude::*;
use openmls::schedule::tests_and_kats::kats::key_schedule::{
    KeyScheduleTestVector, run_test_vector,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::storage::StorageProvider as _;
use openmls_traits::types::{HashType, HpkeCiphertext};
use serde_json::Value;

const SUITE: u64 = 1;
const HPKE: openmls_traits::types::HpkeConfig = openmls_traits::types::HpkeConfig(
    openmls_traits::types::HpkeKemType::DhKem25519,
    openmls_traits::types::HpkeKdfType::HkdfSha256,
    openmls_traits::types::HpkeAeadType::AesGcm128,
);

fn read(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("vector file");
    let Value::Array(items) = serde_json::from_str(&text).expect("vector json") else {
        panic!("{name} is not an array");
    };
    assert!(!items.is_empty(), "{name} is empty");
    items
}

fn hex(value: &Value, key: &str) -> Vec<u8> {
    let text = value[key].as_str().unwrap_or_else(|| panic!("{key}"));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn number(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or_else(|| panic!("{key}"))
}

/// `opaque<V>`: QUIC-style variable-length prefix and the bytes.
fn opaque(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .unwrap()
}

fn mls_label(label: &str) -> Vec<u8> {
    opaque(format!("MLS 1.0 {label}").as_bytes())
}

fn expand_with_label(
    crypto: &impl OpenMlsCrypto,
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: u16,
) -> Vec<u8> {
    let info = [
        &length.to_be_bytes()[..],
        &mls_label(label),
        &opaque(context),
    ]
    .concat();
    crypto
        .hkdf_expand(HashType::Sha2_256, secret, &info, length.into())
        .unwrap()
        .as_slice()
        .to_vec()
}

#[test]
fn key_schedule() {
    let provider = OpenMlsRustCrypto::default();
    for item in read("key-schedule.json") {
        assert_eq!(number(&item, "cipher_suite"), SUITE);
        let mut tampered = item.clone();
        tampered["epochs"][0]["exporter"]["secret"] = Value::from("00".repeat(32));
        let vector: KeyScheduleTestVector = serde_json::from_value(item).unwrap();
        run_test_vector(vector, &provider).unwrap();
        let tampered: KeyScheduleTestVector = serde_json::from_value(tampered).unwrap();
        assert!(run_test_vector(tampered, &provider).is_err());
    }
}

#[test]
fn crypto_basics() {
    let crypto = OpenMlsRustCrypto::default();
    let crypto = crypto.crypto();
    for item in read("crypto-basics.json") {
        assert_eq!(number(&item, "cipher_suite"), SUITE);

        let v = &item["expand_with_label"];
        let length = u16::try_from(number(v, "length")).unwrap();
        let label = v["label"].as_str().unwrap();
        assert_eq!(
            expand_with_label(crypto, &hex(v, "secret"), label, &hex(v, "context"), length),
            hex(v, "out")
        );

        let v = &item["derive_secret"];
        let label = v["label"].as_str().unwrap();
        assert_eq!(
            expand_with_label(crypto, &hex(v, "secret"), label, &[], 32),
            hex(v, "out")
        );

        let v = &item["derive_tree_secret"];
        let generation = u32::try_from(number(v, "generation")).unwrap();
        let length = u16::try_from(number(v, "length")).unwrap();
        let label = v["label"].as_str().unwrap();
        assert_eq!(
            expand_with_label(
                crypto,
                &hex(v, "secret"),
                label,
                &generation.to_be_bytes(),
                length
            ),
            hex(v, "out")
        );

        let v = &item["ref_hash"];
        let input = [
            opaque(v["label"].as_str().unwrap().as_bytes()),
            opaque(&hex(v, "value")),
        ]
        .concat();
        assert_eq!(
            crypto.hash(HashType::Sha2_256, &input).unwrap(),
            hex(v, "out")
        );

        let v = &item["sign_with_label"];
        let content = [
            mls_label(v["label"].as_str().unwrap()),
            opaque(&hex(v, "content")),
        ]
        .concat();
        crypto
            .verify_signature(
                SignatureScheme::ED25519,
                &content,
                &hex(v, "pub"),
                &hex(v, "signature"),
            )
            .unwrap();
        assert_eq!(
            crypto
                .sign(SignatureScheme::ED25519, &content, &hex(v, "priv"))
                .unwrap(),
            hex(v, "signature")
        );

        let v = &item["encrypt_with_label"];
        let info = [
            mls_label(v["label"].as_str().unwrap()),
            opaque(&hex(v, "context")),
        ]
        .concat();
        let ciphertext = HpkeCiphertext {
            kem_output: hex(v, "kem_output").into(),
            ciphertext: hex(v, "ciphertext").into(),
        };
        assert_eq!(
            crypto
                .hpke_open(HPKE, &ciphertext, &hex(v, "priv"), &info, &[])
                .unwrap(),
            hex(v, "plaintext")
        );
    }
}

#[test]
fn welcome() {
    for item in read("welcome.json") {
        assert_eq!(number(&item, "cipher_suite"), SUITE);
        let provider = OpenMlsRustCrypto::default();
        let MlsMessageBodyIn::KeyPackage(key_package) =
            MlsMessageIn::tls_deserialize_exact(hex(&item, "key_package"))
                .unwrap()
                .extract()
        else {
            panic!("not a KeyPackage");
        };
        let key_package: KeyPackage = key_package.into();
        let MlsMessageBodyIn::Welcome(welcome) =
            MlsMessageIn::tls_deserialize_exact(hex(&item, "welcome"))
                .unwrap()
                .extract()
        else {
            panic!("not a Welcome");
        };
        let reference = key_package.hash_ref(provider.crypto()).unwrap();
        let bundle = KeyPackageBundle::new(
            key_package,
            HpkePrivateKey::from(hex(&item, "init_priv")),
            Vec::new().into(),
        );
        provider
            .storage()
            .write_key_package(&reference, &bundle)
            .unwrap();

        let processed =
            ProcessedWelcome::new_from_welcome(&provider, &MlsGroupJoinConfig::default(), welcome)
                .expect("group secrets and GroupInfo decrypt");
        let group_info = openmls::messages::group_info::GroupInfo::from(
            processed.unverified_group_info().clone(),
        );
        let encoded = group_info.tls_serialize_detached().unwrap();
        let signature = group_info.signature().tls_serialize_detached().unwrap();
        let tbs = &encoded[..encoded.len() - signature.len()];
        let signature = VLBytes::tls_deserialize_exact(&signature).unwrap();
        let content = [mls_label("GroupInfoTBS"), opaque(tbs)].concat();
        provider
            .crypto()
            .verify_signature(
                SignatureScheme::ED25519,
                &content,
                &hex(&item, "signer_pub"),
                signature.as_slice(),
            )
            .expect("GroupInfo signature");
    }
}

/// Decodes and re-encodes one structure; the decoder's error message on
/// failure.
type RoundTrip = fn(&[u8]) -> Result<Vec<u8>, String>;

fn round_trip<T: tls_codec::Deserialize + tls_codec::Serialize>(
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let value = T::tls_deserialize_exact(bytes).map_err(|e| e.to_string())?;
    Ok(value.tls_serialize_detached().unwrap())
}

/// OpenMLS validates extension placement while decoding; the generated
/// ReInit proposals carry extension lists RFC 9420 §13 does not allow in a
/// group context, so it refuses all of them (ReInit is unused in v1).
const REFUSED_PLACEMENT: &str = "that is not allowed in the group context";

#[test]
fn messages() {
    let checks: [(&str, RoundTrip); 13] = [
        ("mls_welcome", round_trip::<MlsMessageIn>),
        ("mls_group_info", round_trip::<MlsMessageIn>),
        ("mls_key_package", round_trip::<MlsMessageIn>),
        ("public_message_application", round_trip::<MlsMessageIn>),
        ("public_message_proposal", round_trip::<MlsMessageIn>),
        ("public_message_commit", round_trip::<MlsMessageIn>),
        ("private_message", round_trip::<MlsMessageIn>),
        ("ratchet_tree", round_trip::<RatchetTreeIn>),
        (
            "add_proposal",
            round_trip::<openmls::messages::proposals_in::AddProposalIn>,
        ),
        (
            "update_proposal",
            round_trip::<openmls::messages::proposals_in::UpdateProposalIn>,
        ),
        ("remove_proposal", round_trip::<RemoveProposal>),
        (
            "pre_shared_key_proposal",
            round_trip::<PreSharedKeyProposal>,
        ),
        ("external_init_proposal", round_trip::<ExternalInitProposal>),
    ];
    for item in read("messages.json") {
        for (key, check) in checks {
            let bytes = hex(&item, key);
            assert_eq!(check(&bytes).unwrap(), bytes, "{key}");
        }
        let error = round_trip::<ReInitProposal>(&hex(&item, "re_init_proposal")).unwrap_err();
        assert!(error.contains(REFUSED_PLACEMENT), "{error}");
    }
}
