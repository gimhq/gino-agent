//! Drops: HPKE base mode (X25519, HKDF-SHA256, AES-128-GCM) through the
//! OpenMLS crypto provider, to a key pair derived from an exporter secret.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{DROP_LABEL, SCOPE_ID, create_config, two_member_group};
use openmls::prelude::Capabilities;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType};

const DROP_HPKE: HpkeConfig = HpkeConfig(
    HpkeKemType::DhKem25519,
    HpkeKdfType::HkdfSha256,
    HpkeAeadType::AesGcm128,
);

#[test]
fn seal_open_round_trip_with_derived_key_pair() {
    let crypto = RustCrypto::default();
    let seed = [0x42u8; 32];
    let key_pair = crypto
        .derive_hpke_keypair(DROP_HPKE, &seed)
        .expect("derive key pair");
    assert_eq!(key_pair.public.len(), 32);
    let again = crypto
        .derive_hpke_keypair(DROP_HPKE, &seed)
        .expect("derive key pair");
    assert_eq!(again.public, key_pair.public);

    let aad = b"scope:task-1|drop:webhook-7";
    let sealed = crypto
        .hpke_seal(
            DROP_HPKE,
            &key_pair.public,
            b"",
            aad,
            b"synthetic drop body",
        )
        .expect("seal");
    assert_eq!(sealed.kem_output.as_slice().len(), 32);
    let opened = crypto
        .hpke_open(DROP_HPKE, &sealed, &key_pair.private, b"", aad)
        .expect("open");
    assert_eq!(opened, b"synthetic drop body");

    assert!(
        crypto
            .hpke_open(DROP_HPKE, &sealed, &key_pair.private, b"", b"scope:task-2")
            .is_err()
    );
}

#[test]
fn members_derive_the_same_drop_key_pair_from_the_exporter() {
    let capabilities = Capabilities::default();
    let config = create_config(capabilities.clone());
    let (alice, alice_group, bob, bob_group) = two_member_group(&capabilities, &config);
    let crypto = alice.provider.crypto();

    let alice_seed = alice_group
        .export_secret(crypto, DROP_LABEL, SCOPE_ID, 32)
        .expect("export");
    let bob_seed = bob_group
        .export_secret(bob.provider.crypto(), DROP_LABEL, SCOPE_ID, 32)
        .expect("export");
    let alice_pair = crypto
        .derive_hpke_keypair(DROP_HPKE, &alice_seed)
        .expect("derive");
    let bob_pair = crypto
        .derive_hpke_keypair(DROP_HPKE, &bob_seed)
        .expect("derive");
    assert_eq!(alice_pair.public, bob_pair.public);

    // A non-member seals to the published public key only.
    let sealed = RustCrypto::default()
        .hpke_seal(DROP_HPKE, &alice_pair.public, b"", b"loc", b"payload")
        .expect("seal");
    let opened = bob
        .provider
        .crypto()
        .hpke_open(DROP_HPKE, &sealed, &bob_pair.private, b"", b"loc")
        .expect("open");
    assert_eq!(opened, b"payload");
}
