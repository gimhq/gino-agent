//! Both members of an epoch derive the same exporter content key, and the key
//! changes with the epoch.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{create_config, two_member_group};
use openmls::prelude::{Capabilities, LeafNodeParameters};

#[test]
fn members_share_exporter_secret_per_epoch() {
    let capabilities = Capabilities::default();
    let config = create_config(capabilities.clone());
    let (alice, mut alice_group, bob, mut bob_group) = two_member_group(&capabilities, &config);

    assert_eq!(alice_group.epoch().as_u64(), 1);
    assert_eq!(bob_group.epoch(), alice_group.epoch());
    let alice_k1 = alice.content_key(&alice_group);
    let bob_k1 = bob.content_key(&bob_group);
    assert_eq!(alice_k1.len(), 32);
    assert_eq!(alice_k1, bob_k1);

    let (commit, welcome, _info) = alice_group
        .self_update(
            &alice.provider,
            &alice.signer,
            LeafNodeParameters::default(),
        )
        .expect("self update")
        .into_contents();
    assert!(welcome.is_none());
    alice_group
        .merge_pending_commit(&alice.provider)
        .expect("merge update");
    bob.apply_commit(&mut bob_group, &commit);

    assert_eq!(bob_group.epoch().as_u64(), 2);
    let alice_k2 = alice.content_key(&alice_group);
    assert_eq!(alice_k2, bob.content_key(&bob_group));
    assert_ne!(alice_k2, alice_k1);
}
