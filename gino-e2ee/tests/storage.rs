//! Group state persists as a snapshot of the OpenMLS key-value store: every
//! write goes through `StorageProvider` into `MemoryStorage::values`, so the
//! map can be exported as opaque bytes and loaded into a fresh provider.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashMap;
use std::sync::RwLock;

use common::{Member, Provider, SCOPE_ID, create_config, two_member_group};
use openmls::prelude::*;
use openmls_rust_crypto::MemoryStorage;

/// Length-prefixed `key | value` records, sorted by key.
fn snapshot(storage: &MemoryStorage) -> Vec<u8> {
    let values = storage.values.read().expect("storage lock");
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort();
    let mut out = Vec::new();
    for (key, value) in entries {
        for field in [key, value] {
            out.extend_from_slice(&u32::try_from(field.len()).expect("len").to_be_bytes());
            out.extend_from_slice(field);
        }
    }
    out
}

fn take(bytes: &mut &[u8]) -> Vec<u8> {
    let (len, rest) = bytes.split_at(4);
    let len = u32::from_be_bytes(len.try_into().expect("len")) as usize;
    let (field, rest) = rest.split_at(len);
    *bytes = rest;
    field.to_vec()
}

fn restore(mut bytes: &[u8]) -> MemoryStorage {
    let mut values = HashMap::new();
    while !bytes.is_empty() {
        let key = take(&mut bytes);
        values.insert(key, take(&mut bytes));
    }
    MemoryStorage {
        values: RwLock::new(values),
    }
}

/// Persists a member's store, drops its provider and in-memory group, and
/// reloads the group from the restored store.
fn reload(member: &mut Member, group: MlsGroup) -> MlsGroup {
    let bytes = snapshot(&member.provider.storage);
    drop(group);
    member.provider = Provider {
        storage: restore(&bytes),
        ..Provider::default()
    };
    MlsGroup::load(&member.provider.storage, &GroupId::from_slice(SCOPE_ID))
        .expect("load group")
        .expect("group present")
}

#[test]
fn group_survives_persist_drop_restore() {
    let capabilities = Capabilities::default();
    let config = create_config(capabilities.clone());
    let (mut alice, alice_group, mut bob, bob_group) = two_member_group(&capabilities, &config);
    let k1 = alice.content_key(&alice_group);

    let mut alice_group = reload(&mut alice, alice_group);
    let mut bob_group = reload(&mut bob, bob_group);
    assert_eq!(alice_group.epoch().as_u64(), 1);
    assert_eq!(alice.content_key(&alice_group), k1);
    assert_eq!(bob.content_key(&bob_group), k1);

    // Application messages continue on the restored sender ratchets.
    let message = alice_group
        .create_message(&alice.provider, &alice.signer, b"synthetic after restore")
        .expect("create message");
    assert_eq!(
        bob.open_application(&mut bob_group, &message),
        b"synthetic after restore"
    );

    // A restored member commits; the other merges after its own restore.
    let (commit, _welcome, _info) = bob_group
        .self_update(&bob.provider, &bob.signer, LeafNodeParameters::default())
        .expect("self update")
        .into_contents();
    bob_group
        .merge_pending_commit(&bob.provider)
        .expect("merge update");
    let mut alice_group = reload(&mut alice, alice_group);
    alice.apply_commit(&mut alice_group, &commit);

    assert_eq!(alice_group.epoch().as_u64(), 2);
    let k2 = alice.content_key(&alice_group);
    assert_ne!(k2, k1);
    let bob_group = reload(&mut bob, bob_group);
    assert_eq!(bob.content_key(&bob_group), k2);
}
