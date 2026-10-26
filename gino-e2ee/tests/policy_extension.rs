//! The scope history policy travels as a private-use group context extension
//! that every member must support.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{Member, create_config, two_member_group};
use openmls::prelude::*;

/// Private-use extension type (RFC 9420 §17.3: 0xF000..=0xFFFF).
const HISTORY_POLICY: u16 = 0xF0E2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryPolicy {
    Full,
    FromEpoch(u64),
    FromJoin,
}

impl HistoryPolicy {
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Full => vec![0],
            Self::FromEpoch(epoch) => [&[1][..], &epoch.to_be_bytes()].concat(),
            Self::FromJoin => vec![2],
        }
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [0] => Some(Self::Full),
            [1, epoch @ ..] => Some(Self::FromEpoch(u64::from_be_bytes(epoch.try_into().ok()?))),
            [2] => Some(Self::FromJoin),
            _ => None,
        }
    }
}

fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::Unknown(HISTORY_POLICY)]),
        None,
        None,
    )
}

fn group_context_extensions(policy: HistoryPolicy) -> Extensions<GroupContext> {
    Extensions::from_vec(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(HISTORY_POLICY)],
            &[],
            &[],
        )),
        Extension::Unknown(HISTORY_POLICY, UnknownExtension(policy.encode())),
    ])
    .expect("group context extensions")
}

fn policy_of(group: &MlsGroup) -> Option<HistoryPolicy> {
    group
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            Extension::Unknown(HISTORY_POLICY, UnknownExtension(bytes)) => {
                HistoryPolicy::decode(bytes)
            }
            _ => None,
        })
}

fn config(policy: HistoryPolicy) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(common::CIPHERSUITE)
        .capabilities(capabilities())
        .use_ratchet_tree_extension(true)
        .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .with_group_context_extensions(group_context_extensions(policy))
        .build()
}

#[test]
fn joiner_reads_policy_and_members_agree_on_change() {
    let config = config(HistoryPolicy::Full);
    let (alice, mut alice_group, bob, mut bob_group) = two_member_group(&capabilities(), &config);
    assert_eq!(policy_of(&alice_group), Some(HistoryPolicy::Full));
    assert_eq!(policy_of(&bob_group), Some(HistoryPolicy::Full));

    let (commit, welcome, _info) = alice_group
        .update_group_context_extensions(
            &alice.provider,
            group_context_extensions(HistoryPolicy::FromEpoch(2)),
            &alice.signer,
        )
        .expect("group context extensions commit");
    assert!(welcome.is_none());
    alice_group
        .merge_pending_commit(&alice.provider)
        .expect("merge extensions commit");
    bob.apply_commit(&mut bob_group, &commit);

    assert_eq!(bob_group.epoch().as_u64(), 2);
    assert_eq!(policy_of(&alice_group), Some(HistoryPolicy::FromEpoch(2)));
    assert_eq!(policy_of(&bob_group), Some(HistoryPolicy::FromEpoch(2)));
}

#[test]
fn member_without_policy_support_cannot_be_added() {
    let alice = Member::new("alice");
    let carol = Member::new("carol");
    let mut group = alice.create_group(&config(HistoryPolicy::FromJoin));
    let error = group
        .add_members(
            &alice.provider,
            &alice.signer,
            &[carol.key_package(Capabilities::default())],
        )
        .expect_err("add without policy support");
    assert!(matches!(
        error,
        AddMembersError::CreateCommitError(CreateCommitError::ProposalValidationError(
            ProposalValidationError::InsufficientCapabilities
        ))
    ));
}

#[test]
fn plain_groups_need_no_policy() {
    let capabilities = Capabilities::default();
    let (_alice, alice_group, _bob, _bob_group) =
        two_member_group(&capabilities, &create_config(capabilities.clone()));
    assert_eq!(policy_of(&alice_group), None);
}
