//! Multi-member scenarios of the MLS group layer against an in-memory
//! Delivery Service that follows spec §3 (ordered log, first commit per
//! epoch wins, first link per epoch wins).

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use gino_e2ee::{
    Applied, CommitUnit, EntryKind, Error, GroupError, HistoryPolicy, Identity, KeyHistoryOffer,
    KeyHistoryRecord, KeyPackageStore, Location, LogEntry, MemoryKeyCache, MemoryStateStore,
    ScopeGroup, StateStore, seal_content,
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

    fn create(&self, policy: HistoryPolicy) -> Group {
        ScopeGroup::create(
            &self.identity,
            PROFILE,
            SCOPE,
            policy,
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

/// The DS of one scope.
#[derive(Default)]
struct Ds {
    epoch: u64,
    log: Vec<LogEntry>,
    links: BTreeMap<u64, Vec<u8>>,
}

impl Ds {
    /// Accepts the unit if it is the first commit of the current epoch and
    /// returns the commit's `seq`.
    fn submit(&mut self, unit: &CommitUnit) -> Option<u64> {
        if unit.epoch != self.epoch {
            return None;
        }
        let seq = self.push(EntryKind::Commit, unit.epoch, unit.commit.clone());
        self.log.last_mut().unwrap().drop_public_key = Some(unit.drop_public_key.to_vec());
        self.epoch += 1;
        if let Some(link) = &unit.epoch_link {
            self.links.entry(self.epoch).or_insert_with(|| link.clone());
        }
        for record in &unit.key_history {
            let (kind, bytes) = match record {
                KeyHistoryRecord::Message(bytes) => (EntryKind::KeyHistory, bytes),
                KeyHistoryRecord::Sealed(bytes) => (EntryKind::KeyHistorySealed, bytes),
            };
            self.push(kind, self.epoch, bytes.clone());
        }
        Some(seq)
    }

    fn push(&mut self, kind: EntryKind, epoch: u64, bytes: Vec<u8>) -> u64 {
        let seq = self.log.len() as u64 + 1;
        self.log.push(LogEntry {
            seq,
            kind,
            epoch,
            bytes,
            drop_public_key: None,
        });
        seq
    }

    /// Submits a unit and settles it at the committer.
    fn commit(&mut self, group: &mut Group, unit: &CommitUnit) -> u64 {
        let seq = self.submit(unit).expect("commit accepted");
        group.commit_accepted(seq).unwrap();
        seq
    }

    /// Applies every entry after the member's last applied one.
    fn catch_up(&self, group: &mut Group) -> Vec<Applied> {
        let start = usize::try_from(group.seq()).unwrap();
        self.log[start..]
            .iter()
            .map(|entry| group.apply(entry).unwrap())
            .collect()
    }

    fn fetch(&self) -> impl FnMut(u64) -> Option<Vec<u8>> + '_ {
        |epoch| self.links.get(&epoch).cloned()
    }
}

fn location(field: &str) -> Location {
    Location::new(SCOPE).unwrap().part("field", field).unwrap()
}

/// Seals `text` at the member's current epoch.
fn seal(group: &Group, text: &str) -> Vec<u8> {
    let (epoch, secrets) = group.current().unwrap();
    seal_content(
        &secrets.content_key,
        epoch,
        &location("text"),
        text.as_bytes(),
        &RustCrypto::default(),
    )
    .unwrap()
}

fn open(group: &mut Group, ds: &Ds, envelope: &[u8]) -> Result<Vec<u8>, GroupError> {
    group
        .open(envelope, &location("text"), ds.fetch())
        .map(|opened| opened.plaintext)
}

/// Creator and runner at epoch 1 under `policy`.
fn pair(policy: HistoryPolicy) -> (Ds, Party, Group, Party, Group) {
    let (owner, runner) = (Party::new(), Party::new());
    let mut ds = Ds::default();
    let mut owner_group = owner.create(policy);
    let unit = owner_group
        .add_members(&owner.identity, &[runner.key_package()], None)
        .unwrap();
    let seq = ds.commit(&mut owner_group, &unit);
    let runner_group = runner.join(unit.welcome.as_ref().unwrap(), seq);
    (ds, owner, owner_group, runner, runner_group)
}

/// Advances the group by `count` self-updates of `group`'s member.
fn updates(ds: &mut Ds, party: &Party, group: &mut Group, count: usize) {
    for _ in 0..count {
        let unit = group.self_update(&party.identity).unwrap();
        ds.commit(group, &unit);
    }
}

#[test]
fn create_add_and_exchange_content() {
    let (ds, owner, mut owner_group, runner, mut runner_group) = pair(HistoryPolicy::Full);
    assert_eq!(owner_group.epoch(), 1);
    assert_eq!(runner_group.epoch(), 1);
    assert_eq!(
        owner_group.current().unwrap(),
        runner_group.current().unwrap()
    );
    assert_eq!(
        owner_group.group_id(),
        gino_e2ee::group_id(PROFILE, SCOPE).unwrap()
    );
    assert_eq!(runner_group.policy().unwrap(), HistoryPolicy::Full);
    assert_eq!(
        runner_group.members(),
        [
            owner.identity.public_key().to_vec(),
            runner.identity.public_key().to_vec()
        ]
    );
    assert_eq!(
        owner_group.drop_public_key().unwrap(),
        runner_group.drop_public_key().unwrap()
    );

    let to_runner = seal(&owner_group, "do the task");
    assert_eq!(
        open(&mut runner_group, &ds, &to_runner).unwrap(),
        b"do the task"
    );
    let to_owner = seal(&runner_group, "done");
    assert_eq!(open(&mut owner_group, &ds, &to_owner).unwrap(), b"done");
}

#[test]
fn epoch_zero_content_reaches_the_joiner_through_the_link() {
    let owner = Party::new();
    let runner = Party::new();
    let mut ds = Ds::default();
    let mut owner_group = owner.create(HistoryPolicy::Full);
    let early = seal(&owner_group, "sealed at epoch 0");
    let unit = owner_group
        .add_members(&owner.identity, &[runner.key_package()], None)
        .unwrap();
    assert!(unit.epoch_link.is_some());
    let seq = ds.commit(&mut owner_group, &unit);
    let mut runner_group = runner.join(unit.welcome.as_ref().unwrap(), seq);
    assert_eq!(
        open(&mut runner_group, &ds, &early).unwrap(),
        b"sealed at epoch 0"
    );
}

#[test]
fn removed_member_keeps_held_history_only() {
    let (mut ds, owner, mut owner_group, runner, mut runner_group) = pair(HistoryPolicy::Full);
    let before = seal(&owner_group, "before removal");
    let unit = owner_group
        .remove_members(&owner.identity, &[runner.identity.public_key()])
        .unwrap();
    ds.commit(&mut owner_group, &unit);
    let after = seal(&owner_group, "after removal");

    assert_eq!(
        ds.catch_up(&mut runner_group),
        [Applied::Commit {
            epoch: 2,
            self_removed: true
        }]
    );
    assert!(!runner_group.is_member());
    assert_eq!(
        runner_group.current(),
        Err(GroupError::E2ee(Error::NotMember))
    );
    assert_eq!(runner_group.history().cached(2), None);
    assert_eq!(
        open(&mut runner_group, &ds, &after),
        Err(GroupError::E2ee(Error::EpochUnknown { epoch: 2 }))
    );
    assert_eq!(
        open(&mut runner_group, &ds, &before).unwrap(),
        b"before removal"
    );
    assert_eq!(
        runner_group.self_update(&runner.identity),
        Err(GroupError::E2ee(Error::NotMember))
    );
    assert_eq!(
        runner_group.apply(&LogEntry {
            seq: runner_group.seq() + 1,
            kind: EntryKind::Commit,
            epoch: 2,
            bytes: vec![],
            drop_public_key: None,
        }),
        Err(GroupError::E2ee(Error::NotMember))
    );
}

#[test]
fn runner_state_loss_is_repaired_by_re_adding() {
    let (mut ds, owner, mut owner_group, runner, _lost) = pair(HistoryPolicy::Full);
    let history: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            let envelope = seal(&owner_group, &format!("epoch {}", owner_group.epoch()));
            if i < 2 {
                updates(&mut ds, &owner, &mut owner_group, 1);
            }
            envelope
        })
        .collect();

    // The runner lost its state: remove its old leaf, add a fresh KeyPackage.
    let unit = owner_group
        .remove_members(&owner.identity, &[runner.identity.public_key()])
        .unwrap();
    ds.commit(&mut owner_group, &unit);
    let fresh = Party {
        identity: runner.identity.clone(),
        key_packages: KeyPackageStore::new(),
    };
    let unit = owner_group
        .add_members(&owner.identity, &[fresh.key_package()], None)
        .unwrap();
    let seq = ds.commit(&mut owner_group, &unit);
    let mut runner_group = fresh.join(unit.welcome.as_ref().unwrap(), seq);
    assert_eq!(runner_group.epoch(), 5);
    for (i, envelope) in history.iter().enumerate() {
        assert_eq!(
            open(&mut runner_group, &ds, envelope).unwrap(),
            format!("epoch {}", i + 1).as_bytes()
        );
    }
}

#[test]
fn missing_link_cuts_older_epochs_only() {
    let (mut ds, owner, mut owner_group, _runner, _runner_group) = pair(HistoryPolicy::Full);
    let envelopes: Vec<Vec<u8>> = (0..3)
        .map(|_| {
            let envelope = seal(&owner_group, "x");
            updates(&mut ds, &owner, &mut owner_group, 1);
            envelope
        })
        .collect();
    // Epochs 1, 2, 3 sealed; current 4. Drop the link of epoch 3.
    ds.links.remove(&3);
    let late = Party::new();
    let unit = owner_group
        .add_members(&owner.identity, &[late.key_package()], None)
        .unwrap();
    let seq = ds.commit(&mut owner_group, &unit);
    let mut late_group = late.join(unit.welcome.as_ref().unwrap(), seq);
    assert_eq!(
        open(&mut late_group, &ds, &envelopes[0]),
        Err(GroupError::E2ee(Error::HistoryUnavailable { epoch: 1 }))
    );
    assert_eq!(
        open(&mut late_group, &ds, &envelopes[1]),
        Err(GroupError::E2ee(Error::HistoryUnavailable { epoch: 2 }))
    );
    assert_eq!(open(&mut late_group, &ds, &envelopes[2]).unwrap(), b"x");
}

/// Seals one envelope per epoch `0..=upto` while self-updating, under
/// `policy` from creation; returns the DS, owner, its group and the
/// envelopes.
fn history_under(policy: HistoryPolicy, upto: u64) -> (Ds, Party, Group, Vec<Vec<u8>>) {
    let owner = Party::new();
    let mut ds = Ds::default();
    let mut group = owner.create(policy);
    let mut envelopes = Vec::new();
    for epoch in 0..=upto {
        envelopes.push(seal(&group, &format!("epoch {epoch}")));
        if epoch < upto {
            updates(&mut ds, &owner, &mut group, 1);
        }
    }
    (ds, owner, group, envelopes)
}

fn joiner_reads(
    ds: &mut Ds,
    owner: &Party,
    group: &mut Group,
    envelopes: &[Vec<u8>],
    offer: Option<KeyHistoryOffer>,
) -> Vec<Result<Vec<u8>, GroupError>> {
    let joiner = Party::new();
    let unit = group
        .add_members(&owner.identity, &[joiner.key_package()], offer)
        .unwrap();
    let seq = ds.commit(group, &unit);
    let mut group_of_joiner = joiner.join(unit.welcome.as_ref().unwrap(), seq);
    ds.catch_up(&mut group_of_joiner);
    envelopes
        .iter()
        .map(|envelope| open(&mut group_of_joiner, ds, envelope))
        .collect()
}

fn readable(results: &[Result<Vec<u8>, GroupError>]) -> Vec<bool> {
    results.iter().map(Result::is_ok).collect()
}

#[test]
fn policy_full_reads_everything() {
    let (mut ds, owner, mut group, envelopes) = history_under(HistoryPolicy::Full, 3);
    let results = joiner_reads(&mut ds, &owner, &mut group, &envelopes, None);
    assert_eq!(readable(&results), [true; 4]);
}

#[test]
fn policy_from_epoch_links_from_n() {
    let (mut ds, owner, mut group, envelopes) = history_under(HistoryPolicy::FromEpoch(2), 4);
    assert_eq!(ds.links.keys().copied().collect::<Vec<_>>(), [3, 4]);
    let results = joiner_reads(&mut ds, &owner, &mut group, &envelopes, None);
    assert_eq!(readable(&results), [false, false, true, true, true]);
    assert_eq!(
        results[1],
        Err(GroupError::E2ee(Error::HistoryUnavailable { epoch: 1 }))
    );
}

#[test]
fn policy_from_join_without_key_history() {
    let (mut ds, owner, mut group, envelopes) = history_under(HistoryPolicy::FromJoin, 2);
    assert!(ds.links.is_empty());
    let results = joiner_reads(&mut ds, &owner, &mut group, &envelopes, None);
    assert_eq!(readable(&results), [false; 3]);
    assert_eq!(
        results[2],
        Err(GroupError::E2ee(Error::HistoryUnavailable { epoch: 2 }))
    );
}

#[test]
fn policy_from_join_with_key_history_message() {
    let (mut ds, owner, mut group, envelopes) = history_under(HistoryPolicy::FromJoin, 3);
    let offer = KeyHistoryOffer {
        from_epoch: 2,
        sealed: false,
    };
    let results = joiner_reads(&mut ds, &owner, &mut group, &envelopes, Some(offer));
    assert_eq!(readable(&results), [false, false, true, true]);
    assert_eq!(ds.log.last().unwrap().kind, EntryKind::KeyHistory);
}

#[test]
fn policy_from_join_with_sealed_key_history() {
    let (mut ds, owner, mut group, envelopes) = history_under(HistoryPolicy::FromJoin, 3);
    let offer = KeyHistoryOffer {
        from_epoch: 1,
        sealed: true,
    };
    let results = joiner_reads(&mut ds, &owner, &mut group, &envelopes, Some(offer));
    assert_eq!(readable(&results), [false, true, true, true]);
    assert_eq!(ds.log.last().unwrap().kind, EntryKind::KeyHistorySealed);
}

#[test]
fn key_history_is_skipped_by_other_members_and_the_sender() {
    let (mut ds, owner, mut owner_group, runner, mut runner_group) = pair(HistoryPolicy::FromJoin);
    let joiner = Party::new();
    let offer = KeyHistoryOffer {
        from_epoch: 0,
        sealed: true,
    };
    let unit = owner_group
        .add_members(&owner.identity, &[joiner.key_package()], Some(offer))
        .unwrap();
    ds.commit(&mut owner_group, &unit);
    assert_eq!(
        ds.catch_up(&mut runner_group),
        [
            Applied::Commit {
                epoch: 2,
                self_removed: false
            },
            Applied::Skipped
        ]
    );
    assert_eq!(ds.catch_up(&mut owner_group), [Applied::Skipped]);
    // The message form is opened by members other than the sender.
    let unit = owner_group
        .add_members(
            &owner.identity,
            &[Party::new().key_package()],
            Some(KeyHistoryOffer {
                from_epoch: 0,
                sealed: false,
            }),
        )
        .unwrap();
    ds.commit(&mut owner_group, &unit);
    assert_eq!(ds.catch_up(&mut runner_group)[1], Applied::KeyHistory);
    assert_eq!(ds.catch_up(&mut owner_group), [Applied::Skipped]);
    drop(runner);
}

#[test]
fn policy_change_applies_from_the_next_transition() {
    let (mut ds, owner, mut owner_group, _runner, mut runner_group) = pair(HistoryPolicy::Full);
    let unit = owner_group
        .set_policy(&owner.identity, HistoryPolicy::FromJoin)
        .unwrap();
    assert!(unit.epoch_link.is_none());
    ds.commit(&mut owner_group, &unit);
    ds.catch_up(&mut runner_group);
    assert_eq!(runner_group.policy().unwrap(), HistoryPolicy::FromJoin);
    let unit = owner_group
        .set_policy(&owner.identity, HistoryPolicy::Full)
        .unwrap();
    assert!(unit.epoch_link.is_some());
}

#[test]
fn offline_member_catches_up_in_log_order() {
    let (mut ds, owner, mut owner_group, _runner, mut runner_group) = pair(HistoryPolicy::Full);
    updates(&mut ds, &owner, &mut owner_group, 2);
    let carol = Party::new();
    let unit = owner_group
        .add_members(&owner.identity, &[carol.key_package()], None)
        .unwrap();
    ds.commit(&mut owner_group, &unit);
    updates(&mut ds, &owner, &mut owner_group, 1);
    let latest = seal(&owner_group, "latest");

    assert_eq!(
        open(&mut runner_group, &ds, &latest),
        Err(GroupError::E2ee(Error::EpochUnknown { epoch: 5 }))
    );
    let skipped = ds.log[2].clone();
    assert_eq!(
        runner_group.apply(&skipped),
        Err(GroupError::Gap {
            expected: 2,
            got: 3
        })
    );
    let applied = ds.catch_up(&mut runner_group);
    assert_eq!(applied.len(), 4);
    assert_eq!(runner_group.epoch(), 5);
    assert_eq!(runner_group.members().len(), 3);
    assert_eq!(open(&mut runner_group, &ds, &latest).unwrap(), b"latest");
    // Replays change nothing.
    assert_eq!(runner_group.apply(&ds.log[1]).unwrap(), Applied::Replayed);
    assert_eq!(runner_group.epoch(), 5);
}

#[test]
fn entries_of_another_epoch_are_rejected() {
    let (mut ds, owner, mut owner_group, _runner, mut runner_group) = pair(HistoryPolicy::Full);
    updates(&mut ds, &owner, &mut owner_group, 2);
    let mut ahead = ds.log[1].clone();
    ahead.epoch = 2;
    assert_eq!(
        runner_group.apply(&ahead),
        Err(GroupError::E2ee(Error::EpochUnknown { epoch: 2 }))
    );
    let mut garbage = ds.log[1].clone();
    garbage.bytes[10] ^= 0xff;
    assert!(runner_group.apply(&garbage).is_err());
    assert_eq!(runner_group.seq(), 1);
    ds.catch_up(&mut runner_group);
    assert_eq!(runner_group.epoch(), 3);
}

#[test]
fn concurrent_commits_second_is_rejected_and_retried() {
    let (mut ds, owner, mut owner_group, runner, mut runner_group) = pair(HistoryPolicy::Full);
    let first = owner_group.self_update(&owner.identity).unwrap();
    let second = runner_group.self_update(&runner.identity).unwrap();
    assert_eq!(
        runner_group.self_update(&runner.identity),
        Err(GroupError::CommitPending)
    );
    let seq = ds.submit(&first).unwrap();
    owner_group.commit_accepted(seq).unwrap();
    assert_eq!(ds.submit(&second), None);

    runner_group.commit_rejected().unwrap();
    assert_eq!(
        runner_group.commit_rejected(),
        Err(GroupError::NoPendingCommit)
    );
    ds.catch_up(&mut runner_group);
    assert_eq!(runner_group.epoch(), 2);
    let retry = runner_group.self_update(&runner.identity).unwrap();
    ds.commit(&mut runner_group, &retry);
    ds.catch_up(&mut owner_group);
    assert_eq!(owner_group.epoch(), 3);
    assert_eq!(
        owner_group.current().unwrap(),
        runner_group.current().unwrap()
    );
}

#[test]
fn log_settles_pending_commits() {
    let (mut ds, owner, mut owner_group, runner, mut runner_group) = pair(HistoryPolicy::Full);
    // Another member's commit in the log discards the pending one.
    let first = owner_group.self_update(&owner.identity).unwrap();
    let _losing = runner_group.self_update(&runner.identity).unwrap();
    ds.submit(&first).unwrap();
    ds.catch_up(&mut runner_group);
    assert!(!runner_group.has_pending_commit());
    // The committer's own commit in the log settles it as accepted.
    ds.catch_up(&mut owner_group);
    assert!(!owner_group.has_pending_commit());
    assert_eq!(
        owner_group.current().unwrap(),
        runner_group.current().unwrap()
    );
}

#[test]
fn drop_key_mismatch_is_reported_after_applying() {
    let (mut ds, owner, mut owner_group, _runner, mut runner_group) = pair(HistoryPolicy::Full);
    updates(&mut ds, &owner, &mut owner_group, 1);
    ds.log[1].drop_public_key = Some(vec![0; 32]);
    assert_eq!(
        runner_group.apply(&ds.log[1]),
        Err(GroupError::E2ee(Error::DropKeyMismatch { epoch: 2 }))
    );
    assert_eq!(runner_group.epoch(), 2);
    assert_eq!(runner_group.seq(), 2);
}

#[test]
fn restore_from_persisted_state() {
    let (mut ds, owner, mut owner_group, runner, runner_group) = pair(HistoryPolicy::Full);
    let early = seal(&owner_group, "early");
    let mut store = MemoryStateStore::default();
    runner_group.save(&mut store).unwrap();
    let cache = runner_group.history().cache().clone();
    drop(runner_group);

    updates(&mut ds, &owner, &mut owner_group, 2);
    let mut runner_group: Group = ScopeGroup::load(&store, SCOPE, cache).unwrap();
    assert_eq!(runner_group.epoch(), 1);
    ds.catch_up(&mut runner_group);
    assert_eq!(
        runner_group.current().unwrap(),
        owner_group.current().unwrap()
    );
    assert_eq!(open(&mut runner_group, &ds, &early).unwrap(), b"early");

    // A pending commit survives a restore and settles afterwards.
    let unit = runner_group.self_update(&runner.identity).unwrap();
    let snapshot = runner_group.snapshot().unwrap();
    let cache = runner_group.history().cache().clone();
    let mut runner_group: Group = ScopeGroup::restore(&snapshot, cache).unwrap();
    assert!(runner_group.has_pending_commit());
    ds.commit(&mut runner_group, &unit);
    ds.catch_up(&mut owner_group);
    assert_eq!(
        runner_group.current().unwrap(),
        owner_group.current().unwrap()
    );

    assert_eq!(
        ScopeGroup::load(&store, "t-2", MemoryKeyCache::default()).map(|_: Group| ()),
        Err(GroupError::E2ee(Error::NotMember))
    );
    store.delete(SCOPE).unwrap();
    assert_eq!(store.load(SCOPE).unwrap(), None);
}

#[test]
fn key_package_store_survives_restore_and_consumes_one_time_packages() {
    let owner = Party::new();
    let runner = Party::new();
    let key_package = runner.key_package();
    let restored = Party {
        identity: runner.identity.clone(),
        key_packages: KeyPackageStore::restore(&runner.key_packages.snapshot().unwrap()).unwrap(),
    };
    let mut ds = Ds::default();
    let mut group = owner.create(HistoryPolicy::Full);
    let unit = group
        .add_members(&owner.identity, std::slice::from_ref(&key_package), None)
        .unwrap();
    let seq = ds.commit(&mut group, &unit);
    let welcome = unit.welcome.unwrap();
    restored.join(&welcome, seq);
    assert_eq!(
        ScopeGroup::join(
            &restored.key_packages,
            PROFILE,
            SCOPE,
            &welcome,
            seq,
            MemoryKeyCache::default()
        )
        .map(|_| ()),
        Err(GroupError::E2ee(Error::NotMember))
    );
}

#[test]
fn last_resort_key_package_is_reusable() {
    let runner = Party::new();
    let last_resort = runner
        .key_packages
        .generate(&runner.identity, true)
        .unwrap();
    for scope in ["t-1", "t-2"] {
        let owner = Party::new();
        let mut group: Group = ScopeGroup::create(
            &owner.identity,
            PROFILE,
            scope,
            HistoryPolicy::Full,
            MemoryKeyCache::default(),
        )
        .unwrap();
        let unit = group
            .add_members(&owner.identity, std::slice::from_ref(&last_resort), None)
            .unwrap();
        group.commit_accepted(1).unwrap();
        let joined: Group = ScopeGroup::join(
            &runner.key_packages,
            PROFILE,
            scope,
            unit.welcome.as_ref().unwrap(),
            1,
            MemoryKeyCache::default(),
        )
        .unwrap();
        assert_eq!(joined.current().unwrap(), group.current().unwrap());
    }
}

#[test]
fn welcome_for_another_scope_is_malformed() {
    let owner = Party::new();
    let runner = Party::new();
    let mut group = owner.create(HistoryPolicy::Full);
    let unit = group
        .add_members(&owner.identity, &[runner.key_package()], None)
        .unwrap();
    assert_eq!(
        ScopeGroup::join(
            &runner.key_packages,
            PROFILE,
            "t-2",
            unit.welcome.as_ref().unwrap(),
            1,
            MemoryKeyCache::default()
        )
        .map(|_| ()),
        Err(GroupError::E2ee(Error::Malformed))
    );
    assert_eq!(
        ScopeGroup::join(
            &runner.key_packages,
            PROFILE,
            SCOPE,
            &unit.commit,
            1,
            MemoryKeyCache::default()
        )
        .map(|_| ()),
        Err(GroupError::E2ee(Error::Malformed))
    );
}

#[test]
fn invalid_key_packages_are_refused() {
    let owner = Party::new();
    let mut group = owner.create(HistoryPolicy::Full);
    let mut tampered = Party::new().key_package();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        group.add_members(&owner.identity, &[tampered], None),
        Err(GroupError::E2ee(Error::Malformed))
    );
    assert_eq!(
        group.add_members(&owner.identity, &[b"junk".to_vec()], None),
        Err(GroupError::E2ee(Error::Malformed))
    );
    assert!(!group.has_pending_commit());
    assert_eq!(
        group.remove_members(&owner.identity, &[[7; 32]]),
        Err(GroupError::E2ee(Error::Malformed))
    );
}

#[test]
fn identity_round_trips_through_its_seed() {
    let identity = Identity::generate(&RustCrypto::default()).unwrap();
    let again = Identity::from_seed(&identity.seed());
    assert_eq!(again.public_key(), identity.public_key());
    assert!(!format!("{identity:?}").contains(&gino_e2ee::encode_b64url(&identity.seed())));
}

/// A KeyPackage built directly with OpenMLS, signed by `identity`.
fn raw_key_package(
    identity: &Identity,
    credential_identity: Vec<u8>,
    extensions: &[openmls::prelude::ExtensionType],
) -> Vec<u8> {
    use openmls::prelude::tls_codec::Serialize as _;
    use openmls::prelude::*;
    let provider = openmls_rust_crypto::OpenMlsRustCrypto::default();
    let capabilities = Capabilities::new(
        None,
        Some(&[gino_e2ee::CIPHERSUITE]),
        Some(extensions),
        None,
        None,
    );
    let credential = CredentialWithKey {
        credential: BasicCredential::new(credential_identity).into(),
        signature_key: identity.public_key().to_vec().into(),
    };
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(gino_e2ee::CIPHERSUITE, &provider, identity, credential)
        .unwrap();
    MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .unwrap()
}

#[test]
fn key_packages_break_the_credential_or_capability_rules() {
    use openmls::prelude::ExtensionType;
    let owner = Party::new();
    let mut group = owner.create(HistoryPolicy::Full);
    let runner = Party::new();
    let both = [
        ExtensionType::Unknown(gino_e2ee::PROFILE_EXTENSION),
        ExtensionType::Unknown(gino_e2ee::POLICY_EXTENSION),
    ];
    let foreign = raw_key_package(&runner.identity, b"runner".to_vec(), &both);
    assert_eq!(
        group.add_members(&owner.identity, &[foreign], None),
        Err(GroupError::E2ee(Error::Malformed))
    );
    let incapable = raw_key_package(
        &runner.identity,
        runner.identity.public_key().to_vec(),
        &both[1..],
    );
    assert_eq!(
        group.add_members(&owner.identity, &[incapable], None),
        Err(GroupError::E2ee(Error::Malformed))
    );
    let valid = raw_key_package(
        &runner.identity,
        runner.identity.public_key().to_vec(),
        &both,
    );
    assert!(group.add_members(&owner.identity, &[valid], None).is_ok());
}
