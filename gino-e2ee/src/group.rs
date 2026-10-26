//! The MLS group of one scope (spec §2.8, §3, §4, §7): lifecycle, commit
//! units for the DS, processing of the handshake log in `seq` order, and the
//! epoch secrets with their key cache.

use openmls::prelude::tls_codec::VLBytes;
use openmls::prelude::*;
use openmls_traits::storage::{CURRENT_VERSION, Entity, StorageProvider as _, traits};
use serde::{Deserialize, Serialize};

use crate::envelope::KEY_LEN;
use crate::history::{KeyCache, MemoryKeyCache};
use crate::identity::validate_key_package;
use crate::mls::{
    CIPHERSUITE, CONTENT_LABEL, DROP_LABEL, Provider, check_credential, create_config, deserialize,
    group_context_extensions, join_config, profile_and_policy, serialize,
};
use crate::state::{Reader, StateStore, Writer, restore_storage, snapshot_storage};
use crate::{
    DropKeyPair, EnvelopeType, EpochSecrets, Error, GroupError, Header, History, HistoryPolicy,
    Identity, KeyHistory, KeyHistoryEntry, KeyPackageStore, Location, Opened, group_id,
    seal_epoch_link, verify_drop_public_key,
};

/// The kind of a handshake log entry (spec §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// An `MLSMessage` PublicMessage commit.
    Commit,
    /// An `MLSMessage` PublicMessage proposal.
    Proposal,
    /// An `MLSMessage` PrivateMessage carrying a key-history payload.
    KeyHistory,
    /// A key-history envelope sealed to one leaf.
    KeyHistorySealed,
}

/// One entry of a scope's handshake log as served by the DS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The log position, from 1.
    pub seq: u64,
    /// The entry kind.
    pub kind: EntryKind,
    /// The epoch the entry was sent in.
    pub epoch: u64,
    /// The exact bytes.
    pub bytes: Vec<u8>,
    /// For a commit: the drop public key logged for epoch `epoch + 1`.
    pub drop_public_key: Option<Vec<u8>>,
}

/// A key-history record for the new epoch of a commit (spec §5.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyHistoryRecord {
    /// An `MLSMessage` PrivateMessage to the group (`key_history` entry).
    Message(Vec<u8>),
    /// An envelope sealed to one joiner's leaf (`key_history_sealed` entry).
    Sealed(Vec<u8>),
}

/// What the committer of an Add gives the joiners beyond the policy: the
/// cached secrets of every epoch from `from_epoch` up to the commit's epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHistoryOffer {
    /// The lowest epoch offered.
    pub from_epoch: u64,
    /// One envelope per joiner leaf instead of one MLS message to the group.
    pub sealed: bool,
}

/// A commit submitted to the DS as one unit (spec §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitUnit {
    /// The epoch the commit was sent in.
    pub epoch: u64,
    /// The `MLSMessage` PublicMessage commit.
    pub commit: Vec<u8>,
    /// The drop public key of epoch `epoch + 1`.
    pub drop_public_key: [u8; 32],
    /// The Welcome, iff the commit adds members.
    pub welcome: Option<Vec<u8>>,
    /// The epoch link for `epoch + 1`, iff the new epoch's policy calls for
    /// it.
    pub epoch_link: Option<Vec<u8>>,
    /// Key-history records for the new epoch, logged after the commit.
    pub key_history: Vec<KeyHistoryRecord>,
}

/// The effect of one applied log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The entry was already applied.
    Replayed,
    /// A commit moved the group to `epoch`, or removed this member.
    Commit { epoch: u64, self_removed: bool },
    /// A proposal was stored for the next commit.
    Proposal,
    /// Key-history entries were cached as unverified keys.
    KeyHistory,
    /// A key-history envelope for another leaf, or a record this member sent.
    Skipped,
}

/// This member's commit awaiting the DS answer: the group state as if it
/// was accepted is prepared up front, so key-history messages of the new
/// epoch can be sent with the commit.
#[derive(Debug)]
struct Pending {
    epoch: u64,
    commit: Vec<u8>,
    merged: Vec<u8>,
    secrets: EpochSecrets,
    sent: Vec<Vec<u8>>,
}

/// The MLS group of one scope.
///
/// Group state lives in an in-memory OpenMLS store that is persisted as an
/// opaque snapshot ([`ScopeGroup::snapshot`], [`ScopeGroup::save`]); the
/// epoch secrets live in the key cache `C`, which the caller persists
/// encrypted at rest. Signing operations take the party's [`Identity`].
#[derive(Debug)]
pub struct ScopeGroup<C = MemoryKeyCache> {
    provider: Provider,
    group: MlsGroup,
    profile: String,
    history: History<C>,
    seq: u64,
    pending: Option<Pending>,
    sent: Vec<Vec<u8>>,
}

impl<C: KeyCache> ScopeGroup<C> {
    /// Creates the group of `scope` at epoch 0 with `identity` as the only
    /// member (spec §2.8). `seq` 0 is applied.
    pub fn create(
        identity: &Identity,
        profile: &str,
        scope: &str,
        policy: HistoryPolicy,
        cache: C,
    ) -> Result<Self, GroupError> {
        let id = group_id(profile, scope)?;
        let provider = Provider::default();
        let config = create_config(group_context_extensions(profile, policy)?);
        let group = MlsGroup::new_with_group_id(
            &provider,
            identity,
            &config,
            GroupId::from_slice(&id),
            identity.credential(),
        )
        .map_err(|_| Error::SealFailed)?;
        let secrets = export_secrets(&group, provider.crypto(), scope)?;
        Ok(Self {
            history: History::with_cache(scope, 0, secrets, cache)?,
            provider,
            group,
            profile: profile.to_owned(),
            seq: 0,
            pending: None,
            sent: Vec::new(),
        })
    }

    /// Joins from a Welcome delivered with the `seq` of its commit (spec
    /// §3.3). The group id must match `profile` and `scope` and the group
    /// context extensions; every member credential must follow spec §2.2.
    /// A Welcome for none of the store's KeyPackages is `not_member`.
    pub fn join(
        key_packages: &KeyPackageStore,
        profile: &str,
        scope: &str,
        welcome: &[u8],
        seq: u64,
        cache: C,
    ) -> Result<Self, GroupError> {
        let MlsMessageBodyIn::Welcome(welcome) = deserialize(welcome)?.extract() else {
            return Err(Error::Malformed.into());
        };
        if welcome.ciphersuite() != CIPHERSUITE {
            return Err(Error::UnsupportedSuite.into());
        }
        let (reference, bundle) = welcome
            .secrets()
            .iter()
            .find_map(|secret| {
                let reference = secret.new_member();
                key_packages.bundle(&reference).map(|b| (reference, b))
            })
            .ok_or(Error::NotMember)?;
        let provider = Provider::default();
        provider
            .storage
            .write_key_package(&reference, &bundle)
            .map_err(|_| GroupError::Storage)?;
        let staged = StagedWelcome::new_from_welcome(&provider, &join_config(), welcome, None)
            .map_err(|_| Error::Malformed)?;
        let context = staged.group_context();
        if context.group_id().as_slice() != group_id(profile, scope)?.as_slice()
            || profile_and_policy(context.extensions())?.0 != profile
        {
            return Err(Error::Malformed.into());
        }
        for member in staged.members() {
            check_credential(&member.credential, &member.signature_key)?;
        }
        let group = staged.into_group(&provider).map_err(|_| Error::Malformed)?;
        if !bundle.key_package().last_resort() {
            key_packages.consume(&reference)?;
        }
        let secrets = export_secrets(&group, provider.crypto(), scope)?;
        let epoch = group.epoch().as_u64();
        Ok(Self {
            history: History::with_cache(scope, epoch, secrets, cache)?,
            provider,
            group,
            profile: profile.to_owned(),
            seq,
            pending: None,
            sent: Vec::new(),
        })
    }

    /// The scope id.
    pub fn scope(&self) -> &str {
        self.history.scope()
    }

    /// The profile id.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The 32-byte group id (spec §2.3).
    pub fn group_id(&self) -> &[u8] {
        self.group.group_id().as_slice()
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// The `seq` of the last applied log entry.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Whether this party still holds a leaf (false once removed).
    pub fn is_member(&self) -> bool {
        self.group.is_active()
    }

    /// Whether a commit awaits the DS answer.
    pub fn has_pending_commit(&self) -> bool {
        self.pending.is_some()
    }

    /// The history policy of the current epoch.
    pub fn policy(&self) -> Result<HistoryPolicy, GroupError> {
        Ok(profile_and_policy(self.group.extensions())?.1)
    }

    /// The Ed25519 public keys of the members, in leaf order.
    pub fn members(&self) -> Vec<Vec<u8>> {
        self.group.members().map(|m| m.signature_key).collect()
    }

    /// The history over the key cache.
    pub fn history(&self) -> &History<C> {
        &self.history
    }

    /// The current epoch and its secrets, for sealing. A removed member is
    /// `not_member`.
    pub fn current(&self) -> Result<(u64, EpochSecrets), GroupError> {
        let epoch = self.epoch();
        match self.history.cached(epoch) {
            Some(secrets) if self.is_member() => Ok((epoch, secrets)),
            _ => Err(Error::NotMember.into()),
        }
    }

    /// The drop public key of the current epoch (for the scope record).
    pub fn drop_public_key(&self) -> Result<[u8; 32], GroupError> {
        let (_, secrets) = self.current()?;
        Ok(*DropKeyPair::derive(self.provider.crypto(), &secrets.drop_seed)?.public_key())
    }

    /// The secrets of `epoch` from the cache or the backward walk over links
    /// fetched with `fetch(link_epoch)` (spec §7.3).
    pub fn secrets(
        &mut self,
        epoch: u64,
        fetch: impl FnMut(u64) -> Option<Vec<u8>>,
    ) -> Result<EpochSecrets, GroupError> {
        Ok(self.history.secrets(epoch, fetch)?)
    }

    /// Opens a content, file or drop envelope, resolving its epoch's
    /// secrets from the cache or the walk. Works after removal for epochs
    /// this member held.
    pub fn open(
        &mut self,
        envelope: &[u8],
        location: &Location,
        fetch: impl FnMut(u64) -> Option<Vec<u8>>,
    ) -> Result<Opened, GroupError> {
        Ok(self
            .history
            .open(self.provider.crypto(), envelope, location, fetch)?)
    }

    /// Commits the addition of the parties of `key_packages` (spec §2.7
    /// checks) and optionally attaches key history for them.
    pub fn add_members(
        &mut self,
        identity: &Identity,
        key_packages: &[Vec<u8>],
        offer: Option<KeyHistoryOffer>,
    ) -> Result<CommitUnit, GroupError> {
        self.ready_to_commit()?;
        let key_packages = key_packages
            .iter()
            .map(|bytes| validate_key_package(self.provider.crypto(), bytes))
            .collect::<Result<Vec<_>, _>>()?;
        let joiners: Vec<Vec<u8>> = key_packages
            .iter()
            .map(|kp| kp.leaf_node().signature_key().as_slice().to_vec())
            .collect();
        let (commit, welcome, _) = self
            .group
            .add_members(&self.provider, identity, &key_packages)
            .map_err(|_| Error::Malformed)?;
        let offer = offer.map(|offer| (offer, joiners));
        self.stage(identity, &commit, Some(&welcome), offer)
    }

    /// Commits the removal of the members with the given Ed25519 public
    /// keys. A key that is not a member is `malformed`.
    pub fn remove_members(
        &mut self,
        identity: &Identity,
        public_keys: &[[u8; 32]],
    ) -> Result<CommitUnit, GroupError> {
        self.ready_to_commit()?;
        let leaves = public_keys
            .iter()
            .map(|key| {
                self.group
                    .members()
                    .find(|m| m.signature_key == key)
                    .map(|m| m.index)
                    .ok_or(Error::Malformed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (commit, welcome, _) = self
            .group
            .remove_members(&self.provider, identity, &leaves)
            .map_err(|_| Error::Malformed)?;
        self.stage(identity, &commit, welcome.as_ref(), None)
    }

    /// Commits an Update of this member's own leaf.
    pub fn self_update(&mut self, identity: &Identity) -> Result<CommitUnit, GroupError> {
        self.ready_to_commit()?;
        let (commit, _, _) = self
            .group
            .self_update(&self.provider, identity, LeafNodeParameters::default())
            .map_err(|_| Error::SealFailed)?
            .into_contents();
        self.stage(identity, &commit, None, None)
    }

    /// Commits a new history policy (a GroupContextExtensions proposal that
    /// repeats the profile id and the required capabilities).
    pub fn set_policy(
        &mut self,
        identity: &Identity,
        policy: HistoryPolicy,
    ) -> Result<CommitUnit, GroupError> {
        self.ready_to_commit()?;
        let extensions = group_context_extensions(&self.profile, policy)?;
        let (commit, welcome, _) = self
            .group
            .update_group_context_extensions(&self.provider, extensions, identity)
            .map_err(|_| Error::Malformed)?;
        self.stage(identity, &commit, welcome.as_ref(), None)
    }

    /// The DS accepted the pending commit at `seq`: this member moves to the
    /// new epoch. `seq` must follow the last applied entry.
    pub fn commit_accepted(&mut self, seq: u64) -> Result<(), GroupError> {
        let expected = self.seq + 1;
        if self.pending.is_none() {
            return Err(GroupError::NoPendingCommit);
        }
        if seq != expected {
            return Err(GroupError::Gap { expected, got: seq });
        }
        self.install_pending()?;
        self.seq = seq;
        Ok(())
    }

    /// The DS rejected the pending commit (another commit won the epoch):
    /// it is discarded; catch up on the log and commit again.
    pub fn commit_rejected(&mut self) -> Result<(), GroupError> {
        if self.pending.take().is_none() {
            return Err(GroupError::NoPendingCommit);
        }
        self.group
            .clear_pending_commit(&self.provider.storage)
            .map_err(|_| GroupError::Storage)
    }

    /// Applies the next log entry. Entries at or below the last applied
    /// `seq` are replays and change nothing; a later `seq` than the next one
    /// is a [`GroupError::Gap`]. An entry of a later epoch is
    /// `epoch_unknown`, of an earlier one `malformed`.
    ///
    /// A commit whose logged drop public key differs from the derived one is
    /// applied, then reported as `drop_key_mismatch`. A commit of another
    /// member at the epoch of this member's pending commit discards the
    /// pending one; this member's own commit settles it as accepted.
    pub fn apply(&mut self, entry: &LogEntry) -> Result<Applied, GroupError> {
        let expected = self.seq + 1;
        if entry.seq < expected {
            return Ok(Applied::Replayed);
        }
        if entry.seq > expected {
            return Err(GroupError::Gap {
                expected,
                got: entry.seq,
            });
        }
        if !self.is_member() {
            return Err(Error::NotMember.into());
        }
        let current = self.epoch();
        if entry.epoch > current {
            return Err(Error::EpochUnknown { epoch: entry.epoch }.into());
        }
        if entry.epoch < current {
            return Err(Error::Malformed.into());
        }
        let (applied, mismatch) = match entry.kind {
            EntryKind::Commit => self.apply_commit(entry)?,
            EntryKind::Proposal => (self.apply_proposal(&entry.bytes)?, None),
            EntryKind::KeyHistory => (self.apply_key_history(&entry.bytes)?, None),
            EntryKind::KeyHistorySealed => (self.apply_key_history_sealed(&entry.bytes)?, None),
        };
        self.seq = entry.seq;
        match mismatch {
            Some(error) => Err(error.into()),
            None => Ok(applied),
        }
    }

    /// The group state (without the key cache) as opaque bytes.
    pub fn snapshot(&self) -> Result<Vec<u8>, GroupError> {
        let mut writer = Writer::default();
        writer.bytes(self.profile.as_bytes())?;
        writer.bytes(self.scope().as_bytes())?;
        writer.u64(self.seq);
        writer.bytes(&snapshot_storage(&self.provider.storage)?)?;
        writer.u64(self.sent.len() as u64);
        for record in &self.sent {
            writer.bytes(record)?;
        }
        match &self.pending {
            None => writer.u64(0),
            Some(pending) => {
                writer.u64(1);
                writer.u64(pending.epoch);
                writer.bytes(&pending.commit)?;
                writer.bytes(&pending.merged)?;
                writer.bytes(&pending.secrets.content_key)?;
                writer.bytes(&pending.secrets.drop_seed)?;
                writer.u64(pending.sent.len() as u64);
                for record in &pending.sent {
                    writer.bytes(record)?;
                }
            }
        }
        Ok(writer.finish())
    }

    /// A group from [`ScopeGroup::snapshot`] bytes and its key cache. For a
    /// removed member the cache must hold the secrets of its last epoch.
    pub fn restore(snapshot: &[u8], cache: C) -> Result<Self, GroupError> {
        let mut reader = Reader::new(snapshot);
        let profile = reader.string()?;
        let scope = reader.string()?;
        let seq = reader.u64()?;
        let provider = Provider::default();
        restore_storage(&provider.storage, &reader.bytes()?)?;
        let sent = read_list(&mut reader)?;
        let pending = match reader.u64()? {
            0 => None,
            1 => Some(Pending {
                epoch: reader.u64()?,
                commit: reader.bytes()?,
                merged: reader.bytes()?,
                secrets: EpochSecrets {
                    content_key: key(&reader.bytes()?)?,
                    drop_seed: key(&reader.bytes()?)?,
                },
                sent: read_list(&mut reader)?,
            }),
            _ => return Err(GroupError::Storage),
        };
        reader.finish()?;
        let id = group_id(&profile, &scope)?;
        let group = load_group(&provider, &id)?;
        let epoch = group.epoch().as_u64();
        let secrets = if group.is_active() {
            export_secrets(&group, provider.crypto(), &scope)?
        } else {
            cache
                .get(epoch)
                .map(|held| held.secrets)
                .ok_or(Error::NotMember)?
        };
        Ok(Self {
            history: History::with_cache(&scope, epoch, secrets, cache)?,
            provider,
            group,
            profile,
            seq,
            pending,
            sent,
        })
    }

    /// Saves [`ScopeGroup::snapshot`] under the scope id.
    pub fn save(&self, store: &mut impl StateStore) -> Result<(), GroupError> {
        store.save(self.scope(), self.snapshot()?)
    }

    /// Loads the group of `scope` saved with [`ScopeGroup::save`]; an
    /// absent one is `not_member`.
    pub fn load(store: &impl StateStore, scope: &str, cache: C) -> Result<Self, GroupError> {
        let snapshot = store.load(scope)?.ok_or(Error::NotMember)?;
        Self::restore(&snapshot, cache)
    }

    fn ready_to_commit(&self) -> Result<(), GroupError> {
        if !self.is_member() {
            return Err(Error::NotMember.into());
        }
        if self.pending.is_some() {
            return Err(GroupError::CommitPending);
        }
        Ok(())
    }

    /// Builds the commit unit of the commit OpenMLS just staged. The state
    /// after the commit is prepared on the store (to derive the new epoch's
    /// secrets and send key-history messages in it) and kept aside; the
    /// group returns to the pending commit until the DS answers.
    fn stage(
        &mut self,
        identity: &Identity,
        commit: &MlsMessageOut,
        welcome: Option<&MlsMessageOut>,
        offer: Option<(KeyHistoryOffer, Vec<Vec<u8>>)>,
    ) -> Result<CommitUnit, GroupError> {
        let epoch = self.epoch();
        let pending_state = snapshot_storage(&self.provider.storage)?;
        let prepared = self.prepare(identity, epoch, offer);
        let merged = snapshot_storage(&self.provider.storage);
        restore_storage(&self.provider.storage, &pending_state)?;
        self.group = load_group(&self.provider, self.group_id())?;
        let unit = prepared.and_then(|(secrets, policy, key_history)| {
            self.unit(epoch, commit, welcome, &secrets, policy, key_history)
                .map(|unit| (unit, secrets))
        });
        match (unit, merged) {
            (Ok((unit, secrets)), Ok(merged)) => {
                self.pending = Some(Pending {
                    epoch,
                    commit: unit.commit.clone(),
                    merged,
                    secrets,
                    sent: unit
                        .key_history
                        .iter()
                        .map(|record| match record {
                            KeyHistoryRecord::Message(bytes) | KeyHistoryRecord::Sealed(bytes) => {
                                bytes.clone()
                            }
                        })
                        .collect(),
                });
                Ok(unit)
            }
            (Err(error), _) | (_, Err(error)) => {
                self.group
                    .clear_pending_commit(&self.provider.storage)
                    .map_err(|_| GroupError::Storage)?;
                Err(error)
            }
        }
    }

    /// Merges the pending commit and derives what the new epoch needs: its
    /// secrets, its history policy and the offered key-history records.
    /// Leaves the store in the merged state.
    fn prepare(
        &mut self,
        identity: &Identity,
        epoch: u64,
        offer: Option<(KeyHistoryOffer, Vec<Vec<u8>>)>,
    ) -> Result<(EpochSecrets, HistoryPolicy, Vec<KeyHistoryRecord>), GroupError> {
        let staged = self.group.pending_commit().ok_or(Error::SealFailed)?;
        let policy = profile_and_policy(staged.group_context().extensions())?.1;
        self.group
            .merge_pending_commit(&self.provider)
            .map_err(|_| Error::SealFailed)?;
        let secrets = export_secrets(&self.group, self.provider.crypto(), self.scope())?;
        let Some((offer, joiners)) = offer else {
            return Ok((secrets, policy, Vec::new()));
        };
        let entries: Vec<KeyHistoryEntry> = (offer.from_epoch..=epoch)
            .filter_map(|e| {
                self.history
                    .cached(e)
                    .map(|secrets| KeyHistoryEntry { epoch: e, secrets })
            })
            .collect();
        if entries.is_empty() {
            return Ok((secrets, policy, Vec::new()));
        }
        let history = KeyHistory {
            epoch: epoch + 1,
            entries,
        };
        let mut records = Vec::new();
        if offer.sealed {
            for joiner in &joiners {
                let member = self
                    .group
                    .members()
                    .find(|m| &m.signature_key == joiner)
                    .ok_or(Error::SealFailed)?;
                records.push(KeyHistoryRecord::Sealed(history.seal_to_leaf(
                    self.provider.crypto(),
                    self.scope(),
                    member.index.u32(),
                    &member.encryption_key,
                )?));
            }
        } else {
            let message = self
                .group
                .create_message(&self.provider, identity, &history.encode()?)
                .map_err(|_| Error::SealFailed)?;
            records.push(KeyHistoryRecord::Message(serialize(&message)?));
        }
        Ok((secrets, policy, records))
    }

    /// The commit unit for a commit sent in `epoch` that leads to `secrets`.
    fn unit(
        &self,
        epoch: u64,
        commit: &MlsMessageOut,
        welcome: Option<&MlsMessageOut>,
        secrets: &EpochSecrets,
        policy: HistoryPolicy,
        key_history: Vec<KeyHistoryRecord>,
    ) -> Result<CommitUnit, GroupError> {
        let epoch_link = if policy.links_transition(epoch) {
            let current = self.history.cached(epoch).ok_or(Error::SealFailed)?;
            Some(seal_epoch_link(
                self.scope(),
                epoch,
                &current,
                &secrets.content_key,
                self.provider.rand(),
            )?)
        } else {
            None
        };
        let drop_pair = DropKeyPair::derive(self.provider.crypto(), &secrets.drop_seed)?;
        Ok(CommitUnit {
            epoch,
            commit: serialize(commit)?,
            drop_public_key: *drop_pair.public_key(),
            welcome: welcome.map(serialize).transpose()?,
            epoch_link,
            key_history,
        })
    }

    /// Moves to the state prepared for the pending commit.
    fn install_pending(&mut self) -> Result<Applied, GroupError> {
        let pending = self.pending.take().ok_or(GroupError::NoPendingCommit)?;
        restore_storage(&self.provider.storage, &pending.merged)?;
        self.group = load_group(&self.provider, self.group_id())?;
        self.history.advance(pending.secrets)?;
        self.sent = pending.sent;
        Ok(Applied::Commit {
            epoch: pending.epoch + 1,
            self_removed: false,
        })
    }

    fn apply_commit(&mut self, entry: &LogEntry) -> Result<(Applied, Option<Error>), GroupError> {
        if let Some(pending) = &self.pending {
            if pending.commit == entry.bytes {
                return Ok((self.install_pending()?, None));
            }
            self.commit_rejected()?;
        }
        let message = self.handshake_message(&entry.bytes, ContentType::Commit)?;
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(|_| Error::Malformed)?;
        if !matches!(processed.sender(), Sender::Member(_)) {
            return Err(Error::Malformed.into());
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(Error::Malformed.into());
        };
        for add in staged.add_proposals() {
            let leaf = add.add_proposal().key_package().leaf_node();
            check_credential(leaf.credential(), leaf.signature_key().as_slice())?;
        }
        for update in staged.update_proposals() {
            let leaf = update.update_proposal().leaf_node();
            check_credential(leaf.credential(), leaf.signature_key().as_slice())?;
        }
        if let Some(leaf) = staged.update_path_leaf_node() {
            check_credential(leaf.credential(), leaf.signature_key().as_slice())?;
        }
        if profile_and_policy(staged.group_context().extensions())?.0 != self.profile {
            return Err(Error::Malformed.into());
        }
        let self_removed = staged.self_removed();
        let next = if self_removed {
            None
        } else {
            Some(staged_secrets(
                &staged,
                self.provider.crypto(),
                self.scope(),
            )?)
        };
        self.group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(|_| Error::Malformed)?;
        self.sent.clear();
        let epoch = self.epoch();
        let mut mismatch = None;
        if let Some(next) = next {
            if let Some(logged) = &entry.drop_public_key {
                mismatch =
                    verify_drop_public_key(self.provider.crypto(), &next.drop_seed, epoch, logged)
                        .err();
            }
            self.history.advance(next)?;
        }
        Ok((
            Applied::Commit {
                epoch,
                self_removed,
            },
            mismatch,
        ))
    }

    fn apply_proposal(&mut self, bytes: &[u8]) -> Result<Applied, GroupError> {
        let message = self.handshake_message(bytes, ContentType::Proposal)?;
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(|_| Error::Malformed)?;
        let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
            return Err(Error::Malformed.into());
        };
        self.group
            .store_pending_proposal(&self.provider.storage, *proposal)
            .map_err(|_| GroupError::Storage)?;
        Ok(Applied::Proposal)
    }

    fn apply_key_history(&mut self, bytes: &[u8]) -> Result<Applied, GroupError> {
        if self.sent.iter().any(|sent| sent == bytes) {
            return Ok(Applied::Skipped);
        }
        let message = deserialize(bytes)?
            .try_into_protocol_message()
            .map_err(|_| Error::Malformed)?;
        if message.wire_format() != WireFormat::PrivateMessage
            || message.group_id() != self.group.group_id()
        {
            return Err(Error::Malformed.into());
        }
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(|_| Error::Malformed)?;
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            return Err(Error::Malformed.into());
        };
        let history = KeyHistory::decode(&message.into_bytes())?;
        if history.epoch != self.epoch() {
            return Err(Error::LinkInvalid {
                epoch: history.epoch,
            }
            .into());
        }
        self.history.add_key_history(&history);
        Ok(Applied::KeyHistory)
    }

    fn apply_key_history_sealed(&mut self, bytes: &[u8]) -> Result<Applied, GroupError> {
        if self.sent.iter().any(|sent| sent == bytes) {
            return Ok(Applied::Skipped);
        }
        let header = Header::parse_as(bytes, EnvelopeType::KeyHistorySealed)?;
        if header.epoch != self.epoch() {
            return Err(Error::Malformed.into());
        }
        let leaf_index = bytes
            .get(crate::HEADER_LEN..)
            .and_then(|rest| rest.first_chunk::<4>())
            .map(|index| u32::from_be_bytes(*index))
            .ok_or(Error::Malformed)?;
        if leaf_index != self.group.own_leaf_index().u32() {
            return Ok(Applied::Skipped);
        }
        let leaf_sk = self.own_leaf_private_key()?;
        let history = KeyHistory::open_sealed(
            self.provider.crypto(),
            self.scope(),
            leaf_index,
            &leaf_sk,
            bytes,
        )?;
        self.history.add_key_history(&history);
        Ok(Applied::KeyHistory)
    }

    /// The private HPKE key of this member's leaf in the current epoch, read
    /// from the OpenMLS store (the epoch key pairs, or the key pair of an
    /// own Update).
    fn own_leaf_private_key(&self) -> Result<Vec<u8>, GroupError> {
        let index = self.group.own_leaf_index();
        let public = self
            .group
            .members()
            .find(|m| m.index == index)
            .map(|m| m.encryption_key)
            .ok_or(Error::NotMember)?;
        let storage = &self.provider.storage;
        let pairs: Vec<LeafKeyPair> = storage
            .encryption_epoch_key_pairs(self.group.group_id(), &self.group.epoch(), index.u32())
            .map_err(|_| GroupError::Storage)?;
        let pair = match pairs
            .into_iter()
            .find(|pair| pair.public_key.key.as_slice() == public)
        {
            Some(pair) => Some(pair),
            None => storage
                .encryption_key_pair::<LeafKeyPair, _>(&openmls::treesync::EncryptionKey::from(
                    public,
                ))
                .map_err(|_| GroupError::Storage)?,
        };
        let pair = pair.ok_or(Error::OpenFailed {
            epoch: self.epoch(),
        })?;
        Ok(pair.private_key.key.to_vec())
    }

    /// Parses a handshake log entry: a PublicMessage of `content_type` in
    /// this group (spec §2.6, §3.2).
    fn handshake_message(
        &self,
        bytes: &[u8],
        content_type: ContentType,
    ) -> Result<ProtocolMessage, GroupError> {
        let message = deserialize(bytes)?
            .try_into_protocol_message()
            .map_err(|_| Error::Malformed)?;
        if message.wire_format() != WireFormat::PublicMessage
            || message.content_type() != content_type
            || message.group_id() != self.group.group_id()
        {
            return Err(Error::Malformed.into());
        }
        Ok(message)
    }
}

/// The serde form of OpenMLS's leaf `EncryptionKeyPair`, read back from the
/// store through the public `StorageProvider` lookups.
#[derive(Serialize, Deserialize)]
struct LeafKeyPair {
    public_key: LeafKey<VLBytes>,
    private_key: LeafKey<openmls_traits::types::HpkePrivateKey>,
}

#[derive(Serialize, Deserialize)]
struct LeafKey<K> {
    key: K,
}

impl Entity<CURRENT_VERSION> for LeafKeyPair {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for LeafKeyPair {}

fn load_group(provider: &Provider, id: &[u8]) -> Result<MlsGroup, GroupError> {
    MlsGroup::load(&provider.storage, &GroupId::from_slice(id))
        .map_err(|_| GroupError::Storage)?
        .ok_or(GroupError::Storage)
}

fn export_secrets(
    group: &MlsGroup,
    crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
    scope: &str,
) -> Result<EpochSecrets, Error> {
    let export = |label| {
        group
            .export_secret(crypto, label, scope.as_bytes(), KEY_LEN)
            .map_err(|_| Error::NotMember)
            .and_then(|secret| key(&secret).map_err(|_| Error::SealFailed))
    };
    Ok(EpochSecrets {
        content_key: export(CONTENT_LABEL)?,
        drop_seed: export(DROP_LABEL)?,
    })
}

fn staged_secrets(
    staged: &StagedCommit,
    crypto: &impl openmls_traits::crypto::OpenMlsCrypto,
    scope: &str,
) -> Result<EpochSecrets, Error> {
    let export = |label| {
        staged
            .export_secret(crypto, label, scope.as_bytes(), KEY_LEN)
            .map_err(|_| Error::Malformed)
            .and_then(|secret| key(&secret).map_err(|_| Error::Malformed))
    };
    Ok(EpochSecrets {
        content_key: export(CONTENT_LABEL)?,
        drop_seed: export(DROP_LABEL)?,
    })
}

fn key(bytes: &[u8]) -> Result<[u8; KEY_LEN], GroupError> {
    bytes.try_into().map_err(|_| GroupError::Storage)
}

fn read_list(reader: &mut Reader<'_>) -> Result<Vec<Vec<u8>>, GroupError> {
    let count = reader.u64()?;
    (0..count).map(|_| reader.bytes()).collect()
}
