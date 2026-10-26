//! Per-task MLS group state (task-content §4.1, spec §3, §7, §8).
//!
//! The runner never commits: its group advances only by the DS log, applied
//! strictly in `seq` order. Out-of-order records wait in `e2ee_log_pending`; a
//! gap, a socket open or content of a newer epoch triggers a catch-up read.
//! Older content opens through the epoch-link walk, whose recovered secrets
//! stay in the persistent key cache. Every state change is persisted sealed at
//! rest before it counts. Opening and sealing fail closed with a spec §11 code.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{
    Applied, EntryKind, EnvelopeType, EpochSecrets, Error, FileDigest, GroupError, Header,
    Location, LogEntry, Opened, ScopeGroup, decode_b64url, encode_b64url,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::Value;
use thiserror::Error as ThisError;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tracing::{debug, info, warn};

use super::cache::DbKeyCache;
use super::key_packages::KeyPackagePool;
use super::{E2ee, KEY_PACKAGES_LABEL, SealError, lock};
use crate::db::{Db, DbError, E2eeGroupRow, E2eeKeyPackagesRow, E2eeLogPendingRow, TaskE2eeRow};
use crate::protocol::frames::{
    E2eeLogData, E2eeRequestData, E2eeResponseData, E2eeWelcomeData, EncryptionError, TaskE2ee,
};
use crate::scheduler::to_iso;

/// The only e2ee profile this runner implements.
pub(crate) const PROFILE: &str = "gino.task-content.v1";
/// Bound of one DS request (waiting for a socket included).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound of the wait for a task's group to be ready (outstanding catch-up).
const READY_TIMEOUT: Duration = Duration::from_secs(30);

const REMOVED: &str = "the runner was removed from the task's group";
const NO_GROUP: &str = "no group state for this task; re-add this runner";
const NOT_CAUGHT_UP: &str = "the task's group could not catch up with the DS";

type Group = ScopeGroup<DbKeyCache>;

/// The at-rest label of a task's group snapshot.
fn snapshot_label(task_id: &str) -> String {
    format!("e2ee_group:{task_id}")
}

/// A failed open or seal: the spec §11 failure and a short diagnostic. Never
/// carries plaintext, AAD values or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptionFailure {
    pub(crate) error: Error,
    pub(crate) message: Option<&'static str>,
}

impl EncryptionFailure {
    fn new(error: Error, message: &'static str) -> Self {
        Self {
            error,
            message: Some(message),
        }
    }

    /// The spec §11 code.
    pub(crate) fn code(&self) -> &'static str {
        self.error.code()
    }

    /// The epoch involved, for the codes that carry one.
    pub(crate) fn epoch(&self) -> Option<u64> {
        self.error.epoch()
    }

    /// The `thread_result.data.encryption_error` object.
    pub(crate) fn to_encryption_error(self) -> EncryptionError {
        EncryptionError {
            code: self.code().to_owned(),
            epoch: self.epoch(),
            message: self.message.map(str::to_owned),
        }
    }
}

impl From<Error> for EncryptionFailure {
    fn from(error: Error) -> Self {
        Self {
            error,
            message: None,
        }
    }
}

impl std::fmt::Display for EncryptionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.message {
            Some(message) => write!(f, "{}: {message}", self.error),
            None => write!(f, "{}", self.error),
        }
    }
}

impl std::error::Error for EncryptionFailure {}

/// A task's group state, for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupStatus {
    /// No group state (a plaintext task, or nothing received yet).
    None,
    /// Encrypted, waiting for a Welcome.
    Pending,
    /// A member of the task's group.
    Member,
    /// Removed from the task's group.
    Removed,
    /// Unusable: a group id or profile the runner refuses, or a snapshot that
    /// does not load.
    Lost,
}

impl GroupStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pending => "pending",
            Self::Member => "member",
            Self::Removed => "removed",
            Self::Lost => "lost",
        }
    }

    fn parse(status: &str) -> Self {
        match status {
            "pending" => Self::Pending,
            "member" => Self::Member,
            "removed" => Self::Removed,
            _ => Self::Lost,
        }
    }
}

/// Persisting e2ee state failed.
#[derive(Debug, ThisError)]
pub(super) enum StoreError {
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Seal(#[from] SealError),
    #[error("e2ee state does not encode")]
    Encode,
}

/// Bounds of the DS requests and of the wait for a ready group.
#[derive(Debug, Clone, Copy)]
pub(super) struct Timeouts {
    pub(super) request: Duration,
    pub(super) ready: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            request: REQUEST_TIMEOUT,
            ready: READY_TIMEOUT,
        }
    }
}

/// One task's loaded group state.
#[derive(Debug, Default)]
pub(super) struct Slot {
    loaded: bool,
    group: Option<Group>,
    /// The socket generation the last catch-up completed on.
    caught_up: Option<u64>,
}

/// A task's slot and its current epoch, readable without the slot lock.
#[derive(Debug, Default)]
pub(super) struct SlotHandle {
    state: Arc<AsyncMutex<Slot>>,
    epoch: AtomicU64,
}

/// The loaded group state of every task touched so far.
pub(super) type Groups = std::sync::Mutex<HashMap<String, Arc<SlotHandle>>>;

/// What applying the buffered records ended on.
enum Drain {
    Done,
    Gap,
}

/// The profile's field map for a task's recorded e2ee marker; an unsupported
/// profile or a group id that is not the task's derivation refuses.
fn check_task(task_id: &str, task: &TaskE2eeRow) -> Result<&'static FieldMap, EncryptionFailure> {
    if task.profile_id != PROFILE {
        return Err(EncryptionFailure::new(
            Error::UnsupportedVersion,
            "the task's e2ee profile is not supported",
        ));
    }
    let derived = gino_e2ee::group_id(PROFILE, task_id)
        .map(|id| encode_b64url(&id))
        .map_err(|error| EncryptionFailure::new(error, "the task id forms no group id"))?;
    if derived != task.group_id {
        return Err(EncryptionFailure::new(
            Error::NotMember,
            "the task's group id does not match its derivation",
        ));
    }
    FieldMap::for_profile(PROFILE).ok_or(EncryptionFailure::new(
        Error::UnsupportedVersion,
        "no field map for the task's profile",
    ))
}

/// Whether `map` declares the host-action `method` (task-content §2.1): a key
/// of the `keyed_plain` table of the `thread_message` rule at
/// `data.input.params`. A map without that rule declares nothing.
pub(crate) fn host_action_declared(map: &FieldMap, method: &str) -> bool {
    map.frame("thread_message")
        .into_iter()
        .flat_map(|frame| frame.fields)
        .filter(|rule| rule.path == "data.input.params")
        .filter_map(|rule| rule.keyed_plain)
        .any(|keyed| keyed.table.iter().any(|(declared, _)| *declared == method))
}

/// Whether an encrypted task of `profile` may carry the host-action `method`;
/// an unknown profile declares nothing.
pub(crate) fn host_action_allowed(profile: &str, method: &str) -> bool {
    FieldMap::for_profile(profile).is_some_and(|map| host_action_declared(map, method))
}

/// Record a `task_upsert`'s `data.e2ee` on the task row. Once set it is never
/// changed or cleared; a later different value is logged and ignored. A
/// profile or group id the runner refuses marks the task's group state `lost`.
pub(crate) fn record_task_e2ee(db: &Db, task_id: &str, e2ee: &TaskE2ee) -> bool {
    if let Ok(Some(stored)) = db.get_task_e2ee(task_id)
        && (stored.profile_id != e2ee.profile_id || stored.group_id != e2ee.group_id)
    {
        warn!(task = %task_id, "task_upsert e2ee differs from the recorded value; keeping the recorded one");
    }
    let recorded = db
        .set_task_e2ee(task_id, &e2ee.profile_id, &e2ee.group_id)
        .and_then(|()| db.get_task_e2ee(task_id));
    let task = match recorded {
        Ok(Some(task)) => task,
        Ok(None) => return true,
        Err(err) => {
            warn!(task = %task_id, error = %err, "failed to persist task e2ee");
            return false;
        }
    };
    let status = match check_task(task_id, &task) {
        Ok(_) => GroupStatus::Pending,
        Err(failure) => {
            warn!(
                task = %task_id,
                profile = %task.profile_id,
                code = failure.code(),
                "{failure}; the task's content cannot be opened or sealed"
            );
            GroupStatus::Lost
        }
    };
    let created = db.get_e2ee_group(task_id).and_then(|row| match row {
        Some(_) => Ok(()),
        None => db.put_e2ee_group(&E2eeGroupRow {
            task_id: task_id.to_owned(),
            group_id: task.group_id.clone(),
            profile_id: task.profile_id.clone(),
            snapshot: None,
            last_seq: None,
            status: status.as_str().to_owned(),
            updated_at: String::new(),
        }),
    });
    match created {
        Ok(()) => true,
        Err(err) => {
            warn!(task = %task_id, error = %err, "failed to persist the task's e2ee group row");
            false
        }
    }
}

/// Whether the agent DB records the runner as a member of any task group. A
/// DB failure reads as a member.
pub(crate) fn holds_encrypted_scope(db: &Db) -> bool {
    match db.list_e2ee_groups() {
        Ok(rows) => rows
            .iter()
            .any(|row| row.status == GroupStatus::Member.as_str()),
        Err(_) => true,
    }
}

/// A log record as a [`LogEntry`].
fn log_entry(data: &E2eeLogData) -> Result<LogEntry, EncryptionFailure> {
    let kind = match data.kind.as_str() {
        "commit" => EntryKind::Commit,
        "proposal" => EntryKind::Proposal,
        "key_history" => EntryKind::KeyHistory,
        "key_history_sealed" => EntryKind::KeyHistorySealed,
        _ => {
            return Err(EncryptionFailure::new(
                Error::Malformed,
                "unknown log entry kind",
            ));
        }
    };
    Ok(LogEntry {
        seq: data.seq,
        kind,
        epoch: data.epoch,
        bytes: decode_b64url(&data.message)?,
        drop_public_key: data
            .drop_public_key
            .as_deref()
            .map(decode_b64url)
            .transpose()?,
    })
}

fn to_error(error: &GroupError) -> Error {
    error.encryption_error().unwrap_or(Error::Malformed)
}

/// The location of attachment bytes (task-content §3).
fn file_location(task_id: &str) -> Result<Location, Error> {
    Location::new(task_id)?.part("field", "file")
}

fn open_envelope(
    group: &mut Group,
    envelope: &[u8],
    location: &Location,
    fetch: &mut dyn FnMut(u64) -> Option<Vec<u8>>,
) -> Result<Opened, Error> {
    group
        .open(envelope, location, fetch)
        .map_err(|error| to_error(&error))
}

fn log_failure(task_id: &str, action: &str, failure: &EncryptionFailure) {
    warn!(
        task = %task_id,
        code = failure.code(),
        epoch = ?failure.epoch(),
        "e2ee {action} failed"
    );
}

/// The current epoch and its secrets, for sealing.
fn current(slot: &Slot) -> Result<(u64, EpochSecrets), EncryptionFailure> {
    let group = slot
        .group
        .as_ref()
        .ok_or(EncryptionFailure::new(Error::NotMember, NO_GROUP))?;
    group
        .current()
        .map_err(|error| EncryptionFailure::new(to_error(&error), REMOVED))
}

/// Seals frames of one encrypted task under the epoch that was current when
/// it was made, synchronously (inside a DB transaction).
pub(crate) struct Sealer {
    task_id: String,
    map: &'static FieldMap,
    epoch: u64,
    secrets: EpochSecrets,
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealer")
            .field("task_id", &self.task_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Sealer {
    /// Seal every mapped field of `frame` (the whole frame, of type
    /// `frame_type`) in place, all or nothing. The cleartext ids its
    /// locations reference must already be in the frame.
    pub(crate) fn seal_frame(
        &self,
        frame_type: &str,
        frame: &mut Value,
    ) -> Result<(), EncryptionFailure> {
        let sealed = self
            .map
            .seal_frame(
                frame_type,
                frame,
                self.epoch,
                &self.secrets.content_key,
                &RustCrypto::default(),
            )
            .map_err(EncryptionFailure::from)
            .inspect_err(|failure| log_failure(&self.task_id, "seal", failure))?;
        *frame = sealed;
        Ok(())
    }
}

impl E2ee {
    /// Whether `task_id` is end-to-end encrypted (its task row), whatever its
    /// group state. A DB failure reads as encrypted.
    pub(crate) fn is_encrypted(&self, task_id: &str) -> bool {
        !matches!(lock(&self.db).get_task_e2ee(task_id), Ok(None))
    }

    /// Whether the runner is a member of any task group (remote operations
    /// are refused while it is). A DB failure reads as a member.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "called by the inbound and outbound paths")
    )]
    pub(crate) fn holds_encrypted_scope(&self) -> bool {
        holds_encrypted_scope(&lock(&self.db))
    }

    /// A task's group state, for diagnostics.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "called by the inbound and outbound paths")
    )]
    pub(crate) fn group_status(&self, task_id: &str) -> GroupStatus {
        let db = lock(&self.db);
        if let Ok(Some(task)) = db.get_task_e2ee(task_id)
            && check_task(task_id, &task).is_err()
        {
            return GroupStatus::Lost;
        }
        match db.get_e2ee_group(task_id) {
            Ok(Some(row)) => GroupStatus::parse(&row.status),
            Ok(None) => GroupStatus::None,
            Err(_) => GroupStatus::Lost,
        }
    }

    /// Open every mapped field of `frame` (the whole frame, of type
    /// `frame_type`) in place, all or nothing. A plaintext task's frame is
    /// left as it is; on an encrypted task a plaintext mapped field is
    /// `plaintext_rejected`.
    pub(crate) async fn open_frame(
        &self,
        task_id: &str,
        frame_type: &str,
        frame: &mut Value,
    ) -> Result<(), EncryptionFailure> {
        let Some(map) = self.field_map(task_id)? else {
            return Ok(());
        };
        if map.frame(frame_type).is_none() {
            return Ok(());
        }
        let opened = async {
            let (handle, mut slot) = self.ready(task_id).await?;
            let input = &*frame;
            self.open_with(task_id, &handle, &mut slot, |group, fetch| {
                map.open_frame(frame_type, input, |envelope, location| {
                    open_envelope(group, envelope, location, fetch)
                })
            })
            .await
        }
        .await;
        let opened = opened.inspect_err(|failure| log_failure(task_id, "open", failure))?;
        *frame = opened;
        Ok(())
    }

    /// Seal every mapped field of `frame` in place under the current epoch's
    /// content key. The cleartext ids its locations reference must already
    /// be in the frame. A plaintext task's frame is left as it is.
    pub(crate) async fn seal_frame(
        &self,
        task_id: &str,
        frame_type: &str,
        frame: &mut Value,
    ) -> Result<(), EncryptionFailure> {
        match self.sealer(task_id).await? {
            Some(sealer) => sealer.seal_frame(frame_type, frame),
            None => Ok(()),
        }
    }

    /// A [`Sealer`] under the current epoch of an encrypted task, once its
    /// group is ready; `None` for a plaintext task.
    pub(crate) async fn sealer(&self, task_id: &str) -> Result<Option<Sealer>, EncryptionFailure> {
        let Some(map) = self.field_map(task_id)? else {
            return Ok(None);
        };
        let current = async {
            let (_, slot) = self.ready(task_id).await?;
            current(&slot)
        }
        .await;
        let (epoch, secrets) =
            current.inspect_err(|failure| log_failure(task_id, "seal", failure))?;
        Ok(Some(Sealer {
            task_id: task_id.to_owned(),
            map,
            epoch,
            secrets,
        }))
    }

    /// Seal attachment bytes as a file envelope of an encrypted task (spec
    /// §5.4); returns the envelope and its descriptor digest.
    pub(crate) async fn seal_file(
        &self,
        task_id: &str,
        bytes: &[u8],
    ) -> Result<(Vec<u8>, FileDigest), EncryptionFailure> {
        let sealed = async {
            self.encrypted_task(task_id)?;
            let (_, slot) = self.ready(task_id).await?;
            let (epoch, secrets) = current(&slot)?;
            let sealed = gino_e2ee::seal_file(
                &secrets.content_key,
                epoch,
                &file_location(task_id)?,
                bytes,
                &RustCrypto::default(),
            )?;
            Ok((sealed.envelope, sealed.digest))
        }
        .await;
        sealed.inspect_err(|failure| log_failure(task_id, "seal", failure))
    }

    /// Open a file envelope of an encrypted task whose descriptor gave
    /// `digest`.
    pub(crate) async fn open_file(
        &self,
        task_id: &str,
        envelope: &[u8],
        digest: &FileDigest,
    ) -> Result<Vec<u8>, EncryptionFailure> {
        let opened = async {
            self.encrypted_task(task_id)?;
            if FileDigest::of(envelope) != *digest {
                return Err(EncryptionFailure::new(
                    Error::Malformed,
                    "the file does not match its descriptor",
                ));
            }
            Header::parse_as(envelope, EnvelopeType::File)?;
            let location = file_location(task_id)?;
            let (handle, mut slot) = self.ready(task_id).await?;
            self.open_with(task_id, &handle, &mut slot, |group, fetch| {
                open_envelope(group, envelope, &location, fetch)
            })
            .await
        }
        .await;
        opened
            .map(|opened| opened.plaintext)
            .inspect_err(|failure| log_failure(task_id, "open", failure))
    }

    /// Apply the task's buffered records in `seq` order.
    pub(crate) async fn drain(&self, task_id: &str) {
        let handle = self.slot(task_id);
        let mut slot = Arc::clone(&handle.state).lock_owned().await;
        self.load(task_id, &handle, &mut slot);
        self.drain_slot(task_id, &handle, &mut slot).await;
    }

    /// After a socket open: read the log of every task group the runner is
    /// a member of, then apply what is buffered.
    pub(crate) async fn catch_up_all(&self) {
        let tasks: Vec<String> = match lock(&self.db).list_e2ee_groups() {
            Ok(rows) => rows
                .into_iter()
                .filter(|row| row.status == GroupStatus::Member.as_str())
                .map(|row| row.task_id)
                .collect(),
            Err(err) => {
                warn!(error = %err, "listing the e2ee groups failed; no catch-up");
                return;
            }
        };
        for task_id in tasks {
            let handle = self.slot(&task_id);
            let mut slot = Arc::clone(&handle.state).lock_owned().await;
            self.load(&task_id, &handle, &mut slot);
            if self.needs_catch_up(&slot)
                && let Err(failure) = self.catch_up(&task_id, &handle, &mut slot).await
            {
                warn!(task = %task_id, code = failure.code(), "catching up the task's e2ee group failed");
            }
            self.drain_slot(&task_id, &handle, &mut slot).await;
        }
    }

    /// The field map of an encrypted task; `None` for a plaintext task.
    fn field_map(&self, task_id: &str) -> Result<Option<&'static FieldMap>, EncryptionFailure> {
        let task = lock(&self.db).get_task_e2ee(task_id).map_err(|_| {
            EncryptionFailure::new(Error::NotMember, "reading the task's e2ee state failed")
        })?;
        task.map(|task| check_task(task_id, &task)).transpose()
    }

    fn encrypted_task(&self, task_id: &str) -> Result<&'static FieldMap, EncryptionFailure> {
        self.field_map(task_id)?.ok_or(EncryptionFailure::new(
            Error::NotMember,
            "the task is not end-to-end encrypted",
        ))
    }

    fn slot(&self, task_id: &str) -> Arc<SlotHandle> {
        Arc::clone(lock(&self.groups).entry(task_id.to_owned()).or_default())
    }

    fn needs_catch_up(&self, slot: &Slot) -> bool {
        slot.group.as_ref().is_some_and(Group::is_member)
            && slot.caught_up != Some(self.ds.generation())
    }

    /// The task's slot once its buffered records are applied and its catch-up
    /// after the last socket open is done; bounded, then `epoch_unknown`.
    async fn ready(
        &self,
        task_id: &str,
    ) -> Result<(Arc<SlotHandle>, OwnedMutexGuard<Slot>), EncryptionFailure> {
        let handle = self.slot(task_id);
        let prepared = tokio::time::timeout(self.timeouts.ready, async {
            let mut slot = Arc::clone(&handle.state).lock_owned().await;
            self.load(task_id, &handle, &mut slot);
            self.drain_slot(task_id, &handle, &mut slot).await;
            if self.needs_catch_up(&slot) {
                self.catch_up(task_id, &handle, &mut slot).await?;
            }
            Ok::<_, EncryptionFailure>(slot)
        })
        .await;
        match prepared {
            Ok(Ok(slot)) => Ok((handle, slot)),
            Ok(Err(_)) | Err(_) => Err(EncryptionFailure::new(
                Error::EpochUnknown {
                    epoch: handle.epoch.load(Ordering::SeqCst),
                },
                NOT_CAUGHT_UP,
            )),
        }
    }

    /// Load the task's persisted group state once.
    fn load(&self, task_id: &str, handle: &SlotHandle, slot: &mut Slot) {
        if slot.loaded {
            return;
        }
        let db = lock(&self.db);
        let row = match db.get_e2ee_group(task_id) {
            Ok(row) => row,
            Err(err) => {
                warn!(task = %task_id, error = %err, "reading the e2ee group state failed");
                return;
            }
        };
        slot.loaded = true;
        let Some(mut row) = row else {
            return;
        };
        let Some(sealed) = &row.snapshot else {
            return;
        };
        let restored = self
            .open_at_rest(&snapshot_label(task_id), sealed)
            .map_err(|_| "it does not open under the at-rest key")
            .and_then(|snapshot| {
                let cache = DbKeyCache::load(&db, &self.keys.at_rest, task_id)
                    .map_err(|_| "its key cache does not read")?;
                Group::restore(&snapshot, cache).map_err(|_| "it does not restore")
            });
        match restored {
            Ok(group) => {
                handle.epoch.store(group.epoch(), Ordering::SeqCst);
                slot.group = Some(group);
            }
            Err(reason) => {
                warn!(task = %task_id, status = %row.status, "the task's e2ee group state is unusable: {reason}");
                if row.status != GroupStatus::Removed.as_str() {
                    GroupStatus::Lost.as_str().clone_into(&mut row.status);
                    if let Err(err) = db.put_e2ee_group(&row) {
                        warn!(task = %task_id, error = %err, "marking the e2ee group lost failed");
                    }
                }
            }
        }
    }

    /// Apply the buffered records, catching up over the DS on a gap.
    async fn drain_slot(&self, task_id: &str, handle: &SlotHandle, slot: &mut Slot) {
        loop {
            match self.apply_pending(task_id, handle, slot) {
                Drain::Done => return,
                Drain::Gap => match self.catch_up(task_id, handle, slot).await {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(failure) => {
                        debug!(task = %task_id, code = failure.code(), "catch-up after a log gap failed");
                        return;
                    }
                },
            }
        }
    }

    /// Apply the buffered records in `seq` order until a gap. Replays are
    /// dropped; log entries before the runner's Welcome wait for it.
    fn apply_pending(&self, task_id: &str, handle: &SlotHandle, slot: &mut Slot) -> Drain {
        'rows: loop {
            let rows = match lock(&self.db).list_e2ee_log_pending(task_id) {
                Ok(rows) => rows,
                Err(err) => {
                    warn!(task = %task_id, error = %err, "reading buffered e2ee records failed");
                    return Drain::Done;
                }
            };
            for row in &rows {
                if row.msg_type == "e2ee_welcome" {
                    let Ok(data) = serde_json::from_str::<E2eeWelcomeData>(&row.payload) else {
                        self.discard(task_id, row, "malformed");
                        continue;
                    };
                    match slot
                        .group
                        .as_ref()
                        .filter(|g| g.is_member())
                        .map(Group::seq)
                    {
                        Some(seq) if data.seq <= seq => self.discard(task_id, row, "replayed"),
                        Some(_) => return Drain::Gap,
                        None => {
                            if self.join(task_id, handle, slot, row, &data) {
                                continue 'rows;
                            }
                        }
                    }
                    continue;
                }
                let Some(group) = slot.group.as_ref() else {
                    continue;
                };
                if !group.is_member() {
                    self.discard(task_id, row, "removed");
                    continue;
                }
                let Ok(data) = serde_json::from_str::<E2eeLogData>(&row.payload) else {
                    self.discard(task_id, row, "malformed");
                    continue;
                };
                let next = group.seq() + 1;
                if data.seq < next {
                    self.discard(task_id, row, "replayed");
                } else if data.seq > next {
                    return Drain::Gap;
                } else if self
                    .apply_entry(task_id, handle, slot, &data, Some(row))
                    .is_err()
                {
                    return Drain::Done;
                }
            }
            return Drain::Done;
        }
    }

    fn discard(&self, task_id: &str, row: &E2eeLogPendingRow, reason: &str) {
        debug!(task = %task_id, seq = row.seq, kind = %row.msg_type, reason, "dropping a buffered e2ee record");
        if let Err(err) = lock(&self.db).delete_e2ee_log_pending(task_id, row.seq, &row.msg_type) {
            warn!(task = %task_id, error = %err, "deleting a buffered e2ee record failed");
        }
    }

    /// Join the task's group from a buffered Welcome; `true` once joined and
    /// persisted. A Welcome that does not join is dropped.
    fn join(
        &self,
        task_id: &str,
        handle: &SlotHandle,
        slot: &mut Slot,
        row: &E2eeLogPendingRow,
        data: &E2eeWelcomeData,
    ) -> bool {
        let task = lock(&self.db).get_task_e2ee(task_id);
        if let Ok(Some(task)) = task
            && let Err(failure) = check_task(task_id, &task)
        {
            warn!(task = %task_id, code = failure.code(), "refusing a Welcome: {failure}");
            self.discard(task_id, row, "refused");
            return false;
        }
        let Ok(welcome) = decode_b64url(&data.welcome) else {
            self.discard(task_id, row, "malformed");
            return false;
        };
        let cache = match DbKeyCache::load(&lock(&self.db), &self.keys.at_rest, task_id) {
            Ok(cache) => cache,
            Err(err) => {
                warn!(task = %task_id, error = %err, "reading the e2ee key cache failed");
                return false;
            }
        };
        let mut pool = lock(&self.pool);
        let group = match Group::join(&pool.store, PROFILE, task_id, &welcome, data.seq, cache) {
            Ok(group) => group,
            Err(error) => {
                warn!(task = %task_id, code = to_error(&error).code(), "the Welcome does not join the task's group");
                drop(pool);
                self.discard(task_id, row, "refused");
                return false;
            }
        };
        if let Err(err) = self.persist(task_id, &group, GroupStatus::Member, Some(row), Some(&pool))
        {
            warn!(task = %task_id, error = %err, "persisting the joined e2ee group failed");
            self.reload_key_packages(&mut pool);
            return false;
        }
        drop(pool);
        info!(task = %task_id, epoch = group.epoch(), seq = group.seq(), "joined the task's e2ee group");
        handle.epoch.store(group.epoch(), Ordering::SeqCst);
        slot.group = Some(group);
        slot.caught_up = None;
        true
    }

    /// Restore the KeyPackage store from the DB after a failed persist.
    fn reload_key_packages(&self, pool: &mut KeyPackagePool) {
        let restored = lock(&self.db)
            .get_e2ee_key_packages()
            .ok()
            .flatten()
            .and_then(|row| self.open_at_rest(KEY_PACKAGES_LABEL, &row.store).ok())
            .and_then(|snapshot| gino_e2ee::KeyPackageStore::restore(&snapshot).ok());
        if let Some(store) = restored {
            pool.store = store;
        }
    }

    /// Apply one log entry and persist the result (with the buffered record
    /// it came from). `Ok(false)` for a replay. A failing entry blocks the
    /// log: it is never skipped.
    fn apply_entry(
        &self,
        task_id: &str,
        handle: &SlotHandle,
        slot: &mut Slot,
        data: &E2eeLogData,
        consumed: Option<&E2eeLogPendingRow>,
    ) -> Result<bool, EncryptionFailure> {
        let entry = log_entry(data)?;
        let group = slot
            .group
            .as_mut()
            .ok_or(EncryptionFailure::new(Error::NotMember, NO_GROUP))?;
        let applied = match group.apply(&entry) {
            Ok(Applied::Replayed) => {
                if let Some(row) = consumed {
                    self.discard(task_id, row, "replayed");
                }
                return Ok(false);
            }
            Ok(applied) => applied,
            Err(GroupError::E2ee(error @ Error::DropKeyMismatch { .. })) => {
                warn!(task = %task_id, code = error.code(), epoch = ?error.epoch(), "the logged drop public key differs from the derived one");
                Applied::Commit {
                    epoch: group.epoch(),
                    self_removed: false,
                }
            }
            Err(error) => {
                let error = to_error(&error);
                warn!(task = %task_id, seq = data.seq, code = error.code(), "applying an e2ee log entry failed; the log stops at it");
                return Err(error.into());
            }
        };
        let removed = matches!(
            applied,
            Applied::Commit {
                self_removed: true,
                ..
            }
        );
        let status = if removed {
            GroupStatus::Removed
        } else {
            GroupStatus::Member
        };
        let epoch = group.epoch();
        if let Err(err) = self.persist(task_id, group, status, consumed, None) {
            warn!(task = %task_id, error = %err, "persisting the e2ee group failed; reloading it");
            slot.group = None;
            slot.loaded = false;
            return Err(EncryptionFailure::new(
                Error::EpochUnknown { epoch },
                "persisting the group state failed",
            ));
        }
        handle.epoch.store(epoch, Ordering::SeqCst);
        if removed {
            info!(task = %task_id, epoch, "removed from the task's e2ee group");
        } else if let Applied::Commit { epoch, .. } = applied {
            debug!(task = %task_id, epoch, "applied an e2ee commit");
        }
        Ok(true)
    }

    /// Persist the group's key cache, then its snapshot (sealed), the
    /// consumed buffered record and, after a join, the KeyPackage store.
    fn persist(
        &self,
        task_id: &str,
        group: &Group,
        status: GroupStatus,
        consumed: Option<&E2eeLogPendingRow>,
        pool: Option<&KeyPackagePool>,
    ) -> Result<(), StoreError> {
        let snapshot = group.snapshot().map_err(|_| StoreError::Encode)?;
        let row = E2eeGroupRow {
            task_id: task_id.to_owned(),
            group_id: encode_b64url(group.group_id()),
            profile_id: group.profile().to_owned(),
            snapshot: Some(self.seal_at_rest(&snapshot_label(task_id), &snapshot)?),
            last_seq: i64::try_from(group.seq()).ok(),
            status: status.as_str().to_owned(),
            updated_at: String::new(),
        };
        let key_packages = pool
            .map(|pool| {
                let store = pool.store.snapshot().map_err(|_| StoreError::Encode)?;
                Ok::<_, StoreError>(E2eeKeyPackagesRow {
                    store: self.seal_at_rest(KEY_PACKAGES_LABEL, &store)?,
                    last_resort_created_at: pool.last_resort_created_at.map(to_iso),
                })
            })
            .transpose()?;
        let db = lock(&self.db);
        group
            .history()
            .cache()
            .flush(&db, &self.keys.at_rest, task_id)?;
        db.immediate_transaction(|db| {
            db.put_e2ee_group(&row)?;
            if let Some(key_packages) = &key_packages {
                db.put_e2ee_key_packages(key_packages)?;
            }
            if let Some(consumed) = consumed {
                db.delete_e2ee_log_pending(task_id, consumed.seq, &consumed.msg_type)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// Read the log after the last applied entry (following `more`) and apply
    /// it. `Ok(true)` when anything new was applied.
    async fn catch_up(
        &self,
        task_id: &str,
        handle: &SlotHandle,
        slot: &mut Slot,
    ) -> Result<bool, EncryptionFailure> {
        let generation = self.ds.generation();
        let mut progressed = false;
        while let Some(after) = slot
            .group
            .as_ref()
            .filter(|g| g.is_member())
            .map(Group::seq)
        {
            let response = self
                .ds_request(task_id, E2eeRequestData::Log { after_seq: after })
                .await
                .map_err(|message| {
                    EncryptionFailure::new(
                        Error::EpochUnknown {
                            epoch: handle.epoch.load(Ordering::SeqCst),
                        },
                        message,
                    )
                })?;
            let mut last = after;
            for data in response.entries.as_deref().unwrap_or_default() {
                if !slot.group.as_ref().is_some_and(Group::is_member) {
                    break;
                }
                progressed |= self.apply_entry(task_id, handle, slot, data, None)?;
                last = last.max(data.seq);
            }
            if response.more != Some(true) || last <= after {
                break;
            }
        }
        slot.caught_up = Some(generation);
        Ok(progressed)
    }

    /// Open through `attempt`, fetching the epoch links the walk misses and
    /// catching up once on content of a newer epoch. Recovered secrets are
    /// written to the key cache.
    async fn open_with<T>(
        &self,
        task_id: &str,
        handle: &SlotHandle,
        slot: &mut Slot,
        mut attempt: impl FnMut(&mut Group, &mut dyn FnMut(u64) -> Option<Vec<u8>>) -> Result<T, Error>,
    ) -> Result<T, EncryptionFailure> {
        let mut links: HashMap<u64, Option<Vec<u8>>> = HashMap::new();
        let mut caught_up = false;
        loop {
            let group = slot
                .group
                .as_mut()
                .ok_or(EncryptionFailure::new(Error::NotMember, NO_GROUP))?;
            let mut missing = None;
            let result = attempt(group, &mut |epoch| {
                let link = links.get(&epoch);
                if link.is_none() {
                    missing = Some(epoch);
                }
                link.cloned().flatten()
            });
            if let Err(err) =
                group
                    .history()
                    .cache()
                    .flush(&lock(&self.db), &self.keys.at_rest, task_id)
            {
                warn!(task = %task_id, error = %err, "persisting the e2ee key cache failed");
            }
            let member = group.is_member();
            let error = match result {
                Ok(value) => return Ok(value),
                Err(error) => error,
            };
            match (error, missing) {
                (Error::HistoryUnavailable { epoch }, Some(link_epoch)) => {
                    let link = self
                        .fetch_link(task_id, link_epoch)
                        .await
                        .map_err(|message| {
                            EncryptionFailure::new(Error::HistoryUnavailable { epoch }, message)
                        })?;
                    links.insert(link_epoch, link);
                }
                (Error::EpochUnknown { .. }, _) if !member => {
                    return Err(EncryptionFailure::new(Error::NotMember, REMOVED));
                }
                (Error::EpochUnknown { epoch }, _) if !caught_up => {
                    caught_up = true;
                    self.catch_up(task_id, handle, slot).await.map_err(|_| {
                        EncryptionFailure::new(Error::EpochUnknown { epoch }, NOT_CAUGHT_UP)
                    })?;
                }
                (error, _) => return Err(error.into()),
            }
        }
    }

    /// The DS's epoch link for `epoch`; `None` when it holds none.
    async fn fetch_link(&self, task_id: &str, epoch: u64) -> Result<Option<Vec<u8>>, &'static str> {
        let response = self
            .ds_request(task_id, E2eeRequestData::Link { epoch })
            .await?;
        // An undecodable link fails the walk's checks as `link_invalid`.
        Ok(response
            .link
            .map(|link| decode_b64url(&link).unwrap_or_default()))
    }

    async fn ds_request(
        &self,
        task_id: &str,
        data: E2eeRequestData,
    ) -> Result<E2eeResponseData, &'static str> {
        match self.ds.request(task_id, data, self.timeouts.request).await {
            Ok(response) if response.ok => Ok(response),
            Ok(response) => {
                warn!(
                    task = %task_id,
                    code = ?response.error.as_ref().map(|error| error.code.as_str()),
                    "the DS refused an e2ee request"
                );
                Err("the DS refused the request")
            }
            Err(err) => {
                debug!(task = %task_id, error = %err, "e2ee DS request failed");
                Err("the DS did not answer")
            }
        }
    }
}
