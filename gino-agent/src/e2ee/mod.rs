//! End-to-end encryption, runner role (docs/e2ee/task-content.md §4).
//!
//! [`E2eeKeys`] loads the identity key and the at-rest key at startup, before
//! registration advertises the identity. [`E2ee`] then owns all e2ee state of
//! the runner in the agent DB: the KeyPackage pool, the buffered DS records and
//! the per-task group state. Other modules call this module, never `gino_e2ee`
//! directly except for its types.
//!
//! The key files live in the state directory (the directory of the agent DB),
//! never in the workspace, the engine environment, sandbox or VM binds, or the
//! local agent API.

mod cache;
#[cfg(test)]
mod group_tests;
mod groups;
mod key_packages;
mod keys;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use gino_e2ee::{Identity, KeyPackageStore, encode_b64url, fingerprint_display};
use secrecy::ExposeSecret as _;
use thiserror::Error;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

#[allow(unused_imports, reason = "named by the inbound and outbound paths")]
pub(crate) use self::groups::{EncryptionFailure, GroupStatus, Sealer};
use self::groups::{Groups, Timeouts};
pub(crate) use self::groups::{holds_encrypted_scope, host_action_allowed, record_task_e2ee};
use self::key_packages::{KeyPackagePool, Plan};
pub(crate) use self::keys::{AtRestKey, KeyFileError, OpenError, SealError};
use crate::db::{Db, DbError, E2eeKeyPackagesRow};
use crate::protocol::frames::{
    E2eeCapability, E2eeKeyPackageStatusData, E2eeLiveFrame, InboundFrame,
};
use crate::scheduler::{now, parse_iso, to_iso};
use crate::transport::DsLink;

/// The identity key file (32-byte Ed25519 seed) in the state directory.
pub(crate) const IDENTITY_KEY_FILE: &str = "e2ee-identity.key";
/// The at-rest key file (32 random bytes) in the state directory.
pub(crate) const STATE_KEY_FILE: &str = "e2ee-state.key";
/// Outbox `type` of a KeyPackage upload.
const KEY_PACKAGES_FRAME: &str = "e2ee_key_packages";
/// At-rest label of the KeyPackage store snapshot.
const KEY_PACKAGES_LABEL: &str = "e2ee_key_packages";
/// Cadence of the last-resort lifetime check.
const LAST_RESORT_CHECK: Duration = Duration::from_hours(1);

/// The state directory holding the key files: the directory of the agent DB.
pub(crate) fn state_dir(db_path: &Path) -> PathBuf {
    db_path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// The runner's identity and at-rest keys.
pub(crate) struct E2eeKeys {
    identity: Identity,
    at_rest: AtRestKey,
}

impl std::fmt::Debug for E2eeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E2eeKeys")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl E2eeKeys {
    /// Load both key files from `state_dir`, creating each on first start.
    pub(crate) fn load_or_create(state_dir: &Path) -> Result<Self, KeyFileError> {
        let seed = keys::load_or_create(&state_dir.join(IDENTITY_KEY_FILE))?;
        let identity = Identity::from_seed(seed.expose_secret());
        let at_rest = AtRestKey::new(keys::load_or_create(&state_dir.join(STATE_KEY_FILE))?);
        Ok(Self { identity, at_rest })
    }

    /// The display fingerprint of the identity key (spec §3.5).
    pub(crate) fn fingerprint(&self) -> String {
        fingerprint_display(&self.identity.public_key())
    }

    /// The capability object sent on register and every heartbeat.
    pub(crate) fn capability(&self) -> E2eeCapability {
        E2eeCapability::basic(encode_b64url(&self.identity.public_key()))
    }
}

/// E2ee state that cannot be loaded at startup.
#[derive(Debug, Error)]
pub(crate) enum E2eeError {
    #[error("reading e2ee state from the agent DB: {0}")]
    Db(#[from] DbError),
    #[error(
        "the e2ee KeyPackage state in the agent DB does not open under {STATE_KEY_FILE}; \
         the key file and the DB must come from the same runner"
    )]
    AtRest(#[from] OpenError),
    #[error("the e2ee KeyPackage state in the agent DB is corrupt")]
    Corrupt,
}

/// All e2ee state of the runner.
pub(crate) struct E2ee {
    keys: E2eeKeys,
    db: Arc<Mutex<Db>>,
    /// Wakes the transport after an outbox enqueue.
    flush: Arc<Notify>,
    pool: Mutex<KeyPackagePool>,
    /// DS requests over the live socket.
    ds: Arc<DsLink>,
    groups: Groups,
    timeouts: Timeouts,
}

impl std::fmt::Debug for E2ee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("E2ee")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

impl E2ee {
    /// Restore the KeyPackage store from the agent DB. Group state loads
    /// per task on first use.
    pub(crate) fn new(
        keys: E2eeKeys,
        db: Arc<Mutex<Db>>,
        flush: Arc<Notify>,
        ds: Arc<DsLink>,
    ) -> Result<Self, E2eeError> {
        let row = lock(&db).get_e2ee_key_packages()?;
        let pool = match row {
            Some(row) => {
                let snapshot = keys.at_rest.open(KEY_PACKAGES_LABEL, &row.store)?;
                let store = KeyPackageStore::restore(&snapshot).map_err(|_| E2eeError::Corrupt)?;
                let created_at = row.last_resort_created_at.as_deref().and_then(parse_iso);
                KeyPackagePool::new(store, created_at)
            }
            None => KeyPackagePool::new(KeyPackageStore::new(), None),
        };
        Ok(Self {
            keys,
            db,
            flush,
            pool: Mutex::new(pool),
            ds,
            groups: Groups::default(),
            timeouts: Timeouts::default(),
        })
    }

    /// Publish the first KeyPackages of a runner that has none (a fresh or
    /// lost agent DB). Later publications follow the host's status.
    pub(crate) fn publish_initial(&self) {
        if lock(&self.db)
            .get_e2ee_key_packages()
            .as_ref()
            .is_ok_and(Option::is_none)
        {
            self.publish(&mut lock(&self.pool), Plan::INITIAL);
        }
    }

    /// Serve the live-only e2ee frames, the catch-up after each socket open
    /// and the periodic last-resort check until the transport closes the
    /// channel.
    pub(crate) async fn run(self: Arc<Self>, mut live: mpsc::UnboundedReceiver<E2eeLiveFrame>) {
        let mut check = tokio::time::interval(LAST_RESORT_CHECK);
        check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut connections = self.ds.connections();
        loop {
            tokio::select! {
                frame = live.recv() => match frame {
                    Some(frame) => self.on_live_frame(frame),
                    None => break,
                },
                Some(_) = connections.opened() => {
                    let this = Arc::clone(&self);
                    tokio::spawn(async move { this.catch_up_all().await });
                }
                _ = check.tick() => self.check_last_resort(),
            }
        }
        debug!("e2ee live frame loop stopped");
    }

    /// Handle one live-only frame.
    pub(crate) fn on_live_frame(&self, frame: E2eeLiveFrame) {
        match frame {
            E2eeLiveFrame::KeyPackageStatus { id, data } => {
                self.on_key_package_status(id.as_deref(), &data);
            }
            E2eeLiveFrame::Response {
                task_id, req_id, ..
            } => {
                debug!(task = %task_id, req = %req_id, "e2ee_response with no pending request; ignoring");
            }
        }
    }

    /// React to the host's view of the KeyPackage pool.
    fn on_key_package_status(&self, id: Option<&str>, status: &E2eeKeyPackageStatusData) {
        for rejection in &status.rejected {
            warn!(code = %rejection.code, index = ?rejection.index, "host rejected an e2ee KeyPackage");
        }
        if status.rejected.iter().any(|r| r.code == "key_changed") {
            error!(
                fingerprint = %self.keys.fingerprint(),
                "the host refuses this runner's KeyPackages because its e2ee identity key changed; \
                 an operator must re-pin the runner's key at the host"
            );
        }
        let mut pool = lock(&self.pool);
        let plan = pool.on_status(
            id,
            status,
            |pending| lock(&self.db).is_outbox_unacked(pending).unwrap_or(true),
            now(),
        );
        if !plan.is_empty() {
            self.publish(&mut pool, plan);
        }
    }

    /// Replace the last-resort KeyPackage once less than 28 days remain.
    pub(crate) fn check_last_resort(&self) {
        let mut pool = lock(&self.pool);
        let plan = pool.on_tick(now());
        if !plan.is_empty() {
            self.publish(&mut pool, plan);
        }
    }

    /// Generate `plan`, persist the store (sealed at rest) and enqueue the
    /// upload in one transaction, the store first.
    fn publish(&self, pool: &mut KeyPackagePool, plan: Plan) {
        let data = match pool.generate(&self.keys.identity, plan) {
            Ok(data) => data,
            Err(err) => {
                error!(code = err.code(), "generating e2ee KeyPackages failed");
                return;
            }
        };
        let created_at = if plan.last_resort {
            Some(now())
        } else {
            pool.last_resort_created_at
        };
        let sealed = match pool.store.snapshot() {
            Ok(snapshot) => self.keys.at_rest.seal(KEY_PACKAGES_LABEL, &snapshot),
            Err(_) => Err(SealError),
        };
        let Ok(store) = sealed else {
            error!("sealing the e2ee KeyPackage store failed; not publishing");
            return;
        };
        let row = E2eeKeyPackagesRow {
            store,
            last_resort_created_at: created_at.map(to_iso),
        };
        let enqueued = lock(&self.db).immediate_transaction(|db| {
            db.put_e2ee_key_packages(&row)?;
            db.enqueue_outbox_correlated(KEY_PACKAGES_FRAME, &data, None, None)
        });
        match enqueued {
            Ok(outbox_id) => {
                pool.last_resort_created_at = created_at;
                pool.pending = Some(outbox_id);
                self.flush.notify_one();
                info!(
                    one_time = plan.one_time,
                    last_resort = plan.last_resort,
                    "publishing e2ee KeyPackages"
                );
            }
            Err(err) => {
                warn!(error = %err, "persisting e2ee KeyPackages failed; retrying on the next status");
            }
        }
    }

    /// Seal `plaintext` at rest under `label` (the at-rest key).
    pub(crate) fn seal_at_rest(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        self.keys.at_rest.seal(label, plaintext)
    }

    /// Open a blob sealed at rest under `label`.
    pub(crate) fn open_at_rest(&self, label: &str, sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
        self.keys.at_rest.open(label, sealed)
    }

    /// Accept a durable `e2ee_log`/`e2ee_welcome` record: buffer it, as
    /// received, until the group state applies it in `seq` order
    /// ([`E2ee::drain`]). Returns `false` when it could not be stored (the
    /// inbox row replays).
    pub(crate) fn on_record(&self, frame: &InboundFrame) -> bool {
        let (task_id, seq, msg_type, payload) = match frame {
            InboundFrame::E2eeLog { task_id, data, .. } => {
                (task_id, data.seq, "e2ee_log", serde_json::to_string(data))
            }
            InboundFrame::E2eeWelcome { task_id, data, .. } => (
                task_id,
                data.seq,
                "e2ee_welcome",
                serde_json::to_string(data),
            ),
            _ => return true,
        };
        let Ok(seq_column) = i64::try_from(seq) else {
            warn!(task = %task_id, seq, kind = msg_type, "e2ee record seq out of range; dropping");
            return true;
        };
        let stored = payload.map_err(DbError::from).and_then(|payload| {
            lock(&self.db).put_e2ee_log_pending(task_id, seq_column, msg_type, &payload)
        });
        match stored {
            Ok(inserted) => {
                debug!(task = %task_id, seq, kind = msg_type, inserted, "buffered e2ee record");
                true
            }
            Err(err) => {
                warn!(task = %task_id, seq, kind = msg_type, error = %err, "buffering e2ee record failed");
                false
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
