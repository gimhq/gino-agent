//! Group-state scenarios: a client creates the task's group in-test, adds the
//! runner's KeyPackage and drives the log through a fake DS served over the
//! [`DsLink`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{
    CommitUnit, Error, FileDigest, HistoryPolicy, Identity, KeyHistoryRecord, Location,
    MemoryKeyCache, ScopeGroup, decode_b64url, encode_b64url,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};
use tokio::sync::{Notify, mpsc};

use super::groups::{PROFILE, Timeouts};
use super::{E2ee, E2eeKeys, EncryptionFailure, GroupStatus, lock, record_task_e2ee};
use crate::db::{Db, TaskRow};
use crate::protocol::frames::{
    E2eeKeyPackagesData, E2eeLogData, E2eeRequestData, E2eeResponseData, E2eeWelcomeData,
    InboundFrame, OutboundFrame, TaskE2ee,
};
use crate::transport::DsLink;

const TASK: &str = "t-1";

/// The task's DS as the fake host serves it.
#[derive(Default)]
struct DsState {
    epoch: u64,
    log: Vec<E2eeLogData>,
    links: BTreeMap<u64, Vec<u8>>,
    requests: Vec<E2eeRequestData>,
}

impl DsState {
    /// Accept a commit unit and return its `seq`.
    fn submit(&mut self, unit: &CommitUnit) -> u64 {
        assert_eq!(unit.epoch, self.epoch);
        let seq = self.push(
            "commit",
            unit.epoch,
            &unit.commit,
            Some(&unit.drop_public_key),
        );
        self.epoch += 1;
        if let Some(link) = &unit.epoch_link {
            self.links.entry(self.epoch).or_insert_with(|| link.clone());
        }
        for record in &unit.key_history {
            let (kind, bytes) = match record {
                KeyHistoryRecord::Message(bytes) => ("key_history", bytes),
                KeyHistoryRecord::Sealed(bytes) => ("key_history_sealed", bytes),
            };
            self.push(kind, self.epoch, bytes, None);
        }
        seq
    }

    fn push(&mut self, kind: &str, epoch: u64, bytes: &[u8], drop_key: Option<&[u8; 32]>) -> u64 {
        let seq = self.log.len() as u64 + 1;
        self.log.push(E2eeLogData {
            seq,
            kind: kind.to_owned(),
            epoch,
            message: encode_b64url(bytes),
            drop_public_key: drop_key.map(|key| encode_b64url(key)),
        });
        seq
    }

    fn answer(&mut self, request: &E2eeRequestData) -> E2eeResponseData {
        self.requests.push(request.clone());
        let mut response = E2eeResponseData {
            ok: true,
            error: None,
            entries: None,
            more: None,
            epoch: Some(self.epoch),
            seq: None,
            link: None,
        };
        match request {
            E2eeRequestData::Log { after_seq } => {
                response.entries = Some(
                    self.log
                        .iter()
                        .filter(|entry| entry.seq > *after_seq)
                        .cloned()
                        .collect(),
                );
            }
            E2eeRequestData::Link { epoch } => {
                response.link = self.links.get(epoch).map(|link| encode_b64url(link));
            }
            _ => response.ok = false,
        }
        response
    }

    fn log_reads(&self) -> Vec<u64> {
        self.requests
            .iter()
            .filter_map(|request| match request {
                E2eeRequestData::Log { after_seq } => Some(*after_seq),
                _ => None,
            })
            .collect()
    }

    fn link_reads(&self) -> usize {
        self.requests
            .iter()
            .filter(|request| matches!(request, E2eeRequestData::Link { .. }))
            .count()
    }
}

/// Answer the requests of `link`'s next socket from `ds`.
fn serve(link: &Arc<DsLink>, ds: &Arc<Mutex<DsState>>) {
    let (tx, mut rx) = mpsc::channel::<String>(16);
    link.opened(tx);
    let (link, ds) = (Arc::clone(link), Arc::clone(ds));
    tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            let Ok(OutboundFrame::E2eeRequest { req_id, data, .. }) = serde_json::from_str(&text)
            else {
                continue;
            };
            let response = ds.lock().unwrap().answer(&data);
            link.on_response(&req_id, response);
        }
    });
}

struct Fixture {
    dir: tempfile::TempDir,
    db: Arc<Mutex<Db>>,
    link: Arc<DsLink>,
    ds: Arc<Mutex<DsState>>,
    e2ee: E2ee,
    identity: Identity,
    client: ScopeGroup<MemoryKeyCache>,
    key_packages_used: usize,
}

fn timeouts() -> Timeouts {
    Timeouts {
        request: Duration::from_millis(500),
        ready: Duration::from_secs(2),
    }
}

impl Fixture {
    /// A runner with its KeyPackages published, a client group at epoch 0
    /// and a connected DS.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = task_db(&dir.path().join("agent.db"));
        let link = Arc::new(DsLink::default());
        let ds = Arc::new(Mutex::new(DsState::default()));
        serve(&link, &ds);
        let e2ee = runner(dir.path(), &db, &link);
        e2ee.publish_initial();
        let identity = Identity::generate(&RustCrypto::default()).unwrap();
        let client = ScopeGroup::create(
            &identity,
            PROFILE,
            TASK,
            HistoryPolicy::Full,
            MemoryKeyCache::default(),
        )
        .unwrap();
        Self {
            dir,
            db,
            link,
            ds,
            e2ee,
            identity,
            client,
            key_packages_used: 0,
        }
    }

    /// The runner restarted: state reloads from the agent DB.
    fn restart(&mut self) {
        self.e2ee = runner(self.dir.path(), &self.db, &self.link);
    }

    fn mark_encrypted(&self) {
        let group_id = encode_b64url(&gino_e2ee::group_id(PROFILE, TASK).unwrap());
        self.mark(PROFILE, &group_id);
    }

    fn mark(&self, profile: &str, group_id: &str) {
        let marker = TaskE2ee {
            profile_id: profile.to_owned(),
            group_id: group_id.to_owned(),
        };
        assert!(record_task_e2ee(&lock(&self.db), TASK, &marker));
    }

    fn runner_key_package(&mut self) -> Vec<u8> {
        let rows = lock(&self.db).list_unacked_outbox().unwrap();
        let row = rows
            .iter()
            .find(|row| row.msg_type == "e2ee_key_packages")
            .unwrap();
        let data: E2eeKeyPackagesData = serde_json::from_str(&row.payload).unwrap();
        let key_package = data.one_time.unwrap()[self.key_packages_used].clone();
        self.key_packages_used += 1;
        decode_b64url(&key_package).unwrap()
    }

    /// The client adds the runner; the Welcome is delivered and applied.
    async fn add_runner(&mut self) -> u64 {
        let key_package = self.runner_key_package();
        let unit = self
            .client
            .add_members(&self.identity, &[key_package], None)
            .unwrap();
        let seq = self.commit(&unit);
        let welcome = InboundFrame::E2eeWelcome {
            task_id: TASK.to_owned(),
            data: E2eeWelcomeData {
                welcome: encode_b64url(unit.welcome.as_ref().unwrap()),
                seq,
            },
            msg_id: None,
        };
        assert!(self.e2ee.on_record(&welcome));
        self.e2ee.drain(TASK).await;
        seq
    }

    fn commit(&mut self, unit: &CommitUnit) -> u64 {
        let seq = self.ds.lock().unwrap().submit(unit);
        self.client.commit_accepted(seq).unwrap();
        seq
    }

    /// A client self-update, logged at the DS but not delivered.
    fn update(&mut self) -> u64 {
        let unit = self.client.self_update(&self.identity).unwrap();
        self.commit(&unit)
    }

    /// Deliver log entry `seq` as a durable record (not yet applied).
    fn deliver(&self, seq: u64) {
        let data = self.ds.lock().unwrap().log[usize::try_from(seq - 1).unwrap()].clone();
        let frame = InboundFrame::E2eeLog {
            task_id: TASK.to_owned(),
            data,
            msg_id: None,
        };
        assert!(self.e2ee.on_record(&frame));
    }

    /// A `message` frame sealed by the client at its current epoch.
    fn message(&self, text: &str) -> Value {
        let frame = json!({"type": "message", "taskId": TASK, "data": {"text": text}});
        let (epoch, secrets) = self.client.current().unwrap();
        FieldMap::for_profile(PROFILE)
            .unwrap()
            .seal_frame(
                "message",
                &frame,
                epoch,
                &secrets.content_key,
                &RustCrypto::default(),
            )
            .unwrap()
    }

    async fn open(&self, frame: &Value) -> Result<String, EncryptionFailure> {
        let mut frame = frame.clone();
        self.e2ee.open_frame(TASK, "message", &mut frame).await?;
        Ok(frame["data"]["text"].as_str().unwrap().to_owned())
    }

    fn key_package_uploads(&self) -> usize {
        lock(&self.db)
            .list_unacked_outbox()
            .unwrap()
            .iter()
            .filter(|row| row.msg_type == "e2ee_key_packages")
            .count()
    }

    fn last_seq(&self) -> Option<i64> {
        lock(&self.db)
            .get_e2ee_group(TASK)
            .unwrap()
            .unwrap()
            .last_seq
    }

    fn pending(&self) -> Vec<i64> {
        lock(&self.db)
            .list_e2ee_log_pending(TASK)
            .unwrap()
            .iter()
            .map(|row| row.seq)
            .collect()
    }
}

/// An agent DB at `path` holding the task's row.
fn task_db(path: &std::path::Path) -> Arc<Mutex<Db>> {
    let db = Db::open(path).unwrap();
    db.insert_task_row(&TaskRow {
        id: TASK.to_owned(),
        name: None,
        kind: None,
        status: "active".to_owned(),
        engine: None,
        model: None,
        workdir: None,
        meta: None,
        created_at: "2026-01-01T00:00:00.000Z".to_owned(),
        updated_at: "2026-01-01T00:00:00.000Z".to_owned(),
    })
    .unwrap();
    Arc::new(Mutex::new(db))
}

fn runner(dir: &std::path::Path, db: &Arc<Mutex<Db>>, link: &Arc<DsLink>) -> E2ee {
    let keys = E2eeKeys::load_or_create(dir).unwrap();
    let mut e2ee = E2ee::new(
        keys,
        Arc::clone(db),
        Arc::new(Notify::new()),
        Arc::clone(link),
    )
    .unwrap();
    e2ee.timeouts = timeouts();
    e2ee
}

fn code(result: Result<impl std::fmt::Debug, EncryptionFailure>) -> Error {
    result.unwrap_err().error
}

#[tokio::test]
async fn a_welcome_joins_and_content_opens_and_seals() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Pending);
    assert!(!fx.e2ee.holds_encrypted_scope());
    let store_before = lock(&fx.db).get_e2ee_key_packages().unwrap().unwrap();

    assert_eq!(fx.add_runner().await, 1);
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Member);
    assert!(fx.e2ee.holds_encrypted_scope());
    assert!(fx.e2ee.is_encrypted(TASK));
    assert!(fx.pending().is_empty());
    assert_eq!(fx.last_seq(), Some(1));
    // The consumed one-time KeyPackage is gone from the persisted store.
    let store_after = lock(&fx.db).get_e2ee_key_packages().unwrap().unwrap();
    assert_ne!(store_after.store, store_before.store);

    assert_eq!(
        fx.open(&fx.message("do the task")).await.unwrap(),
        "do the task"
    );

    let mut result = json!({
        "type": "thread_result", "taskId": TASK, "threadId": "th-1", "outboxId": "o-1",
        "data": {"status": "succeeded", "result": "done", "duration_ms": 1, "final_seq": 0}
    });
    fx.e2ee
        .seal_frame(TASK, "thread_result", &mut result)
        .await
        .unwrap();
    assert!(result["data"]["result"]["e2ee"].is_string());
    assert_eq!(result["data"]["status"], "succeeded");
    let client = &mut fx.client;
    let opened = FieldMap::for_profile(PROFILE)
        .unwrap()
        .open_frame("thread_result", &result, |envelope, location| {
            client
                .open(envelope, location, |_| None)
                .map_err(|error| error.encryption_error().unwrap())
        })
        .unwrap();
    assert_eq!(opened["data"]["result"], "done");
}

#[tokio::test]
async fn log_entries_apply_in_order_and_replays_are_no_ops() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    fx.add_runner().await;
    let (two, three) = (fx.update(), fx.update());
    fx.deliver(two);
    fx.deliver(three);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.last_seq(), Some(3));
    assert!(fx.pending().is_empty());

    // A redelivery is a no-op.
    fx.deliver(two);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.last_seq(), Some(3));
    assert!(fx.pending().is_empty());
    assert!(
        fx.ds.lock().unwrap().log_reads().is_empty(),
        "no gap, no read"
    );
    assert_eq!(fx.open(&fx.message("epoch 3")).await.unwrap(), "epoch 3");
}

#[tokio::test]
async fn a_gap_is_buffered_and_caught_up() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    fx.add_runner().await;
    let _ = (fx.update(), fx.update());
    let four = fx.update();
    fx.deliver(four);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.last_seq(), Some(4));
    assert!(fx.pending().is_empty());
    assert_eq!(fx.ds.lock().unwrap().log_reads(), [1]);

    // Without a DS the entry ahead stays buffered, then drains in order.
    fx.link.closed();
    let _ = fx.update();
    let six = fx.update();
    fx.deliver(six);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.last_seq(), Some(4));
    assert_eq!(fx.pending(), [6]);
    serve(&fx.link, &fx.ds);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.last_seq(), Some(6));
    assert!(fx.pending().is_empty());
    assert_eq!(fx.open(&fx.message("epoch 6")).await.unwrap(), "epoch 6");
}

#[tokio::test]
async fn removal_keeps_held_history_and_refuses_new_epochs() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    fx.add_runner().await;
    let before = fx.message("before removal");
    let runner_key = fx.client.members()[1].clone();
    let unit = fx
        .client
        .remove_members(&fx.identity, &[runner_key.try_into().unwrap()])
        .unwrap();
    let seq = fx.commit(&unit);
    fx.deliver(seq);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Removed);
    assert!(!fx.e2ee.holds_encrypted_scope());

    let after = fx.message("after removal");
    assert_eq!(code(fx.open(&after).await), Error::NotMember);
    let mut result = json!({"type": "thread_result", "taskId": TASK, "threadId": "th-1",
        "outboxId": "o-1", "data": {"status": "succeeded", "result": "x"}});
    assert_eq!(
        code(fx.e2ee.seal_frame(TASK, "thread_result", &mut result).await),
        Error::NotMember
    );
    assert_eq!(result["data"]["result"], "x", "nothing sealed in place");
    assert_eq!(fx.open(&before).await.unwrap(), "before removal");

    fx.restart();
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Removed);
    assert_eq!(code(fx.open(&after).await), Error::NotMember);
}

/// Content sealed by the client at epochs 0, 1 and 2, then the runner added
/// (it joins at epoch 3).
async fn history(fx: &mut Fixture) -> Vec<Value> {
    fx.mark_encrypted();
    let mut sealed = vec![fx.message("epoch 0")];
    for epoch in 1..=2 {
        fx.update();
        sealed.push(fx.message(&format!("epoch {epoch}")));
    }
    fx.add_runner().await;
    sealed
}

#[tokio::test]
async fn older_epochs_open_through_links_then_from_the_persistent_cache() {
    let mut fx = Fixture::new();
    let sealed = history(&mut fx).await;
    for (epoch, frame) in sealed.iter().enumerate().rev() {
        assert_eq!(fx.open(frame).await.unwrap(), format!("epoch {epoch}"));
    }
    assert_eq!(fx.ds.lock().unwrap().link_reads(), 3);

    fx.restart();
    for (epoch, frame) in sealed.iter().enumerate() {
        assert_eq!(fx.open(frame).await.unwrap(), format!("epoch {epoch}"));
    }
    assert_eq!(
        fx.ds.lock().unwrap().link_reads(),
        3,
        "served from the cache"
    );
}

#[tokio::test]
async fn a_missing_link_cuts_older_content_only() {
    let mut fx = Fixture::new();
    let sealed = history(&mut fx).await;
    fx.ds.lock().unwrap().links.remove(&2);
    assert_eq!(
        code(fx.open(&sealed[1]).await),
        Error::HistoryUnavailable { epoch: 1 }
    );
    assert_eq!(
        code(fx.open(&sealed[0]).await),
        Error::HistoryUnavailable { epoch: 0 }
    );
    assert_eq!(fx.open(&sealed[2]).await.unwrap(), "epoch 2");
    assert_eq!(fx.open(&fx.message("now")).await.unwrap(), "now");
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Member);
}

#[tokio::test]
async fn content_of_a_newer_epoch_catches_up_first() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    fx.add_runner().await;
    assert_eq!(fx.open(&fx.message("epoch 1")).await.unwrap(), "epoch 1");
    let reads = fx.ds.lock().unwrap().log_reads().len();
    fx.update();
    assert_eq!(fx.open(&fx.message("epoch 2")).await.unwrap(), "epoch 2");
    assert_eq!(fx.ds.lock().unwrap().log_reads().len(), reads + 1);
    assert_eq!(fx.last_seq(), Some(2));
}

#[tokio::test]
async fn an_outstanding_catch_up_times_out_as_epoch_unknown() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    fx.add_runner().await;
    let frame = fx.message("x");
    // Restarted without a socket: the catch-up cannot run.
    fx.link = Arc::new(DsLink::default());
    fx.restart();
    let started = tokio::time::Instant::now();
    assert_eq!(
        code(fx.open(&frame).await),
        Error::EpochUnknown { epoch: 1 }
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    let mut result = json!({"type": "thread_result", "taskId": TASK, "threadId": "th-1",
        "outboxId": "o-1", "data": {"status": "succeeded", "result": "x"}});
    let failure = fx
        .e2ee
        .seal_frame(TASK, "thread_result", &mut result)
        .await
        .unwrap_err();
    assert_eq!(failure.code(), "epoch_unknown");
    assert_eq!(failure.to_encryption_error().epoch, Some(1));
}

#[tokio::test]
async fn a_mismatching_group_id_is_not_member() {
    let mut fx = Fixture::new();
    fx.mark(PROFILE, "b3RoZXI");
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Lost);
    fx.add_runner().await;
    assert_eq!(
        fx.e2ee.group_status(TASK),
        GroupStatus::Lost,
        "Welcome refused"
    );
    let failure = fx.open(&fx.message("x")).await.unwrap_err();
    assert_eq!(failure.error, Error::NotMember);
    assert!(failure.to_string().contains("group id"), "{failure}");
    let mut result = json!({"type": "thread_result", "taskId": TASK, "threadId": "th-1",
        "outboxId": "o-1", "data": {"status": "succeeded", "result": "x"}});
    assert_eq!(
        code(fx.e2ee.seal_frame(TASK, "thread_result", &mut result).await),
        Error::NotMember
    );
}

#[tokio::test]
async fn an_unsupported_profile_is_refused() {
    let fx = Fixture::new();
    let group_id = encode_b64url(&gino_e2ee::group_id("gino.chat.v1", TASK).unwrap());
    fx.mark("gino.chat.v1", &group_id);
    assert_eq!(
        code(fx.open(&fx.message("x")).await),
        Error::UnsupportedVersion
    );
}

#[tokio::test]
async fn an_encrypted_task_without_group_state_is_not_member() {
    let fx = Fixture::new();
    fx.mark_encrypted();
    assert_eq!(code(fx.open(&fx.message("x")).await), Error::NotMember);
    let mut result = json!({"type": "thread_result", "taskId": TASK, "threadId": "th-1",
        "outboxId": "o-1", "data": {"status": "succeeded", "result": "x"}});
    assert_eq!(
        code(fx.e2ee.seal_frame(TASK, "thread_result", &mut result).await),
        Error::NotMember
    );
    assert_eq!(
        code(fx.e2ee.seal_file(TASK, b"bytes").await),
        Error::NotMember
    );
}

#[tokio::test]
async fn a_lost_agent_db_is_not_member_until_re_added_then_history_opens_through_links() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    fx.add_runner().await;
    let before = fx.message("before the loss");
    let seq = fx.update();
    fx.deliver(seq);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.open(&before).await.unwrap(), "before the loss");
    let fingerprint = fx.e2ee.keys.fingerprint();
    let runner_key: [u8; 32] = fx.client.members()[1].clone().try_into().unwrap();

    // A fresh agent DB in the same state dir: same identity key, no group state.
    fx.db = task_db(&fx.dir.path().join("agent-new.db"));
    fx.e2ee = runner(fx.dir.path(), &fx.db, &fx.link);
    fx.e2ee.publish_initial();
    fx.key_packages_used = 0;
    assert_eq!(fx.e2ee.keys.fingerprint(), fingerprint);
    assert_eq!(fx.key_package_uploads(), 1, "a fresh KeyPackage pool");
    fx.mark_encrypted();
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Pending);
    assert!(!fx.e2ee.holds_encrypted_scope());
    let failure = fx.open(&before).await.unwrap_err();
    assert_eq!(failure.error, Error::NotMember);
    assert_eq!(
        failure.to_encryption_error().message.as_deref(),
        Some("no group state for this task; re-add this runner")
    );

    // A client removes the old leaf, then adds a fresh KeyPackage.
    let remove = fx
        .client
        .remove_members(&fx.identity, &[runner_key])
        .unwrap();
    fx.commit(&remove);
    fx.add_runner().await;
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Member);
    assert!(fx.e2ee.holds_encrypted_scope());
    assert_eq!(fx.open(&before).await.unwrap(), "before the loss");
    assert!(fx.ds.lock().unwrap().link_reads() > 0, "through the links");
    assert_eq!(fx.open(&fx.message("after")).await.unwrap(), "after");
}

#[tokio::test]
async fn plaintext_on_an_encrypted_task_is_rejected_and_plaintext_tasks_pass() {
    let mut fx = Fixture::new();
    let mut plain = json!({"type": "message", "taskId": TASK, "data": {"text": "hi"}});
    assert!(!fx.e2ee.is_encrypted(TASK));
    fx.e2ee
        .open_frame(TASK, "message", &mut plain)
        .await
        .unwrap();
    fx.e2ee
        .seal_frame(TASK, "message", &mut plain)
        .await
        .unwrap();
    assert_eq!(plain["data"]["text"], "hi");

    fx.mark_encrypted();
    fx.add_runner().await;
    assert_eq!(code(fx.open(&plain).await), Error::PlaintextRejected);
}

#[tokio::test]
async fn files_seal_and_open_against_their_descriptor() {
    let mut fx = Fixture::new();
    fx.mark_encrypted();
    fx.add_runner().await;
    let (envelope, digest) = fx.e2ee.seal_file(TASK, b"report bytes").await.unwrap();
    assert_eq!(FileDigest::of(&envelope), digest);
    let location = Location::new(TASK).unwrap().part("field", "file").unwrap();
    let (_, secrets) = fx.client.current().unwrap();
    assert_eq!(
        gino_e2ee::open_file(&secrets.content_key, &envelope, &location).unwrap(),
        b"report bytes"
    );
    assert_eq!(
        fx.e2ee.open_file(TASK, &envelope, &digest).await.unwrap(),
        b"report bytes"
    );
    let other = FileDigest {
        sha256: "00".repeat(32),
        size: digest.size,
    };
    assert_eq!(
        code(fx.e2ee.open_file(TASK, &envelope, &other).await),
        Error::Malformed
    );
}

#[tokio::test]
async fn a_restart_reloads_the_sealed_state_and_nothing_is_stored_in_plaintext() {
    let mut fx = Fixture::new();
    let sealed = history(&mut fx).await;
    let seq = fx.update();
    fx.deliver(seq);
    fx.e2ee.drain(TASK).await;
    assert_eq!(fx.open(&sealed[0]).await.unwrap(), "epoch 0");

    fx.restart();
    assert_eq!(fx.e2ee.group_status(TASK), GroupStatus::Member);
    assert_eq!(fx.open(&fx.message("epoch 4")).await.unwrap(), "epoch 4");

    let db = lock(&fx.db);
    let row = db.get_e2ee_group(TASK).unwrap().unwrap();
    let snapshot = row.snapshot.unwrap();
    let group_id = gino_e2ee::group_id(PROFILE, TASK).unwrap();
    assert!(
        !snapshot.windows(32).any(|w| w == group_id),
        "snapshot is sealed"
    );
    let cache = db.list_e2ee_key_cache(TASK).unwrap();
    assert_eq!(cache.len(), 5, "epochs 0 to 4");
    for epoch in 0..=4 {
        let key = fx.client.history().cached(epoch).unwrap().content_key;
        for (_, row) in &cache {
            assert!(
                !row.secrets.windows(32).any(|w| w == key),
                "cache is sealed"
            );
        }
    }
}
