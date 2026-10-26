//! A client member of a task's e2ee group, driven in-test against the stub
//! host's DS.

use std::path::Path;

use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{
    CommitUnit, HistoryPolicy, Identity, MemoryKeyCache, ScopeGroup, decode_b64url, encode_b64url,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};

use super::stub_host::{StubHost, delivery_id};

pub const PROFILE: &str = "gino.task-content.v1";

/// A client that created a task's group.
pub struct Client {
    pub identity: Identity,
    pub group: ScopeGroup<MemoryKeyCache>,
    task: String,
}

impl Client {
    #[must_use]
    pub fn create(task: &str) -> Self {
        let identity = Identity::generate(&RustCrypto::default()).unwrap();
        let group = ScopeGroup::create(
            &identity,
            PROFILE,
            task,
            HistoryPolicy::Full,
            MemoryKeyCache::default(),
        )
        .unwrap();
        Self {
            identity,
            group,
            task: task.to_owned(),
        }
    }

    /// Log `unit` at the DS as accepted at `seq`, with its epoch link; returns
    /// the log entry.
    pub async fn accept(&mut self, host: &StubHost, unit: &CommitUnit, seq: u64) -> Value {
        self.group.commit_accepted(seq).unwrap();
        let entry = json!({
            "seq": seq,
            "kind": "commit",
            "epoch": unit.epoch,
            "message": encode_b64url(&unit.commit),
            "drop_public_key": encode_b64url(&unit.drop_public_key),
        });
        host.ds_append(&self.task, entry.clone()).await;
        if let Some(link) = &unit.epoch_link {
            host.ds_put_link(&self.task, unit.epoch + 1, &encode_b64url(link))
                .await;
        }
        entry
    }

    /// Add `key_package` as commit `seq` and deliver the Welcome.
    pub async fn add(&mut self, host: &StubHost, key_package: Vec<u8>, seq: u64, msg_id: i64) {
        let unit = self
            .group
            .add_members(&self.identity, &[key_package], None)
            .unwrap();
        self.accept(host, &unit, seq).await;
        host.push_e2ee_welcome(
            &self.task,
            &encode_b64url(unit.welcome.as_ref().unwrap()),
            seq,
            msg_id,
        )
        .await;
    }

    /// A `message` frame for `thread_id` whose `text` is sealed under the
    /// current epoch.
    #[must_use]
    pub fn sealed_message(&self, thread_id: &str, text: &str, msg_id: i64) -> Value {
        let frame = json!({
            "type": "message",
            "taskId": self.task,
            "threadId": thread_id,
            "data": { "text": text },
        });
        let (epoch, secrets) = self.group.current().unwrap();
        let mut frame = FieldMap::for_profile(PROFILE)
            .unwrap()
            .seal_frame(
                "message",
                &frame,
                epoch,
                &secrets.content_key,
                &RustCrypto::default(),
            )
            .unwrap();
        frame["msgId"] = Value::from(delivery_id(msg_id));
        frame
    }
}

/// Deliver the `task_upsert` that marks `task` end-to-end encrypted.
pub async fn upsert_encrypted_task(host: &StubHost, task: &str, msg_id: i64) {
    let group_id = encode_b64url(&gino_e2ee::group_id(PROFILE, task).unwrap());
    host.push_frame(&json!({
        "type": "task_upsert",
        "taskId": task,
        "msgId": delivery_id(msg_id),
        "data": { "name": "secret", "e2ee": { "profile_id": PROFILE, "group_id": group_id } },
    }))
    .await;
}

/// The latest uploaded one-time KeyPackage.
pub async fn latest_key_package(host: &StubHost) -> Vec<u8> {
    let uploads = host.key_package_uploads().await;
    let upload = uploads
        .iter()
        .rev()
        .find(|upload| upload["one_time"].is_array())
        .unwrap();
    decode_b64url(upload["one_time"][0].as_str().unwrap()).unwrap()
}

/// `(status, last_seq)` of `task`'s group row in the agent DB.
#[must_use]
pub fn group_row(db: &Path, task: &str) -> Option<(String, Option<i64>)> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    conn.query_row(
        "SELECT status, last_seq FROM e2ee_groups WHERE task_id = ?1",
        [task],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .ok()
}
