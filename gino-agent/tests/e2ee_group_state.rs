//! E2ee group state, black-box against the stub host's DS: the runner joins
//! a task's group from a Welcome, applies delivered log entries in order and
//! catches up on the log after a reconnect.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::path::{Path, PathBuf};

use gino_e2ee::{
    CommitUnit, HistoryPolicy, Identity, MemoryKeyCache, ScopeGroup, decode_b64url, encode_b64url,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};

use support::fake_claude::Behavior;
use support::stub_host::StubHost;
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const PROFILE: &str = "gino.task-content.v1";
const TASK: &str = "t-enc";

/// The agent DB: the harness puts it beside the workspace.
fn db_path(workspace: &Workspace) -> PathBuf {
    workspace.dir().parent().unwrap().join("agent.db")
}

/// `(status, last_seq, snapshot)` of the task's group row.
fn group_row(db: &Path) -> Option<(String, Option<i64>, Option<Vec<u8>>)> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    conn.query_row(
        "SELECT status, last_seq, snapshot FROM e2ee_groups WHERE task_id = ?1",
        [TASK],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

fn applied(db: &Path, seq: i64) -> bool {
    group_row(db).is_some_and(|(status, last_seq, _)| status == "member" && last_seq == Some(seq))
}

/// The DS log entry of a commit accepted at `seq`.
fn commit_entry(unit: &CommitUnit, seq: u64) -> Value {
    json!({
        "seq": seq,
        "kind": "commit",
        "epoch": unit.epoch,
        "message": encode_b64url(&unit.commit),
        "drop_public_key": encode_b64url(&unit.drop_public_key),
    })
}

#[tokio::test]
async fn welcome_log_delivery_and_reconnect_catch_up() {
    let host = StubHost::start(json!({"heartbeatIntervalMs": 500})).await;
    let workspace = Workspace::new().await;
    let db = db_path(&workspace);
    let runner = RunnerProc::spawn_in(&host, &Behavior::echo_lines("s", 1), &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");
    assert!(host.wait_key_package_uploads(1, SETTLE).await, "no upload");
    let key_package = host.key_package_uploads().await[0]["one_time"][0]
        .as_str()
        .map(decode_b64url)
        .unwrap()
        .unwrap();

    // A client creates the task's group and adds the runner (commit seq 1).
    let identity = Identity::generate(&RustCrypto::default()).unwrap();
    let mut client: ScopeGroup<MemoryKeyCache> = ScopeGroup::create(
        &identity,
        PROFILE,
        TASK,
        HistoryPolicy::Full,
        MemoryKeyCache::default(),
    )
    .unwrap();
    let add = client.add_members(&identity, &[key_package], None).unwrap();
    client.commit_accepted(1).unwrap();
    host.ds_append(TASK, commit_entry(&add, 1)).await;
    if let Some(link) = &add.epoch_link {
        host.ds_put_link(TASK, 1, &encode_b64url(link)).await;
    }
    let group_id = encode_b64url(&gino_e2ee::group_id(PROFILE, TASK).unwrap());
    host.push_frame(&json!({
        "type": "task_upsert",
        "taskId": TASK,
        "msgId": support::stub_host::delivery_id(1),
        "data": { "name": "secret", "e2ee": { "profile_id": PROFILE, "group_id": group_id } },
    }))
    .await;
    host.push_e2ee_welcome(TASK, &encode_b64url(add.welcome.as_ref().unwrap()), 1, 2)
        .await;

    // A delivered commit applies in order.
    let update = client.self_update(&identity).unwrap();
    client.commit_accepted(2).unwrap();
    host.push_e2ee_log(TASK, commit_entry(&update, 2), 3).await;
    assert!(
        wait_until(SETTLE, || applied(&db, 2)).await,
        "log entry 2 not applied: {:?}",
        group_row(&db).map(|(status, seq, _)| (status, seq))
    );
    let (_, _, snapshot) = group_row(&db).unwrap();
    let raw_group_id = gino_e2ee::group_id(PROFILE, TASK).unwrap();
    assert!(
        !snapshot.unwrap().windows(32).any(|w| w == raw_group_id),
        "the snapshot is sealed at rest"
    );

    // A commit the runner never received is read back after a reconnect.
    let missed = client.self_update(&identity).unwrap();
    client.commit_accepted(3).unwrap();
    host.ds_append(TASK, commit_entry(&missed, 3)).await;
    host.drop_connection().await;
    assert!(host.wait_connects(2, SETTLE).await, "no reconnect");
    assert!(
        host.wait_e2ee_request(&json!({"op": "log", "after_seq": 2}), SETTLE)
            .await,
        "no catch-up read: {:?}",
        host.e2ee_requests().await
    );
    assert!(
        wait_until(SETTLE, || applied(&db, 3)).await,
        "catch-up not applied"
    );
    runner.shutdown().await;
}
