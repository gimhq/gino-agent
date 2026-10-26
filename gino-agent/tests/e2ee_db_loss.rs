//! Agent DB loss, black-box against the stub host: the runner re-registers
//! with the same e2ee identity key, publishes a fresh KeyPackage pool, holds
//! no group state for an encrypted task it receives again (a sealed turn
//! fails `not_member` without an engine spawn), and is a member that runs
//! sealed turns again once a client removes its old leaf and adds a fresh
//! KeyPackage.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::path::{Path, PathBuf};

use gino_e2ee::Identity;
use serde_json::json;

use support::e2ee::{Client, group_row, latest_key_package, upsert_encrypted_task};
use support::fake_claude::{Behavior, PROMPT_SEEN_FILE};
use support::stub_host::{StubHost, ThreadRun};
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const TASK: &str = "t-enc";
const BEFORE: &str = "PLAINTEXT-BEFORE-3c71";
const AFTER: &str = "PLAINTEXT-AFTER-REFERS-TO-BEFORE-9d02";

#[tokio::test]
async fn a_lost_agent_db_leaves_the_task_without_group_state_until_re_added() {
    let host = StubHost::start(json!({"heartbeatIntervalMs": 500})).await;
    let workspace = Workspace::new().await;
    let state_dir = workspace.dir().parent().unwrap().to_path_buf();
    let db = state_dir.join("agent.db");
    let identity_file = state_dir.join("e2ee-identity.key");

    let behavior = Behavior::Prompt {
        session_id: "s".to_owned(),
    };
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_key_package_uploads(1, SETTLE).await, "no upload");
    let first_key_package = latest_key_package(&host).await;
    let mut client = Client::create(TASK);
    upsert_encrypted_task(&host, TASK, 1).await;
    client.add(&host, first_key_package.clone(), 1, 2).await;
    assert!(
        wait_until(SETTLE, || member_at(&db, 1)).await,
        "never joined"
    );
    let update = client.group.self_update(&client.identity).unwrap();
    let entry = client.accept(&host, &update, 2).await;
    host.push_e2ee_log(TASK, entry, 3).await;
    assert!(
        wait_until(SETTLE, || member_at(&db, 2)).await,
        "update not applied"
    );
    host.push_frame(&client.sealed_message("th-before", BEFORE, 4))
        .await;
    let run = terminal(&host, "th-before").await;
    assert_eq!(run.status, "succeeded", "{run:?}");
    assert!(
        prompt_seen(&workspace, "th-before")
            .unwrap()
            .contains(BEFORE)
    );
    runner.shutdown().await;

    // Lose the agent DB; the rest of the state dir stays.
    let seed = std::fs::read(&identity_file).unwrap();
    for suffix in ["", "-wal", "-shm"] {
        let mut path = db.clone().into_os_string();
        path.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(path));
    }

    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connects(2, SETTLE).await, "no reconnect");
    let registers = host.register_bodies().await;
    assert_eq!(registers.len(), 2, "the runner registers again");
    assert_eq!(
        registers[1]["e2ee"], registers[0]["e2ee"],
        "same identity key"
    );
    assert_eq!(std::fs::read(&identity_file).unwrap(), seed);
    assert!(
        host.wait_key_package_uploads(2, SETTLE).await,
        "no fresh pool"
    );
    let fresh_key_package = latest_key_package(&host).await;
    assert_ne!(fresh_key_package, first_key_package);

    // The task arrives again: encrypted, no group state.
    upsert_encrypted_task(&host, TASK, 10).await;
    assert!(
        wait_until(SETTLE, || group_row(&db, TASK)
            == Some(("pending".to_owned(), None)))
        .await,
        "{:?}",
        group_row(&db, TASK)
    );

    // A sealed turn without group state fails, and the engine never runs.
    host.push_frame(&client.sealed_message("th-pending", BEFORE, 12))
        .await;
    let run = terminal(&host, "th-pending").await;
    assert_eq!(run.status, "failed", "{run:?}");
    assert_eq!(run.failure_reason.as_deref(), Some("agent.encryption"));
    assert_eq!(
        run.encryption_error
            .as_ref()
            .and_then(|error| error["code"].as_str()),
        Some("not_member"),
        "{run:?}"
    );
    assert_eq!(run.result, None);
    assert_eq!(run.error, None);
    assert!(run.attachments.is_empty());
    assert!(
        prompt_seen(&workspace, "th-pending").is_none(),
        "the engine was spawned"
    );
    assert!(
        host.messages_for(TASK, "th-pending").await.is_empty(),
        "a thread_message was sent"
    );

    // A client removes the old leaf, then adds the fresh KeyPackage.
    let runner_key = Identity::from_seed(&seed.clone().try_into().unwrap()).public_key();
    let remove = client
        .group
        .remove_members(&client.identity, &[runner_key])
        .unwrap();
    client.accept(&host, &remove, 3).await;
    client.add(&host, fresh_key_package, 4, 11).await;
    assert!(
        wait_until(SETTLE, || member_at(&db, 4)).await,
        "not re-added: {:?}",
        group_row(&db, TASK)
    );

    // A sealed turn referring to the pre-loss history runs normally.
    host.push_frame(&client.sealed_message("th-after", AFTER, 13))
        .await;
    let run = terminal(&host, "th-after").await;
    assert_eq!(run.status, "succeeded", "{run:?}");
    assert!(prompt_seen(&workspace, "th-after").unwrap().contains(AFTER));
    runner.shutdown().await;
}

async fn terminal(host: &StubHost, thread_id: &str) -> ThreadRun {
    host.wait_thread_terminal(thread_id, SETTLE)
        .await
        .unwrap_or_else(|| panic!("no thread_result for {thread_id}"))
}

/// The user turn the engine received for `thread_id`, if it was spawned.
fn prompt_seen(workspace: &Workspace, thread_id: &str) -> Option<String> {
    find_file(
        &workspace.dir().join("threads").join(thread_id),
        PROMPT_SEEN_FILE,
    )
    .map(|path| std::fs::read_to_string(path).unwrap())
}

fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|file| file == name) {
            return Some(path);
        }
    }
    None
}

fn member_at(db: &Path, seq: i64) -> bool {
    group_row(db, TASK) == Some(("member".to_owned(), Some(seq)))
}
