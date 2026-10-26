//! Remote operations while the runner holds an end-to-end encrypted task:
//! refused by default whatever the host enables, served with the runner-local
//! opt-in, black-box against the stub host.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use support::e2ee::{Client, group_row, latest_key_package, upsert_encrypted_task};
use support::fake_claude::{self, Behavior};
use support::stub_host::StubHost;
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const TASK: &str = "t-enc";

fn db_path(workspace: &Workspace) -> PathBuf {
    workspace.dir().parent().unwrap().join("agent.db")
}

/// The host enables both groups and also sends would-be opt-in keys, which no
/// host layer honours.
fn host_config() -> Value {
    json!({
        "heartbeatIntervalMs": 300,
        "remoteOps": {"fs": true, "pty": true, "allowWithE2ee": true, "allowRemoteOpsWithE2ee": true},
        "allowRemoteOpsWithE2ee": true,
    })
}

fn boot(host: &StubHost, workspace: &Workspace, opt_in: bool, log: &Path) -> RunnerProc {
    let mut envs: Vec<(&str, &OsStr)> = vec![
        ("RUST_LOG", OsStr::new("info")),
        ("NO_COLOR", OsStr::new("1")),
    ];
    if opt_in {
        envs.push(("GINO_ALLOW_REMOTE_OPS_WITH_E2EE", OsStr::new("1")));
    }
    RunnerProc::spawn_in_with_env(
        host,
        workspace,
        fake_claude::install(&Behavior::echo_lines("s", 1)),
        &envs,
        std::fs::File::create(log).unwrap().into(),
    )
}

/// Make the runner a member of `TASK`'s group.
async fn join(host: &StubHost, db: &Path) {
    assert!(host.wait_key_package_uploads(1, SETTLE).await, "no upload");
    let mut client = Client::create(TASK);
    upsert_encrypted_task(host, TASK, 1).await;
    client.add(host, latest_key_package(host).await, 1, 2).await;
    assert!(
        wait_until(SETTLE, || group_row(db, TASK)
            .is_some_and(|(status, _)| status == "member"))
        .await,
        "runner never joined: {:?}",
        group_row(db, TASK)
    );
}

async fn fs_list(host: &StubHost, req_id: &str) -> Value {
    host.push_frame(&json!({
        "type": "fs_request", "reqId": req_id, "data": {"op": "list", "path": "."},
    }))
    .await;
    host.wait_remote_op_reply(&["fs_response"], "reqId", req_id, SETTLE)
        .await
        .unwrap_or_else(|| panic!("no fs_response for {req_id}"))["data"]
        .clone()
}

async fn pty_open(host: &StubHost, pty_id: &str) -> Value {
    host.push_frame(&json!({
        "type": "pty_open", "ptyId": pty_id, "data": {"argv": ["/bin/sh", "-c", "sleep 30"]},
    }))
    .await;
    host.wait_remote_op_reply(&["pty_ready", "pty_exit"], "ptyId", pty_id, SETTLE)
        .await
        .unwrap_or_else(|| panic!("no answer to pty_open {pty_id}"))
}

#[tokio::test]
async fn remote_ops_are_refused_while_a_member_whatever_the_host_enables() {
    let host = StubHost::start(host_config()).await;
    let workspace = Workspace::new().await;
    let log = workspace.dir().parent().unwrap().join("daemon.log");
    let runner = boot(&host, &workspace, false, &log);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // No encrypted task yet: the host's switches apply.
    assert_eq!(fs_list(&host, "r-before").await["ok"], json!(true));
    assert_eq!(pty_open(&host, "p-before").await["type"], "pty_ready");

    join(&host, &db_path(&workspace)).await;

    // The terminal opened before the join ends with `denied`.
    let closed = host
        .wait_remote_op_reply(&["pty_exit"], "ptyId", "p-before", SETTLE)
        .await
        .expect("the open terminal is closed after the join");
    assert_eq!(closed["data"]["error"]["code"], "denied");

    let refused = fs_list(&host, "r-after").await;
    assert_eq!(refused["ok"], json!(false));
    assert_eq!(refused["error"]["code"], "denied");
    assert!(refused.get("entries").is_none());

    let refused = pty_open(&host, "p-after").await;
    assert_eq!(refused["type"], "pty_exit");
    assert_eq!(refused["data"]["error"]["code"], "denied");

    runner.shutdown().await;
    let log = std::fs::read_to_string(&log).unwrap();
    let refusals: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("refused a remote operation"))
        .collect();
    assert_eq!(refusals.len(), 2, "one line per refused operation: {log}");
    assert!(refusals.iter().all(|line| line.contains("reason=\"e2ee\"")));
    assert!(log.contains("closed a terminal session"));
    assert!(!log.contains("allow-remote-ops-with-e2ee is set"));
}

#[tokio::test]
async fn the_runner_local_opt_in_serves_remote_ops_while_a_member() {
    let host = StubHost::start(host_config()).await;
    let workspace = Workspace::new().await;
    let log = workspace.dir().parent().unwrap().join("daemon.log");
    let runner = boot(&host, &workspace, true, &log);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");
    join(&host, &db_path(&workspace)).await;

    assert_eq!(fs_list(&host, "r-1").await["ok"], json!(true));
    assert_eq!(pty_open(&host, "p-1").await["type"], "pty_ready");
    host.push_frame(&json!({"type": "pty_close", "ptyId": "p-1", "data": {}}))
        .await;
    let exit = host
        .wait_remote_op_reply(&["pty_exit"], "ptyId", "p-1", SETTLE)
        .await
        .unwrap();
    assert_ne!(exit["data"]["error"]["code"], "denied");

    runner.shutdown().await;
    let log = std::fs::read_to_string(&log).unwrap();
    assert!(
        log.lines()
            .any(|line| line.contains("WARN") && line.contains("allow-remote-ops-with-e2ee is set")),
        "startup warning: {log}"
    );
    assert!(!log.contains("refused a remote operation"));
}
