//! The real daemon serves the local agent API on `<workspace>/run/agent.sock`
//! and removes the socket on a graceful shutdown.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

#[allow(dead_code)]
mod support;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;

use serde_json::{Value, json};

use support::fake_claude::Behavior;
use support::stub_host::StubHost;
use support::{RunnerProc, SETTLE, Workspace, wait_until};

#[tokio::test(flavor = "multi_thread")]
async fn daemon_serves_system_info_to_the_operator() {
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let runner = RunnerProc::spawn_in(&host, &Behavior::echo_lines("sess-api", 1), &workspace);
    let socket = workspace.dir().join("run").join("agent.sock");
    assert!(
        wait_until(SETTLE, || socket.exists()).await,
        "agent socket never appeared"
    );
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let path = socket.clone();
    let response: Value = tokio::task::spawn_blocking(move || {
        let mut stream = UnixStream::connect(&path).unwrap();
        stream
            .write_all(b"{\"v\":1,\"id\":\"it\",\"method\":\"system.info\"}\n")
            .unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(response["id"], "it");
    assert_eq!(response["result"]["scope"], "operator");
    assert!(response["result"]["version"].is_string());

    // The socket's peer is the daemon itself; SIGTERM it for a graceful stop.
    let daemon_pid = tokio::net::UnixStream::connect(&socket)
        .await
        .unwrap()
        .peer_cred()
        .unwrap()
        .pid()
        .unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(daemon_pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    assert!(
        wait_until(SETTLE, || !socket.exists()).await,
        "agent socket not removed on shutdown"
    );

    runner.shutdown().await;
}
