//! An engine run reaches the local agent API through `$GINO_RUNNER_BIN` with
//! its per-run token: it sees and changes only its own task, and the token is
//! revoked once the run ends. A `host_action` it records reaches the host on
//! its own thread.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

#[allow(dead_code)]
mod support;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use serde_json::{Value, json};

use support::stub_host::StubHost;
use support::{RunnerProc, SETTLE, Workspace, wait_until};

/// A fake `claude` that, for task `t-a` only, runs each CLI command and records
/// its stdout, stderr and exit code (plus the API env) as files under `out`.
fn claude_script(out: &Path) -> String {
    let init = json!({ "type": "system", "subtype": "init", "session_id": "sess-run", "model": "stub", "tools": [] });
    let result = json!({ "type": "result", "subtype": "success", "is_error": false, "result": "done", "session_id": "sess-run" });
    format!(
        r#"#!/usr/bin/env bash
set -u
out="{out}"
rec() {{ local n="$1"; shift; "$@" >"$out/$n.out" 2>"$out/$n.err"; echo $? >"$out/$n.rc"; }}
printf '%s\n' '{init}'
if [ "${{GINO_TASK_ID:-}}" = t-a ]; then
  printf '%s' "$GINO_AGENT_TOKEN" >"$out/token"
  printf '%s' "$GINO_AGENT_SOCK" >"$out/sock"
  rec task_list "$GINO_RUNNER_BIN" task list
  rec task_show_b "$GINO_RUNNER_BIN" task show t-b
  rec thread_show_b "$GINO_RUNNER_BIN" thread show th-b
  rec cron_pause_b "$GINO_RUNNER_BIN" cron pause "$(cat "$out/cron_b")"
  rec thread_list_b "$GINO_RUNNER_BIN" thread list --task-id t-b
  rec cron_list_b "$GINO_RUNNER_BIN" cron list --task-id t-b
  rec cron_create "$GINO_RUNNER_BIN" cron create --type interval --value 3600000 --prompt p
  rec cron_list "$GINO_RUNNER_BIN" cron list
  rec action "$GINO_RUNNER_BIN" action comment '{{"body":"hi"}}'
fi
printf '%s\n' '{result}'
"#,
        out = out.display()
    )
}

/// One request on a fresh connection; returns the response line.
fn request(stream: &mut BufReader<UnixStream>, method: &str, params: &Value) -> Value {
    let line = json!({ "v": 1, "id": "t", "method": method, "params": params });
    stream
        .get_mut()
        .write_all(format!("{line}\n").as_bytes())
        .unwrap();
    let mut response = String::new();
    stream.read_line(&mut response).unwrap();
    serde_json::from_str(&response).unwrap()
}

/// One operator-scope API call's `result`.
fn api(socket: &Path, method: &str, params: &Value) -> Value {
    let mut stream = BufReader::new(UnixStream::connect(socket).unwrap());
    request(&mut stream, method, params)["result"].clone()
}

/// What the engine recorded for command `name`: (stdout, stderr, exit code).
fn recorded(out: &Path, name: &str) -> (String, String, i32) {
    let read = |ext: &str| std::fs::read_to_string(out.join(format!("{name}.{ext}"))).unwrap();
    (read("out"), read("err"), read("rc").trim().parse().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_run_uses_the_agent_api_within_its_own_task() {
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let out = tempfile::tempdir().unwrap();
    let fakes = tempfile::tempdir().unwrap();
    let claude = fakes.path().join("claude");
    std::fs::write(&claude, claude_script(out.path())).unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");
    let socket = workspace.dir().join("run").join("agent.sock");
    assert!(
        wait_until(SETTLE, || socket.exists()).await,
        "agent socket never appeared"
    );

    // Task B with a thread and a cron, seeded first.
    host.push_task_upsert("t-b", Some("other"), Some("chat"), None, 1)
        .await;
    host.push_message("t-b", Some("th-b"), "seed", &[], 2).await;
    let run = host
        .wait_thread_terminal("th-b", SETTLE)
        .await
        .expect("no terminal result for th-b");
    assert_eq!(run.status, "succeeded", "run B: {run:?}");
    let cron_b = api(
        &socket,
        "cron.create",
        &json!({ "type": "interval", "value": "3600000", "prompt": "b", "task_id": "t-b" }),
    )["cron"]
        .clone();
    let cron_b_id = cron_b["id"].as_str().unwrap().to_owned();
    std::fs::write(out.path().join("cron_b"), &cron_b_id).unwrap();

    host.push_task_upsert("t-a", Some("mine"), Some("chat"), None, 3)
        .await;
    host.push_message("t-a", Some("th-a"), "probe", &[], 4)
        .await;
    let run = host
        .wait_thread_terminal("th-a", SETTLE)
        .await
        .expect("no terminal result for th-a");
    assert_eq!(run.status, "succeeded", "run A: {run:?}");

    // Listings cover only the run's own task.
    let (stdout, stderr, rc) = recorded(out.path(), "task_list");
    assert_eq!(rc, 0, "task list: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "task list: {stdout}");
    assert!(lines[0].starts_with("t-a\t"), "task list: {stdout}");

    // Another task's objects read as nonexistent.
    for (name, expected) in [
        ("task_show_b", "Error: no such task: t-b\n".to_owned()),
        ("thread_show_b", "Error: no such thread: th-b\n".to_owned()),
        (
            "cron_pause_b",
            format!("Error: no such cron: {cron_b_id}\n"),
        ),
    ] {
        let (stdout, stderr, rc) = recorded(out.path(), name);
        assert_ne!(rc, 0, "{name} succeeded: {stdout}");
        assert!(stdout.is_empty(), "{name} printed: {stdout}");
        assert_eq!(stderr, expected, "{name}");
    }
    let after = api(&socket, "cron.list", &json!({ "task_id": "t-b" }));
    assert_eq!(after["crons"], json!([cron_b]), "B's cron changed");

    // An explicit foreign task id is refused.
    for name in ["thread_list_b", "cron_list_b"] {
        let (stdout, stderr, rc) = recorded(out.path(), name);
        assert_ne!(rc, 0, "{name} succeeded: {stdout}");
        assert!(stdout.is_empty(), "{name} printed: {stdout}");
        assert!(stderr.starts_with("Error: "), "{name}: {stderr}");
    }

    // The run's own cron: created on its task, listed in the scoped form.
    let (stdout, stderr, rc) = recorded(out.path(), "cron_create");
    assert_eq!(rc, 0, "cron create: {stderr}");
    let cron_a = stdout.strip_suffix('\n').unwrap().to_owned();
    uuid::Uuid::parse_str(cron_a.strip_prefix("cron-").expect("cron id prefix"))
        .expect("cron id is cron-<uuid>");
    let (stdout, stderr, rc) = recorded(out.path(), "cron_list");
    assert_eq!(rc, 0, "cron list: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "cron list: {stdout}");
    assert!(
        lines[0].starts_with(&format!("{cron_a}\tactive\tinterval 3600000\t")),
        "cron list: {stdout}"
    );
    let mine = api(&socket, "cron.list", &json!({ "task_id": "t-a" }));
    assert_eq!(mine["crons"][0]["id"], cron_a.as_str());

    // `action` lands one host_action on the run's own thread, nowhere else.
    let (stdout, stderr, rc) = recorded(out.path(), "action");
    assert_eq!(rc, 0, "action: {stderr}");
    let seq: i64 = stdout.trim().parse().expect("action prints the seq");
    let actions: Vec<_> = host
        .messages_for("t-a", "th-a")
        .await
        .into_iter()
        .filter(|m| m.kind == "host_action")
        .collect();
    assert_eq!(actions.len(), 1, "host actions: {actions:?}");
    assert_eq!(actions[0].seq, seq);
    assert_eq!(
        actions[0].input,
        Some(json!({ "method": "comment", "params": { "body": "hi" } }))
    );
    assert!(
        host.messages_for("t-b", "th-b")
            .await
            .iter()
            .all(|m| m.kind != "host_action"),
        "host_action leaked onto th-b"
    );

    // The engine got the daemon's socket, and its token died with the run.
    let sock = std::fs::read_to_string(out.path().join("sock")).unwrap();
    assert_eq!(sock, socket.display().to_string());
    let token = std::fs::read_to_string(out.path().join("token")).unwrap();
    assert_eq!(token.len(), 64, "token: {token}");
    let auth = |socket: &Path| {
        let mut stream = BufReader::new(UnixStream::connect(socket).unwrap());
        request(&mut stream, "auth", &json!({ "token": token }))
    };
    assert!(
        wait_until(SETTLE, || auth(&socket)["error"]["code"]
            == "unauthenticated")
        .await,
        "token still valid after the run: {}",
        auth(&socket)
    );

    runner.shutdown().await;
}
