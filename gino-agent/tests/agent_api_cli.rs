//! The `gino-agent system|task|thread|cron|action` CLI talks to a running daemon over
//! the local agent API and prints the same text it always has.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

#[allow(dead_code)]
mod support;

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::{Value, json};

use support::fake_claude::Behavior;
use support::stub_host::StubHost;
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const BIN: &str = env!("CARGO_BIN_EXE_gino-agent");

/// Run the CLI in operator mode against `workspace` with `envs` added.
fn cli(workspace: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("GINO_WORKSPACE_DIR", workspace)
        .env("RUST_LOG", "off")
        .env_remove("GINO_AGENT_SOCK")
        .env_remove("GINO_AGENT_TOKEN")
        .env_remove("GINO_TASK_ID")
        .env_remove("GINO_THREAD_ID")
        .env_remove("GINO_DB_PATH")
        .envs(envs.iter().copied())
        .output()
        .expect("run gino-agent CLI")
}

/// Stdout of a successful CLI run.
fn ok(workspace: &Path, args: &[&str]) -> String {
    let out = cli(workspace, args, &[]);
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Stderr of a failing CLI run (stdout must be empty).
fn err(workspace: &Path, args: &[&str], envs: &[(&str, &str)]) -> String {
    let out = cli(workspace, args, envs);
    assert!(!out.status.success(), "{args:?} unexpectedly succeeded");
    assert!(out.stdout.is_empty(), "{args:?} printed to stdout");
    String::from_utf8(out.stderr).unwrap()
}

/// One operator-scope API call, for building the expected output.
fn api(socket: &Path, method: &str, params: &Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    let request = json!({ "v": 1, "id": "t", "method": method, "params": params });
    stream.write_all(format!("{request}\n").as_bytes()).unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    response["result"].clone()
}

fn s(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn or_dash(v: &Value) -> String {
    if v.is_null() { "-".to_owned() } else { s(v) }
}

fn cron_line(c: &Value, scoped: bool) -> String {
    let task = if scoped {
        String::new()
    } else {
        format!("task={}\t", s(&c["task_id"]))
    };
    format!(
        "{}\t{task}{}\t{} {}\tnext={}\tcontinuity={}\truns={}\tprompt={}\n",
        s(&c["id"]),
        s(&c["status"]),
        or_dash(&c["schedule_type"]),
        or_dash(&c["schedule_value"]),
        or_dash(&c["next_run"]),
        s(&c["continuity"]),
        c["run_count"],
        s(&c["prompt"]),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_prints_daemon_state_through_the_agent_api() {
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let runner = RunnerProc::spawn_in(&host, &Behavior::echo_lines("sess-cli", 1), &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");
    let ws = workspace.dir().to_path_buf();
    let socket = ws.join("run").join("agent.sock");
    assert!(
        wait_until(SETTLE, || socket.exists()).await,
        "agent socket never appeared"
    );

    host.push_task_upsert("t-cli", Some("CLI task"), Some("chat"), None, 1)
        .await;
    host.push_message("t-cli", Some("th-cli"), "hello", &[], 2)
        .await;
    let run = host
        .wait_thread_terminal("th-cli", SETTLE)
        .await
        .expect("no thread_result mirrored");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    // The local thread row records the result with the outbox write; wait for it.
    assert!(
        wait_until(SETTLE, || {
            api(&socket, "thread.show", &json!({ "id": "th-cli" }))["thread"]["result"] == "done"
        })
        .await,
        "local thread: {}",
        api(&socket, "thread.show", &json!({ "id": "th-cli" }))
    );

    // system: operator scope shows the daemon's own paths.
    let info = api(&socket, "system.info", &json!({}));
    assert_eq!(info["scope"], "operator");
    assert_eq!(s(&info["workspace_dir"]), ws.display().to_string());
    let caps: Vec<String> = info["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(s)
        .collect();
    let expected = format!(
        "version       : {}\n\
         agent_id      : {}\n\
         name          : {}\n\
         host_url      : {}\n\
         workspace_dir : {}\n\
         db_path       : {}\n\
         capabilities  : {}\n\
         tasks         : 1\n\
         active_crons  : 0\n\
         threads       : pending=0 running=0\n",
        env!("CARGO_PKG_VERSION"),
        s(&info["agent_id"]),
        or_dash(&info["name"]),
        or_dash(&info["host_url"]),
        ws.display(),
        s(&info["db_path"]),
        caps.join(", "),
    );
    assert_eq!(ok(&ws, &["system"]), expected);
    assert!(expected.contains("name          : e2e-runner\n"));

    // task list / task show
    let th = api(&socket, "thread.show", &json!({ "id": "th-cli" }))["thread"].clone();
    let source = s(&th["source"]);
    let th_status = s(&th["status"]);
    let task = api(&socket, "task.show", &json!({ "id": "t-cli" }));
    let status = s(&task["task"]["status"]);
    assert_eq!(
        ok(&ws, &["task", "list"]),
        format!("t-cli\t{status}\tchat\tCLI task\n")
    );
    assert_eq!(
        ok(&ws, &["task", "show", "t-cli"]),
        format!(
            "task    : t-cli\n\
             name    : CLI task\n\
             kind    : chat\n\
             status  : {status}\n\
             created : {}\n\
             threads : 1\n\
             \x20 th-cli\t{th_status}\t{source}\tsession=sess-cli\n\
             crons   : 0\n",
            s(&task["task"]["created_at"])
        )
    );

    // thread list / thread show
    assert_eq!(
        ok(&ws, &["thread", "list", "--task-id", "t-cli"]),
        format!(
            "th-cli\t{th_status}\t{source}\tattempt={}/{}\tsession=sess-cli\n",
            th["attempt"], th["max_attempts"]
        )
    );
    let mut expected = format!(
        "thread        : th-cli\n\
         task          : t-cli\n\
         source        : {source}\n\
         status        : {th_status}\n\
         engine        : {}\n\
         session_id    : sess-cli\n\
         attempt       : {}/{}\n",
        s(&th["engine"]),
        th["attempt"],
        th["max_attempts"]
    );
    if !th["duration_ms"].is_null() {
        writeln!(expected, "duration_ms   : {}", th["duration_ms"]).unwrap();
    }
    expected.push_str("prompt        : hello\nresult        : done\n");
    assert_eq!(ok(&ws, &["thread", "show", "th-cli"]), expected);

    // cron create prints just the new id.
    let create = |prompt: &str| {
        let out = ok(
            &ws,
            &[
                "cron",
                "create",
                "--type",
                "interval",
                "--value",
                "3600000",
                "--prompt",
                prompt,
                "--task-id",
                "t-cli",
            ],
        );
        let id = out.strip_suffix('\n').unwrap().to_owned();
        let uuid = id.strip_prefix("cron-").expect("cron id prefix");
        uuid::Uuid::parse_str(uuid).expect("cron id is cron-<uuid>");
        id
    };
    let cron_a = create("ping");

    // cron list, scoped and unscoped
    let list = api(&socket, "cron.list", &json!({ "task_id": "t-cli" }));
    let crons = list["crons"].as_array().unwrap();
    assert_eq!(crons.len(), 1);
    assert_eq!(
        ok(&ws, &["cron", "list", "--task-id", "t-cli"]),
        cron_line(&crons[0], true)
    );
    assert!(
        cron_line(&crons[0], true)
            .starts_with(&format!("{cron_a}\tactive\tinterval 3600000\tnext="))
    );
    let all = api(&socket, "cron.list", &json!({}));
    assert_eq!(all["scoped"], false);
    assert_eq!(
        ok(&ws, &["cron", "list"]),
        format!(
            "(no task id — listing ACTIVE crons across ALL tasks; pass --task-id to scope)\n{}",
            cron_line(&all["crons"][0], false)
        )
    );

    // pause / resume / cancel (alias) / delete
    assert_eq!(
        ok(&ws, &["cron", "pause", &cron_a]),
        format!("{cron_a} -> paused\n")
    );
    let resumed = ok(&ws, &["cron", "resume", &cron_a]);
    let after = api(&socket, "cron.list", &json!({ "task_id": "t-cli" }));
    assert_eq!(
        resumed,
        format!(
            "{cron_a} -> active (next={})\n",
            or_dash(&after["crons"][0]["next_run"])
        )
    );
    assert_eq!(
        ok(&ws, &["cron", "cancel", &cron_a]),
        format!("{cron_a} -> cancelled\n")
    );
    let cron_b = create("pong");
    assert_eq!(
        ok(&ws, &["cron", "delete", &cron_b]),
        format!("{cron_b} -> cancelled\n")
    );
    assert_eq!(
        ok(&ws, &["cron", "list"]),
        "(no task id — listing ACTIVE crons across ALL tasks; pass --task-id to scope)\n\
         (no crons)\n"
    );

    // Unknown ids read exactly as before.
    assert_eq!(
        err(&ws, &["task", "show", "t-nope"], &[]),
        "Error: no such task: t-nope\n"
    );
    assert_eq!(
        err(&ws, &["thread", "show", "th-nope"], &[]),
        "Error: no such thread: th-nope\n"
    );
    assert_eq!(
        err(&ws, &["cron", "pause", "cron-nope"], &[]),
        "Error: no such cron: cron-nope\n"
    );

    // Inside a run without a token there is no API to fall back to.
    assert_eq!(
        err(&ws, &["system"], &[("GINO_THREAD_ID", "th-cli")]),
        "Error: the local agent API is not available to this run\n"
    );

    // `action` is for engine runs; malformed params fail before any call.
    assert_eq!(
        err(&ws, &["action", "comment"], &[]),
        "Error: thread.action requires a run token\n"
    );
    for (params, expected) in [
        ("{not json", "Error: params must be valid JSON"),
        ("[1]", "Error: params must be a JSON object"),
        ("\"x\"", "Error: params must be a JSON object"),
    ] {
        let stderr = err(&ws, &["action", "comment", params], &[]);
        assert_eq!(stderr.lines().next(), Some(expected), "{params}: {stderr}");
    }

    // A killed daemon leaves nothing listening on the socket.
    runner.shutdown().await;
    for args in [
        &["system"][..],
        &["task", "list"],
        &["cron", "list", "--task-id", "t-cli"],
    ] {
        let stderr = err(&ws, args, &[]);
        assert_eq!(
            stderr.lines().next(),
            Some("Error: the agent is not running"),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn cli_without_a_daemon_reports_the_agent_not_running() {
    let empty = tempfile::tempdir().unwrap();
    for args in [
        &["system"][..],
        &["thread", "show", "th-x"],
        &["cron", "pause", "c-x"],
        &["action", "comment", "{}"],
    ] {
        let stderr = err(empty.path(), args, &[]);
        assert_eq!(
            stderr.lines().next(),
            Some("Error: the agent is not running"),
            "{args:?}: {stderr}"
        );
    }
    // Params are validated before connecting.
    let stderr = err(empty.path(), &["action", "comment", "{not json"], &[]);
    assert_eq!(
        stderr.lines().next(),
        Some("Error: params must be valid JSON"),
        "{stderr}"
    );
}
