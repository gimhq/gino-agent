use super::*;
use tokio::time::timeout;

fn send(
    sessions: &mut Sessions,
    ops: &RemoteOps,
    tx: &mpsc::Sender<String>,
    kind: &str,
    id: &str,
    data: Value,
) {
    sessions.handle(parse(&envelope(kind, id, data)).unwrap(), ops, tx);
}

async fn next(rx: &mut mpsc::Receiver<String>) -> Value {
    serde_json::from_str(
        &timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap()
}

async fn until_exit(rx: &mut mpsc::Receiver<String>) -> (Vec<u8>, Value) {
    let mut output = Vec::new();
    loop {
        let frame = next(rx).await;
        if frame["type"] == "pty_output" {
            output.extend(
                STANDARD
                    .decode(frame["data"]["data"].as_str().unwrap())
                    .unwrap(),
            );
        }
        if frame["type"] == "pty_exit" {
            return (output, frame["data"].clone());
        }
    }
}

#[tokio::test]
async fn real_terminal_round_trip_resize_and_final_output() {
    let dir = tempfile::tempdir().unwrap();
    let ops = RemoteOps::new(false, dir.path());
    ops.configure(false, true, dir.path());
    let mut sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(64);
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_open",
        "p",
        json!({
            "argv": ["/bin/sh", "-c", "test -t 0 && test -t 1 && test -t 2 || exit 9; read line; stty size; printf 'answer:%s' \"$line\"; exit 7"],
            "cols": 80, "rows": 24,
        }),
    );
    assert_eq!(next(&mut rx).await["type"], "pty_ready");
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_resize",
        "p",
        json!({ "cols": 120, "rows": 40 }),
    );
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_input",
        "p",
        json!({ "data": STANDARD.encode(b"hello\n") }),
    );
    let (output, exit) = until_exit(&mut rx).await;
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("40 120"), "{output}");
    assert!(output.contains("answer:hello"), "{output}");
    assert_eq!(exit["exit_code"], 7);
    sessions.shutdown().await;
}

#[tokio::test]
async fn off_by_default_and_invalid_opens_never_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let ops = RemoteOps::new(false, dir.path());
    let mut sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(64);
    send(&mut sessions, &ops, &tx, "pty_open", "p", json!({}));
    assert_eq!(next(&mut rx).await["data"]["error"]["code"], "disabled");
    ops.configure(false, true, dir.path());
    for data in [
        json!({ "cols": 0 }),
        json!({ "argv": [] }),
        json!({ "argv": ["/nonexistent-shell"] }),
    ] {
        send(&mut sessions, &ops, &tx, "pty_open", "p", data);
        assert_eq!(next(&mut rx).await["data"]["error"]["code"], "invalid");
    }
    assert!(sessions.sessions.is_empty());
}

#[tokio::test]
async fn disable_and_disconnect_reap_terminal_process() {
    for disable in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let ops = RemoteOps::new(false, dir.path());
        ops.configure(false, true, dir.path());
        let mut sessions = Sessions::default();
        let (tx, mut rx) = mpsc::channel(64);
        send(
            &mut sessions,
            &ops,
            &tx,
            "pty_open",
            "p",
            json!({
                "argv": ["/bin/sh", "-c", "echo $$; exec sleep 60"],
            }),
        );
        assert_eq!(next(&mut rx).await["type"], "pty_ready");
        let frame = next(&mut rx).await;
        let bytes = STANDARD
            .decode(frame["data"]["data"].as_str().unwrap())
            .unwrap();
        let pid: i32 = String::from_utf8_lossy(&bytes).trim().parse().unwrap();
        if disable {
            ops.configure(false, false, dir.path());
            // A rapid re-enable must not revive an already revoked session.
            ops.configure(false, true, dir.path());
            assert_eq!(until_exit(&mut rx).await.1["error"]["code"], "disabled");
        }
        sessions.shutdown().await;
        assert_eq!(
            nix::sys::signal::kill(Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }
}

#[tokio::test]
async fn ctrl_c_interrupts_foreground_program() {
    let dir = tempfile::tempdir().unwrap();
    let ops = RemoteOps::new(false, dir.path());
    ops.configure(false, true, dir.path());
    let mut sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(64);
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_open",
        "p",
        json!({ "argv": ["/bin/sh", "-c", "printf ready; exec sleep 60"] }),
    );
    assert_eq!(next(&mut rx).await["type"], "pty_ready");
    assert_eq!(next(&mut rx).await["type"], "pty_output");
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_input",
        "p",
        json!({ "data": STANDARD.encode([3]) }),
    );
    let (_, exit) = until_exit(&mut rx).await;
    assert_eq!(exit["signal"], 2);
    sessions.shutdown().await;
}

#[tokio::test]
async fn closed_output_channel_allows_prompt_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let ops = RemoteOps::new(false, dir.path());
    ops.configure(false, true, dir.path());
    let mut sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(1);
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_open",
        "p",
        json!({ "argv": ["/bin/sh", "-c", "while :; do printf x; done"] }),
    );
    assert_eq!(next(&mut rx).await["type"], "pty_ready");
    drop(rx);
    timeout(Duration::from_secs(2), sessions.shutdown())
        .await
        .unwrap();
}

#[tokio::test]
async fn exit_is_prompt_when_a_descendant_keeps_the_terminal_open() {
    let dir = tempfile::tempdir().unwrap();
    let ops = RemoteOps::new(false, dir.path());
    ops.configure(false, true, dir.path());
    let mut sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(64);
    // Job control puts the background job in its own process group, so it
    // outlives the shell and keeps the terminal open.
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_open",
        "p",
        json!({ "argv": ["/bin/sh", "-c", "set -m; sleep 60 & echo pid:$!; exit 3"] }),
    );
    assert_eq!(next(&mut rx).await["type"], "pty_ready");
    let (output, exit) = timeout(Duration::from_secs(2), until_exit(&mut rx))
        .await
        .unwrap();
    let output = String::from_utf8_lossy(&output);
    let pid: i32 = output
        .split("pid:")
        .nth(1)
        .and_then(|rest| rest.trim().parse().ok())
        .unwrap_or_else(|| panic!("{output}"));
    let _ = nix::sys::signal::kill(Pid::from_raw(pid), Signal::SIGKILL);
    assert_eq!(exit, json!({ "exit_code": 3 }));
    sessions.shutdown().await;
}

#[tokio::test]
async fn input_overflow_and_malformed_input_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let ops = RemoteOps::new(false, dir.path());
    ops.configure(false, true, dir.path());
    let mut sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(64);
    let open = json!({ "argv": ["/bin/sh", "-c", "exec sleep 60"] });

    send(&mut sessions, &ops, &tx, "pty_open", "full", open.clone());
    assert_eq!(next(&mut rx).await["type"], "pty_ready");
    // No await between sends: the session cannot drain its queue.
    for _ in 0..=INPUT_QUEUE {
        send(
            &mut sessions,
            &ops,
            &tx,
            "pty_input",
            "full",
            json!({ "data": STANDARD.encode(b"x") }),
        );
    }
    assert_eq!(
        until_exit(&mut rx).await.1["error"]["code"],
        "input_overflow"
    );

    send(&mut sessions, &ops, &tx, "pty_open", "bad", open);
    assert_eq!(next(&mut rx).await["type"], "pty_ready");
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_input",
        "bad",
        json!({ "data": "!" }),
    );
    assert_eq!(until_exit(&mut rx).await.1["error"]["code"], "invalid");
    sessions.shutdown().await;
}

#[test]
fn input_validation_preserves_binary_and_rejects_oversized_data() {
    let bytes = vec![0, 255, 27, 3];
    assert_eq!(
        decode_input(&json!({ "data": STANDARD.encode(&bytes) })),
        Some(bytes)
    );
    assert!(decode_input(&json!({ "data": "!" })).is_none());
    assert!(decode_input(&json!({ "data": STANDARD.encode(vec![0; MAX_BYTES + 1]) })).is_none());
}

#[tokio::test]
async fn a_denied_open_answers_denied_and_spawns_nothing() {
    let sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(64);
    let frame = parse(&envelope("pty_open", "p", json!({}))).unwrap();
    assert!(frame.is_open());
    sessions.deny_open(&frame, &tx);
    let exit = next(&mut rx).await;
    assert_eq!(exit["type"], "pty_exit");
    assert_eq!(exit["ptyId"], "p");
    assert_eq!(exit["data"]["error"]["code"], "denied");
    assert!(sessions.is_idle());
    assert!(
        !parse(&envelope("pty_input", "p", json!({})))
            .unwrap()
            .is_open()
    );
}

#[tokio::test]
async fn deny_all_ends_running_sessions_with_denied() {
    let dir = tempfile::tempdir().unwrap();
    let ops = RemoteOps::new(false, dir.path());
    ops.configure(false, true, dir.path());
    let mut sessions = Sessions::default();
    let (tx, mut rx) = mpsc::channel(64);
    send(
        &mut sessions,
        &ops,
        &tx,
        "pty_open",
        "p",
        json!({ "argv": ["/bin/sh", "-c", "sleep 30"] }),
    );
    assert_eq!(next(&mut rx).await["type"], "pty_ready");
    assert!(!sessions.is_idle());

    sessions.deny_all();
    let (_, exit) = until_exit(&mut rx).await;
    assert_eq!(exit["error"]["code"], "denied");
    sessions.shutdown().await;
    assert!(sessions.is_idle());
}
