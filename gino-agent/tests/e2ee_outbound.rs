//! E2ee outbound, black-box against the stub host: every mapped field of an
//! encrypted task's transcript, result and output files is sealed before the
//! outbox enqueue and opens for a client member under its exact location; the
//! agent DB keeps only the sealed form; a host action whose method the profile
//! does not declare is refused and never sent; a frame that cannot be sealed
//! is never sent and the thread fails `agent.encryption`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{Location, decode_b64url};
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};
use tempfile::TempDir;

use support::e2ee::{Client, PROFILE, group_row, latest_key_package, upsert_encrypted_task};
use support::stub_host::{StubHost, ThreadRun, delivery_id, sha256_hex};
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const TASK: &str = "t-out";
const PROMPT: &str = "PLAINTEXT-PROMPT-31a8";
const THINK: &str = "PLAINTEXT-THINK-6b02";
const TEXT: &str = "PLAINTEXT-TEXT-c4f1";
const INPUT: &str = "PLAINTEXT-INPUT-9e3d";
const OUTPUT: &str = "PLAINTEXT-OUTPUT-17aa";
const METHOD: &str = "plaintext-method-3a71";
const ACTION: &str = "PLAINTEXT-ACTION-5d6e";
const ACTION_LATE: &str = "PLAINTEXT-ACTION-LATE-8a40";
const AFTER: &str = "PLAINTEXT-AFTER-e019";
const RESULT: &str = "PLAINTEXT-RESULT-0c55";
const FILE_NAME: &str = "secret-out-80f2.txt";
const FILE_BYTES: &str = "PLAINTEXT-FILE-2b7c";

/// One stream-json stdout line of the fake engine.
fn emit(line: &Value) -> String {
    format!("printf '%s\\n' '{line}'\n")
}

/// A fake `claude` producing every mapped transcript field: thinking, text, a
/// tool call and its result, a host action attempt, an output file; then,
/// when `$out/<thread>.hold` exists, it waits for `$out/<thread>.release`;
/// then a second host action attempt, more text and the result. The host
/// actions' exit codes land in `$out/<thread>.action.rc` and
/// `$out/<thread>.late.rc`.
fn claude_script(out: &Path) -> String {
    let init = json!({ "type": "system", "subtype": "init", "session_id": "s-out", "model": "stub", "tools": [] });
    let assistant = json!({
        "type": "assistant",
        "message": { "role": "assistant", "content": [
            { "type": "thinking", "thinking": THINK },
            { "type": "text", "text": TEXT },
            { "type": "tool_use", "id": "tu-1", "name": "Read", "input": { "path": INPUT } },
        ]},
    });
    let tool_result = json!({
        "type": "user",
        "message": { "role": "user", "content": [
            { "type": "tool_result", "tool_use_id": "tu-1", "content": OUTPUT },
        ]},
    });
    let after = json!({
        "type": "assistant",
        "message": { "role": "assistant", "content": [ { "type": "text", "text": AFTER } ] },
    });
    let result = json!({ "type": "result", "subtype": "success", "is_error": false, "result": RESULT, "session_id": "s-out" });
    let mut script = format!(
        "#!/usr/bin/env bash\nset -u\nout=\"{}\"\nt=\"${{GINO_THREAD_ID:-none}}\"\n",
        out.display()
    );
    script.push_str(&emit(&init));
    script.push_str(&emit(&assistant));
    script.push_str(&emit(&tool_result));
    let _ = writeln!(
        script,
        "\"$GINO_RUNNER_BIN\" action {METHOD} '{{\"body\":\"{ACTION}\"}}' >/dev/null 2>&1; echo $? >\"$out/$t.action.rc\""
    );
    let _ = writeln!(
        script,
        "mkdir -p ../output\nprintf '%s' '{FILE_BYTES}' > ../output/{FILE_NAME}"
    );
    script.push_str(concat!(
        "if [ -e \"$out/$t.hold\" ]; then\n",
        "  touch \"$out/$t.held\"\n",
        "  for _ in $(seq 1 300); do [ -e \"$out/$t.release\" ] && break; sleep 0.1; done\n",
        "fi\n",
    ));
    let _ = writeln!(
        script,
        "\"$GINO_RUNNER_BIN\" action {METHOD} '{{\"body\":\"{ACTION_LATE}\"}}' >/dev/null 2>&1; echo $? >\"$out/$t.late.rc\""
    );
    script.push_str(&emit(&after));
    script.push_str(&emit(&result));
    script
}

/// A runner on the stub host, member of the encrypted task's group.
struct Fixture {
    host: StubHost,
    workspace: Workspace,
    runner: RunnerProc,
    client: Client,
    out: TempDir,
    msg_id: i64,
}

impl Fixture {
    async fn connect() -> Self {
        let host = StubHost::start(json!({"heartbeatIntervalMs": 500})).await;
        let workspace = Workspace::new().await;
        let out = tempfile::tempdir().unwrap();
        let fakes = tempfile::tempdir().unwrap();
        let claude = fakes.path().join("claude");
        std::fs::write(&claude, claude_script(out.path())).unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
        assert!(host.wait_connected(SETTLE).await, "runner never connected");
        assert!(host.wait_key_package_uploads(1, SETTLE).await, "no upload");

        let mut client = Client::create(TASK);
        upsert_encrypted_task(&host, TASK, 1).await;
        client
            .add(&host, latest_key_package(&host).await, 1, 2)
            .await;
        let fx = Self {
            host,
            workspace,
            runner,
            client,
            out,
            msg_id: 2,
        };
        let db = fx.db_path();
        assert!(
            wait_until(SETTLE, || group_row(&db, TASK)
                .is_some_and(|(status, _)| status == "member"))
            .await,
            "the runner never joined: {:?}",
            group_row(&db, TASK)
        );
        fx
    }

    fn next_msg_id(&mut self) -> i64 {
        self.msg_id += 1;
        self.msg_id
    }

    fn db_path(&self) -> PathBuf {
        self.workspace.dir().parent().unwrap().join("agent.db")
    }

    /// Push the client-sealed prompt of a new thread.
    async fn push_prompt(&mut self, thread_id: &str) {
        let frame = json!({ "type": "message", "taskId": TASK, "threadId": thread_id, "data": { "text": PROMPT } });
        let (epoch, secrets) = self.client.group.current().unwrap();
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
        frame["msgId"] = Value::from(delivery_id(self.next_msg_id()));
        self.host.push_frame(&frame).await;
    }

    async fn terminal(&self, thread_id: &str) -> ThreadRun {
        self.host
            .wait_thread_terminal(thread_id, SETTLE)
            .await
            .unwrap_or_else(|| panic!("no thread_result for {thread_id}"))
    }

    /// Open the sealed `value` at `location` as the client.
    fn open(&mut self, value: &Value, location: &Location) -> Result<Vec<u8>, gino_e2ee::Error> {
        let envelope = sealed_envelope(value);
        self.client
            .group
            .open(&envelope, location, |_| None)
            .map(|opened| opened.plaintext)
            .map_err(|error| error.encryption_error().unwrap())
    }

    fn rc(&self, thread_id: &str, name: &str) -> Option<i32> {
        std::fs::read_to_string(self.out.path().join(format!("{thread_id}.{name}.rc")))
            .ok()
            .map(|rc| rc.trim().parse().unwrap())
    }

    /// The bytes of the agent DB and its WAL.
    fn db_bytes(&self) -> Vec<u8> {
        let mut bytes = std::fs::read(self.db_path()).unwrap();
        if let Ok(wal) = std::fs::read(self.db_path().with_extension("db-wal")) {
            bytes.extend(wal);
        }
        bytes
    }

    async fn shutdown(self) {
        self.runner.shutdown().await;
        drop(self.workspace);
    }
}

/// The envelope of a sealed value: exactly `{"e2ee": "<base64url>"}`.
fn sealed_envelope(value: &Value) -> Vec<u8> {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("not sealed: {value}"));
    assert_eq!(object.len(), 1, "not exactly one member: {value}");
    decode_b64url(object["e2ee"].as_str().unwrap()).unwrap()
}

fn transcript_location(thread_id: &str, seq: u64, field: &str) -> Location {
    Location::new(TASK)
        .unwrap()
        .part("frame", "thread_message")
        .unwrap()
        .part("thread", thread_id)
        .unwrap()
        .part_u64("seq", seq)
        .unwrap()
        .part("field", field)
        .unwrap()
}

fn result_location(thread_id: &str, outbox_id: &str, field: &str) -> Location {
    Location::new(TASK)
        .unwrap()
        .part("frame", "thread_result")
        .unwrap()
        .part("thread", thread_id)
        .unwrap()
        .part("delivery", outbox_id)
        .unwrap()
        .part("field", field)
        .unwrap()
}

fn query_strings(db: &Path, sql: &str) -> Vec<String> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = conn.prepare(sql).unwrap();
    statement
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Every mapped field of a `thread_message` frame, opened:
/// `(kind, field, plaintext)`. Panics on a mapped field that is not sealed or
/// does not open at its location.
fn open_transcript(
    fx: &mut Fixture,
    thread_id: &str,
    frame: &Value,
) -> Vec<(String, String, Vec<u8>)> {
    let data = &frame["data"];
    let seq = data["seq"].as_u64().unwrap();
    let kind = data["kind"].as_str().unwrap().to_owned();
    assert_ne!(kind, "host_action", "a host action was sent: {data}");
    let mut fields = vec![("content", &data["content"]), ("input", &data["input"])];
    if !data["output"].is_null() {
        assert!(
            data["output"]["is_error"].is_boolean(),
            "is_error stays cleartext"
        );
        fields.push(("output.content", &data["output"]["content"]));
    }
    fields
        .into_iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(field, value)| {
            let plaintext = fx
                .open(value, &transcript_location(thread_id, seq, field))
                .unwrap_or_else(|error| panic!("seq {seq} {field} does not open: {error:?}"));
            (kind.clone(), field.to_owned(), plaintext)
        })
        .collect()
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

/// Call the daemon's local agent API as the operator.
async fn api_call(workspace: &Workspace, method: &str, params: Value) -> Value {
    let socket = workspace.dir().join("run").join("agent.sock");
    assert!(
        wait_until(SETTLE, || socket.exists()).await,
        "agent socket never appeared"
    );
    let request = json!({ "v": 1, "id": "it", "method": method, "params": params });
    tokio::task::spawn_blocking(move || {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(format!("{request}\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_outbound_field_is_sealed_before_the_outbox_and_opens_for_members() {
    let mut fx = Fixture::connect().await;
    fx.push_prompt("th-1").await;
    let run = fx.terminal("th-1").await;
    assert_eq!(run.status, "succeeded", "{run:?}");
    // The profile declares no host-action method: both actions are refused.
    for name in ["action", "late"] {
        let rc = fx.rc("th-1", name).expect("the action never ran");
        assert_ne!(rc, 0, "an undeclared thread.action succeeded");
    }

    // Transcript: every mapped field is sealed and opens under its seq.
    let frames = fx.host.thread_frames("th-1").await;
    let mut opened = Vec::new();
    for frame in frames.iter().filter(|f| f["type"] == "thread_message") {
        opened.extend(open_transcript(&mut fx, "th-1", frame));
    }
    for expected in [
        ("thinking", "content", THINK.as_bytes().to_vec()),
        ("assistant_text", "content", TEXT.as_bytes().to_vec()),
        ("assistant_text", "content", AFTER.as_bytes().to_vec()),
        ("tool_use", "input", json_bytes(&json!({ "path": INPUT }))),
        ("tool_result", "output.content", json_bytes(&json!(OUTPUT))),
    ] {
        let (kind, field, plaintext) = &expected;
        assert!(
            opened
                .iter()
                .any(|(k, f, p)| k == kind && f == field && p == plaintext),
            "missing {kind} {field} {:?}",
            String::from_utf8_lossy(plaintext)
        );
    }

    // The result: sealed, bound to its own outboxId.
    let result = frames
        .iter()
        .find(|f| f["type"] == "thread_result")
        .expect("no thread_result frame");
    let outbox_id = result["outboxId"].as_str().expect("no outboxId");
    let sealed_result = &result["data"]["result"];
    assert_eq!(
        fx.open(sealed_result, &result_location("th-1", outbox_id, "result"))
            .unwrap(),
        RESULT.as_bytes()
    );
    let other_id = frames[0]["outboxId"].as_str().unwrap();
    assert_ne!(other_id, outbox_id);
    assert!(
        fx.open(sealed_result, &result_location("th-1", other_id, "result"))
            .is_err(),
        "a result moved to another outboxId opens"
    );

    // The output file: a file envelope under an opaque name, its real name
    // sealed in the descriptor.
    let descriptors = result["data"]["attachments"].as_array().unwrap();
    assert_eq!(descriptors.len(), 1, "{descriptors:?}");
    let descriptor = &descriptors[0];
    let sha256 = descriptor["sha256"].as_str().unwrap();
    assert_eq!(descriptor["content_type"], "application/octet-stream");
    let name_location = Location::new(TASK)
        .unwrap()
        .part("frame", "thread_result")
        .unwrap()
        .part("thread", "th-1")
        .unwrap()
        .part("attachment", sha256)
        .unwrap()
        .part("field", "name")
        .unwrap();
    assert_eq!(
        fx.open(&descriptor["name"], &name_location).unwrap(),
        FILE_NAME.as_bytes()
    );
    let uploads = fx.host.uploads().await;
    let upload = uploads
        .iter()
        .find(|upload| upload.sha256 == sha256)
        .expect("the envelope was not uploaded");
    assert_eq!(upload.name, format!("{sha256}.bin"));
    assert_eq!(upload.content_type, "application/octet-stream");
    assert_eq!(sha256_hex(&upload.bytes), sha256);
    assert_eq!(
        i64::try_from(upload.size).unwrap(),
        descriptor["size"].as_i64().unwrap()
    );
    let file_location = Location::new(TASK).unwrap().part("field", "file").unwrap();
    let opened_file = fx
        .client
        .group
        .open(&upload.bytes, &file_location, |_| None)
        .unwrap();
    assert_eq!(opened_file.plaintext, FILE_BYTES.as_bytes());

    // The agent DB keeps the sealed result, nothing in plaintext.
    let db = fx.db_path();
    let stored = query_strings(&db, "SELECT result FROM threads WHERE id = 'th-1'");
    let stored: Value = serde_json::from_str(&stored[0]).unwrap();
    assert_eq!(&stored, sealed_result);
    let stored_id = query_strings(
        &db,
        "SELECT result_outbox_id FROM threads WHERE id = 'th-1'",
    );
    assert_eq!(stored_id, [outbox_id]);
    let bytes = fx.db_bytes();
    for needle in [
        PROMPT,
        THINK,
        TEXT,
        INPUT,
        OUTPUT,
        METHOD,
        ACTION,
        ACTION_LATE,
        AFTER,
        RESULT,
        FILE_NAME,
        FILE_BYTES,
    ] {
        assert!(
            !contains(&bytes, needle.as_bytes()),
            "the agent DB holds plaintext {needle}"
        );
    }
    for (index, message) in fx.host.wire().await.iter().enumerate() {
        for needle in [METHOD, ACTION, ACTION_LATE] {
            assert!(
                !contains(message, needle.as_bytes()),
                "wire message {index} holds {needle}"
            );
        }
    }
    let cache = fx.workspace.dir().join("attachments-cache");
    for entry in std::fs::read_dir(&cache).unwrap().flatten() {
        let bytes = std::fs::read(entry.path()).unwrap();
        assert!(
            !contains(&bytes, FILE_BYTES.as_bytes()),
            "the cache holds plaintext"
        );
    }

    // The local API opens the stored texts for display.
    let show = api_call(&fx.workspace, "thread.show", json!({ "id": "th-1" })).await;
    assert_eq!(show["result"]["thread"]["result"], RESULT, "{show}");
    assert_eq!(show["result"]["thread"]["prompt"], PROMPT, "{show}");
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runner_removed_mid_turn_sends_nothing_more_and_fails_not_member() {
    let mut fx = Fixture::connect().await;
    std::fs::write(fx.out.path().join("th-2.hold"), b"").unwrap();
    fx.push_prompt("th-2").await;
    let held = fx.out.path().join("th-2.held");
    assert!(
        wait_until(SETTLE, || held.exists()).await,
        "the engine never reached the hold"
    );
    let action = fx.rc("th-2", "action").expect("the action never ran");
    assert_ne!(action, 0, "an undeclared thread.action succeeded");

    // The client removes the runner (commit seq 2).
    let registers = fx.host.register_bodies().await;
    let runner_key: [u8; 32] = decode_b64url(
        registers[0]["e2ee"]["credential"]["public_key"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let remove = fx
        .client
        .group
        .remove_members(&fx.client.identity, &[runner_key])
        .unwrap();
    let entry = fx.client.accept(&fx.host, &remove, 2).await;
    let msg_id = fx.next_msg_id();
    fx.host.push_e2ee_log(TASK, entry, msg_id).await;
    let db = fx.db_path();
    assert!(
        wait_until(SETTLE, || group_row(&db, TASK)
            .is_some_and(|(status, _)| status == "removed"))
        .await,
        "the removal was not applied: {:?}",
        group_row(&db, TASK)
    );
    std::fs::write(fx.out.path().join("th-2.release"), b"").unwrap();

    let run = fx.terminal("th-2").await;
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

    // The late action was refused too, and nothing after the removal was sent:
    // every frame opens under the old epoch, none holds the later content,
    // and no seq was consumed by a frame that was not sent.
    let late = fx.rc("th-2", "late").expect("the late action never ran");
    assert_ne!(late, 0, "a late thread.action succeeded");
    let frames = fx.host.thread_frames("th-2").await;
    let mut max_seq = 0;
    for frame in frames.iter().filter(|f| f["type"] == "thread_message") {
        max_seq = max_seq.max(frame["data"]["seq"].as_i64().unwrap());
        for (_, _, plaintext) in open_transcript(&mut fx, "th-2", frame) {
            for late in [AFTER, ACTION_LATE] {
                assert!(
                    !contains(&plaintext, late.as_bytes()),
                    "{late} was sent after the removal"
                );
            }
        }
    }
    assert!(max_seq > 0, "the transcript before the removal was sent");
    assert_eq!(
        run.final_seq, max_seq,
        "a seq was consumed by an unsent frame"
    );
    let bytes = fx.db_bytes();
    for needle in [AFTER, METHOD, ACTION, ACTION_LATE, RESULT] {
        assert!(
            !contains(&bytes, needle.as_bytes()),
            "the agent DB holds plaintext {needle}"
        );
    }
    fx.shutdown().await;
}
