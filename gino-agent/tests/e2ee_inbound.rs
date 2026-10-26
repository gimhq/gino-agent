//! E2ee inbound, black-box against the stub host: an encrypted task's prompt,
//! attachments, drops and cron prompts are opened right before the turn, the
//! agent DB keeps only the sealed form, and input that does not open fails the
//! thread `agent.encryption` without spawning the engine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{
    CommitUnit, HistoryPolicy, Identity, Location, MemoryKeyCache, ScopeGroup, decode_b64url,
    encode_b64url, seal_drop, to_sealed_value,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{Value, json};

use support::fake_claude::{Behavior, PROMPT_SEEN_FILE};
use support::stub_host::{StubHost, ThreadRun};
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const PROFILE: &str = "gino.task-content.v1";
const TASK: &str = "t-enc";
const PROMPT: &str = "PLAINTEXT-PROMPT-7f3a";
const FILE_NAME: &str = "secret-name-4d1e.txt";
const FILE_BYTES: &[u8] = b"PLAINTEXT-FILE-91c2";

/// A runner on the stub host and a client member of the task's group.
struct Fixture {
    host: StubHost,
    workspace: Workspace,
    runner: RunnerProc,
    identity: Identity,
    client: ScopeGroup<MemoryKeyCache>,
    key_package: Vec<u8>,
    msg_id: i64,
}

impl Fixture {
    /// Boot the runner (a prompt-recording engine) and create the task's group
    /// on the client, without the runner in it.
    async fn connect() -> Self {
        let host = StubHost::start(json!({"heartbeatIntervalMs": 500})).await;
        let workspace = Workspace::new().await;
        let behavior = Behavior::Prompt {
            session_id: "s-enc".to_owned(),
        };
        let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
        assert!(host.wait_connected(SETTLE).await, "runner never connected");
        assert!(host.wait_key_package_uploads(1, SETTLE).await, "no upload");
        let key_package = host.key_package_uploads().await[0]["one_time"][0]
            .as_str()
            .map(decode_b64url)
            .unwrap()
            .unwrap();
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
            host,
            workspace,
            runner,
            identity,
            client,
            key_package,
            msg_id: 0,
        }
    }

    fn next_msg_id(&mut self) -> i64 {
        self.msg_id += 1;
        self.msg_id
    }

    fn db_path(&self) -> PathBuf {
        self.workspace.dir().parent().unwrap().join("agent.db")
    }

    /// Mark the task encrypted (`task_upsert.data.e2ee`).
    async fn mark_encrypted(&mut self) {
        let group_id = encode_b64url(&gino_e2ee::group_id(PROFILE, TASK).unwrap());
        let msg_id = self.next_msg_id();
        self.host
            .push_frame(&json!({
                "type": "task_upsert",
                "taskId": TASK,
                "msgId": support::stub_host::delivery_id(msg_id),
                "data": { "name": "secret", "e2ee": { "profile_id": PROFILE, "group_id": group_id } },
            }))
            .await;
    }

    /// Add the runner (commit seq 1), mark the task encrypted, deliver the
    /// Welcome and wait until the runner is a member. `link` publishes the
    /// epoch link of the add.
    async fn add_runner(&mut self, link: bool) {
        let add = self
            .client
            .add_members(
                &self.identity,
                std::slice::from_ref(&self.key_package),
                None,
            )
            .unwrap();
        self.client.commit_accepted(1).unwrap();
        self.host.ds_append(TASK, commit_entry(&add, 1)).await;
        if link && let Some(epoch_link) = &add.epoch_link {
            self.host
                .ds_put_link(TASK, 1, &encode_b64url(epoch_link))
                .await;
        }
        self.mark_encrypted().await;
        let msg_id = self.next_msg_id();
        self.host
            .push_e2ee_welcome(
                TASK,
                &encode_b64url(add.welcome.as_ref().unwrap()),
                1,
                msg_id,
            )
            .await;
        let db = self.db_path();
        assert!(
            wait_until(SETTLE, || group_status(&db).as_deref() == Some("member")).await,
            "the runner never joined: {:?}",
            group_status(&db)
        );
    }

    /// Seal every mapped field of `frame` under the client's current epoch.
    fn seal(&self, frame_type: &str, frame: &Value) -> Value {
        let (epoch, secrets) = self.client.current().unwrap();
        FieldMap::for_profile(PROFILE)
            .unwrap()
            .seal_frame(
                frame_type,
                frame,
                epoch,
                &secrets.content_key,
                &RustCrypto::default(),
            )
            .unwrap()
    }

    /// Seal `bytes` as a file envelope, stage it at the host and return its
    /// descriptor carrying the plaintext `name` (sealed with the message).
    async fn stage_sealed_file(&self, id: &str, name: &str, bytes: &[u8], tamper: bool) -> Value {
        let (epoch, secrets) = self.client.current().unwrap();
        let location = Location::new(TASK).unwrap().part("field", "file").unwrap();
        let mut envelope = gino_e2ee::seal_file(
            &secrets.content_key,
            epoch,
            &location,
            bytes,
            &RustCrypto::default(),
        )
        .unwrap()
        .envelope;
        if tamper {
            *envelope.last_mut().unwrap() ^= 0x01;
        }
        let mut descriptor = self
            .host
            .stage_inbound_attachment(
                id,
                &format!("{id}.bin"),
                &envelope,
                "application/octet-stream",
            )
            .await;
        descriptor["name"] = Value::from(name);
        descriptor
    }

    /// Push `frame` with the next delivery id.
    async fn push(&mut self, mut frame: Value) {
        frame["msgId"] = Value::from(support::stub_host::delivery_id(self.next_msg_id()));
        self.host.push_frame(&frame).await;
    }

    async fn terminal(&self, thread_id: &str) -> ThreadRun {
        self.host
            .wait_thread_terminal(thread_id, SETTLE)
            .await
            .unwrap_or_else(|| panic!("no thread_result for {thread_id}"))
    }

    /// The user turn the engine received for `thread_id`, if it was spawned.
    fn prompt_seen(&self, thread_id: &str) -> Option<String> {
        find_file(
            &self.workspace.dir().join("threads").join(thread_id),
            PROMPT_SEEN_FILE,
        )
        .map(|path| std::fs::read_to_string(path).unwrap())
    }

    /// The bytes of the agent DB and its WAL.
    fn db_bytes(&self) -> Vec<u8> {
        let mut bytes = std::fs::read(self.db_path()).unwrap();
        if let Ok(wal) = std::fs::read(self.db_path().with_extension("db-wal")) {
            bytes.extend(wal);
        }
        bytes
    }

    /// Assert the agent DB holds none of `needles`.
    fn assert_db_free_of(&self, needles: &[&[u8]]) {
        let bytes = self.db_bytes();
        for needle in needles {
            assert!(
                !contains(&bytes, needle),
                "the agent DB holds plaintext {:?}",
                String::from_utf8_lossy(needle)
            );
        }
    }

    async fn shutdown(self) {
        self.runner.shutdown().await;
        drop(self.workspace);
    }
}

fn commit_entry(unit: &CommitUnit, seq: u64) -> Value {
    json!({
        "seq": seq,
        "kind": "commit",
        "epoch": unit.epoch,
        "message": encode_b64url(&unit.commit),
        "drop_public_key": encode_b64url(&unit.drop_public_key),
    })
}

fn group_status(db: &Path) -> Option<String> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .ok()?;
    conn.query_row(
        "SELECT status FROM e2ee_groups WHERE task_id = ?1",
        [TASK],
        |r| r.get(0),
    )
    .ok()
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn message(thread_id: &str, text: Value, attachments: Vec<Value>) -> Value {
    let mut data = serde_json::Map::new();
    data.insert("text".to_owned(), text);
    let mut data = Value::Object(data);
    if !attachments.is_empty() {
        data["attachments"] = Value::from(attachments);
    }
    json!({ "type": "message", "taskId": TASK, "threadId": thread_id, "data": data })
}

fn cron_upsert(cron_id: &str, prompt: &str, next_run: &str) -> Value {
    json!({
        "type": "cron_upsert",
        "taskId": TASK,
        "cronId": cron_id,
        "data": {
            "kind": "schedule",
            "prompt": prompt,
            "schedule_type": "interval",
            "schedule_value": "60000",
            "continuity": "isolated",
            "next_run": next_run,
        },
    })
}

/// An RFC 3339 instant `secs_ago` seconds in the past and its epoch second.
fn past_slot(secs_ago: i64) -> (String, i64) {
    let epoch = Utc::now().timestamp() - secs_ago;
    let at = DateTime::<Utc>::from_timestamp(epoch, 0).unwrap();
    (at.to_rfc3339_opts(SecondsFormat::Millis, true), epoch)
}

/// Assert `run` failed `agent.encryption` with `code` and nothing else.
fn assert_encryption_failure(run: &ThreadRun, code: &str) {
    assert_eq!(run.status, "failed", "{run:?}");
    assert_eq!(run.failure_reason.as_deref(), Some("agent.encryption"));
    assert_eq!(
        run.encryption_error
            .as_ref()
            .and_then(|e| e["code"].as_str()),
        Some(code),
        "{run:?}"
    );
    assert_eq!(run.result, None);
    assert_eq!(run.error, None);
    assert!(run.attachments.is_empty());
    assert_eq!(run.terminal_count, 1);
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

#[tokio::test]
async fn a_sealed_message_and_attachment_open_before_the_turn_and_stay_sealed_at_rest() {
    let mut fx = Fixture::connect().await;
    fx.add_runner(true).await;

    let descriptor = fx
        .stage_sealed_file("att-1", FILE_NAME, FILE_BYTES, false)
        .await;
    let frame = fx.seal(
        "message",
        &message("th-1", Value::from(PROMPT), vec![descriptor]),
    );
    assert!(frame["data"]["text"]["e2ee"].is_string());
    assert!(frame["data"]["attachments"][0]["name"]["e2ee"].is_string());
    fx.push(frame).await;

    let run = fx.terminal("th-1").await;
    assert_eq!(run.status, "succeeded", "{run:?}");
    let seen = fx.prompt_seen("th-1").expect("the engine never ran");
    assert!(seen.contains(PROMPT), "the engine got the opened prompt");

    // The plaintext file sits under its opened name in the thread's inputs.
    let input = find_file(&fx.workspace.dir().join("threads").join("th-1"), FILE_NAME)
        .expect("the attachment was not materialized under its real name");
    assert_eq!(std::fs::read(input).unwrap(), FILE_BYTES);

    // The agent DB keeps only sealed content: inbox, threads.prompt and
    // thread_attachments.
    let db = fx.db_path();
    let prompts = query_strings(&db, "SELECT prompt FROM threads WHERE id = 'th-1'");
    assert!(prompts[0].contains("\"e2ee\""), "{prompts:?}");
    let descriptors = query_strings(
        &db,
        "SELECT descriptors FROM thread_attachments WHERE thread_id = 'th-1'",
    );
    assert!(descriptors[0].contains("\"e2ee\""), "{descriptors:?}");
    fx.assert_db_free_of(&[PROMPT.as_bytes(), FILE_NAME.as_bytes(), FILE_BYTES]);

    // The attachment cache keeps the envelope, not the plaintext.
    let cache = fx.workspace.dir().join("attachments-cache");
    for entry in std::fs::read_dir(&cache).unwrap().flatten() {
        let bytes = std::fs::read(entry.path()).unwrap();
        assert!(!contains(&bytes, FILE_BYTES), "the cache holds plaintext");
    }
    fx.shutdown().await;
}

#[tokio::test]
async fn drops_and_cron_prompts_open_per_turn_and_api_crons_are_sealed() {
    let mut fx = Fixture::connect().await;
    fx.add_runner(true).await;

    // A drop: the text sealed to the task's drop public key.
    let drop_text = "PLAINTEXT-DROP-55e0";
    let (epoch, _) = fx.client.current().unwrap();
    let location = Location::new(TASK)
        .unwrap()
        .part("frame", "message")
        .unwrap()
        .part("field", "text")
        .unwrap();
    let envelope = seal_drop(
        &RustCrypto::default(),
        &fx.client.drop_public_key().unwrap(),
        epoch,
        &location,
        drop_text.as_bytes(),
    )
    .unwrap();
    fx.push(message("th-drop", to_sealed_value(&envelope), Vec::new()))
        .await;
    let run = fx.terminal("th-drop").await;
    assert_eq!(run.status, "succeeded", "{run:?}");
    assert!(fx.prompt_seen("th-drop").unwrap().contains(drop_text));

    // A sealed cron prompt opens for every fire.
    let cron_prompt = "PLAINTEXT-CRON-0b9d";
    for round in 1..=2 {
        let (slot, slot_epoch) = past_slot(20 - round);
        let frame = fx.seal("cron_upsert", &cron_upsert("cr-1", cron_prompt, &slot));
        assert!(frame["data"]["prompt"]["e2ee"].is_string());
        fx.push(frame).await;
        let thread_id = format!("cr-1@{}", slot_epoch * 1000);
        let run = fx.terminal(&thread_id).await;
        assert_eq!(run.status, "succeeded", "round {round}: {run:?}");
        assert!(
            fx.prompt_seen(&thread_id).unwrap().contains(cron_prompt),
            "round {round}: the fire ran the opened prompt"
        );
    }

    // A cron created through the local API is stored sealed under the
    // cron_upsert location.
    let api_prompt = "PLAINTEXT-API-CRON-a611";
    let response = api_call(
        &fx.workspace,
        "cron.create",
        json!({ "type": "interval", "value": "3600000", "prompt": api_prompt, "task_id": TASK }),
    )
    .await;
    let cron_id = response["result"]["cron"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("cron.create failed: {response}"))
        .to_owned();
    let stored = query_strings(
        &fx.db_path(),
        &format!("SELECT prompt FROM crons WHERE id = '{cron_id}'"),
    );
    let sealed: Value = serde_json::from_str(&stored[0]).unwrap();
    let envelope = decode_b64url(sealed["e2ee"].as_str().unwrap()).unwrap();
    let location = Location::new(TASK)
        .unwrap()
        .part("frame", "cron_upsert")
        .unwrap()
        .part("field", "prompt")
        .unwrap();
    let opened = fx.client.open(&envelope, &location, |_| None).unwrap();
    assert_eq!(opened.plaintext, api_prompt.as_bytes());

    fx.assert_db_free_of(&[
        drop_text.as_bytes(),
        cron_prompt.as_bytes(),
        api_prompt.as_bytes(),
    ]);
    fx.shutdown().await;
}

#[tokio::test]
async fn input_that_does_not_open_fails_the_thread_without_a_turn() {
    let mut fx = Fixture::connect().await;
    // Sealed before the runner joins, and its epoch link is never published.
    let old = fx.seal(
        "message",
        &message("th-old", Value::from(PROMPT), Vec::new()),
    );
    fx.add_runner(false).await;

    // Plaintext on an encrypted task.
    fx.push(message("th-plain", Value::from(PROMPT), Vec::new()))
        .await;
    // A tampered sealed value.
    let mut tampered = fx.seal(
        "message",
        &message("th-tamper", Value::from(PROMPT), Vec::new()),
    );
    let mut envelope = decode_b64url(tampered["data"]["text"]["e2ee"].as_str().unwrap()).unwrap();
    *envelope.last_mut().unwrap() ^= 0x01;
    tampered["data"]["text"]["e2ee"] = Value::from(encode_b64url(&envelope));
    fx.push(tampered).await;
    // A tampered file envelope behind a valid prompt.
    let descriptor = fx
        .stage_sealed_file("att-bad", FILE_NAME, FILE_BYTES, true)
        .await;
    let frame = fx.seal(
        "message",
        &message("th-file", Value::from(PROMPT), vec![descriptor]),
    );
    fx.push(frame).await;
    // Content of an epoch the runner cannot reach.
    fx.push(old).await;

    for (thread_id, code) in [
        ("th-plain", "plaintext_rejected"),
        ("th-tamper", "open_failed"),
        ("th-file", "open_failed"),
        ("th-old", "history_unavailable"),
    ] {
        let run = fx.terminal(thread_id).await;
        assert_encryption_failure(&run, code);
        assert!(
            fx.prompt_seen(thread_id).is_none(),
            "{thread_id}: the engine was spawned"
        );
        assert!(
            fx.host.messages_for(TASK, thread_id).await.is_empty(),
            "{thread_id}: a thread_message was sent"
        );
    }
    assert!(
        find_file(&fx.workspace.dir().join("threads"), FILE_NAME).is_none(),
        "a file that did not open was materialized"
    );

    // Not retried: one terminal result each, the row failed at attempt 1.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let rows = query_strings(
        &fx.db_path(),
        "SELECT id || ':' || status || ':' || failure_reason || ':' || attempt FROM threads ORDER BY id",
    );
    assert_eq!(
        rows,
        [
            "th-file:failed:agent.encryption:1",
            "th-old:failed:agent.encryption:1",
            "th-plain:failed:agent.encryption:1",
            "th-tamper:failed:agent.encryption:1",
        ]
    );
    for thread_id in ["th-plain", "th-tamper", "th-file", "th-old"] {
        assert_eq!(fx.terminal(thread_id).await.terminal_count, 1);
    }
    fx.shutdown().await;
}

#[tokio::test]
async fn an_encrypted_task_without_membership_fails_not_member() {
    let mut fx = Fixture::connect().await;
    fx.mark_encrypted().await;
    let frame = fx.seal(
        "message",
        &message("th-nm", Value::from(PROMPT), Vec::new()),
    );
    fx.push(frame).await;

    let run = fx.terminal("th-nm").await;
    assert_encryption_failure(&run, "not_member");
    assert!(fx.prompt_seen("th-nm").is_none(), "the engine was spawned");
    fx.shutdown().await;
}
