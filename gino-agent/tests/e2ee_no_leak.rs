//! E2ee no-leak, black-box against the stub host: an encrypted task runs end
//! to end (a sealed prompt with a sealed attachment, a drop in a second turn,
//! a sealed cron prompt, transcript events, a refused host action, a result
//! and an output file), then the agent DB, the daemon's debug log, the engine's
//! environment and argv, and everything the runner sent the host are scanned
//! for every plaintext and every key, in every common encoding: none occurs.
//! The plaintexts do reach the engine and open back from the host's frames,
//! so the scan cannot pass vacuously.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

#[allow(dead_code)]
mod support;

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use gino_e2ee::field_map::FieldMap;
use gino_e2ee::{Location, decode_b64url, seal_drop, to_sealed_value};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::random::OpenMlsRand as _;
use serde_json::{Value, json};
use tempfile::TempDir;

use support::e2ee::{Client, PROFILE, group_row, latest_key_package, upsert_encrypted_task};
use support::stub_host::{StubHost, delivery_id};
use support::{RunnerProc, SETTLE, Workspace, wait_until};

const TASK: &str = "t-noleak";
const THREAD: &str = "th-1";
const CRON: &str = "cr-1";

/// A random 24-character token.
fn marker() -> String {
    hex(&RustCrypto::default().random_vec(12).unwrap())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Every plaintext of the run.
struct Markers {
    prompt: String,
    file_name: String,
    file_bytes: String,
    drop_text: String,
    cron_prompt: String,
    think: String,
    text: String,
    input: String,
    output: String,
    method: String,
    action: String,
    result: String,
    out_name: String,
    out_bytes: String,
}

impl Markers {
    fn new() -> Self {
        Self {
            prompt: marker(),
            file_name: format!("{}.txt", marker()),
            file_bytes: marker(),
            drop_text: marker(),
            cron_prompt: marker(),
            think: marker(),
            text: marker(),
            input: marker(),
            output: marker(),
            method: marker(),
            action: marker(),
            result: marker(),
            out_name: format!("{}.txt", marker()),
            out_bytes: marker(),
        }
    }

    fn all(&self) -> [(&'static str, &str); 14] {
        [
            ("prompt", &self.prompt),
            ("file name", &self.file_name),
            ("file bytes", &self.file_bytes),
            ("drop", &self.drop_text),
            ("cron prompt", &self.cron_prompt),
            ("thinking", &self.think),
            ("text", &self.text),
            ("tool input", &self.input),
            ("tool output", &self.output),
            ("host action method", &self.method),
            ("host action", &self.action),
            ("result", &self.result),
            ("output name", &self.out_name),
            ("output bytes", &self.out_bytes),
        ]
    }
}

/// One stream-json stdout line of the fake engine.
fn emit(line: &Value) -> String {
    format!("printf '%s\\n' '{line}'\n")
}

/// A fake `claude` that records its environment, argv, cwd and the user turn
/// it received under `$out/<kind>.<pid>`, then emits thinking, text, a tool
/// call and its result, attempts a host action through the local API (its
/// exit code lands in `$out/action.<pid>`), writes an output file and
/// succeeds.
fn claude_script(out: &Path, m: &Markers) -> String {
    let init = json!({ "type": "system", "subtype": "init", "session_id": "s-nl", "model": "stub", "tools": [] });
    let assistant = json!({
        "type": "assistant",
        "message": { "role": "assistant", "content": [
            { "type": "thinking", "thinking": m.think },
            { "type": "text", "text": m.text },
            { "type": "tool_use", "id": "tu-1", "name": "Read", "input": { "path": m.input } },
        ]},
    });
    let tool_result = json!({
        "type": "user",
        "message": { "role": "user", "content": [
            { "type": "tool_result", "tool_use_id": "tu-1", "content": m.output },
        ]},
    });
    let result = json!({ "type": "result", "subtype": "success", "is_error": false, "result": m.result, "session_id": "s-nl" });
    let mut script = format!(
        concat!(
            "#!/usr/bin/env bash\nset -u\nout=\"{}\"\nn=$$\n",
            "[ \"${{1:-}}\" = --version ] && {{ echo '0.0.0 (fake)'; exit 0; }}\n",
            "env > \"$out/env.$n\"\n",
            "printf '%s\\n' \"$@\" > \"$out/argv.$n\"\n",
            "pwd > \"$out/cwd.$n\"\n",
        ),
        out.display()
    );
    script.push_str(&emit(&init));
    script.push_str(
        "while IFS= read -r line; do case \"$line\" in *'\"type\":\"user\"'*) printf '%s\\n' \"$line\" > \"$out/prompt.$n\"; break ;; esac; done\n",
    );
    script.push_str(&emit(&assistant));
    script.push_str(&emit(&tool_result));
    let _ = writeln!(
        script,
        "\"$GINO_RUNNER_BIN\" action {} '{{\"body\":\"{}\"}}' >/dev/null 2>&1; echo $? > \"$out/action.$n\"",
        m.method, m.action
    );
    let _ = writeln!(
        script,
        "mkdir -p ../output\nprintf '%s' '{}' > ../output/{}",
        m.out_bytes, m.out_name
    );
    script.push_str(&emit(&result));
    script
}

/// The contents of every `$out/<kind>.*` file the fake engine wrote.
fn recorded(out: &Path, kind: &str) -> Vec<String> {
    let prefix = format!("{kind}.");
    let mut files: Vec<_> = std::fs::read_dir(out)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .map(|entry| std::fs::read_to_string(entry.path()).unwrap())
        .collect();
    files.sort();
    files
}

/// The encodings a leaked secret could take in a text or binary sink: raw,
/// hex in both cases, and the base64 and base64url characters determined by
/// the secret alone at each of the three byte alignments it can have inside a
/// longer encoded value.
fn encodings(secret: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut forms = vec![
        ("raw".to_owned(), secret.to_vec()),
        ("hex".to_owned(), hex(secret).into_bytes()),
        ("HEX".to_owned(), hex(secret).to_uppercase().into_bytes()),
    ];
    for shift in 0..3 {
        let mut shifted = vec![0u8; shift];
        shifted.extend_from_slice(secret);
        for (name, encoded) in [
            ("base64", STANDARD.encode(&shifted)),
            ("base64url", URL_SAFE_NO_PAD.encode(&shifted)),
        ] {
            // Groups 1.. up to the last full group hold only secret bytes.
            let full_groups = (shift + secret.len()) / 3;
            forms.push((
                format!("{name} at offset {shift}"),
                encoded.as_bytes()[4..4 * full_groups].to_vec(),
            ));
        }
    }
    forms
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The labelled needles: every encoding of every marker and key.
struct Needles(Vec<(String, Vec<u8>)>);

impl Needles {
    fn new(markers: &Markers, keys: &[(String, Vec<u8>)]) -> Self {
        let mut needles = Vec::new();
        for (label, value) in markers.all() {
            for (encoding, form) in encodings(value.as_bytes()) {
                needles.push((format!("plaintext {label} ({encoding})"), form));
            }
        }
        for (label, key) in keys {
            for (encoding, form) in encodings(key) {
                needles.push((format!("key {label} ({encoding})"), form));
            }
        }
        Self(needles)
    }

    /// Panic when `haystack` holds any needle.
    fn assert_absent(&self, sink: &str, haystack: &[u8]) {
        for (label, needle) in &self.0 {
            assert!(!contains(haystack, needle), "{sink} holds {label}");
        }
    }
}

/// Every text and blob cell of every table of the SQLite DB at `db`, labelled
/// `table.column`.
fn db_cells(db: &Path) -> Vec<(String, Vec<u8>)> {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(tables.iter().any(|t| t == "e2ee_groups"), "{tables:?}");
    let mut cells = Vec::new();
    for table in tables {
        let mut statement = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let columns: Vec<String> = statement
            .column_names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for (index, column) in columns.iter().enumerate() {
                let bytes = match row.get_ref(index).unwrap() {
                    rusqlite::types::ValueRef::Text(bytes)
                    | rusqlite::types::ValueRef::Blob(bytes) => bytes.to_vec(),
                    _ => continue,
                };
                cells.push((format!("{table}.{column}"), bytes));
            }
        }
    }
    cells
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.to_path_buf().into_os_string();
    path.push(suffix);
    PathBuf::from(path)
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

/// The next inbound delivery id.
fn next_msg_id(msg_id: &mut i64) -> String {
    *msg_id += 1;
    delivery_id(*msg_id)
}

/// An RFC 3339 instant `secs_ago` seconds in the past and its epoch second.
fn past_slot(secs_ago: i64) -> (String, i64) {
    let epoch = Utc::now().timestamp() - secs_ago;
    let at = DateTime::<Utc>::from_timestamp(epoch, 0).unwrap();
    (at.to_rfc3339_opts(SecondsFormat::Millis, true), epoch)
}

fn location(parts: &[(&str, &str)]) -> Location {
    parts
        .iter()
        .fold(Location::new(TASK).unwrap(), |location, (name, value)| {
            location.part(name, value).unwrap()
        })
}

/// The envelope of a sealed value: exactly `{"e2ee": "<base64url>"}`.
fn sealed_envelope(value: &Value) -> Vec<u8> {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("not sealed: {value}"));
    assert_eq!(object.len(), 1, "not exactly one member: {value}");
    decode_b64url(object["e2ee"].as_str().unwrap()).unwrap()
}

/// Open every sealed field of the frames the host received for `thread_id`
/// (transcript, result, attachment names) and the uploaded file envelopes,
/// as the client.
async fn open_wire(host: &StubHost, client: &mut Client, thread_id: &str) -> Vec<Vec<u8>> {
    let mut opened = Vec::new();
    let mut open = |value: &Value, location: Location| {
        let plaintext = client
            .group
            .open(&sealed_envelope(value), &location, |_| None)
            .unwrap_or_else(|error| panic!("{value} does not open: {error:?}"))
            .plaintext;
        opened.push(plaintext);
    };
    let mut attachments = Vec::new();
    for frame in host.thread_frames(thread_id).await {
        let data = &frame["data"];
        if frame["type"] == "thread_message" {
            let seq = data["seq"].as_u64().unwrap();
            let at = |field| {
                location(&[("frame", "thread_message"), ("thread", thread_id)])
                    .part_u64("seq", seq)
                    .unwrap()
                    .part("field", field)
                    .unwrap()
            };
            if !data["content"].is_null() {
                open(&data["content"], at("content"));
            }
            assert_ne!(data["kind"], "host_action", "a host action was sent");
            if !data["input"].is_null() {
                open(&data["input"], at("input"));
            }
            if !data["output"].is_null() {
                open(&data["output"]["content"], at("output.content"));
            }
        } else {
            let outbox_id = frame["outboxId"].as_str().unwrap();
            if !data["result"].is_null() {
                open(
                    &data["result"],
                    location(&[
                        ("frame", "thread_result"),
                        ("thread", thread_id),
                        ("delivery", outbox_id),
                        ("field", "result"),
                    ]),
                );
            }
            for descriptor in data["attachments"].as_array().into_iter().flatten() {
                let sha256 = descriptor["sha256"].as_str().unwrap();
                open(
                    &descriptor["name"],
                    location(&[
                        ("frame", "thread_result"),
                        ("thread", thread_id),
                        ("attachment", sha256),
                        ("field", "name"),
                    ]),
                );
                attachments.push(sha256.to_owned());
            }
        }
    }
    let file_location = location(&[("field", "file")]);
    for upload in host.uploads().await {
        if attachments.contains(&upload.sha256) {
            let file = client
                .group
                .open(&upload.bytes, &file_location, |_| None)
                .unwrap();
            opened.push(file.plaintext);
        }
    }
    opened
}

#[tokio::test(flavor = "multi_thread")]
async fn an_encrypted_run_leaves_no_plaintext_or_key_in_db_logs_engine_env_or_wire() {
    let markers = Markers::new();
    let host = StubHost::start(json!({"heartbeatIntervalMs": 500})).await;
    let workspace = Workspace::new().await;
    // The production layout: the agent DB, and so the key files, at the
    // workspace root.
    let state_dir = workspace.dir().to_path_buf();
    let db = state_dir.join("agent.db");
    let out = tempfile::tempdir().unwrap();
    let logs = tempfile::tempdir().unwrap();
    let log_path = logs.path().join("daemon.log");
    let fakes = TempDir::new().unwrap();
    let claude = fakes.path().join("claude");
    std::fs::write(&claude, claude_script(out.path(), &markers)).unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    let runner = RunnerProc::spawn_in_with_env(
        &host,
        &workspace,
        fakes,
        &[
            ("RUST_LOG", std::ffi::OsStr::new("debug")),
            ("GINO_DB_PATH", db.as_os_str()),
        ],
        std::fs::File::create(&log_path).unwrap().into(),
    );
    assert!(host.wait_connected(SETTLE).await, "runner never connected");
    assert!(host.wait_key_package_uploads(1, SETTLE).await, "no upload");

    // The client creates the group and adds the runner (epoch 1).
    let mut client = Client::create(TASK);
    let mut epoch_secrets = vec![client.group.current().unwrap()];
    upsert_encrypted_task(&host, TASK, 1).await;
    client
        .add(&host, latest_key_package(&host).await, 1, 2)
        .await;
    epoch_secrets.push(client.group.current().unwrap());
    assert!(
        wait_until(SETTLE, || group_row(&db, TASK)
            .is_some_and(|(status, _)| status == "member"))
        .await,
        "the runner never joined: {:?}",
        group_row(&db, TASK)
    );
    let mut msg_id = 2;
    let field_map = FieldMap::for_profile(PROFILE).unwrap();

    // Turn 1: a sealed prompt with a sealed attachment.
    let (epoch, secrets) = client.group.current().unwrap();
    let file = gino_e2ee::seal_file(
        &secrets.content_key,
        epoch,
        &location(&[("field", "file")]),
        markers.file_bytes.as_bytes(),
        &RustCrypto::default(),
    )
    .unwrap()
    .envelope;
    let mut descriptor = host
        .stage_inbound_attachment("att-1", "att-1.bin", &file, "application/octet-stream")
        .await;
    descriptor["name"] = Value::from(markers.file_name.as_str());
    let frame = json!({
        "type": "message", "taskId": TASK, "threadId": THREAD,
        "data": { "text": markers.prompt, "attachments": [descriptor] },
    });
    let mut frame = field_map
        .seal_frame(
            "message",
            &frame,
            epoch,
            &secrets.content_key,
            &RustCrypto::default(),
        )
        .unwrap();
    frame["msgId"] = Value::from(next_msg_id(&mut msg_id));
    host.push_frame(&frame).await;
    assert!(
        host.wait_thread_terminal_count(THREAD, 1, SETTLE).await,
        "turn 1 never ended"
    );
    assert_eq!(host.thread_run(THREAD).await.unwrap().status, "succeeded");

    // The client rotates the epoch (epoch 2).
    let update = client.group.self_update(&client.identity).unwrap();
    let entry = client.accept(&host, &update, 2).await;
    msg_id += 1;
    host.push_e2ee_log(TASK, entry, msg_id).await;
    epoch_secrets.push(client.group.current().unwrap());
    assert!(
        wait_until(SETTLE, || group_row(&db, TASK)
            == Some(("member".to_owned(), Some(2))))
        .await,
        "the update was not applied: {:?}",
        group_row(&db, TASK)
    );

    // Turn 2: a drop.
    let (epoch, _) = client.group.current().unwrap();
    let drop_envelope = seal_drop(
        &RustCrypto::default(),
        &client.group.drop_public_key().unwrap(),
        epoch,
        &location(&[("frame", "message"), ("field", "text")]),
        markers.drop_text.as_bytes(),
    )
    .unwrap();
    host.push_frame(&json!({
        "type": "message", "taskId": TASK, "threadId": THREAD, "msgId": next_msg_id(&mut msg_id),
        "data": { "text": to_sealed_value(&drop_envelope) },
    }))
    .await;
    assert!(
        host.wait_thread_terminal_count(THREAD, 2, SETTLE).await,
        "turn 2 never ended"
    );
    assert_eq!(host.thread_run(THREAD).await.unwrap().status, "succeeded");

    // A sealed cron prompt, due now.
    let (slot, slot_epoch) = past_slot(10);
    let cron = json!({
        "type": "cron_upsert", "taskId": TASK, "cronId": CRON,
        "data": {
            "kind": "schedule", "prompt": markers.cron_prompt, "schedule_type": "interval",
            "schedule_value": "3600000", "continuity": "isolated", "next_run": slot,
        },
    });
    let (epoch, secrets) = client.group.current().unwrap();
    let mut cron = field_map
        .seal_frame(
            "cron_upsert",
            &cron,
            epoch,
            &secrets.content_key,
            &RustCrypto::default(),
        )
        .unwrap();
    cron["msgId"] = Value::from(next_msg_id(&mut msg_id));
    host.push_frame(&cron).await;
    let cron_thread = format!("{CRON}@{}", slot_epoch * 1000);
    let cron_run = host
        .wait_thread_terminal(&cron_thread, SETTLE)
        .await
        .expect("the cron never fired");
    assert_eq!(cron_run.status, "succeeded", "{cron_run:?}");

    // Let the last acks and outbox deletes land, then stop the daemon.
    assert!(
        host.wait_upload_count(3, SETTLE).await,
        "not every output was uploaded"
    );
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    runner.shutdown().await;

    // The plaintexts reached the engine...
    let prompts = recorded(out.path(), "prompt").join("\n");
    for expected in [&markers.prompt, &markers.drop_text, &markers.cron_prompt] {
        assert!(
            prompts.contains(expected.as_str()),
            "the engine never got {expected}"
        );
    }
    // The profile declares no host-action method: every attempt is refused.
    let actions = recorded(out.path(), "action");
    assert_eq!(actions.len(), 3, "one action attempt per engine spawn");
    for rc in actions {
        assert_ne!(rc, "0\n", "an undeclared thread.action succeeded");
    }
    let input = find_file(&workspace.dir().join("threads"), &markers.file_name)
        .expect("the attachment was not materialized under its real name");
    assert_eq!(std::fs::read(input).unwrap(), markers.file_bytes.as_bytes());

    // ...and the host's frames open back to them.
    let mut opened = open_wire(&host, &mut client, THREAD).await;
    opened.extend(open_wire(&host, &mut client, &cron_thread).await);
    for expected in [
        &markers.think,
        &markers.text,
        &markers.input,
        &markers.output,
        &markers.result,
        &markers.out_name,
        &markers.out_bytes,
    ] {
        assert!(
            opened.iter().any(|p| contains(p, expected.as_bytes())),
            "no frame opens to {expected}"
        );
    }

    // No sink holds a plaintext or a key.
    let identity_file = state_dir.join("e2ee-identity.key");
    let state_file = state_dir.join("e2ee-state.key");
    let mut keys = vec![
        (
            "identity seed".to_owned(),
            std::fs::read(&identity_file).unwrap(),
        ),
        (
            "at-rest key".to_owned(),
            std::fs::read(&state_file).unwrap(),
        ),
    ];
    for (epoch, secrets) in &epoch_secrets {
        keys.push((format!("content key {epoch}"), secrets.content_key.to_vec()));
        keys.push((format!("drop seed {epoch}"), secrets.drop_seed.to_vec()));
    }
    assert_eq!(epoch_secrets.len(), 3);
    for (label, key) in &keys {
        assert_eq!(key.len(), 32, "{label}");
    }
    let needles = Needles::new(&markers, &keys);

    for suffix in ["", "-wal", "-shm"] {
        let path = path_with_suffix(&db, suffix);
        if let Ok(bytes) = std::fs::read(&path) {
            needles.assert_absent(&path.display().to_string(), &bytes);
        }
    }
    for (cell, bytes) in db_cells(&db) {
        needles.assert_absent(&format!("agent DB cell {cell}"), &bytes);
    }
    let log = std::fs::read(&log_path).unwrap();
    assert!(
        contains(&log, b"DEBUG"),
        "the daemon log has no debug lines"
    );
    needles.assert_absent("the daemon log", &log);
    for kind in ["env", "argv", "cwd"] {
        let files = recorded(out.path(), kind);
        assert_eq!(files.len(), 3, "{kind}: one record per engine spawn");
        for file in files {
            needles.assert_absent(&format!("the engine {kind}"), file.as_bytes());
        }
    }
    for (index, bytes) in host.wire().await.iter().enumerate() {
        needles.assert_absent(&format!("wire message {index}"), bytes);
    }

    // The key files are not reachable from any directory the runner hands
    // the engine: its cwd, its `--add-dir`s and the directories it sets in
    // the engine's environment.
    let key_files = [
        identity_file.canonicalize().unwrap(),
        state_file.canonicalize().unwrap(),
    ];
    let root = workspace.dir().parent().unwrap().canonicalize().unwrap();
    let mut granted: Vec<PathBuf> = Vec::new();
    for cwd in recorded(out.path(), "cwd") {
        granted.push(PathBuf::from(cwd.trim()));
    }
    for argv in recorded(out.path(), "argv") {
        let argv: Vec<&str> = argv.lines().collect();
        for pair in argv.windows(2) {
            if pair[0] == "--add-dir" {
                granted.push(PathBuf::from(pair[1]));
            }
        }
    }
    let inherited = ["PATH", "GINO_WORKSPACE_DIR", "GINO_DB_PATH"];
    for env in recorded(out.path(), "env") {
        for (name, value) in env.lines().filter_map(|line| line.split_once('=')) {
            if !inherited.contains(&name) && value.starts_with('/') {
                granted.push(PathBuf::from(value));
            }
        }
    }
    let granted: Vec<PathBuf> = granted
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .filter(|path| path.starts_with(&root))
        .collect();
    assert!(
        granted.iter().any(|path| path.ends_with("project")),
        "no engine cwd recorded: {granted:?}"
    );
    for path in &granted {
        for key_file in &key_files {
            assert!(
                !key_file.starts_with(path),
                "{} is reachable from {}",
                key_file.display(),
                path.display()
            );
        }
    }
    drop(workspace);
}
