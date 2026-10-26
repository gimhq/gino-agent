//! In-process **stub host** speaking the host protocol.
//!
//! A single TCP listener serves both the HTTP enrollment/attachment endpoints and
//! the persistent WebSocket the runner connects on (the runner derives the WS URL
//! from the same host base, so they must share one port). Frames are hand-rolled
//! JSON matching `crate::protocol::frames` exactly — correlation ids (`taskId`,
//! `threadId`, `cronId`, `msgId`, `outboxId`) at the envelope top level, business
//! fields under `data` (snake_case, since the v2 `data` structs carry no
//! `rename_all`).
//!
//! It maintains the host **read models** the architecture mirrors
//! (agent-architecture §8/§10): `thread_runs` by `threadId`, `messages` keyed
//! `(taskId, threadId, seq)` (idempotent — at-least-once replay collapses),
//! `attachments` (uploads), and `cron_states` by `cronId` (the scheduling ledger
//! summary the cron scenarios assert). It implements at-least-once: it `ack`s outbox-backed
//! frames (`thread_message`/`thread_result`/`cron_state`) by `outboxId` and
//! records the runner's `msg_ack`s; [`StubHost::set_auto_ack`] and
//! [`StubHost::drop_connection`] let a scenario withhold acks and sever the socket
//! to drive the reconnect-replay path.
//!
//! ## Endpoints
//! * `POST /agent/register` → `{agentId, connectToken, config}`
//! * `GET  /agent/config/:id` → `{}` (best-effort startup reconcile; tolerated)
//! * `GET  /agent/attachments/:id` → staged inbound bytes (counted, for cache-hit
//!   assertions)
//! * `POST /agent/attachments` → records the upload, returns `{id, ref}`
//! * `WS   /agent/ws/:id` → the frame channel
//!
//! ## E2ee key directory
//! The host records every register body and heartbeat, keeps the runner's
//! KeyPackage pool (`e2ee_key_packages` uploads add to it,
//! [`StubHost::claim_key_packages`] takes from it) and sends the live-only
//! `e2ee_key_package_status` on socket open, after each claim and in answer to
//! each upload (with the upload's `outboxId` as `id`).
//!
//! ## E2ee Delivery Service
//! A minimal DS per task: a handshake log ([`StubHost::ds_append`], delivered
//! with [`StubHost::push_e2ee_log`]), Welcomes ([`StubHost::push_e2ee_welcome`])
//! and epoch links. It answers `e2ee_request` ops `log`, `log_from_epoch`,
//! `link`, `put_link` and `commit` (appended as the next entry, no framing
//! checks) and records every request.

// `result_large_err`: the tungstenite WS-handshake `Callback` signature forces a
// `Result<Response, ErrorResponse>` whose `Err` variant is a large `http::Response`
// — we never return it, but the closure type is fixed by the API.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::result_large_err)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

/// The hex SHA-256 of `bytes` (lowercase), matching the runner's attachment hash.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Build a provisioning-entry descriptor (`{id, sha256, target, kind}`) — the wire
/// shape the runner parses as a `ProvisioningEntry` for both scopes (the global
/// `config.entries` and `task_upsert.data.entries`). `kind` is `"file"` (a single
/// instruction file) or `"dir"` (an unpacked-tar skill bundle). Pure — no host
/// state — so a scenario can assemble a register-config `entries` set *before*
/// [`StubHost::start`], then [`StubHost::stage_blob`] the bytes the runner will
/// fetch by `id`. `sha256` is derived from `bytes`, matching the runner's
/// download-integrity check.
#[must_use]
pub fn provisioning_entry(id: &str, target: &str, kind: &str, bytes: &[u8]) -> Value {
    json!({
        "id": id,
        "sha256": sha256_hex(bytes),
        "target": target,
        "kind": kind,
    })
}

/// Build an uncompressed tar of `members` (`(path, bytes)`), the `kind:dir` bundle
/// shape the runner unpacks into a store directory. A skill bundle is `SKILL.md`
/// plus any support files (e.g. `scripts/run.sh`); the entry's `sha256` is the hash
/// of these tar bytes (`sha256_hex(tar)`), not of any member.
#[must_use]
pub fn build_tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, path, *data)
            .expect("append tar member");
    }
    builder.into_inner().expect("finish tar")
}

/// The ULID `msgId` the stub host sends for test delivery number `n`.
pub fn delivery_id(n: i64) -> String {
    format!("01jab3x7k2m4n5p6q7r8s9{n:04}")
}

/// The host mirror of one thread execution (host `thread_runs` row), updated from
/// the terminal `thread_result`.
#[derive(Clone, Debug, Default)]
pub struct ThreadRun {
    /// Owning task id (envelope `taskId`).
    pub task_id: String,
    /// Terminal status (`succeeded` / `failed` / `cancelled`).
    pub status: String,
    /// `failure_reason` wire string when failed, else `None`.
    pub failure_reason: Option<String>,
    /// Resume handle reported on the result (`None` when dropped/absent).
    pub engine_session_id: Option<String>,
    /// Final assistant result text, when any.
    pub result: Option<String>,
    /// Error detail, when failed.
    pub error: Option<String>,
    /// `final_seq` — the last `seq` the runner emitted on this thread.
    pub final_seq: i64,
    /// Number of `thread_result` frames received (≥2 ⇒ at-least-once replay).
    pub terminal_count: u32,
    /// Outbound attachment descriptors carried on the terminal result.
    pub attachments: Vec<Value>,
    /// `encryption_error` carried on the terminal result, when any.
    pub encryption_error: Option<Value>,
}

/// One mirrored transcript event (host `messages` row).
#[derive(Clone, Debug)]
pub struct MessageRecord {
    /// Per-thread monotonic sequence (the dedup/order key component).
    pub seq: i64,
    /// `MessageKind` wire string (`assistant_text` / `status` / `error` / …).
    pub kind: String,
    /// Text content, when any.
    pub content: Option<String>,
    /// Tool name on a `tool_use` row (the engine's own name, forwarded verbatim).
    pub tool: Option<String>,
    /// Structured `input` (a `tool_use` call's arguments, a `host_action`'s
    /// `{method, params}`).
    pub input: Option<Value>,
    /// The engine's id for a tool call, echoed on the matching `tool_result`.
    pub tool_use_id: Option<String>,
    /// Set only on events produced INSIDE a sub-agent; absence means the main
    /// agent produced it (protocol §5).
    pub parent_tool_use_id: Option<String>,
}

/// A recorded attachment upload (host `attachments` row).
#[derive(Clone, Debug)]
pub struct UploadRecord {
    /// Host-minted id returned to the runner.
    pub id: String,
    /// Original file name (`x-attachment-name`).
    pub name: String,
    /// Content hash the runner computed (`x-attachment-sha256`).
    pub sha256: String,
    /// Declared content type.
    pub content_type: String,
    /// Byte length received.
    pub size: usize,
    /// The bytes received.
    #[allow(dead_code)] // read by the e2ee suite only
    pub bytes: Vec<u8>,
}

/// The host mirror of a cron's local scheduling ledger (host `crons` summary),
/// updated from each `cron_state` frame (agent-architecture §10). `round_count` is
/// the durable truth (`cron_logs MAX(round_seq)`); `skipped_count`/`last_status`
/// are the runner's process-local tally (D2).
#[derive(Clone, Debug, Default)]
pub struct CronStateRecord {
    /// Owning task id (envelope `taskId`).
    pub task_id: String,
    /// Durable round count = `cron_logs MAX(round_seq)`.
    pub round_count: i64,
    /// Process-local skip + miss tally.
    pub skipped_count: i64,
    /// The most recent fire's scheduling status (`dispatched`/`skipped`/`missed`).
    pub last_status: Option<String>,
    /// The cron's lifecycle status (`active`/`completed`/`cancelled`).
    pub status: Option<String>,
    /// The cron's next scheduled fire, when still recurring.
    pub next_run: Option<String>,
    /// Number of `cron_state` frames received (incl. at-least-once replays).
    pub recv_count: u32,
}

/// A cron trigger definition pushed to the runner (`cron_upsert.data`). All five
/// required wire fields are present; `next_run`/`status` are optional overrides the
/// runner otherwise seeds. Built by a scenario and handed to
/// [`StubHost::push_cron_upsert`].
#[derive(Clone, Debug)]
pub struct CronSpec<'a> {
    /// The recurring instruction → `crons.prompt`, snapshotted into each fired
    /// thread's `threads.prompt` (D10).
    pub prompt: &'a str,
    /// Trigger kind (`schedule` is the only wired kind).
    pub kind: &'a str,
    /// `cron` | `interval` | `once`.
    pub schedule_type: &'a str,
    /// The cron expression / interval-ms / RFC3339 instant for `schedule_type`.
    pub schedule_value: &'a str,
    /// `isolated` (new thread per fire) | `shared` (one ongoing thread).
    pub continuity: &'a str,
    /// Explicit `next_run` (else the runner seeds it from the schedule).
    pub next_run: Option<&'a str>,
    /// Explicit lifecycle status (else `active`).
    pub status: Option<&'a str>,
}

struct InboundBlob {
    bytes: Vec<u8>,
    content_type: String,
}

/// The host's in-memory read models + delivery bookkeeping.
#[derive(Default)]
struct Model {
    thread_runs: HashMap<String, ThreadRun>,
    /// Idempotent on `(taskId, threadId, seq)` — replays collapse.
    messages: HashMap<(String, String, i64), MessageRecord>,
    /// Total `thread_message` frames received, including replayed duplicates.
    message_recv_count: u64,
    /// Every `thread_message`/`thread_result` frame as received, in order.
    thread_frames: Vec<Value>,
    /// `msgId`s the runner durably acked (`msg_ack`).
    msg_acks: Vec<String>,
    /// Recorded uploads (host `attachments`).
    uploads: Vec<UploadRecord>,
    /// Cron scheduling-ledger summaries (host `crons`), keyed by `cronId`.
    cron_states: HashMap<String, CronStateRecord>,
    /// Inbound bytes staged for the runner to download, keyed by attachment id.
    inbound_blobs: HashMap<String, InboundBlob>,
    /// Per-id download counter (cache-hit assertions).
    get_counts: HashMap<String, u64>,
    next_upload: u64,
    /// The `x-internal-token` the runner presented on the most recent WS connect.
    observed_connect_token: Option<String>,
    /// Count of WS connections accepted (≥2 ⇒ a reconnect happened).
    ws_connects: u64,
    /// The base register-response `config` overlay (the global `entries` set), seeded
    /// at [`StubHost::start`] and replaceable via [`StubHost::set_served_config`]. The
    /// served config (both `/agent/register` and `GET /agent/config/:id`) is this
    /// object with the monotonic `config_version` injected as `version`.
    register_config: Value,
    /// The host-owned, monotonic GLOBAL config version. Served as
    /// `version` on the config the runner fetches; bumped via
    /// [`StubHost::bump_config_version`] so a restart sees an advanced version.
    config_version: i64,
    /// When set, `GET /agent/config/:id` returns a non-200 (the offline / unreachable
    /// startup-fetch case): the runner must NOT wipe the installed global set.
    config_offline: bool,
    /// Every `POST /agent/register` body, in order.
    register_bodies: Vec<Value>,
    /// Every heartbeat `data`, in order.
    heartbeats: Vec<Value>,
    /// Every `e2ee_key_packages` upload `data`, in order (replays included).
    key_package_uploads: Vec<Value>,
    /// Upload `outboxId`s already applied to the pool (replays are not re-added).
    key_package_upload_ids: Vec<String>,
    /// Unclaimed one-time KeyPackages held for the runner.
    key_packages_one_time: u64,
    /// Whether a last-resort KeyPackage is held for the runner.
    key_packages_last_resort: bool,
    /// Per task: the DS handshake log entries (`e2ee_log` data), in `seq` order.
    ds_logs: HashMap<String, Vec<Value>>,
    /// Per task: the current epoch (advanced by each logged commit).
    ds_epochs: HashMap<String, u64>,
    /// Epoch links by `(taskId, epoch)`, base64url.
    ds_links: HashMap<(String, u64), String>,
    /// Every `e2ee_request` frame received.
    e2ee_requests: Vec<Value>,
    /// Every live remote-operation reply (`fs_response`, `pty_*`), in order.
    remote_op_replies: Vec<Value>,
    /// Every byte the runner sent: HTTP requests (request line, headers, body)
    /// and WS text frames, in arrival order.
    wire: Vec<Vec<u8>>,
}

/// A handle onto the currently-live WS connection: the queue feeding its sink and
/// a close trigger. Replaced on each (re)connect; cleared when the session ends.
struct Conn {
    sink: mpsc::UnboundedSender<Message>,
    close: Arc<Notify>,
}

/// The stub host. Holds the bound address, the host-minted identity, and shared
/// read-model state. Drop aborts the accept loop.
pub struct StubHost {
    /// The bound `127.0.0.1:<port>` address; the runner's `GINO_HOST_URL`.
    pub addr: SocketAddr,
    /// Host-minted connect token returned at registration (the runner presents it
    /// as `x-internal-token`).
    pub connect_token: String,
    model: Arc<Mutex<Model>>,
    conn: Arc<Mutex<Option<Conn>>>,
    auto_ack: Arc<AtomicBool>,
    accept: JoinHandle<()>,
}

impl Drop for StubHost {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl StubHost {
    /// Bind an ephemeral port, start the accept loop, and return a ready host. The
    /// `config` value is returned verbatim as the register-response `config`
    /// overlay (deserialised by the runner's `ConfigOverlay`; camelCase,
    /// `deny_unknown_fields`).
    ///
    /// # Panics
    /// Panics if the listener cannot bind (a broken test environment).
    pub async fn start(config: Value) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind stub host listener");
        let addr = listener.local_addr().expect("stub host local addr");
        let model = Arc::new(Mutex::new(Model {
            register_config: config,
            // The host assigns a monotonic GLOBAL config version; it
            // starts at 1 and a restart-bump scenario advances it.
            config_version: 1,
            ..Model::default()
        }));
        let conn = Arc::new(Mutex::new(None));
        let auto_ack = Arc::new(AtomicBool::new(true));
        let agent_id = "agent-e2e".to_owned();
        let connect_token = "connect-e2e-secret".to_owned();

        let ctx = ConnCtx {
            model: Arc::clone(&model),
            conn: Arc::clone(&conn),
            auto_ack: Arc::clone(&auto_ack),
            agent_id: agent_id.clone(),
            connect_token: connect_token.clone(),
        };
        let accept = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    handle_conn(stream, ctx).await;
                });
            }
        });

        Self {
            addr,
            connect_token,
            model,
            conn,
            auto_ack,
            accept,
        }
    }

    /// The `http://127.0.0.1:<port>` base the runner registers and connects to.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Toggle automatic `ack`ing of outbox-backed frames. With acking off, frames
    /// stay unacked in the runner's outbox and replay on the next connect — the
    /// reconnect-dedup path (§5b #4).
    pub fn set_auto_ack(&self, on: bool) {
        self.auto_ack.store(on, Ordering::SeqCst);
    }

    /// Sever the live WS connection, forcing the runner to reconnect (§5b #4).
    pub async fn drop_connection(&self) {
        if let Some(conn) = self.conn.lock().await.as_ref() {
            conn.close.notify_one();
        }
    }

    /// Stage `bytes` as a downloadable inbound attachment under `id` and return its
    /// wire **descriptor** (for a `message.data.attachments[]`). The descriptor's
    /// `ref` resolves to `GET /agent/attachments/:id`, served from this blob.
    pub async fn stage_inbound_attachment(
        &self,
        id: &str,
        name: &str,
        bytes: &[u8],
        content_type: &str,
    ) -> Value {
        self.model.lock().await.inbound_blobs.insert(
            id.to_owned(),
            InboundBlob {
                bytes: bytes.to_vec(),
                content_type: content_type.to_owned(),
            },
        );
        json!({
            "id": id,
            "name": name,
            "content_type": content_type,
            "size": bytes.len(),
            "sha256": sha256_hex(bytes),
            "ref": format!("/agent/attachments/{id}"),
            "direction": "inbound",
        })
    }

    /// Push a host→agent `message` (the chat-thread prompt). `attachments` is a
    /// list of descriptors (e.g. from [`Self::stage_inbound_attachment`]). Waits
    /// up to 5s for a live WS connection.
    pub async fn push_message(
        &self,
        task_id: &str,
        thread_id: Option<&str>,
        text: &str,
        attachments: &[Value],
        msg_id: i64,
    ) {
        let mut data = json!({ "text": text });
        if !attachments.is_empty() {
            data["attachments"] = Value::from(attachments.to_vec());
        }
        let mut frame = json!({ "type": "message", "taskId": task_id, "data": data, "msgId": delivery_id(msg_id) });
        if let Some(thread_id) = thread_id {
            frame["threadId"] = Value::from(thread_id);
        }
        self.send_raw(&frame.to_string()).await;
    }

    /// Push a host→agent `task_upsert` (seed/edit a task definition). A cron's
    /// `threads.task_id → tasks(id)` FK needs this before its `cron_upsert`.
    pub async fn push_task_upsert(
        &self,
        task_id: &str,
        name: Option<&str>,
        kind: Option<&str>,
        status: Option<&str>,
        msg_id: i64,
    ) {
        let mut data = serde_json::Map::new();
        if let Some(name) = name {
            data.insert("name".to_owned(), Value::from(name));
        }
        if let Some(kind) = kind {
            data.insert("kind".to_owned(), Value::from(kind));
        }
        if let Some(status) = status {
            data.insert("status".to_owned(), Value::from(status));
        }
        let frame = json!({
            "type": "task_upsert",
            "taskId": task_id,
            "data": Value::Object(data),
            "msgId": delivery_id(msg_id),
        });
        self.send_raw(&frame.to_string()).await;
    }

    /// Push a host→agent `cron_upsert` (seed/edit a trigger under a task). The
    /// `data` carries the five required v2 fields (`prompt`/`kind`/`schedule_type`/
    /// `schedule_value`/`continuity`) plus any `next_run`/`status` override.
    pub async fn push_cron_upsert(
        &self,
        task_id: &str,
        cron_id: &str,
        spec: &CronSpec<'_>,
        msg_id: i64,
    ) {
        let mut data = json!({
            "kind": spec.kind,
            "prompt": spec.prompt,
            "schedule_type": spec.schedule_type,
            "schedule_value": spec.schedule_value,
            "continuity": spec.continuity,
        });
        if let Some(next_run) = spec.next_run {
            data["next_run"] = Value::from(next_run);
        }
        if let Some(status) = spec.status {
            data["status"] = Value::from(status);
        }
        let frame = json!({
            "type": "cron_upsert",
            "taskId": task_id,
            "cronId": cron_id,
            "data": data,
            "msgId": delivery_id(msg_id),
        });
        self.send_raw(&frame.to_string()).await;
    }

    /// Push a host→agent `task_upsert` naming the backend the task's threads run
    /// on (`data.engine`, protocol §7). The executor reads it at spawn time, so
    /// this is the only seeding path a scenario needs to route a run onto a
    /// non-default engine.
    pub async fn push_task_upsert_with_engine(&self, task_id: &str, engine: &str, msg_id: i64) {
        let frame = json!({
            "type": "task_upsert",
            "taskId": task_id,
            "data": { "engine": engine, "status": "active" },
            "msgId": delivery_id(msg_id),
        });
        self.send_raw(&frame.to_string()).await;
    }

    /// Stage `bytes` so the runner's provisioning fetch of the store `<name>`
    /// (= entry `id`) resolves them: reconcile downloads `GET /agent/attachments/<id>`
    /// and verifies the bytes hash to the entry's `sha256`, so the staged id MUST
    /// equal the entry id. Inserts into the same inbound-blob map the attachment
    /// plane serves (counted by [`Self::get_count`]); overwrites a prior blob at
    /// `id` (a repoint stages new bytes under the same logical name).
    pub async fn stage_blob(&self, id: &str, bytes: &[u8]) {
        self.model.lock().await.inbound_blobs.insert(
            id.to_owned(),
            InboundBlob {
                bytes: bytes.to_vec(),
                content_type: "application/octet-stream".to_owned(),
            },
        );
    }

    /// Stage `bytes` under `id` ([`Self::stage_blob`]) AND return the matching entry
    /// descriptor ([`provisioning_entry`]) — the host-side counterpart to one
    /// reconcile entry, in one call. Use for `config_update` / `task_upsert` entries
    /// (the host is already running); for a register-config global set, build the
    /// descriptors with [`provisioning_entry`] *before* `start`, then
    /// [`Self::stage_blob`] each.
    pub async fn stage_provisioning_entry(
        &self,
        id: &str,
        target: &str,
        kind: &str,
        bytes: &[u8],
    ) -> Value {
        self.stage_blob(id, bytes).await;
        provisioning_entry(id, target, kind, bytes)
    }

    /// Push a host→agent `config_update` whose `data` is `config` (a full
    /// `ConfigOverlay` payload — carry the new desired global `entries` set AND its
    /// advanced `version` here, since the runner gates the live re-reconcile on the
    /// version). The runner re-reconciles the global scope: add / repoint / remove
    /// converge `engine-config/` without an engine restart.
    pub async fn push_config_update(&self, config: Value) {
        let frame = json!({ "type": "config_update", "data": config });
        self.send_raw(&frame.to_string()).await;
    }

    /// Monotonically bump the served GLOBAL config version and return the new value.
    /// Used by a restart-bump scenario: after the bump, the runner's
    /// startup `GET /agent/config` sees an advanced version and re-reconciles.
    pub async fn bump_config_version(&self) -> i64 {
        let mut model = self.model.lock().await;
        model.config_version += 1;
        model.config_version
    }

    /// Replace the base config the host serves on `/agent/register` and
    /// `GET /agent/config/:id` (the global `entries` set). The monotonic `version`
    /// is injected on top, so a restart-bump scenario pairs this with
    /// [`Self::bump_config_version`] to advance the desired set across a restart.
    pub async fn set_served_config(&self, config: Value) {
        self.model.lock().await.register_config = config;
    }

    /// Toggle the `GET /agent/config/:id` offline (non-200) response — the
    /// unreachable / offline startup-fetch case. With it on, the runner's startup
    /// config fetch fails and the version gate takes the never-wipe repair-only path.
    pub async fn set_config_offline(&self, offline: bool) {
        self.model.lock().await.config_offline = offline;
    }

    /// Push a `task_upsert` carrying `data.entries` (task-scope provisioning: the
    /// task instruction file + task skills). The runner persists them onto the
    /// `tasks` row and materializes them per-thread into `<work_dir>/project/`
    /// (scope = thread id) on the next run.
    pub async fn push_task_upsert_with_entries(
        &self,
        task_id: &str,
        name: Option<&str>,
        kind: Option<&str>,
        status: Option<&str>,
        entries: &[Value],
        msg_id: i64,
    ) {
        let mut data = serde_json::Map::new();
        if let Some(name) = name {
            data.insert("name".to_owned(), Value::from(name));
        }
        if let Some(kind) = kind {
            data.insert("kind".to_owned(), Value::from(kind));
        }
        if let Some(status) = status {
            data.insert("status".to_owned(), Value::from(status));
        }
        data.insert("entries".to_owned(), Value::from(entries.to_vec()));
        let frame = json!({
            "type": "task_upsert",
            "taskId": task_id,
            "data": Value::Object(data),
            "msgId": delivery_id(msg_id),
        });
        self.send_raw(&frame.to_string()).await;
    }

    /// Send an arbitrary host→agent frame (e.g. an `interrupt`, or a
    /// `task_upsert` carrying `meta`), waiting (≤5s) for a live connection.
    pub async fn push_frame(&self, frame: &Value) {
        self.send_raw(&frame.to_string()).await;
    }

    /// Send a raw host→agent frame, waiting (≤5s) for a live connection.
    async fn send_raw(&self, frame: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(conn) = self.conn.lock().await.as_ref()
                && conn.sink.send(Message::text(frame.to_owned())).is_ok()
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no live WS connection to send frame: {frame}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait (≤`timeout`) until the runner has a live WS connection.
    pub async fn wait_connected(&self, timeout: Duration) -> bool {
        self.poll(timeout, |m| m.ws_connects >= 1).await
    }

    /// Wait (≤`timeout`) until the runner has opened `count` WebSocket connections
    /// in total — a restarted daemon is connected once this reaches the
    /// pre-restart count plus one.
    pub async fn wait_connects(&self, count: u64, timeout: Duration) -> bool {
        self.poll(timeout, |m| m.ws_connects >= count).await
    }

    /// Snapshot the mirrored `thread_runs` row for `thread_id`.
    pub async fn thread_run(&self, thread_id: &str) -> Option<ThreadRun> {
        self.model.lock().await.thread_runs.get(thread_id).cloned()
    }

    /// The number of distinct mirrored `thread_runs` (one per thread id) — the
    /// host-side count of executions, which a cron's isolated fires grow by one each.
    pub async fn thread_run_count(&self) -> usize {
        self.model.lock().await.thread_runs.len()
    }

    /// Snapshot the mirrored cron scheduling-ledger summary for `cron_id`.
    pub async fn cron_state(&self, cron_id: &str) -> Option<CronStateRecord> {
        self.model.lock().await.cron_states.get(cron_id).cloned()
    }

    /// Wait (≤`timeout`) until `cron_id`'s ledger reports at least `rounds` rounds
    /// (`cron_state.round_count >= rounds`).
    pub async fn wait_cron_round(&self, cron_id: &str, rounds: i64, timeout: Duration) -> bool {
        let cron_id = cron_id.to_owned();
        self.poll(timeout, move |m| {
            m.cron_states
                .get(&cron_id)
                .is_some_and(|c| c.round_count >= rounds)
        })
        .await
    }

    /// The ordered (by `seq`) mirrored messages for `thread_id`.
    pub async fn messages_for(&self, task_id: &str, thread_id: &str) -> Vec<MessageRecord> {
        let model = self.model.lock().await;
        let mut rows: Vec<MessageRecord> = model
            .messages
            .iter()
            .filter(|((t, th, _), _)| t == task_id && th == thread_id)
            .map(|(_, v)| v.clone())
            .collect();
        rows.sort_by_key(|m| m.seq);
        rows
    }

    /// Every `thread_message`/`thread_result` frame received for `thread_id`,
    /// as sent (replays included), in arrival order.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn thread_frames(&self, thread_id: &str) -> Vec<Value> {
        let model = self.model.lock().await;
        model
            .thread_frames
            .iter()
            .filter(|frame| frame["threadId"] == thread_id)
            .cloned()
            .collect()
    }

    /// Total `thread_message` frames received, including replayed duplicates.
    pub async fn message_recv_count(&self) -> u64 {
        self.model.lock().await.message_recv_count
    }

    /// Every byte the runner sent the host: HTTP requests (request line,
    /// headers, body) and WS text frames, in arrival order.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn wire(&self) -> Vec<Vec<u8>> {
        self.model.lock().await.wire.clone()
    }

    /// The recorded attachment uploads (host `attachments`).
    pub async fn uploads(&self) -> Vec<UploadRecord> {
        self.model.lock().await.uploads.clone()
    }

    /// How many times the inbound attachment `id` was downloaded (cache-hit ⇒ no
    /// new download on repeat).
    pub async fn get_count(&self, id: &str) -> u64 {
        self.model
            .lock()
            .await
            .get_counts
            .get(id)
            .copied()
            .unwrap_or(0)
    }

    /// The `msgId`s the runner durably acked.
    pub async fn msg_acks(&self) -> Vec<String> {
        self.model.lock().await.msg_acks.clone()
    }

    /// The connect token the runner presented on its most recent WS handshake.
    pub async fn observed_connect_token(&self) -> Option<String> {
        self.model.lock().await.observed_connect_token.clone()
    }

    /// The number of WS connections accepted (≥2 ⇒ a reconnect occurred).
    pub async fn ws_connects(&self) -> u64 {
        self.model.lock().await.ws_connects
    }

    /// Poll `pred` against the model every 20ms up to `timeout`; `true` if it ever
    /// held. Private: `Model` is an internal type.
    /// Every `POST /agent/register` body received.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn register_bodies(&self) -> Vec<Value> {
        self.model.lock().await.register_bodies.clone()
    }

    /// Every heartbeat `data` received.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn heartbeats(&self) -> Vec<Value> {
        self.model.lock().await.heartbeats.clone()
    }

    /// Wait (≤`timeout`) until `count` heartbeats have arrived in total.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn wait_heartbeats(&self, count: usize, timeout: Duration) -> bool {
        self.poll(timeout, |m| m.heartbeats.len() >= count).await
    }

    /// Every `e2ee_key_packages` upload `data` received (replays included).
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn key_package_uploads(&self) -> Vec<Value> {
        self.model.lock().await.key_package_uploads.clone()
    }

    /// Wait (≤`timeout`) until `count` distinct KeyPackage uploads arrived.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn wait_key_package_uploads(&self, count: usize, timeout: Duration) -> bool {
        self.poll(timeout, |m| m.key_package_upload_ids.len() >= count)
            .await
    }

    /// The runner's pool at the host: unclaimed one-time KeyPackages and
    /// whether a last-resort one is held.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn key_package_pool(&self) -> (u64, bool) {
        let model = self.model.lock().await;
        (model.key_packages_one_time, model.key_packages_last_resort)
    }

    /// Claim `count` one-time KeyPackages (as members adding the runner do)
    /// and send the resulting status.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn claim_key_packages(&self, count: u64) {
        let status = {
            let mut model = self.model.lock().await;
            model.key_packages_one_time = model.key_packages_one_time.saturating_sub(count);
            key_package_status(&model, None)
        };
        self.send_raw(&status).await;
    }

    /// Append an entry (`e2ee_log` data with its `seq`) to the task's DS log
    /// without delivering it.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn ds_append(&self, task_id: &str, entry: Value) {
        ds_log_entry(&mut *self.model.lock().await, task_id, entry);
    }

    /// Append an entry to the task's DS log and deliver it as a durable
    /// `e2ee_log`.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn push_e2ee_log(&self, task_id: &str, entry: Value, msg_id: i64) {
        self.ds_append(task_id, entry.clone()).await;
        let frame = json!({
            "type": "e2ee_log", "taskId": task_id, "data": entry, "msgId": delivery_id(msg_id),
        });
        self.send_raw(&frame.to_string()).await;
    }

    /// Deliver a durable `e2ee_welcome` with the `seq` of its commit.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn push_e2ee_welcome(&self, task_id: &str, welcome: &str, seq: u64, msg_id: i64) {
        let frame = json!({
            "type": "e2ee_welcome", "taskId": task_id,
            "data": { "welcome": welcome, "seq": seq }, "msgId": delivery_id(msg_id),
        });
        self.send_raw(&frame.to_string()).await;
    }

    /// Store the epoch link of `epoch` for the task.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn ds_put_link(&self, task_id: &str, epoch: u64, link: &str) {
        self.model
            .lock()
            .await
            .ds_links
            .insert((task_id.to_owned(), epoch), link.to_owned());
    }

    /// Every `e2ee_request` frame received.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn e2ee_requests(&self) -> Vec<Value> {
        self.model.lock().await.e2ee_requests.clone()
    }

    /// Wait (≤`timeout`) for an `e2ee_request` whose `data` equals `data`.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn wait_e2ee_request(&self, data: &Value, timeout: Duration) -> bool {
        self.poll(timeout, |m| {
            m.e2ee_requests.iter().any(|r| r["data"] == *data)
        })
        .await
    }

    /// Wait (≤`timeout`) for the first remote-operation reply of one of
    /// `kinds` whose correlation field `key` (`reqId` or `ptyId`) is `id`.
    #[allow(dead_code)] // used by the e2ee suite only
    pub async fn wait_remote_op_reply(
        &self,
        kinds: &[&str],
        key: &str,
        id: &str,
        timeout: Duration,
    ) -> Option<Value> {
        let matches =
            |frame: &Value| kinds.iter().any(|kind| frame["type"] == *kind) && frame[key] == id;
        self.poll(timeout, |m| m.remote_op_replies.iter().any(matches))
            .await;
        self.model
            .lock()
            .await
            .remote_op_replies
            .iter()
            .find(|frame| matches(frame))
            .cloned()
    }

    async fn poll<F>(&self, timeout: Duration, pred: F) -> bool
    where
        F: Fn(&Model) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if pred(&*self.model.lock().await) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Wait (≤`timeout`) for `thread_id` to reach a terminal `thread_result`.
    pub async fn wait_thread_terminal(
        &self,
        thread_id: &str,
        timeout: Duration,
    ) -> Option<ThreadRun> {
        let thread_id = thread_id.to_owned();
        self.poll(timeout, |m| {
            m.thread_runs
                .get(&thread_id)
                .is_some_and(|tr| !tr.status.is_empty())
        })
        .await;
        self.thread_run(&thread_id).await
    }

    /// Wait (≤`timeout`) until `thread_id`'s mirror has received at least `n`
    /// `thread_result` frames (`terminal_count >= n`) — `≥2` proves an at-least-once
    /// replay of the terminal result (e.g. across a crash/restart).
    pub async fn wait_thread_terminal_count(
        &self,
        thread_id: &str,
        n: u32,
        timeout: Duration,
    ) -> bool {
        let thread_id = thread_id.to_owned();
        self.poll(timeout, move |m| {
            m.thread_runs
                .get(&thread_id)
                .is_some_and(|tr| tr.terminal_count >= n)
        })
        .await
    }

    /// Wait (≤`timeout`) until `thread_id` has at least `n` unique mirrored
    /// messages.
    pub async fn wait_message_count(
        &self,
        task_id: &str,
        thread_id: &str,
        n: usize,
        timeout: Duration,
    ) -> bool {
        let task_id = task_id.to_owned();
        let thread_id = thread_id.to_owned();
        self.poll(timeout, move |m| {
            m.messages
                .keys()
                .filter(|(t, th, _)| *t == task_id && *th == thread_id)
                .count()
                >= n
        })
        .await
    }

    /// Wait (≤`timeout`) for at least `n` recorded attachment uploads.
    pub async fn wait_upload_count(&self, n: usize, timeout: Duration) -> bool {
        self.poll(timeout, move |m| m.uploads.len() >= n).await
    }

    /// Wait (≤`timeout`) for a reconnect (≥2 WS connects) that re-sent frames
    /// beyond `min_recv` — i.e. the outbox replayed unacked rows.
    pub async fn wait_reconnect_replay(&self, min_recv: u64, timeout: Duration) -> bool {
        self.poll(timeout, move |m| {
            m.ws_connects >= 2 && m.message_recv_count > min_recv
        })
        .await
    }
}

/// The per-connection context cloned into each accept task.
#[derive(Clone)]
struct ConnCtx {
    model: Arc<Mutex<Model>>,
    conn: Arc<Mutex<Option<Conn>>>,
    auto_ack: Arc<AtomicBool>,
    agent_id: String,
    connect_token: String,
}

/// Detect WS-vs-HTTP by peeking (not consuming) the request head, then dispatch.
async fn handle_conn(stream: TcpStream, ctx: ConnCtx) {
    let mut peek = [0u8; 1024];
    let Ok(n) = stream.peek(&mut peek).await else {
        return;
    };
    let head = String::from_utf8_lossy(&peek[..n]).to_ascii_lowercase();
    // Match either the upgrade header or the WS path, so a peek that caught only
    // the request line still routes correctly.
    if head.contains("upgrade: websocket") || head.contains("/agent/ws/") {
        handle_ws(stream, ctx).await;
    } else {
        handle_http(stream, ctx).await;
    }
}

/// A parsed HTTP request (one per connection; `Connection: close`).
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Read and parse a single HTTP/1.1 request from `stream`.
async fn read_http_request(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Some(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

/// Serve one HTTP request, then close.
async fn handle_http(mut stream: TcpStream, ctx: ConnCtx) {
    let Some(req) = read_http_request(&mut stream).await else {
        return;
    };
    let response = route_http(&req, &ctx).await;
    let _ = stream.write_all(&response).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

async fn route_http(req: &HttpRequest, ctx: &ConnCtx) -> Vec<u8> {
    let mut raw = format!("{} {}\n", req.method, req.path).into_bytes();
    for (name, value) in &req.headers {
        raw.extend(format!("{name}: {value}\n").into_bytes());
    }
    raw.extend(&req.body);
    ctx.model.lock().await.wire.push(raw);
    let path = req.path.as_str();
    match (req.method.as_str(), path) {
        ("POST", "/agent/register") => {
            let mut model = ctx.model.lock().await;
            if let Ok(body) = serde_json::from_slice::<Value>(&req.body) {
                model.register_bodies.push(body);
            }
            let config = served_config(&model);
            drop(model);
            let body = json!({
                "agentId": ctx.agent_id,
                "connectToken": ctx.connect_token,
                "config": config,
            });
            json_response("200 OK", &body)
        }
        ("POST", "/agent/attachments") => {
            let name = header(req, "x-attachment-name").unwrap_or_default();
            let sha = header(req, "x-attachment-sha256").unwrap_or_default();
            let content_type = header(req, "content-type").unwrap_or_default();
            let mut model = ctx.model.lock().await;
            model.next_upload += 1;
            let id = format!("up-{}", model.next_upload);
            model.uploads.push(UploadRecord {
                id: id.clone(),
                name,
                sha256: sha,
                content_type,
                size: req.body.len(),
                bytes: req.body.clone(),
            });
            let body = json!({ "id": id, "ref": format!("/agent/attachments/{id}") });
            json_response("200 OK", &body)
        }
        // Content-addressed blob fetch (provisioning): the runner asks
        // `GET /agent/attachments?sha256=<hex>`; serve whichever staged blob
        // hashes to it (counted under the STAGED id, so cache-hit assertions
        // keep working).
        ("GET", _) if path.starts_with("/agent/attachments?sha256=") => {
            let sha = path
                .trim_start_matches("/agent/attachments?sha256=")
                .to_owned();
            let mut model = ctx.model.lock().await;
            let hit = model
                .inbound_blobs
                .iter()
                .find(|(_, blob)| sha256_hex(&blob.bytes) == sha)
                .map(|(id, blob)| (id.clone(), blob.content_type.clone(), blob.bytes.clone()));
            match hit {
                Some((id, content_type, bytes)) => {
                    *model.get_counts.entry(id).or_insert(0) += 1;
                    bytes_response("200 OK", &content_type, &bytes)
                }
                None => text_response("404 Not Found", "no blob with that sha256"),
            }
        }
        ("GET", _) if path.starts_with("/agent/attachments/") => {
            let id = path.trim_start_matches("/agent/attachments/").to_owned();
            let mut model = ctx.model.lock().await;
            *model.get_counts.entry(id.clone()).or_insert(0) += 1;
            match model.inbound_blobs.get(&id) {
                Some(blob) => bytes_response("200 OK", &blob.content_type, &blob.bytes),
                None => text_response("404 Not Found", "no such attachment"),
            }
        }
        ("GET", _) if path.starts_with("/agent/config/") => {
            // The runner fetches the AUTHORITATIVE config here at startup
            // (version gate). Serve the SAME versioned config the register response
            // carries — version + entries — so a restart re-acquires the desired set.
            let model = ctx.model.lock().await;
            if model.config_offline {
                // The offline / unreachable case: the runner must keep the installed
                // global set (repair-only), not wipe it.
                text_response("503 Service Unavailable", "config offline")
            } else {
                json_response("200 OK", &served_config(&model))
            }
        }
        _ => text_response("404 Not Found", "not found"),
    }
}

/// Run the persistent WS session: record the connect, publish a sink handle, pump
/// frames until the runner disconnects or [`StubHost::drop_connection`] fires.
async fn handle_ws(stream: TcpStream, ctx: ConnCtx) {
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let observed_cb = Arc::clone(&observed);
    let callback =
        |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
         resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            if let Some(value) = req.headers().get("x-internal-token")
                && let Ok(token) = value.to_str()
            {
                *observed_cb
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(token.to_owned());
            }
            Ok(resp)
        };
    let Ok(ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };

    let token = observed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    {
        let mut model = ctx.model.lock().await;
        model.ws_connects += 1;
        model.observed_connect_token = token;
    }

    let (mut write, mut read) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    // The host reports the runner's KeyPackage pool when the socket opens.
    let status = key_package_status(&*ctx.model.lock().await, None);
    let _ = tx.send(Message::text(status));
    let close = Arc::new(Notify::new());
    *ctx.conn.lock().await = Some(Conn {
        sink: tx,
        close: Arc::clone(&close),
    });

    loop {
        let closed = close.notified();
        tokio::pin!(closed);
        tokio::select! {
            () = &mut closed => {
                let _ = write.send(Message::Close(None)).await;
                break;
            }
            outgoing = rx.recv() => {
                match outgoing {
                    Some(msg) => {
                        if write.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            incoming = read.next() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        let mut failed = false;
                        for reply in handle_frame(text.as_str(), &ctx).await {
                            if write.send(Message::text(reply)).await.is_err() {
                                failed = true;
                                break;
                            }
                        }
                        if failed {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => {} // ping/pong/binary — ignore
                }
            }
        }
    }

    // Clear the shared handle only if it is still ours (a fast reconnect may have
    // already replaced it).
    let mut guard = ctx.conn.lock().await;
    if guard
        .as_ref()
        .is_some_and(|c| Arc::ptr_eq(&c.close, &close))
    {
        *guard = None;
    }
}

/// Record a KeyPackage upload (once per `outboxId`) and return the `ack`
/// (when auto-acking) and the answering status.
fn on_key_packages(model: &mut Model, frame: &Value, data: Value, auto_ack: bool) -> Vec<String> {
    let outbox_id = frame
        .get("outboxId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if !model.key_package_upload_ids.contains(&outbox_id) {
        model.key_package_upload_ids.push(outbox_id.clone());
        let added = data
            .get("one_time")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        model.key_packages_one_time += added as u64;
        if data.get("last_resort").is_some() {
            model.key_packages_last_resort = true;
        }
    }
    model.key_package_uploads.push(data);
    let mut replies = Vec::new();
    if auto_ack {
        replies.push(json!({ "type": "ack", "id": outbox_id }).to_string());
    }
    replies.push(key_package_status(model, Some(&outbox_id)));
    replies
}

/// Apply one agent→host frame to the read models. Returns the frames to send
/// back: an `ack` when the frame is outbox-backed and auto-acking is on, then,
/// for a KeyPackage upload, the answering `e2ee_key_package_status`.
async fn handle_frame(text: &str, ctx: &ConnCtx) -> Vec<String> {
    ctx.model.lock().await.wire.push(text.as_bytes().to_vec());
    let Ok(frame) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let kind = frame
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let data = frame.get("data").cloned().unwrap_or(Value::Null);
    let task_id = frame
        .get("taskId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let thread_id = frame
        .get("threadId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let mut model = ctx.model.lock().await;
    if matches!(kind, "thread_message" | "thread_result") {
        model.thread_frames.push(frame.clone());
    }
    match kind {
        "thread_message" => {
            model.message_recv_count += 1;
            let seq = data.get("seq").and_then(Value::as_i64).unwrap_or(0);
            let record = MessageRecord {
                seq,
                kind: data
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                content: data
                    .get("content")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                tool: data.get("tool").and_then(Value::as_str).map(str::to_owned),
                input: data.get("input").cloned(),
                tool_use_id: data
                    .get("tool_use_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                parent_tool_use_id: data
                    .get("parent_tool_use_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            };
            // Idempotent on (taskId, threadId, seq): replays collapse.
            model
                .messages
                .entry((task_id, thread_id, seq))
                .or_insert(record);
        }
        "thread_result" => {
            let entry = model.thread_runs.entry(thread_id).or_default();
            entry.task_id = task_id;
            data.get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .clone_into(&mut entry.status);
            entry.failure_reason = data
                .get("failure_reason")
                .and_then(Value::as_str)
                .map(str::to_owned);
            entry.engine_session_id = data
                .get("engine_session_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
            entry.result = data
                .get("result")
                .and_then(Value::as_str)
                .map(str::to_owned);
            entry.error = data.get("error").and_then(Value::as_str).map(str::to_owned);
            entry.final_seq = data.get("final_seq").and_then(Value::as_i64).unwrap_or(0);
            entry.terminal_count += 1;
            if let Some(arr) = data.get("attachments").and_then(Value::as_array) {
                entry.attachments.clone_from(arr);
            }
            entry.encryption_error = data.get("encryption_error").cloned();
        }
        "cron_state" => {
            // Correlated by the envelope `cronId` (not a thread). The ledger is
            // monotonic, so the highest-`round_count` frame wins; replays of an
            // earlier snapshot never regress it.
            let cron_id = frame
                .get("cronId")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let round = data.get("round_count").and_then(Value::as_i64).unwrap_or(0);
            let entry = model.cron_states.entry(cron_id).or_default();
            entry.task_id = task_id;
            entry.recv_count += 1;
            if round >= entry.round_count {
                entry.round_count = round;
                entry.skipped_count = data
                    .get("skipped_count")
                    .and_then(Value::as_i64)
                    .unwrap_or(entry.skipped_count);
                entry.last_status = data
                    .get("last_status")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                entry.status = data
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                entry.next_run = data
                    .get("next_run")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
        }
        "msg_ack" => {
            if let Some(msg_id) = frame.get("msgId").and_then(Value::as_str) {
                model.msg_acks.push(msg_id.to_owned());
            }
            return Vec::new();
        }
        "heartbeat" => {
            model.heartbeats.push(data);
            return Vec::new();
        }
        "e2ee_request" => {
            model.e2ee_requests.push(frame.clone());
            let response = ds_answer(&mut model, &task_id, &data);
            let reply = json!({
                "type": "e2ee_response",
                "taskId": task_id,
                "reqId": frame.get("reqId").cloned().unwrap_or(Value::Null),
                "data": response,
            });
            return vec![reply.to_string()];
        }
        "fs_response" | "pty_ready" | "pty_output" | "pty_exit" => {
            model.remote_op_replies.push(frame.clone());
            return Vec::new();
        }
        "e2ee_key_packages" => {
            return on_key_packages(
                &mut model,
                &frame,
                data,
                ctx.auto_ack.load(Ordering::SeqCst),
            );
        }
        _ => {}
    }

    // Outbox-backed frames carry an `outboxId`; ack it (unless withholding).
    if ctx.auto_ack.load(Ordering::SeqCst)
        && let Some(outbox_id) = frame.get("outboxId").and_then(Value::as_str)
    {
        return vec![json!({ "type": "ack", "id": outbox_id }).to_string()];
    }
    Vec::new()
}

/// Append `entry` to the task's DS log; a commit advances the epoch.
fn ds_log_entry(model: &mut Model, task_id: &str, entry: Value) {
    if entry["kind"] == "commit"
        && let Some(epoch) = entry["epoch"].as_u64()
    {
        model.ds_epochs.insert(task_id.to_owned(), epoch + 1);
    }
    model
        .ds_logs
        .entry(task_id.to_owned())
        .or_default()
        .push(entry);
}

/// The `e2ee_response` data for one DS operation.
fn ds_answer(model: &mut Model, task_id: &str, request: &Value) -> Value {
    let log = model.ds_logs.get(task_id).cloned().unwrap_or_default();
    let epoch = model.ds_epochs.get(task_id).copied().unwrap_or(0);
    let number = |key: &str| request.get(key).and_then(Value::as_u64).unwrap_or(0);
    match request
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "log" => {
            let after = number("after_seq");
            let entries: Vec<Value> = log
                .into_iter()
                .filter(|e| e["seq"].as_u64().unwrap_or(0) > after)
                .collect();
            json!({ "ok": true, "entries": entries, "more": false, "epoch": epoch })
        }
        "log_from_epoch" => {
            let from = number("epoch");
            let entries: Vec<Value> = log
                .into_iter()
                .skip_while(|e| e["epoch"].as_u64().unwrap_or(0) < from)
                .collect();
            json!({ "ok": true, "entries": entries, "more": false, "epoch": epoch })
        }
        "link" => {
            let link = model.ds_links.get(&(task_id.to_owned(), number("epoch")));
            match link {
                Some(link) => json!({ "ok": true, "link": link, "epoch": epoch }),
                None => json!({ "ok": true, "epoch": epoch }),
            }
        }
        "put_link" => {
            let key = (task_id.to_owned(), number("epoch"));
            if let Some(link) = model.ds_links.get(&key) {
                return json!({ "ok": false, "error": { "code": "link_exists" }, "link": link });
            }
            let link = request.get("link").cloned().unwrap_or(Value::Null);
            model
                .ds_links
                .insert(key, link.as_str().unwrap_or_default().to_owned());
            json!({ "ok": true })
        }
        "commit" => {
            let seq = log.len() as u64 + 1;
            let entry = json!({
                "seq": seq, "kind": "commit", "epoch": epoch,
                "message": request.get("commit").cloned().unwrap_or(Value::Null),
                "drop_public_key": request.get("drop_public_key").cloned().unwrap_or(Value::Null),
            });
            if let Some(link) = request.get("epoch_link").and_then(Value::as_str) {
                model
                    .ds_links
                    .insert((task_id.to_owned(), epoch + 1), link.to_owned());
            }
            ds_log_entry(model, task_id, entry);
            json!({ "ok": true, "seq": seq, "epoch": epoch + 1 })
        }
        _ => json!({ "ok": false, "error": { "code": "malformed" } }),
    }
}

/// The `e2ee_key_package_status` frame for the current pool; `id` answers an
/// upload.
fn key_package_status(model: &Model, id: Option<&str>) -> String {
    let data = json!({
        "one_time": model.key_packages_one_time,
        "last_resort": model.key_packages_last_resort,
    });
    let mut frame = json!({ "type": "e2ee_key_package_status", "data": data });
    if let Some(id) = id {
        frame["id"] = Value::from(id);
    }
    frame.to_string()
}

/// The config the host serves on `/agent/register` and `GET /agent/config/:id`:
/// the base `register_config` with the monotonic `config_version` injected as
/// `version`. A non-object base is served verbatim (defensive; the
/// scenarios always pass an object).
fn served_config(model: &Model) -> Value {
    let mut config = model.register_config.clone();
    if let Some(obj) = config.as_object_mut() {
        obj.insert("version".to_owned(), Value::from(model.config_version));
    }
    config
}

fn header(req: &HttpRequest, name: &str) -> Option<String> {
    req.headers.get(name).cloned()
}

fn json_response(status: &str, body: &Value) -> Vec<u8> {
    bytes_response(status, "application/json", body.to_string().as_bytes())
}

fn text_response(status: &str, body: &str) -> Vec<u8> {
    bytes_response(status, "text/plain", body.as_bytes())
}

fn bytes_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
