//! mini-host — a minimal gino host speaking the host-agent protocol (`docs/protocol.md`).
//!
//! Enough to enroll a `gino-agent`, dispatch work to it and read back the execution transcript.
//! Not a production control plane: no launchers, no attachments, no provisioning, no end-to-end
//! encryption and no auth on the operator API (bind it to loopback).
//!
//! Agent side (protocol v1):
//!   POST /agent/register          GET /agent/config/{id}
//!   WS   /agent/ws/{id}           POST /agent/output/{id}
//!
//! Operator side (JSON):
//!   GET    /api/agents
//!   GET    /api/tasks                       POST /api/tasks {agentId?, taskId?, name?, kind?, engine?, model?, workdir?, meta?}
//!   GET    /api/tasks/{id}                  DELETE /api/tasks/{id}
//!   POST   /api/tasks/{id}/messages         {text, newThread?}   → {threadId, msgId}
//!   POST   /api/tasks/{id}/interrupt
//!   POST   /api/tasks/{id}/crons            {cronId?, prompt, scheduleType, scheduleValue, continuity?}
//!   DELETE /api/tasks/{id}/crons/{cronId}
//!   GET    /api/tasks/{id}/threads
//!   GET    /api/threads/{threadId}          run + ordered transcript
//!   GET    /api/threads/{threadId}/wait?timeoutMs=60000   long-poll for the terminal result
//!   GET    /api/crons

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{
    CloseFrame, Message, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, Params, params};
use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// The protocol version this host speaks.
pub const PROTOCOL_VERSION: u64 = 1;
const HEARTBEAT_INTERVAL_MS: u64 = 30_000;
const WAIT_POLL: Duration = Duration::from_millis(200);

const SCHEMA: &str = "
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY, name TEXT, connect_token TEXT NOT NULL,
    capabilities TEXT, registered_at TEXT NOT NULL, last_seen TEXT
  );
  CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
    frame TEXT NOT NULL, acked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, name TEXT,
    current_thread_id TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS thread_runs (
    thread_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, status TEXT NOT NULL,
    result TEXT, error TEXT, failure_reason TEXT, engine_session_id TEXT,
    duration_ms INTEGER, final_seq INTEGER, received_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    task_id TEXT NOT NULL, thread_id TEXT NOT NULL, seq INTEGER NOT NULL,
    kind TEXT NOT NULL, data TEXT NOT NULL, received_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, seq)
  );
  CREATE TABLE IF NOT EXISTS cron_states (
    cron_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, data TEXT NOT NULL, received_at TEXT NOT NULL
  );
";

/// Host settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// The enrollment secret an agent must present to register.
    pub register_token: String,
    /// The SQLite file (`:memory:` for an in-memory database).
    pub db_path: PathBuf,
    /// Forwarded to every agent as `config.engine` (credentials, base URL, model).
    pub engine: Map<String, Value>,
}

#[derive(Debug)]
struct Peer {
    conn: u64,
    tx: mpsc::UnboundedSender<Message>,
}

/// Shared host state: the database and the live agent sockets.
#[derive(Debug)]
pub struct Host {
    config: Config,
    db: Mutex<Connection>,
    peers: Mutex<HashMap<String, Peer>>,
    ids: Mutex<ulid::Generator>,
    next_conn: AtomicU64,
}

/// A handler failure, answered as `500 {"error": …}`.
#[derive(Debug)]
pub struct HostError(String);

impl<E: std::fmt::Display> From<E> for HostError {
    fn from(err: E) -> Self {
        Self(err.to_string())
    }
}

impl IntoResponse for HostError {
    fn into_response(self) -> Response {
        error!(error = %self.0, "request failed");
        reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({ "error": self.0 }),
        )
    }
}

type Reply = Result<Response, HostError>;
type Shared = State<Arc<Host>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn reply(status: StatusCode, body: &Value) -> Response {
    (status, Json(body)).into_response()
}

fn fail(status: StatusCode, message: &str) -> Response {
    reply(status, &json!({ "error": message }))
}

fn now() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

fn base36(mut n: u128) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    loop {
        out.push(DIGITS[usize::try_from(n % 36).unwrap_or(0)]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// `<prefix>-<base36 ms>-<8 hex>`.
fn new_id(prefix: &str) -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let random = uuid::Uuid::new_v4().simple().to_string();
    format!("{prefix}-{}-{}", base36(ms), &random[..8])
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn non_empty<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    str_field(value, key).filter(|s| !s.is_empty())
}

/// The request body as a JSON object; anything else reads as `{}`.
fn body_object(body: &[u8]) -> Value {
    serde_json::from_slice::<Value>(body)
        .ok()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

fn parse_json_text(text: Option<&str>) -> Value {
    text.and_then(|t| serde_json::from_str(t).ok())
        .unwrap_or(Value::Null)
}

/// Rows as JSON objects keyed by column name.
fn rows<P: Params>(
    db: &Connection,
    sql: &str,
    params: P,
) -> rusqlite::Result<Vec<Map<String, Value>>> {
    let mut stmt = db.prepare(sql)?;
    let names: Vec<String> = stmt.column_names().map(ToString::to_string).collect();
    let mut out = Vec::new();
    let mut cursor = stmt.query(params)?;
    while let Some(row) = cursor.next()? {
        let mut object = Map::new();
        for (i, name) in names.iter().enumerate() {
            let value = match row.get_ref(i)? {
                ValueRef::Integer(n) => json!(n),
                ValueRef::Real(f) => json!(f),
                ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
                ValueRef::Null | ValueRef::Blob(_) => Value::Null,
            };
            object.insert(name.clone(), value);
        }
        out.push(object);
    }
    Ok(out)
}

fn first_row<P: Params>(
    db: &Connection,
    sql: &str,
    params: P,
) -> rusqlite::Result<Option<Map<String, Value>>> {
    Ok(rows(db, sql, params)?.into_iter().next())
}

impl Host {
    /// Open (or create) the database.
    pub fn open(config: Config) -> rusqlite::Result<Arc<Self>> {
        let db = Connection::open(&config.db_path)?;
        db.execute_batch(SCHEMA)?;
        Ok(Arc::new(Self {
            config,
            db: Mutex::new(db),
            peers: Mutex::new(HashMap::new()),
            ids: Mutex::new(ulid::Generator::new()),
            next_conn: AtomicU64::new(0),
        }))
    }

    /// Monotonic lowercase ULID.
    fn ulid(&self) -> Result<String, HostError> {
        Ok(lock(&self.ids).generate()?.to_string().to_lowercase())
    }

    fn online(&self, agent_id: &str) -> bool {
        lock(&self.peers).contains_key(agent_id)
    }

    fn send(&self, agent_id: &str, frame: &Value) -> bool {
        lock(&self.peers).get(agent_id).is_some_and(|peer| {
            peer.tx
                .send(Message::Text(frame.to_string().into()))
                .is_ok()
        })
    }

    fn agent_config(&self, agent_id: &str) -> Value {
        json!({
            "agentId": agent_id,
            "wsUrl": format!("/agent/ws/{agent_id}"),
            "configUrl": format!("/agent/config/{agent_id}"),
            "outputUrl": format!("/agent/output/{agent_id}"),
            "heartbeatIntervalMs": HEARTBEAT_INTERVAL_MS,
            "protocolVersion": PROTOCOL_VERSION,
            "entries": [],
            "version": 0,
            "engine": self.config.engine,
        })
    }

    /// Persist a host→agent frame (its row id is the `msgId`) and push it if the agent is online.
    fn enqueue(&self, agent_id: &str, frame: Value) -> Result<String, HostError> {
        let id = self.ulid()?;
        lock(&self.db).execute(
            "INSERT INTO outbox (id, agent_id, frame, created_at) VALUES (?, ?, ?, ?)",
            params![id, agent_id, frame.to_string(), now()],
        )?;
        let mut frame = frame;
        if let Some(object) = frame.as_object_mut() {
            object.insert("msgId".into(), Value::String(id.clone()));
        }
        self.send(agent_id, &frame);
        Ok(id)
    }

    /// The agent whose connect token is `token`, if `agent_id` exists and matches.
    fn authenticate(&self, headers: &HeaderMap, agent_id: &str) -> Result<bool, HostError> {
        let token = headers
            .get("x-internal-token")
            .and_then(|v| v.to_str().ok());
        let stored: Option<String> = lock(&self.db)
            .query_row(
                "SELECT connect_token FROM agents WHERE id = ?",
                [agent_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(matches!((token, stored), (Some(t), Some(s)) if t == s))
    }

    /// Mirror one inbound frame; returns the `outboxId` to ack, if any.
    fn handle_agent_frame(
        &self,
        agent_id: &str,
        frame: &Value,
    ) -> Result<Option<String>, HostError> {
        let outbox_id = str_field(frame, "outboxId").map(str::to_owned);
        let task_id = str_field(frame, "taskId").unwrap_or_default();
        let thread_id = str_field(frame, "threadId").unwrap_or_default();
        let empty = json!({});
        let data = frame
            .get("data")
            .filter(|d| d.is_object())
            .unwrap_or(&empty);
        let ts = now();
        let db = lock(&self.db);
        match str_field(frame, "type") {
            Some("msg_ack") => {
                if let Some(msg_id) = str_field(frame, "msgId") {
                    db.execute(
                        "UPDATE outbox SET acked = 1 WHERE id = ? AND agent_id = ?",
                        params![msg_id, agent_id],
                    )?;
                }
                return Ok(None);
            }
            Some("heartbeat") => {
                db.execute(
                    "UPDATE agents SET last_seen = ? WHERE id = ?",
                    params![ts, agent_id],
                )?;
            }
            Some("thread_message") => {
                if let (false, Some(seq)) = (
                    thread_id.is_empty(),
                    data.get("seq").and_then(Value::as_i64),
                ) {
                    db.execute(
                        "INSERT OR IGNORE INTO threads (id, task_id, created_at) VALUES (?, ?, ?)",
                        params![thread_id, task_id, ts],
                    )?;
                    db.execute(
                        "INSERT OR IGNORE INTO messages (task_id, thread_id, seq, kind, data, received_at) VALUES (?, ?, ?, ?, ?, ?)",
                        params![task_id, thread_id, seq, str_field(data, "kind").unwrap_or("unknown"), data.to_string(), ts],
                    )?;
                }
            }
            Some("thread_result") => {
                if !thread_id.is_empty() {
                    db.execute(
                        "INSERT OR IGNORE INTO threads (id, task_id, created_at) VALUES (?, ?, ?)",
                        params![thread_id, task_id, ts],
                    )?;
                    db.execute(
                        "INSERT INTO thread_runs (thread_id, task_id, status, result, error, failure_reason, engine_session_id, duration_ms, final_seq, received_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         ON CONFLICT(thread_id) DO UPDATE SET status = excluded.status, result = excluded.result, error = excluded.error,
                           failure_reason = excluded.failure_reason, engine_session_id = excluded.engine_session_id,
                           duration_ms = excluded.duration_ms, final_seq = excluded.final_seq, received_at = excluded.received_at",
                        params![
                            thread_id,
                            task_id,
                            str_field(data, "status").unwrap_or("unknown"),
                            str_field(data, "result"),
                            str_field(data, "error"),
                            str_field(data, "failure_reason"),
                            str_field(data, "engine_session_id"),
                            data.get("duration_ms").and_then(Value::as_i64),
                            data.get("final_seq").and_then(Value::as_i64),
                            ts,
                        ],
                    )?;
                }
            }
            Some("cron_state") => {
                if let Some(cron_id) = non_empty(frame, "cronId") {
                    db.execute(
                        "INSERT INTO cron_states (cron_id, task_id, data, received_at) VALUES (?, ?, ?, ?)
                         ON CONFLICT(cron_id) DO UPDATE SET task_id = excluded.task_id, data = excluded.data, received_at = excluded.received_at",
                        params![cron_id, task_id, data.to_string(), ts],
                    )?;
                }
            }
            // Unknown type: ignore the payload but still ack so the agent's outbox drains (protocol §1).
            _ => {}
        }
        Ok(outbox_id)
    }

    fn thread_view(&self, thread_id: &str) -> Result<Value, HostError> {
        let db = lock(&self.db);
        let run = first_row(
            &db,
            "SELECT * FROM thread_runs WHERE thread_id = ?",
            [thread_id],
        )?;
        let messages: Vec<Value> = rows(
            &db,
            "SELECT seq, kind, data, received_at FROM messages WHERE thread_id = ? ORDER BY seq",
            [thread_id],
        )?
        .into_iter()
        .map(|mut m| {
            let data = parse_json_text(m.remove("data").as_ref().and_then(Value::as_str));
            if let Value::Object(fields) = data {
                m.extend(fields);
            }
            Value::Object(m)
        })
        .collect();
        Ok(json!({ "threadId": thread_id, "run": run, "messages": messages }))
    }

    fn has_run(&self, thread_id: &str) -> Result<bool, HostError> {
        Ok(lock(&self.db)
            .query_row(
                "SELECT 1 FROM thread_runs WHERE thread_id = ?",
                [thread_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}

// ─── agent routes ───────────────────────────────────────────────────────────

async fn register(State(host): Shared, body: Bytes) -> Reply {
    let body = body_object(&body);
    if str_field(&body, "registerToken") != Some(host.config.register_token.as_str()) {
        return Ok(reply(
            StatusCode::UNAUTHORIZED,
            &json!({ "register_error": { "reason": "invalid_register_token" } }),
        ));
    }
    if body.get("protocolVersion").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            &json!({ "register_error": { "reason": "unsupported_protocol" } }),
        ));
    }
    let id = new_id("ag");
    let connect_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let capabilities = body
        .get("capabilities")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let name = str_field(&body, "name");
    lock(&host.db).execute(
        "INSERT INTO agents (id, name, connect_token, capabilities, registered_at) VALUES (?, ?, ?, ?, ?)",
        params![id, name, connect_token, capabilities.to_string(), now()],
    )?;
    info!(agent = %id, name = name.unwrap_or("unnamed"), %capabilities, "registered");
    Ok(reply(
        StatusCode::OK,
        &json!({ "agentId": id, "connectToken": connect_token, "config": host.agent_config(&id) }),
    ))
}

async fn agent_config(
    State(host): Shared,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Reply {
    if !host.authenticate(&headers, &agent_id)? {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    }
    Ok(reply(StatusCode::OK, &host.agent_config(&agent_id)))
}

async fn agent_output(
    State(host): Shared,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    if !host.authenticate(&headers, &agent_id)? {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    }
    let ack = match host.handle_agent_frame(&agent_id, &body_object(&body))? {
        Some(id) => json!({ "type": "ack", "id": id }),
        None => json!({}),
    };
    Ok(reply(StatusCode::OK, &ack))
}

async fn agent_ws(
    State(host): Shared,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Reply {
    if !host.authenticate(&headers, &agent_id)? {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    }
    let Ok(upgrade) = upgrade else {
        return Ok(fail(StatusCode::UPGRADE_REQUIRED, "upgrade required"));
    };
    Ok(upgrade.on_upgrade(move |socket| agent_session(host, agent_id, socket)))
}

async fn agent_session(host: Arc<Host>, agent_id: String, socket: WebSocket) {
    use futures_util::{SinkExt, StreamExt};
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let conn = host.next_conn.fetch_add(1, Ordering::Relaxed);
    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if sink.send(message).await.is_err() {
                return;
            }
        }
        let close = CloseFrame {
            code: 1000,
            reason: "superseded".into(),
        };
        let _ = sink.send(Message::Close(Some(close))).await;
    });

    // A newer connection supersedes the older one: dropping its sender closes it.
    let replaced = lock(&host.peers).insert(
        agent_id.clone(),
        Peer {
            conn,
            tx: tx.clone(),
        },
    );
    drop(replaced);
    info!(agent = %agent_id, "connected");
    if let Err(err) = connect(&host, &agent_id, &tx) {
        warn!(agent = %agent_id, error = %err.0, "replay failed");
    }

    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text.to_string(),
            Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if !frame.is_object() {
            continue;
        }
        match host.handle_agent_frame(&agent_id, &frame) {
            Ok(Some(outbox_id)) => {
                let _ = tx.send(Message::Text(
                    json!({ "type": "ack", "id": outbox_id }).to_string().into(),
                ));
            }
            Ok(None) => {}
            Err(err) => warn!(agent = %agent_id, error = %err.0, "frame not stored; not acked"),
        }
        if let Some(kind @ ("thread_result" | "thread_message" | "cron_state")) =
            str_field(&frame, "type")
        {
            let data = frame.get("data").unwrap_or(&Value::Null);
            info!(
                agent = %agent_id,
                task = str_field(&frame, "taskId").unwrap_or("-"),
                thread = str_field(&frame, "threadId").or_else(|| str_field(&frame, "cronId")).unwrap_or("-"),
                detail = str_field(data, "status").or_else(|| str_field(data, "kind")).unwrap_or(""),
                "{kind}"
            );
        }
    }

    {
        let mut peers = lock(&host.peers);
        if peers.get(&agent_id).is_some_and(|peer| peer.conn == conn) {
            peers.remove(&agent_id);
        }
    }
    drop(tx);
    let _ = writer.await;
    info!(agent = %agent_id, "disconnected");
}

/// Mark the agent seen and replay every unacked host→agent frame.
fn connect(
    host: &Host,
    agent_id: &str,
    tx: &mpsc::UnboundedSender<Message>,
) -> Result<(), HostError> {
    let db = lock(&host.db);
    db.execute(
        "UPDATE agents SET last_seen = ? WHERE id = ?",
        params![now(), agent_id],
    )?;
    let pending = rows(
        &db,
        "SELECT id, frame FROM outbox WHERE agent_id = ? AND acked = 0 ORDER BY id",
        [agent_id],
    )?;
    for row in &pending {
        let mut frame = parse_json_text(row.get("frame").and_then(Value::as_str));
        if let (Some(object), Some(id)) = (frame.as_object_mut(), row.get("id")) {
            object.insert("msgId".into(), id.clone());
        }
        let _ = tx.send(Message::Text(frame.to_string().into()));
    }
    if !pending.is_empty() {
        info!(agent = %agent_id, count = pending.len(), "replayed unacked frames");
    }
    Ok(())
}

// ─── operator routes ────────────────────────────────────────────────────────

async fn status(State(host): Shared) -> Reply {
    let agents: i64 = lock(&host.db).query_row("SELECT COUNT(*) FROM agents", [], |r| r.get(0))?;
    let online = lock(&host.peers).len();
    Ok(reply(
        StatusCode::OK,
        &json!({ "ok": true, "agents": agents, "online": online }),
    ))
}

async fn list_agents(State(host): Shared) -> Reply {
    let agents = rows(
        &lock(&host.db),
        "SELECT id, name, capabilities, registered_at, last_seen FROM agents ORDER BY registered_at",
        [],
    )?;
    let agents: Vec<Value> = agents
        .into_iter()
        .map(|mut a| {
            let capabilities = parse_json_text(a.get("capabilities").and_then(Value::as_str));
            let online = a
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| host.online(id));
            a.insert("capabilities".into(), capabilities);
            a.insert("online".into(), Value::Bool(online));
            Value::Object(a)
        })
        .collect();
    Ok(reply(StatusCode::OK, &Value::Array(agents)))
}

async fn list_crons(State(host): Shared) -> Reply {
    let crons: Vec<Value> = rows(
        &lock(&host.db),
        "SELECT * FROM cron_states ORDER BY cron_id",
        [],
    )?
    .into_iter()
    .map(|c| {
        let mut out = Map::new();
        out.insert(
            "cronId".into(),
            c.get("cron_id").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "taskId".into(),
            c.get("task_id").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "received_at".into(),
            c.get("received_at").cloned().unwrap_or(Value::Null),
        );
        if let Value::Object(data) = parse_json_text(c.get("data").and_then(Value::as_str)) {
            out.extend(data);
        }
        Value::Object(out)
    })
    .collect();
    Ok(reply(StatusCode::OK, &Value::Array(crons)))
}

async fn get_thread(State(host): Shared, Path(thread_id): Path<String>) -> Reply {
    Ok(reply(StatusCode::OK, &host.thread_view(&thread_id)?))
}

async fn wait_thread(
    State(host): Shared,
    Path(thread_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    let timeout = query
        .get("timeoutMs")
        .and_then(|t| t.parse().ok())
        .unwrap_or(60_000);
    let deadline = Instant::now() + Duration::from_millis(timeout);
    while !host.has_run(&thread_id)? {
        if Instant::now() >= deadline {
            let mut view = host.thread_view(&thread_id)?;
            if let Some(object) = view.as_object_mut() {
                object.insert("timedOut".into(), Value::Bool(true));
            }
            return Ok(reply(StatusCode::REQUEST_TIMEOUT, &view));
        }
        tokio::time::sleep(WAIT_POLL).await;
    }
    Ok(reply(StatusCode::OK, &host.thread_view(&thread_id)?))
}

async fn list_tasks(State(host): Shared) -> Reply {
    let tasks: Vec<Value> = rows(
        &lock(&host.db),
        "SELECT * FROM tasks ORDER BY created_at",
        [],
    )?
    .into_iter()
    .map(|mut t| {
        let online = t
            .get("agent_id")
            .and_then(Value::as_str)
            .is_some_and(|id| host.online(id));
        t.insert("agentOnline".into(), Value::Bool(online));
        Value::Object(t)
    })
    .collect();
    Ok(reply(StatusCode::OK, &Value::Array(tasks)))
}

/// The agent a new task targets: explicit, or the only registered one.
fn pick_agent(host: &Host, explicit: Option<&str>) -> Result<Result<String, Response>, HostError> {
    let db = lock(&host.db);
    if let Some(id) = explicit {
        let known = db
            .query_row("SELECT 1 FROM agents WHERE id = ?", [id], |_| Ok(()))
            .optional()?
            .is_some();
        return Ok(if known {
            Ok(id.to_owned())
        } else {
            Err(fail(StatusCode::NOT_FOUND, &format!("unknown agent {id}")))
        });
    }
    let ids: Vec<String> = db
        .prepare("SELECT id FROM agents")?
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(match ids.as_slice() {
        [only] => Ok(only.clone()),
        [] => Err(fail(StatusCode::BAD_REQUEST, "no agent registered yet")),
        _ => Err(fail(
            StatusCode::BAD_REQUEST,
            "several agents registered; pass agentId",
        )),
    })
}

async fn create_task(State(host): Shared, body: Bytes) -> Reply {
    let body = body_object(&body);
    let agent_id = match pick_agent(&host, non_empty(&body, "agentId"))? {
        Ok(id) => id,
        Err(response) => return Ok(response),
    };
    let task_id = non_empty(&body, "taskId").map_or_else(|| new_id("task"), str::to_owned);
    {
        let db = lock(&host.db);
        if db
            .query_row("SELECT 1 FROM tasks WHERE id = ?", [&task_id], |_| Ok(()))
            .optional()?
            .is_some()
        {
            return Ok(fail(
                StatusCode::CONFLICT,
                &format!("task {task_id} exists"),
            ));
        }
        db.execute(
            "INSERT INTO tasks (id, agent_id, name, created_at) VALUES (?, ?, ?, ?)",
            params![task_id, agent_id, str_field(&body, "name"), now()],
        )?;
    }
    let mut data = Map::new();
    data.insert("status".into(), json!("active"));
    for key in ["name", "kind", "engine", "model", "workdir", "meta"] {
        if let Some(value) = body.get(key) {
            data.insert(key.into(), value.clone());
        }
    }
    let msg_id = host.enqueue(
        &agent_id,
        json!({ "type": "task_upsert", "taskId": task_id, "data": data }),
    )?;
    Ok(reply(
        StatusCode::CREATED,
        &json!({ "taskId": task_id, "agentId": agent_id, "msgId": msg_id }),
    ))
}

fn task_row(host: &Host, task_id: &str) -> Result<Option<Map<String, Value>>, HostError> {
    Ok(first_row(
        &lock(&host.db),
        "SELECT * FROM tasks WHERE id = ?",
        [task_id],
    )?)
}

fn threads_of(host: &Host, task_id: &str) -> Result<Value, HostError> {
    let threads = rows(
        &lock(&host.db),
        "SELECT t.id AS thread_id, t.created_at, r.status, r.result, r.error, r.failure_reason, r.duration_ms, r.final_seq,
                (SELECT COUNT(*) FROM messages m WHERE m.thread_id = t.id) AS message_count
           FROM threads t LEFT JOIN thread_runs r ON r.thread_id = t.id
          WHERE t.task_id = ? ORDER BY t.created_at",
        [task_id],
    )?;
    Ok(Value::Array(
        threads.into_iter().map(Value::Object).collect(),
    ))
}

fn unknown_task(task_id: &str) -> Response {
    fail(StatusCode::NOT_FOUND, &format!("unknown task {task_id}"))
}

fn agent_of(task: &Map<String, Value>) -> String {
    task.get("agent_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

async fn get_task(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    let Some(mut task) = task_row(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    task.insert("threads".into(), threads_of(&host, &task_id)?);
    Ok(reply(StatusCode::OK, &Value::Object(task)))
}

async fn delete_task(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    let Some(task) = task_row(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    lock(&host.db).execute("DELETE FROM tasks WHERE id = ?", [&task_id])?;
    let msg_id = host.enqueue(
        &agent_of(&task),
        json!({ "type": "task_delete", "taskId": task_id }),
    )?;
    Ok(reply(
        StatusCode::OK,
        &json!({ "taskId": task_id, "msgId": msg_id }),
    ))
}

async fn task_threads(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    if task_row(&host, &task_id)?.is_none() {
        return Ok(unknown_task(&task_id));
    }
    Ok(reply(StatusCode::OK, &threads_of(&host, &task_id)?))
}

async fn send_message(State(host): Shared, Path(task_id): Path<String>, body: Bytes) -> Reply {
    let Some(task) = task_row(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    let body = body_object(&body);
    let Some(text) = non_empty(&body, "text") else {
        return Ok(fail(StatusCode::BAD_REQUEST, "text is required"));
    };
    let agent_id = agent_of(&task);
    // The host mints the thread id and records it BEFORE emitting the frame (protocol §5).
    let current = task
        .get("current_thread_id")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty());
    let thread_id = match current {
        Some(id) if body.get("newThread") != Some(&Value::Bool(true)) => id.to_owned(),
        _ => {
            let id = new_id("th");
            let db = lock(&host.db);
            db.execute(
                "INSERT OR IGNORE INTO threads (id, task_id, created_at) VALUES (?, ?, ?)",
                params![id, task_id, now()],
            )?;
            db.execute(
                "UPDATE tasks SET current_thread_id = ? WHERE id = ?",
                params![id, task_id],
            )?;
            id
        }
    };
    let msg_id = host.enqueue(&agent_id, json!({ "type": "message", "taskId": task_id, "threadId": thread_id, "data": { "text": text } }))?;
    let online = host.online(&agent_id);
    Ok(reply(
        StatusCode::ACCEPTED,
        &json!({ "taskId": task_id, "threadId": thread_id, "msgId": msg_id, "agentOnline": online }),
    ))
}

/// `interrupt` is live-only (protocol §5): never persisted, never replayed.
async fn interrupt(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    let Some(task) = task_row(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    if host.send(
        &agent_of(&task),
        &json!({ "type": "interrupt", "taskId": task_id }),
    ) {
        Ok(reply(StatusCode::OK, &json!({ "sent": true })))
    } else {
        Ok(fail(
            StatusCode::CONFLICT,
            "agent offline; interrupt is live-only",
        ))
    }
}

async fn upsert_cron(State(host): Shared, Path(task_id): Path<String>, body: Bytes) -> Reply {
    let Some(task) = task_row(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    let body = body_object(&body);
    let (Some(prompt), Some(schedule_type), Some(schedule_value)) = (
        non_empty(&body, "prompt"),
        non_empty(&body, "scheduleType"),
        non_empty(&body, "scheduleValue"),
    ) else {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            "prompt, scheduleType (cron|interval|once) and scheduleValue are required",
        ));
    };
    let cron_id = non_empty(&body, "cronId").map_or_else(|| new_id("cron"), str::to_owned);
    let data = json!({
        "kind": "schedule",
        "prompt": prompt,
        "schedule_type": schedule_type,
        "schedule_value": schedule_value,
        "continuity": non_empty(&body, "continuity").unwrap_or("isolated"),
        "status": "active",
    });
    let msg_id = host.enqueue(
        &agent_of(&task),
        json!({ "type": "cron_upsert", "taskId": task_id, "cronId": cron_id, "data": data }),
    )?;
    Ok(reply(
        StatusCode::CREATED,
        &json!({ "taskId": task_id, "cronId": cron_id, "msgId": msg_id }),
    ))
}

async fn delete_cron(
    State(host): Shared,
    Path((task_id, cron_id)): Path<(String, String)>,
) -> Reply {
    let Some(task) = task_row(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    let msg_id = host.enqueue(
        &agent_of(&task),
        json!({ "type": "cron_delete", "taskId": task_id, "cronId": cron_id }),
    )?;
    Ok(reply(
        StatusCode::OK,
        &json!({ "taskId": task_id, "cronId": cron_id, "msgId": msg_id }),
    ))
}

/// The HTTP and WebSocket routes.
pub fn router(host: Arc<Host>) -> Router {
    Router::new()
        .route("/", get(status))
        .route("/agent/register", post(register))
        .route("/agent/config/{id}", get(agent_config))
        .route("/agent/output/{id}", post(agent_output))
        .route("/agent/ws/{id}", get(agent_ws))
        .route("/api/agents", get(list_agents))
        .route("/api/crons", get(list_crons))
        .route("/api/threads/{id}", get(get_thread))
        .route("/api/threads/{id}/wait", get(wait_thread))
        .route("/api/tasks", get(list_tasks).post(create_task))
        .route("/api/tasks/{id}", get(get_task).delete(delete_task))
        .route("/api/tasks/{id}/threads", get(task_threads))
        .route("/api/tasks/{id}/messages", post(send_message))
        .route("/api/tasks/{id}/interrupt", post(interrupt))
        .route("/api/tasks/{id}/crons", post(upsert_cron))
        .route("/api/tasks/{id}/crons/{cron_id}", delete(delete_cron))
        .fallback(|| async { fail(StatusCode::NOT_FOUND, "not found") })
        .method_not_allowed_fallback(|| async {
            fail(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        })
        .with_state(host)
}

#[cfg(test)]
mod tests {
    use super::{base36, now};

    #[test]
    fn timestamps_are_rfc3339_millis() {
        let ts = now();
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.ends_with('Z') && ts.as_bytes()[10] == b'T', "{ts}");
    }

    #[test]
    fn base36_matches_javascript() {
        assert_eq!(base36(0), "0");
        assert_eq!(base36(35), "z");
        assert_eq!(base36(1_761_480_000_000), "mh7npmo0");
    }
}
