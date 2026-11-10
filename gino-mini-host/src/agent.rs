//! The agent side of the protocol: enrollment (§3), config fetch, the pre-WebSocket output
//! fallback and the WebSocket session (§4) with its frame dispatch (§5).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::ws::{
    CloseFrame, Message, WebSocket, WebSocketUpgrade, rejection::WebSocketUpgradeRejection,
};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use rusqlite::params;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::host::{Host, HostError, PROTOCOL_VERSION, Peer, Reply, Shared};
use crate::util::{
    body_object, fail, lock, new_id, non_empty, now, parse_json_text, reply, rows, str_field,
};
use crate::{e2ee, fs, pty};

pub(crate) async fn register(State(host): Shared, body: Bytes) -> Reply {
    let mut body = body_object(&body);
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
    if let Some(object) = body.as_object_mut() {
        object.remove("registerToken");
    }
    let id = new_id("ag");
    let connect_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let name = str_field(&body, "name");
    let layer = json!({ "engine": host.config.engine });
    lock(&host.db).execute(
        "INSERT INTO agents (id, name, connect_token, register, config, registered_at) VALUES (?, ?, ?, ?, ?, ?)",
        params![id, name, connect_token, body.to_string(), layer.to_string(), now()],
    )?;
    e2ee::observe_capability(&host, &id, body.get("e2ee"))?;
    info!(agent = %id, name = name.unwrap_or("unnamed"), capabilities = %body["capabilities"], "registered");
    Ok(reply(
        StatusCode::OK,
        &json!({ "agentId": id, "connectToken": connect_token, "config": host.agent_config(&id)? }),
    ))
}

/// `GET /agent/config/{id}`: the config returned flat (protocol §3).
pub(crate) async fn config(
    State(host): Shared,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
) -> Reply {
    if !host.authenticate(&headers, &agent_id)? {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    }
    Ok(reply(StatusCode::OK, &host.agent_config(&agent_id)?))
}

/// `POST /agent/output/{id}`: one durable frame sent before the WebSocket is up.
pub(crate) async fn output(
    State(host): Shared,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    if !host.authenticate(&headers, &agent_id)? {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    }
    let ack = match handle_frame(&host, &agent_id, &body_object(&body))? {
        Some(id) => json!({ "type": "ack", "id": id }),
        None => json!({}),
    };
    Ok(reply(StatusCode::OK, &ack))
}

pub(crate) async fn websocket(
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
    Ok(upgrade.on_upgrade(move |socket| session(host, agent_id, socket)))
}

async fn session(host: Arc<Host>, agent_id: String, socket: WebSocket) {
    use futures_util::{SinkExt, StreamExt};
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let conn = host.next_conn();
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

    // A newer connection supersedes the older one: dropping its sender closes it, and its
    // terminals end with it (protocol §5.2).
    let replaced = lock(&host.peers).insert(
        agent_id.clone(),
        Peer {
            conn,
            tx: tx.clone(),
        },
    );
    if let Some(old) = replaced {
        pty::end_connection(&host, &agent_id, old.conn);
    }
    info!(agent = %agent_id, "connected");
    if let Err(err) = replay(&host, &agent_id, &tx) {
        warn!(agent = %agent_id, error = %err.0, "replay failed");
    }
    if let Err(err) = e2ee::send_pool_status(&host, &agent_id, None, None) {
        warn!(agent = %agent_id, error = %err.0, "key package status failed");
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
        match handle_frame(&host, &agent_id, &frame) {
            Ok(Some(outbox_id)) => {
                let _ = tx.send(Message::Text(
                    json!({ "type": "ack", "id": outbox_id }).to_string().into(),
                ));
            }
            Ok(None) => {}
            Err(err) => warn!(agent = %agent_id, error = %err.0, "frame not stored; not acked"),
        }
        log_frame(&agent_id, &frame);
    }

    let current = {
        let mut peers = lock(&host.peers);
        let current = peers.get(&agent_id).is_some_and(|peer| peer.conn == conn);
        if current {
            peers.remove(&agent_id);
        }
        current
    };
    if current {
        fs::fail_agent(&host, &agent_id);
    }
    pty::end_connection(&host, &agent_id, conn);
    drop(tx);
    let _ = writer.await;
    info!(agent = %agent_id, "disconnected");
}

fn log_frame(agent_id: &str, frame: &Value) {
    if let Some(kind @ ("thread_result" | "thread_message" | "cron_state")) =
        str_field(frame, "type")
    {
        let data = frame.get("data").unwrap_or(&Value::Null);
        info!(
            agent = %agent_id,
            task = str_field(frame, "taskId").unwrap_or("-"),
            thread = str_field(frame, "threadId").or_else(|| str_field(frame, "cronId")).unwrap_or("-"),
            detail = str_field(data, "status").or_else(|| str_field(data, "kind")).unwrap_or(""),
            "{kind}"
        );
    }
}

/// Mark the agent seen and replay every unacked durable host→agent frame in id order.
fn replay(
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

/// Handle one agent frame. Durable frames are mirrored and their `outboxId` returned for the
/// ack; live-only frames go to their module and return `None`.
pub(crate) fn handle_frame(
    host: &Host,
    agent_id: &str,
    frame: &Value,
) -> Result<Option<String>, HostError> {
    let outbox_id = str_field(frame, "outboxId").map(str::to_owned);
    let empty = json!({});
    let data = frame
        .get("data")
        .filter(|d| d.is_object())
        .unwrap_or(&empty);
    match str_field(frame, "type") {
        Some("msg_ack") => {
            if let Some(msg_id) = str_field(frame, "msgId") {
                lock(&host.db).execute(
                    "UPDATE outbox SET acked = 1 WHERE id = ? AND agent_id = ?",
                    params![msg_id, agent_id],
                )?;
            }
            return Ok(None);
        }
        Some("heartbeat") => {
            lock(&host.db).execute(
                "UPDATE agents SET last_seen = ?, heartbeat = ? WHERE id = ?",
                params![now(), data.to_string(), agent_id],
            )?;
            e2ee::observe_capability(host, agent_id, data.get("e2ee"))?;
        }
        Some("thread_message") => mirror_message(host, frame, data)?,
        Some("thread_result") => mirror_result(host, frame, data)?,
        Some("cron_state") => {
            if let Some(cron_id) = non_empty(frame, "cronId") {
                lock(&host.db).execute(
                    "INSERT INTO cron_states (cron_id, task_id, data, received_at) VALUES (?, ?, ?, ?)
                     ON CONFLICT(cron_id) DO UPDATE SET task_id = excluded.task_id, data = excluded.data, received_at = excluded.received_at",
                    params![cron_id, str_field(frame, "taskId").unwrap_or_default(), data.to_string(), now()],
                )?;
            }
        }
        Some("e2ee_key_packages") => {
            e2ee::key_packages(host, agent_id, data, outbox_id.as_deref())?;
        }
        Some("fs_response") => {
            fs::response(host, agent_id, frame);
            return Ok(None);
        }
        Some("pty_ready" | "pty_output" | "pty_exit") => {
            pty::from_agent(host, agent_id, frame);
            return Ok(None);
        }
        Some("e2ee_request") => {
            e2ee::request(host, agent_id, frame)?;
            return Ok(None);
        }
        // Unknown type: ignore the payload but still ack so the agent's outbox drains (§1).
        _ => {}
    }
    Ok(outbox_id)
}

/// Mirror a transcript event; idempotent on `(threadId, seq)` (protocol §6).
fn mirror_message(host: &Host, frame: &Value, data: &Value) -> Result<(), HostError> {
    let task_id = str_field(frame, "taskId").unwrap_or_default();
    let thread_id = str_field(frame, "threadId").unwrap_or_default();
    let Some(seq) = data.get("seq").and_then(Value::as_i64) else {
        return Ok(());
    };
    if thread_id.is_empty() {
        return Ok(());
    }
    e2ee::check_sealed(host, task_id, "thread_message", frame)?;
    let db = lock(&host.db);
    db.execute(
        "INSERT OR IGNORE INTO threads (id, task_id, created_at) VALUES (?, ?, ?)",
        params![thread_id, task_id, now()],
    )?;
    db.execute(
        "INSERT OR IGNORE INTO messages (task_id, thread_id, seq, kind, data, frame, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        params![task_id, thread_id, seq, str_field(data, "kind").unwrap_or("unknown"), data.to_string(), frame.to_string(), now()],
    )?;
    Ok(())
}

/// Mirror a terminal outcome, every field of protocol §5 included.
fn mirror_result(host: &Host, frame: &Value, data: &Value) -> Result<(), HostError> {
    let task_id = str_field(frame, "taskId").unwrap_or_default();
    let thread_id = str_field(frame, "threadId").unwrap_or_default();
    if thread_id.is_empty() {
        return Ok(());
    }
    e2ee::check_sealed(host, task_id, "thread_result", frame)?;
    let json_text = |key: &str| data.get(key).filter(|v| !v.is_null()).map(Value::to_string);
    // `result` / `error` are text, or the sealed form `{"e2ee": …}` on an encrypted task.
    let text = |key: &str| {
        data.get(key).and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
    };
    let db = lock(&host.db);
    db.execute(
        "INSERT OR IGNORE INTO threads (id, task_id, created_at) VALUES (?, ?, ?)",
        params![thread_id, task_id, now()],
    )?;
    db.execute(
        "INSERT INTO thread_runs (thread_id, task_id, outbox_id, status, result, error, failure_reason, engine_session_id,
                                  duration_ms, final_seq, engine, model, usage, attachments, encryption_error, frame, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(thread_id) DO UPDATE SET
           runs = thread_runs.runs + (excluded.outbox_id IS NOT thread_runs.outbox_id),
           outbox_id = excluded.outbox_id, status = excluded.status, result = excluded.result, error = excluded.error,
           failure_reason = excluded.failure_reason, engine_session_id = excluded.engine_session_id,
           duration_ms = excluded.duration_ms, final_seq = excluded.final_seq, engine = excluded.engine,
           model = excluded.model, usage = excluded.usage, attachments = excluded.attachments,
           encryption_error = excluded.encryption_error, frame = excluded.frame, received_at = excluded.received_at",
        params![
            thread_id,
            task_id,
            str_field(frame, "outboxId"),
            str_field(data, "status").unwrap_or("unknown"),
            text("result"),
            text("error"),
            str_field(data, "failure_reason"),
            str_field(data, "engine_session_id"),
            data.get("duration_ms").and_then(Value::as_i64),
            data.get("final_seq").and_then(Value::as_i64),
            str_field(data, "engine"),
            str_field(data, "model"),
            json_text("usage"),
            json_text("attachments"),
            json_text("encryption_error"),
            frame.to_string(),
            now(),
        ],
    )?;
    Ok(())
}
