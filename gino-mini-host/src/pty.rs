//! Interactive terminals (protocol §5.2). An operator opens `GET /api/agents/{id}/pty` as a
//! WebSocket; one socket owns one terminal. Within five seconds it sends
//! `{type: "open", data: {argv?, cwd?, env?, cols?, rows?}}`, waits for
//! `{type: "ready", data: {ptyId}}`, then sends `input` `{data}` (base64), `resize`
//! `{cols, rows}` and `close`, and receives `output` `{data}` and `exit`
//! `{exit_code?, signal?, error?}`. The host mints the `ptyId` and relays the live-only
//! `pty_*` frames; nothing is persisted, and a terminal ends with the agent connection.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tracing::warn;

use crate::config::unknown_agent;
use crate::host::{Host, PtySession, Reply, Shared};
use crate::util::{lock, str_field};

const OPEN_WINDOW: Duration = Duration::from_secs(5);
const READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Frames buffered toward a slow operator before the terminal is closed (protocol §5.2: the
/// host's unread buffer is bounded; slow consumers close).
const CLIENT_QUEUE: usize = 64;

pub(crate) async fn open(
    State(host): Shared,
    Path(agent_id): Path<String>,
    upgrade: WebSocketUpgrade,
) -> Reply {
    if !host.agent_exists(&agent_id)? {
        return Ok(unknown_agent(&agent_id));
    }
    Ok(upgrade
        .on_upgrade(move |socket| terminal(host, agent_id, socket))
        .into_response())
}

async fn terminal(host: Arc<Host>, agent_id: String, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    let send = |frame: Value| Message::Text(frame.to_string().into());

    // 1. The open request.
    let options = match tokio::time::timeout(OPEN_WINDOW, next_json(&mut stream)).await {
        Ok(Some(frame)) if str_field(&frame, "type") == Some("open") => {
            frame.get("data").cloned().unwrap_or_else(|| json!({}))
        }
        _ => {
            let _ = sink
                .send(send(exit_error("invalid", "expected an open message")))
                .await;
            return;
        }
    };
    let Some(conn) = lock(&host.peers).get(&agent_id).map(|peer| peer.conn) else {
        let _ = sink
            .send(send(exit_error("offline", "the agent is not connected")))
            .await;
        return;
    };
    let Ok(pty_id) = host.ulid() else {
        return;
    };
    let (tx, mut rx) = mpsc::channel::<Value>(CLIENT_QUEUE);
    lock(&host.ptys).insert(
        pty_id.clone(),
        PtySession {
            agent_id: agent_id.clone(),
            conn,
            tx,
        },
    );
    host.send(
        &agent_id,
        &json!({ "type": "pty_open", "ptyId": pty_id, "data": options }),
    );

    // 2. Relay until either side ends the terminal.
    let ready_deadline = tokio::time::sleep(READY_TIMEOUT);
    tokio::pin!(ready_deadline);
    let mut ready = false;
    let exit = loop {
        tokio::select! {
            from_agent = rx.recv() => {
                let Some(frame) = from_agent else {
                    break exit_error("closed", "the terminal ended");
                };
                let data = frame.get("data").cloned().unwrap_or_else(|| json!({}));
                match str_field(&frame, "type") {
                    Some("pty_ready") => {
                        ready = true;
                        if sink.send(send(json!({ "type": "ready", "data": { "ptyId": pty_id } }))).await.is_err() {
                            break Value::Null;
                        }
                    }
                    Some("pty_output") => {
                        if sink.send(send(json!({ "type": "output", "data": data }))).await.is_err() {
                            break Value::Null;
                        }
                    }
                    Some("pty_exit") => {
                        lock(&host.ptys).remove(&pty_id);
                        let _ = sink.send(send(json!({ "type": "exit", "data": data }))).await;
                        return;
                    }
                    _ => {}
                }
            }
            from_operator = next_json(&mut stream) => {
                let Some(frame) = from_operator else {
                    break Value::Null;
                };
                let data = frame.get("data").cloned().unwrap_or_else(|| json!({}));
                let forward = match str_field(&frame, "type") {
                    Some("input") => json!({ "type": "pty_input", "ptyId": pty_id, "data": data }),
                    Some("resize") => json!({ "type": "pty_resize", "ptyId": pty_id, "data": data }),
                    Some("close") => break Value::Null,
                    _ => continue,
                };
                host.send(&agent_id, &forward);
            }
            () = &mut ready_deadline, if !ready => {
                break exit_error("timeout", "no pty_ready in time");
            }
        }
    };
    // The operator left, the open timed out or the agent connection ended: close the terminal
    // on the agent (a no-op if it is already gone) and tell the operator why.
    lock(&host.ptys).remove(&pty_id);
    host.send(&agent_id, &json!({ "type": "pty_close", "ptyId": pty_id }));
    if !exit.is_null() {
        let _ = sink
            .send(send(json!({ "type": "exit", "data": exit })))
            .await;
    }
}

fn exit_error(code: &str, message: &str) -> Value {
    json!({ "error": { "code": code, "message": message } })
}

/// The next JSON object from the operator; `None` once the socket closes.
async fn next_json(stream: &mut futures_util::stream::SplitStream<WebSocket>) -> Option<Value> {
    while let Some(Ok(message)) = stream.next().await {
        let text = match message {
            Message::Text(text) => text.to_string(),
            Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Message::Close(_) => return None,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        if let Ok(frame) = serde_json::from_str::<Value>(&text)
            && frame.is_object()
        {
            return Some(frame);
        }
    }
    None
}

/// A `pty_ready` / `pty_output` / `pty_exit` from `agent_id`. Unknown terminals and frames
/// from another agent are ignored; an operator that falls behind loses the terminal.
pub(crate) fn from_agent(host: &Host, agent_id: &str, frame: &Value) {
    let Some(pty_id) = str_field(frame, "ptyId") else {
        return;
    };
    let mut ptys = lock(&host.ptys);
    let Some(session) = ptys.get(pty_id).filter(|s| s.agent_id == agent_id) else {
        return;
    };
    if session.tx.try_send(frame.clone()).is_err() {
        warn!(agent = %agent_id, pty = %pty_id, "terminal consumer too slow; closing");
        ptys.remove(pty_id);
        drop(ptys);
        host.send(agent_id, &json!({ "type": "pty_close", "ptyId": pty_id }));
    }
}

/// End every terminal of one agent connection (disconnect or replacement).
pub(crate) fn end_connection(host: &Host, agent_id: &str, conn: u64) {
    lock(&host.ptys).retain(|_, session| !(session.agent_id == agent_id && session.conn == conn));
}
