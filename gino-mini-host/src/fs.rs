//! Engine-free file operations (protocol §5.1): the operator calls
//! `POST /api/agents/{id}/fs`, the host sends a live `fs_request` under a fresh `reqId` and
//! answers with the matching `fs_response`. Nothing is persisted or replayed; a request to an
//! offline agent fails at once, and a disconnect fails every pending request.

use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::{Map, Value, json};
use tokio::sync::oneshot;

use crate::blobs;
use crate::config::unknown_agent;
use crate::host::{Host, Reply, Shared};
use crate::util::{b64_decode, b64_encode, body_object, fail, lock, new_id, reply, str_field};

const OPS: [&str; 7] = ["list", "stat", "mkdir", "remove", "rename", "put", "get"];
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// `POST /api/agents/{id}/fs`: `{op, path, to?, recursive?, exclusive?, content?, timeoutMs?}`.
/// `put` takes the bytes as base64 `content`; a successful `get` answers them as base64
/// `content` beside the agent's `sha256` and `size`.
pub(crate) async fn request(
    State(host): Shared,
    Path(agent_id): Path<String>,
    body: Bytes,
) -> Reply {
    if !host.agent_exists(&agent_id)? {
        return Ok(unknown_agent(&agent_id));
    }
    let body = body_object(&body);
    let Some(op) = str_field(&body, "op").filter(|op| OPS.contains(op)) else {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            &format!("op must be one of {}", OPS.join(", ")),
        ));
    };
    let Some(path) = str_field(&body, "path").filter(|p| !p.is_empty()) else {
        return Ok(fail(StatusCode::BAD_REQUEST, "path is required"));
    };
    if !host.online(&agent_id) {
        return Ok(fail(
            StatusCode::CONFLICT,
            "agent offline; file operations are live-only",
        ));
    }

    let mut data = Map::new();
    data.insert("op".into(), json!(op));
    data.insert("path".into(), json!(path));
    for key in ["to", "recursive", "exclusive"] {
        if let Some(value) = body.get(key) {
            data.insert(key.into(), value.clone());
        }
    }
    // A `put` stages its bytes as a single-use blob; the host deletes it when the request
    // settles, whatever the outcome.
    let mut staged = None;
    let mut upload = None;
    match op {
        "put" => {
            let Some(content) = str_field(&body, "content").and_then(b64_decode) else {
                return Ok(fail(StatusCode::BAD_REQUEST, "put needs base64 content"));
            };
            let blob = blobs::store(
                &host,
                &agent_id,
                "inbound",
                path,
                "application/octet-stream",
                &content,
                true,
            )?;
            data.insert(
                "ref".into(),
                json!(format!("/agent/attachments/{}", blob.id)),
            );
            data.insert("sha256".into(), json!(blob.sha256));
            data.insert("size".into(), json!(blob.size));
            staged = Some(blob.id);
        }
        "get" => {
            let name = new_id("fs-get");
            data.insert("upload".into(), json!(name));
            upload = Some(name);
        }
        _ => {}
    }

    let timeout = body
        .get("timeoutMs")
        .and_then(Value::as_u64)
        .map_or(DEFAULT_TIMEOUT, Duration::from_millis);
    let answer = exchange(&host, &agent_id, Value::Object(data), timeout).await;
    if let Some(id) = staged {
        blobs::delete(&host, &id)?;
    }
    let mut answer = match answer {
        Ok(answer) => answer,
        Err((status, message)) => return Ok(fail(status, message)),
    };
    if let (Some(name), Some(true)) = (upload, answer.get("ok").and_then(Value::as_bool)) {
        // The host reads a `get` back by the name it minted and the digest the agent reported.
        let blob = blobs::find_upload(&host, &agent_id, &name)?
            .filter(|blob| Some(blob.sha256.as_str()) == str_field(&answer, "sha256"));
        let Some(blob) = blob else {
            return Ok(fail(
                StatusCode::BAD_GATEWAY,
                "the agent's upload is missing or does not match",
            ));
        };
        let content = blobs::bytes(&host, &blob.id)?.unwrap_or_default();
        blobs::delete(&host, &blob.id)?;
        if let Some(object) = answer.as_object_mut() {
            object.insert("content".into(), json!(b64_encode(&content)));
        }
    }
    Ok(reply(StatusCode::OK, &answer))
}

/// Send one `fs_request` and wait for its `fs_response` `data`.
async fn exchange(
    host: &Host,
    agent_id: &str,
    data: Value,
    timeout: Duration,
) -> Result<Value, (StatusCode, &'static str)> {
    let req_id = host
        .ulid()
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "no request id"))?;
    let (tx, rx) = oneshot::channel();
    lock(&host.fs_pending).insert(req_id.clone(), (agent_id.to_owned(), tx));
    let frame = json!({ "type": "fs_request", "reqId": req_id, "data": data });
    if !host.send(agent_id, &frame) {
        lock(&host.fs_pending).remove(&req_id);
        return Err((
            StatusCode::CONFLICT,
            "agent offline; file operations are live-only",
        ));
    }
    let outcome = tokio::time::timeout(timeout, rx).await;
    lock(&host.fs_pending).remove(&req_id);
    match outcome {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(_)) => Err((StatusCode::BAD_GATEWAY, "agent disconnected")),
        Err(_) => Err((StatusCode::GATEWAY_TIMEOUT, "no fs_response in time")),
    }
}

/// An `fs_response` from `agent_id`: settle the request with the same `reqId`. A response
/// for an unknown `reqId` or from another agent is ignored.
pub(crate) fn response(host: &Host, agent_id: &str, frame: &Value) {
    let Some(req_id) = str_field(frame, "reqId") else {
        return;
    };
    let mut pending = lock(&host.fs_pending);
    if pending
        .get(req_id)
        .is_some_and(|(agent, _)| agent == agent_id)
        && let Some((_, tx)) = pending.remove(req_id)
    {
        let _ = tx.send(frame.get("data").cloned().unwrap_or_else(|| json!({})));
    }
}

/// Fail every pending request of an agent whose socket dropped.
pub(crate) fn fail_agent(host: &Host, agent_id: &str) {
    lock(&host.fs_pending).retain(|_, (agent, _)| agent != agent_id);
}
