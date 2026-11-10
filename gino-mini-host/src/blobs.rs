//! The attachment byte channel (protocol §2): bytes never ride a frame. Frames carry a
//! descriptor `{id, name, content_type, size, sha256, ref, direction}` whose `ref` the agent
//! resolves against the host base URL.

use std::collections::HashMap;

use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use crate::host::{Host, HostError, Reply, Shared};
use crate::util::{fail, lock, new_id, now, reply, sha256_hex};
use crate::{api, config, e2ee};

/// A stored blob's metadata.
#[derive(Debug, Clone)]
pub(crate) struct Blob {
    pub(crate) id: String,
    pub(crate) agent_id: String,
    pub(crate) direction: String,
    pub(crate) name: String,
    pub(crate) content_type: String,
    pub(crate) size: i64,
    pub(crate) sha256: String,
    pub(crate) single_use: bool,
}

impl Blob {
    /// The wire descriptor.
    pub(crate) fn descriptor(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "content_type": self.content_type,
            "size": self.size,
            "sha256": self.sha256,
            "ref": format!("/agent/attachments/{}", self.id),
            "direction": self.direction,
        })
    }
}

/// Store a blob and return its metadata.
pub(crate) fn store(
    host: &Host,
    agent_id: &str,
    direction: &str,
    name: &str,
    content_type: &str,
    bytes: &[u8],
    single_use: bool,
) -> Result<Blob, HostError> {
    let blob = Blob {
        id: new_id("att"),
        agent_id: agent_id.to_owned(),
        direction: direction.to_owned(),
        name: name.to_owned(),
        content_type: content_type.to_owned(),
        size: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
        sha256: sha256_hex(bytes),
        single_use,
    };
    lock(&host.db).execute(
        "INSERT INTO blobs (id, agent_id, direction, name, content_type, size, sha256, data, single_use, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params![
            blob.id,
            blob.agent_id,
            blob.direction,
            blob.name,
            blob.content_type,
            blob.size,
            blob.sha256,
            bytes,
            blob.single_use,
            now()
        ],
    )?;
    Ok(blob)
}

const BLOB_COLUMNS: &str = "id, agent_id, direction, name, content_type, size, sha256, single_use";

fn blob_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Blob> {
    Ok(Blob {
        id: r.get(0)?,
        agent_id: r.get(1)?,
        direction: r.get(2)?,
        name: r.get(3)?,
        content_type: r.get(4)?,
        size: r.get(5)?,
        sha256: r.get(6)?,
        single_use: r.get(7)?,
    })
}

pub(crate) fn find(host: &Host, id: &str) -> Result<Option<Blob>, HostError> {
    Ok(lock(&host.db)
        .query_row(
            &format!("SELECT {BLOB_COLUMNS} FROM blobs WHERE id = ?"),
            [id],
            blob_from_row,
        )
        .optional()?)
}

/// The latest agent upload of `agent_id` under `name` (how the host reads an fs `get` back).
pub(crate) fn find_upload(
    host: &Host,
    agent_id: &str,
    name: &str,
) -> Result<Option<Blob>, HostError> {
    Ok(lock(&host.db)
        .query_row(
            &format!(
                "SELECT {BLOB_COLUMNS} FROM blobs WHERE agent_id = ? AND direction = 'outbound' AND name = ?
                 ORDER BY created_at DESC LIMIT 1"
            ),
            params![agent_id, name],
            blob_from_row,
        )
        .optional()?)
}

pub(crate) fn bytes(host: &Host, id: &str) -> Result<Option<Vec<u8>>, HostError> {
    Ok(lock(&host.db)
        .query_row("SELECT data FROM blobs WHERE id = ?", [id], |r| r.get(0))
        .optional()?)
}

pub(crate) fn delete(host: &Host, id: &str) -> Result<(), HostError> {
    lock(&host.db).execute("DELETE FROM blobs WHERE id = ?", [id])?;
    Ok(())
}

fn octets(content_type: &str, bytes: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type.to_owned())],
        Body::from(bytes),
    )
        .into_response()
}

// ─── agent routes ───────────────────────────────────────────────────────────

/// `GET /agent/attachments/{id}`: an inbound blob staged for this agent. A single-use blob
/// (an fs `put`) is deleted once served.
pub(crate) async fn download(
    State(host): Shared,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Reply {
    let Some(agent_id) = host.agent_by_token(&headers)? else {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    };
    let blob = find(&host, &id)?.filter(|b| b.agent_id == agent_id && b.direction == "inbound");
    let Some(blob) = blob else {
        return Ok(fail(StatusCode::NOT_FOUND, "no such attachment"));
    };
    let Some(data) = bytes(&host, &id)? else {
        return Ok(fail(StatusCode::NOT_FOUND, "no such attachment"));
    };
    if blob.single_use {
        delete(&host, &id)?;
    }
    Ok(octets(&blob.content_type, data))
}

/// `GET /agent/attachments?sha256=<hex>`: a provisioning artifact in the agent's desired set.
pub(crate) async fn fetch_artifact(
    State(host): Shared,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    let Some(agent_id) = host.agent_by_token(&headers)? else {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    };
    let Some(sha256) = query.get("sha256") else {
        return Ok(fail(StatusCode::BAD_REQUEST, "sha256 is required"));
    };
    if !config::desired(&host, &agent_id, sha256)? {
        return Ok(fail(
            StatusCode::NOT_FOUND,
            "not in this agent's desired set",
        ));
    }
    match config::artifact(&host, sha256)? {
        Some(data) => Ok(octets("application/octet-stream", data)),
        None => Ok(fail(StatusCode::NOT_FOUND, "no such artifact")),
    }
}

/// `POST /agent/attachments`: an agent upload. The raw body is the bytes; the name and digest
/// ride the `x-attachment-name` / `x-attachment-sha256` headers. Answers the flat descriptor.
pub(crate) async fn upload(State(host): Shared, headers: HeaderMap, body: Bytes) -> Reply {
    let Some(agent_id) = host.agent_by_token(&headers)? else {
        return Ok(fail(StatusCode::UNAUTHORIZED, "invalid connect token"));
    };
    let header_text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let Some(name) = header_text("x-attachment-name").filter(|n| !n.is_empty()) else {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            "x-attachment-name is required",
        ));
    };
    let actual = sha256_hex(&body);
    if let Some(claimed) = header_text("x-attachment-sha256")
        && !claimed.eq_ignore_ascii_case(&actual)
    {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            "sha256 does not match the body",
        ));
    }
    let content_type = header_text("content-type").unwrap_or("application/octet-stream");
    let blob = store(
        &host,
        &agent_id,
        "outbound",
        name,
        content_type,
        &body,
        false,
    )?;
    Ok(reply(StatusCode::CREATED, &blob.descriptor()))
}

// ─── operator routes ────────────────────────────────────────────────────────

/// `POST /api/tasks/{id}/attachments`: stage a file for a later message. The raw body is the
/// bytes; `x-attachment-name` names it. On an encrypted task the client device seals the bytes
/// as a file envelope under an opaque name (task-content profile §2); the real name is sealed
/// in the message frame.
pub(crate) async fn stage(
    State(host): Shared,
    Path(task_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Reply {
    let Some(task) = api::task(&host, &task_id)? else {
        return Ok(api::unknown_task(&task_id));
    };
    let header_text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let Some(name) = header_text("x-attachment-name").filter(|n| !n.is_empty()) else {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            "x-attachment-name is required",
        ));
    };
    let content_type = header_text("content-type").unwrap_or("application/octet-stream");
    if !task.encrypted {
        let blob = store(
            &host,
            &task.agent_id,
            "inbound",
            name,
            content_type,
            &body,
            false,
        )?;
        return Ok(reply(StatusCode::CREATED, &blob.descriptor()));
    }
    // The host stores only the envelope under an opaque name. The real name goes back to the
    // operator, who passes it with the message, where the client seals it.
    let sealed = e2ee::seal_file(&host, &task_id, &body)?;
    let mut blob = store(
        &host,
        &task.agent_id,
        "inbound",
        &new_id("sealed"),
        "application/octet-stream",
        &sealed,
        false,
    )?;
    name.clone_into(&mut blob.name);
    Ok(reply(StatusCode::CREATED, &blob.descriptor()))
}

/// `GET /api/tasks/{id}/attachments/{attachmentId}`: the bytes of a staged or result
/// attachment of the task, opened by the client device on an encrypted task.
pub(crate) async fn read(
    State(host): Shared,
    Path((task_id, id)): Path<(String, String)>,
) -> Reply {
    let Some(task) = api::task(&host, &task_id)? else {
        return Ok(api::unknown_task(&task_id));
    };
    let blob = find(&host, &id)?.filter(|b| b.agent_id == task.agent_id);
    let (Some(blob), Some(data)) = (blob, bytes(&host, &id)?) else {
        return Ok(fail(StatusCode::NOT_FOUND, "no such attachment"));
    };
    if task.encrypted {
        return Ok(match e2ee::open_file(&host, &task_id, &data) {
            Ok(plain) => octets("application/octet-stream", plain),
            Err(err) => fail(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("does not open: {}", err.0),
            ),
        });
    }
    Ok(octets(&blob.content_type, data))
}
