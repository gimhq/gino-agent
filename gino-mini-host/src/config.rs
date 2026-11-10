//! The host config layer (protocol §3) and provisioning artifacts.
//!
//! Each agent has one host config layer: a JSON object the agent receives on register and
//! `GET /agent/config/{id}`, with a monotonic `version`. An operator changes it with an RFC 7386
//! merge patch; the host merges it, bumps the version and pushes the same patch as a durable
//! `config_update` carrying the new `version`. Global provisioning is the layer's `entries`.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

use crate::host::{Host, HostError, Reply, Shared};
use crate::util::{fail, lock, merge_patch, now, parse_json_text, reply, sha256_hex, str_field};

/// Keys of the served config the host owns; a patch may not set them.
const RESERVED: [&str; 6] = [
    "agentId",
    "wsUrl",
    "configUrl",
    "outputUrl",
    "protocolVersion",
    "version",
];

/// `GET /api/agents/{id}/config`: the host layer and its version.
pub(crate) async fn get(State(host): Shared, Path(agent_id): Path<String>) -> Reply {
    if !host.agent_exists(&agent_id)? {
        return Ok(unknown_agent(&agent_id));
    }
    let (config, version) = host.config_layer(&agent_id)?;
    Ok(reply(
        StatusCode::OK,
        &json!({ "config": config, "version": version }),
    ))
}

/// `PATCH /api/agents/{id}/config`: merge a patch into the layer and push it.
pub(crate) async fn patch(State(host): Shared, Path(agent_id): Path<String>, body: Bytes) -> Reply {
    let Ok(patch) = serde_json::from_slice::<Value>(&body) else {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            "the body must be a JSON object",
        ));
    };
    let Some(object) = patch.as_object() else {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            "the body must be a JSON object",
        ));
    };
    if let Some(key) = RESERVED.iter().find(|key| object.contains_key(**key)) {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            &format!("{key} is set by the host"),
        ));
    }
    if let Some(entries) = object.get("entries")
        && let Err(message) = check_entries(&host, entries)?
    {
        return Ok(fail(StatusCode::BAD_REQUEST, &message));
    }
    let Some(version) = apply_patch(&host, &agent_id, &patch)? else {
        return Ok(unknown_agent(&agent_id));
    };
    Ok(reply(StatusCode::OK, &json!({ "version": version })))
}

/// Merge `patch` into the agent's layer, bump the version and enqueue the `config_update`.
/// `None` for an unknown agent.
pub(crate) fn apply_patch(
    host: &Host,
    agent_id: &str,
    patch: &Value,
) -> Result<Option<i64>, HostError> {
    let version = {
        let db = lock(&host.db);
        let row: Option<(String, i64)> = db
            .query_row(
                "SELECT config, config_version FROM agents WHERE id = ?",
                [agent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((layer, version)) = row else {
            return Ok(None);
        };
        let mut layer = parse_json_text(Some(&layer));
        merge_patch(&mut layer, patch);
        let version = version + 1;
        db.execute(
            "UPDATE agents SET config = ?, config_version = ? WHERE id = ?",
            params![layer.to_string(), version, agent_id],
        )?;
        version
    };
    let mut data = patch.clone();
    if let Some(object) = data.as_object_mut() {
        object.insert("version".into(), json!(version));
    }
    host.enqueue(agent_id, json!({ "type": "config_update", "data": data }))?;
    Ok(Some(version))
}

/// Validate a provisioning `entries` set: an array of `{name, sha256, target, kind}` whose
/// artifacts the host holds. The inner `Err` is the operator-facing message.
pub(crate) fn check_entries(host: &Host, entries: &Value) -> Result<Result<(), String>, HostError> {
    let Some(entries) = entries.as_array() else {
        return Ok(Err("entries must be an array".into()));
    };
    for entry in entries {
        let (Some(name), Some(sha256), Some(target), Some(kind)) = (
            str_field(entry, "name"),
            str_field(entry, "sha256"),
            str_field(entry, "target"),
            str_field(entry, "kind"),
        ) else {
            return Ok(Err("each entry needs name, sha256, target and kind".into()));
        };
        if !matches!(kind, "file" | "dir") {
            return Ok(Err(format!("entry {name}: kind must be file or dir")));
        }
        if target.is_empty() {
            return Ok(Err(format!("entry {name}: empty target")));
        }
        if !artifact_exists(host, sha256)? {
            return Ok(Err(format!(
                "entry {name}: unknown artifact {sha256}; upload it first"
            )));
        }
    }
    Ok(Ok(()))
}

fn artifact_exists(host: &Host, sha256: &str) -> Result<bool, HostError> {
    Ok(lock(&host.db)
        .query_row("SELECT 1 FROM artifacts WHERE sha256 = ?", [sha256], |_| {
            Ok(())
        })
        .optional()?
        .is_some())
}

/// `POST /api/artifacts`: store a provisioning artifact (a file, or a `dir` entry's tar) and
/// answer its `sha256`, which entries reference.
pub(crate) async fn upload_artifact(State(host): Shared, body: Bytes) -> Reply {
    let sha256 = sha256_hex(&body);
    lock(&host.db).execute(
        "INSERT OR IGNORE INTO artifacts (sha256, data, created_at) VALUES (?, ?, ?)",
        params![sha256, body.to_vec(), now()],
    )?;
    Ok(reply(
        StatusCode::CREATED,
        &json!({ "sha256": sha256, "size": body.len() }),
    ))
}

/// Whether `sha256` is in the agent's desired provisioning set: its global `entries` or the
/// `entries` of one of its tasks. The provisioning fetch serves nothing else.
pub(crate) fn desired(host: &Host, agent_id: &str, sha256: &str) -> Result<bool, HostError> {
    let (layer, _) = host.config_layer(agent_id)?;
    let listed = |entries: Option<&Value>| {
        entries.and_then(Value::as_array).is_some_and(|entries| {
            entries
                .iter()
                .any(|e| str_field(e, "sha256") == Some(sha256))
        })
    };
    if listed(layer.get("entries")) {
        return Ok(true);
    }
    let db = lock(&host.db);
    let mut stmt = db.prepare("SELECT definition FROM tasks WHERE agent_id = ?")?;
    let definitions = stmt.query_map([agent_id], |r| r.get::<_, String>(0))?;
    for definition in definitions {
        if listed(parse_json_text(Some(&definition?)).get("entries")) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn artifact(host: &Host, sha256: &str) -> Result<Option<Vec<u8>>, HostError> {
    Ok(lock(&host.db)
        .query_row(
            "SELECT data FROM artifacts WHERE sha256 = ?",
            [sha256],
            |r| r.get(0),
        )
        .optional()?)
}

pub(crate) fn unknown_agent(agent_id: &str) -> axum::response::Response {
    fail(StatusCode::NOT_FOUND, &format!("unknown agent {agent_id}"))
}
