//! The operator API (JSON over HTTP, unauthenticated: bind it to loopback). It is the host's
//! own surface, not part of the protocol; each route shows which frames it produces.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value, json};

use crate::config::{check_entries, unknown_agent};
use crate::host::{Host, HostError, Reply, Shared};
use crate::util::{
    body_object, fail, first_row, lock, merge_patch, new_id, non_empty, now, parse_json_text,
    reply, rows, str_field,
};
use crate::{blobs, e2ee};

const WAIT_POLL: Duration = Duration::from_millis(200);

/// The task fields a host sends on `task_upsert` (protocol §5).
const TASK_FIELDS: [&str; 8] = [
    "name", "kind", "status", "engine", "model", "workdir", "meta", "entries",
];

/// A task row.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    pub(crate) agent_id: String,
    pub(crate) encrypted: bool,
    current_thread_id: Option<String>,
}

pub(crate) fn task(host: &Host, task_id: &str) -> Result<Option<Task>, HostError> {
    Ok(lock(&host.db)
        .query_row(
            "SELECT agent_id, encrypted, current_thread_id FROM tasks WHERE id = ?",
            [task_id],
            |r| {
                Ok(Task {
                    agent_id: r.get(0)?,
                    encrypted: r.get(1)?,
                    current_thread_id: r.get(2)?,
                })
            },
        )
        .optional()?)
}

pub(crate) fn unknown_task(task_id: &str) -> Response {
    fail(StatusCode::NOT_FOUND, &format!("unknown task {task_id}"))
}

// ─── status and agents ──────────────────────────────────────────────────────

pub(crate) async fn status(State(host): Shared) -> Reply {
    let agents: i64 = lock(&host.db).query_row("SELECT COUNT(*) FROM agents", [], |r| r.get(0))?;
    let online = lock(&host.peers).len();
    Ok(reply(
        StatusCode::OK,
        &json!({ "ok": true, "agents": agents, "online": online }),
    ))
}

/// An agent as the operator sees it: what it registered with, its last heartbeat (capabilities,
/// engines, e2ee, applied `configVersion`, `defaults`) and the host config version.
fn agent_view(host: &Host, mut row: Map<String, Value>) -> Result<Value, HostError> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    for key in ["register", "heartbeat"] {
        let parsed = parse_json_text(row.get(key).and_then(Value::as_str));
        row.insert(key.into(), parsed);
    }
    let heartbeat = row.get("heartbeat").cloned().unwrap_or(Value::Null);
    let register = row.get("register").cloned().unwrap_or(Value::Null);
    // The latest of each reported field: a heartbeat repeats the register values.
    for key in ["capabilities", "e2ee", "defaults"] {
        let latest = heartbeat
            .get(key)
            .or_else(|| register.get(key))
            .cloned()
            .unwrap_or(Value::Null);
        row.insert(key.into(), latest);
    }
    row.insert(
        "engines".into(),
        heartbeat.get("engines").cloned().unwrap_or(Value::Null),
    );
    row.insert(
        "appliedConfigVersion".into(),
        heartbeat
            .get("configVersion")
            .cloned()
            .unwrap_or(Value::Null),
    );
    row.insert("online".into(), Value::Bool(host.online(&id)));
    row.insert("identity".into(), e2ee::identity_view(host, &id)?);
    Ok(Value::Object(row))
}

const AGENT_COLUMNS: &str =
    "id, name, register, heartbeat, config_version AS configVersion, registered_at, last_seen";

pub(crate) async fn list_agents(State(host): Shared) -> Reply {
    let agents = rows(
        &lock(&host.db),
        &format!("SELECT {AGENT_COLUMNS} FROM agents ORDER BY registered_at"),
        [],
    )?;
    let agents = agents
        .into_iter()
        .map(|row| agent_view(&host, row))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(reply(StatusCode::OK, &Value::Array(agents)))
}

pub(crate) async fn get_agent(State(host): Shared, Path(agent_id): Path<String>) -> Reply {
    let row = first_row(
        &lock(&host.db),
        &format!("SELECT {AGENT_COLUMNS} FROM agents WHERE id = ?"),
        [&agent_id],
    )?;
    match row {
        Some(row) => Ok(reply(StatusCode::OK, &agent_view(&host, row)?)),
        None => Ok(unknown_agent(&agent_id)),
    }
}

/// `POST /api/agents/{id}/close` `{reason?}`: the durable `close` (runner wind-down and exit).
pub(crate) async fn close_agent(
    State(host): Shared,
    Path(agent_id): Path<String>,
    body: Bytes,
) -> Reply {
    if !host.agent_exists(&agent_id)? {
        return Ok(unknown_agent(&agent_id));
    }
    let body = body_object(&body);
    let mut frame = json!({ "type": "close" });
    if let Some(reason) = non_empty(&body, "reason") {
        if !matches!(reason, "stop" | "restart" | "remove") {
            return Ok(fail(
                StatusCode::BAD_REQUEST,
                "reason must be stop, restart or remove",
            ));
        }
        frame["data"] = json!({ "reason": reason });
    }
    let msg_id = host.enqueue(&agent_id, frame)?;
    Ok(reply(StatusCode::OK, &json!({ "msgId": msg_id })))
}

// ─── tasks ──────────────────────────────────────────────────────────────────

/// The agent a new task targets: explicit, or the only registered one.
fn pick_agent(host: &Host, explicit: Option<&str>) -> Result<Result<String, Response>, HostError> {
    if let Some(id) = explicit {
        return Ok(if host.agent_exists(id)? {
            Ok(id.to_owned())
        } else {
            Err(unknown_agent(id))
        });
    }
    let ids: Vec<String> = lock(&host.db)
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

/// Check a task definition's `engine` and `model` against what the agent last reported: the
/// engine must be one it advertises in `capabilities` (protocol §3), and the model one the
/// engine's CLI lists in `heartbeat.engines[].models`. A list the agent has not reported yet
/// is not checked. Returns the reason for a 400.
fn check_engine_model(
    host: &Host,
    agent_id: &str,
    definition: &Value,
) -> Result<Option<String>, HostError> {
    let (register, heartbeat): (String, Option<String>) = lock(&host.db).query_row(
        "SELECT register, heartbeat FROM agents WHERE id = ?",
        [agent_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let register = parse_json_text(Some(&register));
    let heartbeat = parse_json_text(heartbeat.as_deref());
    let engine = str_field(definition, "engine");
    if let Some(engine) = engine
        && let Some(capabilities) = heartbeat
            .get("capabilities")
            .or_else(|| register.get("capabilities"))
            .and_then(Value::as_array)
        && !capabilities.iter().any(|name| name == engine)
    {
        return Ok(Some(format!(
            "agent {agent_id} does not run engine {engine}"
        )));
    }
    let Some(model) = str_field(definition, "model") else {
        return Ok(None);
    };
    let engine = engine
        .or_else(|| {
            heartbeat
                .pointer("/defaults/engine")
                .and_then(Value::as_str)
        })
        .unwrap_or("claude");
    let models = heartbeat["engines"]
        .as_array()
        .and_then(|engines| engines.iter().find(|e| e["name"] == engine))
        .and_then(|e| e["models"].as_array());
    if let Some(models) = models
        && !models.iter().any(|m| m["id"] == model)
    {
        return Ok(Some(format!(
            "engine {engine} on agent {agent_id} offers no model {model}"
        )));
    }
    Ok(None)
}

/// The `task_upsert` fields present in an operator body; `null` is kept (it clears `engine` /
/// `model` on the agent).
fn task_fields(body: &Value) -> Map<String, Value> {
    TASK_FIELDS
        .iter()
        .filter_map(|key| {
            body.get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect()
}

/// `POST /api/tasks` `{agentId?, taskId?, name?, kind?, engine?, model?, workdir?, meta?,
/// entries?, encrypted?}`. With `encrypted: true` the client device creates the task's MLS
/// group, adds the agent and delivers its Welcome (protocol §5.3).
pub(crate) async fn create_task(State(host): Shared, body: Bytes) -> Reply {
    let body = body_object(&body);
    let agent_id = match pick_agent(&host, non_empty(&body, "agentId"))? {
        Ok(id) => id,
        Err(response) => return Ok(response),
    };
    let task_id = non_empty(&body, "taskId").map_or_else(|| new_id("task"), str::to_owned);
    if task(&host, &task_id)?.is_some() {
        return Ok(fail(
            StatusCode::CONFLICT,
            &format!("task {task_id} exists"),
        ));
    }
    if let Some(entries) = body.get("entries")
        && let Err(message) = check_entries(&host, entries)?
    {
        return Ok(fail(StatusCode::BAD_REQUEST, &message));
    }
    let encrypted = body.get("encrypted") == Some(&Value::Bool(true));
    let mut data = task_fields(&body);
    data.entry("status").or_insert_with(|| json!("active"));
    if let Some(message) = check_engine_model(&host, &agent_id, &Value::Object(data.clone()))? {
        return Ok(fail(StatusCode::BAD_REQUEST, &message));
    }
    // An encrypted task is placed only on a runner that can hold its key (downgrade refusal).
    let group = if encrypted {
        match e2ee::create_group(&host, &agent_id, &task_id)? {
            Ok(group) => {
                data.insert("e2ee".into(), group.e2ee.clone());
                Some(group)
            }
            Err(response) => return Ok(response),
        }
    } else {
        None
    };
    lock(&host.db).execute(
        "INSERT INTO tasks (id, agent_id, name, definition, encrypted, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        params![
            task_id,
            agent_id,
            str_field(&body, "name"),
            Value::Object(data.clone()).to_string(),
            encrypted,
            now()
        ],
    )?;
    let msg_id = host.enqueue(
        &agent_id,
        json!({ "type": "task_upsert", "taskId": task_id, "data": data }),
    )?;
    if let Some(group) = group {
        e2ee::deliver_welcome(&host, &agent_id, &task_id, &group)?;
    }
    Ok(reply(
        StatusCode::CREATED,
        &json!({ "taskId": task_id, "agentId": agent_id, "msgId": msg_id, "encrypted": encrypted }),
    ))
}

/// `PATCH /api/tasks/{id}`: a partial `task_upsert`. Absent fields stay; `engine: null` /
/// `model: null` clear them back to the agent's defaults.
pub(crate) async fn update_task(
    State(host): Shared,
    Path(task_id): Path<String>,
    body: Bytes,
) -> Reply {
    let Some(task) = task(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    let body = body_object(&body);
    let data = task_fields(&body);
    if data.is_empty() {
        return Ok(fail(
            StatusCode::BAD_REQUEST,
            &format!("nothing to change; fields: {}", TASK_FIELDS.join(", ")),
        ));
    }
    if let Some(entries) = data.get("entries")
        && let Err(message) = check_entries(&host, entries)?
    {
        return Ok(fail(StatusCode::BAD_REQUEST, &message));
    }
    let definition: String = lock(&host.db).query_row(
        "SELECT definition FROM tasks WHERE id = ?",
        [&task_id],
        |r| r.get(0),
    )?;
    let mut definition = parse_json_text(Some(&definition));
    merge_patch(&mut definition, &Value::Object(data.clone()));
    if (data.contains_key("engine") || data.contains_key("model"))
        && let Some(message) = check_engine_model(&host, &task.agent_id, &definition)?
    {
        return Ok(fail(StatusCode::BAD_REQUEST, &message));
    }
    lock(&host.db).execute(
        "UPDATE tasks SET definition = ?, name = COALESCE(?, name) WHERE id = ?",
        params![definition.to_string(), str_field(&body, "name"), task_id],
    )?;
    let msg_id = host.enqueue(
        &task.agent_id,
        json!({ "type": "task_upsert", "taskId": task_id, "data": data }),
    )?;
    Ok(reply(
        StatusCode::OK,
        &json!({ "taskId": task_id, "msgId": msg_id }),
    ))
}

pub(crate) async fn list_tasks(State(host): Shared) -> Reply {
    let tasks: Vec<Value> = rows(
        &lock(&host.db),
        "SELECT * FROM tasks ORDER BY created_at",
        [],
    )?
    .into_iter()
    .map(|t| task_view(&host, t))
    .collect();
    Ok(reply(StatusCode::OK, &Value::Array(tasks)))
}

fn task_view(host: &Host, mut row: Map<String, Value>) -> Value {
    let online = row
        .get("agent_id")
        .and_then(Value::as_str)
        .is_some_and(|id| host.online(id));
    let definition = parse_json_text(row.get("definition").and_then(Value::as_str));
    row.insert("definition".into(), definition);
    row.insert(
        "encrypted".into(),
        Value::Bool(row.get("encrypted") == Some(&json!(1))),
    );
    row.insert("agentOnline".into(), Value::Bool(online));
    Value::Object(row)
}

fn threads_of(host: &Host, task_id: &str) -> Result<Value, HostError> {
    let threads = rows(
        &lock(&host.db),
        "SELECT t.id AS thread_id, t.created_at, r.status, r.failure_reason, r.duration_ms, r.final_seq,
                r.engine, r.model, (SELECT COUNT(*) FROM messages m WHERE m.thread_id = t.id) AS message_count
           FROM threads t LEFT JOIN thread_runs r ON r.thread_id = t.id
          WHERE t.task_id = ? ORDER BY t.created_at",
        [task_id],
    )?;
    Ok(Value::Array(
        threads.into_iter().map(Value::Object).collect(),
    ))
}

pub(crate) async fn get_task(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    let row = first_row(
        &lock(&host.db),
        "SELECT * FROM tasks WHERE id = ?",
        [&task_id],
    )?;
    let Some(row) = row else {
        return Ok(unknown_task(&task_id));
    };
    let mut view = task_view(&host, row);
    view["threads"] = threads_of(&host, &task_id)?;
    view["e2ee"] = e2ee::scope_view(&host, &task_id)?;
    Ok(reply(StatusCode::OK, &view))
}

pub(crate) async fn delete_task(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    let Some(task) = task(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    lock(&host.db).execute("DELETE FROM tasks WHERE id = ?", [&task_id])?;
    let msg_id = host.enqueue(
        &task.agent_id,
        json!({ "type": "task_delete", "taskId": task_id }),
    )?;
    Ok(reply(
        StatusCode::OK,
        &json!({ "taskId": task_id, "msgId": msg_id }),
    ))
}

pub(crate) async fn task_threads(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    if task(&host, &task_id)?.is_none() {
        return Ok(unknown_task(&task_id));
    }
    Ok(reply(StatusCode::OK, &threads_of(&host, &task_id)?))
}

// ─── messages, interrupts and crons ─────────────────────────────────────────

/// The attachment descriptors of a message from the operator's `attachments`: staged ids, or
/// `{id, name}` to give the name (needed on an encrypted task, whose stored name is opaque).
fn message_attachments(
    host: &Host,
    task: &Task,
    list: &Value,
) -> Result<Result<Vec<Value>, String>, HostError> {
    let Some(items) = list.as_array() else {
        return Ok(Err("attachments must be an array".into()));
    };
    let mut descriptors = Vec::new();
    for item in items {
        let (id, name) = match item {
            Value::String(id) => (id.as_str(), None),
            other => (
                str_field(other, "id").unwrap_or_default(),
                str_field(other, "name"),
            ),
        };
        let blob = blobs::find(host, id)?
            .filter(|b| b.agent_id == task.agent_id && b.direction == "inbound");
        let Some(mut blob) = blob else {
            return Ok(Err(format!("unknown staged attachment {id}")));
        };
        if let Some(name) = name {
            name.clone_into(&mut blob.name);
        } else if task.encrypted {
            return Ok(Err(format!(
                "attachment {id}: pass its name; the stored one is opaque"
            )));
        }
        descriptors.push(blob.descriptor());
    }
    Ok(Ok(descriptors))
}

/// `POST /api/tasks/{id}/messages` `{text, attachments?, newThread?}` → a durable `message`.
/// The host mints the thread id and records it before sending (protocol §5). On an encrypted
/// task the client device seals `text` and the attachment names.
pub(crate) async fn send_message(
    State(host): Shared,
    Path(task_id): Path<String>,
    body: Bytes,
) -> Reply {
    let Some(task) = task(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    let body = body_object(&body);
    let Some(text) = non_empty(&body, "text") else {
        return Ok(fail(StatusCode::BAD_REQUEST, "text is required"));
    };
    let mut data = json!({ "text": text });
    if let Some(list) = body.get("attachments") {
        match message_attachments(&host, &task, list)? {
            Ok(descriptors) => data["attachments"] = Value::Array(descriptors),
            Err(message) => return Ok(fail(StatusCode::BAD_REQUEST, &message)),
        }
    }
    let thread_id = match &task.current_thread_id {
        Some(id) if !id.is_empty() && body.get("newThread") != Some(&Value::Bool(true)) => {
            id.clone()
        }
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
    let mut frame =
        json!({ "type": "message", "taskId": task_id, "threadId": thread_id, "data": data });
    if task.encrypted {
        frame = e2ee::seal_frame(&host, &task_id, "message", &frame)?;
    }
    let runs = run_count(&host, &thread_id)?;
    let msg_id = host.enqueue(&task.agent_id, frame)?;
    Ok(reply(
        StatusCode::ACCEPTED,
        &json!({ "taskId": task_id, "threadId": thread_id, "msgId": msg_id, "runs": runs,
                 "agentOnline": host.online(&task.agent_id) }),
    ))
}

/// `interrupt` is live-only (protocol §5): never persisted, never replayed.
pub(crate) async fn interrupt(State(host): Shared, Path(task_id): Path<String>) -> Reply {
    let Some(task) = task(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    if host.send(
        &task.agent_id,
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

/// `POST /api/tasks/{id}/crons` `{cronId?, prompt, scheduleType, scheduleValue, continuity?,
/// status?}` → a durable `cron_upsert` (prompt sealed on an encrypted task).
pub(crate) async fn upsert_cron(
    State(host): Shared,
    Path(task_id): Path<String>,
    body: Bytes,
) -> Reply {
    let Some(task) = task(&host, &task_id)? else {
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
        "status": non_empty(&body, "status").unwrap_or("active"),
    });
    let mut frame =
        json!({ "type": "cron_upsert", "taskId": task_id, "cronId": cron_id, "data": data });
    if task.encrypted {
        frame = e2ee::seal_frame(&host, &task_id, "cron_upsert", &frame)?;
    }
    let msg_id = host.enqueue(&task.agent_id, frame)?;
    Ok(reply(
        StatusCode::CREATED,
        &json!({ "taskId": task_id, "cronId": cron_id, "msgId": msg_id }),
    ))
}

pub(crate) async fn delete_cron(
    State(host): Shared,
    Path((task_id, cron_id)): Path<(String, String)>,
) -> Reply {
    let Some(task) = task(&host, &task_id)? else {
        return Ok(unknown_task(&task_id));
    };
    let msg_id = host.enqueue(
        &task.agent_id,
        json!({ "type": "cron_delete", "taskId": task_id, "cronId": cron_id }),
    )?;
    Ok(reply(
        StatusCode::OK,
        &json!({ "taskId": task_id, "cronId": cron_id, "msgId": msg_id }),
    ))
}

pub(crate) async fn list_crons(State(host): Shared) -> Reply {
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

// ─── transcripts ────────────────────────────────────────────────────────────

/// A thread's run and ordered transcript (protocol §6: ordered by `seq`). On an encrypted task
/// every stored frame is opened by the client device; one that does not open is shown sealed
/// with `openError`.
pub(crate) fn thread_view(host: &Host, thread_id: &str) -> Result<Value, HostError> {
    let (run, messages, task_id) = {
        let db = lock(&host.db);
        let run = first_row(
            &db,
            "SELECT * FROM thread_runs WHERE thread_id = ?",
            [thread_id],
        )?;
        let messages = rows(
            &db,
            "SELECT seq, kind, data, frame, received_at FROM messages WHERE thread_id = ? ORDER BY seq",
            [thread_id],
        )?;
        let task_id: Option<String> = db
            .query_row(
                "SELECT task_id FROM threads WHERE id = ?",
                [thread_id],
                |r| r.get(0),
            )
            .optional()?;
        (run, messages, task_id)
    };
    let encrypted = match &task_id {
        Some(id) => task(host, id)?.is_some_and(|t| t.encrypted),
        None => false,
    };
    let open = |frame_type: &str, frame: Value| -> Result<Value, String> {
        let task_id = task_id.as_deref().unwrap_or_default();
        e2ee::open_frame(host, task_id, frame_type, &frame).map_err(|err| err.0)
    };

    let messages: Vec<Value> = messages
        .into_iter()
        .map(|mut m| {
            let frame = parse_json_text(m.remove("frame").as_ref().and_then(Value::as_str));
            let mut data = parse_json_text(m.remove("data").as_ref().and_then(Value::as_str));
            if encrypted {
                match open("thread_message", frame) {
                    Ok(opened) => data = opened["data"].clone(),
                    Err(err) => {
                        m.insert("openError".into(), json!(err));
                    }
                }
            }
            if let Value::Object(fields) = data {
                m.extend(fields);
            }
            Value::Object(m)
        })
        .collect();

    let run = run.map(|mut run| {
        let frame = parse_json_text(run.remove("frame").as_ref().and_then(Value::as_str));
        for key in ["usage", "attachments", "encryption_error"] {
            let parsed = parse_json_text(run.get(key).and_then(Value::as_str));
            run.insert(key.into(), parsed);
        }
        if encrypted && frame.is_object() {
            match open("thread_result", frame) {
                Ok(opened) => {
                    for key in ["result", "error", "attachments"] {
                        if let Some(value) = opened["data"].get(key) {
                            run.insert(key.into(), value.clone());
                        }
                    }
                }
                Err(err) => {
                    run.insert("openError".into(), json!(err));
                }
            }
        }
        Value::Object(run)
    });
    Ok(json!({ "threadId": thread_id, "taskId": task_id, "run": run, "messages": messages }))
}

/// How many distinct results the thread has reported (0 before the first).
fn run_count(host: &Host, thread_id: &str) -> Result<i64, HostError> {
    Ok(lock(&host.db)
        .query_row(
            "SELECT runs FROM thread_runs WHERE thread_id = ?",
            [thread_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

pub(crate) async fn get_thread(State(host): Shared, Path(thread_id): Path<String>) -> Reply {
    Ok(reply(StatusCode::OK, &thread_view(&host, &thread_id)?))
}

/// `GET /api/threads/{id}/wait?timeoutMs=60000&after=<runs>`: long-poll until the thread has
/// more than `after` results (default 0: any result). `POST …/messages` answers the count at
/// send time, so waiting with it returns that message's turn, not an earlier one.
pub(crate) async fn wait_thread(
    State(host): Shared,
    Path(thread_id): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    let timeout = query
        .get("timeoutMs")
        .and_then(|t| t.parse().ok())
        .unwrap_or(60_000);
    let after: i64 = query.get("after").and_then(|a| a.parse().ok()).unwrap_or(0);
    let deadline = Instant::now() + Duration::from_millis(timeout);
    while run_count(&host, &thread_id)? <= after {
        if Instant::now() >= deadline {
            let mut view = thread_view(&host, &thread_id)?;
            view["timedOut"] = Value::Bool(true);
            return Ok(reply(StatusCode::REQUEST_TIMEOUT, &view));
        }
        tokio::time::sleep(WAIT_POLL).await;
    }
    Ok(reply(StatusCode::OK, &thread_view(&host, &thread_id)?))
}
