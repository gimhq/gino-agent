//! mini-host — the reference gino host, speaking the whole host-agent protocol
//! (`docs/protocol.md`) against a real `gino-agent`.
//!
//! It is small on purpose: one SQLite file, no launchers and no auth on the operator API (bind
//! it to loopback). Everything an agent can do over the protocol is reachable: other hosts start
//! from it, and the release joint suite (`tests/joint.rs`) runs the agent against it.
//!
//! Modules map to the protocol:
//!
//! | module | protocol |
//! |---|---|
//! | [`agent`](crate::agent) | §3 enrollment and config fetch, §4 the WebSocket, outbox replay and acks, §5 durable frames |
//! | `config` | §3 the host config layer, `config_update` with `version`, provisioning artifacts |
//! | `blobs` | §2 the attachment byte channel |
//! | `fs` | §5.1 engine-free file operations |
//! | `pty` | §5.2 interactive terminals |
//! | `e2ee` | §5.3 end-to-end encryption: the Delivery Service and the operator's client device |
//! | `api` | the operator API (not part of the protocol) |
//!
//! Agent side (protocol v1):
//!
//! ```text
//! POST /agent/register                   GET  /agent/config/{id}
//! WS   /agent/ws/{id}                    POST /agent/output/{id}
//! GET  /agent/attachments/{id}           GET  /agent/attachments?sha256=<hex>
//! POST /agent/attachments
//! ```
//!
//! Operator side (JSON):
//!
//! ```text
//! GET    /api/agents                       GET   /api/agents/{id}
//! GET    /api/agents/{id}/config           PATCH /api/agents/{id}/config        merge patch → config_update
//! POST   /api/agents/{id}/fs               {op, path, to?, recursive?, exclusive?, content?}
//! GET    /api/agents/{id}/pty              WebSocket: open / ready / input / output / resize / close / exit
//! POST   /api/agents/{id}/close            {reason?}
//! POST   /api/agents/{id}/e2ee/repin       accept an identity key change
//! POST   /api/artifacts                    raw bytes → {sha256, size} for provisioning entries
//! GET    /api/tasks                        POST  /api/tasks {agentId?, taskId?, name?, kind?, engine?, model?,
//!                                                            workdir?, meta?, entries?, encrypted?}
//! GET    /api/tasks/{id}                   PATCH /api/tasks/{id}   DELETE /api/tasks/{id}
//! POST   /api/tasks/{id}/attachments       raw bytes, x-attachment-name → descriptor
//! GET    /api/tasks/{id}/attachments/{aid} the bytes (opened on an encrypted task)
//! POST   /api/tasks/{id}/messages          {text, attachments?, newThread?} → {threadId, msgId, runs}
//! POST   /api/tasks/{id}/interrupt
//! POST   /api/tasks/{id}/crons             {cronId?, prompt, scheduleType, scheduleValue, continuity?, status?}
//! DELETE /api/tasks/{id}/crons/{cronId}
//! POST   /api/tasks/{id}/e2ee/update       the client device commits a new epoch
//! GET    /api/tasks/{id}/threads
//! GET    /api/threads/{threadId}           run + ordered transcript
//! GET    /api/threads/{threadId}/wait?timeoutMs=60000&after={runs}
//! GET    /api/crons
//! ```
//!
//! A task's `engine` must be one the agent advertises in `capabilities`, and its `model` one
//! the agent's probe listed for that engine (`engines[].models` on the agent view); otherwise
//! creating or patching the task answers 400.

mod agent;
mod api;
mod blobs;
mod config;
mod e2ee;
mod fs;
mod host;
mod pty;
mod store;
mod util;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{delete, get, post};

pub use crate::host::{Config, HEARTBEAT_INTERVAL_MS, Host, HostError, PROTOCOL_VERSION};
use crate::util::fail;

/// The HTTP and WebSocket routes.
pub fn router(host: Arc<Host>) -> Router {
    Router::new()
        .route("/", get(api::status))
        // Agent side.
        .route("/agent/register", post(agent::register))
        .route("/agent/config/{id}", get(agent::config))
        .route("/agent/output/{id}", post(agent::output))
        .route("/agent/ws/{id}", get(agent::websocket))
        .route(
            "/agent/attachments",
            get(blobs::fetch_artifact).post(blobs::upload),
        )
        .route("/agent/attachments/{id}", get(blobs::download))
        // Operator side.
        .route("/api/agents", get(api::list_agents))
        .route("/api/agents/{id}", get(api::get_agent))
        .route(
            "/api/agents/{id}/config",
            get(config::get).patch(config::patch),
        )
        .route("/api/agents/{id}/fs", post(fs::request))
        .route("/api/agents/{id}/pty", get(pty::open))
        .route("/api/agents/{id}/close", post(api::close_agent))
        .route("/api/agents/{id}/e2ee/repin", post(e2ee::repin))
        .route("/api/artifacts", post(config::upload_artifact))
        .route("/api/crons", get(api::list_crons))
        .route("/api/threads/{id}", get(api::get_thread))
        .route("/api/threads/{id}/wait", get(api::wait_thread))
        .route("/api/tasks", get(api::list_tasks).post(api::create_task))
        .route(
            "/api/tasks/{id}",
            get(api::get_task)
                .patch(api::update_task)
                .delete(api::delete_task),
        )
        .route("/api/tasks/{id}/attachments", post(blobs::stage))
        .route("/api/tasks/{id}/attachments/{aid}", get(blobs::read))
        .route("/api/tasks/{id}/threads", get(api::task_threads))
        .route("/api/tasks/{id}/messages", post(api::send_message))
        .route("/api/tasks/{id}/interrupt", post(api::interrupt))
        .route("/api/tasks/{id}/crons", post(api::upsert_cron))
        .route("/api/tasks/{id}/crons/{cron_id}", delete(api::delete_cron))
        .route("/api/tasks/{id}/e2ee/update", post(e2ee::client_update))
        .fallback(|| async { fail(StatusCode::NOT_FOUND, "not found") })
        .method_not_allowed_fallback(|| async {
            fail(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        })
        .with_state(host)
}
