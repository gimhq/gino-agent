//! The shared host state: the database, the live agent sockets and the in-flight live-only
//! exchanges (file operations, terminals).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::ws::Message;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot};
use tracing::error;

use crate::store::SCHEMA;
use crate::util::{lock, now, parse_json_text, reply};

/// The protocol version this host speaks.
pub const PROTOCOL_VERSION: u64 = 1;
/// The default `heartbeatIntervalMs` handed to agents.
pub const HEARTBEAT_INTERVAL_MS: u64 = 30_000;

/// Host settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// The enrollment secret an agent must present to register.
    pub register_token: String,
    /// The SQLite file (`:memory:` for an in-memory database).
    pub db_path: PathBuf,
    /// The initial `config.engine` of every newly registered agent (credentials, base URL,
    /// model); operators change it per agent with `PATCH /api/agents/{id}/config`.
    pub engine: Map<String, Value>,
    /// `heartbeatIntervalMs` handed to agents ([`HEARTBEAT_INTERVAL_MS`] by default).
    pub heartbeat_interval_ms: u64,
}

/// One live agent socket. A newer connection of the same agent replaces it.
#[derive(Debug)]
pub(crate) struct Peer {
    pub(crate) conn: u64,
    pub(crate) tx: mpsc::UnboundedSender<Message>,
}

/// An operator's terminal: frames from the agent are forwarded to `tx`.
#[derive(Debug)]
pub(crate) struct PtySession {
    pub(crate) agent_id: String,
    pub(crate) conn: u64,
    pub(crate) tx: mpsc::Sender<Value>,
}

/// Shared host state.
#[derive(Debug)]
pub struct Host {
    pub(crate) config: Config,
    pub(crate) db: Mutex<Connection>,
    pub(crate) peers: Mutex<HashMap<String, Peer>>,
    ids: Mutex<ulid::Generator>,
    pub(crate) next_conn: AtomicU64,
    /// Pending `fs_request`s by `reqId`: the agent they went to and the waiting operator call.
    pub(crate) fs_pending: Mutex<HashMap<String, (String, oneshot::Sender<Value>)>>,
    /// Open terminals by `ptyId`.
    pub(crate) ptys: Mutex<HashMap<String, PtySession>>,
}

/// A handler failure, answered as `500 {"error": …}`.
#[derive(Debug)]
pub struct HostError(pub(crate) String);

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

pub(crate) type Reply = Result<Response, HostError>;
pub(crate) type Shared = axum::extract::State<Arc<Host>>;

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
            fs_pending: Mutex::new(HashMap::new()),
            ptys: Mutex::new(HashMap::new()),
        }))
    }

    /// Monotonic lowercase ULID (protocol §4.2 delivery ids).
    pub(crate) fn ulid(&self) -> Result<String, HostError> {
        Ok(lock(&self.ids).generate()?.to_string().to_lowercase())
    }

    pub(crate) fn next_conn(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn online(&self, agent_id: &str) -> bool {
        lock(&self.peers).contains_key(agent_id)
    }

    /// Send a frame on the agent's live socket, if it has one. Live-only frames use this
    /// directly; durable ones go through [`Host::enqueue`].
    pub(crate) fn send(&self, agent_id: &str, frame: &Value) -> bool {
        lock(&self.peers).get(agent_id).is_some_and(|peer| {
            peer.tx
                .send(Message::Text(frame.to_string().into()))
                .is_ok()
        })
    }

    /// Persist a durable host→agent frame (its row id is the `msgId`) and push it if the agent
    /// is online; an offline agent receives it on its next connect (protocol §4.2).
    pub(crate) fn enqueue(&self, agent_id: &str, frame: Value) -> Result<String, HostError> {
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

    /// Whether `headers` carry the connect token of `agent_id`.
    pub(crate) fn authenticate(
        &self,
        headers: &HeaderMap,
        agent_id: &str,
    ) -> Result<bool, HostError> {
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

    /// The agent whose connect token `headers` carry, for the routes without an agent id in
    /// the path (the byte channel).
    pub(crate) fn agent_by_token(&self, headers: &HeaderMap) -> Result<Option<String>, HostError> {
        let Some(token) = headers
            .get("x-internal-token")
            .and_then(|v| v.to_str().ok())
        else {
            return Ok(None);
        };
        Ok(lock(&self.db)
            .query_row(
                "SELECT id FROM agents WHERE connect_token = ?",
                [token],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub(crate) fn agent_exists(&self, agent_id: &str) -> Result<bool, HostError> {
        Ok(lock(&self.db)
            .query_row("SELECT 1 FROM agents WHERE id = ?", [agent_id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// The host config layer of `agent_id` and its version.
    pub(crate) fn config_layer(&self, agent_id: &str) -> Result<(Value, i64), HostError> {
        let row: Option<(String, i64)> = lock(&self.db)
            .query_row(
                "SELECT config, config_version FROM agents WHERE id = ?",
                [agent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(row.map_or_else(
            || (json!({}), 0),
            |(config, version)| (parse_json_text(Some(&config)), version),
        ))
    }

    /// The config the agent receives on register and `GET /agent/config/{id}` (protocol §3):
    /// the fixed routing fields, then the host layer, then its `version`.
    pub(crate) fn agent_config(&self, agent_id: &str) -> Result<Value, HostError> {
        let (layer, version) = self.config_layer(agent_id)?;
        let mut config = json!({
            "agentId": agent_id,
            "wsUrl": format!("/agent/ws/{agent_id}"),
            "configUrl": format!("/agent/config/{agent_id}"),
            "outputUrl": format!("/agent/output/{agent_id}"),
            "heartbeatIntervalMs": self.config.heartbeat_interval_ms,
            "protocolVersion": PROTOCOL_VERSION,
            "entries": [],
        });
        if let (Some(config), Value::Object(layer)) = (config.as_object_mut(), layer) {
            config.extend(layer);
            config.insert("version".into(), json!(version));
        }
        Ok(config)
    }
}
