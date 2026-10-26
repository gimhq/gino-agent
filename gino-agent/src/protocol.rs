//! Wire protocol types.
//!
//! These are the serde envelopes exchanged with the orchestrator. They are
//! host-wire-compatible: field names match the existing TypeScript runner
//! (`container/gino-agent/src/types.ts`) and the host WS handler, so the Rust
//! runner is a drop-in on the same socket.
//!
//! ## The live contract
//!
//! The runner speaks `protocolVersion = 1` end to end
//! (agent-architecture §10): the [`frames`] module is the live frame catalog —
//! correlation ids (`taskId`/`threadId`/`cronId`) at the **envelope top level**,
//! business fields under `data`, and the `thread_*`/`cron_*` frames. The HTTP
//! registration DTOs ([`RegisterRequest`] et al.) live at this top level.
//!
//! ## Secrets
//!
//! The register token and connect token are wrapped in [`Redacted`] so they are
//! never printed by `Debug`/logs, while still serializing transparently onto the
//! wire (the tokens must reach the host) and deserializing back. The durable
//! boundary wrap into `secrecy::SecretString` happens in the config/identity
//! layers that consume these DTOs.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Protocol version
// ---------------------------------------------------------------------------

/// Negotiated wire-protocol version (agent-architecture §10). The agent sends it in
/// `POST /agent/register`; the host returns the version it will speak and rejects
/// a mismatch with `register_error { reason: "unsupported_protocol" }`
/// ([`RegisterError`]). Compatibility is additive-within-major: new optional
/// fields and new `type`s are non-breaking and receivers ignore unknown ones.
///
/// Sent on the wire and gated by [`register`](crate::register): it rides the
/// register request ([`RegisterRequest::protocol_version`]) and the negotiation
/// refuses a host that cannot speak it (Lane PV).
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// A deterministic delivery id for tests: a valid lowercase ULID ordered by `n`.
#[cfg(test)]
pub(crate) fn test_delivery_id(n: u32) -> String {
    format!("01jab3x7k2m4n5p6q7r8s9{n:04}")
}

// ---------------------------------------------------------------------------
// Redaction wrapper
// ---------------------------------------------------------------------------

/// A string that serializes/deserializes transparently but is redacted in
/// `Debug` output. Used for the bootstrap tokens carried by the register DTOs so
/// they never leak through a `{:?}` of a logged request/response.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Redacted(String);

impl Redacted {
    /// Wrap a raw secret string.
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the raw secret. Callers should hand this straight to the
    /// `secrecy`-backed config/identity boundary, not to a logger.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"<redacted>\"")
    }
}

// ---------------------------------------------------------------------------
// HTTP registration
// ---------------------------------------------------------------------------

/// `POST /agent/register` request body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterRequest {
    /// Bootstrap enrollment credential (redacted in `Debug`).
    pub(crate) register_token: Redacted,
    /// Wire-protocol version this agent speaks ([`PROTOCOL_VERSION`]); the host
    /// gates enrollment on it (§1) and rejects a mismatch with
    /// `register_error { reason: "unsupported_protocol" }`.
    pub(crate) protocol_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    pub(crate) capabilities: Vec<String>,
    pub(crate) version: String,
    pub(crate) platform: String,
    /// End-to-end encryption capability (protocol §3); absent on a runner
    /// without e2ee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) e2ee: Option<frames::E2eeCapability>,
}

/// Successful `POST /agent/register` response: the host-generated `agentId`, a
/// freshly minted per-agent `connectToken`, and the assigned config overlay.
///
/// Deliberately `Deserialize`-only: this DTO carries the connect token, and the
/// agent only ever *receives* it. Not deriving `Serialize` removes a whole
/// token-leak surface (accidentally re-serializing the secret into a log, an
/// outbox payload, or a frame).
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RegisterOk {
    pub(crate) agent_id: String,
    /// Per-agent WS connect token (redacted in `Debug`).
    pub(crate) connect_token: Redacted,
    /// Host-assigned config (merged by the config layer). Opaque here.
    pub(crate) config: Value,
}

/// Failure envelope: `{register_error: {reason}}`. Kept snake_case to match the
/// host wire key exactly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct RegisterErrorEnvelope {
    pub(crate) register_error: RegisterError,
}

/// The reason carried by a [`RegisterErrorEnvelope`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct RegisterError {
    pub(crate) reason: String,
}

/// The two shapes a register response can take. Untagged: a body with
/// `agentId`/`connectToken`/`config` parses as [`RegisterResponse::Ok`];
/// `{register_error: …}` parses as [`RegisterResponse::Error`].
/// `Deserialize`-only, like the secret-bearing [`RegisterOk`] it contains.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum RegisterResponse {
    Ok(RegisterOk),
    Error(RegisterErrorEnvelope),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::frames::E2eeCapability;
    use super::{
        PROTOCOL_VERSION, Redacted, RegisterError, RegisterErrorEnvelope, RegisterRequest,
        RegisterResponse,
    };

    #[test]
    fn redacted_hides_value_in_debug_but_serializes_transparently() {
        let secret = Redacted::new("super-secret");
        assert_eq!(secret.expose(), "super-secret");
        assert_eq!(format!("{secret:?}"), "\"<redacted>\"");
        assert_eq!(
            serde_json::to_value(&secret).unwrap(),
            json!("super-secret")
        );
        let back: Redacted = serde_json::from_value(json!("super-secret")).unwrap();
        assert_eq!(back, secret);
    }

    #[test]
    fn register_request_is_camel_case_and_redacts_token() {
        let req = RegisterRequest {
            register_token: Redacted::new("enroll-tok"),
            protocol_version: PROTOCOL_VERSION,
            name: Some("worker-1".to_owned()),
            capabilities: vec!["claude".to_owned()],
            version: "0.1.0".to_owned(),
            platform: "x86_64-unknown-linux-gnu".to_owned(),
            e2ee: None,
        };
        assert!(!format!("{req:?}").contains("enroll-tok"));
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({
                "registerToken": "enroll-tok",
                "protocolVersion": 1,
                "name": "worker-1",
                "capabilities": ["claude"],
                "version": "0.1.0",
                "platform": "x86_64-unknown-linux-gnu"
            })
        );
        let back: RegisterRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn register_request_carries_the_e2ee_capability() {
        let req = RegisterRequest {
            register_token: Redacted::new("enroll-tok"),
            protocol_version: PROTOCOL_VERSION,
            name: None,
            capabilities: Vec::new(),
            version: "0.1.0".to_owned(),
            platform: "x86_64-linux".to_owned(),
            e2ee: Some(E2eeCapability::basic("AAAA".to_owned())),
        };
        let value = serde_json::to_value(&req).unwrap();
        assert_eq!(
            value["e2ee"],
            json!({
                "versions": [1],
                "mls_suites": [1],
                "credential": { "type": "basic", "public_key": "AAAA" }
            })
        );
        let back: RegisterRequest = serde_json::from_value(value).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn register_ok_response_parses_and_redacts() {
        // Parse-only by design: RegisterOk carries the connect token and does not
        // implement Serialize (see the type's doc), so there is no re-serialize
        // round trip to assert here.
        let raw = r#"{
            "agentId": "agent-123",
            "connectToken": "connect-secret",
            "config": { "engine": { "model": "claude-sonnet-4-6" } }
        }"#;
        let resp: RegisterResponse = serde_json::from_str(raw).unwrap();
        let RegisterResponse::Ok(ok) = &resp else {
            panic!("expected Ok variant, got {resp:?}");
        };
        assert_eq!(ok.agent_id, "agent-123");
        assert_eq!(ok.connect_token.expose(), "connect-secret");
        assert_eq!(ok.config["engine"]["model"], json!("claude-sonnet-4-6"));
        assert!(!format!("{resp:?}").contains("connect-secret"));
    }

    #[test]
    fn register_error_response_round_trips() {
        let raw = r#"{ "register_error": { "reason": "invalid register token" } }"#;
        let resp: RegisterResponse = serde_json::from_str(raw).unwrap();
        let envelope = RegisterErrorEnvelope {
            register_error: RegisterError {
                reason: "invalid register token".to_owned(),
            },
        };
        assert_eq!(resp, RegisterResponse::Error(envelope.clone()));
        // The secret-free error envelope still serializes (only the enum and the
        // secret-bearing Ok variant are Deserialize-only).
        assert_eq!(
            serde_json::to_value(&envelope).unwrap(),
            json!({ "register_error": { "reason": "invalid register token" } })
        );
    }
}

// ---------------------------------------------------------------------------
// Protocol frames
// ---------------------------------------------------------------------------

/// Protocol frame types (agent-architecture §10/§12/§14).
///
/// ## Envelope vs payload
///
/// Every frame is one JSON object. Correlation/delivery metadata lives at the
/// **envelope top level** — `type`, the delivery ids `outboxId`/`msgId`, and the
/// correlation ids `taskId`/`threadId`/`cronId` — while `data` carries the
/// type-specific **business** payload only:
///
/// ```json
/// { "type": "thread_message", "outboxId": "01jab3x7k2m4n5p6q7r8s9t0vw", "taskId": "t-1", "threadId": "c-9@1718",
///   "data": { "seq": 3, "kind": "assistant_text", "content": "…" } }
/// ```
///
/// The host routes and correlates by the envelope ids *without parsing `data`*,
/// mirroring the runner's `inbox`/`outbox` correlation columns and the host
/// read-model keys. The correlation ids are **never** repeated inside `data`.
/// `engine_session_id` is a *value* of a thread (the claude `--resume` handle),
/// not a routing key, so it lives **inside `data`** on `thread_result`.
///
/// ## Multiplexing & ordering
///
/// Many threads share one WS, so frames interleave. Each `thread_message` carries
/// a per-thread monotonic `seq` (assigned serially by the runner); the host
/// demuxes by `threadId`, orders each thread by `seq`, and writes idempotently on
/// `(threadId, seq)` (at-least-once replay can duplicate). `thread_result`'s
/// `final_seq` is the last `seq` emitted, letting the host verify it received
/// `1..=final_seq`. `outboxId` is delivery/ack only; `seq` is the per-thread
/// continuity contract.
///
/// These frames are the **live** wire contract, driven end to end by
/// `transport`/`executor`/`scheduler`/`runner`.
pub(crate) mod frames {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    // -----------------------------------------------------------------------
    // Enumerations
    // -----------------------------------------------------------------------

    /// Engine-execution lifecycle state, carried in a [`ThreadResultData`].
    /// A `thread_result` reports a terminal state (`succeeded`/`failed`/
    /// `cancelled`); the earlier states exist on the runner's `threads` row.
    #[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum ThreadStatus {
        Pending,
        Dispatched,
        Running,
        Active,
        Succeeded,
        Failed,
        Cancelled,
    }

    /// Transcript-event classification for a [`ThreadMessageData`]
    /// (agent-architecture §10; the host `messages.kind` column). `thinking`/
    /// `status` are config-filterable.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum MessageKind {
        UserInput,
        AssistantText,
        Thinking,
        ToolUse,
        ToolResult,
        Status,
        Error,
        /// An action the engine asked the host to take; `input` is
        /// `{method, params}`.
        HostAction,
        /// Any `kind` outside the recognized set, kept verbatim: protocol §5
        /// requires a receiver to store an unrecognized `kind` opaquely rather
        /// than reject the frame. Round-trips losslessly.
        #[serde(untagged)]
        Unknown(String),
    }

    // -----------------------------------------------------------------------
    // Shared payloads
    // -----------------------------------------------------------------------

    /// An out-of-band attachment **descriptor** (agent-architecture §9). Only the
    /// descriptor rides the wire; bytes move on the separate attachment channel
    /// (host-proxy / presigned), never inside a frame.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct AttachmentDescriptor {
        pub(crate) id: String,
        /// Sealed on an encrypted task (task-content §2).
        pub(crate) name: Sealable<String>,
        pub(crate) content_type: String,
        pub(crate) size: i64,
        pub(crate) sha256: String,
        /// Backend-specific locator (host-proxy path or presigned URL). `ref` is a
        /// Rust keyword, so the field is named `reference` on this side and renamed
        /// back to `ref` on the wire.
        #[serde(rename = "ref")]
        pub(crate) reference: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) direction: Option<String>,
    }

    /// Shape of a [`ProvisioningEntry`]'s materialized artifact: a
    /// single `file` (e.g. an instruction file `CLAUDE.md`/`AGENTS.md`) or a `dir`
    /// bundle (e.g. a skill = `SKILL.md` + files). Wire-parses `"file"`/`"dir"`; an
    /// unknown kind string fails to deserialize.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum EntryKind {
        File,
        Dir,
    }

    /// A versioned, content-addressed **provisioning entry**: one
    /// instruction file or skill bundle to materialize into a scope root. Engine-
    /// agnostic — the runner only knows `target`/`kind`; the host chooses the
    /// meta-driven `target` per engine (claude→`CLAUDE.md`, codex→`AGENTS.md`, …).
    /// Bytes are fetched out-of-band via `/agent/attachments` by `id`/`sha256`;
    /// only this descriptor rides the wire. Shared by both scopes: the global
    /// config layer (`config.entries`) and the task definition
    /// (`task_upsert.data.entries`).
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct ProvisioningEntry {
        /// Logical name (= store `<name>`); groups an artifact's versions.
        /// The host wire field is `name` (protocol.md §8 `ConfigEntry`); `id`
        /// is the historical agent-side spelling, kept for stored task rows.
        #[serde(alias = "name")]
        pub(crate) id: String,
        /// Full hash — the version identifier and the download-integrity check.
        pub(crate) sha256: String,
        /// Relative, meta-driven landing path under the scope root, e.g.
        /// `CLAUDE.md`, `AGENTS.md`, `.claude/skills/<name>`, `skills/<name>`.
        pub(crate) target: String,
        /// Whether the artifact is a single `file` or a `dir` bundle.
        pub(crate) kind: EntryKind,
    }

    // -----------------------------------------------------------------------
    // host → agent `data` payloads
    // -----------------------------------------------------------------------

    /// `data` of a `task_upsert` (the id is the envelope `taskId`).
    ///
    /// Every field is optional and carries OMISSION-PRESERVES semantics: an
    /// absent field leaves whatever the runner already stored for the task
    /// untouched (it is never a "clear this"), so a host may push a partial
    /// definition without wiping the rest.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct TaskUpsertData {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) kind: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) status: Option<String>,
        /// The backend this task's threads run on (protocol.md §7). The
        /// runner implements `claude` and `codex`, and selects the backend per
        /// run from this field. An engine this build does not implement — or one
        /// whose backend is not registered on this runner — is warned about and
        /// runs on the DEFAULT backend rather than failing the task
        /// ([`crate::runner`]).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) engine: Option<String>,
        /// Per-task model id overriding `config.engine.model` at the NEXT engine
        /// spawn (never hot-swapped into a live session).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) model: Option<String>,
        /// Host-side working directory hint. PERSISTED ONLY — nothing in the
        /// runner reads it yet (the executor still materializes its own
        /// workspace under `paths.workspace_dir`).
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) workdir: Option<String>,
        /// Free-form host passthrough object. PERSISTED ONLY (as JSON text) —
        /// nothing in the runner reads it yet. Typed as a raw [`Value`] rather
        /// than a map so a future non-object shape cannot fail the whole frame.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) meta: Option<Value>,
        /// Task-scope provisioning entries (instruction file + skills) materialized
        /// into `<thread.work_dir>/project/`. Absent → `None`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) entries: Option<Vec<ProvisioningEntry>>,
        /// Marks the task as end-to-end encrypted (protocol §5.3). Once set on
        /// the runner it is never cleared.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) e2ee: Option<TaskE2ee>,
    }

    /// `data` of a `cron_upsert` (ids are the envelope `taskId`/`cronId`).
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct CronUpsertData {
        pub(crate) kind: String,
        /// The recurring instruction the cron runs each fire (agent-architecture
        /// §10, D10:(a)). Required — the runner stores it into `crons.prompt`.
        /// Sealed on an encrypted task.
        pub(crate) prompt: Sealable<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) schedule_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) schedule_value: Option<String>,
        pub(crate) continuity: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) next_run: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) status: Option<String>,
    }

    /// `data` of an inbound `message` (ids are the envelope `taskId`/`threadId?`).
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct MessageInData {
        /// Sealed on an encrypted task (a content or drop envelope).
        pub(crate) text: Sealable<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) attachments: Option<Vec<AttachmentDescriptor>>,
    }

    // -----------------------------------------------------------------------
    // agent → host `data` payloads
    // -----------------------------------------------------------------------

    /// `data` of a `thread_result` — the terminal outcome of an execution.
    /// `engine_session_id` is the thread's resume handle (a value, not a routing
    /// id); `final_seq` is the last `seq` emitted on the thread.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct ThreadResultData {
        pub(crate) status: ThreadStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) result: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) error: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) failure_reason: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) engine_session_id: Option<String>,
        pub(crate) duration_ms: i64,
        pub(crate) final_seq: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) attachments: Option<Vec<AttachmentDescriptor>>,
        /// The end-to-end encryption failure behind `agent.encryption`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) encryption_error: Option<EncryptionError>,
    }

    /// `data` of a `thread_message` — one ordered transcript event. `seq` is
    /// per-thread monotonic (assigned by the runner).
    ///
    /// `parent_tool_use_id` is present on every event produced INSIDE a
    /// sub-agent (a `Task` tool call) and absent for the main agent's own
    /// events, so absence means "the main agent"; `tool_use_id` is the engine's
    /// id for a `tool_use` block, echoed on the matching `tool_result`. Neither
    /// introduces hierarchy — `seq` stays one per-thread stream.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct ThreadMessageData {
        pub(crate) seq: i64,
        pub(crate) kind: MessageKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) role: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) content: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) tool: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) input: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) output: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) tool_use_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) parent_tool_use_id: Option<String>,
    }

    /// `data` of a `cron_state` — the local scheduling-ledger summary for a cron.
    /// Round/skip counts are runner-local (D2); the host derives dispatched counts
    /// from its own mirror by `cron_id`.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct CronStateData {
        pub(crate) kind: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) schedule_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) schedule_value: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) continuity: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) next_run: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) status: Option<String>,
        pub(crate) round_count: i64,
        pub(crate) skipped_count: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) last_status: Option<String>,
    }

    /// `data` of a `heartbeat` — liveness and the runner's current
    /// capabilities (the register list), optionally summarizing live work.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct HeartbeatData {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) active_threads: Option<i64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub(crate) capabilities: Vec<String>,
        /// The engine binaries this runner starts, with their versions.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub(crate) engines: Vec<crate::engine::admin::EngineInfo>,
        /// The same e2ee capability object as on register.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) e2ee: Option<E2eeCapability>,
    }

    // -----------------------------------------------------------------------
    // End-to-end encryption (protocol §5.3)
    // -----------------------------------------------------------------------

    /// The `e2ee` capability object (spec §10) sent on register and on every
    /// heartbeat.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct E2eeCapability {
        /// Supported envelope versions.
        pub(crate) versions: Vec<u32>,
        /// Supported MLS suite ids.
        pub(crate) mls_suites: Vec<u32>,
        pub(crate) credential: E2eeCredential,
    }

    impl E2eeCapability {
        /// Envelope version 1, MLS suite 1 and a basic credential over the
        /// base64url Ed25519 identity key.
        pub(crate) fn basic(public_key: String) -> Self {
            Self {
                versions: vec![1],
                mls_suites: vec![1],
                credential: E2eeCredential {
                    kind: "basic".to_owned(),
                    public_key,
                },
            }
        }
    }

    /// The credential of an [`E2eeCapability`].
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct E2eeCredential {
        #[serde(rename = "type")]
        pub(crate) kind: String,
        /// Raw 32-byte Ed25519 public key, base64url without padding.
        pub(crate) public_key: String,
    }

    /// `task_upsert.data.e2ee`: the task is encrypted under `profile_id`, in
    /// the MLS group `group_id` (32 bytes, base64url).
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct TaskE2ee {
        pub(crate) profile_id: String,
        pub(crate) group_id: String,
    }

    /// The sealed form of a mapped field: exactly `{"e2ee": "<base64url>"}`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct SealedValue {
        pub(crate) e2ee: String,
    }

    /// A mapped field value: plaintext, or the sealed form on an encrypted
    /// task. The sealed form is tried first, so a JSON-valued field holding
    /// exactly `{"e2ee": "<string>"}` reads as sealed.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(untagged)]
    pub(crate) enum Sealable<T> {
        Sealed(SealedValue),
        Plain(T),
    }

    impl<T> Sealable<T> {
        /// The plaintext value, `None` when sealed.
        pub(crate) fn as_plain(&self) -> Option<&T> {
            match self {
                Self::Plain(value) => Some(value),
                Self::Sealed(_) => None,
            }
        }

        /// The sealed value, `None` when plaintext.
        pub(crate) fn as_sealed(&self) -> Option<&SealedValue> {
            match self {
                Self::Sealed(value) => Some(value),
                Self::Plain(_) => None,
            }
        }
    }

    impl Sealable<String> {
        /// The text as the agent DB stores it: the plaintext itself, or the
        /// sealed form as JSON.
        pub(crate) fn to_stored(&self) -> String {
            match self {
                Self::Plain(text) => text.clone(),
                Self::Sealed(sealed) => serde_json::json!({ "e2ee": sealed.e2ee }).to_string(),
            }
        }

        /// The mapped value of a stored text: the sealed form when it parses
        /// as one, else the text as a JSON string.
        pub(crate) fn stored_value(stored: &str) -> Value {
            match serde_json::from_str::<SealedValue>(stored) {
                Ok(sealed) => serde_json::json!({ "e2ee": sealed.e2ee }),
                Err(_) => Value::String(stored.to_owned()),
            }
        }

        /// Whether the value holds no runnable text (blank plaintext).
        pub(crate) fn is_blank(&self) -> bool {
            self.as_plain().is_some_and(|text| text.trim().is_empty())
        }
    }

    impl From<String> for Sealable<String> {
        fn from(text: String) -> Self {
            Self::Plain(text)
        }
    }

    impl From<&str> for Sealable<String> {
        fn from(text: &str) -> Self {
            Self::Plain(text.to_owned())
        }
    }

    /// `thread_result.data.encryption_error`: a spec §11 code (kept an open
    /// string), the epoch involved and a short diagnostic. Never carries
    /// plaintext, AAD values or key material.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct EncryptionError {
        pub(crate) code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) epoch: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) message: Option<String>,
    }

    /// `data` of the outbound durable `e2ee_key_packages`: TLS-serialized
    /// KeyPackage `MLSMessage`s, base64url.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct E2eeKeyPackagesData {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) one_time: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) last_resort: Option<String>,
    }

    /// `data` of the inbound live-only `e2ee_key_package_status`: the
    /// runner's pool at the host and the refused KeyPackages of the answered
    /// upload.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct E2eeKeyPackageStatusData {
        /// Unclaimed one-time KeyPackages held by the host.
        pub(crate) one_time: u64,
        /// Whether the host holds a current last-resort KeyPackage.
        pub(crate) last_resort: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub(crate) rejected: Vec<KeyPackageRejection>,
    }

    /// One refused KeyPackage: `index` into the upload's `one_time`, absent
    /// for its `last_resort`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct KeyPackageRejection {
        pub(crate) code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) index: Option<u64>,
    }

    /// `data` of the inbound durable `e2ee_log`: one handshake log entry of
    /// the task's group. Also the entry shape of an `e2ee_response`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct E2eeLogData {
        pub(crate) seq: u64,
        /// `commit`, `proposal`, `key_history` or `key_history_sealed`.
        pub(crate) kind: String,
        pub(crate) epoch: u64,
        /// The entry bytes, base64url.
        pub(crate) message: String,
        /// On `commit` entries: the drop key of epoch `epoch + 1`, base64url.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) drop_public_key: Option<String>,
    }

    /// `data` of the inbound durable `e2ee_welcome`: a Welcome adding the
    /// runner, and the `seq` of its commit.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct E2eeWelcomeData {
        pub(crate) welcome: String,
        pub(crate) seq: u64,
    }

    /// `data` of the outbound live-only `e2ee_request`: one DS operation.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "sent by the group-state catch-up and commit paths"
        )
    )]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case")]
    pub(crate) enum E2eeRequestData {
        Log {
            after_seq: u64,
        },
        LogFromEpoch {
            epoch: u64,
        },
        Link {
            epoch: u64,
        },
        PutLink {
            epoch: u64,
            link: String,
        },
        Commit {
            commit: String,
            drop_public_key: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            epoch_link: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            key_history: Option<Vec<KeyHistoryItem>>,
        },
    }

    /// A key-history entry submitted with a `commit` request.
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "sent by the group-state commit path")
    )]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct KeyHistoryItem {
        pub(crate) kind: String,
        pub(crate) message: String,
    }

    /// `data` of the inbound live-only `e2ee_response`.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "read by the group-state catch-up and commit paths"
        )
    )]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct E2eeResponseData {
        pub(crate) ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) error: Option<DsError>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) entries: Option<Vec<E2eeLogData>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) more: Option<bool>,
        /// The group's current epoch.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) epoch: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) seq: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) link: Option<String>,
    }

    /// A DS rejection (spec §3.8) in an `e2ee_response`.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "read by the group-state catch-up and commit paths"
        )
    )]
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub(crate) struct DsError {
        pub(crate) code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) message: Option<String>,
    }

    /// Live-only host → agent e2ee frames. They bypass the inbox: never
    /// persisted, acked or replayed.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(
        tag = "type",
        rename_all = "snake_case",
        rename_all_fields = "camelCase"
    )]
    pub(crate) enum E2eeLiveFrame {
        /// The runner's KeyPackage pool at the host. `id` is the `outboxId`
        /// of the answered `e2ee_key_packages` upload; absent on the status
        /// sent at socket open and after a claim.
        #[serde(rename = "e2ee_key_package_status")]
        KeyPackageStatus {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            id: Option<String>,
            data: E2eeKeyPackageStatusData,
        },
        /// The answer to the `e2ee_request` with the same `reqId`.
        #[serde(rename = "e2ee_response")]
        Response {
            task_id: String,
            req_id: String,
            data: E2eeResponseData,
        },
    }

    impl E2eeLiveFrame {
        /// Recognize a live-only e2ee frame; anything else is left to the
        /// other inbound paths.
        pub(crate) fn parse(text: &str) -> Option<Self> {
            // Cheap pre-filter so ordinary frames are not parsed twice.
            if !text.contains("e2ee_key_package_status") && !text.contains("e2ee_response") {
                return None;
            }
            serde_json::from_str(text).ok()
        }
    }

    // -----------------------------------------------------------------------
    // Frame enums
    // -----------------------------------------------------------------------

    /// Inbound frames (host → agent). Internally tagged on `type`;
    /// correlation ids (`taskId`/`cronId`/`threadId`) and the delivery `msgId`
    /// ride the envelope, business fields sit under `data`. An unknown `type`
    /// folds into [`InboundFrame::Unknown`] so a newer host's frames are
    /// ignored, not fatal.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(
        tag = "type",
        rename_all = "snake_case",
        rename_all_fields = "camelCase"
    )]
    pub(crate) enum InboundFrame {
        /// Seed or edit a task definition.
        TaskUpsert {
            task_id: String,
            data: TaskUpsertData,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// Remove a task (identity is the envelope `taskId`; no `data`).
        TaskDelete {
            task_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// Seed or edit a cron/trigger under a task.
        CronUpsert {
            task_id: String,
            cron_id: String,
            data: CronUpsertData,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// Remove a cron (identity is the envelope `taskId`/`cronId`; no `data`).
        CronDelete {
            task_id: String,
            cron_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// A user/system message for a task (optionally targeting a live thread).
        Message {
            task_id: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            thread_id: Option<String>,
            data: MessageInData,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// Graceful cancel of the current turn (no kill). An absent `taskId`
        /// interrupts whatever is in flight; a present one scopes the cancel
        /// to that task's run (additive: old hosts omit it).
        Interrupt {
            #[serde(skip_serializing_if = "Option::is_none")]
            task_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// Host requests runner/session shutdown.
        Close {
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// Live config change (opaque overlay; merged by the config layer).
        ConfigUpdate {
            data: Value,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// One handshake log entry of an encrypted task's group.
        E2eeLog {
            task_id: String,
            data: E2eeLogData,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// A Welcome adding the runner to an encrypted task's group.
        E2eeWelcome {
            task_id: String,
            data: E2eeWelcomeData,
            #[serde(skip_serializing_if = "Option::is_none")]
            msg_id: Option<String>,
        },
        /// Host acknowledges receipt of the outbox row `id`.
        Ack { id: String },
        /// Forward-compat catch-all: an unknown `type` deserializes here so a
        /// receiver ignores frames added by a newer peer (additive-within-major).
        #[serde(other)]
        Unknown,
    }

    /// Outbound frames (agent → host). Outbox-backed frames carry an
    /// optional `outboxId`; the acks are sent raw. An unknown `type` folds into
    /// [`OutboundFrame::Unknown`].
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(
        tag = "type",
        rename_all = "snake_case",
        rename_all_fields = "camelCase"
    )]
    pub(crate) enum OutboundFrame {
        /// Terminal outcome of a thread execution (mirror → host `thread_runs`).
        ThreadResult {
            task_id: String,
            thread_id: String,
            data: ThreadResultData,
            #[serde(skip_serializing_if = "Option::is_none")]
            outbox_id: Option<String>,
        },
        /// One ordered transcript event (mirror → host `messages`).
        ThreadMessage {
            task_id: String,
            thread_id: String,
            data: ThreadMessageData,
            #[serde(skip_serializing_if = "Option::is_none")]
            outbox_id: Option<String>,
        },
        /// Local scheduling-ledger summary for a cron (mirror → host `crons`).
        CronState {
            task_id: String,
            cron_id: String,
            data: CronStateData,
            #[serde(skip_serializing_if = "Option::is_none")]
            outbox_id: Option<String>,
        },
        /// Liveness ping (interval from `config.heartbeatIntervalMs`).
        Heartbeat {
            data: HeartbeatData,
            #[serde(skip_serializing_if = "Option::is_none")]
            outbox_id: Option<String>,
        },
        /// Publish KeyPackages to the host's key directory.
        E2eeKeyPackages {
            data: E2eeKeyPackagesData,
            #[serde(skip_serializing_if = "Option::is_none")]
            outbox_id: Option<String>,
        },
        /// One live-only Delivery Service operation on a task's group.
        #[cfg_attr(
            not(test),
            allow(
                dead_code,
                reason = "sent by the group-state catch-up and commit paths"
            )
        )]
        E2eeRequest {
            task_id: String,
            req_id: String,
            data: E2eeRequestData,
        },
        /// Runner durably stored an inbound host frame `msgId`.
        MsgAck { msg_id: String },
        /// Forward-compat catch-all (see [`InboundFrame::Unknown`]).
        #[serde(other)]
        Unknown,
    }

    #[cfg(test)]
    mod tests {
        use serde_json::json;

        use super::{
            AttachmentDescriptor, CronStateData, CronUpsertData, E2eeCapability,
            E2eeKeyPackageStatusData, E2eeKeyPackagesData, E2eeLiveFrame, E2eeLogData,
            E2eeRequestData, E2eeWelcomeData, EncryptionError, EntryKind, HeartbeatData,
            InboundFrame, KeyPackageRejection, MessageInData, MessageKind, OutboundFrame,
            ProvisioningEntry, Sealable, SealedValue, TaskE2ee, TaskUpsertData, ThreadMessageData,
            ThreadResultData, ThreadStatus,
        };

        fn did(n: u32) -> String {
            crate::protocol::test_delivery_id(n)
        }

        fn round_trip_inbound(frame: &InboundFrame) {
            let json = serde_json::to_string(frame).unwrap();
            let back: InboundFrame = serde_json::from_str(&json).unwrap();
            assert_eq!(*frame, back, "inbound round-trip mismatch via {json}");
        }

        fn round_trip_outbound(frame: &OutboundFrame) {
            let json = serde_json::to_string(frame).unwrap();
            let back: OutboundFrame = serde_json::from_str(&json).unwrap();
            assert_eq!(*frame, back, "outbound round-trip mismatch via {json}");
        }

        fn sample_attachment() -> AttachmentDescriptor {
            AttachmentDescriptor {
                id: "a-1".to_owned(),
                name: "in.txt".into(),
                content_type: "text/plain".to_owned(),
                size: 12,
                sha256: "deadbeef".to_owned(),
                reference: "/agent/attachments/a-1".to_owned(),
                direction: Some("inbound".to_owned()),
            }
        }

        #[test]
        fn protocol_version_is_one() {
            assert_eq!(crate::protocol::PROTOCOL_VERSION, 1);
        }

        #[test]
        fn delivery_ids_are_strings_and_integers_are_rejected() {
            let msg_ack: OutboundFrame =
                serde_json::from_value(json!({ "type": "msg_ack", "msgId": did(1) })).unwrap();
            assert_eq!(msg_ack, OutboundFrame::MsgAck { msg_id: did(1) });
            assert!(
                serde_json::from_value::<InboundFrame>(json!({ "type": "close", "msgId": 4 }))
                    .is_err()
            );
            assert!(
                serde_json::from_value::<InboundFrame>(json!({ "type": "ack", "id": 9 })).is_err()
            );
        }

        #[test]
        fn thread_message_splits_envelope_and_data() {
            let frame = OutboundFrame::ThreadMessage {
                task_id: "t-1".to_owned(),
                thread_id: "c-9@1718".to_owned(),
                data: ThreadMessageData {
                    seq: 3,
                    kind: MessageKind::AssistantText,
                    role: Some("assistant".to_owned()),
                    content: Some("hi".to_owned()),
                    tool: None,
                    input: None,
                    output: None,
                    tool_use_id: None,
                    parent_tool_use_id: None,
                },
                outbox_id: Some(did(43)),
            };
            assert_eq!(
                serde_json::to_value(&frame).unwrap(),
                json!({
                    "type": "thread_message",
                    "taskId": "t-1",
                    "threadId": "c-9@1718",
                    "outboxId": did(43),
                    "data": {
                        "seq": 3,
                        "kind": "assistant_text",
                        "role": "assistant",
                        "content": "hi"
                    }
                })
            );
            // Correlation ids never leak into `data`.
            let value = serde_json::to_value(&frame).unwrap();
            assert!(value["data"].get("taskId").is_none());
            assert!(value["data"].get("threadId").is_none());
            round_trip_outbound(&frame);
        }

        #[test]
        fn thread_message_tool_event_round_trips() {
            let frame = OutboundFrame::ThreadMessage {
                task_id: "t-1".to_owned(),
                thread_id: "th-2".to_owned(),
                data: ThreadMessageData {
                    seq: 7,
                    kind: MessageKind::ToolUse,
                    role: None,
                    content: None,
                    tool: Some("bash".to_owned()),
                    input: Some(json!({ "cmd": "ls" })),
                    output: Some(json!({ "code": 0 })),
                    tool_use_id: None,
                    parent_tool_use_id: None,
                },
                outbox_id: None,
            };
            round_trip_outbound(&frame);
        }

        #[test]
        fn thread_result_keeps_business_fields_in_data() {
            let frame = OutboundFrame::ThreadResult {
                task_id: "t-1".to_owned(),
                thread_id: "c-9@1718".to_owned(),
                data: ThreadResultData {
                    status: ThreadStatus::Succeeded,
                    result: Some("done".to_owned()),
                    error: None,
                    failure_reason: None,
                    engine_session_id: Some("sess-7".to_owned()),
                    duration_ms: 1500,
                    final_seq: 9,
                    attachments: Some(vec![sample_attachment()]),
                    encryption_error: None,
                },
                outbox_id: Some(did(1)),
            };
            let value = serde_json::to_value(&frame).unwrap();
            assert_eq!(value["type"], json!("thread_result"));
            assert_eq!(value["taskId"], json!("t-1"));
            assert_eq!(value["threadId"], json!("c-9@1718"));
            // engine_session_id, duration_ms, final_seq are business fields in data.
            assert_eq!(value["data"]["engine_session_id"], json!("sess-7"));
            assert_eq!(value["data"]["duration_ms"], json!(1500));
            assert_eq!(value["data"]["final_seq"], json!(9));
            // Attachment descriptor renames `reference` → `ref` on the wire.
            assert_eq!(
                value["data"]["attachments"][0]["ref"],
                json!("/agent/attachments/a-1")
            );
            round_trip_outbound(&frame);
        }

        #[test]
        fn thread_result_failure_carries_reason_and_drops_session() {
            let frame = OutboundFrame::ThreadResult {
                task_id: "t-1".to_owned(),
                thread_id: "c-9@1718".to_owned(),
                data: ThreadResultData {
                    status: ThreadStatus::Failed,
                    result: None,
                    error: Some("boom".to_owned()),
                    failure_reason: Some("agent.invalid_request".to_owned()),
                    engine_session_id: None,
                    duration_ms: 42,
                    final_seq: 2,
                    attachments: None,
                    encryption_error: None,
                },
                outbox_id: None,
            };
            let value = serde_json::to_value(&frame).unwrap();
            assert_eq!(value["data"]["status"], json!("failed"));
            assert_eq!(
                value["data"]["failure_reason"],
                json!("agent.invalid_request")
            );
            // resume-unsafe failure → no engine_session_id persisted on the wire.
            assert!(value["data"].get("engine_session_id").is_none());
            assert!(value.get("outboxId").is_none());
            round_trip_outbound(&frame);
        }

        #[test]
        fn cron_state_ids_in_envelope_ledger_in_data() {
            let frame = OutboundFrame::CronState {
                task_id: "t-1".to_owned(),
                cron_id: "cr-1".to_owned(),
                data: CronStateData {
                    kind: "schedule".to_owned(),
                    schedule_type: Some("interval".to_owned()),
                    schedule_value: Some("300".to_owned()),
                    continuity: Some("isolated".to_owned()),
                    next_run: Some("2026-06-22T15:00:00Z".to_owned()),
                    status: Some("active".to_owned()),
                    round_count: 5,
                    skipped_count: 1,
                    last_status: Some("dispatched".to_owned()),
                },
                outbox_id: Some(did(2)),
            };
            let value = serde_json::to_value(&frame).unwrap();
            assert_eq!(value["type"], json!("cron_state"));
            assert_eq!(value["taskId"], json!("t-1"));
            assert_eq!(value["cronId"], json!("cr-1"));
            assert_eq!(value["data"]["round_count"], json!(5));
            assert_eq!(value["data"]["skipped_count"], json!(1));
            assert_eq!(value["data"]["last_status"], json!("dispatched"));
            assert!(value["data"].get("cronId").is_none());
            round_trip_outbound(&frame);
        }

        #[test]
        fn heartbeat_and_acks_round_trip() {
            assert_eq!(
                serde_json::to_value(OutboundFrame::Heartbeat {
                    data: HeartbeatData {
                        active_threads: Some(2),
                        capabilities: Vec::new(),
                        engines: Vec::new(),
                        e2ee: None,
                    },
                    outbox_id: None,
                })
                .unwrap(),
                json!({ "type": "heartbeat", "data": { "activeThreads": 2 } })
            );
            assert_eq!(
                serde_json::to_value(OutboundFrame::MsgAck { msg_id: did(5) }).unwrap(),
                json!({ "type": "msg_ack", "msgId": did(5) })
            );
            for frame in [
                OutboundFrame::Heartbeat {
                    data: HeartbeatData {
                        active_threads: None,
                        capabilities: vec!["claude".to_owned(), "sandbox".to_owned()],
                        engines: Vec::new(),
                        e2ee: None,
                    },
                    outbox_id: Some(did(1)),
                },
                OutboundFrame::MsgAck { msg_id: did(5) },
            ] {
                round_trip_outbound(&frame);
            }
        }

        #[test]
        fn heartbeat_carries_the_e2ee_capability() {
            let frame = OutboundFrame::Heartbeat {
                data: HeartbeatData {
                    active_threads: None,
                    capabilities: vec!["claude".to_owned()],
                    engines: Vec::new(),
                    e2ee: Some(E2eeCapability::basic("cGs".to_owned())),
                },
                outbox_id: None,
            };
            assert_eq!(
                serde_json::to_value(&frame).unwrap(),
                json!({
                    "type": "heartbeat",
                    "data": {
                        "capabilities": ["claude"],
                        "e2ee": {
                            "versions": [1],
                            "mls_suites": [1],
                            "credential": { "type": "basic", "public_key": "cGs" }
                        }
                    }
                })
            );
            round_trip_outbound(&frame);
        }

        #[test]
        fn task_upsert_carries_e2ee() {
            let data: TaskUpsertData = serde_json::from_value(json!({
                "name": "secret",
                "e2ee": { "profile_id": "gino.task-content.v1", "group_id": "Z2lk" }
            }))
            .unwrap();
            assert_eq!(
                data.e2ee,
                Some(TaskE2ee {
                    profile_id: "gino.task-content.v1".to_owned(),
                    group_id: "Z2lk".to_owned(),
                })
            );
            let plain: TaskUpsertData = serde_json::from_value(json!({ "name": "x" })).unwrap();
            assert_eq!(plain.e2ee, None);
            assert!(serde_json::to_value(&plain).unwrap().get("e2ee").is_none());
        }

        #[test]
        fn thread_result_carries_encryption_error() {
            let data = ThreadResultData {
                status: ThreadStatus::Failed,
                result: None,
                error: None,
                failure_reason: Some("agent.encryption".to_owned()),
                engine_session_id: None,
                duration_ms: 0,
                final_seq: 0,
                attachments: None,
                encryption_error: Some(EncryptionError {
                    code: "epoch_unknown".to_owned(),
                    epoch: Some(4),
                    message: None,
                }),
            };
            let value = serde_json::to_value(&data).unwrap();
            assert_eq!(
                value["encryption_error"],
                json!({ "code": "epoch_unknown", "epoch": 4 })
            );
            let back: ThreadResultData = serde_json::from_value(value).unwrap();
            assert_eq!(back, data);
            // An unknown future code stays parseable.
            let future: EncryptionError =
                serde_json::from_value(json!({ "code": "future_code", "x": 1 })).unwrap();
            assert_eq!(future.code, "future_code");
        }

        #[test]
        fn sealable_reads_plain_and_sealed_forms() {
            let plain: Sealable<String> = serde_json::from_value(json!("hi")).unwrap();
            assert_eq!(plain.as_plain().map(String::as_str), Some("hi"));
            let sealed: Sealable<String> =
                serde_json::from_value(json!({ "e2ee": "AQID" })).unwrap();
            assert_eq!(
                sealed.as_sealed(),
                Some(&SealedValue {
                    e2ee: "AQID".to_owned()
                })
            );
            assert_eq!(
                serde_json::to_value(&sealed).unwrap(),
                json!({ "e2ee": "AQID" })
            );
            // A JSON-valued field: the exact sealed form is sealed, anything else plain.
            let json_sealed: Sealable<serde_json::Value> =
                serde_json::from_value(json!({ "e2ee": "AQID" })).unwrap();
            assert!(json_sealed.as_sealed().is_some());
            let json_plain: Sealable<serde_json::Value> =
                serde_json::from_value(json!({ "e2ee": "AQID", "cmd": "ls" })).unwrap();
            assert_eq!(
                json_plain.as_plain(),
                Some(&json!({ "e2ee": "AQID", "cmd": "ls" }))
            );
            // A text field rejects a malformed sealed form outright.
            assert!(serde_json::from_value::<Sealable<String>>(json!({ "e2ee": 1 })).is_err());
        }

        #[test]
        fn sealed_text_is_stored_as_its_json_and_read_back() {
            let sealed: Sealable<String> =
                serde_json::from_value(json!({ "e2ee": "AAEC" })).unwrap();
            let stored = sealed.to_stored();
            assert_eq!(stored, r#"{"e2ee":"AAEC"}"#);
            assert_eq!(Sealable::stored_value(&stored), json!({ "e2ee": "AAEC" }));
            assert!(!sealed.is_blank());
            let plain = Sealable::from("hello");
            assert_eq!(plain.to_stored(), "hello");
            assert_eq!(Sealable::stored_value("hello"), json!("hello"));
            assert_eq!(
                Sealable::stored_value(r#"{"e2ee":1}"#),
                json!(r#"{"e2ee":1}"#)
            );
            assert!(Sealable::from("  ").is_blank());
        }

        #[test]
        fn a_sealed_message_parses_with_sealed_text_and_names() {
            let frame: InboundFrame = serde_json::from_value(json!({
                "type": "message",
                "taskId": "t",
                "data": {
                    "text": { "e2ee": "AA" },
                    "attachments": [{
                        "id": "a", "name": { "e2ee": "BB" }, "content_type": "application/octet-stream",
                        "size": 1, "sha256": "00", "ref": "/r"
                    }],
                },
            }))
            .unwrap();
            let InboundFrame::Message { data, .. } = frame else {
                panic!("not a message");
            };
            assert!(data.text.as_sealed().is_some());
            assert!(data.attachments.unwrap()[0].name.as_sealed().is_some());
        }

        #[test]
        fn e2ee_log_and_welcome_are_durable_inbound_frames() {
            let log = InboundFrame::E2eeLog {
                task_id: "t-1".to_owned(),
                data: E2eeLogData {
                    seq: 3,
                    kind: "commit".to_owned(),
                    epoch: 2,
                    message: "bXNn".to_owned(),
                    drop_public_key: Some("ZHBr".to_owned()),
                },
                msg_id: Some(did(7)),
            };
            assert_eq!(
                serde_json::to_value(&log).unwrap(),
                json!({
                    "type": "e2ee_log",
                    "taskId": "t-1",
                    "msgId": did(7),
                    "data": {
                        "seq": 3, "kind": "commit", "epoch": 2,
                        "message": "bXNn", "drop_public_key": "ZHBr"
                    }
                })
            );
            let welcome = InboundFrame::E2eeWelcome {
                task_id: "t-1".to_owned(),
                data: E2eeWelcomeData {
                    welcome: "d2Vs".to_owned(),
                    seq: 2,
                },
                msg_id: Some(did(6)),
            };
            round_trip_inbound(&log);
            round_trip_inbound(&welcome);
            let extra: InboundFrame = serde_json::from_value(json!({
                "type": "e2ee_welcome", "taskId": "t-1", "msgId": did(6),
                "future": 1, "data": { "welcome": "d2Vs", "seq": 2, "future": true }
            }))
            .unwrap();
            assert_eq!(extra, welcome);
        }

        #[test]
        fn e2ee_key_packages_is_an_outbound_frame_without_correlation_ids() {
            let frame = OutboundFrame::E2eeKeyPackages {
                data: E2eeKeyPackagesData {
                    one_time: Some(vec!["a2Ex".to_owned(), "a2Ey".to_owned()]),
                    last_resort: Some("bHI".to_owned()),
                },
                outbox_id: Some(did(9)),
            };
            assert_eq!(
                serde_json::to_value(&frame).unwrap(),
                json!({
                    "type": "e2ee_key_packages",
                    "outboxId": did(9),
                    "data": { "one_time": ["a2Ex", "a2Ey"], "last_resort": "bHI" }
                })
            );
            round_trip_outbound(&frame);
            let only_last_resort = E2eeKeyPackagesData {
                one_time: None,
                last_resort: Some("bHI".to_owned()),
            };
            assert_eq!(
                serde_json::to_value(&only_last_resort).unwrap(),
                json!({ "last_resort": "bHI" })
            );
        }

        #[test]
        fn e2ee_request_ops_serialize_with_their_fields() {
            let frame = OutboundFrame::E2eeRequest {
                task_id: "t-1".to_owned(),
                req_id: "r-1".to_owned(),
                data: E2eeRequestData::Log { after_seq: 4 },
            };
            assert_eq!(
                serde_json::to_value(&frame).unwrap(),
                json!({
                    "type": "e2ee_request", "taskId": "t-1", "reqId": "r-1",
                    "data": { "op": "log", "after_seq": 4 }
                })
            );
            let commit = E2eeRequestData::Commit {
                commit: "Yw".to_owned(),
                drop_public_key: "ZA".to_owned(),
                epoch_link: None,
                key_history: None,
            };
            assert_eq!(
                serde_json::to_value(&commit).unwrap(),
                json!({ "op": "commit", "commit": "Yw", "drop_public_key": "ZA" })
            );
            assert_eq!(
                serde_json::to_value(E2eeRequestData::LogFromEpoch { epoch: 2 }).unwrap(),
                json!({ "op": "log_from_epoch", "epoch": 2 })
            );
            round_trip_outbound(&frame);
        }

        #[test]
        fn e2ee_live_frames_parse_apart_from_durable_ones() {
            let status = E2eeLiveFrame::parse(
                &json!({
                    "type": "e2ee_key_package_status",
                    "id": did(3),
                    "data": {
                        "one_time": 4, "last_resort": false,
                        "rejected": [{ "code": "key_changed", "index": 0 }, { "code": "malformed" }]
                    }
                })
                .to_string(),
            )
            .unwrap();
            assert_eq!(
                status,
                E2eeLiveFrame::KeyPackageStatus {
                    id: Some(did(3)),
                    data: E2eeKeyPackageStatusData {
                        one_time: 4,
                        last_resort: false,
                        rejected: vec![
                            KeyPackageRejection {
                                code: "key_changed".to_owned(),
                                index: Some(0),
                            },
                            KeyPackageRejection {
                                code: "malformed".to_owned(),
                                index: None,
                            },
                        ],
                    },
                }
            );
            let open = E2eeLiveFrame::parse(
                r#"{"type":"e2ee_key_package_status","data":{"one_time":10,"last_resort":true}}"#,
            )
            .unwrap();
            assert!(matches!(
                open,
                E2eeLiveFrame::KeyPackageStatus { id: None, .. }
            ));
            let response = E2eeLiveFrame::parse(
                &json!({
                    "type": "e2ee_response", "taskId": "t-1", "reqId": "r-1",
                    "data": {
                        "ok": true, "more": false, "epoch": 3,
                        "entries": [{ "seq": 1, "kind": "commit", "epoch": 0, "message": "bQ" }]
                    }
                })
                .to_string(),
            )
            .unwrap();
            let E2eeLiveFrame::Response { req_id, data, .. } = response else {
                panic!("expected e2ee_response");
            };
            assert_eq!(req_id, "r-1");
            assert_eq!(data.entries.unwrap()[0].seq, 1);
            // Durable frames, even ones quoting the type name, are not live.
            assert!(
                E2eeLiveFrame::parse(
                    &json!({
                        "type": "message", "taskId": "t", "msgId": did(1),
                        "data": { "text": "e2ee_response" }
                    })
                    .to_string()
                )
                .is_none()
            );
            assert!(E2eeLiveFrame::parse(r#"{"type":"e2ee_log"}"#).is_none());
        }

        #[test]
        fn inbound_message_carries_ids_in_envelope() {
            let frame = InboundFrame::Message {
                task_id: "t-1".to_owned(),
                thread_id: Some("c-9@1718".to_owned()),
                data: MessageInData {
                    text: "hi".into(),
                    attachments: Some(vec![sample_attachment()]),
                },
                msg_id: Some(did(2)),
            };
            assert_eq!(
                serde_json::to_value(&frame).unwrap(),
                json!({
                    "type": "message",
                    "taskId": "t-1",
                    "threadId": "c-9@1718",
                    "msgId": did(2),
                    "data": {
                        "text": "hi",
                        "attachments": [{
                            "id": "a-1",
                            "name": "in.txt",
                            "content_type": "text/plain",
                            "size": 12,
                            "sha256": "deadbeef",
                            "ref": "/agent/attachments/a-1",
                            "direction": "inbound"
                        }]
                    }
                })
            );
            round_trip_inbound(&frame);
        }

        #[test]
        fn inbound_message_omits_absent_thread_id() {
            let frame = InboundFrame::Message {
                task_id: "t-1".to_owned(),
                thread_id: None,
                data: MessageInData {
                    text: "hi".into(),
                    attachments: None,
                },
                msg_id: None,
            };
            assert_eq!(
                serde_json::to_value(&frame).unwrap(),
                json!({ "type": "message", "taskId": "t-1", "data": { "text": "hi" } })
            );
            round_trip_inbound(&frame);
        }

        #[test]
        fn inbound_task_frames_round_trip() {
            let upsert = InboundFrame::TaskUpsert {
                task_id: "t-1".to_owned(),
                data: TaskUpsertData {
                    name: Some("nightly".to_owned()),
                    kind: Some("job".to_owned()),
                    status: Some("active".to_owned()),
                    engine: None,
                    model: None,
                    workdir: None,
                    meta: None,
                    entries: None,
                    e2ee: None,
                },
                msg_id: Some(did(1)),
            };
            assert_eq!(
                serde_json::to_value(&upsert).unwrap(),
                json!({
                    "type": "task_upsert",
                    "taskId": "t-1",
                    "msgId": did(1),
                    "data": { "name": "nightly", "kind": "job", "status": "active" }
                })
            );
            let delete = InboundFrame::TaskDelete {
                task_id: "t-1".to_owned(),
                msg_id: None,
            };
            assert_eq!(
                serde_json::to_value(&delete).unwrap(),
                json!({ "type": "task_delete", "taskId": "t-1" })
            );
            round_trip_inbound(&upsert);
            round_trip_inbound(&delete);
        }

        #[test]
        fn task_upsert_data_parses_provisioning_entries() {
            // A `task_upsert` data payload with `entries` deserializes into
            // `Some(vec![..])` and round-trips through serde unchanged.
            let raw = r#"{
                "name": "build",
                "entries": [
                    { "id": "clauderc", "sha256": "aa", "target": "CLAUDE.md", "kind": "file" },
                    { "id": "demo", "sha256": "bb", "target": ".claude/skills/demo", "kind": "dir" }
                ]
            }"#;
            let data: TaskUpsertData = serde_json::from_str(raw).unwrap();
            assert_eq!(
                data.entries,
                Some(vec![
                    ProvisioningEntry {
                        id: "clauderc".to_owned(),
                        sha256: "aa".to_owned(),
                        target: "CLAUDE.md".to_owned(),
                        kind: EntryKind::File,
                    },
                    ProvisioningEntry {
                        id: "demo".to_owned(),
                        sha256: "bb".to_owned(),
                        target: ".claude/skills/demo".to_owned(),
                        kind: EntryKind::Dir,
                    },
                ])
            );
            let back: TaskUpsertData =
                serde_json::from_str(&serde_json::to_string(&data).unwrap()).unwrap();
            assert_eq!(back, data);
        }

        #[test]
        fn task_upsert_data_without_entries_is_none() {
            // No `entries` key → `None`, and the omitted field is not serialized back.
            let data: TaskUpsertData = serde_json::from_str(r#"{ "name": "build" }"#).unwrap();
            assert_eq!(data.entries, None);
            assert!(
                serde_json::to_value(&data)
                    .unwrap()
                    .get("entries")
                    .is_none()
            );
        }

        #[test]
        fn provisioning_entry_rejects_unknown_kind() {
            let raw = r#"{ "id": "x", "sha256": "aa", "target": "x", "kind": "symlink" }"#;
            assert!(serde_json::from_str::<ProvisioningEntry>(raw).is_err());
        }

        #[test]
        fn provisioning_entry_accepts_host_name_spelling() {
            // The host wire field is `name` (protocol.md §8 `ConfigEntry`);
            // the agent's `id` is an accepted alias, so a real host
            // `config_update` / `task_upsert.entries` payload parses.
            let raw =
                r#"{ "name": "clauderc", "sha256": "aa", "target": "CLAUDE.md", "kind": "file" }"#;
            let entry: ProvisioningEntry = serde_json::from_str(raw).unwrap();
            assert_eq!(entry.id, "clauderc");
        }

        #[test]
        fn inbound_cron_frames_round_trip() {
            let upsert = InboundFrame::CronUpsert {
                task_id: "t-1".to_owned(),
                cron_id: "cr-1".to_owned(),
                data: CronUpsertData {
                    kind: "schedule".to_owned(),
                    prompt: "send the daily digest".into(),
                    schedule_type: Some("cron".to_owned()),
                    schedule_value: Some("0 9 * * *".to_owned()),
                    continuity: "isolated".to_owned(),
                    next_run: Some("2026-06-23T09:00:00Z".to_owned()),
                    status: Some("active".to_owned()),
                },
                msg_id: None,
            };
            assert_eq!(
                serde_json::to_value(&upsert).unwrap(),
                json!({
                    "type": "cron_upsert",
                    "taskId": "t-1",
                    "cronId": "cr-1",
                    "data": {
                        "kind": "schedule",
                        "prompt": "send the daily digest",
                        "schedule_type": "cron",
                        "schedule_value": "0 9 * * *",
                        "continuity": "isolated",
                        "next_run": "2026-06-23T09:00:00Z",
                        "status": "active"
                    }
                })
            );
            let delete = InboundFrame::CronDelete {
                task_id: "t-1".to_owned(),
                cron_id: "cr-1".to_owned(),
                msg_id: Some(did(8)),
            };
            assert_eq!(
                serde_json::to_value(&delete).unwrap(),
                json!({ "type": "cron_delete", "taskId": "t-1", "cronId": "cr-1", "msgId": did(8) })
            );
            round_trip_inbound(&upsert);
            round_trip_inbound(&delete);
        }

        #[test]
        fn inbound_control_frames_round_trip() {
            let config = InboundFrame::ConfigUpdate {
                data: json!({ "engine": { "model": "claude-opus-4-8" } }),
                msg_id: Some(did(3)),
            };
            assert_eq!(
                serde_json::to_value(&config).unwrap(),
                json!({
                    "type": "config_update",
                    "msgId": did(3),
                    "data": { "engine": { "model": "claude-opus-4-8" } }
                })
            );
            assert_eq!(
                serde_json::to_value(InboundFrame::Interrupt {
                    task_id: None,
                    msg_id: None
                })
                .unwrap(),
                json!({ "type": "interrupt" })
            );
            assert_eq!(
                serde_json::to_value(InboundFrame::Ack { id: did(9) }).unwrap(),
                json!({ "type": "ack", "id": did(9) })
            );
            for frame in [
                InboundFrame::Interrupt {
                    task_id: None,
                    msg_id: None,
                },
                InboundFrame::Interrupt {
                    task_id: Some("t-1".to_owned()),
                    msg_id: Some(did(6)),
                },
                InboundFrame::Close {
                    msg_id: Some(did(4)),
                },
                InboundFrame::Close { msg_id: None },
                config,
                InboundFrame::Ack { id: did(9) },
            ] {
                round_trip_inbound(&frame);
            }
        }

        #[test]
        fn interrupt_task_id_is_additive() {
            // Scoped form: envelope `taskId` lands in `task_id`.
            let scoped: InboundFrame =
                serde_json::from_str(r#"{ "type": "interrupt", "taskId": "t-1" }"#).unwrap();
            assert_eq!(
                scoped,
                InboundFrame::Interrupt {
                    task_id: Some("t-1".to_owned()),
                    msg_id: None,
                }
            );
            // Legacy form: an interrupt without `taskId` must still parse.
            let global: InboundFrame = serde_json::from_str(r#"{ "type": "interrupt" }"#).unwrap();
            assert_eq!(
                global,
                InboundFrame::Interrupt {
                    task_id: None,
                    msg_id: None,
                }
            );
        }

        #[test]
        fn unknown_type_is_tolerated() {
            let raw = r#"{ "type": "some_future_frame", "taskId": "t", "data": { "x": 1 } }"#;
            let inbound: InboundFrame = serde_json::from_str(raw).unwrap();
            assert_eq!(inbound, InboundFrame::Unknown);
            let outbound: OutboundFrame = serde_json::from_str(raw).unwrap();
            assert_eq!(outbound, OutboundFrame::Unknown);
        }

        #[test]
        fn unknown_fields_are_ignored() {
            // Extra envelope and extra `data` fields must not break a known frame.
            let raw = r#"{
                "type": "thread_message",
                "taskId": "t-1",
                "threadId": "th-1",
                "outboxId": "01jab3x7k2m4n5p6q7r8s90005",
                "futureEnvelopeField": true,
                "data": { "seq": 1, "kind": "status", "futureDataField": 42 }
            }"#;
            let frame: OutboundFrame = serde_json::from_str(raw).unwrap();
            let OutboundFrame::ThreadMessage { task_id, data, .. } = frame else {
                panic!("expected thread_message, parsed something else");
            };
            assert_eq!(task_id, "t-1");
            assert_eq!(data.seq, 1);
            assert_eq!(data.kind, MessageKind::Status);
        }

        #[test]
        fn sub_agent_attribution_ids_serialize_when_set() {
            let data = ThreadMessageData {
                seq: 11,
                kind: MessageKind::ToolResult,
                role: None,
                content: None,
                tool: Some("Task".to_owned()),
                input: None,
                output: Some(json!({ "content": "done", "is_error": false })),
                tool_use_id: Some("toolu_01".to_owned()),
                parent_tool_use_id: Some("toolu_parent".to_owned()),
            };
            assert_eq!(
                serde_json::to_value(&data).unwrap(),
                json!({
                    "seq": 11,
                    "kind": "tool_result",
                    "tool": "Task",
                    "output": { "content": "done", "is_error": false },
                    "tool_use_id": "toolu_01",
                    "parent_tool_use_id": "toolu_parent"
                })
            );
        }

        #[test]
        fn sub_agent_attribution_ids_are_omitted_when_unset() {
            // Absence is meaningful: no `parent_tool_use_id` == the main agent.
            let data = ThreadMessageData {
                seq: 1,
                kind: MessageKind::AssistantText,
                role: None,
                content: Some("hi".to_owned()),
                tool: None,
                input: None,
                output: None,
                tool_use_id: None,
                parent_tool_use_id: None,
            };
            let value = serde_json::to_value(&data).unwrap();
            assert!(value.get("tool_use_id").is_none());
            assert!(value.get("parent_tool_use_id").is_none());
        }

        #[test]
        fn message_kind_round_trips_known_and_unknown() {
            // Known kind: the snake_case wire name.
            let known: MessageKind = serde_json::from_value(json!("tool_use")).unwrap();
            assert_eq!(known, MessageKind::ToolUse);
            assert_eq!(serde_json::to_value(&known).unwrap(), json!("tool_use"));
            let action: MessageKind = serde_json::from_value(json!("host_action")).unwrap();
            assert_eq!(action, MessageKind::HostAction);
            assert_eq!(serde_json::to_value(&action).unwrap(), json!("host_action"));

            // Unknown kind: stored opaquely (§5) and re-serialized verbatim.
            let unknown: MessageKind = serde_json::from_value(json!("video_frame")).unwrap();
            assert_eq!(unknown, MessageKind::Unknown("video_frame".to_owned()));
            assert_eq!(
                serde_json::to_value(&unknown).unwrap(),
                json!("video_frame")
            );
        }
    }
}
