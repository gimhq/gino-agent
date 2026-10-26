//! The engine abstraction.
//!
//! An [`Engine`] is a backend that runs agent work; a [`Session`] is one
//! conversation driven by that backend. The runner's transport, scheduler and
//! persistence are all engine-agnostic — they speak only the types in this
//! module, never a backend's wire format — so a new backend is added as a fresh
//! [`Engine`] impl without touching anything else.
//!
//! The trait is deliberately the **spawn/events/interrupt** shape the executor
//! actually drives: [`Engine::start_session`] spawns a session process (fresh or
//! resumed, with an optional initial prompt), [`Session::events`] streams its
//! [`EngineEvent`]s to the single `Result`, and [`Session::interrupt`] cancels a
//! turn gracefully. The abandoned turn-append half (an `Input`/`Session::send`
//! design plus a `run_once` one-shot) was removed — every turn starts a session
//! via [`SessionCfg`] (resuming by session id where continuity is wanted), so
//! there is no live-session follow-up delivery to model.
//!
//! ## Object safety
//!
//! Both traits are object-safe so the runner can hold a `Box<dyn Engine>` /
//! `Box<dyn Session>` selected at runtime by `Task.engine`. Native `async fn` in
//! traits is *not* `dyn`-compatible, so the async methods are desugared to boxed
//! futures by [`mod@async_trait`]; [`Session::events`] returns a boxed
//! [`futures_util::stream::BoxStream`] for the same reason. The
//! `object_safe_*` compile-time tests below pin this guarantee.
//!
//! This module is engine-agnostic: the Claude backend lives entirely under
//! [`claude`].

pub(crate) mod admin;
pub(crate) mod claude;
/// The Codex backend: one `codex exec --json` child per turn.
pub(crate) mod codex;
/// The name → backend map the executor dispatches through; a run picks its
/// backend by name, and an unknown name falls back to the default rather than
/// failing.
pub(crate) mod registry;

use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_util::stream::{BoxStream, Stream};
use thiserror::Error;
use tokio::sync::mpsc;

pub(crate) use registry::EngineRegistry;

use crate::memory::AgentMemoryAccess;
use crate::sandbox::{IsolationError, IsolationSpec};

/// Status of a completed engine turn. Engine-agnostic mirror of the host
/// `output` status (`success`/`error`); the wire mapping lives in the transport
/// layer, not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunStatus {
    /// The turn completed normally.
    Success,
    /// The turn ended in an error (engine error, max turns, …).
    Error,
}

/// Structured cause of an errored turn, derived from the backend's structured
/// result fields (Claude's `result.subtype`) — never from the result prose,
/// which is (or quotes) model output and must not drive policy. `None` on an
/// errored [`RunOutcome`] means the backend reported no structured cause the
/// runner recognises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunErrorKind {
    /// The engine hit its own turn/iteration cap (`error_max_turns`).
    MaxTurns,
    /// The engine reported a generic in-run failure (`error_during_execution`)
    /// with no more specific structured cause.
    Execution,
}

/// Severity of an [`EngineEvent::Log`] line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LogLevel {
    /// Verbose, diagnostic detail.
    Debug,
    /// A recoverable concern (e.g. an API retry).
    Warn,
    /// An error the engine surfaced (e.g. the stderr tail of a dead child).
    Error,
}

/// Configuration for a long-lived [`Session`].
#[derive(Clone, Debug, Default)]
pub(crate) struct SessionCfg {
    /// Working directory the engine runs in. Empty means the current directory.
    pub(crate) cwd: PathBuf,
    /// Resume an existing backend session id, or `None` to start fresh.
    pub(crate) resume: Option<String>,
    /// Resume at a specific message id within the resumed session.
    pub(crate) resume_at: Option<String>,
    /// An optional first user message sent right after the handshake.
    pub(crate) initial_prompt: Option<String>,
    /// Per-task model id overriding the backend's configured model for THIS
    /// session (the host's `task_upsert.data.model`). `None` keeps the
    /// engine's own configured model. Read at spawn only — see the
    /// apply-on-next-run note on the Claude backend's `start_session`.
    pub(crate) model: Option<String>,
    /// The task this session runs for, exported to the engine as `GINO_TASK_ID`
    /// so in-engine tooling (e.g. the `gino-agent cron` CLI) can self-reference.
    pub(crate) task_id: Option<String>,
    /// The thread this session runs for, exported as `GINO_THREAD_ID`.
    pub(crate) thread_id: Option<String>,
    /// The thread's work dir; `cwd` lies inside it. Required when sandboxed.
    pub(crate) work_dir: Option<PathBuf>,
    /// The task's isolation override (`tasks.meta.isolation`).
    pub(crate) isolation: Option<IsolationSpec>,
    /// Local agent API access for this run, exported as `GINO_AGENT_SOCK` /
    /// `GINO_AGENT_TOKEN`. `None` exports neither.
    pub(crate) agent_api: Option<AgentApiAccess>,
    /// The task's memory dir on the host, exported as `GINO_MEMORY_DIR`.
    pub(crate) memory_dir: Option<PathBuf>,
    /// The agent memory dir on the host, exported as `GINO_AGENT_MEMORY_DIR`;
    /// `None` when agent memory is off or could not be prepared.
    pub(crate) agent_memory_dir: Option<PathBuf>,
    /// How the engine may use [`Self::agent_memory_dir`]. Read-only is enforced
    /// only by an isolated launch; an unsandboxed engine is merely told.
    pub(crate) agent_memory_access: AgentMemoryAccess,
    /// Host dirs `<work_dir>/conversations` of this task's other threads,
    /// oldest first; an isolated launch with task memory exposes a read-only
    /// snapshot of them.
    pub(crate) task_archives: Vec<PathBuf>,
    /// Cap on the bytes of that snapshot.
    pub(crate) conversations_max_bytes: u64,
}

/// The local agent API socket and the run's token. `Debug` never prints the
/// token.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AgentApiAccess {
    pub(crate) socket: PathBuf,
    pub(crate) token: String,
}

impl std::fmt::Debug for AgentApiAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentApiAccess")
            .field("socket", &self.socket)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The result of a completed turn. Carries the
/// host-output triple `{status, result, newSessionId}` plus an optional error
/// detail; the transport maps this onto an `output` frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunOutcome {
    /// Whether the turn succeeded or errored.
    pub(crate) status: RunStatus,
    /// The assistant's final text, if any.
    pub(crate) result: Option<String>,
    /// The backend session id this turn ran under, for resume/persistence.
    pub(crate) session_id: Option<String>,
    /// Error detail when `status` is [`RunStatus::Error`].
    pub(crate) error: Option<String>,
    /// Structured cause when `status` is [`RunStatus::Error`], if the backend
    /// reported one. This — never `error`/`result` prose — is what failure
    /// classification keys off.
    pub(crate) error_kind: Option<RunErrorKind>,
}

/// An event emitted while a [`Session`] runs. The
/// runner forwards these to the orchestrator (mapping `Result` → `output`, the
/// rest → transcript events and logs) and persists the session id from
/// `SessionStarted`.
///
/// The transcript-carrying variants (`Output`, `Thinking`, `ToolUse`,
/// `ToolResult`) all carry `parent_tool_use_id`: the id of the tool call that
/// produced them. It is `Some` ONLY for events produced inside a SUB-AGENT (the
/// engine's `Task` tool); `None` means the main agent. It is attribution only —
/// it introduces no hierarchy, and `seq` stays one per-thread stream.
///
/// `serde_json::Value` payloads mean this type is `PartialEq` but not `Eq`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EngineEvent {
    /// The backend reported its session id (Claude `system/init`). The consumer
    /// persists this for resume.
    SessionStarted {
        /// The backend session identifier.
        session_id: String,
    },
    /// Streaming assistant output text.
    Output {
        /// A chunk of assistant text.
        text: String,
        /// The sub-agent tool call this text came from, `None` for the main agent.
        parent_tool_use_id: Option<String>,
    },
    /// Streaming assistant reasoning text (an engine `thinking` block).
    Thinking {
        /// A chunk of reasoning text.
        text: String,
        /// The sub-agent tool call this text came from, `None` for the main agent.
        parent_tool_use_id: Option<String>,
    },
    /// The assistant invoked a tool (an engine `tool_use` block).
    ToolUse {
        /// The engine's id for this call, echoed on the matching [`Self::ToolResult`].
        tool_use_id: String,
        /// The tool's name.
        tool: String,
        /// The call's arguments, verbatim.
        input: serde_json::Value,
        /// The sub-agent tool call this call was made inside, `None` for the main agent.
        parent_tool_use_id: Option<String>,
    },
    /// A tool call returned (an engine `tool_result` block).
    ToolResult {
        /// The [`Self::ToolUse`] id this result belongs to.
        tool_use_id: String,
        /// `{content, is_error}` — the block's content verbatim plus its error flag.
        output: serde_json::Value,
        /// The sub-agent tool call this result came from, `None` for the main agent.
        parent_tool_use_id: Option<String>,
    },
    /// The turn completed (Claude `result`).
    Result(RunOutcome),
    /// A diagnostic line (API retries, hook activity, raw assistant traffic).
    Log {
        /// Severity of the line.
        level: LogLevel,
        /// The human-readable message.
        message: String,
    },
}

/// Errors raised by an [`Engine`] or [`Session`].
#[derive(Debug, Error)]
pub(crate) enum EngineError {
    /// The backend process could not be spawned.
    #[error("spawning engine process: {0}")]
    Spawn(#[source] std::io::Error),
    /// A control or input message could not be serialized.
    #[error("serialize engine message: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The backend's stdin/stdout pipe was not available after spawn.
    #[error("engine process is missing its {0} pipe")]
    MissingPipe(&'static str),
    /// The writer task's channel closed, so the session can no longer be driven.
    #[error("engine session is closed")]
    Closed,
    /// The run's isolation could not be resolved or set up.
    #[error("engine isolation: {0}")]
    Isolation(#[from] IsolationError),
}

/// A backend that runs agent work. One implementation per backend; object-safe so
/// the runner can dispatch on `Task.engine` at runtime.
#[async_trait]
pub(crate) trait Engine: Send + Sync {
    /// The backend's stable name (e.g. `"claude"`).
    fn name(&self) -> &'static str;

    /// Open a session (fresh or resumed per [`SessionCfg`]). The returned
    /// [`Session`] stays alive until dropped or interrupted.
    async fn start_session(&self, cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError>;
}

/// A live conversation driven by an [`Engine`]. Object-safe.
#[async_trait]
pub(crate) trait Session: Send + Sync {
    /// Gracefully cancel the current turn without killing the session (the
    /// process stays alive for the next turn).
    async fn interrupt(&self) -> Result<(), EngineError>;

    /// The stream of [`EngineEvent`]s this session produces. The stream ends when
    /// the backend exits. Intended to be consumed once; a second call yields an
    /// empty stream.
    fn events(&self) -> BoxStream<'_, EngineEvent>;
}

/// A [`Stream`] adapter over a session's event receiver, shared by every
/// backend. Yields until the backend's reader task drops its sender (the child
/// exited), then ends.
///
/// Backends pair this with a take-once `Mutex<Option<Receiver>>` behind
/// [`Session::events`]: the first call moves the receiver into an `EventStream`,
/// and a second call yields an empty stream, matching the trait's
/// consume-once contract.
#[derive(Debug)]
pub(crate) struct EventStream {
    rx: mpsc::UnboundedReceiver<EngineEvent>,
}

impl EventStream {
    /// Wrap a session's event receiver.
    pub(crate) fn new(rx: mpsc::UnboundedReceiver<EngineEvent>) -> Self {
        Self { rx }
    }
}

impl Stream for EventStream {
    type Item = EngineEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::{Engine, EngineEvent, LogLevel, Session};

    // Compile-time proof that both traits are object-safe (`dyn`-compatible):
    // if either method were not, these signatures would fail to compile.
    #[allow(dead_code, reason = "compile-time object-safety proof, never called")]
    fn object_safe_engine(_engine: &dyn Engine) {}
    #[allow(dead_code, reason = "compile-time object-safety proof, never called")]
    fn object_safe_session(_session: Box<dyn Session>) {}

    #[test]
    fn engine_event_equality_distinguishes_variants() {
        let a = EngineEvent::SessionStarted {
            session_id: "s".to_owned(),
        };
        let b = EngineEvent::Log {
            level: LogLevel::Warn,
            message: "s".to_owned(),
        };
        assert_ne!(a, b);
        assert_eq!(
            a,
            EngineEvent::SessionStarted {
                session_id: "s".to_owned()
            }
        );
    }
}
