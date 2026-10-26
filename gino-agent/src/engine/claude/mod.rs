//! The Claude [`Engine`]: one long-lived `claude` child driven over
//! the bkd control protocol.
//!
//! [`ClaudeEngine::start_session`] spawns a single `claude -p` child speaking
//! stream-json on stdout and accepting stream-json on stdin, then drives it with
//! two independent tokio tasks so neither side can deadlock the other:
//!
//! * **writer** — drains a channel of stdin lines (user turns + control
//!   responses + control requests) and writes them, one per line.
//! * **reader** — parses each stdout line; [`control`] requests are answered
//!   straight back through the writer (auto-allow under bypass), and every other
//!   line is mapped by [`events`] into an [`EngineEvent`] on the session's stream.
//!
//! The handshake is `initialize` → `set_permission_mode(bypassPermissions)` →
//! first `user` turn. A `result` completes a turn but leaves the process alive, and
//! the CLI may run further turns on its own before it reports `idle`; [`ClaudeSession::interrupt`] cancels a turn gracefully without
//! killing it. The child is configured `kill_on_drop`, so dropping the session
//! tears the process down.

mod control;
mod events;

use std::borrow::Cow;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use uuid::Uuid;

use self::control::ControlAsk;
use self::events::EventMapper;
use crate::config::Config;
use crate::engine::{
    AgentApiAccess, Engine, EngineError, EngineEvent, EventStream, LogLevel, Session, SessionCfg,
};
use crate::memory::{self, AgentMemoryAccess};
use crate::sandbox::vm::VmMonitor;
use crate::sandbox::{self, EngineProcess, IsolationSpec, Launch, LaunchContext, NetExit, Spawned};

/// Everything needed to build the `claude` argv, spawn the child, and resolve its
/// environment. Built from the global [`Config`]
/// via [`ClaudeSettings::from_config`]; tests construct it directly to point at a
/// stub binary.
#[derive(Clone, Debug)]
pub(crate) struct ClaudeSettings {
    /// The `claude` executable to spawn (default `claude` on `PATH`).
    pub(crate) binary: PathBuf,
    /// Path to *this* `gino-agent` binary, used for the `--settings` hooks
    /// (PreCompact `<self_exe> archive`, SessionStart `<self_exe> memory-context`).
    /// `None` omits the flag (e.g. in tests).
    pub(crate) self_exe: Option<PathBuf>,
    /// Model id passed via `--model`.
    pub(crate) model: Option<String>,
    /// Tools passed via `--allowed-tools`.
    pub(crate) allowed_tools: Vec<String>,
    /// Extra directories passed via repeated `--add-dir`.
    pub(crate) add_dirs: Vec<PathBuf>,
    /// Text passed via `--append-system-prompt` (e.g. a global CLAUDE.md).
    pub(crate) append_system_prompt: Option<String>,
    /// Sources joined into `--setting-sources` (default `user,project`).
    pub(crate) setting_sources: Vec<String>,
    /// Turn cap passed via `--max-turns`.
    pub(crate) max_turns: Option<u32>,
    /// Environment variables layered onto the child (engine credentials etc.).
    pub(crate) env: Vec<(String, String)>,
    /// The provisioned engine config dir. When set, the child is
    /// launched with both the generic `ENGINE_CONFIG_DIR` and claude's
    /// `CLAUDE_CONFIG_DIR` pointed here, so it reads the global instruction file +
    /// skills the runner materialized. `None` exports neither (tests / no
    /// provisioning); the runner always sets it to a stable dir.
    pub(crate) config_dir: Option<PathBuf>,
    /// Default isolation (`engine.isolation`); empty means off.
    pub(crate) isolation: IsolationSpec,
    /// A local isolation floor (`GINO_ISOLATION_FILE`) is configured.
    pub(crate) isolation_floored: bool,
    /// The daemon workspace dir, which isolation paths are checked against.
    pub(crate) workspace_dir: PathBuf,
    /// Soft size cap for the task memory dir.
    pub(crate) memory_max_bytes: u64,
}

impl Default for ClaudeSettings {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("claude"),
            self_exe: None,
            model: None,
            allowed_tools: Vec::new(),
            add_dirs: Vec::new(),
            append_system_prompt: None,
            setting_sources: vec!["user".to_owned(), "project".to_owned()],
            max_turns: None,
            env: Vec::new(),
            config_dir: None,
            isolation: IsolationSpec::default(),
            isolation_floored: false,
            workspace_dir: PathBuf::new(),
            memory_max_bytes: memory::DEFAULT_MAX_BYTES,
        }
    }
}

impl ClaudeSettings {
    /// Resolve engine settings from the global [`Config`]: the model and allowed
    /// tools come straight across, and the credential env (`ANTHROPIC_API_KEY` /
    /// `CLAUDE_CODE_OAUTH_TOKEN` / `ANTHROPIC_BASE_URL`) is materialised here at
    /// the secret boundary. `self_exe` defaults to the current executable so the
    /// PreCompact hook resolves to this same binary.
    pub(crate) fn from_config(config: &Config) -> Self {
        let engine = &config.engine;
        // The agent, not the engine, updates the install (`gino-agent engine update`).
        let mut env = vec![("DISABLE_AUTOUPDATER".to_owned(), "1".to_owned())];
        if let Some(key) = &engine.anthropic_api_key {
            env.push((
                "ANTHROPIC_API_KEY".to_owned(),
                key.expose_secret().to_owned(),
            ));
        }
        if let Some(token) = &engine.claude_code_oauth_token {
            env.push((
                "CLAUDE_CODE_OAUTH_TOKEN".to_owned(),
                token.expose_secret().to_owned(),
            ));
        }
        if let Some(url) = &engine.anthropic_base_url {
            env.push(("ANTHROPIC_BASE_URL".to_owned(), url.clone()));
        }
        Self {
            binary: super::admin::resolve_binary(
                &config.paths.workspace_dir,
                super::admin::EngineKind::Claude,
                None,
            ),
            self_exe: std::env::current_exe().ok(),
            model: engine.model.clone(),
            allowed_tools: engine.allowed_tools.clone(),
            env,
            isolation: engine.isolation.clone(),
            isolation_floored: engine.isolation_floor.is_some(),
            workspace_dir: config.paths.workspace_dir.clone(),
            memory_max_bytes: config.memory.max_bytes,
            ..Self::default()
        }
    }
}

/// The session id to start the child under: either a freshly minted id
/// (`--session-id`) or a resume of an existing one (`--resume`).
#[derive(Clone, Debug)]
enum SessionId {
    /// Start a new session with this generated v4 id.
    New(String),
    /// Resume an existing session, optionally at a specific message id.
    Resume {
        /// The session id to resume.
        id: String,
        /// The message id to resume at (`--resume-session-at`).
        at: Option<String>,
    },
}

/// The per-run argument inputs to [`build_args`]: the working directory and how
/// the session id is established.
#[derive(Clone, Debug)]
struct SessionArgs {
    cwd: PathBuf,
    session: SessionId,
    /// The session has a task or agent memory dir, so the SessionStart memory
    /// hook is set.
    memory: bool,
    /// The session has a read-only agent memory dir.
    agent_read_only: bool,
    /// Where Claude's auto memory is redirected (`<memory_dir>/claude`);
    /// `None` switches auto memory off.
    auto_memory_dir: Option<PathBuf>,
}

impl SessionArgs {
    /// Derive the args for a long-lived session: resume when the caller supplied
    /// a session id, otherwise mint a new one.
    fn for_session(cfg: &SessionCfg) -> Self {
        let session = match &cfg.resume {
            Some(id) => SessionId::Resume {
                id: id.clone(),
                at: cfg.resume_at.clone(),
            },
            None => SessionId::New(Uuid::new_v4().to_string()),
        };
        Self {
            cwd: cfg.cwd.clone(),
            session,
            memory: cfg.memory_dir.is_some() || cfg.agent_memory_dir.is_some(),
            agent_read_only: cfg.agent_memory_dir.is_some()
                && cfg.agent_memory_access == AgentMemoryAccess::Ro,
            auto_memory_dir: cfg.memory_dir.as_ref().map(|dir| dir.join("claude")),
        }
    }
}

/// Build the `claude` argv from [`ClaudeSettings`] and the per-run [`SessionArgs`].
/// Pure and order-stable so it is unit-testable.
fn build_args(settings: &ClaudeSettings, session_args: &SessionArgs) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "-p".to_owned(),
        "--output-format".to_owned(),
        "stream-json".to_owned(),
        "--verbose".to_owned(),
        "--no-chrome".to_owned(),
        "--input-format".to_owned(),
        "stream-json".to_owned(),
        "--permission-prompt-tool".to_owned(),
        "stdio".to_owned(),
        "--dangerously-skip-permissions".to_owned(),
    ];

    if let Some(model) = &settings.model {
        argv.push("--model".to_owned());
        argv.push(model.clone());
    }

    match &session_args.session {
        SessionId::New(id) => {
            argv.push("--session-id".to_owned());
            argv.push(id.clone());
        }
        SessionId::Resume { id, at } => {
            argv.push("--resume".to_owned());
            argv.push(id.clone());
            if let Some(at) = at {
                argv.push("--resume-session-at".to_owned());
                argv.push(at.clone());
            }
        }
    }

    for dir in &settings.add_dirs {
        argv.push("--add-dir".to_owned());
        argv.push(dir.display().to_string());
    }

    if let Some(prompt) = &settings.append_system_prompt {
        argv.push("--append-system-prompt".to_owned());
        argv.push(prompt.clone());
    }

    if !settings.setting_sources.is_empty() {
        argv.push("--setting-sources".to_owned());
        argv.push(settings.setting_sources.join(","));
    }

    argv.push("--settings".to_owned());
    argv.push(launch_settings_json(settings, session_args));

    if let Some(max_turns) = settings.max_turns {
        argv.push("--max-turns".to_owned());
        argv.push(max_turns.to_string());
    }

    // Kept last: `--allowed-tools` is variadic, so trailing tool names cannot be
    // mistaken for another flag's value.
    if !settings.allowed_tools.is_empty() {
        argv.push("--allowed-tools".to_owned());
        argv.extend(settings.allowed_tools.iter().cloned());
    }

    argv
}

/// The config-dir environment the child inherits: the provisioned
/// engine config dir exported as both the generic `ENGINE_CONFIG_DIR` (future
/// engines) and claude's own `CLAUDE_CONFIG_DIR`, so the child resolves the
/// runner-materialized global instruction file + skills from there. Empty when
/// `config_dir` is unset. Pure + order-stable so it is unit-testable.
fn config_dir_env(settings: &ClaudeSettings) -> Vec<(&'static str, String)> {
    match &settings.config_dir {
        Some(dir) => {
            let path = dir.display().to_string();
            vec![
                ("ENGINE_CONFIG_DIR", path.clone()),
                ("CLAUDE_CONFIG_DIR", path),
            ]
        }
        None => Vec::new(),
    }
}

/// The `--settings` JSON: the auto memory keys and, when `self_exe` is set,
/// the runner hooks as external commands.
///
/// Auto memory is redirected via `autoMemoryDirectory` to the session's
/// [`SessionArgs::auto_memory_dir`], or switched off with
/// `autoMemoryEnabled: false` when there is none. The hooks are the PreCompact
/// transcript archive (`<self_exe> archive`) and, with a task or agent memory
/// dir, the SessionStart memory context (`<self_exe> memory-context`,
/// `--agent-read-only` for a read-only agent dir) on startup/clear/compact —
/// never on resume.
fn launch_settings_json(settings: &ClaudeSettings, session_args: &SessionArgs) -> String {
    let mut json = match &session_args.auto_memory_dir {
        Some(dir) => json!({ "autoMemoryDirectory": dir.display().to_string() }),
        None => json!({ "autoMemoryEnabled": false }),
    };
    if let Some(hooks) = hook_commands(settings, session_args) {
        json["hooks"] = hooks;
    }
    json.to_string()
}

/// The runner hook registrations of [`launch_settings_json`]; `None` when
/// `self_exe` is unset.
fn hook_commands(
    settings: &ClaudeSettings,
    session_args: &SessionArgs,
) -> Option<serde_json::Value> {
    let exe = settings.self_exe.as_ref()?;
    let archive = format!("{} archive", exe.display());
    let mut hooks = json!({
        "PreCompact": [{ "hooks": [{ "type": "command", "command": archive }] }]
    });
    if session_args.memory {
        let mut context = format!(
            "{} memory-context --max-bytes {}",
            exe.display(),
            settings.memory_max_bytes
        );
        if session_args.agent_read_only {
            context.push_str(" --agent-read-only");
        }
        hooks["SessionStart"] = json!([{
            "matcher": "startup|clear|compact",
            "hooks": [{ "type": "command", "command": context }]
        }]);
    }
    Some(hooks)
}

/// Layer the per-session [`SessionCfg::model`] (the task's `model`) onto
/// the configured settings for ONE spawn: present → it wins over
/// `config.engine.model`, absent → the configured model stands untouched
/// (borrowed, so the common case copies nothing).
///
/// DECISION: APPLY-ON-NEXT-SPAWN. The override is read here, at spawn, and never
/// pushed into a session already running — a live turn keeps the model it was
/// launched with. This is the same policy the `config_update` route applies to
/// engine settings (see `runner::apply_engine_config`), so a task's model change
/// takes effect on its next run rather than mid-turn.
fn effective_settings<'a>(
    settings: &'a ClaudeSettings,
    cfg: &SessionCfg,
) -> Cow<'a, ClaudeSettings> {
    match &cfg.model {
        Some(model) => {
            let mut overridden = settings.clone();
            overridden.model = Some(model.clone());
            Cow::Owned(overridden)
        }
        None => Cow::Borrowed(settings),
    }
}

/// The Claude backend. Holds the resolved [`ClaudeSettings`]; cheap to clone-free
/// share behind a `Box<dyn Engine>`.
#[derive(Clone, Debug)]
pub(crate) struct ClaudeEngine {
    settings: ClaudeSettings,
}

impl ClaudeEngine {
    /// Construct an engine from explicit settings (used by tests and the registry).
    pub(crate) fn new(settings: ClaudeSettings) -> Self {
        Self { settings }
    }
}

#[async_trait]
impl Engine for ClaudeEngine {
    fn name(&self) -> &'static str {
        "claude"
    }

    async fn start_session(&self, cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError> {
        let session_args = SessionArgs::for_session(&cfg);
        let settings = effective_settings(&self.settings, &cfg);
        let session = spawn_session(&settings, &session_args, &cfg).await?;
        Ok(Box::new(session))
    }
}

/// Bounds on the captured stderr tail: enough for a startup/auth error banner,
/// small enough to embed in a failure message.
const STDERR_TAIL_MAX_LINES: usize = 32;
const STDERR_TAIL_MAX_BYTES: usize = 4096;
/// How long the reader waits for the stderr drain to settle after stdout EOF
/// (both pipes close on child exit, so this is only a scheduling grace).
const STDERR_DRAIN_WINDOW: Duration = Duration::from_millis(500);

/// A bounded tail of the child's stderr (audit P3): startup/auth failures die
/// before any stream-json `result`, so their stderr is the only diagnostic.
/// Shared between the drain task (writer) and the failure paths (readers).
#[derive(Clone, Debug, Default)]
struct StderrTail {
    lines: Arc<Mutex<VecDeque<String>>>,
}

impl StderrTail {
    /// Append a line, dropping oldest lines beyond the line/byte bounds.
    fn push(&self, line: String) {
        if let Ok(mut lines) = self.lines.lock() {
            lines.push_back(line);
            while lines.len() > STDERR_TAIL_MAX_LINES
                || lines.iter().map(String::len).sum::<usize>() > STDERR_TAIL_MAX_BYTES
            {
                if lines.pop_front().is_none() {
                    break;
                }
            }
        }
    }

    /// The captured tail joined into one block; `None` when nothing arrived.
    fn snapshot(&self) -> Option<String> {
        let lines = self.lines.lock().ok()?;
        if lines.is_empty() {
            None
        } else {
            Some(
                lines
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
        }
    }
}

/// Makes the CLI emit `system/session_state_changed` lines.
const SESSION_STATE_EVENTS_ENV: &str = "CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS";

/// Switches Claude's auto memory off, including model-initiated memory writes.
const DISABLE_AUTO_MEMORY_ENV: &str = "CLAUDE_CODE_DISABLE_AUTO_MEMORY";

/// Env keys naming the engine config dir.
const CONFIG_DIR_ENV_KEYS: [&str; 2] = ["ENGINE_CONFIG_DIR", "CLAUDE_CONFIG_DIR"];

/// The direct (unisolated) `claude` launch: binary, argv, env and cwd.
///
/// `task_id`/`thread_id` (when present) are exported to the child as
/// `GINO_TASK_ID`/`GINO_THREAD_ID`, and the runner's own path as
/// `GINO_RUNNER_BIN`, so in-engine tooling (the `gino-agent cron` CLI) can
/// self-reference the task and re-invoke the runner without a hard-coded path.
/// An issued agent API token is exported as `GINO_AGENT_SOCK`/`GINO_AGENT_TOKEN`,
/// the task's memory dir as `GINO_MEMORY_DIR`, and the agent memory dir as
/// `GINO_AGENT_MEMORY_DIR`. Without a redirected auto memory dir,
/// `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` switches Claude's auto memory off.
fn direct_launch(
    settings: &ClaudeSettings,
    session_args: &SessionArgs,
    task_id: Option<&str>,
    thread_id: Option<&str>,
    agent_api: Option<&AgentApiAccess>,
    memory_dir: Option<&Path>,
    agent_memory_dir: Option<&Path>,
) -> Launch {
    let mut env: Vec<(String, OsString)> = settings
        .env
        .iter()
        .map(|(key, value)| (key.clone(), value.into()))
        .collect();
    // The provisioned engine config dir — both the generic var and
    // claude's own, so the child reads the global instruction file + skills.
    env.extend(
        config_dir_env(settings)
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.into())),
    );
    // In-engine self-reference (used by the `gino-agent cron` skill/CLI).
    if let Some(exe) = &settings.self_exe {
        env.push(("GINO_RUNNER_BIN".to_owned(), exe.into()));
    }
    if let Some(task_id) = task_id {
        env.push(("GINO_TASK_ID".to_owned(), task_id.into()));
    }
    if let Some(thread_id) = thread_id {
        env.push(("GINO_THREAD_ID".to_owned(), thread_id.into()));
    }
    if let Some(api) = agent_api {
        env.push(("GINO_AGENT_SOCK".to_owned(), api.socket.clone().into()));
        env.push(("GINO_AGENT_TOKEN".to_owned(), api.token.clone().into()));
    }
    if let Some(dir) = memory_dir {
        env.push(("GINO_MEMORY_DIR".to_owned(), dir.into()));
    }
    if let Some(dir) = agent_memory_dir {
        env.push(("GINO_AGENT_MEMORY_DIR".to_owned(), dir.into()));
    }
    if session_args.auto_memory_dir.is_none() {
        env.push((DISABLE_AUTO_MEMORY_ENV.to_owned(), "1".into()));
    }
    // Ask for `session_state_changed`, whose `idle` marks the end of the run.
    env.push((SESSION_STATE_EVENTS_ENV.to_owned(), "1".into()));
    Launch::direct(
        settings.binary.clone(),
        build_args(settings, session_args),
        env,
        session_args.cwd.clone(),
    )
}

/// The isolation inputs for one spawn.
fn launch_context<'a>(settings: &'a ClaudeSettings, cfg: &'a SessionCfg) -> LaunchContext<'a> {
    LaunchContext {
        isolation: &settings.isolation,
        task_override: cfg.isolation.as_ref(),
        workspace_dir: &settings.workspace_dir,
        task_id: cfg.task_id.as_deref(),
        thread_id: cfg.thread_id.as_deref(),
        work_dir: cfg.work_dir.as_deref(),
        memory_dir: cfg.memory_dir.as_deref(),
        agent_memory_dir: cfg.agent_memory_dir.as_deref(),
        agent_memory_access: cfg.agent_memory_access,
        task_archives: &cfg.task_archives,
        conversations_max_bytes: cfg.conversations_max_bytes,
        self_exe: settings.self_exe.as_deref(),
        global_config_dir: settings.config_dir.as_deref(),
        config_dir_keys: &CONFIG_DIR_ENV_KEYS,
        floored: settings.isolation_floored,
    }
}

/// Spawn the `claude` child (directly or sandboxed, per the run's isolation),
/// wire the reader/writer tasks, and perform the handshake. Returns the live
/// [`ClaudeSession`].
async fn spawn_session(
    settings: &ClaudeSettings,
    session_args: &SessionArgs,
    cfg: &SessionCfg,
) -> Result<ClaudeSession, EngineError> {
    let launch = sandbox::launch(
        direct_launch(
            settings,
            session_args,
            cfg.task_id.as_deref(),
            cfg.thread_id.as_deref(),
            cfg.agent_api.as_ref(),
            cfg.memory_dir.as_deref(),
            cfg.agent_memory_dir.as_deref(),
        ),
        &launch_context(settings, cfg),
    )?;
    // Stderr is captured (audit P3): a child that dies at startup (bad binary
    // args, auth failure) writes its reason to stderr only — the bounded tail
    // is folded into the failure diagnostics instead of vanishing into the
    // daemon's inherited stderr.
    let initial_prompt = cfg.initial_prompt.as_deref();
    let Spawned {
        process,
        stdin,
        stdout,
        stderr,
        net,
    } = sandbox::spawn(launch).await?;

    let (writer_tx, writer_rx) = mpsc::unbounded_channel::<String>();
    let (events_tx, events_rx) = mpsc::unbounded_channel::<EngineEvent>();

    let stderr_tail = StderrTail::default();
    let stderr_handle = tokio::spawn(stderr_task(stderr, stderr_tail.clone()));
    let writer_handle = tokio::spawn(writer_task(stdin, writer_rx));
    let reader_handle = tokio::spawn(reader_task(
        stdout,
        events_tx,
        writer_tx.clone(),
        stderr_handle,
        stderr_tail,
        process.vm_monitor(),
    ));

    // Handshake: initialize → bypass mode → optional first user turn. These are
    // queued on the single writer channel so the child receives them in order.
    writer_tx
        .send(control::initialize_line(None)?)
        .map_err(|_| EngineError::Closed)?;
    writer_tx
        .send(control::set_bypass_mode_line()?)
        .map_err(|_| EngineError::Closed)?;
    if let Some(prompt) = initial_prompt {
        writer_tx
            .send(control::user_message_line(prompt)?)
            .map_err(|_| EngineError::Closed)?;
    }

    Ok(ClaudeSession {
        writer: writer_tx,
        events: Mutex::new(Some(events_rx)),
        child: Mutex::new(Some(process)),
        tasks: vec![writer_handle, reader_handle],
        _net: net,
    })
}

/// Drain the child's stderr into the bounded tail. Ends on EOF (child exited)
/// or a read error; each line is also traced for live debugging.
async fn stderr_task(stderr: ChildStderr, tail: StderrTail) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        debug!(line = %line, "engine stderr");
        tail.push(line);
    }
}

/// Drive the child's stdin: write each queued line, newline-framed and flushed.
/// When the channel closes (session dropped, reader gone), shut stdin to signal
/// EOF so a still-running child exits.
async fn writer_task(mut stdin: ChildStdin, mut rx: mpsc::UnboundedReceiver<String>) {
    while let Some(line) = rx.recv().await {
        if let Err(err) = write_line(&mut stdin, &line).await {
            warn!(error = %err, "engine stdin write failed; stopping writer");
            return;
        }
    }
    if let Err(err) = stdin.shutdown().await {
        debug!(error = %err, "closing engine stdin");
    }
}

async fn write_line(stdin: &mut ChildStdin, line: &str) -> std::io::Result<()> {
    stdin.write_all(line.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await
}

/// Parse the child's stdout line by line: answer control requests through
/// `writer`, forward mapped events on `events`. Ends on EOF (child exited),
/// dropping both senders to wind the session down. On EOF the captured stderr
/// tail is surfaced as a final error log event (audit P3): a child that died
/// before its `result` (startup/auth failure) has stderr as its only diagnostic.
/// A VM run that ended without reporting the engine's exit adds the runner-side
/// reason.
async fn reader_task(
    stdout: ChildStdout,
    events: mpsc::UnboundedSender<EngineEvent>,
    writer: mpsc::UnboundedSender<String>,
    stderr_drain: JoinHandle<()>,
    stderr_tail: StderrTail,
    vm: Option<VmMonitor>,
) {
    let mut mapper = EventMapper::default();
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                handle_line(&line, &mut mapper, &events, &writer);
            }
            Ok(None) => {
                if let Some(event) = mapper.finish() {
                    let _ = events.send(event);
                }
                // Child exited: stderr hits EOF too — give its drain a grace
                // window so the tail is complete before it is surfaced.
                let _ = tokio::time::timeout(STDERR_DRAIN_WINDOW, stderr_drain).await;
                if let Some(tail) = stderr_tail.snapshot() {
                    let _ = events.send(EngineEvent::Log {
                        level: LogLevel::Error,
                        message: format!("engine stderr tail:\n{tail}"),
                    });
                }
                if let Some(vm) = &vm
                    && let Some(reason) = vm.failure().await
                {
                    let _ = events.send(EngineEvent::Log {
                        level: LogLevel::Error,
                        message: reason,
                    });
                }
                return;
            }
            Err(err) => {
                warn!(error = %err, "engine stdout read failed; stopping reader");
                return;
            }
        }
    }
}

/// Classify one stdout line and act: control requests are auto-answered, control
/// responses are logged, everything else is mapped to its [`EngineEvent`]s and
/// sent in stream order.
fn handle_line(
    line: &str,
    mapper: &mut EventMapper,
    events: &mpsc::UnboundedSender<EngineEvent>,
    writer: &mpsc::UnboundedSender<String>,
) {
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(err) => {
            warn!(error = %err, "skipping non-JSON engine stdout line");
            return;
        }
    };

    match control::message_type(&value) {
        control::TYPE_CONTROL_REQUEST => answer_control(&value, writer),
        control::TYPE_CONTROL_RESPONSE => trace!("control_response from engine"),
        _ => {
            for event in mapper.map_line(&value) {
                // The receiver lives as long as the session; a send failure just
                // means the consumer dropped the stream — nothing to recover.
                let _ = events.send(event);
            }
        }
    }
}

/// Answer an inbound control request under the bypass-everything policy and queue
/// the response on the writer channel.
fn answer_control(value: &Value, writer: &mpsc::UnboundedSender<String>) {
    let Some((request_id, ask)) = control::classify(value) else {
        warn!("control_request without a request_id; dropping");
        return;
    };
    match &ask {
        ControlAsk::CanUseTool { tool_name, .. } => {
            debug!(%tool_name, %request_id, "auto-allowing tool");
        }
        ControlAsk::HookCallback { callback_id } => {
            debug!(%callback_id, %request_id, "auto-approving hook");
        }
        ControlAsk::Unknown { subtype } => {
            warn!(%subtype, %request_id, "unknown control request; replying with error");
        }
    }
    match control::auto_response_line(&request_id, &ask) {
        Ok(line) => {
            let _ = writer.send(line);
        }
        Err(err) => warn!(error = %err, "failed to build control response"),
    }
}

/// A live Claude conversation. Holds the writer channel, the (one-shot) event
/// receiver, the engine process (killed or stopped on drop), and the
/// reader/writer task handles (aborted on drop).
#[derive(Debug)]
pub(crate) struct ClaudeSession {
    writer: mpsc::UnboundedSender<String>,
    events: Mutex<Option<mpsc::UnboundedReceiver<EngineEvent>>>,
    child: Mutex<Option<EngineProcess>>,
    tasks: Vec<JoinHandle<()>>,
    /// Allowlist network exit; stops when the session is dropped.
    _net: Option<NetExit>,
}

#[async_trait]
impl Session for ClaudeSession {
    async fn interrupt(&self) -> Result<(), EngineError> {
        let line = control::interrupt_line()?;
        self.writer.send(line).map_err(|_| EngineError::Closed)
    }

    fn events(&self) -> BoxStream<'_, EngineEvent> {
        let taken = self.events.lock().ok().and_then(|mut guard| guard.take());
        match taken {
            Some(rx) => Box::pin(EventStream::new(rx)),
            None => Box::pin(futures_util::stream::empty::<EngineEvent>()),
        }
    }
}

impl Drop for ClaudeSession {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // Dropping the process kills the child or stops the VM.
        if let Ok(mut guard) = self.child.lock() {
            drop(guard.take());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::{
        ClaudeEngine, ClaudeSettings, SessionArgs, SessionId, build_args, config_dir_env,
        direct_launch, effective_settings, launch_context,
    };
    use crate::config::{Config, ConfigOverlay};
    use crate::engine::{AgentApiAccess, Engine, EngineError, SessionCfg};
    use crate::memory::AgentMemoryAccess;
    use crate::sandbox::{self, IsolationSpec, Launch, SandboxHost};
    use serde_json::json;

    #[test]
    fn from_config_prefers_the_managed_install_and_disables_self_updates() {
        let ws = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.paths.workspace_dir = ws.path().to_path_buf();
        let settings = ClaudeSettings::from_config(&config);
        assert_eq!(settings.binary, Path::new("claude"));
        assert!(
            settings
                .env
                .contains(&("DISABLE_AUTOUPDATER".to_owned(), "1".to_owned()))
        );
        let managed = ws.path().join("engines/home/.local/bin/claude");
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::write(&managed, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(ClaudeSettings::from_config(&config).binary, managed);
    }

    fn env_of<'a>(launch: &'a Launch, key: &str) -> Vec<&'a OsString> {
        launch
            .env
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v)
            .collect()
    }

    fn os_args(args: Vec<String>) -> Vec<std::ffi::OsString> {
        args.into_iter().map(Into::into).collect()
    }

    fn sandbox_spec() -> IsolationSpec {
        IsolationSpec {
            mode: Some("sandbox".to_owned()),
            ..IsolationSpec::default()
        }
    }

    #[test]
    fn from_config_carries_isolation_and_workspace_dir() {
        let mut config = Config::default();
        config.apply(
            ConfigOverlay::from_json(r#"{ "engine": { "isolation": { "mode": "sandbox" } } }"#)
                .unwrap(),
        );
        let settings = ClaudeSettings::from_config(&config);
        assert_eq!(settings.isolation, sandbox_spec());
        assert_eq!(settings.workspace_dir, config.paths.workspace_dir);

        let settings = ClaudeSettings::from_config(&Config::default());
        assert_eq!(settings.isolation, IsolationSpec::default());
        assert_eq!(
            settings.workspace_dir,
            Config::default().paths.workspace_dir
        );
    }

    #[test]
    fn from_config_carries_memory_max_bytes() {
        let mut config = Config::default();
        config.memory.max_bytes = 2048;
        assert_eq!(ClaudeSettings::from_config(&config).memory_max_bytes, 2048);
        assert_eq!(
            ClaudeSettings::default().memory_max_bytes,
            crate::memory::DEFAULT_MAX_BYTES
        );
    }

    #[test]
    fn off_launch_is_the_direct_spawn() {
        let settings = ClaudeSettings {
            self_exe: Some("/app/gino-agent".into()),
            env: vec![("ANTHROPIC_API_KEY".to_owned(), "k".to_owned())],
            config_dir: Some("/ws/engine-config".into()),
            ..ClaudeSettings::default()
        };
        let cfg = SessionCfg {
            cwd: "/ws/threads/t1/project".into(),
            work_dir: Some("/ws/threads/t1".into()),
            ..SessionCfg::default()
        };
        let args = SessionArgs::for_session(&cfg);
        let direct = direct_launch(
            &settings,
            &args,
            Some("task-1"),
            Some("th-1"),
            None,
            None,
            None,
        );
        assert_eq!(direct.program, Path::new("claude"));
        assert_eq!(direct.cwd, cfg.cwd);
        assert_eq!(direct.args, os_args(build_args(&settings, &args)));
        let env: Vec<(&str, &str)> = direct
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            env,
            [
                ("ANTHROPIC_API_KEY", "k"),
                ("ENGINE_CONFIG_DIR", "/ws/engine-config"),
                ("CLAUDE_CONFIG_DIR", "/ws/engine-config"),
                ("GINO_RUNNER_BIN", "/app/gino-agent"),
                ("GINO_TASK_ID", "task-1"),
                ("GINO_THREAD_ID", "th-1"),
                ("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1"),
                ("CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS", "1"),
            ]
        );
        let launched = sandbox::launch(direct.clone(), &launch_context(&settings, &cfg)).unwrap();
        assert_eq!(launched, direct);
    }

    #[test]
    fn an_issued_agent_api_token_is_exported_next_to_the_thread_id() {
        let settings = ClaudeSettings::default();
        let cfg = SessionCfg {
            memory_dir: Some("/ws/memory/task/task-1".into()),
            ..SessionCfg::default()
        };
        let args = SessionArgs::for_session(&cfg);
        let api = AgentApiAccess {
            socket: "/ws/run/agent.sock".into(),
            token: "tok".to_owned(),
        };
        let direct = direct_launch(
            &settings,
            &args,
            Some("task-1"),
            Some("th-1"),
            Some(&api),
            Some(Path::new("/ws/memory/task/task-1")),
            Some(Path::new("/ws/memory/agent")),
        );
        let env: Vec<(&str, &str)> = direct
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            env,
            [
                ("GINO_TASK_ID", "task-1"),
                ("GINO_THREAD_ID", "th-1"),
                ("GINO_AGENT_SOCK", "/ws/run/agent.sock"),
                ("GINO_AGENT_TOKEN", "tok"),
                ("GINO_MEMORY_DIR", "/ws/memory/task/task-1"),
                ("GINO_AGENT_MEMORY_DIR", "/ws/memory/agent"),
                ("CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS", "1"),
            ]
        );
    }

    #[test]
    fn sandboxed_launch_points_the_claude_config_at_the_engine_home() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let binary = root.join("claude");
        std::fs::write(&binary, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let work_dir = root.join("threads/t1");
        let settings = ClaudeSettings {
            binary: binary.clone(),
            self_exe: Some("/opt/gino/gino-agent".into()),
            config_dir: Some(root.join("engine-config")),
            isolation: sandbox_spec(),
            workspace_dir: root.clone(),
            ..ClaudeSettings::default()
        };
        let cfg = SessionCfg {
            cwd: work_dir.join("project"),
            work_dir: Some(work_dir.clone()),
            memory_dir: Some(root.join("memory/task-1")),
            ..SessionCfg::default()
        };
        let args = SessionArgs::for_session(&cfg);
        let isolation = sandbox::resolve(
            &settings.isolation,
            None,
            &root,
            sandbox::LlmBaseUrl::default(),
        )
        .unwrap();
        let wrapped = sandbox::wrap(
            direct_launch(&settings, &args, Some("task-1"), None, None, None, None),
            &launch_context(&settings, &cfg),
            &isolation,
            &SandboxHost::fixture(None),
        )
        .unwrap();

        assert!(wrapped.sandboxed);
        let boundary = wrapped
            .args
            .iter()
            .position(|a| a == "sandbox-init")
            .unwrap();
        assert_eq!(wrapped.args[boundary - 1], "/opt/gino/gino-agent");
        assert_eq!(wrapped.args[boundary + 1], "--");
        assert_eq!(wrapped.args[boundary + 2], binary.as_os_str());
        let engine_args = SessionArgs {
            auto_memory_dir: Some("/run/gino/memory/task/claude".into()),
            ..args.clone()
        };
        assert_eq!(
            wrapped.args[boundary + 3..],
            os_args(build_args(&settings, &engine_args))[..]
        );
        let host_memory = root.join("memory/task-1");
        assert!(
            !wrapped.args[boundary + 3..]
                .iter()
                .any(|a| a.to_str().unwrap().contains(host_memory.to_str().unwrap()))
        );
        let hook = wrapped.args.iter().position(|a| a == "--settings").unwrap();
        assert!(
            wrapped.args[hook + 1]
                .to_str()
                .unwrap()
                .contains("/opt/gino/gino-agent archive")
        );
        assert!(
            wrapped.args[hook + 1]
                .to_str()
                .unwrap()
                .contains("/opt/gino/gino-agent memory-context --max-bytes")
        );

        let home = work_dir.join(".engine-home");
        assert_eq!(env_of(&wrapped, "ENGINE_CONFIG_DIR"), [home.as_os_str()]);
        assert_eq!(env_of(&wrapped, "CLAUDE_CONFIG_DIR"), [home.as_os_str()]);
        assert_eq!(
            env_of(&wrapped, "GINO_RUNNER_BIN"),
            ["/opt/gino/gino-agent"]
        );
        assert_eq!(env_of(&wrapped, "GINO_TASK_ID"), ["task-1"]);
        assert_eq!(env_of(&wrapped, "GINO_SANDBOX"), ["1"]);
        assert_eq!(
            env_of(&wrapped, "GINO_ARCHIVE_DIR"),
            [work_dir.join("conversations").as_os_str()]
        );
    }

    #[tokio::test]
    async fn invalid_isolation_fails_before_spawning() {
        for (default, task) in [
            (
                IsolationSpec {
                    mode: Some("vm".to_owned()),
                    ..IsolationSpec::default()
                },
                None,
            ),
            (
                IsolationSpec::default(),
                Some(IsolationSpec {
                    mode: Some("jail".to_owned()),
                    ..IsolationSpec::default()
                }),
            ),
        ] {
            let engine = ClaudeEngine::new(ClaudeSettings {
                binary: PathBuf::from("/nonexistent/claude"),
                isolation: default,
                ..ClaudeSettings::default()
            });
            let err = engine
                .start_session(SessionCfg {
                    isolation: task,
                    ..SessionCfg::default()
                })
                .await
                .err()
                .unwrap();
            assert!(matches!(err, EngineError::Isolation(_)), "{err:?}");
        }
    }

    fn args_with(session: SessionId) -> SessionArgs {
        SessionArgs {
            cwd: std::path::PathBuf::new(),
            session,
            memory: false,
            agent_read_only: false,
            auto_memory_dir: None,
        }
    }

    #[test]
    fn build_args_has_the_mandatory_print_mode_prefix() {
        let argv = build_args(
            &ClaudeSettings::default(),
            &args_with(SessionId::New("sess-1".to_owned())),
        );
        // The fixed stream-json / control-protocol flags, in order.
        let head = &argv[..10];
        assert_eq!(
            head,
            [
                "-p",
                "--output-format",
                "stream-json",
                "--verbose",
                "--no-chrome",
                "--input-format",
                "stream-json",
                "--permission-prompt-tool",
                "stdio",
                "--dangerously-skip-permissions",
            ]
        );
    }

    #[test]
    fn new_session_uses_session_id_flag() {
        let argv = build_args(
            &ClaudeSettings::default(),
            &args_with(SessionId::New("sess-1".to_owned())),
        );
        let pos = argv.iter().position(|a| a == "--session-id").unwrap();
        assert_eq!(argv[pos + 1], "sess-1");
        assert!(!argv.iter().any(|a| a == "--resume"));
        // Default settings still join the setting sources.
        let sources = argv.iter().position(|a| a == "--setting-sources").unwrap();
        assert_eq!(argv[sources + 1], "user,project");
    }

    #[test]
    fn resume_session_uses_resume_flags() {
        let argv = build_args(
            &ClaudeSettings::default(),
            &args_with(SessionId::Resume {
                id: "sess-prev".to_owned(),
                at: Some("msg-7".to_owned()),
            }),
        );
        let resume = argv.iter().position(|a| a == "--resume").unwrap();
        assert_eq!(argv[resume + 1], "sess-prev");
        let at = argv
            .iter()
            .position(|a| a == "--resume-session-at")
            .unwrap();
        assert_eq!(argv[at + 1], "msg-7");
        assert!(!argv.iter().any(|a| a == "--session-id"));
    }

    #[test]
    fn resume_without_message_id_omits_resume_session_at() {
        let argv = build_args(
            &ClaudeSettings::default(),
            &args_with(SessionId::Resume {
                id: "sess-prev".to_owned(),
                at: None,
            }),
        );
        assert!(!argv.iter().any(|a| a == "--resume-session-at"));
    }

    #[test]
    fn optional_settings_render_model_dirs_tools_and_hooks() {
        let settings = ClaudeSettings {
            self_exe: Some(std::path::PathBuf::from("/app/gino-agent")),
            model: Some("claude-opus-4-8".to_owned()),
            allowed_tools: vec!["Bash".to_owned(), "Read".to_owned()],
            add_dirs: vec![std::path::PathBuf::from("/workspace/extra/a")],
            append_system_prompt: Some("be terse".to_owned()),
            max_turns: Some(10),
            ..ClaudeSettings::default()
        };
        let argv = build_args(&settings, &args_with(SessionId::New("s".to_owned())));

        let model = argv.iter().position(|a| a == "--model").unwrap();
        assert_eq!(argv[model + 1], "claude-opus-4-8");

        let dir = argv.iter().position(|a| a == "--add-dir").unwrap();
        assert_eq!(argv[dir + 1], "/workspace/extra/a");

        let sys = argv
            .iter()
            .position(|a| a == "--append-system-prompt")
            .unwrap();
        assert_eq!(argv[sys + 1], "be terse");

        let turns = argv.iter().position(|a| a == "--max-turns").unwrap();
        assert_eq!(argv[turns + 1], "10");

        // `--settings` carries the PreCompact archive hook pointing back at us.
        let settings_pos = argv.iter().position(|a| a == "--settings").unwrap();
        assert!(argv[settings_pos + 1].contains("PreCompact"));
        assert!(argv[settings_pos + 1].contains("/app/gino-agent archive"));

        // `--allowed-tools` is last, with the tools trailing it.
        let tools = argv.iter().position(|a| a == "--allowed-tools").unwrap();
        assert_eq!(&argv[tools + 1..], ["Bash", "Read"]);
    }

    /// D2: the per-task `model` on the session config wins over the
    /// configured `config.engine.model` for that spawn's `--model`, and a
    /// session without one leaves the configured model in place.
    #[test]
    fn session_model_overrides_the_configured_model_in_argv() {
        let settings = ClaudeSettings {
            model: Some("claude-sonnet-4-6".to_owned()),
            ..ClaudeSettings::default()
        };
        let model_flag = |cfg: &SessionCfg| {
            let effective = effective_settings(&settings, cfg);
            let argv = build_args(&effective, &args_with(SessionId::New("s".to_owned())));
            let at = argv.iter().position(|a| a == "--model").unwrap();
            argv[at + 1].clone()
        };

        assert_eq!(
            model_flag(&SessionCfg::default()),
            "claude-sonnet-4-6",
            "no per-task model → the configured one stands"
        );
        assert_eq!(
            model_flag(&SessionCfg {
                model: Some("claude-opus-4-8".to_owned()),
                ..SessionCfg::default()
            }),
            "claude-opus-4-8",
            "a per-task model overrides the configured one"
        );
    }

    /// The parsed `--settings` JSON of `argv`.
    fn settings_json(argv: &[String]) -> serde_json::Value {
        let at = argv.iter().position(|a| a == "--settings").unwrap();
        serde_json::from_str(&argv[at + 1]).unwrap()
    }

    fn memory_cfg(resume: Option<&str>) -> SessionCfg {
        SessionCfg {
            resume: resume.map(str::to_owned),
            memory_dir: Some("/ws/memory/task-1".into()),
            ..SessionCfg::default()
        }
    }

    fn hook_settings() -> ClaudeSettings {
        ClaudeSettings {
            self_exe: Some("/app/gino-agent".into()),
            memory_max_bytes: 4096,
            ..ClaudeSettings::default()
        }
    }

    #[test]
    fn memory_session_registers_the_session_start_memory_hook() {
        let argv = build_args(
            &hook_settings(),
            &SessionArgs::for_session(&memory_cfg(None)),
        );
        let json = settings_json(&argv);

        assert_eq!(
            json["hooks"]["PreCompact"][0]["hooks"][0]["command"],
            "/app/gino-agent archive"
        );
        let start = &json["hooks"]["SessionStart"][0];
        assert_eq!(start["matcher"], "startup|clear|compact");
        assert_eq!(start["hooks"][0]["type"], "command");
        assert_eq!(
            start["hooks"][0]["command"],
            "/app/gino-agent memory-context --max-bytes 4096"
        );
    }

    /// The SessionStart command of a session built from `cfg`, if any.
    fn session_start_command(cfg: &SessionCfg) -> Option<String> {
        let argv = build_args(&hook_settings(), &SessionArgs::for_session(cfg));
        settings_json(&argv)["hooks"]["SessionStart"][0]["hooks"][0]["command"]
            .as_str()
            .map(str::to_owned)
    }

    #[test]
    fn agent_memory_alone_registers_the_session_start_hook() {
        let cfg = SessionCfg {
            agent_memory_dir: Some("/ws/memory/agent".into()),
            ..SessionCfg::default()
        };
        assert_eq!(
            session_start_command(&cfg).as_deref(),
            Some("/app/gino-agent memory-context --max-bytes 4096")
        );
    }

    #[test]
    fn read_only_agent_memory_adds_the_read_only_flag() {
        let cfg = SessionCfg {
            agent_memory_dir: Some("/ws/memory/agent".into()),
            agent_memory_access: AgentMemoryAccess::Ro,
            ..memory_cfg(None)
        };
        assert_eq!(
            session_start_command(&cfg).as_deref(),
            Some("/app/gino-agent memory-context --max-bytes 4096 --agent-read-only")
        );
        // Without an agent dir the access setting is moot.
        let cfg = SessionCfg {
            agent_memory_access: AgentMemoryAccess::Ro,
            ..memory_cfg(None)
        };
        assert_eq!(
            session_start_command(&cfg).as_deref(),
            Some("/app/gino-agent memory-context --max-bytes 4096")
        );
    }

    #[test]
    fn session_without_memory_dir_has_no_session_start_hook() {
        let argv = build_args(
            &hook_settings(),
            &SessionArgs::for_session(&SessionCfg::default()),
        );
        let json = settings_json(&argv);

        assert!(json["hooks"].get("PreCompact").is_some());
        assert!(json["hooks"].get("SessionStart").is_none());
    }

    /// A resumed session carries the same hook; claude filters by source, and
    /// the matcher never names `resume`, so nothing is injected on resume.
    #[test]
    fn resumed_memory_session_hook_excludes_resume() {
        let resumed = build_args(
            &hook_settings(),
            &SessionArgs::for_session(&memory_cfg(Some("sess-1"))),
        );
        assert!(resumed.iter().any(|a| a == "--resume"));
        let json = settings_json(&resumed);
        let matcher = json["hooks"]["SessionStart"][0]["matcher"]
            .as_str()
            .unwrap();
        let sources: Vec<&str> = matcher.split('|').collect();
        assert_eq!(sources, ["startup", "clear", "compact"]);
        assert!(!sources.contains(&"resume"));
    }

    #[test]
    fn default_settings_pass_memory_settings_without_hooks() {
        let argv = build_args(
            &ClaudeSettings::default(),
            &args_with(SessionId::New("s".to_owned())),
        );
        assert_eq!(argv.iter().filter(|a| *a == "--settings").count(), 1);
        assert_eq!(settings_json(&argv), json!({ "autoMemoryEnabled": false }));
        assert!(!argv.iter().any(|a| a == "--model"));
        assert!(!argv.iter().any(|a| a == "--allowed-tools"));

        let argv = build_args(
            &ClaudeSettings::default(),
            &SessionArgs::for_session(&memory_cfg(None)),
        );
        assert_eq!(
            settings_json(&argv),
            json!({ "autoMemoryDirectory": "/ws/memory/task-1/claude" })
        );
    }

    /// The value of `key` in the direct launch env of a session built from `cfg`.
    fn launch_env(cfg: &SessionCfg, key: &str) -> Option<String> {
        let direct = direct_launch(
            &hook_settings(),
            &SessionArgs::for_session(cfg),
            None,
            None,
            None,
            cfg.memory_dir.as_deref(),
            cfg.agent_memory_dir.as_deref(),
        );
        direct
            .env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.to_str().unwrap().to_owned())
    }

    #[test]
    fn task_memory_redirects_auto_memory_into_the_task_dir() {
        let cfg = memory_cfg(None);
        let json = settings_json(&build_args(
            &hook_settings(),
            &SessionArgs::for_session(&cfg),
        ));
        assert_eq!(json["autoMemoryDirectory"], "/ws/memory/task-1/claude");
        assert!(json.get("autoMemoryEnabled").is_none());
        assert!(json["hooks"].get("PreCompact").is_some());
        assert!(json["hooks"].get("SessionStart").is_some());
        assert_eq!(launch_env(&cfg, "CLAUDE_CODE_DISABLE_AUTO_MEMORY"), None);
    }

    #[test]
    fn no_task_memory_disables_auto_memory() {
        let agent_only = SessionCfg {
            agent_memory_dir: Some("/ws/memory/agent".into()),
            ..SessionCfg::default()
        };
        for cfg in [SessionCfg::default(), agent_only] {
            let json = settings_json(&build_args(
                &hook_settings(),
                &SessionArgs::for_session(&cfg),
            ));
            assert_eq!(json["autoMemoryEnabled"], false);
            assert!(json.get("autoMemoryDirectory").is_none());
            assert!(json["hooks"].get("PreCompact").is_some());
            assert_eq!(
                launch_env(&cfg, "CLAUDE_CODE_DISABLE_AUTO_MEMORY").as_deref(),
                Some("1")
            );
        }
    }

    #[test]
    fn config_dir_env_exports_generic_and_claude_vars_when_set() {
        let settings = ClaudeSettings {
            config_dir: Some(std::path::PathBuf::from("/ws/engine-config")),
            ..ClaudeSettings::default()
        };
        assert_eq!(
            config_dir_env(&settings),
            vec![
                ("ENGINE_CONFIG_DIR", "/ws/engine-config".to_owned()),
                ("CLAUDE_CONFIG_DIR", "/ws/engine-config".to_owned()),
            ]
        );
        // Unset → neither var is exported.
        assert!(config_dir_env(&ClaudeSettings::default()).is_empty());
    }

    #[test]
    fn session_args_for_session_resumes_when_id_present() {
        let cfg = SessionCfg {
            resume: Some("sess-x".to_owned()),
            resume_at: Some("m-1".to_owned()),
            ..SessionCfg::default()
        };
        match SessionArgs::for_session(&cfg).session {
            SessionId::Resume { id, at } => {
                assert_eq!(id, "sess-x");
                assert_eq!(at.as_deref(), Some("m-1"));
            }
            SessionId::New(_) => panic!("expected a resume"),
        }
    }

    #[test]
    fn session_args_for_session_mints_new_id_without_resume() {
        let cfg = SessionCfg::default();
        assert!(matches!(
            SessionArgs::for_session(&cfg).session,
            SessionId::New(_)
        ));
    }
}

// Integration smoke test (no auth, no network): a fake `claude` stub script
// drives the full control protocol — emit `init`, ask `can_use_tool`, block until
// the host auto-allows, then emit a `result`. Asserts the auto-allow round-trips,
// the result maps to an outcome, and the session id is captured.
#[cfg(test)]
#[cfg(unix)]
mod smoke {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use futures_util::StreamExt;

    use super::{ClaudeEngine, ClaudeSettings};
    use crate::engine::{Engine, EngineError, EngineEvent, LogLevel, RunStatus, SessionCfg};

    /// Write an executable bash stub that speaks just enough control protocol to
    /// require — and prove — the host's auto-allow.
    fn write_fake_claude(dir: &Path) -> PathBuf {
        let path = dir.join("fake-claude.sh");
        let script = r#"#!/usr/bin/env bash
set -u
# 1. Announce the session id.
printf '%s\n' '{"type":"system","subtype":"init","session_id":"sess-smoke","model":"m","tools":[]}'
# 2. Ask to run a tool and block until the host answers with an allow.
printf '%s\n' '{"type":"control_request","request_id":"req-1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"echo hi"}}}'
allowed=0
while IFS= read -r line; do
  case "$line" in
    *control_response*allow*) allowed=1; break ;;
    *) : ;;
  esac
done
# 3. Only after the allow do we stream the assistant text and the result.
if [ "$allowed" -eq 1 ]; then
  printf '%s\n' '{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"done"}]}}'
  printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"all good","session_id":"sess-smoke"}'
fi
"#;
        {
            let mut file = std::fs::File::create(&path).expect("create stub");
            file.write_all(script.as_bytes()).expect("write stub");
            let mut perms = file.metadata().expect("stub metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod stub");
        }
        path
    }

    #[tokio::test]
    async fn session_auto_allows_tool_and_captures_result() {
        let dir = tempfile::tempdir().expect("temp dir");
        let fake = write_fake_claude(dir.path());
        let engine = ClaudeEngine::new(ClaudeSettings {
            binary: fake,
            ..ClaudeSettings::default()
        });

        // ETXTBSY retry: a concurrently-spawning test child can briefly hold
        // the just-written script's fd, failing exec with "text file busy".
        let session = loop {
            match engine
                .start_session(SessionCfg {
                    cwd: dir.path().to_path_buf(),
                    initial_prompt: Some("hi".to_owned()),
                    ..SessionCfg::default()
                })
                .await
            {
                Ok(session) => break session,
                Err(EngineError::Spawn(err))
                    if err.kind() == std::io::ErrorKind::ExecutableFileBusy =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => panic!("unexpected engine error: {err}"),
            }
        };

        // Drain the stream to the single `result` — it only arrives if the stub
        // saw our auto-allow.
        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = session.events();
            let mut session_started = None;
            while let Some(event) = stream.next().await {
                match event {
                    EngineEvent::SessionStarted { session_id } => {
                        session_started = Some(session_id);
                    }
                    EngineEvent::Result(outcome) => return Some((session_started, outcome)),
                    _ => {}
                }
            }
            None
        })
        .await
        .expect("session timed out")
        .expect("stream ended without a result");

        let (session_started, outcome) = outcome;
        assert_eq!(session_started.as_deref(), Some("sess-smoke"));
        assert_eq!(outcome.status, RunStatus::Success);
        assert_eq!(outcome.result.as_deref(), Some("all good"));
        assert_eq!(outcome.session_id.as_deref(), Some("sess-smoke"));
        assert!(outcome.error.is_none());
    }

    /// A stub that reports session state when asked to, and answers a prompt
    /// with an interim result followed by a second turn's result.
    fn write_two_turn_claude(dir: &Path) -> PathBuf {
        let path = dir.join("two-turn-claude.sh");
        let script = r#"#!/usr/bin/env bash
set -u
state() {
  if [ "${CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS:-}" = 1 ]; then
    printf '%s\n' "{\"type\":\"system\",\"subtype\":\"session_state_changed\",\"state\":\"$1\"}"
  fi
}
state running
printf '%s\n' '{"type":"system","subtype":"init","session_id":"sess-two"}'
printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"subagent still running","session_id":"sess-two"}'
printf '%s\n' '{"type":"system","subtype":"init","session_id":"sess-two"}'
printf '%s\n' '{"type":"result","subtype":"success","is_error":false,"result":"the answer is 4","session_id":"sess-two"}'
state idle
# Stay alive like the real CLI until the host closes stdin.
cat >/dev/null
"#;
        {
            let mut file = std::fs::File::create(&path).expect("create stub");
            file.write_all(script.as_bytes()).expect("write stub");
            let mut perms = file.metadata().expect("stub metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod stub");
        }
        path
    }

    #[tokio::test]
    async fn session_reports_the_result_of_the_last_turn() {
        let dir = tempfile::tempdir().expect("temp dir");
        let engine = ClaudeEngine::new(ClaudeSettings {
            binary: write_two_turn_claude(dir.path()),
            ..ClaudeSettings::default()
        });
        let session = loop {
            match engine
                .start_session(SessionCfg {
                    cwd: dir.path().to_path_buf(),
                    initial_prompt: Some("hi".to_owned()),
                    ..SessionCfg::default()
                })
                .await
            {
                Ok(session) => break session,
                Err(EngineError::Spawn(err))
                    if err.kind() == std::io::ErrorKind::ExecutableFileBusy =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => panic!("unexpected engine error: {err}"),
            }
        };

        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = session.events();
            while let Some(event) = stream.next().await {
                if let EngineEvent::Result(outcome) = event {
                    return Some(outcome);
                }
            }
            None
        })
        .await
        .expect("session timed out")
        .expect("stream ended without a result");

        assert_eq!(outcome.result.as_deref(), Some("the answer is 4"));
    }

    /// Audit P3: a child that dies at startup (e.g. an auth failure) writes its
    /// reason to stderr only — the reader must surface that tail as an error log
    /// event before the stream ends, instead of letting it vanish.
    #[tokio::test]
    async fn startup_failure_diagnostics_carry_the_stderr_tail() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("dying-claude.sh");
        let script = "#!/usr/bin/env bash\n\
                      echo 'Invalid API key: please run /login' >&2\n\
                      exit 1\n";
        {
            let mut file = std::fs::File::create(&path).expect("create stub");
            file.write_all(script.as_bytes()).expect("write stub");
            let mut perms = file.metadata().expect("stub metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod stub");
        }
        let engine = ClaudeEngine::new(ClaudeSettings {
            binary: path,
            ..ClaudeSettings::default()
        });

        // ETXTBSY retry: a concurrently-spawning test child can briefly hold
        // the just-written script's fd, failing exec with "text file busy".
        let session = loop {
            match engine
                .start_session(SessionCfg {
                    cwd: dir.path().to_path_buf(),
                    initial_prompt: Some("hi".to_owned()),
                    ..SessionCfg::default()
                })
                .await
            {
                Ok(session) => break session,
                Err(EngineError::Spawn(err))
                    if err.kind() == std::io::ErrorKind::ExecutableFileBusy =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => panic!("unexpected engine error: {err}"),
            }
        };

        // No `result` ever arrives; the stderr tail must reach the stream as an
        // error-level log event before EOF ends it.
        let tail_log = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = session.events();
            let mut tail_log = None;
            while let Some(event) = stream.next().await {
                match event {
                    EngineEvent::Result(_) => panic!("a dead child must not produce a result"),
                    EngineEvent::Log {
                        level: LogLevel::Error,
                        message,
                    } => tail_log = Some(message),
                    _ => {}
                }
            }
            tail_log
        })
        .await
        .expect("session timed out")
        .expect("stream ended without surfacing the stderr tail");

        assert!(
            tail_log.contains("Invalid API key: please run /login"),
            "the stderr tail must reach the diagnostics, got: {tail_log}"
        );
    }
}
