//! The Codex [`Engine`]: one `codex exec --json` child per turn.
//!
//! DECISION: ONE TURN PER PROCESS. Unlike the claude backend — a single
//! long-lived child driven over a bidirectional control protocol — `codex exec`
//! reads its prompt from stdin, runs exactly one turn, and exits. The runner
//! therefore spawns a fresh child per turn, writes the prompt, CLOSES stdin so
//! the child sees EOF, and reads JSONL `ThreadEvent`s off stdout until the
//! process ends. Continuity comes from the thread id: `thread.started` reports
//! it, the runner persists it as the session id, and the next turn passes it
//! back as the trailing `resume <thread_id>` argument. No attempt is made to
//! keep a session process alive across turns.
//!
//! Because stdin is already closed by the time the turn is running, there is no
//! in-band cancel channel — [`CodexSession::interrupt`] is a SIGNAL, not a
//! message. See its doc comment.
//!
//! The wire format itself is mapped by [`events`]; this module owns the process:
//! argv, environment, spawn, the stdout reader, the bounded stderr tail, and the
//! session lifecycle.

mod events;

use std::borrow::Cow;
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use secrecy::ExposeSecret;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use self::events::EventMapper;
use crate::config::Config;
use crate::engine::{Engine, EngineError, EngineEvent, EventStream, LogLevel, Session, SessionCfg};
use crate::memory::{self, AgentMemoryAccess};
use crate::sandbox::vm::VmMonitor;
use crate::sandbox::{self, EngineProcess, IsolationSpec, Launch, LaunchContext, NetExit, Spawned};

/// Everything needed to build the `codex` argv, spawn the child, and resolve its
/// environment. Built from the global [`Config`] via [`CodexSettings::from_config`];
/// tests construct it directly to point at a stub binary.
///
/// DECISION: THE DEFAULTS ARE NON-INTERACTIVE, AND THAT IS MANDATORY.
/// `--ask-for-approval never` means a turn can never block waiting on an
/// approval prompt the runner has no way to answer — `codex exec` exposes no
/// approval channel the runner speaks, so a blocking turn would simply hang
/// until a watchdog killed it. The flags stay configurable for deployments that
/// know better, but the DEFAULT must be non-interactive.
///
/// DECISION: `--sandbox danger-full-access` BY DEFAULT, for parity with the
/// claude backend, which already runs `--dangerously-skip-permissions`.
/// Isolation in this product is the CONTAINER boundary, not the engine's own
/// sandbox. A narrower default would silently deny the writes and network access
/// the claude backend allows, so the two backends would not run the same task the
/// same way — a task that succeeds on one engine would mysteriously fail on the
/// other. A deployment that wants the engine sandbox on can tighten it through
/// the config block.
///
/// DECISION: `--skip-git-repo-check` BY DEFAULT. `codex exec` refuses to run
/// outside a git repository, and the runner's per-thread working directory
/// (`work_dir/project/`) is not one.
#[derive(Clone, Debug)]
pub(crate) struct CodexSettings {
    /// The `codex` executable to spawn (default `codex` on `PATH`).
    pub(crate) binary: PathBuf,
    /// Path to *this* `gino-agent` binary, exported as `GINO_RUNNER_BIN` so
    /// in-engine tooling can re-invoke the runner without a hard-coded path.
    /// `None` omits the variable (e.g. in tests).
    pub(crate) self_exe: Option<PathBuf>,
    /// Model id passed via `--model`.
    pub(crate) model: Option<String>,
    /// Approval policy passed via `--ask-for-approval`.
    pub(crate) approval_policy: Option<String>,
    /// Sandbox mode passed via `--sandbox`.
    pub(crate) sandbox_mode: Option<String>,
    /// Whether to pass `--skip-git-repo-check`.
    pub(crate) skip_git_repo_check: bool,
    /// Extra arguments appended verbatim, for flags this struct does not model.
    pub(crate) extra_args: Vec<String>,
    /// Environment variables layered onto the child (engine credentials etc.).
    pub(crate) env: Vec<(String, String)>,
    /// The provisioned engine config dir. When set, the child is launched with
    /// both the generic `ENGINE_CONFIG_DIR` and codex's own `CODEX_HOME` pointed
    /// here, so it reads the instruction file + skills the runner materialized.
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

impl Default for CodexSettings {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("codex"),
            self_exe: None,
            model: None,
            approval_policy: Some("never".to_owned()),
            sandbox_mode: Some("danger-full-access".to_owned()),
            skip_git_repo_check: true,
            extra_args: Vec::new(),
            env: Vec::new(),
            config_dir: None,
            isolation: IsolationSpec::default(),
            isolation_floored: false,
            workspace_dir: PathBuf::new(),
            memory_max_bytes: memory::DEFAULT_MAX_BYTES,
        }
    }
}

impl CodexSettings {
    /// Resolve the codex settings from the global [`Config`]'s `engine.codex`
    /// block. Every field is optional there and an ABSENT field leaves this
    /// struct's [`Default`] in place — notably `skip_git_repo_check`, where a
    /// missing value must keep the flag ON rather than silently meaning "off".
    /// The credential env (`OPENAI_API_KEY` / `OPENAI_BASE_URL`) is materialised
    /// here, at the secret boundary, exactly as the claude backend does.
    pub(crate) fn from_config(config: &Config) -> Self {
        let codex = &config.engine.codex;
        let defaults = Self::default();
        let mut env = Vec::new();
        if let Some(key) = &codex.openai_api_key {
            env.push(("OPENAI_API_KEY".to_owned(), key.expose_secret().to_owned()));
        }
        if let Some(url) = &codex.openai_base_url {
            env.push(("OPENAI_BASE_URL".to_owned(), url.clone()));
        }
        Self {
            binary: super::admin::resolve_binary(
                &config.paths.workspace_dir,
                super::admin::EngineKind::Codex,
                codex.binary.as_deref(),
            ),
            self_exe: std::env::current_exe().ok(),
            model: codex.model.clone(),
            approval_policy: codex.approval_policy.clone().or(defaults.approval_policy),
            sandbox_mode: codex.sandbox_mode.clone().or(defaults.sandbox_mode),
            skip_git_repo_check: codex
                .skip_git_repo_check
                .unwrap_or(defaults.skip_git_repo_check),
            extra_args: codex.extra_args.clone(),
            env,
            config_dir: None,
            isolation: config.engine.isolation.clone(),
            isolation_floored: config.engine.isolation_floor.is_some(),
            workspace_dir: config.paths.workspace_dir.clone(),
            memory_max_bytes: config.memory.max_bytes,
        }
    }
}

/// Whether `binary` names a codex executable this runner could actually spawn: a
/// path with a separator must itself be an executable file, a bare name is
/// searched across the `PATH` entries.
///
/// DECISION: THE PROBE NEVER EXECUTES THE BINARY. Running the configured program
/// (a `--version` spawn) at registration time would execute an arbitrary
/// host-supplied path on every start and config update, which is both slower than
/// a stat and a strictly worse posture than never running it at all. A stat
/// answers the only question the caller has: can this be spawned.
pub(crate) fn is_available(binary: &Path) -> bool {
    is_available_in(binary, std::env::var_os("PATH").as_deref())
}

/// [`is_available`] against an explicit `PATH` value, so the search is testable
/// without mutating the process environment (which no test can do safely while
/// its siblings run in the same process).
fn is_available_in(binary: &Path, search_path: Option<&OsStr>) -> bool {
    // `parent()` is `Some("")` for a bare name and a real directory otherwise.
    let has_separator = binary
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    if has_separator {
        return is_executable_file(binary);
    }
    let Some(search_path) = search_path else {
        return false;
    };
    std::env::split_paths(search_path).any(|dir| is_executable_file(&dir.join(binary)))
}

/// Whether `path` is an existing regular file with an executable bit set.
/// Symlinks are followed ([`std::fs::metadata`]), so a `PATH` shim resolves.
fn is_executable_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Build the `codex` argv from [`CodexSettings`] plus the thread id to resume,
/// if any. Pure and order-stable so it is unit-testable.
///
/// `resume <thread_id>` is a positional SUBCOMMAND argument, so it is appended
/// LAST — after every flag, including `extra_args` — where no flag can swallow
/// the id as its value.
fn build_args(settings: &CodexSettings, resume: Option<&str>) -> Vec<String> {
    // `--ask-for-approval` is a TOP-LEVEL flag: `codex exec` rejects it with
    // `error: unexpected argument` (verified against codex-cli 0.154.0), so it
    // must precede the `exec` subcommand. Everything else below is an `exec`
    // option and follows it.
    let mut argv = Vec::new();
    if let Some(policy) = &settings.approval_policy {
        argv.push("--ask-for-approval".to_owned());
        argv.push(policy.clone());
    }
    argv.push("exec".to_owned());
    argv.push("--json".to_owned());

    if let Some(model) = &settings.model {
        argv.push("--model".to_owned());
        argv.push(model.clone());
    }
    if let Some(mode) = &settings.sandbox_mode {
        argv.push("--sandbox".to_owned());
        argv.push(mode.clone());
    }
    if settings.skip_git_repo_check {
        argv.push("--skip-git-repo-check".to_owned());
    }
    argv.extend(settings.extra_args.iter().cloned());
    if let Some(thread_id) = resume {
        argv.push("resume".to_owned());
        argv.push(thread_id.to_owned());
    }

    argv
}

/// The config-dir environment the child inherits: the provisioned engine config
/// dir exported as both the generic `ENGINE_CONFIG_DIR` (shared across backends)
/// and codex's own `CODEX_HOME`. Empty when `config_dir` is unset. Pure +
/// order-stable so it is unit-testable.
fn config_dir_env(settings: &CodexSettings) -> Vec<(&'static str, String)> {
    match &settings.config_dir {
        Some(dir) => {
            let path = dir.display().to_string();
            vec![("ENGINE_CONFIG_DIR", path.clone()), ("CODEX_HOME", path)]
        }
        None => Vec::new(),
    }
}

/// Layer the per-session [`SessionCfg::model`] (the task's model) onto the
/// configured settings for ONE spawn: present → it wins over the configured
/// model, absent → the configured model stands untouched (borrowed, so the
/// common case copies nothing).
///
/// DECISION: APPLY-ON-NEXT-SPAWN, matching the claude backend. The override is
/// read here, at spawn, and never pushed into a child already running — so a
/// task's model change takes effect on its next run rather than mid-turn. With
/// one turn per process that boundary is simply the next turn.
fn effective_settings<'a>(settings: &'a CodexSettings, cfg: &SessionCfg) -> Cow<'a, CodexSettings> {
    match &cfg.model {
        Some(model) => {
            let mut overridden = settings.clone();
            overridden.model = Some(model.clone());
            Cow::Owned(overridden)
        }
        None => Cow::Borrowed(settings),
    }
}

/// The Codex backend. Holds the resolved [`CodexSettings`].
#[derive(Clone, Debug)]
pub(crate) struct CodexEngine {
    settings: CodexSettings,
}

impl CodexEngine {
    /// Construct an engine from explicit settings.
    pub(crate) fn new(settings: CodexSettings) -> Self {
        Self { settings }
    }
}

#[async_trait]
impl Engine for CodexEngine {
    fn name(&self) -> &'static str {
        "codex"
    }

    /// Spawn one `codex exec` child for this turn, resuming
    /// [`SessionCfg::resume`] when set.
    ///
    /// [`SessionCfg::resume_at`] has no codex equivalent — the CLI resumes a
    /// thread whole, with no way to rewind to a message — so it is IGNORED
    /// rather than approximated.
    async fn start_session(&self, cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError> {
        let settings = effective_settings(&self.settings, &cfg);
        let session = spawn_session(&settings, &cfg).await?;
        Ok(Box::new(session))
    }
}

/// Bounds on the captured stderr tail: enough for a startup/auth error banner,
/// small enough to embed in a failure message. Same bounds as the claude
/// backend — the diagnostic serves the same purpose.
const STDERR_TAIL_MAX_LINES: usize = 32;
const STDERR_TAIL_MAX_BYTES: usize = 4096;
/// How long the reader waits for the stderr drain to settle after stdout EOF
/// (both pipes close on child exit, so this is only a scheduling grace).
const STDERR_DRAIN_WINDOW: Duration = Duration::from_millis(500);
/// How long [`CodexSession::interrupt`] lets the child wind down after SIGINT
/// before escalating to a kill.
const INTERRUPT_GRACE: Duration = Duration::from_secs(2);

/// A bounded tail of the child's stderr: a startup or auth failure dies before
/// any JSONL event, so its stderr is the only diagnostic. Shared between the
/// drain task (writer) and the reader (which surfaces it at EOF).
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

/// Env keys naming the engine config dir.
const CONFIG_DIR_ENV_KEYS: [&str; 2] = ["ENGINE_CONFIG_DIR", "CODEX_HOME"];

/// The direct (unisolated) `codex exec` launch: binary, argv, env and cwd.
///
/// `task_id`/`thread_id` (when present) are exported to the child as
/// `GINO_TASK_ID`/`GINO_THREAD_ID`, and the runner's own path as
/// `GINO_RUNNER_BIN`, so in-engine tooling can self-reference the task and
/// re-invoke the runner without a hard-coded path. An issued agent API token is
/// exported as `GINO_AGENT_SOCK`/`GINO_AGENT_TOKEN`, and the task's memory dir as
/// `GINO_MEMORY_DIR`.
fn direct_launch(settings: &CodexSettings, cfg: &SessionCfg) -> Launch {
    let mut env: Vec<(String, OsString)> = settings
        .env
        .iter()
        .map(|(key, value)| (key.clone(), value.into()))
        .collect();
    // The provisioned engine config dir — both the generic var and codex's own.
    env.extend(
        config_dir_env(settings)
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.into())),
    );
    if let Some(exe) = &settings.self_exe {
        env.push(("GINO_RUNNER_BIN".to_owned(), exe.into()));
    }
    if let Some(task_id) = &cfg.task_id {
        env.push(("GINO_TASK_ID".to_owned(), task_id.into()));
    }
    if let Some(thread_id) = &cfg.thread_id {
        env.push(("GINO_THREAD_ID".to_owned(), thread_id.into()));
    }
    if let Some(api) = &cfg.agent_api {
        env.push(("GINO_AGENT_SOCK".to_owned(), api.socket.clone().into()));
        env.push(("GINO_AGENT_TOKEN".to_owned(), api.token.clone().into()));
    }
    if let Some(dir) = &cfg.memory_dir {
        env.push(("GINO_MEMORY_DIR".to_owned(), dir.into()));
    }
    if let Some(dir) = &cfg.agent_memory_dir {
        env.push(("GINO_AGENT_MEMORY_DIR".to_owned(), dir.into()));
    }
    Launch::direct(
        settings.binary.clone(),
        build_args(settings, cfg.resume.as_deref()),
        env,
        cfg.cwd.clone(),
    )
}

/// The isolation inputs for one spawn.
fn launch_context<'a>(settings: &'a CodexSettings, cfg: &'a SessionCfg) -> LaunchContext<'a> {
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

/// Spawn the `codex exec` child (directly or sandboxed, per the run's
/// isolation), deliver the prompt, and wire the reader tasks.
async fn spawn_session(
    settings: &CodexSettings,
    cfg: &SessionCfg,
) -> Result<CodexSession, EngineError> {
    let launch = sandbox::launch(direct_launch(settings, cfg), &launch_context(settings, cfg))?;
    // Stderr is captured: a child that dies at startup (bad args, auth failure)
    // writes its reason to stderr only — the bounded tail is surfaced as a log
    // event instead of vanishing into the daemon's inherited stderr.
    let Spawned {
        process,
        stdin,
        stdout,
        stderr,
        net,
    } = sandbox::spawn(launch).await?;

    // `codex exec` reads its prompt from stdin and runs exactly one turn, so
    // stdin is written once and then CLOSED — unconditionally, even with no
    // prompt to send. A child left waiting on an open stdin would never start.
    let prompt = cfg
        .initial_prompt
        .as_deref()
        .map(|prompt| match &cfg.resume {
            None => first_prompt(prompt, &memory_context(settings, cfg)),
            Some(_) => prompt.to_owned(),
        });
    tokio::spawn(async move {
        let mut stdin = stdin;
        if let Some(prompt) = prompt
            && let Err(err) = write_prompt(&mut stdin, &prompt).await
        {
            warn!(error = %err, "codex stdin write failed");
        }
        if let Err(err) = stdin.shutdown().await {
            debug!(error = %err, "closing codex stdin");
        }
        drop(stdin);
    });

    let (events_tx, events_rx) = mpsc::unbounded_channel::<EngineEvent>();
    let stderr_tail = StderrTail::default();
    let stderr_handle = tokio::spawn(stderr_task(stderr, stderr_tail.clone()));
    let reader_handle = tokio::spawn(reader_task(
        stdout,
        events_tx,
        stderr_handle,
        stderr_tail,
        process.vm_monitor(),
    ));

    Ok(CodexSession {
        events: Mutex::new(Some(events_rx)),
        child: Arc::new(tokio::sync::Mutex::new(process)),
        tasks: vec![reader_handle],
        _net: net,
    })
}

/// The memory context for a fresh thread: the agent tree, then the task tree.
fn memory_context(settings: &CodexSettings, cfg: &SessionCfg) -> String {
    let agent = cfg
        .agent_memory_dir
        .as_deref()
        .map(|dir| memory::AgentContext {
            dir,
            read_only: cfg.agent_memory_access == AgentMemoryAccess::Ro,
        });
    memory::render_context(agent, cfg.memory_dir.as_deref(), settings.memory_max_bytes)
}

/// The first prompt of a fresh thread: the memory `context`, a blank line, then
/// `prompt`; `prompt` alone when `context` is empty.
fn first_prompt(prompt: &str, context: &str) -> String {
    if context.is_empty() {
        prompt.to_owned()
    } else {
        format!("{}\n\n{prompt}", context.trim_end())
    }
}

/// Write the turn's prompt, newline-terminated and flushed.
async fn write_prompt(stdin: &mut tokio::process::ChildStdin, prompt: &str) -> std::io::Result<()> {
    stdin.write_all(prompt.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await
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

/// Parse the child's stdout JSONL line by line and forward the mapped events.
///
/// A line that is not valid JSON is DROPPED with a debug line — never an error,
/// never an event. `codex exec` interleaves the occasional human-readable banner
/// with its JSONL, and one unparsable line must not fail an otherwise good turn.
///
/// On EOF the captured stderr tail is surfaced as a final error log event, then
/// the stream ENDS. DECISION: no terminal [`EngineEvent::Result`] is synthesized
/// here. `executor::drive` already turns a stream that ends without a `Result`
/// into an `agent.process_failure`; inventing an outcome would both hide the
/// crash and diverge from the claude backend. A VM run that ended without
/// reporting the engine's exit adds the runner-side reason as a log event.
async fn reader_task(
    stdout: ChildStdout,
    events: mpsc::UnboundedSender<EngineEvent>,
    stderr_drain: JoinHandle<()>,
    stderr_tail: StderrTail,
    vm: Option<VmMonitor>,
) {
    let mut mapper = EventMapper::new();
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                let value: Value = match serde_json::from_str(&line) {
                    Ok(value) => value,
                    Err(err) => {
                        debug!(error = %err, "skipping non-JSON codex stdout line");
                        continue;
                    }
                };
                for event in mapper.map_line(&value) {
                    // The receiver lives as long as the session; a send failure
                    // just means the consumer dropped the stream.
                    let _ = events.send(event);
                }
            }
            Ok(None) => {
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

/// One `codex exec` turn. Holds the (one-shot) event receiver, the engine
/// process (killed or stopped on drop, and kept so [`Session::interrupt`] can
/// signal it), and the reader task handle (aborted on drop).
#[derive(Debug)]
pub(crate) struct CodexSession {
    events: Mutex<Option<mpsc::UnboundedReceiver<EngineEvent>>>,
    child: Arc<tokio::sync::Mutex<EngineProcess>>,
    tasks: Vec<JoinHandle<()>>,
    /// Allowlist network exit; stops when the session is dropped.
    _net: Option<NetExit>,
}

#[async_trait]
impl Session for CodexSession {
    /// Cancel the running turn.
    ///
    /// DECISION: THE INTERRUPT IS A SIGNAL, NOT A MESSAGE. `codex exec` reads its
    /// prompt from stdin and we close that pipe immediately, so there is no
    /// in-band cancel channel of the kind the claude backend uses. The only way
    /// to stop a turn is to signal the process: SIGINT first (codex handles it as
    /// a graceful abort), then a bounded [`INTERRUPT_GRACE`] wait, then
    /// `start_kill` if it is still alive.
    ///
    /// The cancelled turn settles through the EXISTING executor path and needs no
    /// cancel logic here: the child dies, its stdout hits EOF, the event stream
    /// ends, and `executor::drain_cancelled` settles the thread `cancelled`.
    ///
    /// `Ok(())` even when the child is already gone — interrupting a turn that
    /// has finished is a no-op, not an error.
    async fn interrupt(&self) -> Result<(), EngineError> {
        let mut child = self.child.lock().await;
        if child.id().is_none() {
            // Already reaped: nothing to signal.
            return Ok(());
        }
        // Sandboxed, SIGINT goes to `sandbox-init` (`bwrap` does not forward
        // signals); in a VM, over its control channel.
        child.interrupt();

        // Bounded wait: if the child honours SIGINT it exits within the grace
        // window, otherwise it is killed outright.
        if tokio::time::timeout(INTERRUPT_GRACE, child.wait())
            .await
            .is_err()
        {
            child.start_kill();
        }
        Ok(())
    }

    fn events(&self) -> BoxStream<'_, EngineEvent> {
        let taken = self.events.lock().ok().and_then(|mut guard| guard.take());
        match taken {
            Some(rx) => Box::pin(EventStream::new(rx)),
            None => Box::pin(futures_util::stream::empty::<EngineEvent>()),
        }
    }
}

impl Drop for CodexSession {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        // Dropping the last process handle kills the child or stops the VM.
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use futures_util::StreamExt as _;

    use super::{
        CodexEngine, CodexSettings, build_args, config_dir_env, direct_launch, effective_settings,
        first_prompt, is_available_in, launch_context,
    };
    use crate::config::{Config, ConfigOverlay};
    use crate::engine::{
        AgentApiAccess, Engine, EngineError, EngineEvent, RunStatus, Session, SessionCfg,
    };
    use crate::memory::AgentMemoryAccess;
    use crate::sandbox::{self, IsolationSpec, SandboxHost};

    fn os_args(args: Vec<String>) -> Vec<std::ffi::OsString> {
        args.into_iter().map(Into::into).collect()
    }

    #[test]
    fn from_config_carries_isolation_and_workspace_dir() {
        let mut config = Config::default();
        config.apply(
            ConfigOverlay::from_json(
                r#"{ "engine": { "isolation": { "mode": "sandbox", "network": { "mode": "full" } } } }"#,
            )
            .expect("overlay"),
        );
        let settings = CodexSettings::from_config(&config);
        assert_eq!(settings.isolation, config.engine.isolation);
        assert_eq!(settings.isolation.mode.as_deref(), Some("sandbox"));
        assert_eq!(settings.workspace_dir, config.paths.workspace_dir);
        assert_eq!(
            CodexSettings::from_config(&Config::default()).isolation,
            IsolationSpec::default()
        );
    }

    #[test]
    fn from_config_prefers_a_configured_binary_then_the_managed_install() {
        let ws = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.paths.workspace_dir = ws.path().to_path_buf();
        assert_eq!(
            CodexSettings::from_config(&config).binary,
            Path::new("codex")
        );
        let managed = ws.path().join("engines/home/.local/bin/codex");
        std::fs::create_dir_all(managed.parent().unwrap()).unwrap();
        std::fs::write(&managed, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(CodexSettings::from_config(&config).binary, managed);
        config.engine.codex.binary = Some("/opt/bin/codex".into());
        assert_eq!(
            CodexSettings::from_config(&config).binary,
            Path::new("/opt/bin/codex")
        );
    }

    #[test]
    fn from_config_carries_memory_max_bytes() {
        let mut config = Config::default();
        config.memory.max_bytes = 2048;
        assert_eq!(CodexSettings::from_config(&config).memory_max_bytes, 2048);
        assert_eq!(
            CodexSettings::default().memory_max_bytes,
            crate::memory::DEFAULT_MAX_BYTES
        );
    }

    #[test]
    fn off_launch_is_the_direct_spawn() {
        let settings = CodexSettings {
            self_exe: Some("/app/gino-agent".into()),
            config_dir: Some("/ws/engine-config".into()),
            ..CodexSettings::default()
        };
        let cfg = SessionCfg {
            cwd: "/ws/threads/t1/project".into(),
            work_dir: Some("/ws/threads/t1".into()),
            task_id: Some("task-1".to_owned()),
            resume: Some("thread-9".to_owned()),
            ..SessionCfg::default()
        };
        let direct = direct_launch(&settings, &cfg);
        assert_eq!(direct.program, Path::new("codex"));
        assert_eq!(direct.cwd, cfg.cwd);
        assert_eq!(
            direct.args,
            os_args(build_args(&settings, Some("thread-9")))
        );
        let env: Vec<(&str, &str)> = direct
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            env,
            [
                ("ENGINE_CONFIG_DIR", "/ws/engine-config"),
                ("CODEX_HOME", "/ws/engine-config"),
                ("GINO_RUNNER_BIN", "/app/gino-agent"),
                ("GINO_TASK_ID", "task-1"),
            ]
        );
        let launched = sandbox::launch(direct.clone(), &launch_context(&settings, &cfg)).unwrap();
        assert_eq!(launched, direct);
    }

    #[test]
    fn an_issued_agent_api_token_is_exported_next_to_the_thread_id() {
        let settings = CodexSettings::default();
        let cfg = SessionCfg {
            task_id: Some("task-1".to_owned()),
            thread_id: Some("th-1".to_owned()),
            agent_api: Some(AgentApiAccess {
                socket: "/ws/run/agent.sock".into(),
                token: "tok".to_owned(),
            }),
            memory_dir: Some("/ws/memory/task/task-1".into()),
            agent_memory_dir: Some("/ws/memory/agent".into()),
            ..SessionCfg::default()
        };
        let direct = direct_launch(&settings, &cfg);
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
            ]
        );
    }

    #[test]
    fn sandboxed_launch_points_codex_home_at_the_engine_home() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let bin_dir = root.join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let binary = executable_stub(bin_dir.join("codex"));
        let work_dir = root.join("threads/t1");
        let settings = CodexSettings {
            self_exe: Some("/opt/gino/gino-agent".into()),
            config_dir: Some(root.join("engine-config")),
            isolation: IsolationSpec {
                mode: Some("sandbox".to_owned()),
                ..IsolationSpec::default()
            },
            workspace_dir: root.clone(),
            ..CodexSettings::default()
        };
        let cfg = SessionCfg {
            cwd: work_dir.join("project"),
            work_dir: Some(work_dir.clone()),
            ..SessionCfg::default()
        };
        let isolation = sandbox::resolve(
            &settings.isolation,
            None,
            &root,
            sandbox::LlmBaseUrl::default(),
        )
        .unwrap();
        let wrapped = sandbox::wrap(
            direct_launch(&settings, &cfg),
            &launch_context(&settings, &cfg),
            &isolation,
            &SandboxHost::fixture(Some(bin_dir.into_os_string())),
        )
        .unwrap();

        assert!(wrapped.sandboxed);
        assert_eq!(wrapped.program, Path::new("/usr/bin/bwrap"));
        let boundary = wrapped
            .args
            .iter()
            .position(|a| a == "sandbox-init")
            .unwrap();
        assert_eq!(wrapped.args[boundary + 1], "--");
        assert_eq!(wrapped.args[boundary + 2], binary.as_os_str());
        assert_eq!(wrapped.args[boundary + 3], "--ask-for-approval");

        let home = work_dir.join(".engine-home").into_os_string();
        let value = |key: &str| {
            wrapped
                .env
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(value("ENGINE_CONFIG_DIR"), value("CODEX_HOME"));
        assert_eq!(value("CODEX_HOME"), [home]);
        assert_eq!(value("HOME"), ["/home/gino"]);
        assert_eq!(value("TMPDIR"), ["/tmp"]);
        assert_eq!(value("GINO_SANDBOX"), ["1"]);
    }

    #[tokio::test]
    async fn invalid_isolation_fails_before_spawning() {
        let engine = CodexEngine::new(CodexSettings {
            binary: PathBuf::from("/nonexistent/codex"),
            isolation: IsolationSpec {
                mode: Some("sandbox".to_owned()),
                network: Some(crate::sandbox::NetworkSpec {
                    mode: Some("allowlist".to_owned()),
                    ..crate::sandbox::NetworkSpec::default()
                }),
                ..IsolationSpec::default()
            },
            ..CodexSettings::default()
        });
        let err = engine
            .start_session(SessionCfg::default())
            .await
            .err()
            .unwrap();
        assert!(matches!(err, EngineError::Isolation(_)), "{err:?}");
    }

    /// Write an executable no-op stub at `path` and return it.
    fn executable_stub(path: PathBuf) -> PathBuf {
        let mut file = std::fs::File::create(&path).expect("create stub");
        file.write_all(b"#!/bin/sh\nexit 0\n").expect("write stub");
        let mut perms = file.metadata().expect("stub metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod stub");
        path
    }

    #[test]
    fn from_config_keeps_the_backend_defaults_when_the_block_is_empty() {
        let settings = CodexSettings::from_config(&Config::default());
        assert_eq!(settings.binary, PathBuf::from("codex"));
        assert_eq!(settings.approval_policy.as_deref(), Some("never"));
        assert_eq!(settings.sandbox_mode.as_deref(), Some("danger-full-access"));
        assert!(
            settings.skip_git_repo_check,
            "an absent skipGitRepoCheck must not turn the flag off"
        );
        assert!(settings.model.is_none());
        assert!(settings.extra_args.is_empty());
        assert!(settings.env.is_empty());
        assert!(settings.config_dir.is_none());
    }

    #[test]
    fn from_config_resolves_the_block_and_the_credential_env() {
        let mut config = Config::default();
        config.apply(
            ConfigOverlay::from_json(
                r#"{
                    "engine": {
                        "codex": {
                            "binary": "/opt/bin/codex",
                            "model": "gpt-5-codex",
                            "approvalPolicy": "on-request",
                            "sandboxMode": "workspace-write",
                            "skipGitRepoCheck": false,
                            "extraArgs": ["--profile", "ci"],
                            "openaiApiKey": "sk-openai",
                            "openaiBaseUrl": "https://proxy.example.com/v1"
                        }
                    }
                }"#,
            )
            .expect("overlay"),
        );

        let settings = CodexSettings::from_config(&config);
        assert_eq!(settings.binary, PathBuf::from("/opt/bin/codex"));
        assert_eq!(settings.model.as_deref(), Some("gpt-5-codex"));
        assert_eq!(settings.approval_policy.as_deref(), Some("on-request"));
        assert_eq!(settings.sandbox_mode.as_deref(), Some("workspace-write"));
        assert!(!settings.skip_git_repo_check);
        assert_eq!(settings.extra_args, ["--profile", "ci"]);
        assert_eq!(
            settings.env,
            [
                ("OPENAI_API_KEY".to_owned(), "sk-openai".to_owned()),
                (
                    "OPENAI_BASE_URL".to_owned(),
                    "https://proxy.example.com/v1".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn the_probe_accepts_only_an_executable_file_at_an_explicit_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let good = executable_stub(dir.path().join("codex"));
        assert!(is_available_in(&good, None));

        let plain = dir.path().join("not-executable");
        std::fs::write(&plain, "#!/bin/sh\n").expect("write file");
        assert!(!is_available_in(&plain, None));

        assert!(!is_available_in(&dir.path().join("missing"), None));
        // A directory is not a spawnable file, even though it exists.
        assert!(!is_available_in(dir.path(), None));
    }

    #[test]
    fn the_probe_searches_a_bare_name_across_the_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let empty = tempfile::tempdir().expect("temp dir");
        executable_stub(dir.path().join("codex"));

        let search = std::env::join_paths([empty.path(), dir.path()]).expect("join paths");
        assert!(is_available_in(Path::new("codex"), Some(&search)));

        let only_empty = std::env::join_paths([empty.path()]).expect("join paths");
        assert!(!is_available_in(Path::new("codex"), Some(&only_empty)));
        // No PATH at all: a bare name can never resolve.
        assert!(!is_available_in(Path::new("codex"), None));
    }

    #[test]
    fn fresh_argv_is_the_non_interactive_default() {
        let argv = build_args(&CodexSettings::default(), None);
        assert_eq!(
            argv,
            [
                "--ask-for-approval",
                "never",
                "exec",
                "--json",
                "--sandbox",
                "danger-full-access",
                "--skip-git-repo-check",
            ]
        );
    }

    #[test]
    fn resume_appends_the_thread_id_last() {
        let settings = CodexSettings {
            extra_args: vec!["--color".to_owned(), "never".to_owned()],
            ..CodexSettings::default()
        };
        let argv = build_args(&settings, Some("th-7"));
        assert_eq!(
            argv,
            [
                "--ask-for-approval",
                "never",
                "exec",
                "--json",
                "--sandbox",
                "danger-full-access",
                "--skip-git-repo-check",
                "--color",
                "never",
                "resume",
                "th-7",
            ]
        );
    }

    #[test]
    fn session_model_overrides_the_configured_one_for_this_spawn() {
        let settings = CodexSettings {
            model: Some("gpt-configured".to_owned()),
            ..CodexSettings::default()
        };
        let cfg = SessionCfg {
            model: Some("gpt-per-task".to_owned()),
            ..SessionCfg::default()
        };
        let effective = effective_settings(&settings, &cfg);
        let argv = build_args(&effective, None);
        let model = argv.iter().position(|a| a == "--model").unwrap();
        assert_eq!(argv[model + 1], "gpt-per-task");
        // The configured settings are untouched — the override is per-spawn.
        assert_eq!(settings.model.as_deref(), Some("gpt-configured"));

        // No per-task model: the configured one stands, borrowed.
        let effective = effective_settings(&settings, &SessionCfg::default());
        let argv = build_args(&effective, None);
        let model = argv.iter().position(|a| a == "--model").unwrap();
        assert_eq!(argv[model + 1], "gpt-configured");
    }

    #[test]
    fn approval_sandbox_and_extra_args_are_configurable() {
        let settings = CodexSettings {
            approval_policy: Some("on-request".to_owned()),
            sandbox_mode: Some("workspace-write".to_owned()),
            extra_args: vec!["--profile".to_owned(), "ci".to_owned()],
            ..CodexSettings::default()
        };
        let argv = build_args(&settings, None);
        let approval = argv.iter().position(|a| a == "--ask-for-approval").unwrap();
        assert_eq!(argv[approval + 1], "on-request");
        // The approval flag is top-level: `codex exec` rejects it as an
        // unexpected argument, so it MUST come before the subcommand.
        let exec = argv.iter().position(|a| a == "exec").unwrap();
        assert!(
            approval < exec,
            "approval flag must precede `exec`: {argv:?}"
        );
        let sandbox = argv.iter().position(|a| a == "--sandbox").unwrap();
        assert_eq!(argv[sandbox + 1], "workspace-write");
        assert_eq!(&argv[argv.len() - 2..], ["--profile", "ci"]);
    }

    #[test]
    fn unset_policies_and_disabled_git_check_drop_their_flags() {
        let settings = CodexSettings {
            approval_policy: None,
            sandbox_mode: None,
            skip_git_repo_check: false,
            ..CodexSettings::default()
        };
        assert_eq!(build_args(&settings, None), ["exec", "--json"]);
    }

    #[test]
    fn config_dir_exports_the_generic_and_codex_vars() {
        let settings = CodexSettings {
            config_dir: Some(PathBuf::from("/var/lib/gino/engine")),
            ..CodexSettings::default()
        };
        assert_eq!(
            config_dir_env(&settings),
            [
                ("ENGINE_CONFIG_DIR", "/var/lib/gino/engine".to_owned()),
                ("CODEX_HOME", "/var/lib/gino/engine".to_owned()),
            ]
        );
        assert!(config_dir_env(&CodexSettings::default()).is_empty());
    }

    /// A stub `codex` that records its argv, echoes the prompt it read from
    /// stdin to `$CODEX_PROMPT_LOG` (when set), and emits the two JSONL events
    /// a minimal turn produces.
    fn write_fake_codex(dir: &Path) -> PathBuf {
        let path = dir.join("fake-codex.sh");
        let script = r#"#!/usr/bin/env bash
set -u
# 1. Record exactly what we were spawned with, one argv per line.
printf '%s\n' "$*" >> "$CODEX_ARGV_LOG"
# 2. The prompt arrives on stdin, which the runner closes right after writing it.
prompt=$(cat)
if [ -n "${CODEX_PROMPT_LOG:-}" ]; then printf '%s' "$prompt" > "$CODEX_PROMPT_LOG"; fi
# 3. Announce the thread, then complete the turn.
printf '%s\n' '{"type":"thread.started","thread_id":"codex-smoke"}'
printf '%s\n' '{"type":"turn.completed"}'
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

    /// Spawn with the ETXTBSY retry: a concurrently-spawning test child can
    /// briefly hold the just-written script's fd, failing exec with "text file
    /// busy".
    async fn start(engine: &CodexEngine, cfg: SessionCfg) -> Box<dyn Session> {
        loop {
            match engine.start_session(cfg.clone()).await {
                Ok(session) => return session,
                Err(EngineError::Spawn(err))
                    if err.kind() == std::io::ErrorKind::ExecutableFileBusy =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => panic!("unexpected engine error: {err}"),
            }
        }
    }

    /// Drain a session to its terminal `Result`, bounded so a hung child can
    /// never wedge the suite.
    async fn drain(session: &dyn Session) -> (Option<String>, crate::engine::RunOutcome) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = session.events();
            let mut started = None;
            while let Some(event) = stream.next().await {
                match event {
                    EngineEvent::SessionStarted { session_id } => started = Some(session_id),
                    EngineEvent::Result(outcome) => return Some((started, outcome)),
                    _ => {}
                }
            }
            None
        })
        .await
        .expect("session timed out")
        .expect("stream ended without a result")
    }

    /// A stub `codex` that announces its thread and then hangs, recording that
    /// it saw SIGINT so the test can tell a handled signal from the kill
    /// escalation. `sleep` is backgrounded (with its stdout redirected, so it
    /// cannot hold the pipe open) and waited on, which is what lets bash run the
    /// trap promptly instead of after a foreground command finishes.
    fn write_hanging_codex(dir: &Path, marker: &Path) -> PathBuf {
        let path = dir.join("hanging-codex.sh");
        let script = format!(
            r#"#!/usr/bin/env bash
set -u
trap 'echo sigint > "{marker}"; exit 0' INT
printf '%s\n' '{{"type":"thread.started","thread_id":"codex-int"}}'
sleep 30 >/dev/null 2>&1 &
wait $!
"#,
            marker = marker.display()
        );
        {
            let mut file = std::fs::File::create(&path).expect("create stub");
            file.write_all(script.as_bytes()).expect("write stub");
            let mut perms = file.metadata().expect("stub metadata").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod stub");
        }
        path
    }

    /// `interrupt` has no in-band channel to use, so it must actually signal the
    /// child: the stub records the SIGINT it handled, and the turn settles by the
    /// stream ending (no synthesized `Result`), which is what
    /// `executor::drain_cancelled` consumes.
    #[tokio::test]
    async fn interrupt_signals_the_child_and_ends_the_stream() {
        let dir = tempfile::tempdir().expect("temp dir");
        let marker = dir.path().join("sigint.marker");
        let fake = write_hanging_codex(dir.path(), &marker);
        let engine = CodexEngine::new(CodexSettings {
            binary: fake,
            ..CodexSettings::default()
        });

        let session = start(
            &engine,
            SessionCfg {
                cwd: dir.path().to_path_buf(),
                initial_prompt: Some("hang".to_owned()),
                ..SessionCfg::default()
            },
        )
        .await;

        let ended = tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = session.events();
            // Wait until the child is definitely running its turn.
            let first = stream.next().await;
            assert!(
                matches!(first, Some(EngineEvent::SessionStarted { .. })),
                "expected the thread announcement first, got {first:?}"
            );
            session.interrupt().await.expect("interrupt");
            // The interrupted turn settles by the stream ENDING — no terminal
            // `Result` is synthesized here.
            while let Some(event) = stream.next().await {
                assert!(
                    !matches!(event, EngineEvent::Result(_)),
                    "an interrupted turn must not synthesize a result"
                );
            }
        })
        .await;
        assert!(ended.is_ok(), "the interrupted session did not wind down");

        assert!(
            marker.exists(),
            "the child must have received and handled SIGINT"
        );
        // Interrupting an already-finished turn is a no-op, not an error.
        session.interrupt().await.expect("second interrupt");
    }

    #[tokio::test]
    async fn smoke_turn_reports_the_thread_id_and_resumes_it_next_turn() {
        let dir = tempfile::tempdir().expect("temp dir");
        let fake = write_fake_codex(dir.path());
        let argv_log = dir.path().join("argv.log");
        let engine = CodexEngine::new(CodexSettings {
            binary: fake,
            env: vec![("CODEX_ARGV_LOG".to_owned(), argv_log.display().to_string())],
            ..CodexSettings::default()
        });

        let session = start(
            &engine,
            SessionCfg {
                cwd: dir.path().to_path_buf(),
                initial_prompt: Some("hi".to_owned()),
                ..SessionCfg::default()
            },
        )
        .await;

        let (started, outcome) = drain(session.as_ref()).await;
        assert_eq!(started.as_deref(), Some("codex-smoke"));
        assert_eq!(outcome.status, RunStatus::Success);
        assert_eq!(outcome.session_id.as_deref(), Some("codex-smoke"));
        assert!(outcome.error.is_none());

        // A second turn resumes the thread the first one reported.
        let resumed = start(
            &engine,
            SessionCfg {
                cwd: dir.path().to_path_buf(),
                resume: Some("codex-smoke".to_owned()),
                initial_prompt: Some("again".to_owned()),
                ..SessionCfg::default()
            },
        )
        .await;
        let (_, outcome) = drain(resumed.as_ref()).await;
        assert_eq!(outcome.status, RunStatus::Success);

        let log = std::fs::read_to_string(&argv_log).expect("argv log");
        let spawns: Vec<&str> = log.lines().collect();
        assert_eq!(spawns.len(), 2, "expected two spawns, got: {log}");
        assert!(
            !spawns[0].contains("resume"),
            "a fresh turn must not resume: {}",
            spawns[0]
        );
        assert!(
            spawns[1].ends_with("resume codex-smoke"),
            "the resumed turn must end in `resume codex-smoke`: {}",
            spawns[1]
        );
    }

    #[test]
    fn first_prompt_prepends_the_context_with_a_blank_line() {
        assert_eq!(
            first_prompt("do it", "# Task memory\n"),
            "# Task memory\n\ndo it"
        );
        assert_eq!(first_prompt("do it", ""), "do it");
    }

    /// Run one stub turn and return the prompt the stub read from stdin.
    async fn echoed_prompt(cfg: SessionCfg) -> String {
        let dir = tempfile::tempdir().expect("temp dir");
        let fake = write_fake_codex(dir.path());
        let prompt_log = dir.path().join("prompt.log");
        let engine = CodexEngine::new(CodexSettings {
            binary: fake,
            env: vec![
                (
                    "CODEX_ARGV_LOG".to_owned(),
                    dir.path().join("argv.log").display().to_string(),
                ),
                (
                    "CODEX_PROMPT_LOG".to_owned(),
                    prompt_log.display().to_string(),
                ),
            ],
            ..CodexSettings::default()
        });
        let session = start(
            &engine,
            SessionCfg {
                cwd: dir.path().to_path_buf(),
                initial_prompt: Some("user prompt".to_owned()),
                ..cfg
            },
        )
        .await;
        let (_, outcome) = drain(session.as_ref()).await;
        assert_eq!(outcome.status, RunStatus::Success);
        std::fs::read_to_string(&prompt_log).expect("prompt log")
    }

    /// A memory dir whose `index.md` carries a marker.
    fn memory_dir_with_marker() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("memory dir");
        std::fs::write(dir.path().join("index.md"), "MEMORY-MARKER-42\n").expect("write index");
        dir
    }

    #[tokio::test]
    async fn fresh_thread_prepends_the_memory_context() {
        let memory = memory_dir_with_marker();
        let prompt = echoed_prompt(SessionCfg {
            memory_dir: Some(memory.path().to_path_buf()),
            ..SessionCfg::default()
        })
        .await;
        let marker = prompt.find("MEMORY-MARKER-42").expect("marker in prompt");
        let claude_line = prompt
            .find("Claude Code's native auto memory for this task: `$GINO_MEMORY_DIR/claude/`")
            .expect("claude dir line in prompt");
        assert!(marker < claude_line, "prompt: {prompt}");
        assert!(claude_line < prompt.len() - "user prompt".len());
        assert!(prompt.ends_with("\n\nuser prompt"), "prompt: {prompt}");
        assert!(marker < prompt.len() - "user prompt".len());
    }

    /// An agent memory dir whose `index.md` carries a marker.
    fn agent_memory_dir_with_marker() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("agent memory dir");
        std::fs::write(dir.path().join("index.md"), "AGENT-MARKER-7\n").expect("write index");
        dir
    }

    #[tokio::test]
    async fn fresh_thread_prepends_agent_memory_before_task_memory() {
        let agent = agent_memory_dir_with_marker();
        let memory = memory_dir_with_marker();
        for (access, read_only) in [
            (AgentMemoryAccess::Rw, false),
            (AgentMemoryAccess::Ro, true),
        ] {
            let prompt = echoed_prompt(SessionCfg {
                memory_dir: Some(memory.path().to_path_buf()),
                agent_memory_dir: Some(agent.path().to_path_buf()),
                agent_memory_access: access,
                ..SessionCfg::default()
            })
            .await;
            let agent_at = prompt
                .find("AGENT-MARKER-7")
                .expect("agent marker in prompt");
            let task_at = prompt
                .find("MEMORY-MARKER-42")
                .expect("task marker in prompt");
            assert!(agent_at < task_at, "prompt: {prompt}");
            assert_eq!(prompt.contains("read-only"), read_only, "prompt: {prompt}");
            assert!(prompt.ends_with("\n\nuser prompt"), "prompt: {prompt}");
        }
    }

    #[tokio::test]
    async fn resumed_thread_sends_the_prompt_unchanged() {
        let agent = agent_memory_dir_with_marker();
        let memory = memory_dir_with_marker();
        let prompt = echoed_prompt(SessionCfg {
            resume: Some("codex-smoke".to_owned()),
            memory_dir: Some(memory.path().to_path_buf()),
            agent_memory_dir: Some(agent.path().to_path_buf()),
            ..SessionCfg::default()
        })
        .await;
        assert_eq!(prompt, "user prompt");
    }

    #[tokio::test]
    async fn no_memory_dir_sends_the_prompt_unchanged() {
        assert_eq!(echoed_prompt(SessionCfg::default()).await, "user prompt");
    }
}
