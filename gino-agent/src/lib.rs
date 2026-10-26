#![forbid(unsafe_code)]

//! `gino-agent` — a generic, WebSocket-based, runtime-agnostic agent runner.
//! It is the persistent node agent: it registers with the gino
//! orchestrator, receives its config, and supervises local execution.
//!
//! This module owns the CLI and subcommand dispatch; the daemon itself lives
//! in [`runner`], on top of the transport, engine, db, executor and scheduler
//! modules.
//!
//! The `gino-agent` binary is a thin wrapper around [`run`].

mod agent_api;
mod archive;
mod attachment_source;
mod attachments;
mod chat;
mod config;
mod db;
mod e2ee;
mod engine;
mod executor;
mod failure;
mod gino_cli;
mod guest_init;
mod login;
mod memory;
mod net;
mod paths;
mod protocol;
mod provisioning;
mod register;
mod remote_ops;
mod runner;
mod sandbox;
mod scheduler;
mod transport;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use tracing::{debug, error, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{Config, ConfigOverlay};

/// Generic WebSocket-based agent runner daemon.
#[derive(Parser)]
#[command(name = "gino-agent", version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    bootstrap: BootstrapArgs,

    /// Increase log verbosity (`-v` = debug, `-vv` = trace). `RUST_LOG` wins.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Bootstrap inputs: the only things the runner needs to start.
/// Everything else — agent id, connect token, config — is host-assigned at
/// registration. These are global so they may appear before or after the
/// subcommand.
#[derive(Args)]
struct BootstrapArgs {
    /// Orchestrator base URL, e.g. `https://gino.example.com`.
    #[arg(long, env = "GINO_HOST_URL", global = true)]
    host: Option<String>,

    /// Enrollment token — a bootstrap credential used only to register. The
    /// per-agent connect token used for the WebSocket is negotiated at
    /// registration and is never this value. DEPRECATED as a flag (argv is
    /// world-readable via /proc/*/cmdline): prefer GINO_REGISTER_TOKEN or
    /// GINO_REGISTER_TOKEN_FILE, both resolved in [`register`] and taking
    /// precedence over this flag.
    #[arg(long, global = true)]
    register_token: Option<String>,

    /// Human-readable agent name.
    #[arg(long, env = "GINO_AGENT_NAME", global = true)]
    name: Option<String>,

    /// Serve the host-enabled remote operations (`remoteOps`) even while this
    /// runner holds an end-to-end encrypted task; they are refused by default.
    /// Runner-local only: no host config or local API can set it.
    #[arg(
        long,
        env = "GINO_ALLOW_REMOTE_OPS_WITH_E2EE",
        global = true,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    allow_remote_ops_with_e2ee: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Run the persistent gino-agent daemon (the default subcommand).
    Run,
    /// PreCompact hook target: archive a transcript read as JSON on stdin.
    Archive,
    /// SessionStart hook target: print the agent and task memory context.
    MemoryContext {
        /// Soft size cap in bytes per tree; above it the context carries a prune
        /// warning.
        #[arg(long, default_value_t = memory::DEFAULT_MAX_BYTES)]
        max_bytes: u64,
        /// Mark the agent memory read-only in the context.
        #[arg(long)]
        agent_read_only: bool,
    },
    /// Show this agent's system info: identity, version, host, paths, live counts.
    #[command(visible_alias = "info")]
    System,
    /// Mint a long-lived Claude OAuth token via `claude setup-token` and store it
    /// for the daemon's engine (no host-supplied credential needed). Not needed
    /// when `CLAUDE_CONFIG_USE_DEFAULT=true` reuses an already-logged-in `~/.claude`.
    Login,
    /// Install, update or inspect the engines this agent runs.
    #[command(subcommand)]
    Engine(engine::admin::EngineCommand),
    /// Manage this agent's scheduled triggers (crons): create, list, pause, cancel.
    #[command(subcommand)]
    Cron(gino_cli::CronCommand),
    /// Inspect this agent's tasks (read-only mirror of host-assigned tasks).
    #[command(subcommand)]
    Task(gino_cli::TaskCommand),
    /// Inspect this agent's execution threads.
    #[command(subcommand)]
    Thread(gino_cli::ThreadCommand),
    /// Ask the host to act: record a host-defined action on this run's thread.
    Action(gino_cli::ActionArgs),
    /// First process inside the engine sandbox: drops to a non-root uid and
    /// supervises the engine.
    #[command(hide = true)]
    SandboxInit(sandbox::init::SandboxInitArgs),
    /// Workload of an engine microVM: mounts, networking and the control
    /// channel, then supervises the engine.
    #[command(hide = true)]
    GuestInit,
}

/// Parse CLI arguments, install logging, and dispatch the selected subcommand.
///
/// # Examples
///
/// The binary entry point is a thin wrapper:
///
/// ```no_run
/// fn main() -> anyhow::Result<()> {
///     gino_agent::run()
/// }
/// ```
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    disable_core_dumps();
    install_panic_hook();
    install_crypto_provider();

    match cli.command.unwrap_or(Command::Run) {
        Command::Run => {
            if cli.bootstrap.allow_remote_ops_with_e2ee {
                warn!(
                    "--allow-remote-ops-with-e2ee is set: host remote operations are served \
                     even while this runner holds end-to-end encrypted tasks"
                );
                remote_ops::allow_with_e2ee();
            }
            runner::run_daemon(
                cli.bootstrap.host,
                register::resolve_register_token(cli.bootstrap.register_token),
                cli.bootstrap.name,
            )?;
        }
        Command::Archive => archive()?,
        Command::MemoryContext {
            max_bytes,
            agent_read_only,
        } => memory_context(max_bytes, agent_read_only),
        Command::System => gino_cli::system()?,
        Command::Login => {
            let mut config = Config::default();
            config.apply(ConfigOverlay::paths_from_env()?);
            login::run(&config.paths)?;
        }
        Command::Engine(cmd) => {
            let mut config = Config::default();
            config.apply(ConfigOverlay::paths_from_env()?);
            engine::admin::command(&config.paths.workspace_dir, cmd)?;
        }
        Command::Cron(cmd) => gino_cli::cron(cmd)?,
        Command::Task(cmd) => gino_cli::task(cmd)?,
        Command::Thread(cmd) => gino_cli::thread(cmd)?,
        Command::Action(args) => gino_cli::action(&args)?,
        Command::SandboxInit(args) => std::process::exit(sandbox::init::run(&args)),
        Command::GuestInit => std::process::exit(guest_init::run()),
    }
    Ok(())
}

/// Install aws-lc-rs as the process-wide rustls `CryptoProvider` before any TLS
/// use, so no client depends on rustls picking a default. Idempotent: a second
/// call — or another installer winning the race — is a harmless no-op.
fn install_crypto_provider() {
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        debug!("rustls CryptoProvider already installed");
    }
}

/// The `archive` subcommand: read the PreCompact hook payload on stdin and write
/// a Markdown archive + sessions index under `GINO_ARCHIVE_DIR`, else the
/// workspace `conversations` dir.
///
/// This runs as a short-lived subprocess Claude spawns for its PreCompact hook,
/// so it cannot reach host-assigned config; the workspace path is resolved from
/// the `GINO_WORKSPACE_DIR` env (set by the engine when it spawns Claude)
/// or the built-in default. No network, no runtime needed.
fn archive() -> Result<()> {
    let workspace_dir = env_path_or("GINO_WORKSPACE_DIR", |paths| paths.workspace_dir);
    let conversations_dir = archive::conversations_dir(
        std::env::var_os("GINO_ARCHIVE_DIR").map(std::path::PathBuf::from),
        &workspace_dir,
    );
    let stdin = std::io::stdin();
    archive::run(&conversations_dir, stdin.lock()).context("archiving transcript")?;
    Ok(())
}

/// The `memory-context` subcommand: print the memory context of the trees named
/// by `GINO_AGENT_MEMORY_DIR` and `GINO_MEMORY_DIR` (each absent when unset or
/// empty). Never fails the hook: any error prints nothing to stdout and a short
/// message to stderr.
fn memory_context(max_bytes: u64, agent_read_only: bool) {
    use std::io::Write as _;

    let result = render_memory_context(
        std::env::var_os("GINO_AGENT_MEMORY_DIR").as_deref(),
        std::env::var_os("GINO_MEMORY_DIR").as_deref(),
        max_bytes,
        agent_read_only,
    )
    .and_then(|context| std::io::stdout().lock().write_all(context.as_bytes()));
    if let Err(err) = result {
        eprintln!("gino-agent memory-context: {err}");
    }
}

/// The memory context for the `memory-context` env values: an unset or empty
/// value leaves that tree out.
fn render_memory_context(
    agent_dir: Option<&std::ffi::OsStr>,
    task_dir: Option<&std::ffi::OsStr>,
    max_bytes: u64,
    agent_read_only: bool,
) -> std::io::Result<String> {
    let agent = agent_dir
        .filter(|dir| !dir.is_empty())
        .map(|dir| memory::AgentContext {
            dir: std::path::Path::new(dir),
            read_only: agent_read_only,
        });
    let task = task_dir
        .filter(|dir| !dir.is_empty())
        .map(std::path::Path::new);
    memory::try_render_context(agent, task, max_bytes)
}

/// Resolve a filesystem path for the hook subprocess: an environment override
/// when present, otherwise the corresponding [`Config`] default. The hook
/// subprocess has no host config, so env is the only channel the daemon can hand
/// it a non-default path through.
fn env_path_or(
    var: &str,
    default: impl FnOnce(crate::config::Paths) -> std::path::PathBuf,
) -> std::path::PathBuf {
    std::env::var_os(var).map_or_else(
        || default(Config::default().paths),
        std::path::PathBuf::from,
    )
}

/// Set `RLIMIT_CORE` to zero so a crash never writes the process memory —
/// which holds the connect token and engine credentials — to disk.
fn disable_core_dumps() {
    if let Err(err) = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0) {
        warn!(error = %err, "failed to disable core dumps");
    }
}

/// Log every panic as a structured `error` event with its location and a
/// backtrace, replacing the default stderr report.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info.location().map(ToString::to_string);
        let backtrace = std::backtrace::Backtrace::force_capture();
        error!(
            message = panic_message(info.payload()),
            location = location.as_deref(),
            %backtrace,
            "panic"
        );
    }));
}

/// The text of a panic payload (`panic!` produces `&str` or `String`).
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

/// Install a tracing subscriber writing to stderr. `RUST_LOG` takes precedence;
/// otherwise the level is derived from the `-v` count.
fn init_tracing(verbose: u8) {
    let default_directive = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .init();
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::{Cli, disable_core_dumps, panic_message, render_memory_context};

    #[test]
    fn the_remote_ops_opt_in_is_off_unless_the_flag_is_given() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from(args)
                .unwrap()
                .bootstrap
                .allow_remote_ops_with_e2ee
        };
        assert!(!parse(&["gino-agent", "run"]));
        assert!(parse(&[
            "gino-agent",
            "run",
            "--allow-remote-ops-with-e2ee"
        ]));
        assert!(parse(&["gino-agent", "--allow-remote-ops-with-e2ee"]));
    }

    #[test]
    fn core_dumps_are_disabled() {
        disable_core_dumps();
        assert_eq!(rlimit::getrlimit(rlimit::Resource::CORE).unwrap(), (0, 0));
    }

    #[test]
    fn panic_message_reads_str_and_string_payloads() {
        assert_eq!(panic_message(&"boom"), "boom");
        assert_eq!(panic_message(&String::from("bang")), "bang");
        assert_eq!(panic_message(&42_u8), "non-string panic payload");
    }

    #[test]
    fn memory_context_renders_the_trees_named_by_both_env_values() {
        let ws = tempfile::tempdir().unwrap();
        let agent = ws.path().join("agent");
        let task = ws.path().join("task");
        for (dir, marker) in [(&agent, "AGENT-MARKER"), (&task, "TASK-MARKER")] {
            std::fs::create_dir(dir).unwrap();
            std::fs::write(dir.join("index.md"), marker).unwrap();
        }
        let render = |agent: Option<&std::path::Path>, task: Option<&std::path::Path>, ro| {
            render_memory_context(
                agent.map(std::path::Path::as_os_str),
                task.map(std::path::Path::as_os_str),
                u64::MAX,
                ro,
            )
            .unwrap()
        };

        let both = render(Some(&agent), Some(&task), true);
        let agent_at = both.find("AGENT-MARKER").expect("agent tree");
        assert!(agent_at < both.find("TASK-MARKER").expect("task tree"));
        assert!(both.contains("read-only: you cannot change it"));

        let task_only = render(None, Some(&task), false);
        assert!(task_only.contains("TASK-MARKER") && !task_only.contains("AGENT-MARKER"));
        let empty = std::path::Path::new("");
        let agent_only = render(Some(&agent), Some(empty), false);
        assert!(agent_only.contains("AGENT-MARKER") && !agent_only.contains("TASK-MARKER"));
        assert!(!agent_only.contains("read-only"));
        assert_eq!(render(Some(empty), None, false), "");
    }
}
