//! Shared **e2e harness** for the §5b deterministic full-loop tests.
//!
//! The runner exposes only `gino_agent::run()` publicly — its `Engine`/`Session`
//! traits, `protocol::frames` and `db` read models are all `pub(crate)`, so an
//! integration-test crate cannot construct them. The harness therefore drives the
//! runner **black-box**: it boots the real `gino-agent` binary as a subprocess
//! against an in-process [`stub_host::StubHost`] (HTTP register + attachments + WS
//! v2) with a scripted [`fake_claude`] `claude` on the subprocess `PATH`. The full
//! production stack — register, transport (outbox/inbox, at-least-once, reconnect),
//! scheduler, executor (drainer, watchdog, retry, resume-safety) and the
//! attachment plane — runs unmodified.
//!
//! ## Hermetic per-test workspace (Lane WP)
//!
//! [`run_async`](gino_agent) resolves the workspace + SQLite path from
//! `GINO_WORKSPACE_DIR` / `GINO_DB_PATH` *before* opening the DB, so each scenario
//! boots the daemon against its **own** temp [`Workspace`] — no shared mount, no
//! pre-boot wipe. A [`Workspace`] also holds a process-global serial guard for its
//! lifetime, so at most one daemon runs at a time (keeping the watchdog-sensitive
//! timeout scenarios deterministic) and a crash/restart scenario can relaunch a
//! second daemon on the **same** db without the lock churning.
//!
//! ## Lane I2 cron scenarios (now live)
//!
//! The cron **prompt** path landed (Z2: `crons.prompt` ← `cron_upsert.data.prompt`,
//! snapshotted into `threads.prompt` at fire time), so the §5b cron scenarios
//! (#1/#2/#3/#8) run here on the real scheduler: push `task_upsert`/`cron_upsert`
//! frames ([`stub_host::StubHost::push_cron_upsert`]) and assert `cron_state` /
//! `cron_logs` mirroring ([`stub_host::StubHost::cron_state`]). The scripted
//! [`fake_claude`] echo behaviour drives a cron run unchanged (the engine ignores
//! the prompt text, so no cron-specific `Behavior` is needed).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)] // used by the e2ee suites only
pub mod e2ee;
pub mod fake_claude;
pub mod fake_codex;
pub mod stub_host;

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::support::fake_claude::Behavior;
use crate::support::stub_host::StubHost;

/// The compiled `gino-agent` binary under test (Cargo sets this for integration
/// tests).
const DAEMON_BIN: &str = env!("CARGO_BIN_EXE_gino-agent");

/// Process-global serialization: at most one live daemon at a time, so the
/// watchdog-sensitive timeout scenarios stay deterministic under `cargo test`'s
/// parallel harness. Held as an owned guard inside each [`Workspace`].
static SERIAL: LazyLock<Arc<Mutex<()>>> = LazyLock::new(|| Arc::new(Mutex::new(())));

/// A hermetic per-test workspace: its own temp workspace dir + SQLite db path,
/// relocated into the daemon via `GINO_WORKSPACE_DIR` / `GINO_DB_PATH` (Lane WP).
/// Holds the process-global serial guard for its whole lifetime, so a restart
/// scenario can boot a second daemon on the **same** db (the durable state outlives
/// the first [`RunnerProc`]) without another scenario interleaving.
pub struct Workspace {
    _root: TempDir,
    dir: PathBuf,
    db_path: PathBuf,
    _serial: OwnedMutexGuard<()>,
}

impl Workspace {
    /// The workspace root the daemon materializes its on-disk state under
    /// (`GINO_WORKSPACE_DIR`): the `store/` content-addressed tree, the global
    /// `engine-config/` scope root, and the per-thread `threads/<id>/project/`
    /// scopes. The provisioning scenarios inspect these directly (black-box), so a
    /// scenario builds a [`Workspace`] explicitly and boots via [`RunnerProc::spawn_in`]
    /// to keep the handle across the run (and any restart).
    #[must_use]
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }

    /// The global config version the daemon recorded as applied — persisted only
    /// after the global reconcile has fully committed, so a restart scenario waits
    /// on it before killing the first daemon.
    #[must_use]
    pub fn applied_global_version(&self) -> Option<String> {
        let conn = rusqlite::Connection::open_with_flags(
            &self.db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()?;
        conn.query_row(
            "SELECT value FROM config_meta WHERE key = 'applied_global_config_version'",
            [],
            |r| r.get(0),
        )
        .ok()
    }

    /// Acquire the serial lock and mint a fresh temp workspace + db path. The
    /// daemon creates both directories on boot, so nothing is pre-created here.
    pub async fn new() -> Self {
        let serial = SERIAL.clone().lock_owned().await;
        let root = tempfile::Builder::new()
            .prefix("gino-agent-e2e-")
            .tempdir()
            .expect("create e2e workspace temp dir");
        let dir = root.path().join("workspace");
        let db_path = root.path().join("agent.db");
        Self {
            _root: root,
            dir,
            db_path,
            _serial: serial,
        }
    }
}

/// A booted runner subprocess: the child plus the engine-fakes dir
/// (removed on drop). `kill_on_drop` reaps the daemon if a scenario panics before
/// [`Self::shutdown`]. The serial guard + durable state live in the [`Workspace`]
/// (owned by this proc in the common case, by the caller for a restart).
pub struct RunnerProc {
    child: Child,
    fake_dir: TempDir,
    /// `Some` when this proc owns its (ephemeral) workspace; `None` for a
    /// [`Self::spawn_in`] proc whose workspace the caller keeps across a restart.
    _workspace: Option<Workspace>,
}

impl RunnerProc {
    /// Common case: boot the daemon against a fresh hermetic [`Workspace`] this
    /// proc owns (released, with the serial lock, on [`Self::shutdown`]). Returns
    /// once the process is spawned; call [`stub_host::StubHost::wait_connected`] to
    /// await the WS connect.
    pub async fn spawn(host: &StubHost, behavior: &Behavior) -> Self {
        let workspace = Workspace::new().await;
        let (child, fake_dir) = boot(host, behavior, &workspace, None);
        Self {
            child,
            fake_dir,
            _workspace: Some(workspace),
        }
    }

    /// Boot with BOTH engine fakes on `PATH`: the scripted fake-`claude` and a
    /// fake-`codex` announcing `codex_thread_id`. Installing the codex script is
    /// what makes the runner register the codex backend at all (the probe is a
    /// stat on `PATH`), so only a scenario that asks for it runs multi-engine.
    pub async fn spawn_with_codex(
        host: &StubHost,
        behavior: &Behavior,
        codex_thread_id: &str,
    ) -> Self {
        let workspace = Workspace::new().await;
        let (child, fake_dir) = boot(host, behavior, &workspace, Some(codex_thread_id));
        Self {
            child,
            fake_dir,
            _workspace: Some(workspace),
        }
    }

    /// The directory holding the installed engine fakes — where
    /// [`fake_codex::recorded_argv`] reads the argv the fake `codex` was spawned
    /// with.
    #[must_use]
    pub fn fake_dir(&self) -> &std::path::Path {
        self.fake_dir.path()
    }

    /// Restart-capable: boot against a caller-owned [`Workspace`] (which holds the
    /// serial guard and the on-disk db). Used by the crash/restart durability
    /// scenario to relaunch a second daemon on the same db after the first is
    /// killed; the workspace survives because the caller, not this proc, owns it.
    pub fn spawn_in(host: &StubHost, behavior: &Behavior, workspace: &Workspace) -> Self {
        let (child, fake_dir) = boot(host, behavior, workspace, None);
        Self {
            child,
            fake_dir,
            _workspace: None,
        }
    }

    /// Boot against a caller-owned [`Workspace`] with engine fakes the caller
    /// installed into `fake_dir`. `path` replaces the daemon's whole `PATH` when
    /// set; otherwise `fake_dir` goes first on the inherited one.
    #[allow(dead_code)] // used by the sandbox suite only
    pub fn spawn_in_with_fakes(
        host: &StubHost,
        workspace: &Workspace,
        fake_dir: TempDir,
        path: Option<&str>,
    ) -> Self {
        let path = path.map_or_else(|| fakes_first_path(fake_dir.path()), str::to_owned);
        let child = launch(host, workspace, &path, &[], std::process::Stdio::null());
        Self {
            child,
            fake_dir,
            _workspace: None,
        }
    }

    /// Like [`Self::spawn_in_with_fakes`] with the fakes dir first on the
    /// inherited `PATH`, plus extra daemon `envs` (overriding the defaults) and
    /// the daemon's stderr sent to `stderr`.
    pub fn spawn_in_with_env(
        host: &StubHost,
        workspace: &Workspace,
        fake_dir: TempDir,
        envs: &[(&str, &std::ffi::OsStr)],
        stderr: std::process::Stdio,
    ) -> Self {
        let path = fakes_first_path(fake_dir.path());
        let child = launch(host, workspace, &path, envs, stderr);
        Self {
            child,
            fake_dir,
            _workspace: None,
        }
    }

    /// The daemon's pid.
    #[allow(dead_code)] // used by the vm suite only
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id().expect("the daemon is running")
    }

    /// Kill the daemon and wait for it to exit. For a [`Self::spawn`] proc this also
    /// drops the owned workspace (removing it and releasing the serial lock); for a
    /// [`Self::spawn_in`] proc the caller's workspace (and lock) persist.
    pub async fn shutdown(mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
    }
}

/// Install the scripted fake-`claude` (and, when `codex_thread_id` is set, the
/// fake-`codex` beside it) and boot the daemon against `host` with that directory
/// first on `PATH` and the workspace relocated into `workspace`. Returns the child
/// and the fakes' temp dir (kept alive for the child's lifetime).
fn boot(
    host: &StubHost,
    behavior: &Behavior,
    workspace: &Workspace,
    codex_thread_id: Option<&str>,
) -> (Child, TempDir) {
    let fake_dir = fake_claude::install(behavior);
    if let Some(thread_id) = codex_thread_id {
        fake_codex::install_into(fake_dir.path(), thread_id);
    }
    let child = launch(
        host,
        workspace,
        &fakes_first_path(fake_dir.path()),
        &[],
        std::process::Stdio::null(),
    );
    (child, fake_dir)
}

/// `dir` first, then the inherited `PATH`.
fn fakes_first_path(dir: &std::path::Path) -> String {
    match std::env::var("PATH") {
        Ok(existing) => format!("{}:{existing}", dir.display()),
        Err(_) => dir.display().to_string(),
    }
}

/// Boot the daemon against `host` with `path` as its `PATH`, the workspace
/// relocated into `workspace`, `envs` set last and stderr to `stderr`.
fn launch(
    host: &StubHost,
    workspace: &Workspace,
    path: &str,
    envs: &[(&str, &std::ffi::OsStr)],
    stderr: std::process::Stdio,
) -> Child {
    let mut command = Command::new(DAEMON_BIN);
    command
        .arg("run")
        .env("PATH", path)
        .env("GINO_HOST_URL", host.base_url())
        .env("GINO_REGISTER_TOKEN", "e2e-register-token")
        .env("GINO_AGENT_NAME", "e2e-runner")
        // Lane WP: relocate the workspace + db off the default mount so each
        // scenario is hermetic (and a restart reuses the same db).
        .env("GINO_WORKSPACE_DIR", &workspace.dir)
        .env("GINO_DB_PATH", &workspace.db_path)
        // Quiet by default; flip to `info`/`debug` + inherited stderr when
        // diagnosing a scenario.
        .env("RUST_LOG", "off")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr)
        .envs(envs.iter().copied())
        .kill_on_drop(true);
    command.spawn().expect("spawn gino-agent daemon")
}

/// A short standard timeout for waiting on host-mirror state in scenarios.
pub const SETTLE: Duration = Duration::from_secs(10);

/// Poll a synchronous predicate every 20ms up to `timeout`; `true` if it ever held.
///
/// The provisioning scenarios assert on **on-disk** state (symlinks / store
/// entries) the daemon materializes asynchronously — the startup global reconcile
/// runs just after the WS connect, and a `config_update` re-reconcile lands shortly
/// after the frame is sent — so a scenario waits on the filesystem the same way it
/// waits on the host mirror, with no fixed sleeps (deterministic under the serial
/// harness).
pub async fn wait_until<F: Fn() -> bool>(timeout: Duration, pred: F) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if pred() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
