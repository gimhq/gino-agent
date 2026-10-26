//! The persistent gino-agent daemon.
//!
//! [`run_daemon`] wires the whole node agent together
//! and serves until shutdown:
//!
//! 1. resolve [`Config`] from bootstrap inputs,
//! 2. load-or-register the runner [`identity`](crate::register),
//! 3. open the reconnecting [`Transport`] (frames, outbox/inbox),
//! 4. build the engine and the v2 [`ThreadExecutor`] (the pending-thread drainer),
//! 5. recover crash-orphan threads from a previous process,
//! 6. start the local [`Scheduler`] (fires crons → pending threads + `cron_state`),
//! 7. start the **executor worker** (drains pending threads, flushes the outbox),
//! 8. **serve**: route inbound frames to the executor / scheduler / config.
//!
//! ## Two planes, one runtime
//!
//! The scheduler (scheduling plane) and the executor (result plane) communicate
//! only through the DB: a fire inserts a `pending` thread and enqueues `cron_state`,
//! then nudges the [`Scheduler::drain_signal`]; the **executor worker** wakes on
//! that nudge (or a bounded poll), drains every `pending` thread via the
//! [`ThreadExecutor`], and pokes the transport's [`flush`](Transport::flush_handle)
//! so the freshly-enqueued result-plane frames stream out over the live socket.
//!
//! The runner is **autonomous and offline-tolerant**: the scheduler keeps firing
//! and the executor keeps draining while the orchestrator is unreachable; result
//! frames persist in the at-least-once outbox and replay on reconnect. The
//! transport drives its own heartbeat and reconnect.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::TimeDelta;
use futures_util::FutureExt as _;
use futures_util::future::OptionFuture;
use tokio::sync::{Notify, mpsc};
use tracing::{debug, error, info, warn};

use crate::agent_api::{self, AgentApiServer, ApiContext};
use crate::attachment_source::DbAttachmentSource;
use crate::attachments::{self, AttachmentManager, AttachmentSource};
use crate::chat::{
    InboxPromptSource, drain_with_queued_messages, ensure_chat_thread, minted_thread_id,
    seed_task_if_missing,
};
use crate::config::{Config, ConfigOverlay, ExecutorConfig};
use crate::db::{Db, TaskRow, ThreadRow};
use crate::e2ee::{self, E2ee, E2eeKeys};
use crate::engine::admin::{self, EngineInfo, EngineKind};
use crate::engine::claude::{ClaudeEngine, ClaudeSettings};
use crate::engine::codex::{self, CodexEngine, CodexSettings};
use crate::engine::{Engine, EngineError, Session, SessionCfg};
use crate::executor::{ThreadExecutor, WatchdogCfg};
use crate::memory;
use crate::protocol::frames::{CronUpsertData, InboundFrame, ProvisioningEntry, TaskUpsertData};
use crate::provisioning::{BlobFetcher, Provisioner};
use crate::register::{self, ResolvedIdentity};
use crate::remote_ops::RemoteOps;
use crate::sandbox;
use crate::scheduler::{Cancel, Scheduler, apply_cron_delete, apply_cron_upsert, now, to_iso};
use crate::transport::http::HttpClient;
use crate::transport::{DsLink, Inbound, MAX_INBOX_RETRIES, Transport, TransportConfig};

/// Safety-net cadence for the executor worker when no drain nudge arrives — picks
/// up freshly-pending threads and flushes any outbox rows the host has not yet
/// acked.
const WORKER_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Bounded graceful drain at shutdown: how long the executor worker gets
/// to settle the interrupted active run (post-interrupt drain, output collection,
/// finalize) before it is aborted and the leftover engine session killed.
/// Comfortably above the executor's in-run `cancel_drain_timeout` and inside
/// systemd's default `TimeoutStopSec` (90 s).
const SHUTDOWN_DRAIN_WINDOW: Duration = Duration::from_secs(15);

/// Lockfile inside the (0700-hardened) workspace dir backing the daemon's
/// single-instance flock.
const DAEMON_LOCK_FILE: &str = "agent.lock";

/// The daemon's single-instance guard: an exclusive advisory
/// lock (`flock`-style, via [`std::fs::File::try_lock`]) on a lockfile in the
/// state dir, held for the daemon's whole lifetime and released by the OS on
/// any exit, clean or not. A second daemon fails fast instead of racing the
/// first over migrations and thread claims. CLI subcommands never take this
/// lock — they are short-lived readers/writers of the shared WAL DB.
#[derive(Debug)]
struct DaemonLock {
    /// The open lockfile handle; dropping it releases the lock.
    _file: std::fs::File,
}

/// Acquire the exclusive daemon lock, failing fast (no blocking wait) when
/// another process — or another handle in this one — already holds it. The
/// lock is advisory and per open-file-description, so it works across
/// processes and is testable with two handles in one.
fn acquire_daemon_lock(workspace_dir: &Path) -> Result<DaemonLock> {
    let path = workspace_dir.join(DAEMON_LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("opening daemon lockfile {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(DaemonLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(anyhow::anyhow!(
            "another gino-agent daemon is already running (exclusive lock on {} is held); \
             stop it before starting a new one",
            path.display()
        )),
        Err(std::fs::TryLockError::Error(err)) => {
            Err(err).with_context(|| format!("locking daemon lockfile {}", path.display()))
        }
    }
}

/// Create the DB/workspace directories, then restrict the workspace to
/// owner-only (`0700`): it holds the DB (connect token), engine work dirs and
/// the provisioning store. Hardening runs on every startup so pre-existing
/// world-readable deployments are healed, not only fresh installs.
fn prepare_state_dirs(paths: &crate::config::Paths) -> Result<()> {
    if let Some(parent) = paths.db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating db directory {}", parent.display()))?;
    }
    std::fs::create_dir_all(&paths.workspace_dir).with_context(|| {
        format!(
            "creating workspace directory {}",
            paths.workspace_dir.display()
        )
    })?;
    crate::db::harden_state_dir(&paths.workspace_dir).with_context(|| {
        format!(
            "hardening workspace directory permissions {}",
            paths.workspace_dir.display()
        )
    })?;
    Ok(())
}

/// Resolve the env/CLI bootstrap layer: the host/identity
/// inputs, then the local paths from the environment (`GINO_WORKSPACE_DIR` /
/// `GINO_DB_PATH` / `CLAUDE_CONFIG_USE_DEFAULT`, see
/// [`ConfigOverlay::paths_from_env`]) — resolved *before* the DB opens so ops or
/// the e2e harness can relocate local state off the default mount — and
/// finally the local engine credential stored by `gino-agent login`
/// (`{workspace}/claude-oauth-token`), if any. All of this sits BELOW the host
/// layers (register / config refresh / `config_update`), which still override per
/// the normal precedence — a host-supplied credential wins over the local token.
fn bootstrap_config(
    host: Option<String>,
    register_token: Option<String>,
    name: Option<String>,
) -> Result<Config> {
    let mut config = Config::default();
    config.apply(ConfigOverlay::bootstrap(host, register_token, name));
    config.apply(ConfigOverlay::paths_from_env()?);
    config.validate()?;
    if let Some(token) = crate::login::read_token(&config.paths.workspace_dir) {
        info!("engine auth: using the local Claude OAuth token from `gino-agent login`");
        config.apply(ConfigOverlay::local_engine_oauth_token(token));
    }
    Ok(config)
}

/// Build the tokio runtime and drive the daemon to completion. Kept sync so the
/// CLI dispatcher in [`crate`] stays sync.
pub(crate) fn run_daemon(
    host: Option<String>,
    register_token: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(run_async(host, register_token, name))
}

/// Resolve config → register → connect → start scheduler + executor → serve.
#[allow(clippy::too_many_lines)] // the daemon's linear startup/shutdown sequence
async fn run_async(
    host: Option<String>,
    register_token: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let mut config = bootstrap_config(host, register_token, name)?;

    prepare_state_dirs(&config.paths)?;

    // Single-instance guard, taken BEFORE the DB open so a second
    // daemon can never run migrations — let alone claim threads — against a
    // live instance's database. Held (via the binding) until run_async returns.
    let _daemon_lock = acquire_daemon_lock(&config.paths.workspace_dir)?;

    let db = Db::open(&config.paths.db_path)
        .with_context(|| format!("opening db at {}", config.paths.db_path.display()))?;
    let http = HttpClient::new().context("building the HTTP client")?;

    // Registration advertises the e2ee identity, so the keys load first.
    let e2ee_keys = E2eeKeys::load_or_create(&e2ee::state_dir(&config.paths.db_path))
        .context("loading the e2ee keys")?;
    info!(fingerprint = %e2ee_keys.fingerprint(), "e2ee identity key");
    let e2ee_capability = e2ee_keys.capability();

    // Probed once: register and every heartbeat advertise the same list.
    let vm = config
        .engine
        .isolation_floor
        .as_ref()
        .and_then(|floor| floor.vm.as_ref());
    let capabilities = register::capabilities(&config, sandbox::probe(vm));
    info!(capabilities = ?capabilities, "runner capabilities");
    // `--version` of a stuck engine must not hold up startup.
    let engines = Arc::new(std::sync::OnceLock::new());
    {
        let engines = Arc::clone(&engines);
        let workspace = config.paths.workspace_dir.clone();
        let codex = config.engine.codex.binary.clone();
        tokio::task::spawn_blocking(move || {
            let report = engine_report(&workspace, codex.as_deref());
            info!(engines = ?report, "engines");
            let _ = engines.set(report);
        });
    }
    let identity = register::load_or_register(
        &mut config,
        &db,
        &http,
        &capabilities,
        Some(&e2ee_capability),
    )
    .await
    .context("resolving runner identity")?;
    info!(agent_id = %identity.agent_id, "runner identity resolved");

    // 7 (A): authoritative startup config fetch. On a restart the runner
    // reuses its persisted identity (no second register), so `GET /agent/config` —
    // not the register response — re-supplies the versioned desired set the version
    // gate reads (see [`fetch_and_apply_config`]). Non-fatal / offline-tolerant.
    fetch_and_apply_config(&mut config, &identity, &http).await;

    let ws_url = config.ws_url(&identity.agent_id)?;
    let db = Arc::new(Mutex::new(db));
    let (e2ee_live_tx, e2ee_live_rx) = mpsc::unbounded_channel();
    let e2ee_ds = Arc::new(DsLink::default());
    let transport_config = TransportConfig {
        heartbeat: Duration::from_millis(config.heartbeat_interval_ms),
        capabilities,
        engines,
        e2ee: Some(e2ee_capability),
        e2ee_live: Some(e2ee_live_tx),
        e2ee_ds: Some(Arc::clone(&e2ee_ds)),
        ..TransportConfig::default()
    };
    // The dial happens in the background: the daemon boots and serves
    // local work while the host is unreachable; outbound frames queue durably
    // and replay once a connection is up.
    let remote_ops = build_remote_ops(&config, &http);
    let mut transport = Transport::open(
        ws_url,
        identity.connect_token,
        Arc::clone(&db),
        transport_config,
        Arc::clone(&remote_ops),
    );
    info!("transport started; connecting in the background");

    let e2ee = Arc::new(
        E2ee::new(
            e2ee_keys,
            Arc::clone(&db),
            transport.flush_handle(),
            e2ee_ds,
        )
        .context("loading the e2ee state")?,
    );
    e2ee.publish_initial();
    tokio::spawn(Arc::clone(&e2ee).run(e2ee_live_rx));

    // The GLOBAL provisioning scope root. Created up front so the
    // engine always launches with a stable config dir — even with no entries.
    let engine_config_dir = config.paths.engine_config_dir.clone();
    info!(dir = %engine_config_dir.display(), "engine config dir (CLAUDE_CONFIG_DIR for the engine)");
    std::fs::create_dir_all(&engine_config_dir).with_context(|| {
        format!(
            "creating engine config directory {}",
            engine_config_dir.display()
        )
    })?;

    // One shutdown token for every plane: the serve loop, the scheduler,
    // the executor worker AND the active engine run (via the executor's converged
    // cancel path) all watch this token, so a shutdown signal cancels an in-flight
    // turn instead of waiting out its running_timeout.
    let cancel = Arc::new(Cancel::new());

    // The v2 execution plane: the source-agnostic pending-thread drainer, its
    // out-of-band attachment plane (Lane Z1) and the global config/skills
    // provisioner — all over one shared content-addressed manager — then
    // the startup global reconcile. A resolved message's inbound descriptors reach
    // the executor through the durable `thread_attachments` snapshot (P1-10b).
    let flush = transport.flush_handle();
    // One retry budget for every thread source (cron fires + chat messages).
    let max_attempts = config.executor.max_attempts;
    let scheduler = Scheduler::new(
        Arc::clone(&db),
        Arc::clone(&cancel),
        max_attempts,
        config.retention.days,
    );
    let (nudge, drain) = (scheduler.nudge(), scheduler.drain_signal());
    // Listen for the shutdown signals before the agent API socket appears: a
    // signal during the rest of startup then neither kills the daemon past its
    // cleanup nor goes unseen by the serve loop.
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let _ = shutdown.as_mut().now_or_never();
    // Started before the executor so runs can be handed its token registry.
    let api = start_agent_api(&config, &db, &nudge, &flush, &e2ee);
    let (executor, provisioner, seams) = build_execution_plane(
        &config,
        &http,
        &db,
        &engine_config_dir,
        &cancel,
        Arc::clone(&flush),
        api.as_ref(),
        &e2ee,
    )
    .await;
    let prompts = Arc::new(InboxPromptSource {
        db: Arc::clone(&db),
    });

    // Crash recovery: any thread left `dispatched`/`running`/`active` by a previous
    // process has no live driver — fail it `runner.runtime_offline` (retryable, so
    // it re-pends and re-runs on this process).
    let recovered = executor.fail_offline(&in_flight_threads(&db));
    if recovered > 0 {
        info!(recovered, "recovered crash-orphan threads at startup");
    }

    let scheduler_task = tokio::spawn(scheduler.run());

    let worker = tokio::spawn(run_worker(
        Arc::clone(&executor),
        Arc::clone(&db),
        Arc::clone(&prompts),
        Arc::clone(&drain),
        Arc::clone(&flush),
        Arc::clone(&cancel),
        max_attempts,
    ));
    info!("scheduler + executor running; serving inbound/outbound frames");

    let context = ServeContext {
        executor: Arc::clone(&executor),
        db: Arc::clone(&db),
        nudge,
        drain: Arc::clone(&drain),
        chat_max_attempts: max_attempts,
        provisioner,
        engine_config_dir,
        config: Mutex::new(config),
        engine_settings: seams.claude,
        codex_settings: seams.codex,
        remote_ops,
        e2ee,
    };
    serve(&mut transport, &context, &cancel, shutdown).await;

    OptionFuture::from(api.map(AgentApiServer::shutdown)).await;
    // Shutdown: drain the execution plane within a bounded window (the
    // active run is cancelled, not waited out), stop the scheduler, fail any
    // leftover in-flight threads (so the host sees a terminal result rather than
    // a silent gap), then drain the transport. No engine child survives this.
    shutdown_worker(&cancel, &executor, worker, SHUTDOWN_DRAIN_WINDOW).await;
    if scheduler_task.await.is_err_and(|err| err.is_panic()) {
        warn!("scheduler task panicked during shutdown");
    }
    let failed = executor.fail_offline(&in_flight_threads(&db));
    if failed > 0 {
        info!(failed, "failed in-flight threads on shutdown");
    }
    flush.notify_one(); // best-effort live flush; durable rows replay on next connect
    transport.shutdown().await;
    info!("gino-agent stopped");
    Ok(())
}

/// Serve the local agent API under the workspace. A failure is logged and the
/// daemon carries on without it.
fn start_agent_api(
    config: &Config,
    db: &Arc<Mutex<Db>>,
    nudge: &Arc<Notify>,
    flush: &Arc<Notify>,
    e2ee: &Arc<E2ee>,
) -> Option<AgentApiServer> {
    let ctx = ApiContext {
        db: Arc::clone(db),
        nudge: Arc::clone(nudge),
        flush: Arc::clone(flush),
        e2ee: Some(Arc::clone(e2ee)),
        agent_name: config.agent_name.clone(),
        host_url: config.host_url.clone(),
        workspace_dir: config.paths.workspace_dir.clone(),
        db_path: config.paths.db_path.clone(),
    };
    match AgentApiServer::start(ctx, &config.paths.workspace_dir) {
        Ok(server) => {
            info!(
                socket = %agent_api::socket_path(&config.paths.workspace_dir).display(),
                "local agent API listening"
            );
            Some(server)
        }
        Err(err) => {
            error!(
                error = format!("{err:#}"),
                "starting the local agent API failed; continuing without it"
            );
            None
        }
    }
}

/// Stop the execution plane within a bounded drain window: trip the
/// shutdown token (stops the worker loop and, through the executor's converged
/// cancel path, the active run), gracefully interrupt the running engine turn
/// (the same [`ThreadExecutor::interrupt`] machinery a host `interrupt` frame
/// uses), then await the worker. A worker that has not settled when the window
/// closes is aborted, and any leftover engine session is dropped — killing the
/// engine child (`kill_on_drop`) — so no engine process survives the daemon.
async fn shutdown_worker(
    cancel: &Cancel,
    executor: &ThreadExecutor,
    mut worker: tokio::task::JoinHandle<()>,
    window: Duration,
) {
    cancel.cancel();
    executor.interrupt().await;
    match tokio::time::timeout(window, &mut worker).await {
        Ok(joined) => {
            if joined.is_err_and(|err| err.is_panic()) {
                warn!("executor worker panicked during shutdown");
            }
        }
        Err(_elapsed) => {
            warn!("executor worker did not settle within the shutdown drain window; aborting it");
            worker.abort();
            let _ = worker.await;
        }
    }
    executor.kill_active().await;
}

/// The executor worker: drains every `pending` thread on each scheduler/route
/// nudge (or a bounded poll), runs a periodic stale-thread reap, then pokes the
/// transport flush so the result-plane frames the drain enqueued stream out.
async fn run_worker(
    executor: Arc<ThreadExecutor>,
    db: Arc<Mutex<Db>>,
    prompts: Arc<InboxPromptSource>,
    drain: Arc<Notify>,
    flush: Arc<Notify>,
    cancel: Arc<Cancel>,
    chat_max_attempts: i64,
) {
    loop {
        // Register drain interest before draining so a fire that lands mid-drain
        // still wakes the next pass.
        let nudged = drain.notified();
        tokio::pin!(nudged);
        nudged.as_mut().enable();
        tokio::select! {
            () = cancel.cancelled() => break,
            () = &mut nudged => {}
            () = tokio::time::sleep(WORKER_POLL_INTERVAL) => {}
        }
        if cancel.is_cancelled() {
            break;
        }

        // Watchdog reap runs between drains — the drainer is serial, so no thread is
        // live here and there is nothing to race. Live runs are bounded by the
        // in-run watchdog inside [`ThreadExecutor::drive`].
        executor.reap_stale(&in_flight_threads(&db));
        drain_with_queued_messages(&executor, &db, prompts.as_ref(), chat_max_attempts).await;
        flush.notify_one();
    }
    debug!("executor worker stopped");
}

/// The in-flight threads (`dispatched` + `running`) — the crash-orphan recovery /
/// watchdog candidate set (agent-architecture §5). A `pending` thread re-runs on
/// its own; an `active` thread is *resting* between shared-turn runs (not in
/// flight), so it is deliberately excluded — failing it would spuriously re-run it.
fn in_flight_threads(db: &Mutex<Db>) -> Vec<ThreadRow> {
    let guard = lock_db(db);
    let mut rows = guard
        .list_threads_by_status("dispatched")
        .unwrap_or_default();
    rows.extend(guard.list_threads_by_status("running").unwrap_or_default());
    rows
}

/// Map the [`ExecutorConfig`] knobs onto the executor's watchdog thresholds. A
/// zero `inactivity_timeout_secs` disables the in-run inactivity watchdog only —
/// the total-time watchdog still bounds a silent engine on wall clock,
/// so the serial plane can never wedge indefinitely.
fn watchdog_cfg(cfg: &ExecutorConfig) -> WatchdogCfg {
    WatchdogCfg {
        dispatched_timeout: TimeDelta::seconds(cfg.dispatched_timeout_secs),
        running_timeout: TimeDelta::seconds(cfg.running_timeout_secs),
        inactivity_timeout: (cfg.inactivity_timeout_secs > 0)
            .then(|| Duration::from_secs(cfg.inactivity_timeout_secs)),
        ..WatchdogCfg::default()
    }
}

/// 7 (A): fetch the authoritative config from `GET /agent/config/:id` and
/// merge it onto `config`. The payload is the same host-assigned overlay the register
/// response carries (engine credentials, limits, the versioned global provisioning
/// set, …); fetching it at startup is what lets a **restart** re-acquire that config
/// without a second registration. Non-fatal and offline-tolerant: an unbuildable URL,
/// a transport/HTTP failure, or an unparseable payload is logged and the prior
/// (register/bootstrap) config stands — and `config.config_version` stays `None`,
/// which the reconcile version gate treats as non-authoritative (repair-only, never
/// wipe).
async fn fetch_and_apply_config(
    config: &mut Config,
    identity: &ResolvedIdentity,
    http: &HttpClient,
) {
    let url = match config.config_url(&identity.agent_id) {
        Ok(url) => url,
        Err(err) => {
            debug!(error = %err, "no config url; skipping startup config fetch");
            return;
        }
    };
    let mut value = match http.fetch_config(&url, &identity.connect_token).await {
        Ok(value) => value,
        Err(err) => {
            warn!(error = %err, "startup config fetch failed; keeping register/bootstrap config (offline-tolerant)");
            return;
        }
    };
    // The config refresh may echo `protocolVersion` (as the register response does);
    // strip it so the strict (`deny_unknown_fields`) overlay parse stays happy.
    // Protocol negotiation already happened at register; the overlay's own `version`
    // field is the unrelated GLOBAL config version the reconcile gate reads.
    if let Some(obj) = value.as_object_mut() {
        obj.remove("protocolVersion");
    }
    match serde_json::from_value::<ConfigOverlay>(value) {
        Ok(overlay) => {
            info!(version = ?overlay.version(), "startup config fetched and applied");
            config.apply(overlay);
        }
        Err(err) => {
            warn!(error = %err, "startup config payload did not parse; keeping register/bootstrap config");
        }
    }
}

/// Build the full execution plane over ONE shared content-addressed manager:
/// the [`ThreadExecutor`] (+ its attachment plane), the global
/// config/skills [`Provisioner`], and the startup global reconcile. The manager is
/// built once and shared between both planes so bytes are fetched + cached once; a
/// `None` manager (absent host base / connect token) degrades both planes off. The
/// returned provisioner is `None` in that same degraded case. The startup reconcile
/// (repair → reconcile(global) → gc) is non-fatal — see [`reconcile_global_startup`].
/// Also returns the live engine-settings seam the executor's engine
/// snapshots at every spawn, so the `config_update` route can replace its contents.
#[allow(
    clippy::too_many_arguments,
    reason = "one handle per plane the executor is wired onto"
)]
async fn build_execution_plane(
    config: &Config,
    http: &HttpClient,
    db: &Arc<Mutex<Db>>,
    engine_config_dir: &Path,
    shutdown: &Arc<Cancel>,
    flush: Arc<Notify>,
    api: Option<&AgentApiServer>,
    e2ee: &Arc<E2ee>,
) -> (Arc<ThreadExecutor>, Option<Arc<Provisioner>>, EngineSeams) {
    let seams = EngineSeams {
        claude: Arc::new(Mutex::new(engine_settings(config, engine_config_dir))),
        codex: Arc::new(Mutex::new(codex_settings(config, engine_config_dir))),
    };
    let manager = build_attachment_manager(config, http);

    // The shared content-addressed provisioner over the manager (`impl BlobFetcher
    // for AttachmentManager`), reusing the SAME cache as the attachment plane. Built
    // before the executor so the one handle drives BOTH the global startup reconcile
    // (below) and the per-thread task scope (wired into the executor next).
    let provisioner = manager.clone().map(|manager| {
        let fetcher: Arc<dyn BlobFetcher> = manager;
        Arc::new(Provisioner::new(
            config.paths.workspace_dir.clone(),
            Arc::clone(db),
            fetcher,
        ))
    });

    let executor = build_executor(
        config,
        Arc::clone(db),
        &seams,
        manager,
        provisioner.clone(),
        Arc::clone(shutdown),
        flush,
    )
    .with_e2ee(Arc::clone(e2ee));
    // Per-run API tokens; without the API, runs get none.
    let executor = Arc::new(match api {
        Some(api) => executor.with_agent_api(
            api.registry(),
            agent_api::socket_path(&config.paths.workspace_dir),
        ),
        None => executor,
    });

    if let Some(provisioner) = &provisioner {
        reconcile_global_startup(
            provisioner,
            db,
            engine_config_dir,
            &config.entries,
            config.config_version,
        )
        .await;
    }
    (executor, provisioner, seams)
}

/// Build the v2 [`ThreadExecutor`] and (when present) wire its out-of-band
/// attachment plane (Lane Z1) onto the shared `manager`. The inbound
/// descriptors reach the executor through a [`DbAttachmentSource`] over the
/// durable `thread_attachments` snapshot the prompt drainer writes (the message
/// is consumed before materialization, and retries/restarts must resolve the
/// same set — P1-10b; see [`crate::attachment_source`]). The plane is non-fatal:
/// a `None` manager (absent host base / connect token) leaves attachments off
/// and the executor behaves as before.
fn build_executor(
    config: &Config,
    db: Arc<Mutex<Db>>,
    seams: &EngineSeams,
    manager: Option<Arc<AttachmentManager>>,
    provisioner: Option<Arc<Provisioner>>,
    shutdown: Arc<Cancel>,
    flush: Arc<Notify>,
) -> ThreadExecutor {
    let engine: Arc<dyn Engine> = Arc::new(ReloadableEngine {
        settings: Arc::clone(&seams.claude),
    });
    // The daemon shutdown token: a shutdown cancels the active run through
    // the executor's converged cancel path and stops the pending drain. The
    // transport flush signal: the executor pokes it after each persisted
    // frame so transcript events stream mid-run over the live socket.
    let mut executor = ThreadExecutor::new(
        engine,
        Arc::clone(&db),
        config.paths.workspace_dir.clone(),
        watchdog_cfg(&config.executor),
    )
    .with_shutdown(shutdown)
    .with_flush(flush)
    .with_agent_memory_access(config.memory.agent_access)
    .with_task_memory(config.memory.task)
    .with_conversations_max_bytes(config.memory.conversations_max_bytes);
    // The second backend, registered ONLY when its binary is actually there.
    // DECISION: registration and the advertised capability (`register.rs`) are
    // gated on the SAME probe, so the host is never told this runner can run an
    // engine it cannot spawn. A task that names `codex` on a runner without the
    // binary still runs: the registry warns about the unknown name and falls back
    // to the default backend, which is the existing forward-compat policy rather
    // than a new failure mode. The probe runs ONCE, here at build time: a later
    // `config_update` that points codex at a binary this runner does not have yet
    // reaches the seam but not the registry, so it takes effect on restart.
    let codex_binary = lock(&seams.codex).binary.clone();
    if codex::is_available(&codex_binary) {
        info!(binary = %codex_binary.display(), "codex engine available; registered");
        executor = executor.with_engine(Arc::new(ReloadableCodexEngine {
            settings: Arc::clone(&seams.codex),
        }));
    } else {
        debug!(binary = %codex_binary.display(), "codex binary not found; codex engine not registered");
    }
    if let Some(manager) = manager {
        info!("attachment plane active (host-proxy byte backend)");
        let source: Arc<dyn AttachmentSource> = Arc::new(DbAttachmentSource::new(db));
        executor = executor.with_attachments(manager, source);
    } else {
        debug!("attachment plane disabled (no host base / connect token)");
    }
    // Per-thread task provisioning: materialize the task scope
    // into `work_dir/project/` and run the engine there. Shares the same handle
    // (and cache) as the global startup reconcile; `None` keeps cwd = `work_dir`.
    if let Some(provisioner) = provisioner {
        info!("task provisioning plane active (per-thread project/ scope)");
        executor = executor.with_provisioning(provisioner);
    } else {
        debug!("task provisioning plane disabled (no host base / connect token)");
    }
    executor
}

/// Resolve the Claude engine settings from the config, exporting the workspace
/// dir (`GINO_WORKSPACE_DIR`, read by the PreCompact `archive` hook subprocess)
/// and pointing the engine at the provisioned global config dir on
/// top of the credential env. Rebuilt on a live `config_update` so
/// a rotated credential reaches the next engine run without a restart.
fn engine_settings(config: &Config, engine_config_dir: &Path) -> ClaudeSettings {
    let mut settings = ClaudeSettings::from_config(config);
    settings.env.push((
        "GINO_WORKSPACE_DIR".to_owned(),
        config.paths.workspace_dir.display().to_string(),
    ));
    // Launch the engine reading the global instruction file + skills the runner
    // materialized; `ClaudeSettings` exports `ENGINE_CONFIG_DIR`/`CLAUDE_CONFIG_DIR`.
    settings.config_dir = Some(engine_config_dir.to_path_buf());
    settings
}

/// The live engine-settings seam: the executor's engine snapshots
/// these settings at every spawn, and the `config_update` route replaces them
/// after merging the overlay onto the live [`Config`] — so a rotated
/// `anthropicApiKey` takes effect without a daemon restart.
type SharedEngineSettings = Arc<Mutex<ClaudeSettings>>;

/// An [`Engine`] over the [`SharedEngineSettings`] seam: each call snapshots the
/// current settings and delegates to a [`ClaudeEngine`] built from that snapshot.
/// Decision (protocol.md leaves `config_update` apply semantics open):
/// APPLY-ON-NEXT-RUN — a session already spawned keeps the environment it was
/// born with; only the next spawn reads the updated settings. A mid-flight run
/// is never hot-swapped.
#[derive(Debug)]
struct ReloadableEngine {
    settings: SharedEngineSettings,
}

#[async_trait]
impl Engine for ReloadableEngine {
    fn name(&self) -> &'static str {
        "claude"
    }

    async fn start_session(&self, cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError> {
        self.snapshot().start_session(cfg).await
    }
}

impl ReloadableEngine {
    /// A [`ClaudeEngine`] over the settings as they stand right now.
    fn snapshot(&self) -> ClaudeEngine {
        ClaudeEngine::new(lock(&self.settings).clone())
    }
}

/// Resolve the Codex engine settings from the config, the codex twin of
/// [`engine_settings`]: the `engine.codex` block plus the workspace dir
/// (`GINO_WORKSPACE_DIR`) and the provisioned global config dir, which
/// [`CodexSettings`] exports as `ENGINE_CONFIG_DIR` + codex's own `CODEX_HOME`
/// (where the claude side exports `CLAUDE_CONFIG_DIR`). Rebuilt on a live
/// `config_update` so a rotated `openaiApiKey` reaches the next run.
fn codex_settings(config: &Config, engine_config_dir: &Path) -> CodexSettings {
    let mut settings = CodexSettings::from_config(config);
    settings.env.push((
        "GINO_WORKSPACE_DIR".to_owned(),
        config.paths.workspace_dir.display().to_string(),
    ));
    settings.config_dir = Some(engine_config_dir.to_path_buf());
    settings
}

/// The live codex-settings seam, the codex twin of [`SharedEngineSettings`]: one
/// seam per backend, both replaced on `config_update`.
type SharedCodexSettings = Arc<Mutex<CodexSettings>>;

/// Both live engine-settings seams, one per backend, carried together so the
/// execution plane hands them around as one value.
#[derive(Clone, Debug)]
struct EngineSeams {
    claude: SharedEngineSettings,
    codex: SharedCodexSettings,
}

/// An [`Engine`] over the [`SharedCodexSettings`] seam, mirroring
/// [`ReloadableEngine`]: each spawn snapshots the current settings and delegates
/// to a [`CodexEngine`] built from that snapshot. Same APPLY-ON-NEXT-RUN
/// decision — a session already spawned keeps the environment it was born with,
/// and with one turn per codex process that boundary is simply the next turn.
#[derive(Debug)]
struct ReloadableCodexEngine {
    settings: SharedCodexSettings,
}

#[async_trait]
impl Engine for ReloadableCodexEngine {
    fn name(&self) -> &'static str {
        "codex"
    }

    async fn start_session(&self, cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError> {
        self.snapshot().start_session(cfg).await
    }
}

impl ReloadableCodexEngine {
    /// A [`CodexEngine`] over the settings as they stand right now.
    fn snapshot(&self) -> CodexEngine {
        CodexEngine::new(lock(&self.settings).clone())
    }
}

/// The engines the runner starts and their versions, as heartbeats report them.
fn engine_report(workspace: &Path, codex: Option<&Path>) -> Vec<EngineInfo> {
    let claude = admin::resolve_binary(workspace, EngineKind::Claude, None);
    let codex = admin::resolve_binary(workspace, EngineKind::Codex, codex);
    let path_env = std::env::var_os("PATH");
    admin::report(
        [
            (EngineKind::Claude, claude.as_path()),
            (EngineKind::Codex, codex.as_path()),
        ],
        path_env.as_deref(),
    )
}

/// Build the engine-free operations handle. Its file transfers get their own
/// [`AttachmentManager`]: they stream straight to and from the destination and
/// never touch the content-addressed cache.
fn build_remote_ops(config: &Config, http: &HttpClient) -> Arc<RemoteOps> {
    let remote_ops = RemoteOps::new(config.remote_ops.fs, &config.paths.workspace_dir);
    remote_ops.configure(
        config.remote_ops.fs,
        config.remote_ops.pty,
        &config.paths.workspace_dir,
    );
    remote_ops.set_byte_channel(build_attachment_manager(config, http));
    Arc::new(remote_ops)
}

/// Build the shared content-addressed [`AttachmentManager`] (agent-
/// architecture §9): the config-selected byte backend
/// ([`attachments::build_backend`] — host-proxy by default) over a workspace-scoped
/// cache. ONE manager backs both the executor's attachment plane and the config/
/// skills [`Provisioner`], so bytes are fetched and cached once. Returns `None`
/// (both planes degrade off) when the host base or connect token the byte backend
/// needs is unavailable; post-registration both are present, so it is `Some`.
fn build_attachment_manager(config: &Config, http: &HttpClient) -> Option<Arc<AttachmentManager>> {
    let connect_token = config.connect_token.clone()?;
    let http_base = match config.http_base() {
        Ok(base) => base.to_owned(),
        Err(err) => {
            debug!(error = %err, "no host base; attachment/provisioning planes disabled");
            return None;
        }
    };
    let backend =
        attachments::build_backend(&config.attachments, http.clone(), http_base, connect_token);
    let manager = AttachmentManager::new(
        backend,
        &config.paths.workspace_dir,
        config.attachments.clone(),
    );
    Some(Arc::new(manager))
}

/// Run the **version-gated** startup global provisioning sequence.
///
/// The host owns a monotonic GLOBAL config `version` scoping the desired `entries`
/// set; the runner reconciles the global scope ONLY when that version advances past
/// the persisted applied version. This is the restart-durability fix: on a restart
/// the runner reuses its persisted identity (no second register), so the register
/// response no longer carries the desired set — but the §A startup fetch re-supplies
/// the SAME version, which now takes the repair-only path instead of the old
/// unconditional `reconcile("global", &config.entries)` that wiped every global
/// symlink + row (because `config.entries` was empty on a restart) and then let `gc`
/// collect the orphaned store.
///
/// * **authoritative new** — `fetched` is `Some` and `> applied` (incl. the first
///   versioned set, when `applied` is `None`): reconcile the global scope to
///   `entries` — add / repoint / **delete** to match the desired set, *including
///   removing all when `entries` is empty* (the authoritative-empty case: a versioned
///   empty set means the host genuinely wants none). The applied version is persisted
///   only after a SUCCESSFUL reconcile, so a transient failure re-reconciles on the
///   next restart rather than being masked as already-applied.
/// * **same version** (`fetched == applied`) or **non-authoritative** (`fetched` is
///   `None` — no version served / fetch failed / offline): NEVER reconcile-to-empty.
///   The installed set is left intact.
///
/// `repair` and `gc` run in **every** branch — `repair` recreates symlinks a restart
/// lost from the persisted manifest (the only self-heal in the repair-only branches),
/// and `gc` refcounts the whole store against the manifest (safe everywhere: a
/// repair-only branch leaves rows intact, so nothing referenced is collected). Each
/// step is non-fatal — a failure is logged and the daemon proceeds.
async fn reconcile_global_startup(
    provisioner: &Provisioner,
    db: &Mutex<Db>,
    engine_config_dir: &Path,
    entries: &[ProvisioningEntry],
    fetched_version: Option<i64>,
) {
    let applied = lock_db(db)
        .get_applied_global_version()
        .unwrap_or_else(|err| {
            warn!(error = %err, "failed to read applied global config version; treating as unset");
            None
        });
    // Authoritative-new ⇔ a version is served AND it advances past what we applied
    // (an absent applied version is the never-reconciled / fresh-DB case).
    let authoritative_new =
        matches!(fetched_version, Some(fetched) if applied.is_none_or(|a| fetched > a));

    let mut reconciled_ok = false;
    if authoritative_new {
        match provisioner
            .reconcile("global", engine_config_dir, entries)
            .await
        {
            Ok(()) => {
                reconciled_ok = true;
                info!(
                    entries = entries.len(),
                    version = ?fetched_version,
                    "global provisioning reconciled to new config version"
                );
            }
            Err(err) => {
                warn!(error = %err, "startup global reconcile failed (continuing; version not marked applied)");
            }
        }
    } else {
        // The restart-durability invariant: same version (or no authoritative version
        // at all) ⇒ keep the installed set; repair below still self-heals a lost link.
        debug!(
            applied = ?applied,
            fetched = ?fetched_version,
            "global config version not advanced; repair-only (no reconcile, store-durable)"
        );
    }

    if let Err(err) = provisioner.repair().await {
        warn!(error = %err, "startup provisioning repair failed (continuing)");
    }

    // Persist the applied version only after a successful reconcile of the new set, so
    // a subsequent restart at the same version takes the repair-only path.
    if reconciled_ok
        && let Some(fetched) = fetched_version
        && let Err(err) = lock_db(db).set_applied_global_version(fetched)
    {
        warn!(error = %err, "failed to persist applied global config version");
    }

    if let Err(err) = provisioner.gc().await {
        warn!(error = %err, "startup provisioning gc failed (continuing)");
    }
}

/// Shared handles the serve loop hands to the inbound router.
struct ServeContext {
    executor: Arc<ThreadExecutor>,
    db: Arc<Mutex<Db>>,
    /// Wakes the scheduler after a trigger-definition change.
    nudge: Arc<Notify>,
    /// Wakes the executor worker after a chat message creates a pending thread.
    drain: Arc<Notify>,
    /// Retry budget stamped on executor-created (chat) threads.
    chat_max_attempts: i64,
    /// Global config/skills provisioner; `None` when the byte backend
    /// is absent, in which case `config_update` provisioning is a no-op.
    provisioner: Option<Arc<Provisioner>>,
    /// The global scope root the provisioner materializes into (= the engine's
    /// `ENGINE_CONFIG_DIR`), re-reconciled live on `config_update`.
    engine_config_dir: PathBuf,
    /// The merged live config. A WS `config_update` overlay lands here (the last
    /// layer of the config.rs precedence chain) and drives the engine-settings
    /// rebuild below.
    config: Mutex<Config>,
    /// The live engine-settings seam: replaced on `config_update`,
    /// snapshotted by [`ReloadableEngine`] at every engine spawn.
    engine_settings: SharedEngineSettings,
    /// The codex twin of [`ServeContext::engine_settings`], snapshotted by
    /// [`ReloadableCodexEngine`]. Held whether or not the backend was registered,
    /// so the seam stays in step with the live config either way.
    codex_settings: SharedCodexSettings,
    /// Follows the live config: a `config_update` can switch a group on or off.
    remote_ops: Arc<RemoteOps>,
    /// All e2ee state; receives the durable DS records.
    e2ee: Arc<E2ee>,
}

/// Resolve when a daemon shutdown signal arrives: SIGINT (Ctrl-C) and —
/// on unix — SIGTERM (what systemd `stop`/`restart` sends) are handled
/// identically. A listener that cannot be installed is logged and disabled;
/// the other signal and the internal cancel/`close` paths still shut down.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            warn!(error = %err, "failed to listen for SIGINT; that signal cannot trigger shutdown");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    () = ctrl_c => {}
                    _ = term.recv() => {}
                }
            }
            Err(err) => {
                warn!(error = %err, "failed to listen for SIGTERM; that signal cannot trigger shutdown");
                ctrl_c.await;
            }
        }
    }
    #[cfg(not(unix))]
    ctrl_c.await;
}

/// Pump inbound frames until a shutdown signal or a `close`. Outbound frames
/// are produced straight into the durable outbox by the executor/scheduler and
/// shipped by the transport (flush/replay), so the serve loop has no outbound
/// branch. Transport loss never ends the loop: the manager reconnects
/// forever, and even a dead manager task only stops the frame pump — the
/// daemon (scheduler + executor) keeps serving local work until shutdown.
async fn serve(
    transport: &mut Transport,
    context: &ServeContext,
    cancel: &Cancel,
    mut shutdown: Pin<&mut impl Future<Output = ()>>,
) {
    loop {
        tokio::select! {
            biased;
            () = shutdown.as_mut() => {
                info!("shutdown signal received");
                break;
            }
            () = cancel.cancelled() => break,
            inbound = transport.recv() => {
                let Some(inbound) = inbound else {
                    // Reconnect never exhausts, so a closed channel means the
                    // manager task itself died. Local execution must outlive
                    // the transport: keep running, wait for a real shutdown.
                    warn!("transport channel closed; daemon keeps serving local work");
                    wait_for_shutdown(cancel, shutdown).await;
                    break;
                };
                if route(inbound, context).await.is_break() {
                    info!("close received; shutting down");
                    break;
                }
            }
        }
    }
}

/// Block until a shutdown signal or an internal cancel — the tail of [`serve`]
/// once the transport channel has closed (transport death must not shut
/// the daemon down; the scheduler and executor keep running until a real
/// shutdown).
async fn wait_for_shutdown(cancel: &Cancel, shutdown: Pin<&mut impl Future<Output = ()>>) {
    tokio::select! {
        () = shutdown => {
            info!("shutdown signal received");
        }
        () = cancel.cancelled() => {}
    }
}

/// Route one inbound frame to the executor / scheduler / config, then settle
/// its inbox row: a successfully applied frame is marked processed; a FAILED
/// apply leaves the row unprocessed (it replays on reconnect) and bumps its
/// processing-failure counter, so the poison policy counts real failures — never
/// reconnects. Returns [`ControlFlow::Break`] for a `close`.
///
/// A `message` is the one frame **not** settled here: its text is the chat
/// thread's prompt, consumed (and marked) later by the [`InboxPromptSource`].
async fn route(inbound: Inbound, context: &ServeContext) -> ControlFlow<()> {
    let Inbound { inbox_id, frame } = inbound;
    let defer_processing = matches!(frame, InboundFrame::Message { .. });
    let mut applied = true;
    let flow = match frame {
        InboundFrame::Message {
            task_id, thread_id, ..
        } => {
            // Idempotent thread minting: an absent `threadId` derives the
            // thread id from the inbox row, so a reconnect replay of the same row
            // finds the already-minted thread instead of racing a fresh one.
            let tid = thread_id.unwrap_or_else(|| minted_thread_id(&task_id, inbox_id));
            ensure_chat_thread(&context.db, &task_id, &tid, context.chat_max_attempts);
            context.drain.notify_one();
            ControlFlow::Continue(())
        }
        InboundFrame::Interrupt { task_id, .. } => {
            // No `taskId` → legacy global interrupt: cancel whatever is in
            // flight. Scoped → interrupt only when the task owns the active
            // run. Always marked processed (even on a scope-check DB error):
            // replaying an interrupt is worthless.
            match task_id {
                None => context.executor.interrupt().await,
                Some(tid) => {
                    if task_owns_active_run(&context.db, &tid) {
                        context.executor.interrupt().await;
                    } else {
                        debug!(task = %tid, "scoped interrupt: task has no in-flight run; ignoring");
                    }
                }
            }
            ControlFlow::Continue(())
        }
        InboundFrame::TaskUpsert { task_id, data, .. } => {
            let reactivated = data.status.as_deref() == Some("active");
            applied = apply_task_def(&context.db, &task_id, &data);
            // Re-activation unparks this task's work (D1): wake both loops so the
            // crons the scheduler skipped and the threads/messages the drain left
            // parked resume now instead of on their next poll.
            if applied && reactivated {
                context.nudge.notify_one();
                context.drain.notify_one();
            }
            ControlFlow::Continue(())
        }
        InboundFrame::TaskDelete { task_id, .. } => {
            let workspace_dir = lock(&context.config).paths.workspace_dir.clone();
            applied = delete_task(&context.db, &workspace_dir, &task_id);
            ControlFlow::Continue(())
        }
        InboundFrame::CronUpsert {
            task_id,
            cron_id,
            data,
            ..
        } => {
            applied = handle_cron_upsert(&context.db, &task_id, &cron_id, &data, &context.nudge);
            ControlFlow::Continue(())
        }
        InboundFrame::CronDelete { cron_id, .. } => {
            applied = apply_trigger(
                || apply_cron_delete(&context.db, &cron_id),
                "cron_delete",
                &context.nudge,
            );
            ControlFlow::Continue(())
        }
        InboundFrame::ConfigUpdate { data, .. } => {
            debug!(keys = ?config_keys(&data), "config_update received");
            // Applied on both planes: the overlay merges onto the
            // live config + engine settings (rotated credentials reach the next
            // engine run), and a re-pushed global provisioning set is reconciled
            // live. Always marked processed: the host re-pushes
            // config on connect, so a replay is worthless.
            apply_config_update(context, &data).await;
            ControlFlow::Continue(())
        }
        frame @ (InboundFrame::E2eeLog { .. } | InboundFrame::E2eeWelcome { .. }) => {
            applied = context.e2ee.on_record(&frame);
            if applied
                && let InboundFrame::E2eeLog { task_id, .. }
                | InboundFrame::E2eeWelcome { task_id, .. } = frame
            {
                let e2ee = Arc::clone(&context.e2ee);
                tokio::spawn(async move { e2ee.drain(&task_id).await });
            }
            ControlFlow::Continue(())
        }
        InboundFrame::Close { .. } => ControlFlow::Break(()),
        // The transport intercepts `ack`; an unknown frame is forward-compat noise.
        InboundFrame::Ack { .. } | InboundFrame::Unknown => ControlFlow::Continue(()),
    };
    if !defer_processing {
        conclude_inbox_row(&context.db, inbox_id, applied);
    }
    flow
}

/// Whether `task_id` owns the in-flight run: any of its threads is
/// `dispatched` or `running`. The executor drains threads serially (single
/// active run), so such a thread can only be the active one. The check and
/// the interrupt are not atomic — the run may finish in between — but that
/// race is benign: interrupting an idle executor is a no-op. On a DB read
/// error, answer `false`: never cancel another task's turn on uncertain data.
fn task_owns_active_run(db: &Mutex<Db>, task_id: &str) -> bool {
    match lock_db(db).list_threads_by_task(task_id) {
        Ok(threads) => threads
            .iter()
            .any(|t| t.status == "dispatched" || t.status == "running"),
        Err(err) => {
            warn!(task = %task_id, error = %err, "scoped interrupt: thread lookup failed; not interrupting");
            false
        }
    }
}

/// Settle a routed inbox row. Applied → processed. Failed → left unprocessed
/// (replayed on reconnect) with its processing-failure counter bumped; once the
/// counter reaches [`MAX_INBOX_RETRIES`] the row is discarded (marked processed)
/// so a permanently failing frame cannot replay forever.
fn conclude_inbox_row(db: &Mutex<Db>, inbox_id: i64, applied: bool) {
    let guard = lock_db(db);
    if applied {
        if let Err(err) = guard.mark_inbox_processed(inbox_id) {
            warn!(inbox = inbox_id, error = %err, "failed to mark inbox row processed");
        }
        return;
    }
    match guard.increment_inbox_retry(inbox_id) {
        Ok(failures) if failures >= MAX_INBOX_RETRIES => {
            warn!(
                inbox = inbox_id,
                failures, "inbox row failed too many times; discarding (poison)"
            );
            if let Err(err) = guard.mark_inbox_processed(inbox_id) {
                warn!(inbox = inbox_id, error = %err, "failed to discard poison inbox row");
            }
        }
        Ok(failures) => {
            debug!(
                inbox = inbox_id,
                failures, "inbox row apply failed; left unprocessed for replay"
            );
        }
        Err(err) => {
            warn!(inbox = inbox_id, error = %err, "failed to record inbox processing failure");
        }
    }
}

/// Apply a host `cron_upsert`, seeding a minimal task row first when the cron
/// arrives before its `task_upsert` (the ordering must not drop the cron —
/// the later `task_upsert` patches the seeded row in place).
fn handle_cron_upsert(
    db: &Mutex<Db>,
    task_id: &str,
    cron_id: &str,
    data: &CronUpsertData,
    nudge: &Notify,
) -> bool {
    if !seed_task_if_missing(&lock_db(db), task_id) {
        return false;
    }
    apply_trigger(
        || apply_cron_upsert(db, task_id, cron_id, data),
        "cron_upsert",
        nudge,
    )
}

/// Apply a host `task_upsert` to the v2 `tasks` entity: insert when new, patch the
/// supplied fields in place when known. Returns `false` on a DB failure so the
/// router leaves the inbox row unprocessed for replay.
///
/// Every field follows the OMISSION-PRESERVES rule the `entries` column already
/// had: an absent field leaves the stored value alone, so a partial `task_upsert`
/// never wipes a definition the host pushed earlier. The task DEFINITION fields
/// (`engine`/`model`/`workdir`/`meta`) ride the same rule; only `model`
/// reaches execution today (at the next engine spawn, see
/// [`crate::executor`]) — `workdir` and `meta` are persisted and nothing more.
fn apply_task_def(db: &Mutex<Db>, task_id: &str, data: &TaskUpsertData) -> bool {
    let guard = lock_db(db);
    let now_iso = to_iso(now());
    warn_unsupported_engine(task_id, data.engine.as_deref());
    let Ok(meta) = task_meta_json(task_id, data) else {
        return false;
    };
    match guard.get_task_row(task_id) {
        Ok(Some(mut row)) => {
            if let Some(name) = &data.name {
                row.name = Some(name.clone());
            }
            if let Some(kind) = &data.kind {
                row.kind = Some(kind.clone());
            }
            if let Some(status) = &data.status {
                row.status.clone_from(status);
            }
            if let Some(engine) = &data.engine {
                row.engine = Some(engine.clone());
            }
            if let Some(model) = &data.model {
                row.model = Some(model.clone());
            }
            if let Some(workdir) = &data.workdir {
                row.workdir = Some(workdir.clone());
            }
            if meta.is_some() {
                row.meta = meta;
            }
            row.updated_at = now_iso;
            if let Err(err) = guard.update_task_row(&row) {
                warn!(task = %task_id, error = %err, "failed to update task");
                return false;
            }
            persist_task_entries(&guard, task_id, data) && persist_task_e2ee(&guard, task_id, data)
        }
        Ok(None) => {
            let row = TaskRow {
                id: task_id.to_owned(),
                name: data.name.clone(),
                kind: data.kind.clone(),
                status: data.status.clone().unwrap_or_else(|| "active".to_owned()),
                engine: data.engine.clone(),
                model: data.model.clone(),
                workdir: data.workdir.clone(),
                meta,
                created_at: now_iso.clone(),
                updated_at: now_iso,
            };
            if let Err(err) = guard.insert_task_row(&row) {
                warn!(task = %task_id, error = %err, "failed to insert task");
                return false;
            }
            persist_task_entries(&guard, task_id, data) && persist_task_e2ee(&guard, task_id, data)
        }
        Err(err) => {
            warn!(task = %task_id, error = %err, "task lookup failed");
            false
        }
    }
}

/// The engine backends this BUILD implements (`Engine::name`). Whether a given
/// one is actually REGISTERED is a runtime property — the codex backend is wired
/// in only when its binary is present (see [`build_executor`]) — so this list is
/// about the build, not about the deployment.
const SUPPORTED_ENGINES: &[&str] = &["claude", "codex"];

/// Warn once per applied `task_upsert` when the host names an engine no backend
/// in this build implements. DECISION: NON-FATAL — an unsupported engine is a
/// forward-compat signal from a newer host, not a bad request, so the value is
/// still persisted and the task's threads keep running on the runner's DEFAULT
/// engine. Failing them would strand a whole task on a field the runner is free
/// to ignore.
fn warn_unsupported_engine(task_id: &str, engine: Option<&str>) {
    if let Some(engine) = engine
        && !SUPPORTED_ENGINES.contains(&engine)
    {
        warn!(
            task = %task_id,
            requested = %engine,
            supported = ?SUPPORTED_ENGINES,
            "task_upsert named an engine this build does not implement; running on the default one"
        );
    }
}

/// Serialize a `task_upsert`'s free-form `meta` object for the `tasks.meta` text
/// column. `Ok(None)` means the host omitted it (omission preserves the stored
/// value); `Err(())` is a serialize failure, which fails the apply so the inbox
/// row replays rather than silently dropping half a definition.
fn task_meta_json(task_id: &str, data: &TaskUpsertData) -> Result<Option<String>, ()> {
    let Some(meta) = &data.meta else {
        return Ok(None);
    };
    serde_json::to_string(meta).map(Some).map_err(|err| {
        warn!(task = %task_id, error = %err, "failed to serialize task meta");
    })
}

/// Persist a `task_upsert`'s provisioning entries onto the `tasks` row.
/// Present → serialized to the `entries` JSON column for the per-thread
/// materialize ([`ThreadExecutor::with_provisioning`]); absent (`None`) → left
/// untouched, so a `task_upsert` that omits `entries` never wipes a prior set.
/// Returns `false` on a serialize/DB failure.
fn persist_task_entries(db: &Db, task_id: &str, data: &TaskUpsertData) -> bool {
    let Some(entries) = &data.entries else {
        return true;
    };
    match serde_json::to_string(entries) {
        Ok(json) => match db.set_task_entries(task_id, Some(&json)) {
            Ok(()) => true,
            Err(err) => {
                warn!(task = %task_id, error = %err, "failed to persist task entries");
                false
            }
        },
        Err(err) => {
            warn!(task = %task_id, error = %err, "failed to serialize task entries");
            false
        }
    }
}

/// Record a `task_upsert`'s `e2ee` marker on the task. Absent leaves the
/// task as it is; once encrypted, a task stays encrypted.
fn persist_task_e2ee(db: &Db, task_id: &str, data: &TaskUpsertData) -> bool {
    if let Some(marker) = &data.e2ee {
        return e2ee::record_task_e2ee(db, task_id, marker);
    }
    if matches!(db.get_task_e2ee(task_id), Ok(Some(_))) {
        debug!(task = %task_id, "task_upsert without e2ee; the task stays encrypted");
    }
    true
}

/// Apply a host `task_delete`: there is no hard delete, so the task is marked
/// `cancelled` (its triggers stop being seeded by their own `cron_delete`). An
/// unknown task is a no-op success (nothing to replay); only a DB failure
/// returns `false`. Once the row is handled the task's memory dir and VM disk
/// are removed, best-effort: a removal failure is logged and never turns into
/// a replay.
fn delete_task(db: &Mutex<Db>, workspace_dir: &Path, task_id: &str) -> bool {
    if !cancel_task(db, task_id) {
        return false;
    }
    if let Err(err) = memory::remove(workspace_dir, task_id) {
        warn!(task = %task_id, error = %err, "failed to remove the task memory dir");
    }
    if let Err(err) = crate::sandbox::vm_disk::remove_task(workspace_dir, task_id) {
        warn!(task = %task_id, error = %err, "failed to remove the task VM disk");
    }
    true
}

/// Mark `task_id` `cancelled`; an unknown task is a no-op success. Returns
/// `false` only on a DB failure.
fn cancel_task(db: &Mutex<Db>, task_id: &str) -> bool {
    let guard = lock_db(db);
    match guard.get_task_row(task_id) {
        Ok(Some(mut row)) => {
            "cancelled".clone_into(&mut row.status);
            row.updated_at = to_iso(now());
            match guard.update_task_row(&row) {
                Ok(()) => true,
                Err(err) => {
                    warn!(task = %task_id, error = %err, "failed to cancel task");
                    false
                }
            }
        }
        Ok(None) => {
            debug!(task = %task_id, "task_delete for an unknown task; ignoring");
            true
        }
        Err(err) => {
            warn!(task = %task_id, error = %err, "task lookup failed");
            false
        }
    }
}

/// Apply a trigger-definition mutation and nudge the scheduler when it changed.
/// Returns `false` only when the apply FAILED (an unchanged trigger is a
/// success), so the router can leave the inbox row unprocessed for replay.
fn apply_trigger(
    op: impl FnOnce() -> Result<bool, crate::db::DbError>,
    label: &str,
    nudge: &Notify,
) -> bool {
    match op() {
        Ok(true) => {
            debug!(op = label, "trigger updated; nudging scheduler");
            nudge.notify_one();
            true
        }
        Ok(false) => {
            debug!(op = label, "trigger unchanged");
            true
        }
        Err(err) => {
            warn!(op = label, error = %err, "failed to apply trigger");
            false
        }
    }
}

/// The top-level keys of a `config_update` payload, for a non-leaky log line (the
/// values may carry secrets, so only the key set is logged).
fn config_keys(data: &serde_json::Value) -> Vec<String> {
    data.as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

/// Apply a live `config_update` end-to-end. The payload is parsed
/// ONCE as a [`ConfigOverlay`], then applied on both planes:
///
/// 1. **engine/config** ([`apply_engine_config`]) — merge the overlay onto the
///    live [`Config`] and rebuild the shared engine settings, so a rotated
///    `anthropicApiKey` reaches the next engine run without a restart.
/// 2. **provisioning** ([`apply_provisioning_update`]) — the version-gated global
///    reconcile.
///
/// A payload that does not parse as an overlay is dropped, not retried: the
/// failure is deterministic (a replay re-fails identically) and the host
/// re-pushes config on connect, so dropping follows the same dead-letter policy
/// the transport applies to malformed known-type frames. Non-fatal.
async fn apply_config_update(context: &ServeContext, data: &serde_json::Value) {
    let overlay: ConfigOverlay = match serde_json::from_value(data.clone()) {
        Ok(overlay) => overlay,
        Err(err) => {
            warn!(error = %err, "config_update did not parse as a config overlay; dropping (dead-letter)");
            return;
        }
    };
    apply_engine_config(context, overlay.clone());
    apply_provisioning_update(context, &overlay).await;
}

/// Merge a `config_update` overlay onto the live [`Config`] (the "WS update"
/// layer — last in the config.rs precedence chain) and rebuild the shared
/// [`ClaudeSettings`] AND [`CodexSettings`] from the merged result, so the NEXT
/// engine spawn sees the updated credentials/model/tools (see [`ReloadableEngine`]
/// for the
/// apply-on-next-run decision). Fields the engine does not read at spawn time
/// (heartbeat cadence, paths) are merged too but only take effect where they
/// are re-read — the transport and DB keep their startup values until restart.
fn apply_engine_config(context: &ServeContext, overlay: ConfigOverlay) {
    let (rebuilt, rebuilt_codex) = {
        let mut config = lock(&context.config);
        config.apply(overlay);
        context.remote_ops.configure(
            config.remote_ops.fs,
            config.remote_ops.pty,
            &config.paths.workspace_dir,
        );
        (
            engine_settings(&config, &context.engine_config_dir),
            codex_settings(&config, &context.engine_config_dir),
        )
    };
    *lock(&context.engine_settings) = rebuilt;
    *lock(&context.codex_settings) = rebuilt_codex;
    debug!("config_update merged onto live config; engine settings apply on the next run");
}

/// Apply the provisioning side of a live `config_update` under the SAME
/// version gate as the startup reconcile. Re-reconcile the global scope ONLY when the
/// overlay carries BOTH a `version` and an
/// `entries` set AND that version advances past the persisted applied version. The
/// host re-pushes the FULL desired set, so one [`Provisioner::reconcile`] converges
/// add / repoint / remove (incl. the authoritative-empty case — a versioned empty set
/// removes all). A stale/equal version is ignored, and an update without a
/// `version`+`entries` pair never touches provisioning (so neither a routine config
/// refresh nor a non-authoritative empty set is mistaken for "remove all"). The
/// applied version is persisted only after a successful reconcile. Unlike the startup
/// path this does NOT gc — orphaned store versions are collected on the next restart's
/// startup gc, matching the documented "no GC without a restart". Non-fatal.
async fn apply_provisioning_update(context: &ServeContext, overlay: &ConfigOverlay) {
    let Some(provisioner) = &context.provisioner else {
        return;
    };
    // The version gate keys on a (version, entries) pair: a versioned desired set.
    let (Some(fetched), Some(entries)) = (overlay.version(), overlay.entries()) else {
        debug!("config_update without a version+entries pair; leaving global provisioning intact");
        return;
    };
    let applied = lock_db(&context.db)
        .get_applied_global_version()
        .unwrap_or_else(|err| {
            warn!(error = %err, "failed to read applied global config version; treating as unset");
            None
        });
    if applied.is_some_and(|a| fetched <= a) {
        debug!(
            applied = ?applied,
            fetched,
            "config_update version not advanced; ignoring (repair-only on restart)"
        );
        return;
    }
    match provisioner
        .reconcile("global", &context.engine_config_dir, entries)
        .await
    {
        Ok(()) => {
            debug!(
                count = entries.len(),
                version = fetched,
                "config_update reconciled global provisioning to new version"
            );
            if let Err(err) = lock_db(&context.db).set_applied_global_version(fetched) {
                warn!(error = %err, "failed to persist applied global config version after config_update");
            }
        }
        Err(err) => warn!(error = %err, "config_update global reconcile failed"),
    }
}

/// Poison-tolerant DB lock (Lock 6): recover the guard rather than panic. Critical
/// sections are short and never span an `.await`.
fn lock_db(db: &Mutex<Db>) -> MutexGuard<'_, Db> {
    db.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Poison-tolerant lock for the live config / engine-settings seams — same
/// policy as [`lock_db`]: short critical sections, never across an `.await`.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;

/// Focused coverage of the global-provisioning startup wiring
/// (`reconcile_global_startup`) against a fake byte fetcher — the full host-driven
/// path is exercised by the e2e harness.
#[cfg(test)]
mod provisioning_wiring_tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;

    use crate::attachments::sha256_hex;
    use crate::db::Db;
    use crate::protocol::frames::{EntryKind, ProvisioningEntry};
    use crate::provisioning::{BlobFetcher, Provisioner, ProvisioningError};

    use super::reconcile_global_startup;
    use crate::config::ENGINE_CONFIG_SUBDIR;

    /// In-memory blob fetcher keyed by host-proxy `reference`. Verifies the served
    /// bytes hash to the requested `sha256` (mirroring the real fetcher's contract)
    /// and counts fetches so a test can assert the version gate's repair-only branch
    /// performs no byte re-fetch.
    struct FakeFetcher {
        blobs: HashMap<String, Vec<u8>>,
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl BlobFetcher for FakeFetcher {
        async fn fetch(&self, reference: &str, sha256: &str) -> Result<Vec<u8>, ProvisioningError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let bytes =
                self.blobs
                    .get(reference)
                    .cloned()
                    .ok_or_else(|| ProvisioningError::Fetch {
                        reason: format!("no blob at {reference}"),
                    })?;
            assert_eq!(sha256_hex(&bytes), sha256, "fake blob sha mismatch");
            Ok(bytes)
        }
    }

    /// A provisioner over a fresh in-memory DB and `blobs`, returning the SHARED db
    /// handle (the version gate reads/writes `config_meta` on it) and the fetch
    /// counter so the no-refetch invariant is assertable.
    fn provisioner_with(
        ws: &std::path::Path,
        blobs: HashMap<String, Vec<u8>>,
    ) -> (Provisioner, Arc<Mutex<Db>>, Arc<AtomicUsize>) {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let fetches = Arc::new(AtomicUsize::new(0));
        let blob_fetcher: Arc<dyn BlobFetcher> = Arc::new(FakeFetcher {
            blobs,
            fetches: Arc::clone(&fetches),
        });
        let prov = Provisioner::new(ws.to_path_buf(), Arc::clone(&db), blob_fetcher);
        (prov, db, fetches)
    }

    fn file_entry(id: &str, target: &str, bytes: &[u8]) -> ProvisioningEntry {
        ProvisioningEntry {
            id: id.to_owned(),
            sha256: sha256_hex(bytes),
            target: target.to_owned(),
            kind: EntryKind::File,
        }
    }

    /// The startup sequence with a versioned empty desired set is a clean no-op: it
    /// must not panic and must leave the engine config dir empty (no spurious links).
    #[tokio::test]
    async fn startup_reconcile_with_no_entries_is_a_clean_noop() {
        let ws = tempfile::tempdir().unwrap();
        let engine_config_dir = ws.path().join(ENGINE_CONFIG_SUBDIR);
        std::fs::create_dir_all(&engine_config_dir).unwrap();
        let (prov, db, _fetches) = provisioner_with(ws.path(), HashMap::new());

        reconcile_global_startup(&prov, &db, &engine_config_dir, &[], Some(1)).await;

        assert!(
            std::fs::read_dir(&engine_config_dir)
                .unwrap()
                .next()
                .is_none(),
            "no entries → engine config dir stays empty"
        );
        assert_eq!(
            lock_applied(&db),
            Some(1),
            "a versioned reconcile records its applied version"
        );
    }

    /// The startup sequence materializes a global `file` entry as a symlink under
    /// the engine config dir that resolves to the fetched bytes.
    #[tokio::test]
    async fn startup_reconcile_materializes_global_entry_symlink() {
        let ws = tempfile::tempdir().unwrap();
        let engine_config_dir = ws.path().join(ENGINE_CONFIG_SUBDIR);
        std::fs::create_dir_all(&engine_config_dir).unwrap();

        let bytes = b"# global CLAUDE.md\n".to_vec();
        let mut blobs = HashMap::new();
        blobs.insert(
            format!("/agent/attachments?sha256={}", sha256_hex(&bytes)),
            bytes.clone(),
        );
        let (prov, db, _fetches) = provisioner_with(ws.path(), blobs);

        let entry = file_entry("clauderc", "CLAUDE.md", &bytes);
        reconcile_global_startup(
            &prov,
            &db,
            &engine_config_dir,
            std::slice::from_ref(&entry),
            Some(1),
        )
        .await;

        let link = engine_config_dir.join("CLAUDE.md");
        assert_eq!(
            std::fs::read(&link).unwrap(),
            bytes,
            "symlink resolves to the fetched bytes"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "target is materialized as a symlink into the store"
        );
    }

    /// AUTHORITATIVE-EMPTY: a VERSIONED config whose `version` ADVANCES
    /// with zero entries means the host genuinely wants none → the reconcile removes
    /// every installed global entry, and the applied version advances.
    #[tokio::test]
    async fn versioned_empty_set_is_authoritative_and_removes_all() {
        let ws = tempfile::tempdir().unwrap();
        let engine_config_dir = ws.path().join(ENGINE_CONFIG_SUBDIR);
        std::fs::create_dir_all(&engine_config_dir).unwrap();

        let bytes = b"# CLAUDE.md v1\n".to_vec();
        let mut blobs = HashMap::new();
        blobs.insert(
            format!("/agent/attachments?sha256={}", sha256_hex(&bytes)),
            bytes.clone(),
        );
        let (prov, db, _fetches) = provisioner_with(ws.path(), blobs);

        // v1 installs one global entry.
        let entry = file_entry("clauderc", "CLAUDE.md", &bytes);
        reconcile_global_startup(
            &prov,
            &db,
            &engine_config_dir,
            std::slice::from_ref(&entry),
            Some(1),
        )
        .await;
        assert!(engine_config_dir.join("CLAUDE.md").is_symlink());
        assert_eq!(lock_applied(&db), Some(1));

        // v2 with an EMPTY set is authoritative-empty → removes the installed entry.
        reconcile_global_startup(&prov, &db, &engine_config_dir, &[], Some(2)).await;
        assert!(
            std::fs::read_dir(&engine_config_dir)
                .unwrap()
                .next()
                .is_none(),
            "an authoritative (versioned) empty set must remove every global entry"
        );
        assert_eq!(lock_applied(&db), Some(2), "applied version advanced to 2");
    }

    /// NON-AUTHORITATIVE-EMPTY (the restart-durability crux): an empty
    /// set with NO version (offline / not-yet-loaded) must NOT wipe — the installed
    /// global entry survives (repair-only), and the applied version is unchanged.
    #[tokio::test]
    async fn unversioned_empty_set_never_wipes_installed_global() {
        let ws = tempfile::tempdir().unwrap();
        let engine_config_dir = ws.path().join(ENGINE_CONFIG_SUBDIR);
        std::fs::create_dir_all(&engine_config_dir).unwrap();

        let bytes = b"# CLAUDE.md durable\n".to_vec();
        let mut blobs = HashMap::new();
        blobs.insert(
            format!("/agent/attachments?sha256={}", sha256_hex(&bytes)),
            bytes.clone(),
        );
        let (prov, db, fetches) = provisioner_with(ws.path(), blobs);

        // Install at v1 (one fetch).
        let entry = file_entry("clauderc", "CLAUDE.md", &bytes);
        reconcile_global_startup(
            &prov,
            &db,
            &engine_config_dir,
            std::slice::from_ref(&entry),
            Some(1),
        )
        .await;
        let link = engine_config_dir.join("CLAUDE.md");
        assert!(link.is_symlink());
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "v1 fetched once");

        // Simulate a restart whose config fetch FAILED (no version) handing an EMPTY
        // desired set: the installed entry must survive (no reconcile-to-empty).
        reconcile_global_startup(&prov, &db, &engine_config_dir, &[], None).await;
        assert!(
            link.is_symlink() && std::fs::read(&link).unwrap() == bytes,
            "a non-authoritative empty set must never wipe the installed global entry"
        );
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "repair-only leaves the present store entry untouched (no re-fetch)"
        );
        assert_eq!(lock_applied(&db), Some(1), "applied version unchanged");
    }

    /// SAME-VERSION (restart durability): re-running at the SAME applied version
    /// neither wipes nor re-fetches — repair-only keeps the installed link, and the
    /// applied version is unchanged.
    #[tokio::test]
    async fn same_version_is_repair_only_no_refetch_no_wipe() {
        let ws = tempfile::tempdir().unwrap();
        let engine_config_dir = ws.path().join(ENGINE_CONFIG_SUBDIR);
        std::fs::create_dir_all(&engine_config_dir).unwrap();

        let bytes = b"# CLAUDE.md stable\n".to_vec();
        let mut blobs = HashMap::new();
        blobs.insert(
            format!("/agent/attachments?sha256={}", sha256_hex(&bytes)),
            bytes.clone(),
        );
        let (prov, db, fetches) = provisioner_with(ws.path(), blobs);

        let entry = file_entry("clauderc", "CLAUDE.md", &bytes);
        reconcile_global_startup(
            &prov,
            &db,
            &engine_config_dir,
            std::slice::from_ref(&entry),
            Some(1),
        )
        .await;
        assert_eq!(fetches.load(Ordering::SeqCst), 1);

        // Re-run at the SAME version with the SAME desired set (the restart case):
        // repair-only, so the link survives and nothing is re-fetched.
        reconcile_global_startup(
            &prov,
            &db,
            &engine_config_dir,
            std::slice::from_ref(&entry),
            Some(1),
        )
        .await;
        let link = engine_config_dir.join("CLAUDE.md");
        assert!(link.is_symlink() && std::fs::read(&link).unwrap() == bytes);
        assert_eq!(
            fetches.load(Ordering::SeqCst),
            1,
            "same version → no re-fetch"
        );
        assert_eq!(lock_applied(&db), Some(1));
    }

    /// Read the persisted applied global config version off the shared db handle.
    fn lock_applied(db: &Mutex<Db>) -> Option<i64> {
        db.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_applied_global_version()
            .unwrap()
    }
}
