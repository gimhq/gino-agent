//! Local persistence layer — v2 data model (A, agent-architecture §3).
//!
//! A single SQLite database (rusqlite, bundled) holding the runner's durable
//! state. The path is **configurable** — it comes from [`crate::config`]
//! (`paths.db_path`), never a hardcoded Docker mount — so the runner is equally
//! at home in a VM, a container, or as a bare service.
//!
//! ## v2 schema (the target model)
//!
//! Everything belongs to a **`task`** — the single global top category per
//! runner (agent-architecture §1). Two planes hang off it:
//!
//! - **Scheduling plane** (local): `crons` (triggers) + `cron_logs` (per-fire
//!   ledger, incl. skips). Firing idempotency is the schema-enforced
//!   `cron_logs UNIQUE(cron_id, scheduled_at)` — it replaces the old in-memory
//!   `HashSet` dedup.
//! - **Result plane** (synced to host): `threads` (engine executions /
//!   conversations) → `outbox` → host. "session" survives only as the
//!   `threads.engine_session_id` field (the claude `--resume` handle).
//!
//! `inbox`/`outbox` carry `task_id`/`thread_id` as indexed correlation columns
//! (routing); the `payload` stays an opaque JSON blob (agent-architecture §8).
//! `identity` is unchanged.
//!
//! ## v1 strangler removal
//!
//! The v1 strangler surface is gone now that v2 is the only live path: the
//! `session_state` table (the engine session id moved to
//! `threads.engine_session_id`), the `task_runs` table (absorbed into `threads`),
//! and the host-mirror task-snapshot merge are all removed. The last v1 remnant —
//! the legacy `tasks` columns
//! (`prompt`/`schedule_type`/`schedule_value`/`context_mode`/`next_run`/
//! `last_run`/`last_result`/`dirty`) and the `TaskRecord` CRUD that drove them — is
//! gone too: it existed only for the cancelled in-runner tool server, superseded by
//! skills provisioning (campaign l1-03ce6ctr). The `tasks` table now
//! holds the v2 entity columns (`id`, `name`, `kind`, `status`, `created_at`,
//! `updated_at`) plus the `entries` provisioning column, driven by
//! [`TaskRow`] + the `set_task_entries`/`get_task_entries` accessors.
//!
//! The module keeps a `#[allow(dead_code)]` at its `mod db;` site in `lib.rs` for
//! the **not-yet-wired v2 read-model CRUD** (cron-log reads) that no production
//! caller drives yet; its own unit tests keep the surface honest. The v1 dead code
//! above is removed, not suppressed. The write-only reconciliation plane
//! (`threads.synced` / `crons.dirty` accessors) is removed outright: the result
//! plane is transactional ([`Db::immediate_transaction`]), so a terminal
//! thread state and its outbox frame commit together and there is nothing left to
//! reconcile after the fact.
//!
//! ## Statement caching
//!
//! Every query goes through [`rusqlite::Connection::prepare_cached`], so prepared
//! statements are compiled once and reused — the Rust analogue of the TS cached
//! `db.prepare(...)` handles, without the lifetime juggling of stored statements.
//!
//! ## Secrets
//!
//! The connect token is stored in a plain `TEXT` column (SQLite has no secret
//! type), but it crosses the API boundary wrapped in `secrecy::SecretString`:
//! [`Db::set_identity`] takes a `SecretString` and [`Identity`] hands one back,
//! so the token is redacted in any `Debug`/log of an [`Identity`].

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------
//
// The schema is versioned through `PRAGMA user_version`. [`Db::migrate`] creates
// a fresh database at [`SCHEMA_VERSION`] in one transaction; a database recorded
// at any other version is refused (pre-release: discard and recreate it).

/// The schema version this binary reads and writes (`PRAGMA user_version`).
pub(crate) const SCHEMA_VERSION: i64 = 3;

/// The full schema, applied once to a fresh database.
const SCHEMA: &str = "\
CREATE TABLE outbox (
  id          TEXT    PRIMARY KEY,                -- monotonic lowercase ULID; the wire `outboxId`
  type        TEXT    NOT NULL,
  payload     TEXT    NOT NULL,
  task_id     TEXT,
  thread_id   TEXT,
  created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  acked_at    TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_outbox_task    ON outbox(task_id);
CREATE INDEX idx_outbox_thread  ON outbox(thread_id);
-- Partial hot-path indexes: reconnect replay scans WHERE acked_at IS NULL /
-- processed_at IS NULL under the global DB mutex on every flush, so the scans
-- stay proportional to the backlog, not the tables' history.
CREATE INDEX idx_outbox_unacked ON outbox(id) WHERE acked_at IS NULL;

CREATE TABLE inbox (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  type         TEXT    NOT NULL,
  payload      TEXT    NOT NULL,
  task_id      TEXT,
  thread_id    TEXT,
  msg_id       TEXT,                              -- host delivery id (ULID); NULL when the frame carries none
  received_at  TEXT    NOT NULL DEFAULT (datetime('now')),
  processed_at TEXT,
  retry_count  INTEGER NOT NULL DEFAULT 0         -- PROCESSING failures (not replays); the poison policy discards a row after MAX failures
);
CREATE INDEX idx_inbox_task   ON inbox(task_id);
CREATE INDEX idx_inbox_thread ON inbox(thread_id);
-- At-least-once dedup (protocol.md §4.2); multiple NULLs allowed.
CREATE UNIQUE INDEX idx_inbox_msg_id ON inbox(msg_id);
CREATE INDEX idx_inbox_unprocessed ON inbox(id) WHERE processed_at IS NULL;

-- The global top category (agent-architecture §3), driven by TaskRow.
CREATE TABLE tasks (
  id             TEXT PRIMARY KEY,
  name           TEXT,
  kind           TEXT,
  status         TEXT NOT NULL DEFAULT 'active',
  entries        TEXT,                              -- JSON array of the task's DESIRED provisioning entries [{id,sha256,target,kind}] (PLAN-007 §5); nullable, set via set_task_entries (insert_task_row omits it)
  engine         TEXT,                              -- backend name; only 'claude' is implemented (unknown → warn + claude)
  model          TEXT,                              -- per-task model id; overrides config.engine.model at the NEXT spawn
  workdir        TEXT,                              -- PERSIST-ONLY: nothing reads this yet
  meta           TEXT,                              -- PERSIST-ONLY: free-form host JSON, stored as text
  e2ee_profile_id TEXT,                             -- task_upsert.data.e2ee.profile_id; once set never cleared (set_task_e2ee)
  e2ee_group_id   TEXT,                             -- task_upsert.data.e2ee.group_id (base64url); once set never cleared
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);

-- A trigger under a task (1 task : N crons). agent-architecture §3/§4.
CREATE TABLE crons (
  id             TEXT PRIMARY KEY,
  task_id        TEXT NOT NULL REFERENCES tasks(id),
  kind           TEXT NOT NULL,                     -- schedule | webhook | api
  prompt         TEXT NOT NULL,                     -- the recurring instruction this cron runs each fire (a cron = a recurring prompt) [D10:(a)]
  schedule_type  TEXT,                              -- cron | interval | once (kind='schedule'; else NULL)
  schedule_value TEXT,
  next_run       TEXT,
  last_fired_at  TEXT,
  continuity     TEXT    NOT NULL DEFAULT 'isolated', -- isolated | shared
  run_count      INTEGER NOT NULL DEFAULT 0,        -- CACHE; truth = cron_logs (D4)
  status         TEXT    NOT NULL DEFAULT 'active',  -- active | paused | completed | cancelled
  created_at     TEXT    NOT NULL,
  updated_at     TEXT    NOT NULL
);
CREATE INDEX idx_crons_task   ON crons(task_id);
CREATE INDEX idx_crons_status ON crons(status, next_run);

-- One engine execution / conversation under a task (1 task : N threads).
-- This is what used to be called a 'session'; the engine resume handle survives
-- as the engine_session_id field. agent-architecture §3/§5.
CREATE TABLE threads (
  id                TEXT PRIMARY KEY,
  task_id           TEXT NOT NULL REFERENCES tasks(id),
  cron_id           TEXT REFERENCES crons(id),     -- NULL = chat/api/direct
  source            TEXT NOT NULL,                 -- cron | chat | api
  prompt            TEXT NOT NULL,                 -- RESOLVED instruction snapshot at attempt 0 (crons.prompt | message.text); retries/resume reuse it [D10]
  engine            TEXT NOT NULL,                 -- claude | codex | …
  engine_session_id TEXT,                          -- claude --resume handle (may rotate / be shared)
  status            TEXT NOT NULL DEFAULT 'pending', -- pending|dispatched|running|active|succeeded|failed|cancelled
  failure_reason    TEXT,                          -- taxonomy (§6); NULL on success
  attempt           INTEGER NOT NULL DEFAULT 0,
  max_attempts      INTEGER NOT NULL DEFAULT 1,
  work_dir          TEXT,                          -- assigned when the executor materializes the workspace
  started_at        TEXT,
  finished_at       TEXT,
  duration_ms       INTEGER,
  result            TEXT,
  error             TEXT,
  last_seq          INTEGER NOT NULL DEFAULT 0,     -- last per-thread executor seq; continues across a runner restart (host dedups on (thread_id, seq))
  result_outbox_id  TEXT,                          -- outboxId of the last thread_result; binds an encrypted task's sealed result/error
  created_at        TEXT NOT NULL
);
CREATE INDEX idx_threads_task   ON threads(task_id);
CREATE INDEX idx_threads_cron   ON threads(cron_id);
CREATE INDEX idx_threads_status ON threads(status);

-- Inbound attachment descriptors snapshotted per thread. The inbox `message`
-- carrying them is CONSUMED at prompt-resolve time, so without this snapshot a
-- retry or a restarted daemon would re-run the thread with its snapshotted
-- prompt but ZERO attachments and still report success. Written before the
-- message is consumed; read (never popped) on every attempt.
CREATE TABLE thread_attachments (
  thread_id   TEXT PRIMARY KEY REFERENCES threads(id),
  descriptors TEXT NOT NULL,                       -- JSON array of wire AttachmentDescriptor
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Per-fire scheduling ledger (LOCAL, incl. skips that produce no thread).
-- UNIQUE(cron_id, scheduled_at) is the durable firing-dedup contract — it
-- replaces the in-memory HashSet. agent-architecture §3/§7.
CREATE TABLE cron_logs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  cron_id      TEXT    NOT NULL REFERENCES crons(id),
  task_id      TEXT    NOT NULL REFERENCES tasks(id),
  round_seq    INTEGER NOT NULL,
  scheduled_at TEXT    NOT NULL,
  fired_at     TEXT,
  status       TEXT    NOT NULL,                   -- dispatched | skipped | missed | failed
  skip_reason  TEXT,
  thread_id    TEXT REFERENCES threads(id),        -- the thread this fire drove (NULL on skip/missed)
  created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
  UNIQUE(cron_id, scheduled_at)
);
CREATE INDEX idx_cron_logs_cron   ON cron_logs(cron_id);
CREATE INDEX idx_cron_logs_thread ON cron_logs(thread_id);

-- Installed manifest + store-refcount index for provisioned config/skills
-- (agent-architecture §3/§9b, PLAN-007 §4). NOT a copy of config content: the
-- bytes live in the filesystem store (store/<name>/<short>) and the DESIRED set
-- lives in config (global) / the tasks.entries column (task). This table records
-- only WHAT is materialized WHERE — backing reconcile, GC (refcount), restart
-- repair, and observability.
CREATE TABLE config_entries (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  scope        TEXT NOT NULL,   -- materialization location: 'global' (engine-config root) | <task_id> (the task project/ scope, P1-11)
  name         TEXT NOT NULL,   -- logical id (= store <name>)
  sha256       TEXT NOT NULL,   -- full hash (version / integrity)
  short        TEXT NOT NULL,   -- store short id (sha256[:12])
  target       TEXT NOT NULL,   -- relative landing path
  kind         TEXT NOT NULL,   -- file | dir
  store_path   TEXT NOT NULL,   -- store/<name>/<short>
  link_path    TEXT NOT NULL,   -- <scope-root>/<target>
  installed_at TEXT NOT NULL,
  UNIQUE(scope, target)
);
CREATE INDEX idx_config_entries_scope ON config_entries(scope);
CREATE INDEX idx_config_entries_store ON config_entries(name, sha256);

CREATE TABLE identity (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  agent_id      TEXT NOT NULL,
  connect_token TEXT NOT NULL,
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Durable little KV for applied-config bookkeeping (PLAN-007 §6). Distinct from
-- config_entries (the materialized manifest): this records the APPLIED global
-- config VERSION so a restart can tell an authoritative new desired set (version
-- advanced → reconcile) from an unchanged one (same version → repair-only, no wipe).
CREATE TABLE config_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- End-to-end encryption (runner role). Every BLOB below is sealed at rest under
-- the e2ee state key (a separate 0600 file next to the DB), bound to its label.
CREATE TABLE e2ee_key_packages (
  id                     INTEGER PRIMARY KEY CHECK (id = 1),
  store                  BLOB NOT NULL,              -- sealed KeyPackageStore snapshot (private init keys)
  last_resort_created_at TEXT,                       -- RFC3339; when the current last-resort KeyPackage was generated
  updated_at             TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE e2ee_groups (
  task_id    TEXT PRIMARY KEY,
  group_id   TEXT NOT NULL,                          -- base64url MLS group id
  profile_id TEXT NOT NULL,
  snapshot   BLOB,                                   -- sealed ScopeGroup snapshot; NULL until a Welcome is processed
  last_seq   INTEGER,                                -- last applied handshake log seq
  status     TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'member', 'removed', 'lost')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE e2ee_key_cache (
  task_id  TEXT    NOT NULL,
  epoch    INTEGER NOT NULL,
  secrets  BLOB    NOT NULL,                         -- sealed CachedSecrets
  verified INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (task_id, epoch)
);

-- Out-of-order e2ee_log / e2ee_welcome records, buffered as received (opaque
-- MLS bytes) until the group state applies them in seq order. A Welcome carries
-- the seq of its commit, so the record type is part of the key.
CREATE TABLE e2ee_log_pending (
  task_id     TEXT    NOT NULL,
  seq         INTEGER NOT NULL,
  type        TEXT    NOT NULL CHECK (type IN ('e2ee_log', 'e2ee_welcome')),
  payload     TEXT    NOT NULL,                      -- the frame's data as received
  received_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (task_id, seq, type)
);
";

/// A new outbox delivery id: a lowercase ULID, monotonic within the process so
/// ids minted in the same millisecond still sort in creation order.
pub(crate) fn new_delivery_id() -> String {
    static GENERATOR: std::sync::LazyLock<std::sync::Mutex<ulid::Generator>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(ulid::Generator::new()));
    let mut generator = GENERATOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let id = generator
        .generate()
        .unwrap_or_else(ulid::Overflow::commit_overflow_increment);
    id.to_string().to_lowercase()
}

/// The per-connection pragma preamble. WAL for concurrent read/write; a busy
/// timeout to ride out brief locks; `foreign_keys` because SQLite ships FK
/// enforcement OFF per connection while this schema declares — and the code
/// assumes — live REFERENCES. (On an in-memory DB the WAL pragma
/// simply reports `memory`; it is a harmless no-op there.)
const PRAGMAS: &str =
    "PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 3000; PRAGMA foreign_keys = ON;";

/// `config_meta` key holding the last APPLIED global config version.
const APPLIED_GLOBAL_VERSION_KEY: &str = "applied_global_config_version";

/// Errors raised by the persistence layer.
#[derive(Debug, Error)]
pub(crate) enum DbError {
    /// An underlying SQLite failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A payload could not be serialized before enqueue.
    #[error("serialize payload: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Hardening the on-disk permissions of the DB files failed.
    #[error("harden db file permissions: {0}")]
    Permissions(#[from] std::io::Error),
    /// The DB was written by a newer binary; migrating down is not supported.
    #[error(
        "database schema is v{found} but this binary supports up to v{supported}; \
         upgrade gino-agent"
    )]
    SchemaNewerThanBinary { found: i64, supported: i64 },
    /// The DB was created by an older development build; delete it and restart.
    #[error(
        "database schema v{found} is from an older development build and cannot be \
         upgraded; delete the database and restart gino-agent"
    )]
    UnsupportedSchema { found: i64 },
}

/// Convenience alias for fallible DB operations.
pub(crate) type DbResult<T> = Result<T, DbError>;

/// Restrict the DB file — and its `-wal`/`-shm` siblings when present — to
/// owner-only read/write (`0600`). Runs on every open so pre-existing files from
/// deployments that created them world-readable are healed, not only fresh ones.
#[cfg(unix)]
fn harden_db_files(path: &Path) -> std::io::Result<()> {
    set_mode(path, 0o600)?;
    for suffix in ["-wal", "-shm"] {
        let mut sibling = path.as_os_str().to_owned();
        sibling.push(suffix);
        let sibling = std::path::PathBuf::from(sibling);
        if sibling.exists() {
            set_mode(&sibling, 0o600)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn harden_db_files(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Restrict a state directory (the agent workspace holding the DB, engine
/// work dirs and the provisioning store) to owner-only access (`0700`). Called by
/// the daemon at startup on directories it owns, so pre-existing deployments are
/// healed too. Never call this on a shared system directory.
#[cfg(unix)]
pub(crate) fn harden_state_dir(path: &Path) -> std::io::Result<()> {
    set_mode(path, 0o700)
}

#[cfg(not(unix))]
pub(crate) fn harden_state_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

/// A row of the `outbox` (runner → host, at-least-once). `task_id`/`thread_id`
/// are the correlation columns (routing); `payload` stays opaque JSON.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OutboxRow {
    pub(crate) id: String,
    pub(crate) msg_type: String,
    pub(crate) payload: String,
    pub(crate) task_id: Option<String>,
    pub(crate) thread_id: Option<String>,
    pub(crate) created_at: String,
    pub(crate) acked_at: Option<String>,
    pub(crate) retry_count: i64,
}

/// A row of the `inbox` (host → runner, at-least-once replay). `task_id`/
/// `thread_id` are the correlation columns; `payload` stays opaque JSON.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct InboxRow {
    pub(crate) id: i64,
    pub(crate) msg_type: String,
    pub(crate) payload: String,
    pub(crate) task_id: Option<String>,
    pub(crate) thread_id: Option<String>,
    pub(crate) received_at: String,
    pub(crate) processed_at: Option<String>,
    pub(crate) retry_count: i64,
}

/// A `tasks` row — the **v2 top-category entity** (agent-architecture §3).
/// "session" is not here; per-execution state lives on [`ThreadRow`].
///
/// `engine`/`model`/`workdir`/`meta` are the host-authored task DEFINITION
/// (protocol.md §7 `task_upsert`). All four are `Option` because the host
/// may push a partial definition and because rows predating the v4 ladder step
/// carry NULL; `None` therefore means "never told", not "cleared".
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct TaskRow {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) kind: Option<String>,
    pub(crate) status: String,
    /// Backend name. Only `claude` is implemented; an unsupported value is
    /// stored as sent but falls back to claude at execution time.
    pub(crate) engine: Option<String>,
    /// Per-task model id. Overrides `config.engine.model` on the NEXT engine
    /// spawn for this task's threads.
    pub(crate) model: Option<String>,
    /// PERSIST-ONLY (align-2026-08 D2): stored so the definition round-trips,
    /// but no runner path reads it — the executor still materializes its own
    /// per-thread workspace.
    pub(crate) workdir: Option<String>,
    /// The host's free-form JSON object, stored verbatim as text. The executor
    /// reads only its `isolation` key (the per-task isolation override); nothing
    /// else reads it.
    pub(crate) meta: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

/// A `crons` row — a trigger under a task (agent-architecture §3/§4).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CronRow {
    pub(crate) id: String,
    pub(crate) task_id: String,
    /// `schedule` | `webhook` | `api`.
    pub(crate) kind: String,
    /// The recurring instruction this cron runs each fire — a cron is a recurring
    /// prompt (agent-architecture §3, D10:(a)). Snapshotted into the driven
    /// thread's [`ThreadRow::prompt`] on each fire.
    pub(crate) prompt: String,
    /// `cron` | `interval` | `once` for `kind = 'schedule'`; `None` otherwise.
    pub(crate) schedule_type: Option<String>,
    pub(crate) schedule_value: Option<String>,
    pub(crate) next_run: Option<String>,
    pub(crate) last_fired_at: Option<String>,
    /// `isolated` (new thread per fire) | `shared` (one ongoing thread).
    pub(crate) continuity: String,
    /// Cache of the fire count; the truth is `cron_logs` (D4).
    pub(crate) run_count: i64,
    /// `active` | `paused` | `completed` | `cancelled`.
    pub(crate) status: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

/// A `threads` row — one engine execution / conversation (agent-architecture
/// §3/§5). The `engine_session_id` is the engine's `--resume` handle (a field,
/// not an entity).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ThreadRow {
    pub(crate) id: String,
    pub(crate) task_id: String,
    /// The trigger that spawned it; `None` for chat/api/direct threads.
    pub(crate) cron_id: Option<String>,
    /// `cron` | `chat` | `api`.
    pub(crate) source: String,
    /// The **resolved instruction snapshot** taken at attempt 0 — from
    /// `crons.prompt` (cron-fired) or the inbox `message.text` (chat/api). Retries
    /// and resume reuse this snapshot instead of re-resolving, which is what fixes
    /// the chat-retry nuance (a consumed inbox message would otherwise re-resolve
    /// to `runner.invalid_request`). agent-architecture §3/§6/§8, D10.
    pub(crate) prompt: String,
    /// `claude` | `codex` | …
    pub(crate) engine: String,
    pub(crate) engine_session_id: Option<String>,
    /// `pending` | `dispatched` | `running` | `active` | `succeeded` | `failed` | `cancelled`.
    pub(crate) status: String,
    /// Failure taxonomy (agent-architecture §6); `None` on success.
    pub(crate) failure_reason: Option<String>,
    pub(crate) attempt: i64,
    pub(crate) max_attempts: i64,
    pub(crate) work_dir: Option<String>,
    pub(crate) started_at: Option<String>,
    pub(crate) finished_at: Option<String>,
    pub(crate) duration_ms: Option<i64>,
    pub(crate) result: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) created_at: String,
}

/// A `cron_logs` row — one per-fire ledger line (agent-architecture §3/§7).
/// Records every fire, including skips/misses that produce no thread.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CronLogRow {
    pub(crate) id: i64,
    pub(crate) cron_id: String,
    pub(crate) task_id: String,
    pub(crate) round_seq: i64,
    pub(crate) scheduled_at: String,
    pub(crate) fired_at: Option<String>,
    /// `dispatched` | `skipped` | `missed` | `failed` (a scheduling outcome).
    pub(crate) status: String,
    pub(crate) skip_reason: Option<String>,
    /// The thread this fire drove (new, or the shared one it added a turn to).
    pub(crate) thread_id: Option<String>,
    pub(crate) created_at: String,
}

/// A `config_entries` row — the **installed manifest + store-refcount index**
/// for one provisioned config/skill artifact (agent-architecture §3/§9b).
/// It records *what is materialized where*, not the bytes: the
/// content lives in the filesystem store and the desired set lives in config
/// (global) / `tasks.entries` (task). `id` is auto-assigned by SQLite.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ConfigEntryRow {
    pub(crate) id: i64,
    /// Materialization location: `'global'` (engine-config root) | `<thread_id>`
    /// (per-thread `project/`).
    pub(crate) scope: String,
    /// Logical id (= store `<name>`).
    pub(crate) name: String,
    /// Full hash (version / integrity).
    pub(crate) sha256: String,
    /// Store short id (`sha256[:12]`).
    pub(crate) short: String,
    /// Relative landing path (meta-driven; e.g. `CLAUDE.md` | `.claude/skills/x`).
    pub(crate) target: String,
    /// `file` | `dir`.
    pub(crate) kind: String,
    /// `store/<name>/<short>`.
    pub(crate) store_path: String,
    /// `<scope-root>/<target>`.
    pub(crate) link_path: String,
    pub(crate) installed_at: String,
}

/// The `e2ee_key_packages` singleton: the sealed KeyPackageStore snapshot and
/// when the current last-resort KeyPackage was generated.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct E2eeKeyPackagesRow {
    pub(crate) store: Vec<u8>,
    pub(crate) last_resort_created_at: Option<String>,
}

/// An `e2ee_groups` row: the runner's MLS group state of one encrypted task.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct E2eeGroupRow {
    pub(crate) task_id: String,
    pub(crate) group_id: String,
    pub(crate) profile_id: String,
    /// Sealed `ScopeGroup` snapshot; `None` until a Welcome is processed.
    pub(crate) snapshot: Option<Vec<u8>>,
    pub(crate) last_seq: Option<i64>,
    /// `pending`, `member`, `removed` or `lost`.
    pub(crate) status: String,
    pub(crate) updated_at: String,
}

/// An `e2ee_key_cache` row: sealed epoch secrets of one task epoch.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct E2eeKeyCacheRow {
    pub(crate) secrets: Vec<u8>,
    pub(crate) verified: bool,
}

/// An `e2ee_log_pending` row: one buffered `e2ee_log`/`e2ee_welcome` record.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct E2eeLogPendingRow {
    pub(crate) task_id: String,
    pub(crate) seq: i64,
    /// `e2ee_log` or `e2ee_welcome`.
    pub(crate) msg_type: String,
    /// The frame's `data` as received (JSON).
    pub(crate) payload: String,
    pub(crate) received_at: String,
}

/// A task's `task_upsert.data.e2ee`, as stored on its row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TaskE2eeRow {
    pub(crate) profile_id: String,
    pub(crate) group_id: String,
}

/// The persisted runner identity. The token is held as a
/// `SecretString` so it is redacted in `Debug`/log output.
#[derive(Clone, Debug)]
pub(crate) struct Identity {
    pub(crate) agent_id: String,
    pub(crate) connect_token: SecretString,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// The runner's SQLite store. Owns one connection; all access is through cached
/// prepared statements.
///
/// DECISION (execution placement): every rusqlite call on this type runs
/// inline on the calling thread — often a tokio async worker — rather than
/// through `spawn_blocking`. This is deliberate. Current posture: statements
/// are short point-indexed reads/writes on a WAL database with a single writer
/// (the daemon), the execution plane is strictly serial, and the 3 s
/// `busy_timeout` is a worst-case bound that engages only against a short-lived
/// CLI invocation — in steady state each call is microseconds of blocking, far
/// below the cost of a blocking-pool hop. Converting call sites piecemeal is
/// the one option that is NOT acceptable: callers hold the global `Mutex<Db>`
/// around each call, so a `spawn_blocking` inside the guard means holding the
/// mutex across an `.await` (a known deadlock source in this codebase) and a
/// `spawn_blocking` outside means handing the guard to another thread. A future
/// migration, if profiling ever shows DB stalls on the runtime, must move the
/// whole type behind an owned boundary in one step: either a dedicated DB
/// thread consuming a channel of operations, or `spawn_blocking` at the Db API
/// boundary with the connection owned by the blocking side — never
/// mutex-across-await.
#[derive(Debug)]
pub(crate) struct Db {
    conn: Connection,
}

impl Db {
    /// Open (creating if absent) the database at `path` and migrate it to
    /// [`SCHEMA_VERSION`] — the **daemon** open path.
    ///
    /// The connect token lives in this file in plaintext (SQLite has no secret
    /// type), so the DB file — and its WAL/SHM siblings — are chmod'd `0600` on
    /// every open: fresh files are created private, and pre-existing deployments
    /// that shipped world-readable (default umask 0644) are healed at startup.
    pub(crate) fn open(path: &Path) -> DbResult<Self> {
        let conn = Connection::open(path)?;
        // Harden BEFORE the first write: a WAL/SHM sqlite creates during
        // `from_connection` inherits the main file's (now 0600) mode; siblings
        // left behind by an earlier 0644 deployment are healed explicitly.
        harden_db_files(path)?;
        Self::from_connection(conn)
    }

    /// Open an ephemeral in-memory database (used by unit tests).
    #[cfg(test)]
    pub(crate) fn open_in_memory() -> DbResult<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> DbResult<Self> {
        conn.execute_batch(PRAGMAS)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Create the schema in a fresh database; an up-to-date one is a no-op. A
    /// database at any other version, or an unversioned one that already has
    /// tables, is refused — pre-release, there is no upgrade path.
    pub(crate) fn migrate(&self) -> DbResult<()> {
        let version = self.user_version()?;
        if version == SCHEMA_VERSION {
            return Ok(());
        }
        if version > SCHEMA_VERSION {
            return Err(DbError::SchemaNewerThanBinary {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        if version != 0 || !self.is_uninitialized()? {
            return Err(DbError::UnsupportedSchema { found: version });
        }
        self.immediate_transaction(|db| {
            db.conn.execute_batch(SCHEMA)?;
            db.conn
                .pragma_update(None, "user_version", SCHEMA_VERSION)?;
            Ok(())
        })
    }

    /// The schema version recorded in the DB header (`PRAGMA user_version`).
    pub(crate) fn user_version(&self) -> DbResult<i64> {
        let version = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?;
        Ok(version)
    }

    /// Whether the DB holds no tables at all — a freshly created file (or a
    /// pristine in-memory DB).
    fn is_uninitialized(&self) -> DbResult<bool> {
        let tables: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        Ok(tables == 0)
    }

    /// Run `f` inside one `BEGIN IMMEDIATE` transaction on the shared connection:
    /// every write `f` makes commits atomically, and any error rolls the whole
    /// batch back (the [`rusqlite::Transaction`] drop is a rollback). This is the
    /// result-plane atomicity primitive: the scheduler wraps a whole
    /// cron fire in it and the executor wraps the terminal persist+enqueue pair.
    ///
    /// The caller must hold the global DB mutex for the duration of the call
    /// (i.e. call this through the usual `lock_db` guard) so no other statement
    /// interleaves into the open transaction. `f` must only use the plain
    /// single-statement accessors — nesting `immediate_transaction` would fail.
    pub(crate) fn immediate_transaction<T>(
        &self,
        f: impl FnOnce(&Self) -> DbResult<T>,
    ) -> DbResult<T> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.conn,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let value = f(self)?;
        tx.commit()?;
        Ok(value)
    }

    /// Execute raw SQL — test-only escape hatch for fault injection (dropping a
    /// table mid-flight, toggling pragmas) in the transactional-plane tests.
    #[cfg(test)]
    pub(crate) fn exec_raw(&self, sql: &str) -> DbResult<()> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Recreate the `outbox` table after a fault-injection `DROP TABLE outbox`
    /// (the transactional-plane tests' failure lever). `migrate()` no longer
    /// repairs dropped tables — it is a versioned ladder and a no-op at the
    /// latest version — so the tests restore the table explicitly.
    #[cfg(test)]
    pub(crate) fn restore_outbox_table(&self) -> DbResult<()> {
        self.exec_raw(
            "CREATE TABLE outbox (
               id          TEXT    PRIMARY KEY,
               type        TEXT    NOT NULL,
               payload     TEXT    NOT NULL,
               task_id     TEXT,
               thread_id   TEXT,
               created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
               acked_at    TEXT,
               retry_count INTEGER NOT NULL DEFAULT 0
             );",
        )
    }

    // -- Outbox (at-least-once, runner → host) -----------------------------

    /// Persist a message to the outbox before sending, tagging it with the
    /// correlation ids (either may be `None`). Returns the new row's ULID.
    pub(crate) fn enqueue_outbox_correlated<T: Serialize>(
        &self,
        msg_type: &str,
        payload: &T,
        task_id: Option<&str>,
        thread_id: Option<&str>,
    ) -> DbResult<String> {
        let id = new_delivery_id();
        self.enqueue_outbox_with_id(&id, msg_type, payload, task_id, thread_id)?;
        Ok(id)
    }

    /// [`Self::enqueue_outbox_correlated`] under an `id` minted beforehand by
    /// [`new_delivery_id`] (a frame whose payload binds its own `outboxId`).
    pub(crate) fn enqueue_outbox_with_id<T: Serialize>(
        &self,
        id: &str,
        msg_type: &str,
        payload: &T,
        task_id: Option<&str>,
        thread_id: Option<&str>,
    ) -> DbResult<()> {
        let json = serde_json::to_string(payload)?;
        self.conn
            .prepare_cached(
                "INSERT INTO outbox (id, type, payload, task_id, thread_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?
            .execute(params![id, msg_type, json, task_id, thread_id])?;
        Ok(())
    }

    /// Persist a message to the outbox before sending (no correlation ids).
    /// Returns the new row's ULID.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "test-only convenience over enqueue_outbox_correlated (production always correlates); keeps the surface honest"
        )
    )]
    pub(crate) fn enqueue_outbox<T: Serialize>(
        &self,
        msg_type: &str,
        payload: &T,
    ) -> DbResult<String> {
        self.enqueue_outbox_correlated(msg_type, payload, None, None)
    }

    /// All outbox rows the host has not yet acknowledged, oldest first.
    pub(crate) fn list_unacked_outbox(&self) -> DbResult<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, type, payload, task_id, thread_id, created_at, acked_at, retry_count
               FROM outbox WHERE acked_at IS NULL ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(OutboxRow {
                    id: r.get(0)?,
                    msg_type: r.get(1)?,
                    payload: r.get(2)?,
                    task_id: r.get(3)?,
                    thread_id: r.get(4)?,
                    created_at: r.get(5)?,
                    acked_at: r.get(6)?,
                    retry_count: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Mark an outbox row acknowledged. Idempotent — re-acking an already-acked
    /// row is a harmless no-op (it simply stays out of [`Self::list_unacked_outbox`]).
    pub(crate) fn mark_outbox_acked(&self, id: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE outbox SET acked_at = datetime('now') WHERE id = ?1")?
            .execute(params![id])?;
        Ok(())
    }

    /// Bump an outbox row's retry counter before a replay attempt.
    pub(crate) fn increment_outbox_retry(&self, id: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE outbox SET retry_count = retry_count + 1 WHERE id = ?1")?
            .execute(params![id])?;
        Ok(())
    }

    /// Dead-letter a poison outbox row (audit P3): stamp `acked_at` so it leaves
    /// the replay set and ages out with the acked rows. DECISION: `acked_at`
    /// doubles as the tombstone — the inbox poison policy reuses `processed_at`
    /// the same way — so no schema change is needed and `acked_at IS NULL` stays
    /// the single replay predicate the partial index serves.
    pub(crate) fn mark_outbox_dead(&self, id: &str) -> DbResult<()> {
        self.mark_outbox_acked(id)
    }

    // -- Inbox (at-least-once replay, host → runner) -----------------------

    /// Persist an inbound message to the inbox for at-least-once processing,
    /// tagging it with the correlation ids (either may be `None`) and the
    /// host's delivery `msg_id`. The `msg_id` UNIQUE column is the at-least-once
    /// dedup (protocol.md §6): a redelivery of an already-stored `msg_id` is a
    /// no-op and returns `None` (the caller re-acks); a fresh insert returns the
    /// new row id. A `None` msg_id (frame without one) always inserts.
    pub(crate) fn record_inbound_correlated<T: Serialize>(
        &self,
        msg_type: &str,
        payload: &T,
        task_id: Option<&str>,
        thread_id: Option<&str>,
        msg_id: Option<&str>,
    ) -> DbResult<Option<i64>> {
        let json = serde_json::to_string(payload)?;
        let inserted = self
            .conn
            .prepare_cached(
                "INSERT INTO inbox (type, payload, task_id, thread_id, msg_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(msg_id) DO NOTHING",
            )?
            .execute(params![msg_type, json, task_id, thread_id, msg_id])?;
        Ok((inserted > 0).then(|| self.conn.last_insert_rowid()))
    }

    /// Persist an inbound message to the inbox (no correlation ids, no delivery
    /// id — never deduped). Returns the new row id.
    #[cfg(test)]
    pub(crate) fn record_inbound<T: Serialize>(
        &self,
        msg_type: &str,
        payload: &T,
    ) -> DbResult<i64> {
        let id = self
            .record_inbound_correlated(msg_type, payload, None, None, None)?
            .expect("insert without msg_id never conflicts");
        Ok(id)
    }

    /// All inbox rows not yet processed, oldest first.
    pub(crate) fn list_unprocessed_inbox(&self) -> DbResult<Vec<InboxRow>> {
        self.query_inbox(
            "SELECT id, type, payload, task_id, thread_id, received_at, processed_at, retry_count
               FROM inbox WHERE processed_at IS NULL ORDER BY id",
            params![],
        )
    }

    /// Unprocessed inbox rows of a given `type`, oldest first.
    pub(crate) fn list_inbox_by_type(&self, msg_type: &str) -> DbResult<Vec<InboxRow>> {
        self.query_inbox(
            "SELECT id, type, payload, task_id, thread_id, received_at, processed_at, retry_count
               FROM inbox WHERE type = ?1 AND processed_at IS NULL ORDER BY id",
            params![msg_type],
        )
    }

    fn query_inbox(&self, sql: &str, params: &[&dyn rusqlite::ToSql]) -> DbResult<Vec<InboxRow>> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt
            .query_map(params, |r| {
                Ok(InboxRow {
                    id: r.get(0)?,
                    msg_type: r.get(1)?,
                    payload: r.get(2)?,
                    task_id: r.get(3)?,
                    thread_id: r.get(4)?,
                    received_at: r.get(5)?,
                    processed_at: r.get(6)?,
                    retry_count: r.get(7)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Mark an inbox row processed (dedup: it will not be replayed again).
    pub(crate) fn mark_inbox_processed(&self, id: i64) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE inbox SET processed_at = datetime('now') WHERE id = ?1")?
            .execute(params![id])?;
        Ok(())
    }

    /// Bump an inbox row's processing-failure counter after a failed apply,
    /// returning the new count (drives the poison policy: the row is discarded
    /// once the count reaches the limit).
    pub(crate) fn increment_inbox_retry(&self, id: i64) -> DbResult<i64> {
        let count = self
            .conn
            .prepare_cached(
                "UPDATE inbox SET retry_count = retry_count + 1 WHERE id = ?1
                 RETURNING retry_count",
            )?
            .query_row(params![id], |r| r.get(0))?;
        Ok(count)
    }

    // -- Tasks (v2 top category) -------------------------------------------

    /// Insert a v2 task entity row. The legacy shim columns take their schema
    /// defaults (`prompt`/`schedule_type`/`schedule_value` → `''`).
    pub(crate) fn insert_task_row(&self, task: &TaskRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO tasks (id, name, kind, status, engine, model, workdir, meta, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?
            .execute(params![
                task.id,
                task.name,
                task.kind,
                task.status,
                task.engine,
                task.model,
                task.workdir,
                task.meta,
                task.created_at,
                task.updated_at,
            ])?;
        Ok(())
    }

    /// Read a single v2 task entity by id, or `None`.
    pub(crate) fn get_task_row(&self, id: &str) -> DbResult<Option<TaskRow>> {
        let row = self
            .conn
            .prepare_cached(
                "SELECT id, name, kind, status, engine, model, workdir, meta, created_at, updated_at
                 FROM tasks WHERE id = ?1",
            )?
            .query_row(params![id], Self::map_task_row)
            .optional()?;
        Ok(row)
    }

    /// Every task on this agent, oldest first — the `gino-agent task list` view.
    pub(crate) fn list_tasks(&self) -> DbResult<Vec<TaskRow>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT id, name, kind, status, engine, model, workdir, meta, created_at, updated_at
                 FROM tasks ORDER BY created_at, id",
            )?
            .query_map([], Self::map_task_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Update a v2 task entity's mutable columns by id (`created_at` is immutable).
    /// Writes the row WHOLESALE, so the omission-preserves rule for a partial
    /// `task_upsert` lives in the caller: it loads the row, patches only the
    /// fields the host sent, and writes it back (`runner::apply_task_def`).
    pub(crate) fn update_task_row(&self, task: &TaskRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "UPDATE tasks
                    SET name = ?2, kind = ?3, status = ?4, engine = ?5, model = ?6,
                        workdir = ?7, meta = ?8, updated_at = ?9
                  WHERE id = ?1",
            )?
            .execute(params![
                task.id,
                task.name,
                task.kind,
                task.status,
                task.engine,
                task.model,
                task.workdir,
                task.meta,
                task.updated_at,
            ])?;
        Ok(())
    }

    /// Whether `task_id`'s status parks execution (D1): a `closed`/`cancelled`
    /// task neither fires its crons nor dispatches its pending threads / queued
    /// inbox messages. Every other status — including an unknown one — keeps
    /// running, and so does a MISSING row: the runner seeds task rows lazily
    /// ([`crate::chat::seed_task_if_missing`]), so absence means not-yet-seeded,
    /// never closed.
    pub(crate) fn task_execution_blocked(&self, task_id: &str) -> DbResult<bool> {
        let blocked = self
            .conn
            .prepare_cached(
                "SELECT 1 FROM tasks WHERE id = ?1 AND status IN ('closed', 'cancelled')",
            )?
            .exists(params![task_id])?;
        Ok(blocked)
    }

    fn map_task_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskRow> {
        Ok(TaskRow {
            id: r.get(0)?,
            name: r.get(1)?,
            kind: r.get(2)?,
            status: r.get(3)?,
            engine: r.get(4)?,
            model: r.get(5)?,
            workdir: r.get(6)?,
            meta: r.get(7)?,
            created_at: r.get(8)?,
            updated_at: r.get(9)?,
        })
    }

    // -- Crons (v2 triggers) -----------------------------------------------

    /// Insert a new cron (trigger) row.
    pub(crate) fn insert_cron(&self, cron: &CronRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO crons
                   (id, task_id, kind, prompt, schedule_type, schedule_value, next_run, last_fired_at,
                    continuity, run_count, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?
            .execute(params![
                cron.id,
                cron.task_id,
                cron.kind,
                cron.prompt,
                cron.schedule_type,
                cron.schedule_value,
                cron.next_run,
                cron.last_fired_at,
                cron.continuity,
                cron.run_count,
                cron.status,
                cron.created_at,
                cron.updated_at,
            ])?;
        Ok(())
    }

    /// Update an existing cron's mutable columns by id (`created_at` is immutable).
    pub(crate) fn update_cron(&self, cron: &CronRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "UPDATE crons SET
                   task_id = ?2, kind = ?3, prompt = ?4, schedule_type = ?5, schedule_value = ?6,
                   next_run = ?7, last_fired_at = ?8, continuity = ?9, run_count = ?10,
                   status = ?11, updated_at = ?12
                 WHERE id = ?1",
            )?
            .execute(params![
                cron.id,
                cron.task_id,
                cron.kind,
                cron.prompt,
                cron.schedule_type,
                cron.schedule_value,
                cron.next_run,
                cron.last_fired_at,
                cron.continuity,
                cron.run_count,
                cron.status,
                cron.updated_at,
            ])?;
        Ok(())
    }

    /// Advance a fired cron **in place**: a targeted UPDATE of only the
    /// scheduling columns (`next_run`, `last_fired_at`, `run_count`, `status`,
    /// `updated_at`), guarded by `status = 'active'` so a `cron_delete` /
    /// `cron_upsert` that landed after the scheduler's tick-read is never
    /// overwritten by stale full-row state (a deleted cron must not be
    /// resurrected). Returns `false` when the guard rejected the advance (the
    /// cron is gone or no longer active).
    pub(crate) fn advance_cron(
        &self,
        id: &str,
        next_run: Option<&str>,
        last_fired_at: &str,
        run_count: i64,
        status: &str,
        updated_at: &str,
    ) -> DbResult<bool> {
        let changed = self
            .conn
            .prepare_cached(
                "UPDATE crons SET
                   next_run = ?2, last_fired_at = ?3, run_count = ?4, status = ?5, updated_at = ?6
                 WHERE id = ?1 AND status = 'active'",
            )?
            .execute(params![
                id,
                next_run,
                last_fired_at,
                run_count,
                status,
                updated_at
            ])?;
        Ok(changed == 1)
    }

    /// Read a single cron by id, or `None`.
    pub(crate) fn get_cron(&self, id: &str) -> DbResult<Option<CronRow>> {
        let cron = self
            .conn
            .prepare_cached(
                "SELECT id, task_id, kind, prompt, schedule_type, schedule_value, next_run, last_fired_at,
                        continuity, run_count, status, created_at, updated_at
                   FROM crons WHERE id = ?1",
            )?
            .query_row(params![id], Self::map_cron)
            .optional()?;
        Ok(cron)
    }

    /// All crons with `status = 'active'`, oldest first — the scheduler's load set.
    pub(crate) fn list_active_crons(&self) -> DbResult<Vec<CronRow>> {
        self.query_crons(
            "SELECT id, task_id, kind, prompt, schedule_type, schedule_value, next_run, last_fired_at,
                    continuity, run_count, status, created_at, updated_at
               FROM crons WHERE status = 'active' ORDER BY created_at, id",
        )
    }

    /// Every cron under a task (any status), oldest first — the `gino-agent cron
    /// list` view for the AI managing its own task's triggers.
    pub(crate) fn list_crons_by_task(&self, task_id: &str) -> DbResult<Vec<CronRow>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT id, task_id, kind, prompt, schedule_type, schedule_value, next_run, last_fired_at,
                        continuity, run_count, status, created_at, updated_at
                   FROM crons WHERE task_id = ?1 ORDER BY created_at, id",
            )?
            .query_map(params![task_id], Self::map_cron)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn query_crons(&self, sql: &str) -> DbResult<Vec<CronRow>> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt
            .query_map([], Self::map_cron)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn map_cron(r: &rusqlite::Row<'_>) -> rusqlite::Result<CronRow> {
        Ok(CronRow {
            id: r.get(0)?,
            task_id: r.get(1)?,
            kind: r.get(2)?,
            prompt: r.get(3)?,
            schedule_type: r.get(4)?,
            schedule_value: r.get(5)?,
            next_run: r.get(6)?,
            last_fired_at: r.get(7)?,
            continuity: r.get(8)?,
            run_count: r.get(9)?,
            status: r.get(10)?,
            created_at: r.get(11)?,
            updated_at: r.get(12)?,
        })
    }

    // -- Threads (v2 engine executions) ------------------------------------

    /// Insert a new thread row.
    pub(crate) fn insert_thread(&self, t: &ThreadRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO threads
                   (id, task_id, cron_id, source, prompt, engine, engine_session_id, status,
                    failure_reason, attempt, max_attempts, work_dir, started_at, finished_at,
                    duration_ms, result, error, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            )?
            .execute(params![
                t.id,
                t.task_id,
                t.cron_id,
                t.source,
                t.prompt,
                t.engine,
                t.engine_session_id,
                t.status,
                t.failure_reason,
                t.attempt,
                t.max_attempts,
                t.work_dir,
                t.started_at,
                t.finished_at,
                t.duration_ms,
                t.result,
                t.error,
                t.created_at,
            ])?;
        Ok(())
    }

    /// Update a thread's mutable columns by id (`id`/`task_id`/`cron_id`/
    /// `source`/`engine`/`created_at` are immutable once the row is born).
    pub(crate) fn update_thread(&self, t: &ThreadRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "UPDATE threads SET
                   engine_session_id = ?2, status = ?3, failure_reason = ?4, attempt = ?5,
                   max_attempts = ?6, work_dir = ?7, started_at = ?8, finished_at = ?9,
                   duration_ms = ?10, result = ?11, error = ?12, prompt = ?13
                 WHERE id = ?1",
            )?
            .execute(params![
                t.id,
                t.engine_session_id,
                t.status,
                t.failure_reason,
                t.attempt,
                t.max_attempts,
                t.work_dir,
                t.started_at,
                t.finished_at,
                t.duration_ms,
                t.result,
                t.error,
                t.prompt,
            ])?;
        Ok(())
    }

    /// CAS-claim a pending thread: `pending → dispatched`,
    /// stamping the attempt's `started_at` and the assigned `work_dir`, guarded
    /// by `status = 'pending'`. Returns `false` when the guard rejected the
    /// claim — the row is gone, already claimed (a concurrent claimer won), or
    /// otherwise no longer pending — so even a rogue second daemon cannot drive
    /// the same thread twice.
    pub(crate) fn claim_pending_thread(
        &self,
        id: &str,
        started_at: &str,
        work_dir: &str,
    ) -> DbResult<bool> {
        let changed = self
            .conn
            .prepare_cached(
                "UPDATE threads SET status = 'dispatched', started_at = ?2, work_dir = ?3
                  WHERE id = ?1 AND status = 'pending'",
            )?
            .execute(params![id, started_at, work_dir])?;
        Ok(changed == 1)
    }

    /// Read a single thread by id, or `None`.
    pub(crate) fn get_thread(&self, id: &str) -> DbResult<Option<ThreadRow>> {
        let thread = self
            .conn
            .prepare_cached(
                "SELECT id, task_id, cron_id, source, prompt, engine, engine_session_id, status,
                        failure_reason, attempt, max_attempts, work_dir, started_at, finished_at,
                        duration_ms, result, error, created_at
                   FROM threads WHERE id = ?1",
            )?
            .query_row(params![id], Self::map_thread)
            .optional()?;
        Ok(thread)
    }

    /// All threads with `status = 'pending'`, oldest first — the executor's
    /// source-agnostic drain set (agent-architecture §5).
    pub(crate) fn list_pending_threads(&self) -> DbResult<Vec<ThreadRow>> {
        self.query_threads(
            "SELECT id, task_id, cron_id, source, prompt, engine, engine_session_id, status,
                    failure_reason, attempt, max_attempts, work_dir, started_at, finished_at,
                    duration_ms, result, error, created_at
               FROM threads WHERE status = 'pending' ORDER BY created_at, id",
        )
    }

    /// Every thread in a given `status`, oldest first. The executor watchdog
    /// uses this to reap crash-orphans left in `dispatched`/`running` after an
    /// unclean restart — the live in-flight set alone misses rows abandoned by
    /// a previous process (agent-architecture §5).
    pub(crate) fn list_threads_by_status(&self, status: &str) -> DbResult<Vec<ThreadRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, task_id, cron_id, source, prompt, engine, engine_session_id, status,
                    failure_reason, attempt, max_attempts, work_dir, started_at, finished_at,
                    duration_ms, result, error, created_at
               FROM threads WHERE status = ?1 ORDER BY created_at, id",
        )?;
        let rows = stmt
            .query_map(params![status], Self::map_thread)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// The last per-thread `seq` the executor emitted, or `0` if the thread is
    /// fresh or unknown. The executor reads this at (re)start so seq numbering
    /// **continues** across a runner restart: the host dedups on
    /// `(thread_id, seq)`, so restarting from 1 would collide and drop emits
    /// (agent-architecture §5/§6).
    /// Every thread under a task, oldest first — the `gino-agent thread list` view.
    pub(crate) fn list_threads_by_task(&self, task_id: &str) -> DbResult<Vec<ThreadRow>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT id, task_id, cron_id, source, prompt, engine, engine_session_id, status,
                        failure_reason, attempt, max_attempts, work_dir, started_at, finished_at,
                        duration_ms, result, error, created_at
                   FROM threads WHERE task_id = ?1 ORDER BY created_at, id",
            )?
            .query_map(params![task_id], Self::map_thread)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub(crate) fn get_thread_last_seq(&self, thread_id: &str) -> DbResult<i64> {
        let seq = self
            .conn
            .prepare_cached("SELECT last_seq FROM threads WHERE id = ?1")?
            .query_row(params![thread_id], |r| r.get(0))
            .optional()?
            .unwrap_or(0);
        Ok(seq)
    }

    /// Persist the highest `seq` emitted for a thread. A no-op (0 rows changed)
    /// when the thread id is unknown.
    pub(crate) fn set_thread_last_seq(&self, thread_id: &str, seq: i64) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE threads SET last_seq = ?2 WHERE id = ?1")?
            .execute(params![thread_id, seq])?;
        Ok(())
    }

    /// Record the `outboxId` of a thread's latest `thread_result`.
    pub(crate) fn set_thread_result_outbox_id(&self, thread_id: &str, id: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE threads SET result_outbox_id = ?2 WHERE id = ?1")?
            .execute(params![thread_id, id])?;
        Ok(())
    }

    /// The `outboxId` of a thread's latest `thread_result`, if any.
    pub(crate) fn get_thread_result_outbox_id(&self, thread_id: &str) -> DbResult<Option<String>> {
        let id = self
            .conn
            .prepare_cached("SELECT result_outbox_id FROM threads WHERE id = ?1")?
            .query_row(params![thread_id], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(id)
    }

    fn query_threads(&self, sql: &str) -> DbResult<Vec<ThreadRow>> {
        let mut stmt = self.conn.prepare_cached(sql)?;
        let rows = stmt
            .query_map([], Self::map_thread)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn map_thread(r: &rusqlite::Row<'_>) -> rusqlite::Result<ThreadRow> {
        Ok(ThreadRow {
            id: r.get(0)?,
            task_id: r.get(1)?,
            cron_id: r.get(2)?,
            source: r.get(3)?,
            prompt: r.get(4)?,
            engine: r.get(5)?,
            engine_session_id: r.get(6)?,
            status: r.get(7)?,
            failure_reason: r.get(8)?,
            attempt: r.get(9)?,
            max_attempts: r.get(10)?,
            work_dir: r.get(11)?,
            started_at: r.get(12)?,
            finished_at: r.get(13)?,
            duration_ms: r.get(14)?,
            result: r.get(15)?,
            error: r.get(16)?,
            created_at: r.get(17)?,
        })
    }

    // -- Cron logs (v2 per-fire ledger) ------------------------------------

    /// Append a fire to the ledger. A duplicate `(cron_id, scheduled_at)` is
    /// **rejected** by the schema `UNIQUE` constraint (the error surfaces as
    /// [`DbError::Sqlite`]) — this is the durable firing-dedup contract. Use
    /// [`Self::try_insert_cron_log`] for the idempotent (no-error) variant.
    /// `created_at` is DB-defaulted. Returns the new row id.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "test-only writer of the cron ledger (production fires through try_insert_cron_log); keeps the surface honest"
        )
    )]
    pub(crate) fn insert_cron_log(&self, log: &CronLogRow) -> DbResult<i64> {
        self.conn
            .prepare_cached(
                "INSERT INTO cron_logs
                   (cron_id, task_id, round_seq, scheduled_at, fired_at, status, skip_reason, thread_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                log.cron_id,
                log.task_id,
                log.round_seq,
                log.scheduled_at,
                log.fired_at,
                log.status,
                log.skip_reason,
                log.thread_id,
            ])?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Idempotent ledger append: `INSERT OR IGNORE`. Returns `Some(id)` on a
    /// fresh fire, or `None` when `(cron_id, scheduled_at)` was already logged
    /// (the fire is a duplicate and must not double-dispatch). This is the
    /// scheduler's hot-path dedup primitive (replaces the in-memory `HashSet`).
    pub(crate) fn try_insert_cron_log(&self, log: &CronLogRow) -> DbResult<Option<i64>> {
        let changed = self
            .conn
            .prepare_cached(
                "INSERT OR IGNORE INTO cron_logs
                   (cron_id, task_id, round_seq, scheduled_at, fired_at, status, skip_reason, thread_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?
            .execute(params![
                log.cron_id,
                log.task_id,
                log.round_seq,
                log.scheduled_at,
                log.fired_at,
                log.status,
                log.skip_reason,
                log.thread_id,
            ])?;
        Ok((changed == 1).then(|| self.conn.last_insert_rowid()))
    }

    /// Read a single cron-log row by id, or `None`.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "test-only reader of the cron ledger (its own and the scheduler's unit tests); keeps the surface honest"
        )
    )]
    pub(crate) fn get_cron_log(&self, id: i64) -> DbResult<Option<CronLogRow>> {
        let log = self
            .conn
            .prepare_cached(
                "SELECT id, cron_id, task_id, round_seq, scheduled_at, fired_at, status,
                        skip_reason, thread_id, created_at
                   FROM cron_logs WHERE id = ?1",
            )?
            .query_row(params![id], Self::map_cron_log)
            .optional()?;
        Ok(log)
    }

    /// The highest `round_seq` recorded for a cron, or `None` if it has never
    /// fired. This is the **round-count truth** (D4); `crons.run_count` is a
    /// startup-reconciled cache of it.
    pub(crate) fn max_round_seq(&self, cron_id: &str) -> DbResult<Option<i64>> {
        let max = self
            .conn
            .prepare_cached("SELECT MAX(round_seq) FROM cron_logs WHERE cron_id = ?1")?
            .query_row(params![cron_id], |r| r.get::<_, Option<i64>>(0))?;
        Ok(max)
    }

    fn map_cron_log(r: &rusqlite::Row<'_>) -> rusqlite::Result<CronLogRow> {
        Ok(CronLogRow {
            id: r.get(0)?,
            cron_id: r.get(1)?,
            task_id: r.get(2)?,
            round_seq: r.get(3)?,
            scheduled_at: r.get(4)?,
            fired_at: r.get(5)?,
            status: r.get(6)?,
            skip_reason: r.get(7)?,
            thread_id: r.get(8)?,
            created_at: r.get(9)?,
        })
    }

    // -- Config entries (v2 provisioning manifest / store index) -----------

    /// Upsert one installed-config-entry row, keyed by `(scope, target)` — the
    /// one-artifact-per-landing-path invariant. A repoint (new `sha256`/`short`/
    /// `store_path`/`link_path`/`kind`) updates the row in place rather than
    /// inserting a second; `id`/`scope`/`target` are the stable identity.
    pub(crate) fn upsert_config_entry(&self, row: &ConfigEntryRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO config_entries
                   (scope, name, sha256, short, target, kind, store_path, link_path, installed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(scope, target) DO UPDATE SET
                   name = excluded.name, sha256 = excluded.sha256, short = excluded.short,
                   kind = excluded.kind, store_path = excluded.store_path,
                   link_path = excluded.link_path, installed_at = excluded.installed_at",
            )?
            .execute(params![
                row.scope,
                row.name,
                row.sha256,
                row.short,
                row.target,
                row.kind,
                row.store_path,
                row.link_path,
                row.installed_at,
            ])?;
        Ok(())
    }

    /// All installed entries for one `scope`, ordered by `target` — the desired-vs-
    /// installed diff set for reconcile.
    pub(crate) fn list_config_entries(&self, scope: &str) -> DbResult<Vec<ConfigEntryRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, scope, name, sha256, short, target, kind, store_path, link_path, installed_at
               FROM config_entries WHERE scope = ?1 ORDER BY target",
        )?;
        let rows = stmt
            .query_map(params![scope], Self::map_config_entry)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every installed entry across all scopes, ordered by `(scope, target)` — the
    /// restart-repair and GC-sweep load set.
    pub(crate) fn list_all_config_entries(&self) -> DbResult<Vec<ConfigEntryRow>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, scope, name, sha256, short, target, kind, store_path, link_path, installed_at
               FROM config_entries ORDER BY scope, target",
        )?;
        let rows = stmt
            .query_map([], Self::map_config_entry)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Remove one installed entry by `(scope, target)` (reconcile drops an entry
    /// no longer in the desired set; the symlink teardown is a later L3).
    pub(crate) fn delete_config_entry(&self, scope: &str, target: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("DELETE FROM config_entries WHERE scope = ?1 AND target = ?2")?
            .execute(params![scope, target])?;
        Ok(())
    }

    /// The GC refcount: how many installed entries reference one store artifact
    /// `store/<name>/<sha256[:12]>` (keyed by full `(name, sha256)`, across all
    /// scopes). `store/<name>/<short>` is removable once this drops to 0.
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "test-only read model (the provisioner GC refcounts in bulk via list_config_entries); keeps the surface honest"
        )
    )]
    pub(crate) fn count_store_refs(&self, name: &str, sha256: &str) -> DbResult<i64> {
        let count = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM config_entries WHERE name = ?1 AND sha256 = ?2")?
            .query_row(params![name, sha256], |r| r.get(0))?;
        Ok(count)
    }

    fn map_config_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConfigEntryRow> {
        Ok(ConfigEntryRow {
            id: r.get(0)?,
            scope: r.get(1)?,
            name: r.get(2)?,
            sha256: r.get(3)?,
            short: r.get(4)?,
            target: r.get(5)?,
            kind: r.get(6)?,
            store_path: r.get(7)?,
            link_path: r.get(8)?,
            installed_at: r.get(9)?,
        })
    }

    // -- Task entries (v2 task DESIRED provisioning set) -------------------

    /// Set (or clear, with `None`) a task's `entries` column — the JSON array of
    /// its desired provisioning entries. Kept off [`TaskRow`] so the
    /// existing v2 task CRUD sites stay untouched; the host pushes this via
    /// `task_upsert.data.entries`.
    pub(crate) fn set_task_entries(
        &self,
        task_id: &str,
        entries_json: Option<&str>,
    ) -> DbResult<()> {
        self.conn
            .prepare_cached("UPDATE tasks SET entries = ?2 WHERE id = ?1")?
            .execute(params![task_id, entries_json])?;
        Ok(())
    }

    /// Read a task's `entries` JSON, or `None` when the column is NULL or the task
    /// is absent.
    pub(crate) fn get_task_entries(&self, task_id: &str) -> DbResult<Option<String>> {
        let entries = self
            .conn
            .prepare_cached("SELECT entries FROM tasks WHERE id = ?1")?
            .query_row(params![task_id], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten();
        Ok(entries)
    }

    // -- Thread attachments (inbound descriptor snapshot, audit P1-10b) -----

    /// Persist (or replace) the inbound attachment descriptors snapshotted for a
    /// thread. Serialized here (like the outbox/inbox payloads) so the schema
    /// stays wire-agnostic; the runner writes this BEFORE consuming the inbox
    /// `message` the descriptors rode in on, making retries and restarts see the
    /// same attachments the first attempt saw.
    pub(crate) fn set_thread_attachments<T: Serialize>(
        &self,
        thread_id: &str,
        descriptors: &T,
    ) -> DbResult<()> {
        let json = serde_json::to_string(descriptors)?;
        self.conn
            .prepare_cached(
                "INSERT INTO thread_attachments (thread_id, descriptors) VALUES (?1, ?2)
                 ON CONFLICT(thread_id) DO UPDATE SET descriptors = excluded.descriptors",
            )?
            .execute(params![thread_id, json])?;
        Ok(())
    }

    /// Read a thread's snapshotted inbound descriptors JSON, or `None` when the
    /// thread never carried any. The row is never deleted on read — a retried or
    /// recovered thread must resolve the identical set on every attempt.
    pub(crate) fn get_thread_attachments(&self, thread_id: &str) -> DbResult<Option<String>> {
        let json = self
            .conn
            .prepare_cached("SELECT descriptors FROM thread_attachments WHERE thread_id = ?1")?
            .query_row(params![thread_id], |r| r.get::<_, String>(0))
            .optional()?;
        Ok(json)
    }

    // -- Queue GC (retention sweep) ------------------------------
    //
    // Each method deletes ONE bounded batch (`LIMIT` inside an `id IN (…)`
    // subquery — SQLite's portable DELETE…LIMIT form) so a caller can sweep a
    // year-old backlog across many short mutex holds instead of one multi-second
    // one. Rows still owed to the at-least-once contract (un-acked outbox,
    // un-processed inbox) are never eligible, regardless of age. The cutoff is
    // computed in SQL (`datetime('now', '-N days')`) so it compares in the same
    // format the DB-defaulted timestamp columns store.

    /// Delete one batch of acked outbox rows older than the retention window.
    /// Dead-lettered poison rows carry `acked_at` too and age out the same way.
    /// Returns the rows deleted; a count below `limit` means the backlog is drained.
    pub(crate) fn gc_outbox_batch(&self, retention_days: u32, limit: usize) -> DbResult<usize> {
        let deleted = self
            .conn
            .prepare_cached(
                "DELETE FROM outbox WHERE id IN (
                   SELECT id FROM outbox
                    WHERE acked_at IS NOT NULL AND created_at < datetime('now', ?1)
                    LIMIT ?2)",
            )?
            .execute(params![gc_cutoff_modifier(retention_days), limit])?;
        Ok(deleted)
    }

    /// Delete one batch of processed inbox rows older than the retention window.
    pub(crate) fn gc_inbox_batch(&self, retention_days: u32, limit: usize) -> DbResult<usize> {
        let deleted = self
            .conn
            .prepare_cached(
                "DELETE FROM inbox WHERE id IN (
                   SELECT id FROM inbox
                    WHERE processed_at IS NOT NULL AND received_at < datetime('now', ?1)
                    LIMIT ?2)",
            )?
            .execute(params![gc_cutoff_modifier(retention_days), limit])?;
        Ok(deleted)
    }

    /// Delete one batch of cron ledger rows older than the retention window.
    /// Every `cron_logs` row is a terminal ledger line, but the **newest row of
    /// each cron is always kept** so the round-accounting truth
    /// (`MAX(round_seq)`, D4) and the latest fire's dedup slot survive even for
    /// a cron idle longer than the window.
    pub(crate) fn gc_cron_logs_batch(&self, retention_days: u32, limit: usize) -> DbResult<usize> {
        let deleted = self
            .conn
            .prepare_cached(
                "DELETE FROM cron_logs WHERE id IN (
                   SELECT id FROM cron_logs
                    WHERE created_at < datetime('now', ?1)
                      AND id NOT IN (SELECT MAX(id) FROM cron_logs GROUP BY cron_id)
                    LIMIT ?2)",
            )?
            .execute(params![gc_cutoff_modifier(retention_days), limit])?;
        Ok(deleted)
    }

    /// Delete one batch of attachment snapshots whose owning thread is terminal
    /// and older than the retention window. DECISION: no thread-deletion path
    /// exists today, so the snapshot's lifetime is tied to the same retention
    /// window as the queues rather than to a thread GC; a live (non-terminal)
    /// thread keeps its snapshot at any age because a retry must still resolve
    /// the identical attachment set. Thread timestamps are ISO-8601 (`to_iso`),
    /// so they are normalized through `datetime()` before comparing against the
    /// SQL-side cutoff.
    pub(crate) fn gc_thread_attachments_batch(
        &self,
        retention_days: u32,
        limit: usize,
    ) -> DbResult<usize> {
        let deleted = self
            .conn
            .prepare_cached(
                "DELETE FROM thread_attachments WHERE thread_id IN (
                   SELECT ta.thread_id FROM thread_attachments ta
                   JOIN threads t ON t.id = ta.thread_id
                    WHERE t.status IN ('succeeded', 'failed', 'cancelled')
                      AND datetime(t.created_at) < datetime('now', ?1)
                    LIMIT ?2)",
            )?
            .execute(params![gc_cutoff_modifier(retention_days), limit])?;
        Ok(deleted)
    }

    // -- Identity ------------------------------------------

    /// Persist (or replace) the runner identity: the host-generated `agent_id`
    /// and the negotiated connect token. The token crosses in as a
    /// `SecretString`; only its exposed value is written to the `TEXT` column.
    pub(crate) fn set_identity(
        &self,
        agent_id: &str,
        connect_token: &SecretString,
    ) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO identity (id, agent_id, connect_token, updated_at)
                 VALUES (1, ?1, ?2, datetime('now'))
                 ON CONFLICT(id) DO UPDATE SET
                   agent_id = excluded.agent_id,
                   connect_token = excluded.connect_token,
                   updated_at = datetime('now')",
            )?
            .execute(params![agent_id, connect_token.expose_secret()])?;
        Ok(())
    }

    /// Load the persisted identity, or `None` if the runner has not registered.
    pub(crate) fn get_identity(&self) -> DbResult<Option<Identity>> {
        let row = self
            .conn
            .prepare_cached("SELECT agent_id, connect_token FROM identity WHERE id = 1")?
            .query_row([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .optional()?;
        Ok(row.map(|(agent_id, token)| Identity {
            agent_id,
            connect_token: SecretString::from(token),
        }))
    }

    // -- Config meta (applied-config bookkeeping) --------------

    /// Upsert a `config_meta` KV entry (durable across restarts).
    pub(crate) fn set_config_meta(&self, key: &str, value: &str) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO config_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )?
            .execute(params![key, value])?;
        Ok(())
    }

    /// Read a `config_meta` value, or `None` when the key is absent.
    pub(crate) fn get_config_meta(&self, key: &str) -> DbResult<Option<String>> {
        let value = self
            .conn
            .prepare_cached("SELECT value FROM config_meta WHERE key = ?1")?
            .query_row(params![key], |r| r.get::<_, String>(0))
            .optional()?;
        Ok(value)
    }

    /// Persist the APPLIED global config version — the desired-set version the
    /// startup/`config_update` reconcile last converged the global scope to.
    /// The version gate compares the host's served version against
    /// this to decide reconcile (advanced) vs. repair-only (unchanged).
    pub(crate) fn set_applied_global_version(&self, version: i64) -> DbResult<()> {
        self.set_config_meta(APPLIED_GLOBAL_VERSION_KEY, &version.to_string())
    }

    /// The last APPLIED global config version, or `None` if the global scope has
    /// never been reconciled to a versioned set (a fresh DB, or a pre-version DB).
    /// A stored value that does not parse as an integer is treated as `None`.
    pub(crate) fn get_applied_global_version(&self) -> DbResult<Option<i64>> {
        Ok(self
            .get_config_meta(APPLIED_GLOBAL_VERSION_KEY)?
            .and_then(|raw| raw.parse::<i64>().ok()))
    }
}

/// End-to-end encryption state of the runner role. The blobs are sealed by the
/// caller (`crate::e2ee`); these are plain row accessors.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the group-state, inbound and outbound paths drive the rest"
    )
)]
impl Db {
    /// Whether outbox row `id` exists and is not yet acknowledged.
    pub(crate) fn is_outbox_unacked(&self, id: &str) -> DbResult<bool> {
        let found = self
            .conn
            .prepare_cached("SELECT 1 FROM outbox WHERE id = ?1 AND acked_at IS NULL")?
            .query_row(params![id], |_| Ok(()))
            .optional()?;
        Ok(found.is_some())
    }

    /// Record a task's e2ee profile and group id. Once set they are never
    /// changed or cleared: a later call keeps the stored values.
    pub(crate) fn set_task_e2ee(
        &self,
        task_id: &str,
        profile_id: &str,
        group_id: &str,
    ) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "UPDATE tasks SET
                   e2ee_profile_id = COALESCE(e2ee_profile_id, ?2),
                   e2ee_group_id = COALESCE(e2ee_group_id, ?3)
                 WHERE id = ?1",
            )?
            .execute(params![task_id, profile_id, group_id])?;
        Ok(())
    }

    /// A task's e2ee profile and group id; `None` for a plaintext or unknown
    /// task.
    pub(crate) fn get_task_e2ee(&self, task_id: &str) -> DbResult<Option<TaskE2eeRow>> {
        let row = self
            .conn
            .prepare_cached(
                "SELECT e2ee_profile_id, e2ee_group_id FROM tasks
                  WHERE id = ?1 AND e2ee_profile_id IS NOT NULL AND e2ee_group_id IS NOT NULL",
            )?
            .query_row(params![task_id], |r| {
                Ok(TaskE2eeRow {
                    profile_id: r.get(0)?,
                    group_id: r.get(1)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// The KeyPackage store snapshot, or `None` before the first generate.
    pub(crate) fn get_e2ee_key_packages(&self) -> DbResult<Option<E2eeKeyPackagesRow>> {
        let row = self
            .conn
            .prepare_cached(
                "SELECT store, last_resort_created_at FROM e2ee_key_packages WHERE id = 1",
            )?
            .query_row([], |r| {
                Ok(E2eeKeyPackagesRow {
                    store: r.get(0)?,
                    last_resort_created_at: r.get(1)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Store (replace) the KeyPackage store snapshot.
    pub(crate) fn put_e2ee_key_packages(&self, row: &E2eeKeyPackagesRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO e2ee_key_packages (id, store, last_resort_created_at, updated_at)
                 VALUES (1, ?1, ?2, datetime('now'))
                 ON CONFLICT(id) DO UPDATE SET
                   store = excluded.store,
                   last_resort_created_at = excluded.last_resort_created_at,
                   updated_at = datetime('now')",
            )?
            .execute(params![row.store, row.last_resort_created_at])?;
        Ok(())
    }

    /// Remove the KeyPackage store snapshot.
    pub(crate) fn delete_e2ee_key_packages(&self) -> DbResult<()> {
        self.conn
            .prepare_cached("DELETE FROM e2ee_key_packages")?
            .execute([])?;
        Ok(())
    }

    /// A task's group state row.
    pub(crate) fn get_e2ee_group(&self, task_id: &str) -> DbResult<Option<E2eeGroupRow>> {
        let row = self
            .conn
            .prepare_cached(
                "SELECT task_id, group_id, profile_id, snapshot, last_seq, status, updated_at
                   FROM e2ee_groups WHERE task_id = ?1",
            )?
            .query_row(params![task_id], map_e2ee_group)
            .optional()?;
        Ok(row)
    }

    /// Every group state row, by task id.
    pub(crate) fn list_e2ee_groups(&self) -> DbResult<Vec<E2eeGroupRow>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT task_id, group_id, profile_id, snapshot, last_seq, status, updated_at
                   FROM e2ee_groups ORDER BY task_id",
            )?
            .query_map([], map_e2ee_group)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Store (replace) a task's group state row; `updated_at` is set to now.
    pub(crate) fn put_e2ee_group(&self, row: &E2eeGroupRow) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO e2ee_groups
                   (task_id, group_id, profile_id, snapshot, last_seq, status, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'))
                 ON CONFLICT(task_id) DO UPDATE SET
                   group_id = excluded.group_id,
                   profile_id = excluded.profile_id,
                   snapshot = excluded.snapshot,
                   last_seq = excluded.last_seq,
                   status = excluded.status,
                   updated_at = datetime('now')",
            )?
            .execute(params![
                row.task_id,
                row.group_id,
                row.profile_id,
                row.snapshot,
                row.last_seq,
                row.status
            ])?;
        Ok(())
    }

    /// Remove a task's group state row.
    pub(crate) fn delete_e2ee_group(&self, task_id: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("DELETE FROM e2ee_groups WHERE task_id = ?1")?
            .execute(params![task_id])?;
        Ok(())
    }

    /// The cached secrets of one task epoch.
    pub(crate) fn get_e2ee_key_cache(
        &self,
        task_id: &str,
        epoch: i64,
    ) -> DbResult<Option<E2eeKeyCacheRow>> {
        let row = self
            .conn
            .prepare_cached(
                "SELECT secrets, verified FROM e2ee_key_cache WHERE task_id = ?1 AND epoch = ?2",
            )?
            .query_row(params![task_id, epoch], |r| {
                Ok(E2eeKeyCacheRow {
                    secrets: r.get(0)?,
                    verified: r.get(1)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Every cached epoch of a task, by epoch.
    pub(crate) fn list_e2ee_key_cache(
        &self,
        task_id: &str,
    ) -> DbResult<Vec<(i64, E2eeKeyCacheRow)>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT epoch, secrets, verified FROM e2ee_key_cache
                  WHERE task_id = ?1 ORDER BY epoch",
            )?
            .query_map(params![task_id], |r| {
                Ok((
                    r.get(0)?,
                    E2eeKeyCacheRow {
                        secrets: r.get(1)?,
                        verified: r.get(2)?,
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Store (replace) the cached secrets of one task epoch.
    pub(crate) fn put_e2ee_key_cache(
        &self,
        task_id: &str,
        epoch: i64,
        row: &E2eeKeyCacheRow,
    ) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "INSERT INTO e2ee_key_cache (task_id, epoch, secrets, verified)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(task_id, epoch) DO UPDATE SET
                   secrets = excluded.secrets,
                   verified = excluded.verified",
            )?
            .execute(params![task_id, epoch, row.secrets, row.verified])?;
        Ok(())
    }

    /// Remove the cached secrets of one task epoch.
    pub(crate) fn delete_e2ee_key_cache(&self, task_id: &str, epoch: i64) -> DbResult<()> {
        self.conn
            .prepare_cached("DELETE FROM e2ee_key_cache WHERE task_id = ?1 AND epoch = ?2")?
            .execute(params![task_id, epoch])?;
        Ok(())
    }

    /// Remove every cached epoch of a task.
    pub(crate) fn delete_e2ee_key_cache_for_task(&self, task_id: &str) -> DbResult<()> {
        self.conn
            .prepare_cached("DELETE FROM e2ee_key_cache WHERE task_id = ?1")?
            .execute(params![task_id])?;
        Ok(())
    }

    /// Buffer one `e2ee_log`/`e2ee_welcome` record. Returns `false` when the
    /// same `(task_id, seq, type)` is already buffered (a redelivery).
    pub(crate) fn put_e2ee_log_pending(
        &self,
        task_id: &str,
        seq: i64,
        msg_type: &str,
        payload: &str,
    ) -> DbResult<bool> {
        let inserted = self
            .conn
            .prepare_cached(
                "INSERT INTO e2ee_log_pending (task_id, seq, type, payload)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
            )?
            .execute(params![task_id, seq, msg_type, payload])?;
        Ok(inserted > 0)
    }

    /// A task's buffered records in `seq` order (a Welcome before the log
    /// entry of the same `seq`).
    pub(crate) fn list_e2ee_log_pending(&self, task_id: &str) -> DbResult<Vec<E2eeLogPendingRow>> {
        let rows = self
            .conn
            .prepare_cached(
                "SELECT task_id, seq, type, payload, received_at FROM e2ee_log_pending
                  WHERE task_id = ?1
                  ORDER BY seq, CASE type WHEN 'e2ee_welcome' THEN 0 ELSE 1 END",
            )?
            .query_map(params![task_id], |r| {
                Ok(E2eeLogPendingRow {
                    task_id: r.get(0)?,
                    seq: r.get(1)?,
                    msg_type: r.get(2)?,
                    payload: r.get(3)?,
                    received_at: r.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Remove one buffered record.
    pub(crate) fn delete_e2ee_log_pending(
        &self,
        task_id: &str,
        seq: i64,
        msg_type: &str,
    ) -> DbResult<()> {
        self.conn
            .prepare_cached(
                "DELETE FROM e2ee_log_pending WHERE task_id = ?1 AND seq = ?2 AND type = ?3",
            )?
            .execute(params![task_id, seq, msg_type])?;
        Ok(())
    }
}

/// Map an `e2ee_groups` row selected in column order.
fn map_e2ee_group(r: &rusqlite::Row<'_>) -> rusqlite::Result<E2eeGroupRow> {
    Ok(E2eeGroupRow {
        task_id: r.get(0)?,
        group_id: r.get(1)?,
        profile_id: r.get(2)?,
        snapshot: r.get(3)?,
        last_seq: r.get(4)?,
        status: r.get(5)?,
        updated_at: r.get(6)?,
    })
}

/// The SQLite datetime modifier selecting rows older than the retention window
/// (`datetime('now', '-N days')`).
fn gc_cutoff_modifier(retention_days: u32) -> String {
    format!("-{retention_days} days")
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;

    use super::{
        ConfigEntryRow, CronLogRow, CronRow, Db, DbError, E2eeGroupRow, E2eeKeyCacheRow,
        E2eeKeyPackagesRow, InboxRow, OutboxRow, SCHEMA_VERSION, TaskE2eeRow, TaskRow, ThreadRow,
    };

    // -- v2 row builders ---------------------------------------------------

    fn task_row(id: &str, status: &str) -> TaskRow {
        TaskRow {
            id: id.to_owned(),
            name: Some("nightly digest".to_owned()),
            kind: Some("agent".to_owned()),
            status: status.to_owned(),
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            created_at: "2026-06-22T11:00:00Z".to_owned(),
            updated_at: "2026-06-22T11:00:00Z".to_owned(),
        }
    }

    fn cron_row(id: &str, task_id: &str, status: &str) -> CronRow {
        CronRow {
            id: id.to_owned(),
            task_id: task_id.to_owned(),
            kind: "schedule".to_owned(),
            prompt: "run the recurring job".to_owned(),
            schedule_type: Some("interval".to_owned()),
            schedule_value: Some("60000".to_owned()),
            next_run: Some("2026-06-22T12:00:00Z".to_owned()),
            last_fired_at: None,
            continuity: "isolated".to_owned(),
            run_count: 0,
            status: status.to_owned(),
            created_at: "2026-06-22T11:00:00Z".to_owned(),
            updated_at: "2026-06-22T11:00:00Z".to_owned(),
        }
    }

    fn thread_row(id: &str, task_id: &str, cron_id: Option<&str>, status: &str) -> ThreadRow {
        ThreadRow {
            id: id.to_owned(),
            task_id: task_id.to_owned(),
            cron_id: cron_id.map(ToOwned::to_owned),
            source: "cron".to_owned(),
            prompt: "run the recurring job".to_owned(),
            engine: "claude".to_owned(),
            engine_session_id: None,
            status: status.to_owned(),
            failure_reason: None,
            attempt: 0,
            max_attempts: 1,
            work_dir: None,
            started_at: None,
            finished_at: None,
            duration_ms: None,
            result: None,
            error: None,
            created_at: "2026-06-22T11:00:00Z".to_owned(),
        }
    }

    fn cron_log_row(
        cron_id: &str,
        task_id: &str,
        round_seq: i64,
        scheduled_at: &str,
    ) -> CronLogRow {
        CronLogRow {
            id: 0, // assigned by SQLite on insert
            cron_id: cron_id.to_owned(),
            task_id: task_id.to_owned(),
            round_seq,
            scheduled_at: scheduled_at.to_owned(),
            fired_at: Some("2026-06-22T12:00:01Z".to_owned()),
            status: "dispatched".to_owned(),
            skip_reason: None,
            thread_id: None,
            created_at: String::new(), // DB-defaulted; populated on read
        }
    }

    fn config_entry(scope: &str, name: &str, target: &str, sha256: &str) -> ConfigEntryRow {
        let short = sha256.get(..12).unwrap_or(sha256).to_owned();
        ConfigEntryRow {
            id: 0, // assigned by SQLite on insert
            scope: scope.to_owned(),
            name: name.to_owned(),
            sha256: sha256.to_owned(),
            short: short.clone(),
            target: target.to_owned(),
            kind: "file".to_owned(),
            store_path: format!("store/{name}/{short}"),
            link_path: format!("{scope}/{target}"),
            installed_at: "2026-06-22T11:00:00Z".to_owned(),
        }
    }

    // -- Schema / migration ------------------------------------------------

    #[test]
    fn schema_init_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        // A fresh DB fast-paths straight to the latest version.
        assert_eq!(db.user_version().unwrap(), SCHEMA_VERSION);
        // Re-running the migration must not error or disturb existing data.
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.migrate().unwrap();
        db.migrate().unwrap();
        assert_eq!(db.user_version().unwrap(), SCHEMA_VERSION);
        assert!(db.get_task_row("t-1").unwrap().is_some());
    }

    /// Regression: SQLite ships `PRAGMA foreign_keys` OFF per connection;
    /// every open path must switch it on so the schema's REFERENCES (which the
    /// code assumes are live) are actually enforced.
    #[test]
    fn foreign_keys_are_on_and_enforced() {
        let db = Db::open_in_memory().unwrap();
        let on: i64 = db
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1, "foreign_keys must be ON");
        // An FK-violating insert fails: a thread under an absent task.
        assert!(
            db.insert_thread(&thread_row("th-orphan", "t-absent", None, "pending"))
                .is_err(),
            "FK violation must be rejected"
        );

        // The file-backed open path enables it too.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        let db = Db::open(&path).unwrap();
        let on: i64 = db
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1, "foreign_keys must be ON on file opens");
    }

    /// D2: the task-definition columns round-trip through insert/get/update.
    #[test]
    fn task_definition_columns_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let mut row = task_row("t-1", "active");
        row.engine = Some("claude".to_owned());
        row.model = Some("claude-opus-4-8".to_owned());
        row.workdir = Some("/srv/project".to_owned());
        row.meta = Some(r#"{"team":"infra"}"#.to_owned());
        db.insert_task_row(&row).unwrap();
        assert_eq!(db.get_task_row("t-1").unwrap().as_ref(), Some(&row));

        row.model = Some("claude-sonnet-4-6".to_owned());
        db.update_task_row(&row).unwrap();
        assert_eq!(
            db.get_task_row("t-1").unwrap().unwrap().model.as_deref(),
            Some("claude-sonnet-4-6")
        );
        assert_eq!(db.list_tasks().unwrap(), vec![row]);
    }

    /// The daemon refuses a database written by a newer binary rather
    /// than corrupting a schema it does not understand.
    #[test]
    fn daemon_open_refuses_a_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        Db::open(&path).unwrap();
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        assert!(matches!(
            Db::open(&path).unwrap_err(),
            DbError::SchemaNewerThanBinary { .. }
        ));
    }

    /// A database left by an older development build (unversioned with tables)
    /// is refused instead of being patched up.
    #[test]
    fn daemon_open_refuses_a_database_from_an_older_build() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT);")
            .unwrap();
        assert!(matches!(
            Db::open(&path).unwrap_err(),
            DbError::UnsupportedSchema { found: 0 }
        ));
    }

    /// Regression: claiming a pending thread is a CAS — of two claims on
    /// one pending row, exactly one wins.
    #[test]
    fn claim_pending_thread_is_a_cas() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_thread(&thread_row("th-1", "t-1", None, "pending"))
            .unwrap();

        assert!(
            db.claim_pending_thread("th-1", "2026-06-22T12:00:00Z", "/w/th-1")
                .unwrap()
        );
        assert!(
            !db.claim_pending_thread("th-1", "2026-06-22T12:00:01Z", "/w/th-1-b")
                .unwrap(),
            "the second claim must lose"
        );

        let row = db.get_thread("th-1").unwrap().unwrap();
        assert_eq!(row.status, "dispatched");
        assert_eq!(
            row.started_at.as_deref(),
            Some("2026-06-22T12:00:00Z"),
            "the loser must not overwrite the winner's stamps"
        );
        assert_eq!(row.work_dir.as_deref(), Some("/w/th-1"));

        // Absent id: nothing to claim.
        assert!(!db.claim_pending_thread("th-absent", "t", "w").unwrap());
    }

    #[test]
    fn v2_schema_creates_all_entity_tables() {
        // Insert one row into each v2 table to prove the schema created them.
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();
        db.insert_thread(&thread_row("cr-1@1718", "t-1", Some("cr-1"), "pending"))
            .unwrap();
        db.insert_cron_log(&cron_log_row("cr-1", "t-1", 0, "2026-06-22T12:00:00Z"))
            .unwrap();

        assert!(db.get_task_row("t-1").unwrap().is_some());
        assert!(db.get_cron("cr-1").unwrap().is_some());
        assert!(db.get_thread("cr-1@1718").unwrap().is_some());
        assert_eq!(db.max_round_seq("cr-1").unwrap(), Some(0));
    }

    // -- v2: tasks ---------------------------------------------------------

    #[test]
    fn task_row_insert_get_update_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();

        assert_eq!(
            db.get_task_row("t-1").unwrap().as_ref(),
            Some(&task_row("t-1", "active"))
        );

        let mut updated = task_row("t-1", "cancelled");
        updated.name = Some("renamed".to_owned());
        updated.kind = None;
        updated.updated_at = "2026-06-22T13:00:00Z".to_owned();
        db.update_task_row(&updated).unwrap();

        let reloaded = db.get_task_row("t-1").unwrap().unwrap();
        assert_eq!(reloaded.status, "cancelled");
        assert_eq!(reloaded.name.as_deref(), Some("renamed"));
        assert_eq!(reloaded.kind, None);
        assert_eq!(reloaded.updated_at, "2026-06-22T13:00:00Z");
        // created_at is immutable across an update.
        assert_eq!(reloaded.created_at, "2026-06-22T11:00:00Z");
    }

    /// D1: the task-status gate every execution plane consults. Only `closed`
    /// and `cancelled` park work; any other status — including one this runner
    /// does not know — and a MISSING row (task rows are seeded lazily) do not.
    #[test]
    fn task_execution_blocked_only_for_closed_and_cancelled() {
        let db = Db::open_in_memory().unwrap();
        for status in ["active", "closed", "cancelled", "paused-by-a-future-host"] {
            db.insert_task_row(&task_row(status, status)).unwrap();
        }

        assert!(db.task_execution_blocked("closed").unwrap());
        assert!(db.task_execution_blocked("cancelled").unwrap());
        assert!(!db.task_execution_blocked("active").unwrap());
        assert!(
            !db.task_execution_blocked("paused-by-a-future-host")
                .unwrap()
        );
        assert!(
            !db.task_execution_blocked("never-seeded").unwrap(),
            "a missing task row must not silently park work"
        );
    }

    // -- v2: crons ---------------------------------------------------------

    #[test]
    fn cron_insert_get_update_and_active_filter() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-2", "t-1", "paused")).unwrap();

        // Round-trips column-for-column.
        assert_eq!(
            db.get_cron("cr-1").unwrap().as_ref(),
            Some(&cron_row("cr-1", "t-1", "active"))
        );

        // list-active filters on status.
        let active = db.list_active_crons().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "cr-1");

        // Update mutates and bumps the run_count cache.
        let mut updated = cron_row("cr-1", "t-1", "completed");
        updated.run_count = 5;
        updated.last_fired_at = Some("2026-06-22T12:05:00Z".to_owned());
        db.update_cron(&updated).unwrap();

        let reloaded = db.get_cron("cr-1").unwrap().unwrap();
        assert_eq!(reloaded.status, "completed");
        assert_eq!(reloaded.run_count, 5);
        assert_eq!(
            reloaded.last_fired_at.as_deref(),
            Some("2026-06-22T12:05:00Z")
        );
        assert!(db.list_active_crons().unwrap().is_empty());
    }

    /// Regression: advancing a fired cron is a targeted UPDATE guarded on
    /// `status = 'active'` — a cron deleted (soft-cancelled) or completed after
    /// the scheduler's tick-read is left untouched, never resurrected.
    #[test]
    fn advance_cron_is_guarded_and_targeted() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();

        // An active cron advances: only the scheduling columns change.
        assert!(
            db.advance_cron(
                "cr-1",
                Some("2026-06-22T12:01:00Z"),
                "2026-06-22T12:00:00Z",
                1,
                "active",
                "2026-06-22T12:00:00Z",
            )
            .unwrap()
        );
        let advanced = db.get_cron("cr-1").unwrap().unwrap();
        assert_eq!(advanced.next_run.as_deref(), Some("2026-06-22T12:01:00Z"));
        assert_eq!(advanced.run_count, 1);
        assert_eq!(advanced.prompt, "run the recurring job", "prompt untouched");

        // Soft-delete lands between tick-read and advance: the guard rejects the
        // stale advance and the cron stays cancelled with no next_run.
        let mut deleted = db.get_cron("cr-1").unwrap().unwrap();
        "cancelled".clone_into(&mut deleted.status);
        deleted.next_run = None;
        db.update_cron(&deleted).unwrap();
        assert!(
            !db.advance_cron(
                "cr-1",
                Some("2026-06-22T12:02:00Z"),
                "2026-06-22T12:01:00Z",
                2,
                "active",
                "2026-06-22T12:01:00Z",
            )
            .unwrap()
        );
        let untouched = db.get_cron("cr-1").unwrap().unwrap();
        assert_eq!(untouched.status, "cancelled");
        assert_eq!(untouched.next_run, None);

        // A hard-deleted (absent) cron is likewise a rejected no-op.
        assert!(
            !db.advance_cron(
                "cr-absent",
                None,
                "2026-06-22T12:00:00Z",
                1,
                "active",
                "2026-06-22T12:00:00Z",
            )
            .unwrap()
        );
    }

    /// The transactional-plane primitive: writes inside
    /// [`Db::immediate_transaction`] commit together, and an error inside the
    /// closure rolls every one of them back.
    #[test]
    fn immediate_transaction_commits_together_or_not_at_all() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();

        // Commit path: both writes land.
        db.immediate_transaction(|db| {
            db.insert_thread(&thread_row("cr-1@1", "t-1", Some("cr-1"), "pending"))?;
            db.insert_cron_log(&cron_log_row("cr-1", "t-1", 1, "2026-06-22T12:00:00Z"))?;
            Ok(())
        })
        .unwrap();
        assert!(db.get_thread("cr-1@1").unwrap().is_some());
        assert_eq!(db.max_round_seq("cr-1").unwrap(), Some(1));

        // Rollback path: the first write succeeds, the second hits the ledger
        // UNIQUE(cron_id, scheduled_at) constraint — the thread insert must be
        // rolled back with it, leaving no partial state.
        let result = db.immediate_transaction(|db| {
            db.insert_thread(&thread_row("cr-1@2", "t-1", Some("cr-1"), "pending"))?;
            db.insert_cron_log(&cron_log_row("cr-1", "t-1", 2, "2026-06-22T12:00:00Z"))?;
            Ok(())
        });
        assert!(result.is_err(), "duplicate ledger slot must error");
        assert!(
            db.get_thread("cr-1@2").unwrap().is_none(),
            "the thread insert must roll back with the failed ledger insert"
        );
        assert_eq!(db.max_round_seq("cr-1").unwrap(), Some(1));

        // The connection is usable again after the rollback.
        db.insert_thread(&thread_row("cr-1@3", "t-1", Some("cr-1"), "pending"))
            .unwrap();
        assert!(db.get_thread("cr-1@3").unwrap().is_some());
    }

    #[test]
    fn cron_prompt_persists_and_updates() {
        // crons.prompt (NOT NULL, D10:(a)) round-trips through insert/get and is
        // mutated by update — a distinct value guards the column mapping against
        // an off-by-one with the neighbouring `kind`/`schedule_type` columns.
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        let mut cron = cron_row("cr-1", "t-1", "active");
        "summarize today's inbox".clone_into(&mut cron.prompt);
        db.insert_cron(&cron).unwrap();
        assert_eq!(
            db.get_cron("cr-1").unwrap().unwrap().prompt,
            "summarize today's inbox"
        );

        cron.prompt = "summarize this week's inbox".to_owned();
        db.update_cron(&cron).unwrap();
        assert_eq!(
            db.get_cron("cr-1").unwrap().unwrap().prompt,
            "summarize this week's inbox"
        );
    }

    #[test]
    fn thread_prompt_snapshot_persists_and_updates() {
        // threads.prompt (NOT NULL, D10) is the resolved snapshot; insert/get
        // round-trip it and update can rewrite it (the executor's attempt-0 chat
        // snapshot / a chat re-pend clearing the stale prompt).
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();
        let mut thread = thread_row("cr-1@1718", "t-1", Some("cr-1"), "pending");
        "the snapshotted instruction".clone_into(&mut thread.prompt);
        db.insert_thread(&thread).unwrap();
        assert_eq!(
            db.get_thread("cr-1@1718").unwrap().unwrap().prompt,
            "the snapshotted instruction"
        );

        thread.prompt = "a re-resolved instruction".to_owned();
        db.update_thread(&thread).unwrap();
        assert_eq!(
            db.get_thread("cr-1@1718").unwrap().unwrap().prompt,
            "a re-resolved instruction"
        );
    }

    // -- v2: threads -------------------------------------------------------

    #[test]
    fn thread_insert_get_update_and_pending_filter() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();

        // An isolated cron fire mints a deterministic thread id.
        db.insert_thread(&thread_row("cr-1@1718", "t-1", Some("cr-1"), "pending"))
            .unwrap();
        // A chat thread has no cron.
        db.insert_thread(&thread_row("th-chat", "t-1", None, "running"))
            .unwrap();

        assert_eq!(
            db.get_thread("cr-1@1718").unwrap().as_ref(),
            Some(&thread_row("cr-1@1718", "t-1", Some("cr-1"), "pending"))
        );

        // Executor drains pending threads only.
        let pending = db.list_pending_threads().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "cr-1@1718");

        // Drive a thread to a terminal state.
        let mut done = thread_row("cr-1@1718", "t-1", Some("cr-1"), "succeeded");
        done.engine_session_id = Some("sess-9".to_owned());
        done.work_dir = Some("/w/cr-1@1718".to_owned());
        done.started_at = Some("2026-06-22T12:00:00Z".to_owned());
        done.finished_at = Some("2026-06-22T12:00:30Z".to_owned());
        done.duration_ms = Some(30_000);
        done.result = Some("ok".to_owned());
        done.attempt = 1;
        db.update_thread(&done).unwrap();

        let reloaded = db.get_thread("cr-1@1718").unwrap().unwrap();
        assert_eq!(reloaded.status, "succeeded");
        assert_eq!(reloaded.engine_session_id.as_deref(), Some("sess-9"));
        assert_eq!(reloaded.duration_ms, Some(30_000));
        // Immutable columns survive the update.
        assert_eq!(reloaded.cron_id.as_deref(), Some("cr-1"));
        assert_eq!(reloaded.source, "cron");
    }

    #[test]
    fn thread_last_seq_defaults_then_round_trips() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();
        db.insert_thread(&thread_row("cr-1@1718", "t-1", Some("cr-1"), "running"))
            .unwrap();

        // A fresh row defaults to 0; an unknown thread also reads 0.
        assert_eq!(db.get_thread_last_seq("cr-1@1718").unwrap(), 0);
        assert_eq!(db.get_thread_last_seq("nope").unwrap(), 0);

        // The executor advances the counter as it emits; the value survives a
        // re-read (i.e. a runner restart that reloads it from the DB).
        db.set_thread_last_seq("cr-1@1718", 7).unwrap();
        assert_eq!(db.get_thread_last_seq("cr-1@1718").unwrap(), 7);
        db.set_thread_last_seq("cr-1@1718", 42).unwrap();
        assert_eq!(db.get_thread_last_seq("cr-1@1718").unwrap(), 42);

        // Setting an unknown thread is a no-op, not an error.
        db.set_thread_last_seq("nope", 5).unwrap();
        assert_eq!(db.get_thread_last_seq("nope").unwrap(), 0);
    }

    #[test]
    fn list_threads_by_status_filters_by_status() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();

        // Seed a spread of statuses, two of them sharing 'dispatched'.
        db.insert_thread(&thread_row("th-disp-1", "t-1", Some("cr-1"), "dispatched"))
            .unwrap();
        db.insert_thread(&thread_row("th-disp-2", "t-1", Some("cr-1"), "dispatched"))
            .unwrap();
        db.insert_thread(&thread_row("th-run", "t-1", None, "running"))
            .unwrap();
        db.insert_thread(&thread_row("th-done", "t-1", None, "succeeded"))
            .unwrap();

        // Only the matching rows come back, oldest first (id tie-break).
        let dispatched = db.list_threads_by_status("dispatched").unwrap();
        let ids: Vec<&str> = dispatched.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["th-disp-1", "th-disp-2"]);

        let running = db.list_threads_by_status("running").unwrap();
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].id, "th-run");

        // A status with no rows yields an empty set, not an error.
        assert!(db.list_threads_by_status("cancelled").unwrap().is_empty());
    }

    // -- v2: cron_logs -----------------------------------------------------

    #[test]
    fn cron_log_unique_rejects_duplicate_fire() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();

        let first = cron_log_row("cr-1", "t-1", 0, "2026-06-22T12:00:00Z");
        let id = db.insert_cron_log(&first).unwrap();
        assert!(id > 0);

        // The schema UNIQUE(cron_id, scheduled_at) rejects a duplicate fire.
        let dup = cron_log_row("cr-1", "t-1", 1, "2026-06-22T12:00:00Z");
        assert!(
            db.insert_cron_log(&dup).is_err(),
            "duplicate (cron_id, scheduled_at) must be rejected"
        );

        // The idempotent variant returns None for the duplicate (no error).
        assert_eq!(db.try_insert_cron_log(&dup).unwrap(), None);
        // …and Some(id) for a fresh fire.
        let next = cron_log_row("cr-1", "t-1", 1, "2026-06-22T12:01:00Z");
        assert!(db.try_insert_cron_log(&next).unwrap().is_some());

        // A different cron may share the same scheduled_at.
        db.insert_cron(&cron_row("cr-2", "t-1", "active")).unwrap();
        let other = cron_log_row("cr-2", "t-1", 0, "2026-06-22T12:00:00Z");
        assert!(db.insert_cron_log(&other).is_ok());

        // Round-count truth (D4): MAX(round_seq) per cron.
        assert_eq!(db.max_round_seq("cr-1").unwrap(), Some(1));
        assert_eq!(db.max_round_seq("cr-2").unwrap(), Some(0));
        assert_eq!(db.max_round_seq("cr-absent").unwrap(), None);
    }

    #[test]
    fn cron_log_records_skip_with_no_thread() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();

        let mut skipped = cron_log_row("cr-1", "t-1", 0, "2026-06-22T12:00:00Z");
        skipped.status = "skipped".to_owned();
        skipped.skip_reason = Some("overlap".to_owned());
        skipped.fired_at = None;
        skipped.thread_id = None;
        let id = db.insert_cron_log(&skipped).unwrap();

        let reloaded = db.get_cron_log(id).unwrap().unwrap();
        assert_eq!(reloaded.status, "skipped");
        assert_eq!(reloaded.skip_reason.as_deref(), Some("overlap"));
        assert_eq!(reloaded.thread_id, None);
        assert!(
            !reloaded.created_at.is_empty(),
            "created_at is DB-defaulted"
        );
    }

    // -- v2: config_entries (provisioning manifest / store index) ----------

    #[test]
    fn config_entries_insert_list_and_scope_filter() {
        let db = Db::open_in_memory().unwrap();

        // Two entries in the global scope (distinct targets) + one task scope.
        db.upsert_config_entry(&config_entry(
            "global",
            "skills-x",
            "skills/x",
            "a".repeat(64).as_str(),
        ))
        .unwrap();
        db.upsert_config_entry(&config_entry(
            "global",
            "claude-md",
            "CLAUDE.md",
            "b".repeat(64).as_str(),
        ))
        .unwrap();
        db.upsert_config_entry(&config_entry(
            "th-1",
            "claude-md",
            "CLAUDE.md",
            "c".repeat(64).as_str(),
        ))
        .unwrap();

        // list_config_entries(scope) returns that scope only, ordered by target
        // (CLAUDE.md < skills/x).
        let global = db.list_config_entries("global").unwrap();
        let global_targets: Vec<&str> = global.iter().map(|e| e.target.as_str()).collect();
        assert_eq!(global_targets, ["CLAUDE.md", "skills/x"]);

        // list_all_config_entries spans scopes, ordered by (scope, target).
        let all = db.list_all_config_entries().unwrap();
        let all_keys: Vec<(&str, &str)> = all
            .iter()
            .map(|e| (e.scope.as_str(), e.target.as_str()))
            .collect();
        assert_eq!(
            all_keys,
            [
                ("global", "CLAUDE.md"),
                ("global", "skills/x"),
                ("th-1", "CLAUDE.md"),
            ]
        );

        // The auto id is populated on read.
        assert!(all.iter().all(|e| e.id > 0));
    }

    #[test]
    fn config_entry_upsert_repoints_in_place() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_config_entry(&config_entry(
            "global",
            "claude-md",
            "CLAUDE.md",
            "a".repeat(64).as_str(),
        ))
        .unwrap();

        // Repoint the SAME (scope, target) to a new version.
        let v2 = config_entry("global", "claude-md", "CLAUDE.md", "d".repeat(64).as_str());
        db.upsert_config_entry(&v2).unwrap();

        // One row, not two; the version columns are updated.
        let rows = db.list_config_entries("global").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].sha256, "d".repeat(64));
        assert_eq!(rows[0].short, "d".repeat(12));
        assert_eq!(
            rows[0].store_path,
            format!("store/claude-md/{}", "d".repeat(12))
        );
    }

    #[test]
    fn count_store_refs_counts_across_scopes_and_drops_to_zero() {
        let db = Db::open_in_memory().unwrap();
        let sha = "e".repeat(64);

        // Same artifact (name, sha256) referenced by two scopes.
        db.upsert_config_entry(&config_entry("global", "skills-y", "skills/y", &sha))
            .unwrap();
        db.upsert_config_entry(&config_entry("th-1", "skills-y", ".claude/skills/y", &sha))
            .unwrap();
        // A different version of the same name does not count.
        db.upsert_config_entry(&config_entry(
            "th-2",
            "skills-y",
            ".claude/skills/y",
            "f".repeat(64).as_str(),
        ))
        .unwrap();

        assert_eq!(db.count_store_refs("skills-y", &sha).unwrap(), 2);
        assert_eq!(db.count_store_refs("skills-y", &"f".repeat(64)).unwrap(), 1);
        assert_eq!(db.count_store_refs("absent", &sha).unwrap(), 0);

        // Delete one referencing row → 1; repoint the other to a new version → 0.
        db.delete_config_entry("global", "skills/y").unwrap();
        assert_eq!(db.count_store_refs("skills-y", &sha).unwrap(), 1);
        db.upsert_config_entry(&config_entry(
            "th-1",
            "skills-y",
            ".claude/skills/y",
            "g".repeat(64).as_str(),
        ))
        .unwrap();
        assert_eq!(db.count_store_refs("skills-y", &sha).unwrap(), 0);
        // …and the new version is now the only reference.
        assert_eq!(db.count_store_refs("skills-y", &"g".repeat(64)).unwrap(), 1);
    }

    #[test]
    fn delete_config_entry_removes_one_scope_target() {
        let db = Db::open_in_memory().unwrap();
        db.upsert_config_entry(&config_entry(
            "global",
            "claude-md",
            "CLAUDE.md",
            "a".repeat(64).as_str(),
        ))
        .unwrap();
        db.upsert_config_entry(&config_entry(
            "global",
            "skills-x",
            "skills/x",
            "b".repeat(64).as_str(),
        ))
        .unwrap();

        db.delete_config_entry("global", "CLAUDE.md").unwrap();

        let remaining = db.list_config_entries("global").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].target, "skills/x");

        // Deleting an absent (scope, target) is a harmless no-op.
        db.delete_config_entry("global", "nope").unwrap();
        assert_eq!(db.list_config_entries("global").unwrap().len(), 1);
    }

    // -- v2: task entries (desired provisioning set on the tasks row) -------

    #[test]
    fn task_entries_round_trip_and_clear() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();

        // A v2 task is born with no entries (NULL column → None).
        assert_eq!(db.get_task_entries("t-1").unwrap(), None);

        // Set then read back the desired-set JSON.
        let json = r#"[{"id":"claude-md","sha256":"abc","target":"CLAUDE.md","kind":"file"}]"#;
        db.set_task_entries("t-1", Some(json)).unwrap();
        assert_eq!(db.get_task_entries("t-1").unwrap().as_deref(), Some(json));

        // Clearing resets the column to NULL.
        db.set_task_entries("t-1", None).unwrap();
        assert_eq!(db.get_task_entries("t-1").unwrap(), None);

        // An unknown task reads None (no row), not an error.
        assert_eq!(db.get_task_entries("absent").unwrap(), None);
    }

    // -- v2: thread attachments (inbound descriptor snapshot, P1-10b) -------

    #[test]
    fn thread_attachments_round_trip_without_consuming() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_thread(&thread_row("th-1", "t-1", None, "pending"))
            .unwrap();

        // A thread with no snapshot reads None (not an error).
        assert_eq!(db.get_thread_attachments("th-1").unwrap(), None);

        let descriptors =
            json!([{ "id": "att-1", "name": "spec.txt", "ref": "/agent/attachments/att-1" }]);
        db.set_thread_attachments("th-1", &descriptors).unwrap();

        // Reads never consume the snapshot: a retry sees the identical set.
        let first = db.get_thread_attachments("th-1").unwrap().unwrap();
        let second = db.get_thread_attachments("th-1").unwrap().unwrap();
        assert_eq!(first, second);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&first).unwrap(),
            descriptors
        );

        // Re-recording replaces (upsert), never duplicates.
        let updated =
            json!([{ "id": "att-2", "name": "other.txt", "ref": "/agent/attachments/att-2" }]);
        db.set_thread_attachments("th-1", &updated).unwrap();
        let read = db.get_thread_attachments("th-1").unwrap().unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read).unwrap(),
            updated
        );
    }

    // -- v2: inbox / outbox correlation ------------------------------------

    #[test]
    fn outbox_and_inbox_carry_correlation_ids() {
        let db = Db::open_in_memory().unwrap();

        let out_id = db
            .enqueue_outbox_correlated(
                "thread_result",
                &json!({ "status": "succeeded" }),
                Some("t-1"),
                Some("cr-1@1718"),
            )
            .unwrap();
        // The plain helper leaves the correlation columns NULL.
        db.enqueue_outbox("heartbeat", &json!({})).unwrap();

        let out_rows: Vec<OutboxRow> = db.list_unacked_outbox().unwrap();
        let correlated = out_rows.iter().find(|r| r.id == out_id).unwrap();
        assert_eq!(correlated.task_id.as_deref(), Some("t-1"));
        assert_eq!(correlated.thread_id.as_deref(), Some("cr-1@1718"));
        let plain = out_rows.iter().find(|r| r.msg_type == "heartbeat").unwrap();
        assert_eq!(plain.task_id, None);
        assert_eq!(plain.thread_id, None);

        let in_id = db
            .record_inbound_correlated(
                "message",
                &json!({ "text": "hi" }),
                Some("t-1"),
                Some("cr-1@1718"),
                Some(crate::protocol::test_delivery_id(7).as_str()),
            )
            .unwrap()
            .unwrap();
        db.record_inbound("close", &json!({})).unwrap();

        let in_rows: Vec<InboxRow> = db.list_unprocessed_inbox().unwrap();
        let in_correlated = in_rows.iter().find(|r| r.id == in_id).unwrap();
        assert_eq!(in_correlated.task_id.as_deref(), Some("t-1"));
        assert_eq!(in_correlated.thread_id.as_deref(), Some("cr-1@1718"));
        assert_eq!(db.list_inbox_by_type("message").unwrap().len(), 1);
    }

    /// Regression: the `msg_id` UNIQUE column dedups an at-least-once
    /// redelivery — the second insert of the same delivery id is a no-op
    /// (`None`), leaving exactly ONE row; frames without a `msg_id` are never
    /// deduped (multiple NULLs allowed).
    #[test]
    fn inbox_msg_id_dedups_redelivery() {
        let db = Db::open_in_memory().unwrap();
        let first = db
            .record_inbound_correlated(
                "message",
                &json!({ "text": "hi" }),
                Some("t-1"),
                None,
                Some(crate::protocol::test_delivery_id(42).as_str()),
            )
            .unwrap();
        assert!(first.is_some(), "first delivery inserts");
        let dup = db
            .record_inbound_correlated(
                "message",
                &json!({ "text": "hi" }),
                Some("t-1"),
                None,
                Some(crate::protocol::test_delivery_id(42).as_str()),
            )
            .unwrap();
        assert_eq!(dup, None, "redelivery of the same msg_id is a no-op");
        assert_eq!(db.list_unprocessed_inbox().unwrap().len(), 1);

        // No msg_id → no dedup key → both rows insert.
        db.record_inbound_correlated("interrupt", &json!({}), None, None, None)
            .unwrap()
            .unwrap();
        db.record_inbound_correlated("interrupt", &json!({}), None, None, None)
            .unwrap()
            .unwrap();
        assert_eq!(db.list_unprocessed_inbox().unwrap().len(), 3);
    }

    /// Ids from a recreated host database are fresh ULIDs, never the ids the
    /// inbox already holds, so they are stored instead of deduped away.
    #[test]
    fn inbox_accepts_ids_from_a_recreated_host_db() {
        let db = Db::open_in_memory().unwrap();
        let before = "01jab3x7k2m4n5p6q7r8s90001";
        let after = "01jbcd3x7k2m4n5p6q7r8s9001";
        for id in [before, after] {
            let stored = db
                .record_inbound_correlated("message", &json!({}), Some("t-1"), None, Some(id))
                .unwrap();
            assert!(stored.is_some(), "{id} is a new delivery");
        }
        assert_eq!(db.list_unprocessed_inbox().unwrap().len(), 2);
    }

    #[test]
    fn outbox_ids_are_lowercase_ulids_in_creation_order() {
        let db = Db::open_in_memory().unwrap();
        let ids: Vec<String> = (0..200)
            .map(|n| db.enqueue_outbox("heartbeat", &json!({ "n": n })).unwrap())
            .collect();
        for id in &ids {
            assert_eq!(id.len(), 26);
            assert!(
                id.chars()
                    .all(|c| "0123456789abcdefghjkmnpqrstvwxyz".contains(c)),
                "{id} is lowercase Crockford base32"
            );
        }
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(sorted, ids);
        let replayed: Vec<String> = db
            .list_unacked_outbox()
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        assert_eq!(replayed, ids);
    }

    #[test]
    fn a_pre_minted_outbox_id_is_enqueued_as_given_and_keeps_creation_order() {
        let db = Db::open_in_memory().unwrap();
        let minted = super::new_delivery_id();
        let later = db.enqueue_outbox("heartbeat", &json!({})).unwrap();
        db.enqueue_outbox_with_id(&minted, "thread_result", &json!({}), Some("t"), Some("c"))
            .unwrap();
        let rows = db.list_unacked_outbox().unwrap();
        assert_eq!(rows[0].id, minted);
        assert_eq!(rows[0].msg_type, "thread_result");
        assert_eq!(rows[0].thread_id.as_deref(), Some("c"));
        assert_eq!(rows[1].id, later);
    }

    #[test]
    fn a_threads_result_outbox_id_round_trips() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_thread(&thread_row("c-1", "t-1", None, "running"))
            .unwrap();
        assert_eq!(db.get_thread_result_outbox_id("c-1").unwrap(), None);
        db.set_thread_result_outbox_id("c-1", "01jab").unwrap();
        assert_eq!(
            db.get_thread_result_outbox_id("c-1").unwrap().as_deref(),
            Some("01jab")
        );
        assert_eq!(db.get_thread_result_outbox_id("nope").unwrap(), None);
    }

    // -- Existing outbox/inbox behavior (regression) -----------------------

    #[test]
    fn outbox_enqueue_list_ack_and_dedup() {
        let db = Db::open_in_memory().unwrap();
        let id1 = db
            .enqueue_outbox("output", &json!({ "status": "success" }))
            .unwrap();
        let id2 = db
            .enqueue_outbox("idle", &json!({ "status": "success" }))
            .unwrap();
        assert!(id1 < id2, "ids sort in creation order: {id1} < {id2}");

        let unacked = db.list_unacked_outbox().unwrap();
        assert_eq!(unacked.len(), 2);
        assert_eq!(unacked[0].msg_type, "output");
        assert!(unacked[0].acked_at.is_none());

        db.mark_outbox_acked(&id1).unwrap();
        let unacked = db.list_unacked_outbox().unwrap();
        assert_eq!(unacked.len(), 1);
        assert_eq!(unacked[0].id, id2);

        // Re-acking is idempotent (dedup): no duplicate, count unchanged.
        db.mark_outbox_acked(&id1).unwrap();
        assert_eq!(db.list_unacked_outbox().unwrap().len(), 1);

        db.increment_outbox_retry(&id2).unwrap();
        db.increment_outbox_retry(&id2).unwrap();
        assert_eq!(db.list_unacked_outbox().unwrap()[0].retry_count, 2);
    }

    #[test]
    fn inbox_record_list_and_process() {
        let db = Db::open_in_memory().unwrap();
        let id = db
            .record_inbound("user_message", &json!({ "text": "hello" }))
            .unwrap();
        db.record_inbound("system_close", &json!({})).unwrap();

        assert_eq!(db.list_unprocessed_inbox().unwrap().len(), 2);
        assert_eq!(db.list_inbox_by_type("user_message").unwrap().len(), 1);

        assert_eq!(db.increment_inbox_retry(id).unwrap(), 1);
        assert_eq!(db.increment_inbox_retry(id).unwrap(), 2);
        db.mark_inbox_processed(id).unwrap();

        let remaining = db.list_unprocessed_inbox().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].msg_type, "system_close");
        assert!(db.list_inbox_by_type("user_message").unwrap().is_empty());
    }

    // -- Queue GC (retention sweep) -----------------------------

    /// Rewrite a DB-defaulted timestamp column so the row is `days` old.
    fn age_row(db: &Db, table: &str, column: &str, id: impl std::fmt::Display, days: u32) {
        db.exec_raw(&format!(
            "UPDATE {table} SET {column} = datetime('now', '-{days} days') WHERE id = '{id}'"
        ))
        .unwrap();
    }

    /// Rewrite a thread's ISO-8601 `created_at` so the thread is `days` old
    /// (relative to the test's real wall clock, never a fixed date).
    fn age_thread(db: &Db, thread_id: &str, days: u32) {
        db.exec_raw(&format!(
            "UPDATE threads SET created_at =
               strftime('%Y-%m-%dT%H:%M:%SZ', datetime('now', '-{days} days'))
             WHERE id = '{thread_id}'"
        ))
        .unwrap();
    }

    #[test]
    fn gc_outbox_deletes_only_old_acked_rows() {
        let db = Db::open_in_memory().unwrap();
        let old_acked = db.enqueue_outbox("output", &json!({})).unwrap();
        let fresh_acked = db.enqueue_outbox("output", &json!({})).unwrap();
        let old_unacked = db.enqueue_outbox("output", &json!({})).unwrap();
        db.mark_outbox_acked(&old_acked).unwrap();
        db.mark_outbox_acked(&fresh_acked).unwrap();
        age_row(&db, "outbox", "created_at", &old_acked, 40);
        age_row(&db, "outbox", "created_at", &old_unacked, 400);

        assert_eq!(db.gc_outbox_batch(30, 100).unwrap(), 1);

        // The fresh acked row survives the window; the un-acked row survives at
        // ANY age (at-least-once contract) and still replays.
        let unacked = db.list_unacked_outbox().unwrap();
        assert_eq!(unacked.len(), 1);
        assert_eq!(unacked[0].id, old_unacked);
        let remaining: i64 = db
            .conn
            .prepare("SELECT COUNT(*) FROM outbox")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 2);
    }

    #[test]
    fn gc_inbox_deletes_only_old_processed_rows() {
        let db = Db::open_in_memory().unwrap();
        let old_processed = db.record_inbound("message", &json!({})).unwrap();
        let fresh_processed = db.record_inbound("message", &json!({})).unwrap();
        let old_unprocessed = db.record_inbound("message", &json!({})).unwrap();
        db.mark_inbox_processed(old_processed).unwrap();
        db.mark_inbox_processed(fresh_processed).unwrap();
        age_row(&db, "inbox", "received_at", old_processed, 40);
        age_row(&db, "inbox", "received_at", old_unprocessed, 400);

        assert_eq!(db.gc_inbox_batch(30, 100).unwrap(), 1);

        let unprocessed = db.list_unprocessed_inbox().unwrap();
        assert_eq!(unprocessed.len(), 1);
        assert_eq!(unprocessed[0].id, old_unprocessed);
        let remaining: i64 = db
            .conn
            .prepare("SELECT COUNT(*) FROM inbox")
            .unwrap()
            .query_row([], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 2);
    }

    #[test]
    fn gc_cron_logs_deletes_old_rows_but_keeps_each_crons_newest() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-2", "t-1", "active")).unwrap();

        // cr-1: three old dispatched rows — the two oldest age out, the newest
        // stays so MAX(round_seq) (the D4 round truth) survives a long idle.
        for (round, at, age_days) in [(0, "12:00", 42), (1, "12:01", 41), (2, "12:02", 40)] {
            let id = db
                .insert_cron_log(&cron_log_row(
                    "cr-1",
                    "t-1",
                    round,
                    &format!("2026-01-01T{at}:00Z"),
                ))
                .unwrap();
            age_row(&db, "cron_logs", "created_at", id, age_days);
        }
        // cr-2: one fresh row — inside the window, untouched.
        db.insert_cron_log(&cron_log_row("cr-2", "t-1", 0, "2026-01-02T12:00:00Z"))
            .unwrap();

        assert_eq!(db.gc_cron_logs_batch(30, 100).unwrap(), 2);
        assert_eq!(db.max_round_seq("cr-1").unwrap(), Some(2));
        assert_eq!(db.max_round_seq("cr-2").unwrap(), Some(0));
        // Nothing further to collect.
        assert_eq!(db.gc_cron_logs_batch(30, 100).unwrap(), 0);
    }

    #[test]
    fn gc_thread_attachments_ages_out_terminal_threads_only() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        db.insert_cron(&cron_row("cr-1", "t-1", "active")).unwrap();
        db.insert_thread(&thread_row("th-old-done", "t-1", None, "succeeded"))
            .unwrap();
        db.insert_thread(&thread_row("th-old-live", "t-1", None, "pending"))
            .unwrap();
        db.insert_thread(&thread_row("th-fresh-done", "t-1", None, "failed"))
            .unwrap();
        age_thread(&db, "th-old-done", 40);
        age_thread(&db, "th-old-live", 400);
        age_thread(&db, "th-fresh-done", 1);
        for id in ["th-old-done", "th-old-live", "th-fresh-done"] {
            db.set_thread_attachments(id, &json!([{ "id": "a-1" }]))
                .unwrap();
        }

        assert_eq!(db.gc_thread_attachments_batch(30, 100).unwrap(), 1);

        // Only the old TERMINAL thread's snapshot is gone; a live thread keeps
        // its snapshot at any age (a retry must resolve the same set).
        assert!(db.get_thread_attachments("th-old-done").unwrap().is_none());
        assert!(db.get_thread_attachments("th-old-live").unwrap().is_some());
        assert!(
            db.get_thread_attachments("th-fresh-done")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn gc_batches_are_bounded_by_limit() {
        let db = Db::open_in_memory().unwrap();
        for _ in 0..5 {
            let id = db.enqueue_outbox("output", &json!({})).unwrap();
            db.mark_outbox_acked(&id).unwrap();
            age_row(&db, "outbox", "created_at", &id, 40);
        }

        // Each invocation deletes at most `limit` rows; repeated calls drain.
        assert_eq!(db.gc_outbox_batch(30, 2).unwrap(), 2);
        assert_eq!(db.gc_outbox_batch(30, 2).unwrap(), 2);
        assert_eq!(db.gc_outbox_batch(30, 2).unwrap(), 1);
        assert_eq!(db.gc_outbox_batch(30, 2).unwrap(), 0);
    }

    #[test]
    fn partial_indexes_exist_and_drive_the_replay_queries() {
        let db = Db::open_in_memory().unwrap();

        // The partial hot-path indexes are created by the idempotent schema.
        let indexes: Vec<String> = db
            .conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type = 'index'
                  AND name IN ('idx_outbox_unacked', 'idx_inbox_unprocessed')
                  ORDER BY name",
            )
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(indexes, ["idx_inbox_unprocessed", "idx_outbox_unacked"]);

        // …and the planner actually uses them for the replay hot paths (the SQL
        // mirrors list_unacked_outbox / list_unprocessed_inbox).
        let plan = |sql: &str| -> String {
            db.conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
                .join("; ")
        };
        let outbox_plan = plan(
            "SELECT id, type, payload, task_id, thread_id, created_at, acked_at, retry_count
               FROM outbox WHERE acked_at IS NULL ORDER BY id",
        );
        assert!(
            outbox_plan.contains("idx_outbox_unacked"),
            "outbox replay must use the partial index, got: {outbox_plan}"
        );
        let inbox_plan = plan(
            "SELECT id, type, payload, task_id, thread_id, received_at, processed_at, retry_count
               FROM inbox WHERE processed_at IS NULL ORDER BY id",
        );
        assert!(
            inbox_plan.contains("idx_inbox_unprocessed"),
            "inbox replay must use the partial index, got: {inbox_plan}"
        );
    }

    #[test]
    fn identity_persists_and_reloads_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");

        {
            let db = Db::open(&path).unwrap();
            assert!(db.get_identity().unwrap().is_none());
            db.set_identity("agent-123", &SecretString::from("connect-secret"))
                .unwrap();
        }

        // Reopen the same file — identity must survive.
        let db = Db::open(&path).unwrap();
        let identity = db.get_identity().unwrap().unwrap();
        assert_eq!(identity.agent_id, "agent-123");
        assert_eq!(identity.connect_token.expose_secret(), "connect-secret");

        // The token is redacted in Debug output.
        assert!(!format!("{identity:?}").contains("connect-secret"));

        // Singleton upsert replaces in place (no second row).
        db.set_identity("agent-456", &SecretString::from("rotated-secret"))
            .unwrap();
        let rotated = db.get_identity().unwrap().unwrap();
        assert_eq!(rotated.agent_id, "agent-456");
        assert_eq!(rotated.connect_token.expose_secret(), "rotated-secret");
    }

    // -- v2: config meta (applied global version) -------------

    #[test]
    fn applied_global_version_persists_and_upserts_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");

        {
            let db = Db::open(&path).unwrap();
            // Absent on a fresh DB — the never-reconciled case the version gate maps
            // to "authoritative new" on the first versioned payload.
            assert_eq!(db.get_applied_global_version().unwrap(), None);
            db.set_applied_global_version(1).unwrap();
            assert_eq!(db.get_applied_global_version().unwrap(), Some(1));
        }

        // Reopen the same file — the applied version survives a restart (this is the
        // durable slot that distinguishes a restart-at-same-version from a bump).
        let db = Db::open(&path).unwrap();
        assert_eq!(db.get_applied_global_version().unwrap(), Some(1));

        // A bump upserts in place (single row keyed by the meta key).
        db.set_applied_global_version(5).unwrap();
        assert_eq!(db.get_applied_global_version().unwrap(), Some(5));

        // The generic KV is independent and round-trips any string.
        assert_eq!(db.get_config_meta("nope").unwrap(), None);
        db.set_config_meta("nope", "yes").unwrap();
        assert_eq!(db.get_config_meta("nope").unwrap().as_deref(), Some("yes"));
    }

    // -- file permission hardening -----------------------------------

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn open_creates_the_db_files_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");

        let db = Db::open(&path).unwrap();
        // Force a write so the WAL sibling exists while the connection is live.
        db.set_identity("agent-1", &SecretString::from("tok"))
            .unwrap();

        assert_eq!(mode_of(&path), 0o600, "db file must be 0600");
        let wal = dir.path().join("agent.db-wal");
        assert!(wal.exists(), "WAL mode must have created the -wal sibling");
        assert_eq!(mode_of(&wal), 0o600, "WAL sibling must inherit 0600");
    }

    #[cfg(unix)]
    #[test]
    fn open_heals_world_readable_preexisting_db_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        // Simulate a pre-hardening deployment: create the DB, close it cleanly
        // (removing the WAL), then plant a stale 0644 WAL/SHM pair and loosen
        // the DB file itself to 0644.
        drop(Db::open(&path).unwrap());
        let wal = dir.path().join("agent.db-wal");
        let shm = dir.path().join("agent.db-shm");
        std::fs::write(&wal, b"").unwrap();
        std::fs::write(&shm, b"").unwrap();
        for f in [&path, &wal, &shm] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(mode_of(f), 0o644);
        }

        let _db = Db::open(&path).unwrap();

        assert_eq!(mode_of(&path), 0o600, "pre-existing db file must be healed");
        // SQLite may replace the stale siblings; whatever exists must be 0600.
        for f in [&wal, &shm] {
            if f.exists() {
                assert_eq!(mode_of(f), 0o600, "{} must be healed", f.display());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn harden_state_dir_heals_a_world_readable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let outer = tempfile::tempdir().unwrap();
        let dir = outer.path().join("workspace");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(mode_of(&dir), 0o755);

        super::harden_state_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700, "state dir must be owner-only");
    }

    // -- e2ee ---------------------------------------------------------------

    #[test]
    fn task_e2ee_is_set_once_and_never_cleared() {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&task_row("t-1", "active")).unwrap();
        assert_eq!(db.get_task_e2ee("t-1").unwrap(), None);
        db.set_task_e2ee("t-1", "gino.task-content.v1", "Z2lk")
            .unwrap();
        let stored = TaskE2eeRow {
            profile_id: "gino.task-content.v1".to_owned(),
            group_id: "Z2lk".to_owned(),
        };
        assert_eq!(db.get_task_e2ee("t-1").unwrap(), Some(stored.clone()));
        // A later value never replaces the first, and a row update keeps it.
        db.set_task_e2ee("t-1", "other.v2", "b3RoZXI").unwrap();
        let mut row = db.get_task_row("t-1").unwrap().unwrap();
        row.name = Some("renamed".to_owned());
        db.update_task_row(&row).unwrap();
        assert_eq!(db.get_task_e2ee("t-1").unwrap(), Some(stored));
        assert_eq!(db.get_task_e2ee("missing").unwrap(), None);
    }

    #[test]
    fn e2ee_key_packages_singleton_round_trips() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.get_e2ee_key_packages().unwrap(), None);
        let first = E2eeKeyPackagesRow {
            store: vec![1, 2, 3],
            last_resort_created_at: Some("2026-10-25T00:00:00Z".to_owned()),
        };
        db.put_e2ee_key_packages(&first).unwrap();
        assert_eq!(db.get_e2ee_key_packages().unwrap(), Some(first));
        let second = E2eeKeyPackagesRow {
            store: vec![9],
            last_resort_created_at: None,
        };
        db.put_e2ee_key_packages(&second).unwrap();
        assert_eq!(db.get_e2ee_key_packages().unwrap(), Some(second));
        db.delete_e2ee_key_packages().unwrap();
        assert_eq!(db.get_e2ee_key_packages().unwrap(), None);
    }

    #[test]
    fn e2ee_group_rows_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let mut row = E2eeGroupRow {
            task_id: "t-1".to_owned(),
            group_id: "Z2lk".to_owned(),
            profile_id: "gino.task-content.v1".to_owned(),
            snapshot: None,
            last_seq: None,
            status: "pending".to_owned(),
            updated_at: String::new(),
        };
        db.put_e2ee_group(&row).unwrap();
        let stored = db.get_e2ee_group("t-1").unwrap().unwrap();
        assert_eq!(stored.snapshot, None);
        assert_eq!(stored.status, "pending");
        assert!(!stored.updated_at.is_empty());
        row.snapshot = Some(vec![7; 4]);
        row.last_seq = Some(5);
        "member".clone_into(&mut row.status);
        db.put_e2ee_group(&row).unwrap();
        let stored = db.get_e2ee_group("t-1").unwrap().unwrap();
        assert_eq!(stored.snapshot, Some(vec![7; 4]));
        assert_eq!(stored.last_seq, Some(5));
        assert_eq!(db.list_e2ee_groups().unwrap().len(), 1);
        "bogus".clone_into(&mut row.status);
        assert!(db.put_e2ee_group(&row).is_err());
        db.delete_e2ee_group("t-1").unwrap();
        assert_eq!(db.get_e2ee_group("t-1").unwrap(), None);
    }

    fn cache_row(byte: u8, verified: bool) -> E2eeKeyCacheRow {
        E2eeKeyCacheRow {
            secrets: vec![byte; 8],
            verified,
        }
    }

    #[test]
    fn e2ee_key_cache_rows_round_trip() {
        let db = Db::open_in_memory().unwrap();
        let row = E2eeKeyCacheRow {
            secrets: vec![1; 8],
            verified: false,
        };
        db.put_e2ee_key_cache("t-1", 2, &row).unwrap();
        db.put_e2ee_key_cache("t-1", 3, &row).unwrap();
        assert_eq!(db.get_e2ee_key_cache("t-1", 2).unwrap(), Some(row));
        let verified = E2eeKeyCacheRow {
            secrets: vec![2; 8],
            verified: true,
        };
        db.put_e2ee_key_cache("t-1", 2, &verified).unwrap();
        assert_eq!(db.get_e2ee_key_cache("t-1", 2).unwrap(), Some(verified));
        db.delete_e2ee_key_cache("t-1", 2).unwrap();
        assert_eq!(db.get_e2ee_key_cache("t-1", 2).unwrap(), None);
        db.put_e2ee_key_cache("t-2", 1, &cache_row(3, true))
            .unwrap();
        let listed = db.list_e2ee_key_cache("t-1").unwrap();
        assert_eq!(listed, [(3, cache_row(1, false))]);
        db.delete_e2ee_key_cache_for_task("t-1").unwrap();
        assert_eq!(db.get_e2ee_key_cache("t-1", 3).unwrap(), None);
        assert!(db.list_e2ee_key_cache("t-1").unwrap().is_empty());
    }

    #[test]
    fn e2ee_log_pending_dedups_and_orders_by_seq() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.put_e2ee_log_pending("t-1", 4, "e2ee_log", "{}").unwrap());
        assert!(db.put_e2ee_log_pending("t-1", 2, "e2ee_log", "{}").unwrap());
        assert!(
            db.put_e2ee_log_pending("t-1", 2, "e2ee_welcome", "{}")
                .unwrap()
        );
        assert!(
            !db.put_e2ee_log_pending("t-1", 4, "e2ee_log", "{\"x\":1}")
                .unwrap()
        );
        assert!(db.put_e2ee_log_pending("t-2", 1, "e2ee_log", "{}").unwrap());
        assert!(db.put_e2ee_log_pending("t-1", 5, "bogus", "{}").is_err());
        let rows = db.list_e2ee_log_pending("t-1").unwrap();
        let keys: Vec<_> = rows.iter().map(|r| (r.seq, r.msg_type.as_str())).collect();
        assert_eq!(
            keys,
            [(2, "e2ee_welcome"), (2, "e2ee_log"), (4, "e2ee_log")]
        );
        assert_eq!(rows[2].payload, "{}");
        db.delete_e2ee_log_pending("t-1", 2, "e2ee_welcome")
            .unwrap();
        assert_eq!(db.list_e2ee_log_pending("t-1").unwrap().len(), 2);
    }

    #[test]
    fn outbox_unacked_tracks_the_ack() {
        let db = Db::open_in_memory().unwrap();
        let id = db.enqueue_outbox("e2ee_key_packages", &json!({})).unwrap();
        assert!(db.is_outbox_unacked(&id).unwrap());
        db.mark_outbox_acked(&id).unwrap();
        assert!(!db.is_outbox_unacked(&id).unwrap());
        assert!(!db.is_outbox_unacked("missing").unwrap());
    }
}
