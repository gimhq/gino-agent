//! The SQLite schema. One file holds everything; blobs (attachments, provisioning artifacts,
//! e2ee records) are stored inline, which is fine for a reference host and keeps a restart
//! lossless.

pub(crate) const SCHEMA: &str = "
  PRAGMA journal_mode = WAL;

  -- Enrolled agents. `register` is the register body without the token, `heartbeat` the last
  -- heartbeat `data`, `config` the host config layer (a JSON object served flat on
  -- GET /agent/config) and `config_version` its monotonic version.
  CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY, name TEXT, connect_token TEXT NOT NULL,
    register TEXT NOT NULL DEFAULT '{}', heartbeat TEXT,
    config TEXT NOT NULL DEFAULT '{}', config_version INTEGER NOT NULL DEFAULT 0,
    registered_at TEXT NOT NULL, last_seen TEXT
  );

  -- Durable host→agent frames; the row id is the frame's `msgId`.
  CREATE TABLE IF NOT EXISTS outbox (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
    frame TEXT NOT NULL, acked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
  );

  -- `definition` accumulates the task_upsert data the host sent; `encrypted` marks a task whose
  -- mapped fields travel sealed (protocol §5.3).
  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, name TEXT,
    definition TEXT NOT NULL DEFAULT '{}', encrypted INTEGER NOT NULL DEFAULT 0,
    current_thread_id TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS threads (
    id TEXT PRIMARY KEY, task_id TEXT NOT NULL, created_at TEXT NOT NULL
  );
  -- The latest result of each thread. `runs` counts distinct results (by `outboxId`, so a
  -- replay does not count twice); `frame` keeps the received envelope, since an encrypted
  -- task's sealed fields open against its cleartext ids (`outboxId`, `threadId`, `seq`).
  CREATE TABLE IF NOT EXISTS thread_runs (
    thread_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, runs INTEGER NOT NULL DEFAULT 1,
    outbox_id TEXT, status TEXT NOT NULL,
    result TEXT, error TEXT, failure_reason TEXT, engine_session_id TEXT,
    duration_ms INTEGER, final_seq INTEGER, engine TEXT, model TEXT, usage TEXT,
    attachments TEXT, encryption_error TEXT, frame TEXT NOT NULL, received_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    task_id TEXT NOT NULL, thread_id TEXT NOT NULL, seq INTEGER NOT NULL,
    kind TEXT NOT NULL, data TEXT NOT NULL, frame TEXT NOT NULL, received_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, seq)
  );
  CREATE TABLE IF NOT EXISTS cron_states (
    cron_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, data TEXT NOT NULL, received_at TEXT NOT NULL
  );

  -- The attachment byte channel (protocol §2). `inbound` blobs are staged by the host for an
  -- agent (message attachments, fs put); `outbound` ones are agent uploads (result
  -- attachments, fs get). A `single_use` blob is served once, then deleted.
  CREATE TABLE IF NOT EXISTS blobs (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, direction TEXT NOT NULL,
    name TEXT NOT NULL, content_type TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
    data BLOB NOT NULL, single_use INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS blobs_by_name ON blobs (agent_id, direction, name);

  -- Provisioning artifacts, content-addressed: a `file` entry's bytes or a `dir` entry's tar.
  CREATE TABLE IF NOT EXISTS artifacts (
    sha256 TEXT PRIMARY KEY, data BLOB NOT NULL, created_at TEXT NOT NULL
  );

  -- e2ee key directory (spec §3.5): the pinned identity key per agent, a key change awaiting
  -- an operator re-pin, and the KeyPackage pool.
  CREATE TABLE IF NOT EXISTS e2ee_identities (
    agent_id TEXT PRIMARY KEY, public_key TEXT NOT NULL, pending_key TEXT, pinned_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS e2ee_key_packages (
    reference TEXT PRIMARY KEY, agent_id TEXT NOT NULL, last_resort INTEGER NOT NULL,
    data BLOB NOT NULL, not_after INTEGER NOT NULL, claimed INTEGER NOT NULL DEFAULT 0
  );

  -- e2ee Delivery Service (spec §3): the scope record, the handshake log, epoch links and the
  -- group membership as the DS tracks it.
  CREATE TABLE IF NOT EXISTS e2ee_scopes (
    task_id TEXT PRIMARY KEY, profile_id TEXT NOT NULL, group_id BLOB NOT NULL,
    epoch INTEGER NOT NULL, drop_public_key BLOB NOT NULL, created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS e2ee_log (
    task_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, epoch INTEGER NOT NULL,
    message BLOB NOT NULL, drop_public_key BLOB, submitter TEXT NOT NULL,
    accepted_at TEXT NOT NULL, PRIMARY KEY (task_id, seq)
  );
  CREATE TABLE IF NOT EXISTS e2ee_links (
    task_id TEXT NOT NULL, epoch INTEGER NOT NULL, link BLOB NOT NULL,
    PRIMARY KEY (task_id, epoch)
  );
  CREATE TABLE IF NOT EXISTS e2ee_members (
    task_id TEXT NOT NULL, agent_id TEXT NOT NULL, PRIMARY KEY (task_id, agent_id)
  );

  -- The operator's own client device: its identity seed and, per encrypted task, the MLS group
  -- snapshot plus the epoch secrets it holds (spec §4.6).
  CREATE TABLE IF NOT EXISTS client_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1), seed BLOB NOT NULL
  );
  CREATE TABLE IF NOT EXISTS client_groups (
    task_id TEXT PRIMARY KEY, snapshot BLOB NOT NULL
  );
  CREATE TABLE IF NOT EXISTS client_secrets (
    task_id TEXT NOT NULL, epoch INTEGER NOT NULL, secrets BLOB NOT NULL,
    PRIMARY KEY (task_id, epoch)
  );
";
