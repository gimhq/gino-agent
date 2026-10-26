use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::chat::InboxPromptSource;
use crate::db::{Db, TaskRow, ThreadRow};
use crate::protocol::frames::{EntryKind, InboundFrame, ProvisioningEntry, TaskUpsertData};
use crate::transport::Inbound;

use super::{
    ServeContext, acquire_daemon_lock, apply_task_def, conclude_inbox_row, delete_task,
    handle_cron_upsert, lock, lock_db, route, task_owns_active_run,
};

fn chat_thread(id: &str, task_id: &str) -> ThreadRow {
    ThreadRow {
        id: id.to_owned(),
        task_id: task_id.to_owned(),
        cron_id: None,
        source: "chat".to_owned(),
        prompt: String::new(),
        engine: "claude".to_owned(),
        engine_session_id: None,
        status: "pending".to_owned(),
        failure_reason: None,
        attempt: 0,
        max_attempts: 1,
        work_dir: None,
        started_at: None,
        finished_at: None,
        duration_ms: None,
        result: None,
        error: None,
        created_at: "2026-06-22T00:00:00Z".to_owned(),
    }
}

/// Task-scoped interrupt: the scope check says a task owns the active run
/// only when one of its threads is `dispatched` or `running` — a `pending`
/// thread hasn't started and an `active`/settled one isn't in flight, so a
/// scoped interrupt for those tasks must be a no-op.
#[test]
fn task_owns_active_run_matches_only_in_flight_threads() {
    let db = Mutex::new(Db::open_in_memory().unwrap());
    {
        let guard = lock_db(&db);
        for task in ["t-running", "t-dispatched", "t-idle", "t-resting"] {
            guard
                .insert_task_row(&TaskRow {
                    id: task.to_owned(),
                    name: None,
                    kind: None,
                    status: "active".to_owned(),
                    engine: None,
                    model: None,
                    workdir: None,
                    meta: None,
                    created_at: "2026-06-22T09:00:00.000Z".to_owned(),
                    updated_at: "2026-06-22T09:00:00.000Z".to_owned(),
                })
                .unwrap();
        }
        for (id, task, status) in [
            ("th-run", "t-running", "running"),
            ("th-disp", "t-dispatched", "dispatched"),
            ("th-pend", "t-idle", "pending"),
            ("th-done", "t-idle", "succeeded"),
            ("th-rest", "t-resting", "active"),
        ] {
            let mut row = chat_thread(id, task);
            row.status = status.to_owned();
            guard.insert_thread(&row).unwrap();
        }
    }
    assert!(task_owns_active_run(&db, "t-running"));
    assert!(task_owns_active_run(&db, "t-dispatched"));
    assert!(!task_owns_active_run(&db, "t-idle"));
    assert!(!task_owns_active_run(&db, "t-resting"));
    assert!(!task_owns_active_run(&db, "t-unknown"));
}

/// Regression: the daemon's single-instance lock is exclusive and
/// fails fast. The lock is per open-file-description, so a second handle in
/// THIS process conflicts exactly like a second daemon process would — that
/// is the seam this test drives (no subprocess needed).
#[test]
fn daemon_lock_is_exclusive_and_released_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let held = acquire_daemon_lock(dir.path()).unwrap();

    let err = acquire_daemon_lock(dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("already running"),
        "second acquire must fail fast with a clear error, got: {err}"
    );

    // Released on drop (any process exit): a new daemon can start.
    drop(held);
    acquire_daemon_lock(dir.path()).unwrap();
}

/// The daemon's e2ee state over `db`, its keys in `dir`.
fn test_e2ee(db: &Arc<Mutex<Db>>, dir: &std::path::Path) -> Arc<crate::e2ee::E2ee> {
    let keys = crate::e2ee::E2eeKeys::load_or_create(dir).unwrap();
    Arc::new(
        crate::e2ee::E2ee::new(
            keys,
            Arc::clone(db),
            Arc::new(tokio::sync::Notify::new()),
            Arc::default(),
        )
        .unwrap(),
    )
}

/// Audit P3 wiring: the daemon path builds its executor with the transport
/// flush signal attached, so transcript frames stream mid-run in production
/// (the behavior the executor's own tests pin down).
#[tokio::test]
async fn build_execution_plane_wires_the_transport_flush() {
    let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let http = crate::transport::http::HttpClient::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(crate::scheduler::Cancel::new());
    let flush = Arc::new(tokio::sync::Notify::new());
    let (executor, _provisioner, _settings) = super::build_execution_plane(
        &crate::config::Config::default(),
        &http,
        &db,
        dir.path(),
        &cancel,
        Arc::clone(&flush),
        None,
        &test_e2ee(&db, dir.path()),
    )
    .await;
    assert!(executor.flush_wired());
}

/// Build a [`ServeContext`] over an in-memory DB for route-level tests. The
/// default config carries no host, so the provisioner is absent and the
/// provisioning side of `config_update` is a no-op here.
async fn serve_context(db: Arc<Mutex<Db>>, dir: &std::path::Path) -> ServeContext {
    let http = crate::transport::http::HttpClient::new().unwrap();
    let cancel = Arc::new(crate::scheduler::Cancel::new());
    let mut config = crate::config::Config::default();
    config.paths.workspace_dir = dir.to_path_buf();
    let remote_ops = Arc::new(crate::remote_ops::RemoteOps::new(false, dir));
    let e2ee = test_e2ee(&db, dir);
    let (executor, provisioner, settings) = super::build_execution_plane(
        &config,
        &http,
        &db,
        dir,
        &cancel,
        Arc::new(tokio::sync::Notify::new()),
        None,
        &e2ee,
    )
    .await;
    ServeContext {
        executor,
        db,
        nudge: Arc::new(tokio::sync::Notify::new()),
        drain: Arc::new(tokio::sync::Notify::new()),
        chat_max_attempts: 1,
        provisioner,
        engine_config_dir: dir.to_path_buf(),
        config: Mutex::new(config),
        engine_settings: settings.claude,
        codex_settings: settings.codex,
        remote_ops,
        e2ee,
    }
}

/// Regression: a `config_update` carrying a rotated `anthropicApiKey`
/// takes effect WITHOUT a restart — the route merges the overlay onto the
/// live config and rebuilds the shared engine settings the executor's engine
/// snapshots at its next spawn — and the inbox row is settled like any other
/// applied frame (no replay).
#[tokio::test]
async fn config_update_rotated_key_applies_to_the_next_engine_run() {
    let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let dir = tempfile::tempdir().unwrap();
    let context = serve_context(Arc::clone(&db), dir.path()).await;
    assert!(
        !lock(&context.engine_settings)
            .env
            .iter()
            .any(|(key, _)| key == "ANTHROPIC_API_KEY"),
        "no key configured at startup"
    );

    let frame = InboundFrame::ConfigUpdate {
        data: serde_json::json!({ "engine": { "anthropicApiKey": "sk-rotated" } }),
        msg_id: Some(crate::protocol::test_delivery_id(21)),
    };
    let inbox_id = lock_db(&db)
        .record_inbound_correlated(
            "config_update",
            &frame,
            None,
            None,
            Some(crate::protocol::test_delivery_id(21).as_str()),
        )
        .unwrap()
        .expect("a fresh msg_id stores a row");

    assert!(
        route(Inbound { inbox_id, frame }, &context)
            .await
            .is_continue()
    );

    // The seam the engine snapshots at every spawn now carries the new key…
    let env = lock(&context.engine_settings).env.clone();
    assert!(
        env.iter()
            .any(|(key, value)| key == "ANTHROPIC_API_KEY" && value == "sk-rotated"),
        "the next engine run must see the rotated key: {env:?}"
    );
    // …and the row is settled (applied), never left to replay.
    assert!(lock_db(&db).list_unprocessed_inbox().unwrap().is_empty());
}

/// A `config_update` whose payload does not parse as a config overlay
/// follows the dead-letter policy — dropped and settled (the failure is
/// deterministic and the host re-pushes config on connect), never left to
/// head-of-line-block the inbox — and the engine settings stay untouched.
#[tokio::test]
async fn malformed_config_update_overlay_is_dropped_and_settled() {
    let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let dir = tempfile::tempdir().unwrap();
    let context = serve_context(Arc::clone(&db), dir.path()).await;
    let before = lock(&context.engine_settings).env.clone();

    let frame = InboundFrame::ConfigUpdate {
        // `engine` must be an object; a number fails the overlay parse.
        data: serde_json::json!({ "engine": 5 }),
        msg_id: Some(crate::protocol::test_delivery_id(22)),
    };
    let inbox_id = lock_db(&db)
        .record_inbound_correlated(
            "config_update",
            &frame,
            None,
            None,
            Some(crate::protocol::test_delivery_id(22).as_str()),
        )
        .unwrap()
        .expect("a fresh msg_id stores a row");

    assert!(
        route(Inbound { inbox_id, frame }, &context)
            .await
            .is_continue()
    );

    assert_eq!(
        lock(&context.engine_settings).env,
        before,
        "a malformed overlay must not disturb the engine settings"
    );
    assert!(
        lock_db(&db).list_unprocessed_inbox().unwrap().is_empty(),
        "the malformed update is settled, not left to replay"
    );
}

/// `task_delete` removes the task's memory dir, whether or not the task row is
/// known, and leaves other tasks' memory and the agent memory alone.
#[test]
fn task_delete_removes_only_that_tasks_memory_dir() {
    let db = Mutex::new(Db::open_in_memory().unwrap());
    let ws = tempfile::tempdir().unwrap();
    lock_db(&db)
        .insert_task_row(&TaskRow {
            id: "t-1".to_owned(),
            name: None,
            kind: None,
            status: "active".to_owned(),
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            created_at: "2026-06-22T09:00:00.000Z".to_owned(),
            updated_at: "2026-06-22T09:00:00.000Z".to_owned(),
        })
        .unwrap();
    for task in ["t-1", "t-unknown", "t-other"] {
        crate::memory::prepare(
            &crate::memory::memory_dir(ws.path(), task),
            crate::memory::Tree::Task,
        )
        .unwrap();
    }
    let agent = crate::memory::agent_memory_dir(ws.path());
    crate::memory::prepare(&agent, crate::memory::Tree::Agent).unwrap();

    assert!(delete_task(&db, ws.path(), "t-1"));
    assert!(delete_task(&db, ws.path(), "t-unknown"));

    assert_eq!(
        lock_db(&db).get_task_row("t-1").unwrap().unwrap().status,
        "cancelled"
    );
    assert!(!crate::memory::memory_dir(ws.path(), "t-1").exists());
    assert!(!crate::memory::memory_dir(ws.path(), "t-unknown").exists());
    assert!(
        crate::memory::memory_dir(ws.path(), "t-other")
            .join("index.md")
            .is_file()
    );
    assert!(agent.join("index.md").is_file());
    assert!(agent.join("system/definition.md").is_file());
}

/// D1: `task_delete` maps to `cancelled`, so the task's work inherits the
/// task-status gate for free — its crons stop firing and its pending threads /
/// queued messages stop draining. The paired `task_upsert{status:"active"}`
/// clears the gate AND wakes both loops (scheduler nudge + executor drain), so
/// the parked work resumes without an external nudge.
#[tokio::test]
async fn task_delete_parks_the_tasks_work_until_a_task_upsert_reactivates_it() {
    let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let dir = tempfile::tempdir().unwrap();
    let context = serve_context(Arc::clone(&db), dir.path()).await;
    lock_db(&db)
        .insert_task_row(&TaskRow {
            id: "t-1".to_owned(),
            name: None,
            kind: None,
            status: "active".to_owned(),
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            created_at: "2026-06-22T09:00:00.000Z".to_owned(),
            updated_at: "2026-06-22T09:00:00.000Z".to_owned(),
        })
        .unwrap();

    let frame = InboundFrame::TaskDelete {
        task_id: "t-1".to_owned(),
        msg_id: Some(crate::protocol::test_delivery_id(31)),
    };
    let inbox_id = lock_db(&db)
        .record_inbound_correlated(
            "task_delete",
            &frame,
            Some("t-1"),
            None,
            Some(crate::protocol::test_delivery_id(31).as_str()),
        )
        .unwrap()
        .expect("a fresh msg_id stores a row");
    assert!(
        route(Inbound { inbox_id, frame }, &context)
            .await
            .is_continue()
    );
    assert_eq!(
        lock_db(&db).get_task_row("t-1").unwrap().unwrap().status,
        "cancelled"
    );
    assert!(
        lock_db(&db).task_execution_blocked("t-1").unwrap(),
        "a deleted task parks its crons/threads/messages"
    );

    let frame = InboundFrame::TaskUpsert {
        task_id: "t-1".to_owned(),
        data: TaskUpsertData {
            name: None,
            kind: None,
            status: Some("active".to_owned()),
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            entries: None,
            e2ee: None,
        },
        msg_id: Some(crate::protocol::test_delivery_id(32)),
    };
    let inbox_id = lock_db(&db)
        .record_inbound_correlated(
            "task_upsert",
            &frame,
            Some("t-1"),
            None,
            Some(crate::protocol::test_delivery_id(32).as_str()),
        )
        .unwrap()
        .expect("a fresh msg_id stores a row");
    assert!(
        route(Inbound { inbox_id, frame }, &context)
            .await
            .is_continue()
    );
    assert!(!lock_db(&db).task_execution_blocked("t-1").unwrap());
    // Both wake-ups are already stored as permits, so each `notified()` resolves
    // immediately — the scheduler re-fires and the drainer re-runs the parked work.
    for (label, signal) in [
        ("scheduler nudge", &context.nudge),
        ("executor drain", &context.drain),
    ] {
        tokio::time::timeout(std::time::Duration::from_millis(100), signal.notified())
            .await
            .unwrap_or_else(|_| panic!("re-activation must wake the {label}"));
    }
}

/// A `task_upsert` carrying `entries` persists them as the `tasks.entries` JSON
/// (insert-new and patch-existing); a later `task_upsert` that OMITS `entries`
/// must leave the prior set intact, while an explicit (empty) set replaces it.
#[test]
fn task_upsert_persists_entries_and_omission_preserves_them() {
    let db = Mutex::new(Db::open_in_memory().unwrap());
    let entry = ProvisioningEntry {
        id: "claude-md".to_owned(),
        sha256: "ab".repeat(32),
        target: "CLAUDE.md".to_owned(),
        kind: EntryKind::File,
    };

    // Insert-new WITH entries → persisted as the JSON array.
    apply_task_def(
        &db,
        "t-1",
        &TaskUpsertData {
            name: Some("build".to_owned()),
            kind: None,
            status: None,
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            entries: Some(vec![entry.clone()]),
            e2ee: None,
        },
    );
    let json = lock_db(&db)
        .get_task_entries("t-1")
        .unwrap()
        .expect("entries persisted on insert");
    assert_eq!(
        serde_json::from_str::<Vec<ProvisioningEntry>>(&json).unwrap(),
        vec![entry],
    );

    // Patch-existing WITHOUT entries → the prior set is untouched.
    apply_task_def(
        &db,
        "t-1",
        &TaskUpsertData {
            name: Some("build-2".to_owned()),
            kind: None,
            status: None,
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            entries: None,
            e2ee: None,
        },
    );
    assert_eq!(
        lock_db(&db).get_task_entries("t-1").unwrap().as_deref(),
        Some(json.as_str()),
        "a task_upsert without entries must not wipe them"
    );

    // Patch-existing WITH an explicit empty set → replaced.
    apply_task_def(
        &db,
        "t-1",
        &TaskUpsertData {
            name: None,
            kind: None,
            status: None,
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            entries: Some(Vec::new()),
            e2ee: None,
        },
    );
    assert_eq!(
        lock_db(&db).get_task_entries("t-1").unwrap().as_deref(),
        Some("[]"),
        "an explicit empty entries set replaces the prior one"
    );
}

/// D2: the host ALWAYS sends the task definition (`engine`/`model`/`workdir`/
/// `meta`) on `task_upsert`; the runner used to discard all four. They must land
/// on the `tasks` row, and — like `entries` — a later upsert that OMITS them must
/// not wipe what is already stored.
#[test]
fn task_upsert_persists_definition_and_omission_preserves_it() {
    let db = Mutex::new(Db::open_in_memory().unwrap());

    // Insert-new carrying the full definition.
    assert!(apply_task_def(
        &db,
        "t-1",
        &TaskUpsertData {
            name: Some("build".to_owned()),
            kind: Some("agent".to_owned()),
            status: Some("active".to_owned()),
            engine: Some("claude".to_owned()),
            model: Some("claude-opus-4-8".to_owned()),
            workdir: Some("/srv/project".to_owned()),
            meta: Some(json!({ "team": "infra" })),
            entries: None,
            e2ee: None,
        },
    ));
    let row = lock_db(&db).get_task_row("t-1").unwrap().unwrap();
    assert_eq!(row.engine.as_deref(), Some("claude"));
    assert_eq!(row.model.as_deref(), Some("claude-opus-4-8"));
    assert_eq!(row.workdir.as_deref(), Some("/srv/project"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(row.meta.as_deref().unwrap()).unwrap(),
        json!({ "team": "infra" }),
        "meta is persisted verbatim as JSON text"
    );

    // Patch-existing that omits all four → the stored definition is untouched.
    assert!(apply_task_def(
        &db,
        "t-1",
        &TaskUpsertData {
            name: Some("build-2".to_owned()),
            kind: None,
            status: None,
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            entries: None,
            e2ee: None,
        },
    ));
    let after = lock_db(&db).get_task_row("t-1").unwrap().unwrap();
    assert_eq!(
        after.name.as_deref(),
        Some("build-2"),
        "the sent field applies"
    );
    assert_eq!(
        (after.engine, after.model, after.workdir, after.meta),
        (row.engine, row.model, row.workdir, row.meta),
        "an upsert omitting the definition must not wipe it"
    );

    // A sent field still overwrites.
    assert!(apply_task_def(
        &db,
        "t-1",
        &TaskUpsertData {
            name: None,
            kind: None,
            status: None,
            engine: None,
            model: Some("claude-sonnet-4-6".to_owned()),
            workdir: None,
            meta: None,
            entries: None,
            e2ee: None,
        },
    ));
    assert_eq!(
        lock_db(&db)
            .get_task_row("t-1")
            .unwrap()
            .unwrap()
            .model
            .as_deref(),
        Some("claude-sonnet-4-6")
    );
}

/// D2: an engine this build cannot run is FORWARD-COMPAT NOISE, not a bad
/// request — the value is stored as sent, the apply still succeeds (so the inbox
/// row is marked processed rather than replayed forever), and the task's threads
/// stay runnable on the claude fallback.
#[tokio::test]
async fn unsupported_engine_is_stored_but_never_fails_the_task() {
    let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));

    assert!(
        apply_task_def(
            &db,
            "t-1",
            &TaskUpsertData {
                name: None,
                kind: None,
                status: Some("active".to_owned()),
                engine: Some("codex".to_owned()),
                model: None,
                workdir: None,
                meta: None,
                entries: None,
                e2ee: None,
            },
        ),
        "an unsupported engine must not fail the apply"
    );
    assert_eq!(
        lock_db(&db)
            .get_task_row("t-1")
            .unwrap()
            .unwrap()
            .engine
            .as_deref(),
        Some("codex"),
        "the value is persisted as sent"
    );

    // The task's thread is still runnable: nothing parked or failed it.
    lock_db(&db)
        .insert_thread(&chat_thread("th-1", "t-1"))
        .unwrap();
    assert!(!crate::executor::task_parked(&db, "t-1"));
    assert_eq!(
        lock_db(&db).list_pending_threads().unwrap().len(),
        1,
        "the thread stays pending and drainable despite the unknown engine"
    );
}

/// Regression (inbound half): a processing FAILURE leaves the inbox row
/// unprocessed (so it replays) and bumps the failure counter; a success marks
/// it processed. The poison policy discards the row only after
/// [`MAX_INBOX_RETRIES`] processing failures — reconnects never count.
#[test]
fn processing_failure_leaves_row_unprocessed_and_poisons_after_limit() {
    use crate::transport::MAX_INBOX_RETRIES;

    let db = Mutex::new(Db::open_in_memory().unwrap());
    let id = lock_db(&db)
        .record_inbound_correlated(
            "cron_upsert",
            &serde_json::json!({ "type": "cron_upsert" }),
            Some("t-1"),
            Some("cr-1"),
            Some(crate::protocol::test_delivery_id(11).as_str()),
        )
        .unwrap()
        .unwrap();

    // One failure: still unprocessed (replayable), counter = 1.
    conclude_inbox_row(&db, id, false);
    let rows = lock_db(&db).list_unprocessed_inbox().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "a failed apply must NOT mark the row processed"
    );
    assert_eq!(
        rows[0].retry_count, 1,
        "the counter counts processing failures"
    );

    // A later success settles it.
    conclude_inbox_row(&db, id, true);
    assert!(lock_db(&db).list_unprocessed_inbox().unwrap().is_empty());

    // A row that keeps failing is discarded exactly at the limit.
    let poison = lock_db(&db)
        .record_inbound_correlated(
            "task_delete",
            &serde_json::json!({ "type": "task_delete" }),
            Some("t-2"),
            None,
            Some(crate::protocol::test_delivery_id(12).as_str()),
        )
        .unwrap()
        .unwrap();
    for _ in 0..MAX_INBOX_RETRIES - 1 {
        conclude_inbox_row(&db, poison, false);
    }
    assert_eq!(
        lock_db(&db).list_unprocessed_inbox().unwrap().len(),
        1,
        "below the limit the row stays replayable"
    );
    conclude_inbox_row(&db, poison, false);
    assert!(
        lock_db(&db).list_unprocessed_inbox().unwrap().is_empty(),
        "at the limit the poison row is discarded"
    );
}

/// Regression: a `cron_upsert` arriving BEFORE its `task_upsert` is not
/// dropped — the task row is seeded and the cron applies (the later
/// `task_upsert` patches the seeded row in place).
#[test]
fn cron_upsert_before_task_upsert_is_not_dropped() {
    let db = Mutex::new(Db::open_in_memory().unwrap());
    let nudge = tokio::sync::Notify::new();
    let data = crate::protocol::frames::CronUpsertData {
        kind: "schedule".to_owned(),
        prompt: "do the rounds".into(),
        schedule_type: Some("interval".to_owned()),
        schedule_value: Some("60000".to_owned()),
        next_run: None,
        continuity: "isolated".to_owned(),
        status: Some("active".to_owned()),
    };

    assert!(
        handle_cron_upsert(&db, "t-new", "cr-1", &data, &nudge),
        "a cron for a not-yet-seen task applies (task seeded)"
    );
    assert!(
        lock_db(&db).get_task_row("t-new").unwrap().is_some(),
        "a minimal task row is seeded to satisfy the FK"
    );
    let cron = lock_db(&db)
        .get_cron("cr-1")
        .unwrap()
        .expect("cron persisted");
    assert_eq!(cron.prompt, "do the rounds");

    // The later task_upsert patches the seeded row rather than failing.
    assert!(apply_task_def(
        &db,
        "t-new",
        &TaskUpsertData {
            name: Some("rounds".to_owned()),
            kind: None,
            status: None,
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            entries: None,
            e2ee: None,
        },
    ));
    assert_eq!(
        lock_db(&db)
            .get_task_row("t-new")
            .unwrap()
            .unwrap()
            .name
            .as_deref(),
        Some("rounds")
    );
}

/// Regression, over the runner's own wiring: with the host UNREACHABLE
/// (the transport dialing in the background, never connected) the local
/// planes still run — the scheduler fires a due cron and the executor
/// worker drains it through the engine — and shutdown completes cleanly.
/// The old code blocked boot on the first dial and shut the whole daemon
/// down once the transport's 60-retry budget was exhausted.
#[allow(
    clippy::too_many_lines,
    reason = "the in-test engine stub is the bulk; splitting it would obscure the scenario"
)]
#[tokio::test]
async fn local_planes_run_and_shut_down_cleanly_while_host_unreachable() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use futures_util::stream::{self, BoxStream};
    use secrecy::SecretString;

    use crate::db::CronRow;
    use crate::engine::{
        Engine, EngineError, EngineEvent, RunOutcome, RunStatus, Session, SessionCfg,
    };
    use crate::executor::{ThreadExecutor, WatchdogCfg};
    use crate::scheduler::{Cancel, Scheduler};
    use crate::transport::{Transport, TransportConfig};

    /// Counts engine runs; every session immediately succeeds.
    struct CountingEngine {
        runs: AtomicUsize,
    }
    struct OkSession;

    #[async_trait]
    impl Engine for CountingEngine {
        fn name(&self) -> &'static str {
            "counting"
        }
        async fn start_session(&self, _cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(OkSession))
        }
    }

    #[async_trait]
    impl Session for OkSession {
        async fn interrupt(&self) -> Result<(), EngineError> {
            Ok(())
        }
        fn events(&self) -> BoxStream<'_, EngineEvent> {
            Box::pin(stream::iter(vec![
                EngineEvent::SessionStarted {
                    session_id: "sess-off".to_owned(),
                },
                EngineEvent::Result(RunOutcome {
                    status: RunStatus::Success,
                    result: Some("ran while the host was down".to_owned()),
                    session_id: Some("sess-off".to_owned()),
                    error: None,
                    error_kind: None,
                }),
            ]))
        }
    }

    let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    // A task with a cron already due: the scheduler's first tick fires it
    // (an overdue `interval` slot dispatches; only `once` has a grace cut).
    lock_db(&db)
        .insert_task_row(&TaskRow {
            id: "task-1".to_owned(),
            name: None,
            kind: None,
            status: "active".to_owned(),
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            created_at: "2026-06-22T09:00:00.000Z".to_owned(),
            updated_at: "2026-06-22T09:00:00.000Z".to_owned(),
        })
        .unwrap();
    lock_db(&db)
        .insert_cron(&CronRow {
            id: "c-off".to_owned(),
            task_id: "task-1".to_owned(),
            kind: "schedule".to_owned(),
            prompt: "run the recurring job".to_owned(),
            schedule_type: Some("interval".to_owned()),
            schedule_value: Some("60000".to_owned()),
            next_run: Some("2026-06-22T09:00:00.000Z".to_owned()),
            last_fired_at: None,
            continuity: "isolated".to_owned(),
            run_count: 0,
            status: "active".to_owned(),
            created_at: "2026-06-22T09:00:00.000Z".to_owned(),
            updated_at: "2026-06-22T09:00:00.000Z".to_owned(),
        })
        .unwrap();

    // The host is UNREACHABLE: a bound-then-dropped port refuses every dial.
    let addr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let transport = Transport::open(
        format!("ws://{addr}/agent/ws/agent-off"),
        SecretString::from("tok"),
        Arc::clone(&db),
        TransportConfig::default(),
        Arc::new(crate::remote_ops::RemoteOps::new(
            false,
            std::path::Path::new("/nonexistent"),
        )),
    );

    let engine = Arc::new(CountingEngine {
        runs: AtomicUsize::new(0),
    });
    let dir = tempfile::tempdir().unwrap();
    let executor = Arc::new(ThreadExecutor::new(
        Arc::clone(&engine) as Arc<dyn Engine>,
        Arc::clone(&db),
        dir.path().to_path_buf(),
        WatchdogCfg {
            inactivity_timeout: None,
            ..WatchdogCfg::default()
        },
    ));
    let prompts = Arc::new(InboxPromptSource {
        db: Arc::clone(&db),
    });

    // The runner's own planes: the real scheduler task + executor worker.
    let cancel = Arc::new(Cancel::new());
    let scheduler = Scheduler::new(Arc::clone(&db), Arc::clone(&cancel), 1, 30);
    let drain = scheduler.drain_signal();
    let scheduler_task = tokio::spawn(scheduler.run());
    let worker = tokio::spawn(super::run_worker(
        Arc::clone(&executor),
        Arc::clone(&db),
        prompts,
        drain,
        transport.flush_handle(),
        Arc::clone(&cancel),
        1,
    ));

    // The cron fires and its thread EXECUTES while the host is down.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while lock_db(&db)
        .list_threads_by_status("succeeded")
        .unwrap()
        .is_empty()
    {
        assert!(
            std::time::Instant::now() < deadline,
            "cron thread did not execute while the host was unreachable"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        engine.runs.load(Ordering::SeqCst),
        1,
        "the engine actually ran offline"
    );
    // The result plane queued durably for the eventual reconnect replay.
    assert!(
        !lock_db(&db).list_unacked_outbox().unwrap().is_empty(),
        "result frames wait in the outbox for the host to come back"
    );

    // Shutdown completes although the transport never connected.
    cancel.cancel();
    worker.await.unwrap();
    scheduler_task.await.unwrap();
    transport.shutdown().await;
}

/// Regression: SIGTERM (what systemd `stop` sends) resolves the
/// shutdown-signal future — the old code handled only SIGINT and left
/// SIGTERM on the default handler. The OS edge is exercised in-process:
/// tokio's listener registration replaces the default disposition, so
/// raising SIGTERM here notifies the future instead of killing the test
/// runner.
#[cfg(unix)]
#[tokio::test]
async fn sigterm_resolves_the_shutdown_signal() {
    use std::time::Duration;

    // Install the process-wide SIGTERM handler BEFORE raising, so a lost
    // registration race cannot kill the test binary (tokio never restores
    // the default disposition once a listener has existed).
    let _armed = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM listener");
    let task = tokio::spawn(super::shutdown_signal());
    // Let the spawned future register its own listeners before the raise.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let status = std::process::Command::new("kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status()
        .expect("raising SIGTERM");
    assert!(status.success());

    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("shutdown_signal did not resolve on SIGTERM")
        .unwrap();
}

/// Regression, over the runner's own shutdown sequence: a shutdown
/// while a run is ACTIVE trips the run's cancellation and the worker
/// settles within the bounded drain window — the old code awaited the
/// worker unconditionally, blocking up to running_timeout (30 min) until
/// the supervisor SIGKILLed the daemon and orphaned the engine child.
#[allow(
    clippy::too_many_lines,
    reason = "the in-test engine stub is the bulk; splitting it would obscure the scenario"
)]
#[tokio::test]
async fn shutdown_cancels_the_active_run_within_the_drain_window() {
    use std::time::Duration;

    use async_trait::async_trait;
    use futures_util::StreamExt;
    use futures_util::stream::{self, BoxStream};

    use crate::engine::{Engine, EngineError, EngineEvent, Session, SessionCfg};
    use crate::executor::{ThreadExecutor, WatchdogCfg};
    use crate::scheduler::Cancel;

    /// Announces a session then stalls forever, ignoring the interrupt —
    /// the engine shape that used to pin shutdown until running_timeout.
    struct StallingEngine;
    struct StallingSession;

    #[async_trait]
    impl Engine for StallingEngine {
        fn name(&self) -> &'static str {
            "stalling"
        }
        async fn start_session(&self, _cfg: SessionCfg) -> Result<Box<dyn Session>, EngineError> {
            Ok(Box::new(StallingSession))
        }
    }

    #[async_trait]
    impl Session for StallingSession {
        async fn interrupt(&self) -> Result<(), EngineError> {
            Ok(())
        }
        fn events(&self) -> BoxStream<'_, EngineEvent> {
            let head = stream::iter(vec![EngineEvent::SessionStarted {
                session_id: "sess-stall".to_owned(),
            }]);
            Box::pin(head.chain(stream::pending::<EngineEvent>()))
        }
    }

    let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    lock_db(&db)
        .insert_task_row(&TaskRow {
            id: "t-1".to_owned(),
            name: None,
            kind: None,
            status: "active".to_owned(),
            engine: None,
            model: None,
            workdir: None,
            meta: None,
            created_at: "2026-06-22T09:00:00.000Z".to_owned(),
            updated_at: "2026-06-22T09:00:00.000Z".to_owned(),
        })
        .unwrap();
    // A pending thread with a prompt snapshot: the drain runs it directly.
    let mut thread = chat_thread("th-stall", "t-1");
    thread.prompt = "keep busy".to_owned();
    lock_db(&db).insert_thread(&thread).unwrap();

    let cancel = Arc::new(Cancel::new());
    let engine: Arc<dyn Engine> = Arc::new(StallingEngine);
    let dir = tempfile::tempdir().unwrap();
    let executor = Arc::new(
        ThreadExecutor::new(
            engine,
            Arc::clone(&db),
            dir.path().to_path_buf(),
            WatchdogCfg {
                inactivity_timeout: None,
                cancel_drain_timeout: Duration::from_millis(100),
                ..WatchdogCfg::default()
            },
        )
        .with_shutdown(Arc::clone(&cancel)),
    );
    let prompts = Arc::new(InboxPromptSource {
        db: Arc::clone(&db),
    });
    let worker = tokio::spawn(super::run_worker(
        Arc::clone(&executor),
        Arc::clone(&db),
        prompts,
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
        Arc::clone(&cancel),
        1,
    ));

    // Wait until the run is live (the engine is stalling inside it).
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while lock_db(&db).get_thread("th-stall").unwrap().unwrap().status != "running" {
        assert!(
            std::time::Instant::now() < deadline,
            "the stalling run never started"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // The full shutdown sequence must settle in seconds, not 30 minutes.
    tokio::time::timeout(
        Duration::from_secs(5),
        super::shutdown_worker(&cancel, &executor, worker, Duration::from_secs(10)),
    )
    .await
    .expect("shutdown did not settle within the drain window");

    let row = lock_db(&db).get_thread("th-stall").unwrap().unwrap();
    assert_eq!(row.status, "cancelled", "the active run was cancelled");
    assert!(
        row.engine_session_id.is_none(),
        "the hard-killed turn keeps no resume handle"
    );
}
