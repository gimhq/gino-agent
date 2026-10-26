//! Chat-threading policy for inbound `message` frames (host-architecture M4) —
//! the executor's companion module for the chat plane.
//!
//! This module owns the inbound message → thread policy the runner wires around
//! the [`ThreadExecutor`]:
//!
//! * **routing / minting** ([`ensure_chat_thread`], [`minted_thread_id`]) — a
//!   present `threadId` continues its thread; an absent one maps to a thread id
//!   derived deterministically from the message's inbox row, so reconnect
//!   replays never mint duplicate threads;
//! * **prompt resolution** ([`InboxPromptSource`]) — the drainer's
//!   [`PromptSource`]: a chat/api thread runs (and consumes) its oldest
//!   unprocessed inbox `message`, a cron thread runs its trigger's
//!   `crons.prompt`;
//! * **the post-terminal re-scan** ([`drain_with_queued_messages`]) — messages
//!   queued while their thread was in flight are re-pended and drained until
//!   none remain, so the second of two quick messages executes instead of
//!   rotting in the inbox.
//!
//! The runner (see [`crate::runner`]) supplies the wiring: it calls into this
//! policy from its inbound router and its executor worker loop.

use std::sync::{Arc, Mutex};

use tracing::{debug, warn};

use crate::db::{Db, TaskRow, ThreadRow};
use crate::executor::{PromptSource, ThreadExecutor, lock_db, task_parked};
use crate::protocol::frames::InboundFrame;
use crate::scheduler::{now, to_iso};

/// Engine a chat/api thread defaults to (the only engine today; sourced from the
/// task/config when more engines land).
const DEFAULT_ENGINE: &str = "claude";

/// Drain every `pending` thread, then keep re-pending threads whose inbox holds a
/// queued `message` (one that arrived while the thread was in flight and was only
/// logged "queued") and draining again until no queued message remains — the
/// post-terminal re-scan (the second of two quick messages must
/// EXECUTE once the first run finishes, not rot in the inbox). Terminates because
/// every re-pended thread's next run consumes its queued message row.
pub(crate) async fn drain_with_queued_messages(
    executor: &ThreadExecutor,
    db: &Mutex<Db>,
    prompts: &InboxPromptSource,
    chat_max_attempts: i64,
) {
    executor.drain_pending(prompts).await;
    while repend_queued_messages(db, chat_max_attempts) > 0 {
        executor.drain_pending(prompts).await;
    }
}

/// Re-pend every resting thread that still has an unprocessed inbox `message`
/// targeting it. An untargeted (absent-`threadId`) row maps to its
/// deterministically minted thread ([`minted_thread_id`]) — recreating it if a
/// crash lost the mint. Threads that are in flight (or already `pending`) are
/// left alone: their message stays queued for the next pass. Cron threads are
/// never re-pended here — their prompt source is `crons.prompt`, so a re-pend
/// would re-run the cron without ever consuming the message. A message under a
/// closed/cancelled task is left queued (D1). Returns how many threads were made
/// `pending`.
fn repend_queued_messages(db: &Mutex<Db>, chat_max_attempts: i64) -> usize {
    let rows = match lock_db(db).list_inbox_by_type("message") {
        Ok(rows) => rows,
        Err(err) => {
            warn!(error = %err, "failed to scan inbox for queued messages");
            return 0;
        }
    };
    let mut pended = 0;
    for row in rows {
        let Some(task_id) = row.task_id.clone() else {
            continue;
        };
        // Task-status gate (D1): a closed/cancelled task's message stays queued
        // in the inbox — unprocessed, never failed — until the task re-activates.
        if task_parked(db, &task_id) {
            debug!(task = %task_id, inbox = row.id, "task closed/cancelled; leaving the message queued");
            continue;
        }
        let tid = row
            .thread_id
            .clone()
            .unwrap_or_else(|| minted_thread_id(&task_id, row.id));
        let is_cron_thread = matches!(
            lock_db(db).get_thread(&tid),
            Ok(Some(thread)) if thread.source == "cron"
        );
        if is_cron_thread {
            debug!(thread = %tid, inbox = row.id, "queued message targets a cron thread; leaving it");
            continue;
        }
        if ensure_chat_thread(db, &task_id, &tid, chat_max_attempts) {
            pended += 1;
        }
    }
    pended
}

/// Resolves engine prompts for the drainer. This is consulted **only at attempt 0
/// for a thread with no snapshot** — the executor reuses `threads.prompt` for cron
/// threads (snapshotted at fire time) and for every retry/resume (D10). A `cron`
/// thread runs its trigger's `crons.prompt` (the recurring instruction, D10:(a) —
/// no longer the v1 `tasks.prompt` shim); a `chat`/`api` thread runs the text of
/// its oldest unprocessed inbox `message`, which it **consumes** (marks processed)
/// so the row neither replays nor re-resolves. `None` (no runnable prompt) fails
/// the thread `runner.invalid_request`.
pub(crate) struct InboxPromptSource {
    pub(crate) db: Arc<Mutex<Db>>,
}

impl PromptSource for InboxPromptSource {
    fn prompt_for(&self, thread: &ThreadRow) -> Option<String> {
        match thread.source.as_str() {
            // A cron thread's instruction is its trigger's crons.prompt (D10:(a)).
            "cron" => thread
                .cron_id
                .as_deref()
                .and_then(|cron_id| lock_db(&self.db).get_cron(cron_id).ok().flatten())
                .map(|cron| cron.prompt)
                .filter(|prompt| !prompt.trim().is_empty()),
            _ => resolve_inbox_message(&self.db, thread),
        }
    }
}

/// Find, consume, and return the text of the oldest unprocessed inbox `message`
/// for `thread` (matched by `threadId`, falling back to `taskId` for an untargeted
/// chat message). Consuming it (mark processed) prevents both a replay re-run and a
/// re-resolve; an empty message yields `None` (which fails the thread) but is still
/// consumed so it cannot loop. A sealed text (an encrypted task) is returned in
/// its sealed form; the executor opens it right before the run.
///
/// For a runnable message this also snapshots its inbound attachment descriptors
/// into the durable `thread_attachments` table (P1-10b), BEFORE consuming the row:
/// once processed the message is invisible to every later query, so a
/// consumed-but-unsnapshotted crash window would silently strip the thread of its
/// inputs. Snapshotted only when the prompt is non-empty, so a failed (unrunnable)
/// thread — which never reaches materialization — leaves no orphan row; on a
/// snapshot write failure the message is left unconsumed (a later resolve retries)
/// and the resolve fails rather than running without the inputs.
fn resolve_inbox_message(db: &Mutex<Db>, thread: &ThreadRow) -> Option<String> {
    let guard = lock_db(db);
    let rows = guard.list_inbox_by_type("message").ok()?;
    let row = rows.into_iter().find(|row| {
        row.thread_id.as_deref() == Some(thread.id.as_str())
            || (row.thread_id.is_none() && row.task_id.as_deref() == Some(thread.task_id.as_str()))
    })?;
    let message = match serde_json::from_str::<InboundFrame>(&row.payload) {
        Ok(InboundFrame::Message { data, .. }) if !data.text.is_blank() => Some(data),
        _ => None,
    };
    if let Some(data) = &message
        && let Some(attachments) = data.attachments.as_ref().filter(|a| !a.is_empty())
        && let Err(err) = guard.set_thread_attachments(&thread.id, attachments)
    {
        warn!(thread = %thread.id, error = %err, "failed to snapshot inbound attachments; leaving the message unconsumed");
        return None;
    }
    if let Err(err) = guard.mark_inbox_processed(row.id) {
        warn!(id = row.id, error = %err, "failed to consume inbox message");
    }
    message.map(|data| data.text.to_stored())
}

/// The deterministic thread id for an absent-`threadId` `message`: derived
/// from the inbox row that carries the message, so every delivery of that row —
/// original or reconnect replay — resolves to the SAME thread instead of minting a
/// fresh UUID each time (N reconnects must not race N+1 threads for one inbox
/// row). The `task_id@` prefix is kept so the id shape matches host-minted ones.
pub(crate) fn minted_thread_id(task_id: &str, inbox_id: i64) -> String {
    format!("{task_id}@in-{inbox_id}")
}

/// Seed a minimal `tasks` row when `task_id` is unknown (satisfies the
/// `→ tasks(id)` FK for frames that may arrive before their `task_upsert`; the
/// later `task_upsert` patches the seeded row in place). Returns `false` only on
/// a DB error.
pub(crate) fn seed_task_if_missing(db: &Db, task_id: &str) -> bool {
    match db.get_task_row(task_id) {
        Ok(Some(_)) => true,
        Ok(None) => {
            let now_iso = to_iso(now());
            let task = TaskRow {
                id: task_id.to_owned(),
                name: None,
                kind: None,
                status: "active".to_owned(),
                engine: None,
                model: None,
                workdir: None,
                meta: None,
                created_at: now_iso.clone(),
                updated_at: now_iso,
            };
            match db.insert_task_row(&task) {
                Ok(()) => true,
                Err(err) => {
                    warn!(task = %task_id, error = %err, "failed to seed task row");
                    false
                }
            }
        }
        Err(err) => {
            warn!(task = %task_id, error = %err, "task lookup failed");
            false
        }
    }
}

/// Ensure the chat thread `tid` exists and is runnable for a `message` (host-v2
/// §M4 threading). A host-supplied `threadId` CONTINUES that thread; an absent
/// one arrives here as the [`minted_thread_id`] derived from the message's inbox
/// row, so the call is idempotent across replays. A resting
/// (`active`/`succeeded`/`failed`/`cancelled`) thread is re-set `pending` for the
/// new turn, KEEPING its `engine_session_id` so the engine conversation resumes;
/// an in-flight (or already `pending`) thread is left as-is — the message waits in
/// the inbox and [`repend_queued_messages`] re-pends the thread once it settles.
/// An unknown `tid` creates a fresh thread with no carried
/// `engine_session_id`, so the outbound `thread_result`/`thread_message` carry it
/// back for the host to record as `current_thread_id`. Returns `true` when this
/// call made the thread `pending` (re-pended or created).
pub(crate) fn ensure_chat_thread(
    db: &Mutex<Db>,
    task_id: &str,
    tid: &str,
    max_attempts: i64,
) -> bool {
    let guard = lock_db(db);
    match guard.get_thread(tid) {
        Ok(Some(existing)) => {
            if matches!(
                existing.status.as_str(),
                "active" | "succeeded" | "failed" | "cancelled"
            ) {
                let mut turn = existing;
                "pending".clone_into(&mut turn.status);
                turn.attempt = 0;
                turn.failure_reason = None;
                turn.started_at = None;
                turn.finished_at = None;
                turn.duration_ms = None;
                turn.result = None;
                turn.error = None;
                // A new turn snapshots its OWN message: clear the prior snapshot so
                // the executor re-resolves this turn's `message.text` at attempt 0
                // (D10). Retries within the turn then reuse the fresh snapshot.
                turn.prompt = String::new();
                match guard.update_thread(&turn) {
                    Ok(()) => true,
                    Err(err) => {
                        warn!(thread = %tid, error = %err, "failed to re-pend chat thread");
                        false
                    }
                }
            } else {
                debug!(thread = %tid, status = %existing.status, "chat message for an in-flight thread; queued");
                false
            }
        }
        Ok(None) => {
            // A chat message may arrive before its `task_upsert`.
            seed_task_if_missing(&guard, task_id);
            let row = ThreadRow {
                id: tid.to_owned(),
                task_id: task_id.to_owned(),
                cron_id: None,
                source: "chat".to_owned(),
                // No snapshot yet: the executor resolves and snapshots this turn's
                // inbox `message.text` into threads.prompt at attempt 0 (D10).
                prompt: String::new(),
                engine: DEFAULT_ENGINE.to_owned(),
                engine_session_id: None,
                status: "pending".to_owned(),
                failure_reason: None,
                attempt: 0,
                max_attempts,
                work_dir: None,
                started_at: None,
                finished_at: None,
                duration_ms: None,
                result: None,
                error: None,
                created_at: to_iso(now()),
            };
            match guard.insert_thread(&row) {
                Ok(()) => true,
                Err(err) => {
                    warn!(thread = %tid, error = %err, "failed to create chat thread");
                    false
                }
            }
        }
        Err(err) => {
            warn!(thread = %tid, error = %err, "chat thread lookup failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::attachment_source::DbAttachmentSource;
    use crate::attachments::AttachmentSource;
    use crate::db::{Db, TaskRow, ThreadRow};
    use crate::executor::{PromptSource, lock_db};
    use crate::protocol::frames::{AttachmentDescriptor, InboundFrame, MessageInData};

    use super::{InboxPromptSource, ensure_chat_thread, minted_thread_id, repend_queued_messages};

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

    fn inbound_descriptor(name: &str) -> AttachmentDescriptor {
        AttachmentDescriptor {
            id: format!("in-{name}"),
            name: name.into(),
            content_type: "text/plain".to_owned(),
            size: 4,
            sha256: "11".repeat(32),
            reference: format!("/agent/attachments/in-{name}"),
            direction: Some("inbound".to_owned()),
        }
    }

    /// Record a `message` frame carrying `attachments` for the thread, then resolve
    /// its prompt. The drainer consumes the inbox row (hiding it from a later inbox
    /// query) yet the executor's source still surfaces the descriptors — the
    /// consume-before-materialize ordering is handled via the durable
    /// `thread_attachments` snapshot (P1-10b), so a retry AND a fresh source over
    /// the same db (a daemon restart) resolve the identical set.
    #[test]
    fn message_attachments_survive_prompt_consumption_for_inbound_for() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let descriptors = vec![
            inbound_descriptor("spec.txt"),
            inbound_descriptor("data.json"),
        ];
        let frame = InboundFrame::Message {
            task_id: "t-1".to_owned(),
            thread_id: Some("th-1".to_owned()),
            data: MessageInData {
                text: "summarize the inputs".into(),
                attachments: Some(descriptors.clone()),
            },
            msg_id: Some(crate::protocol::test_delivery_id(7)),
        };
        lock_db(&db)
            .record_inbound_correlated(
                "message",
                &frame,
                Some("t-1"),
                Some("th-1"),
                Some(crate::protocol::test_delivery_id(7).as_str()),
            )
            .unwrap();
        let thread = chat_thread("th-1", "t-1");
        {
            // Seed the FK targets: the snapshot table references threads(id).
            let guard = lock_db(&db);
            guard
                .insert_task_row(&TaskRow {
                    id: "t-1".to_owned(),
                    name: None,
                    kind: None,
                    status: "active".to_owned(),
                    engine: None,
                    model: None,
                    workdir: None,
                    meta: None,
                    created_at: "2026-06-22T00:00:00Z".to_owned(),
                    updated_at: "2026-06-22T00:00:00Z".to_owned(),
                })
                .unwrap();
            guard.insert_thread(&thread).unwrap();
        }

        let prompts = InboxPromptSource {
            db: Arc::clone(&db),
        };

        // Resolving the prompt consumes the inbox message...
        assert_eq!(
            prompts.prompt_for(&thread).as_deref(),
            Some("summarize the inputs")
        );
        assert!(
            lock_db(&db)
                .list_inbox_by_type("message")
                .unwrap()
                .is_empty(),
            "message must be consumed (no replay/re-resolve)"
        );

        // ...but the executor's attachment source still resolves the descriptors,
        // on the first attempt AND on a retry (the snapshot is never popped).
        let source = DbAttachmentSource::new(Arc::clone(&db));
        assert_eq!(source.inbound_for(&thread), descriptors);
        assert_eq!(
            source.inbound_for(&thread),
            descriptors,
            "a retried run must see the same attachments"
        );

        // A daemon restart = a fresh source over the same db: identical set.
        let restarted = DbAttachmentSource::new(Arc::clone(&db));
        assert_eq!(restarted.inbound_for(&thread), descriptors);
    }

    /// A message with no attachments snapshots nothing → `inbound_for` is empty
    /// (the executor then materializes no inputs).
    #[test]
    fn message_without_attachments_yields_no_inbound() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let frame = InboundFrame::Message {
            task_id: "t-2".to_owned(),
            thread_id: Some("th-2".to_owned()),
            data: MessageInData {
                text: "no files attached".into(),
                attachments: None,
            },
            msg_id: None,
        };
        lock_db(&db)
            .record_inbound_correlated("message", &frame, Some("t-2"), Some("th-2"), None)
            .unwrap();

        let prompts = InboxPromptSource {
            db: Arc::clone(&db),
        };
        let thread = chat_thread("th-2", "t-2");
        assert!(prompts.prompt_for(&thread).is_some());

        let source = DbAttachmentSource::new(Arc::clone(&db));
        assert!(source.inbound_for(&thread).is_empty());
    }

    /// host-v2 §M4: a `message` with an ABSENT `threadId` starts a brand-new thread
    /// per MESSAGE — two distinct inbox rows derive two distinct thread ids, each
    /// fresh (no inherited `engine_session_id`). The old `"<task>@chat"` implicit
    /// continue is gone.
    #[test]
    fn absent_thread_id_mints_fresh_thread_per_inbox_row() {
        let db = Mutex::new(Db::open_in_memory().unwrap());
        ensure_chat_thread(&db, "t-1", &minted_thread_id("t-1", 1), 1);
        ensure_chat_thread(&db, "t-1", &minted_thread_id("t-1", 2), 1);

        let threads = lock_db(&db).list_pending_threads().unwrap();
        assert_eq!(
            threads.len(),
            2,
            "each absent-threadId message mints its own fresh thread"
        );
        assert_ne!(threads[0].id, threads[1].id, "minted ids are distinct");
        assert!(threads.iter().all(|t| t.task_id == "t-1"));
        assert!(
            threads.iter().all(|t| t.engine_session_id.is_none()),
            "fresh threads carry no engine session (nothing inherited to resume)"
        );
    }

    /// D1: a queued `message` whose task is closed/cancelled is NOT re-pended —
    /// it stays unprocessed in the inbox and its thread keeps resting — and the
    /// re-scan picks it up the moment the task is `active` again.
    #[test]
    fn closed_task_leaves_its_queued_message_in_the_inbox() {
        let db = Mutex::new(Db::open_in_memory().unwrap());
        let frame = InboundFrame::Message {
            task_id: "t-1".to_owned(),
            thread_id: Some("th-1".to_owned()),
            data: MessageInData {
                text: "queued while the turn ran".into(),
                attachments: None,
            },
            msg_id: Some(crate::protocol::test_delivery_id(1)),
        };
        let mut resting = chat_thread("th-1", "t-1");
        "succeeded".clone_into(&mut resting.status);
        {
            let guard = lock_db(&db);
            guard
                .insert_task_row(&TaskRow {
                    id: "t-1".to_owned(),
                    name: None,
                    kind: None,
                    status: "closed".to_owned(),
                    engine: None,
                    model: None,
                    workdir: None,
                    meta: None,
                    created_at: "2026-06-22T00:00:00Z".to_owned(),
                    updated_at: "2026-06-22T00:00:00Z".to_owned(),
                })
                .unwrap();
            guard.insert_thread(&resting).unwrap();
            guard
                .record_inbound_correlated(
                    "message",
                    &frame,
                    Some("t-1"),
                    Some("th-1"),
                    Some(crate::protocol::test_delivery_id(1).as_str()),
                )
                .unwrap();
        }

        assert_eq!(
            repend_queued_messages(&db, 1),
            0,
            "a closed task's queued message is not re-pended"
        );
        assert_eq!(
            lock_db(&db).get_thread("th-1").unwrap().unwrap().status,
            "succeeded",
            "the resting thread is left alone"
        );
        assert_eq!(
            lock_db(&db).list_inbox_by_type("message").unwrap().len(),
            1,
            "the message stays unprocessed in the inbox"
        );

        {
            let guard = lock_db(&db);
            let mut task = guard.get_task_row("t-1").unwrap().unwrap();
            "active".clone_into(&mut task.status);
            guard.update_task_row(&task).unwrap();
        }
        assert_eq!(
            repend_queued_messages(&db, 1),
            1,
            "re-activation re-pends the parked message's thread"
        );
        assert_eq!(
            lock_db(&db).get_thread("th-1").unwrap().unwrap().status,
            "pending"
        );
    }

    /// Regression: replaying an unprocessed absent-`threadId` message (the
    /// reconnect replay re-delivers the SAME inbox row) derives the SAME thread id
    /// and must NOT mint a second thread — N reconnects used to race N+1 threads
    /// for one inbox row.
    #[test]
    fn replayed_absent_thread_id_message_does_not_mint_second_thread() {
        let db = Mutex::new(Db::open_in_memory().unwrap());
        let tid = minted_thread_id("t-1", 5);

        assert!(
            ensure_chat_thread(&db, "t-1", &tid, 1),
            "original delivery mints"
        );
        assert!(
            !ensure_chat_thread(&db, "t-1", &tid, 1),
            "the replay finds the minted thread and is a no-op"
        );

        let threads = lock_db(&db).list_pending_threads().unwrap();
        assert_eq!(threads.len(), 1, "replay must not mint a second thread");
        assert_eq!(threads[0].id, tid);
    }

    /// host-v2 §M4: a `message` with a PRESENT `threadId` continues that same thread —
    /// a resting thread is re-pended for the new turn while its `engine_session_id` is
    /// PRESERVED (resumed, not minted anew).
    #[test]
    fn present_thread_id_continues_same_thread() {
        let db = Mutex::new(Db::open_in_memory().unwrap());
        {
            let guard = lock_db(&db);
            // Seed the task (FK target) and a resting thread holding a resume handle.
            guard
                .insert_task_row(&TaskRow {
                    id: "t-1".to_owned(),
                    name: None,
                    kind: None,
                    status: "active".to_owned(),
                    engine: None,
                    model: None,
                    workdir: None,
                    meta: None,
                    created_at: "2026-06-22T00:00:00Z".to_owned(),
                    updated_at: "2026-06-22T00:00:00Z".to_owned(),
                })
                .unwrap();
            let mut existing = chat_thread("th-x", "t-1");
            existing.engine_session_id = Some("sess-1".to_owned());
            "succeeded".clone_into(&mut existing.status);
            guard.insert_thread(&existing).unwrap();
        }

        ensure_chat_thread(&db, "t-1", "th-x", 1);

        let row = lock_db(&db)
            .get_thread("th-x")
            .unwrap()
            .expect("the present thread is reused, not minted anew");
        assert_eq!(row.id, "th-x", "same thread id reused");
        assert_eq!(
            row.status, "pending",
            "resting thread re-pended for the new turn"
        );
        assert_eq!(
            row.engine_session_id.as_deref(),
            Some("sess-1"),
            "engine session preserved → conversation resumes"
        );
        assert_eq!(
            lock_db(&db).list_pending_threads().unwrap().len(),
            1,
            "no extra thread minted on a present threadId"
        );
    }

    /// Regression: two quick messages to the SAME thread — the first runs
    /// immediately; the second (queued while the thread was in flight) must
    /// actually EXECUTE once the first run finishes, driven by the post-terminal
    /// inbox re-scan. Asserts the second EXECUTION (the engine receives the
    /// second prompt), not just a queued row.
    #[allow(
        clippy::too_many_lines,
        reason = "the in-test engine stub is the bulk; splitting it would obscure the scenario"
    )]
    #[tokio::test]
    async fn queued_message_executes_after_the_run_finishes() {
        use async_trait::async_trait;
        use futures_util::stream::{self, BoxStream};

        use crate::engine::{
            Engine, EngineError, EngineEvent, RunOutcome, RunStatus, Session, SessionCfg,
        };
        use crate::executor::{ThreadExecutor, WatchdogCfg};

        /// Records every prompt it is started with, succeeding each run.
        struct RecordingEngine {
            prompts: Arc<Mutex<Vec<String>>>,
        }
        struct OkSession;

        #[async_trait]
        impl Engine for RecordingEngine {
            fn name(&self) -> &'static str {
                "recording"
            }
            async fn start_session(
                &self,
                cfg: SessionCfg,
            ) -> Result<Box<dyn Session>, EngineError> {
                self.prompts
                    .lock()
                    .unwrap()
                    .push(cfg.initial_prompt.unwrap_or_default());
                Ok(Box::new(OkSession))
            }
        }

        #[async_trait]
        impl Session for OkSession {
            async fn interrupt(&self) -> Result<(), EngineError> {
                Ok(())
            }
            fn events(&self) -> BoxStream<'_, EngineEvent> {
                Box::pin(stream::iter(vec![EngineEvent::Result(RunOutcome {
                    status: RunStatus::Success,
                    result: Some("ok".to_owned()),
                    session_id: Some("sess".to_owned()),
                    error: None,
                    error_kind: None,
                })]))
            }
        }

        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));

        // Message 1 arrives: inbox row + pending thread th-1.
        let m1 = InboundFrame::Message {
            task_id: "t-1".to_owned(),
            thread_id: Some("th-1".to_owned()),
            data: MessageInData {
                text: "first".into(),
                attachments: None,
            },
            msg_id: Some(crate::protocol::test_delivery_id(1)),
        };
        lock_db(&db)
            .record_inbound_correlated(
                "message",
                &m1,
                Some("t-1"),
                Some("th-1"),
                Some(crate::protocol::test_delivery_id(1).as_str()),
            )
            .unwrap();
        assert!(ensure_chat_thread(&db, "t-1", "th-1", 1));

        // Message 2 arrives while th-1 is in flight: only queued (the original
        // Defect: nothing ever re-checked the inbox after the run).
        let m2 = InboundFrame::Message {
            task_id: "t-1".to_owned(),
            thread_id: Some("th-1".to_owned()),
            data: MessageInData {
                text: "second".into(),
                attachments: None,
            },
            msg_id: Some(crate::protocol::test_delivery_id(2)),
        };
        lock_db(&db)
            .record_inbound_correlated(
                "message",
                &m2,
                Some("t-1"),
                Some("th-1"),
                Some(crate::protocol::test_delivery_id(2).as_str()),
            )
            .unwrap();
        assert!(
            !ensure_chat_thread(&db, "t-1", "th-1", 1),
            "the second quick message is queued, not a second pending turn"
        );

        let prompts_seen = Arc::new(Mutex::new(Vec::new()));
        let engine: Arc<dyn Engine> = Arc::new(RecordingEngine {
            prompts: Arc::clone(&prompts_seen),
        });
        let dir = tempfile::tempdir().unwrap();
        let executor = ThreadExecutor::new(
            engine,
            Arc::clone(&db),
            dir.path().to_path_buf(),
            WatchdogCfg {
                inactivity_timeout: None,
                ..WatchdogCfg::default()
            },
        );
        let source = InboxPromptSource {
            db: Arc::clone(&db),
        };

        // First drain: runs turn 1 only; the second message sits queued.
        executor.drain_pending(&source).await;
        assert_eq!(*prompts_seen.lock().unwrap(), vec!["first".to_owned()]);
        assert_eq!(
            lock_db(&db).get_thread("th-1").unwrap().unwrap().status,
            "active",
            "chat thread rests between turns"
        );

        // The post-terminal re-scan re-pends the thread for the queued message...
        assert_eq!(repend_queued_messages(&db, 1), 1);
        // ...and the next drain EXECUTES it (this is the fix).
        executor.drain_pending(&source).await;
        assert_eq!(
            *prompts_seen.lock().unwrap(),
            vec!["first".to_owned(), "second".to_owned()],
            "the queued second message must actually execute"
        );
        assert!(
            lock_db(&db)
                .list_inbox_by_type("message")
                .unwrap()
                .is_empty(),
            "both messages consumed"
        );
        assert_eq!(
            repend_queued_messages(&db, 1),
            0,
            "nothing left to re-pend — the loop terminates"
        );
    }
}
