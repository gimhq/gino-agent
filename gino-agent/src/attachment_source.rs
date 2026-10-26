//! The runner's [`AttachmentSource`] (agent-architecture §9; audit
//! P1-10b).
//!
//! Inbound attachment **descriptors** ride the inbox `message` frame
//! ([`MessageInData::attachments`](crate::protocol::frames::MessageInData)), not the
//! `threads` row, so the executor materializes them through a resolver
//! ([`AttachmentSource`]) that the runner supplies.
//!
//! ## Why a durable snapshot and not a fresh inbox query
//!
//! The pending-thread drainer resolves a thread's prompt
//! ([`InboxPromptSource`](crate::runner)) and **consumes** its inbox `message`
//! (marks it processed, so it neither replays nor re-resolves) *before* the
//! executor materializes inputs ([`ThreadExecutor::run_thread`] calls
//! `inbound_for` only after the prompt is resolved). A fresh
//! `list_inbox_by_type("message")` here would therefore miss it — the only inbox
//! query returns *unprocessed* rows. The drainer therefore snapshots the
//! descriptors from the very `MessageInData` it already parsed into the
//! `thread_attachments` table (keyed by thread id, written BEFORE the message is
//! consumed), and [`DbAttachmentSource::inbound_for`] reads them back — without
//! popping, so a retried, re-pended or crash-recovered thread resolves the
//! identical set on every attempt. The previous in-memory one-shot stash lost
//! the descriptors on retry and on restart, silently running the thread with
//! zero attachments (P1-10b).
//!
//! [`ThreadExecutor::run_thread`]: crate::executor::ThreadExecutor

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tracing::warn;

use crate::attachments::AttachmentSource;
use crate::db::{Db, ThreadRow};
use crate::protocol::frames::AttachmentDescriptor;

/// The runner's [`AttachmentSource`]: reads the inbound descriptors the prompt
/// drainer snapshotted into `thread_attachments` for a thread. Engine-agnostic
/// and non-fatal for the common case — a thread that never carried attachments
/// (cron threads, attachment-free messages) resolves to an empty list, and the
/// executor materializes nothing.
#[derive(Clone, Debug)]
pub(crate) struct DbAttachmentSource {
    db: Arc<Mutex<Db>>,
}

impl DbAttachmentSource {
    /// Build a source reading the `thread_attachments` snapshots the prompt
    /// drainer writes.
    pub(crate) fn new(db: Arc<Mutex<Db>>) -> Self {
        Self { db }
    }

    /// Poison-tolerant DB lock (Lock 6): the critical section is one SELECT that
    /// never spans an `.await`, so recovering the guard cannot observe torn state.
    fn lock(&self) -> MutexGuard<'_, Db> {
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AttachmentSource for DbAttachmentSource {
    fn inbound_for(&self, thread: &ThreadRow) -> Vec<AttachmentDescriptor> {
        let json = match self.lock().get_thread_attachments(&thread.id) {
            Ok(None) => return Vec::new(),
            Ok(Some(json)) => json,
            Err(err) => {
                warn!(thread = %thread.id, error = %err, "failed to read the thread's attachment snapshot");
                return unreadable_sentinel();
            }
        };
        match serde_json::from_str(&json) {
            Ok(descriptors) => descriptors,
            Err(err) => {
                warn!(thread = %thread.id, error = %err, "thread attachment snapshot did not parse");
                unreadable_sentinel()
            }
        }
    }
}

/// DECISION (P1-10b): the executor seam ([`AttachmentSource::inbound_for`])
/// returns a bare `Vec`, so a snapshot-read failure cannot surface as an error
/// through it. Returning empty would run the thread WITHOUT its inputs and
/// report success — the exact silent drop this module exists to close. Instead
/// return one descriptor with a negative declared size: materialization rejects
/// it up front ([`InvalidDeclaredSize`]) with zero byte transfer, failing the
/// run loudly.
///
/// [`InvalidDeclaredSize`]: crate::attachments::AttachmentError::InvalidDeclaredSize
fn unreadable_sentinel() -> Vec<AttachmentDescriptor> {
    vec![AttachmentDescriptor {
        id: String::new(),
        name: "thread-attachments-unreadable".into(),
        content_type: String::new(),
        size: -1,
        sha256: String::new(),
        reference: String::new(),
        direction: None,
    }]
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::DbAttachmentSource;
    use crate::attachments::AttachmentSource;
    use crate::db::{Db, TaskRow, ThreadRow};
    use crate::protocol::frames::AttachmentDescriptor;

    /// A bare `pending` thread row carrying just the id `inbound_for` keys on.
    fn thread(id: &str) -> ThreadRow {
        ThreadRow {
            id: id.to_owned(),
            task_id: "t-1".to_owned(),
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

    fn descriptor(name: &str) -> AttachmentDescriptor {
        AttachmentDescriptor {
            id: format!("att-{name}"),
            name: name.into(),
            content_type: "text/plain".to_owned(),
            size: 4,
            sha256: "00".repeat(32),
            reference: format!("/agent/attachments/{name}"),
            direction: Some("inbound".to_owned()),
        }
    }

    fn db_with_thread(id: &str) -> Arc<Mutex<Db>> {
        let db = Db::open_in_memory().unwrap();
        db.insert_task_row(&TaskRow {
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
        db.insert_thread(&thread(id)).unwrap();
        Arc::new(Mutex::new(db))
    }

    #[test]
    fn inbound_for_reads_the_persisted_snapshot() {
        let db = db_with_thread("th-1");
        let descriptors = vec![descriptor("a.txt"), descriptor("b.json")];
        db.lock()
            .unwrap()
            .set_thread_attachments("th-1", &descriptors)
            .unwrap();

        let source = DbAttachmentSource::new(db);
        assert_eq!(source.inbound_for(&thread("th-1")), descriptors);
    }

    #[test]
    fn inbound_for_is_empty_without_a_snapshot() {
        let source = DbAttachmentSource::new(db_with_thread("th-unknown"));
        assert!(source.inbound_for(&thread("th-unknown")).is_empty());
    }

    /// P1-10b regression: a retried run (second `inbound_for` on the same source)
    /// and a restarted daemon (a FRESH source over the same db) both resolve the
    /// identical descriptor set — the snapshot is read, never popped.
    #[test]
    fn snapshot_survives_retry_and_a_fresh_source_over_the_same_db() {
        let db = db_with_thread("th-3");
        let descriptors = vec![descriptor("once.txt")];
        db.lock()
            .unwrap()
            .set_thread_attachments("th-3", &descriptors)
            .unwrap();

        let source = DbAttachmentSource::new(Arc::clone(&db));
        assert_eq!(source.inbound_for(&thread("th-3")), descriptors);
        // A retry on the same source sees the same set (the old stash was
        // one-shot and returned empty here).
        assert_eq!(source.inbound_for(&thread("th-3")), descriptors);

        // A daemon restart = a fresh source instance over the same db.
        let restarted = DbAttachmentSource::new(db);
        assert_eq!(restarted.inbound_for(&thread("th-3")), descriptors);
    }

    /// A snapshot that exists but cannot be decoded must NOT resolve to "no
    /// attachments" (that would run — and succeed — without the inputs). The
    /// sentinel's negative declared size fails materialization up front.
    #[test]
    fn unreadable_snapshot_yields_a_run_failing_sentinel_not_empty() {
        let db = db_with_thread("th-4");
        db.lock()
            .unwrap()
            .set_thread_attachments("th-4", &"not-an-array")
            .unwrap();

        let source = DbAttachmentSource::new(db);
        let got = source.inbound_for(&thread("th-4"));
        assert_eq!(got.len(), 1);
        assert!(
            got[0].size < 0,
            "the sentinel must carry a negative declared size so materialization rejects it"
        );
    }
}
