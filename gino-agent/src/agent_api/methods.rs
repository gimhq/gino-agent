//! Method handlers. Each runs synchronously on a blocking thread.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Notify;
use uuid::Uuid;

use super::protocol::{
    ApiError, CronInfo, CronList, CronResult, ErrorCode, SystemInfo, TaskList, TaskShow,
    TaskSummary, ThreadActionResult, ThreadCounts, ThreadDetail, ThreadList, ThreadShow,
    ThreadSummary,
};
use super::scope::Scope;
use crate::db::{CronRow, Db, DbError, TaskRow, ThreadRow};
use crate::e2ee::{E2ee, EncryptionFailure, host_action_allowed};
use crate::executor::{Sealing, TranscriptEvent, append_thread_message};
use crate::protocol::frames::{MessageKind, Sealable};
use crate::scheduler::{CronTally, cron_state_data, next_run_at_creation, now, to_iso};

/// Daemon handles and config values the handlers read.
#[derive(Debug)]
pub(crate) struct ApiContext {
    pub(crate) db: Arc<Mutex<Db>>,
    /// Wakes the scheduler after a trigger change.
    pub(crate) nudge: Arc<Notify>,
    /// Wakes the transport to flush the outbox.
    pub(crate) flush: Arc<Notify>,
    pub(crate) agent_name: Option<String>,
    pub(crate) host_url: Option<String>,
    pub(crate) workspace_dir: PathBuf,
    pub(crate) db_path: PathBuf,
    /// Seals what the API stores for an encrypted task; `None` without e2ee.
    pub(crate) e2ee: Option<Arc<E2ee>>,
}

impl ApiContext {
    fn db(&self) -> MutexGuard<'_, Db> {
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Run `method` for a caller holding `scope`. `params` is a JSON object.
pub(crate) fn dispatch(
    ctx: &ApiContext,
    scope: &Scope,
    method: &str,
    params: &Value,
) -> Result<Value, ApiError> {
    match method {
        "system.info" => to_value(&system_info(ctx, scope)?),
        "task.list" => {
            parse::<NoParams>(params)?;
            to_value(&task_list(ctx, scope)?)
        }
        "task.show" => to_value(&task_show(ctx, scope, &parse::<IdParams>(params)?.id)?),
        "thread.list" => to_value(&thread_list(ctx, scope, parse(params)?)?),
        "thread.show" => to_value(&thread_show(ctx, scope, &parse::<IdParams>(params)?.id)?),
        "thread.action" => to_value(&thread_action(ctx, scope, parse(params)?)?),
        "cron.create" => to_value(&cron_create(ctx, scope, parse(params)?)?),
        "cron.list" => to_value(&cron_list(ctx, scope, parse(params)?)?),
        "cron.delete" => to_value(&cron_set_status(
            ctx,
            scope,
            &parse::<IdParams>(params)?.id,
            "cancelled",
            true,
        )?),
        "cron.pause" => to_value(&cron_set_status(
            ctx,
            scope,
            &parse::<IdParams>(params)?.id,
            "paused",
            false,
        )?),
        "cron.resume" => to_value(&cron_resume(ctx, scope, &parse::<IdParams>(params)?.id)?),
        _ => Err(ApiError::invalid_params(format!(
            "unknown method: {method}"
        ))),
    }
}

fn to_value(result: &impl Serialize) -> Result<Value, ApiError> {
    serde_json::to_value(result).map_err(|err| ApiError::internal(&err))
}

fn parse<T: DeserializeOwned>(params: &Value) -> Result<T, ApiError> {
    T::deserialize(params).map_err(|err| ApiError::invalid_params(format!("invalid params: {err}")))
}

/// A database failure: the cause is logged, the caller sees a generic error.
#[allow(clippy::needless_pass_by_value)] // used as a `map_err` adapter
fn db_error(err: DbError) -> ApiError {
    tracing::warn!(error = %err, "agent API database access failed");
    ApiError::new(ErrorCode::Internal, "internal error")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskFilterParams {
    #[serde(default)]
    task_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CronCreateParams {
    #[serde(rename = "type")]
    schedule_type: String,
    value: String,
    prompt: String,
    #[serde(default = "default_continuity")]
    continuity: String,
    #[serde(default)]
    task_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadActionParams {
    method: String,
    #[serde(default)]
    params: Option<serde_json::Map<String, Value>>,
}

fn default_continuity() -> String {
    "isolated".to_owned()
}

/// Whether `scope` covers `task_id`.
fn in_scope(scope: &Scope, task_id: &str) -> bool {
    match scope {
        Scope::Run(run) => run.task_id == task_id,
        Scope::Operator => true,
    }
}

/// `forbidden` unless `scope` covers an explicitly named `task_id`.
fn authorize(scope: &Scope, task_id: &str) -> Result<(), ApiError> {
    if in_scope(scope, task_id) {
        Ok(())
    } else {
        Err(ApiError::new(
            ErrorCode::Forbidden,
            "this run may only access its own task",
        ))
    }
}

/// The looked-up `row` if it exists and `scope` covers its task; otherwise
/// the `missing` error, so a row outside the scope reads as nonexistent.
fn scoped_row<T>(
    scope: &Scope,
    row: Option<T>,
    task_of: impl Fn(&T) -> &str,
    missing: impl FnOnce() -> ApiError,
) -> Result<T, ApiError> {
    row.filter(|r| in_scope(scope, task_of(r)))
        .ok_or_else(missing)
}

/// The task a request targets: a run defaults to (and is limited to) its own;
/// the operator must name one.
fn target_task(scope: &Scope, task_id: Option<String>) -> Result<String, ApiError> {
    match (scope, task_id) {
        (_, Some(id)) => {
            authorize(scope, &id)?;
            Ok(id)
        }
        (Scope::Run(run), None) => Ok(run.task_id.clone()),
        (Scope::Operator, None) => Err(ApiError::invalid_params("task_id is required")),
    }
}

fn task_summary(row: &TaskRow) -> TaskSummary {
    TaskSummary {
        id: row.id.clone(),
        name: row.name.clone(),
        kind: row.kind.clone(),
        status: row.status.clone(),
        created_at: row.created_at.clone(),
    }
}

fn thread_summary(row: &ThreadRow) -> ThreadSummary {
    ThreadSummary {
        id: row.id.clone(),
        task_id: row.task_id.clone(),
        status: row.status.clone(),
        source: row.source.clone(),
        attempt: row.attempt,
        max_attempts: row.max_attempts,
        engine_session_id: row.engine_session_id.clone(),
    }
}

fn cron_info(row: &CronRow) -> CronInfo {
    CronInfo {
        id: row.id.clone(),
        task_id: row.task_id.clone(),
        kind: row.kind.clone(),
        status: row.status.clone(),
        schedule_type: row.schedule_type.clone(),
        schedule_value: row.schedule_value.clone(),
        next_run: row.next_run.clone(),
        last_fired_at: row.last_fired_at.clone(),
        continuity: row.continuity.clone(),
        run_count: row.run_count,
        prompt: row.prompt.clone(),
        created_at: row.created_at.clone(),
        updated_at: row.updated_at.clone(),
    }
}

fn no_such_task(id: &str) -> ApiError {
    ApiError::new(ErrorCode::NotFound, format!("no such task: {id}"))
}

fn task_list(ctx: &ApiContext, scope: &Scope) -> Result<TaskList, ApiError> {
    let tasks = ctx.db().list_tasks().map_err(db_error)?;
    Ok(TaskList {
        tasks: tasks
            .iter()
            .filter(|t| in_scope(scope, &t.id))
            .map(task_summary)
            .collect(),
    })
}

fn task_show(ctx: &ApiContext, scope: &Scope, id: &str) -> Result<TaskShow, ApiError> {
    let db = ctx.db();
    let task = scoped_row(
        scope,
        db.get_task_row(id).map_err(db_error)?,
        |t| &t.id,
        || no_such_task(id),
    )?;
    let threads = db.list_threads_by_task(id).map_err(db_error)?;
    let crons = db.list_crons_by_task(id).map_err(db_error)?;
    drop(db);
    Ok(TaskShow {
        task: task_summary(&task),
        threads: threads.iter().map(thread_summary).collect(),
        crons: crons.iter().map(|row| shown_cron(ctx, row)).collect(),
    })
}

fn thread_list(
    ctx: &ApiContext,
    scope: &Scope,
    params: TaskFilterParams,
) -> Result<ThreadList, ApiError> {
    let task_id = target_task(scope, params.task_id)?;
    let threads = ctx.db().list_threads_by_task(&task_id).map_err(db_error)?;
    Ok(ThreadList {
        threads: threads.iter().map(thread_summary).collect(),
    })
}

fn thread_show(ctx: &ApiContext, scope: &Scope, id: &str) -> Result<ThreadShow, ApiError> {
    let thread = scoped_row(
        scope,
        ctx.db().get_thread(id).map_err(db_error)?,
        |t| &t.task_id,
        || ApiError::new(ErrorCode::NotFound, format!("no such thread: {id}")),
    )?;
    let summary = thread_summary(&thread);
    let (prompt, result, error) = if task_encrypted(ctx, &thread.task_id) {
        opened_thread(ctx, &thread)
    } else {
        (thread.prompt, thread.result, thread.error)
    };
    Ok(ThreadShow {
        thread: ThreadDetail {
            summary,
            cron_id: thread.cron_id,
            failure_reason: thread.failure_reason,
            engine: thread.engine,
            duration_ms: thread.duration_ms,
            prompt,
            result,
            error,
        },
    })
}

/// Whether `task_id` is end-to-end encrypted; a DB failure reads as
/// encrypted.
fn task_encrypted(ctx: &ApiContext, task_id: &str) -> bool {
    match &ctx.e2ee {
        Some(e2ee) => e2ee.is_encrypted(task_id),
        None => !matches!(ctx.db().get_task_e2ee(task_id), Ok(None)),
    }
}

/// Open the mapped fields of an encrypted task's stored `frame` for display
/// (the runner's trust boundary) and read the texts at `pointers`. When the
/// frame does not open, every present text reads `[sealed: <code>]`.
fn opened_for_display(
    ctx: &ApiContext,
    task_id: &str,
    frame_type: &str,
    mut frame: Value,
    pointers: &[&str],
) -> Vec<Option<String>> {
    let opened = match (&ctx.e2ee, tokio::runtime::Handle::try_current()) {
        (Some(e2ee), Ok(runtime)) => {
            runtime.block_on(e2ee.open_frame(task_id, frame_type, &mut frame))
        }
        (None, _) => Err(EncryptionFailure::from(gino_e2ee::Error::NotMember)),
        (_, Err(_)) => Err(EncryptionFailure::from(gino_e2ee::Error::Malformed)),
    };
    let text = |pointer: &str| frame.pointer(pointer).filter(|value| !value.is_null());
    pointers
        .iter()
        .map(|pointer| match &opened {
            Ok(()) => text(pointer).and_then(Value::as_str).map(str::to_owned),
            Err(failure) => text(pointer).map(|_| format!("[sealed: {}]", failure.code())),
        })
        .collect()
}

/// An encrypted task's thread prompt, result and error, opened for display.
/// The prompt is sealed as its cron's `cron_upsert.data.prompt` or its
/// `message.data.text`; the result and error as `thread_result` fields bound
/// to the thread's last `thread_result` `outboxId`.
fn opened_thread(ctx: &ApiContext, thread: &ThreadRow) -> (String, Option<String>, Option<String>) {
    let sealed = Sealable::stored_value;
    let prompt_frame = if thread.source == "cron" {
        (
            "cron_upsert",
            json!({"taskId": thread.task_id, "cronId": thread.cron_id, "data": {"prompt": sealed(&thread.prompt)}}),
            "/data/prompt",
        )
    } else {
        (
            "message",
            json!({"taskId": thread.task_id, "threadId": thread.id, "data": {"text": sealed(&thread.prompt)}}),
            "/data/text",
        )
    };
    let (frame_type, frame, pointer) = prompt_frame;
    let prompt = if thread.prompt.is_empty() {
        String::new()
    } else {
        opened_for_display(ctx, &thread.task_id, frame_type, frame, &[pointer])
            .pop()
            .flatten()
            .unwrap_or_default()
    };
    if thread.result.is_none() && thread.error.is_none() {
        return (prompt, None, None);
    }
    let outbox_id = ctx
        .db()
        .get_thread_result_outbox_id(&thread.id)
        .ok()
        .flatten();
    let mut data = serde_json::Map::new();
    for (field, text) in [("result", &thread.result), ("error", &thread.error)] {
        if let Some(text) = text {
            data.insert(field.to_owned(), sealed(text));
        }
    }
    let frame = json!({"taskId": thread.task_id, "threadId": thread.id, "outboxId": outbox_id, "data": data});
    let mut opened = opened_for_display(
        ctx,
        &thread.task_id,
        "thread_result",
        frame,
        &["/data/result", "/data/error"],
    );
    let error = opened.pop().flatten();
    let result = opened.pop().flatten();
    (prompt, result, error)
}

/// A cron as shown by the API; an encrypted task's prompt opened for
/// display.
fn shown_cron(ctx: &ApiContext, row: &CronRow) -> CronInfo {
    let mut info = cron_info(row);
    if task_encrypted(ctx, &row.task_id) {
        let frame = json!({"taskId": row.task_id, "cronId": row.id, "data": {"prompt": Sealable::stored_value(&row.prompt)}});
        info.prompt =
            opened_for_display(ctx, &row.task_id, "cron_upsert", frame, &["/data/prompt"])
                .pop()
                .flatten()
                .unwrap_or_default();
    }
    info
}

/// Append a `host_action` transcript event to the caller's own thread and
/// wake the outbox flush. Run scope only; the host is not awaited.
fn thread_action(
    ctx: &ApiContext,
    scope: &Scope,
    params: ThreadActionParams,
) -> Result<ThreadActionResult, ApiError> {
    let Scope::Run(run) = scope else {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "thread.action requires a run token",
        ));
    };
    if params.method.is_empty() {
        return Err(ApiError::invalid_params("method must not be empty"));
    }
    // The method stays cleartext on an encrypted task, so only a method its
    // profile declares may be sent; the task row decides, not group state.
    let declared = ctx
        .db()
        .get_task_e2ee(&run.task_id)
        .map_err(db_error)?
        .is_none_or(|task| host_action_allowed(&task.profile_id, &params.method));
    if !declared {
        return Err(ApiError::new(
            ErrorCode::Forbidden,
            "host actions are not available on this end-to-end encrypted task: \
             the method is not declared by its e2ee profile",
        ));
    }
    let input = serde_json::json!({
        "method": params.method,
        "params": params.params.unwrap_or_default(),
    });
    let event = TranscriptEvent {
        input: Some(input),
        ..TranscriptEvent::new(MessageKind::HostAction)
    };
    // An encrypted task's params are sealed here, in the daemon; one that
    // cannot be sealed appends nothing and consumes no `seq`.
    let unavailable = |reason: &str| {
        ApiError::new(
            ErrorCode::Unavailable,
            format!("the task is end-to-end encrypted and the action cannot be sealed: {reason}"),
        )
    };
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| unavailable("no async runtime"))?;
    let sealing = runtime
        .block_on(Sealing::for_task(
            ctx.e2ee.as_deref(),
            &ctx.db,
            &run.task_id,
        ))
        .map_err(|failure| unavailable(failure.code()))?;
    let seq = ctx
        .db()
        .immediate_transaction(|db| {
            append_thread_message(db, &run.task_id, &run.thread_id, event, &sealing)
        })
        .map_err(db_error)?
        .map_err(|failure| unavailable(failure.code()))?;
    ctx.flush.notify_one();
    Ok(ThreadActionResult { seq })
}

fn cron_list(
    ctx: &ApiContext,
    scope: &Scope,
    params: TaskFilterParams,
) -> Result<CronList, ApiError> {
    let db = ctx.db();
    let (crons, scoped) = match (scope, params.task_id) {
        (Scope::Operator, None) => (db.list_active_crons().map_err(db_error)?, false),
        (_, task_id) => {
            let task_id = target_task(scope, task_id)?;
            (db.list_crons_by_task(&task_id).map_err(db_error)?, true)
        }
    };
    drop(db);
    Ok(CronList {
        crons: crons.iter().map(|row| shown_cron(ctx, row)).collect(),
        scoped,
    })
}

fn cron_create(
    ctx: &ApiContext,
    scope: &Scope,
    params: CronCreateParams,
) -> Result<CronResult, ApiError> {
    let task_id = target_task(scope, params.task_id)?;
    let continuity = match params.continuity.as_str() {
        "isolated" | "shared" => params.continuity,
        other => {
            return Err(ApiError::invalid_params(format!(
                "continuity must be 'isolated' or 'shared' (got '{other}')"
            )));
        }
    };
    // Seed the first fire (and validate the schedule) the same way the host path does.
    let next_run =
        next_run_at_creation(&params.schedule_type, &params.value, now()).map_err(|err| {
            ApiError::invalid_params(format!(
                "invalid schedule: type={} value={}: {err}",
                params.schedule_type, params.value
            ))
        })?;
    let prompt = stored_cron_prompt(ctx, &task_id, params.prompt)?;
    let db = ctx.db();
    if db.get_task_row(&task_id).map_err(db_error)?.is_none() {
        return Err(no_such_task(&task_id));
    }
    let now_iso = to_iso(now());
    let row = CronRow {
        id: format!("cron-{}", Uuid::new_v4()),
        task_id,
        kind: "schedule".to_owned(),
        prompt,
        schedule_type: Some(params.schedule_type),
        schedule_value: Some(params.value),
        next_run,
        last_fired_at: None,
        continuity,
        run_count: 0,
        status: "active".to_owned(),
        created_at: now_iso.clone(),
        updated_at: now_iso,
    };
    db.insert_cron(&row).map_err(db_error)?;
    cron_changed(ctx, &db, &row);
    drop(db);
    Ok(CronResult {
        cron: shown_cron(ctx, &row),
    })
}

/// A new cron's prompt as stored: on an encrypted task sealed as
/// `cron_upsert.data.prompt` under the current epoch, else as given. A prompt
/// that cannot be sealed is an error; it is never stored in plaintext.
fn stored_cron_prompt(ctx: &ApiContext, task_id: &str, prompt: String) -> Result<String, ApiError> {
    if !task_encrypted(ctx, task_id) {
        return Ok(prompt);
    }
    let unavailable = |reason: &str| {
        ApiError::new(
            ErrorCode::Unavailable,
            format!("the task is end-to-end encrypted and its prompt cannot be sealed: {reason}"),
        )
    };
    let e2ee = ctx
        .e2ee
        .as_ref()
        .ok_or_else(|| unavailable("e2ee is not available"))?;
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| unavailable("no async runtime"))?;
    let mut frame = json!({ "taskId": task_id, "data": { "prompt": prompt } });
    runtime
        .block_on(e2ee.seal_frame(task_id, "cron_upsert", &mut frame))
        .map_err(|failure| unavailable(failure.code()))?;
    let sealed = frame
        .pointer_mut("/data/prompt")
        .map(Value::take)
        .and_then(|value| serde_json::from_value::<Sealable<String>>(value).ok())
        .filter(|value| value.as_sealed().is_some())
        .ok_or_else(|| unavailable("the sealed prompt is malformed"))?;
    Ok(sealed.to_stored())
}

/// The cron `id`, if it exists and `scope` covers its task.
fn scoped_cron(db: &Db, scope: &Scope, id: &str) -> Result<CronRow, ApiError> {
    scoped_row(
        scope,
        db.get_cron(id).map_err(db_error)?,
        |c| &c.task_id,
        || ApiError::new(ErrorCode::NotFound, format!("no such cron: {id}")),
    )
}

fn cron_set_status(
    ctx: &ApiContext,
    scope: &Scope,
    id: &str,
    status: &str,
    clear_next: bool,
) -> Result<CronResult, ApiError> {
    let db = ctx.db();
    let mut cron = scoped_cron(&db, scope, id)?;
    status.clone_into(&mut cron.status);
    if clear_next {
        cron.next_run = None;
    }
    cron.updated_at = to_iso(now());
    db.update_cron(&cron).map_err(db_error)?;
    cron_changed(ctx, &db, &cron);
    drop(db);
    Ok(CronResult {
        cron: shown_cron(ctx, &cron),
    })
}

fn cron_resume(ctx: &ApiContext, scope: &Scope, id: &str) -> Result<CronResult, ApiError> {
    let db = ctx.db();
    let mut cron = scoped_cron(&db, scope, id)?;
    "active".clone_into(&mut cron.status);
    // Recompute the next fire forward from now (don't replay a backlog).
    if let (Some(ty), Some(val)) = (
        cron.schedule_type.as_deref(),
        cron.schedule_value.as_deref(),
    ) {
        cron.next_run = next_run_at_creation(ty, val, now()).ok().flatten();
    }
    cron.updated_at = to_iso(now());
    db.update_cron(&cron).map_err(db_error)?;
    cron_changed(ctx, &db, &cron);
    drop(db);
    Ok(CronResult {
        cron: shown_cron(ctx, &cron),
    })
}

/// Enqueue a `cron_state` for the host mirror (best-effort), then wake the
/// scheduler and the outbox flush.
fn cron_changed(ctx: &ApiContext, db: &Db, row: &CronRow) {
    let data = cron_state_data(row, row.run_count, &CronTally::default());
    if let Err(err) =
        db.enqueue_outbox_correlated("cron_state", &data, Some(&row.task_id), Some(&row.id))
    {
        tracing::warn!(cron_id = %row.id, error = %err, "failed to enqueue cron_state");
    }
    ctx.nudge.notify_one();
    ctx.flush.notify_one();
}

fn system_info(ctx: &ApiContext, scope: &Scope) -> Result<SystemInfo, ApiError> {
    let db = ctx.db();
    let internal = |err: crate::db::DbError| ApiError::internal(&err);
    let agent_id = db.get_identity().map_err(internal)?.map(|i| i.agent_id);
    let tasks = db.list_tasks().map_err(internal)?;
    let crons = db.list_active_crons().map_err(internal)?;
    let pending = db.list_threads_by_status("pending").map_err(internal)?;
    let running = db.list_threads_by_status("running").map_err(internal)?;
    drop(db);

    let (scope_name, own_task, workspace_dir, db_path) = match scope {
        Scope::Operator => (
            "operator",
            None,
            Some(ctx.workspace_dir.display().to_string()),
            Some(ctx.db_path.display().to_string()),
        ),
        Scope::Run(run) => ("run", Some(run.task_id.as_str()), None, None),
    };
    let visible = |task_id: &str| own_task.is_none_or(|own| own == task_id);
    Ok(SystemInfo {
        scope: scope_name.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        agent_id,
        name: ctx.agent_name.clone(),
        host_url: ctx.host_url.clone(),
        capabilities: vec!["claude".to_owned()],
        workspace_dir,
        db_path,
        tasks: tasks.iter().filter(|t| visible(&t.id)).count(),
        active_crons: crons.iter().filter(|c| visible(&c.task_id)).count(),
        threads: ThreadCounts {
            pending: pending.iter().filter(|t| visible(&t.task_id)).count(),
            running: running.iter().filter(|t| visible(&t.task_id)).count(),
        },
    })
}
