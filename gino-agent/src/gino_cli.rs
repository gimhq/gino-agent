//! `gino-agent <system|cron|task|thread|action>` — the in-engine "gino" operations CLI
//! (agent-architecture §3, §10). It lets the Claude engine, running inside a task,
//! inspect this agent and manage its own scheduled triggers via the `gino` skill.
//!
//! Each invocation is a short-lived client of the daemon's local agent API
//! (agent-architecture §10b). The socket is `$GINO_AGENT_SOCK`, else
//! `<workspace>/run/agent.sock`. Inside an engine run the connection
//! authenticates with `$GINO_AGENT_TOKEN` (scoped to the run's task); run by hand
//! on the agent's machine it connects unauthenticated with operator access.
//!
//! The current task/thread are exported to the engine as `$GINO_TASK_ID` /
//! `$GINO_THREAD_ID`, and the runner's own path as `$GINO_RUNNER_BIN`, so the skill
//! self-references without hard-coded ids or paths.

use std::fmt::Write as _;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::agent_api;
use crate::agent_api::client::{Client, ClientError};
use crate::agent_api::protocol::{
    CronInfo, CronList, CronResult, SystemInfo, TaskList, TaskShow, TaskSummary,
    ThreadActionResult, ThreadDetail, ThreadList, ThreadShow, ThreadSummary,
};
use crate::config::Config;
use crate::scheduler::{next_run_at_creation, now};

// ─── argument groups ─────────────────────────────────────────────────────────

/// `gino-agent cron <action>`.
#[derive(Subcommand)]
pub(crate) enum CronCommand {
    /// Schedule a recurring (cron/interval) or one-off (once) trigger.
    Create(CreateArgs),
    /// List this task's triggers (defaults to $GINO_TASK_ID).
    List(TaskFilterArg),
    /// Cancel a trigger by id (it stops firing).
    #[command(visible_alias = "cancel")]
    Delete(IdArg),
    /// Pause a trigger (keep it; it stops firing until `resume`).
    Pause(IdArg),
    /// Resume a paused trigger (next fire is computed forward from now).
    Resume(IdArg),
}

/// `gino-agent task <action>` — read-only inspection (tasks are host-assigned).
#[derive(Subcommand)]
pub(crate) enum TaskCommand {
    /// List this agent's tasks.
    List,
    /// Show one task with its threads and crons.
    Show(IdArg),
}

/// `gino-agent thread <action>` — read-only inspection of execution threads.
#[derive(Subcommand)]
pub(crate) enum ThreadCommand {
    /// List threads for a task (defaults to $GINO_TASK_ID).
    List(TaskFilterArg),
    /// Show one thread (status, session, result/error, prompt).
    Show(IdArg),
}

#[derive(Args)]
pub(crate) struct CreateArgs {
    /// Schedule kind: `cron` | `interval` | `once`.
    #[arg(long = "type", value_name = "cron|interval|once")]
    schedule_type: String,
    /// Schedule value: a 5-field cron expr (`"0 9 * * *"`), interval milliseconds
    /// (`"3600000"`), or a local ISO timestamp for `once` (`"2026-02-01T15:30:00"`).
    #[arg(long, value_name = "VALUE")]
    value: String,
    /// The recurring instruction run on each fire (the prompt the agent executes).
    #[arg(long)]
    prompt: String,
    /// `isolated` (a fresh thread per fire) | `shared` (one ongoing thread).
    #[arg(long, default_value = "isolated")]
    continuity: String,
    /// Task to attach to. Defaults to `$GINO_TASK_ID` (the current task).
    #[arg(long)]
    task_id: Option<String>,
}

#[derive(Args)]
pub(crate) struct TaskFilterArg {
    /// Task to operate on. Defaults to `$GINO_TASK_ID`.
    #[arg(long)]
    task_id: Option<String>,
}

#[derive(Args)]
pub(crate) struct ActionArgs {
    /// The host-defined action name (opaque to the agent).
    method: String,
    /// The action's parameters as a JSON object.
    params: Option<String>,
}

#[derive(Args)]
pub(crate) struct IdArg {
    /// The id (a cron id, task id, or thread id depending on the command).
    id: String,
}

// ─── dispatch ────────────────────────────────────────────────────────────────

/// Shown for a `system` path the server withholds from a run.
const NOT_AVAILABLE: &str = "(not available to this run)";

/// Connect to the agent API: authenticated with `$GINO_AGENT_TOKEN` when set,
/// otherwise as the operator (outside an engine run).
fn connect() -> Result<Client> {
    let socket = non_empty_env("GINO_AGENT_SOCK")
        .map_or_else(|| agent_api::socket_path(&workspace_dir()), PathBuf::from);
    if let Some(token) = non_empty_env("GINO_AGENT_TOKEN") {
        let mut client = Client::connect(&socket).map_err(client_error)?;
        client.auth(&token).map_err(client_error)?;
        return Ok(client);
    }
    if non_empty_env("GINO_THREAD_ID").is_some() {
        bail!("the local agent API is not available to this run");
    }
    Client::connect(&socket).map_err(client_error)
}

/// Call `method` and decode its result.
fn call<T: DeserializeOwned>(method: &str, params: Value) -> Result<T> {
    let result = connect()?.call(method, params).map_err(client_error)?;
    serde_json::from_value(result).with_context(|| format!("malformed {method} result"))
}

/// A client failure as a CLI error: an API error reads as its message alone.
fn client_error(err: ClientError) -> anyhow::Error {
    match err {
        ClientError::Api { message, .. } => anyhow!(message),
        other => anyhow::Error::new(other),
    }
}

/// `gino-agent system` — identity, version, host, paths, live counts.
pub(crate) fn system() -> Result<()> {
    let info: SystemInfo = call("system.info", json!({}))?;
    print!("{}", render_system(&info));
    Ok(())
}

pub(crate) fn cron(cmd: CronCommand) -> Result<()> {
    match cmd {
        CronCommand::Create(a) => cron_create(a),
        CronCommand::List(a) => cron_list(a),
        CronCommand::Delete(a) => cron_set_status("cron.delete", &a.id),
        CronCommand::Pause(a) => cron_set_status("cron.pause", &a.id),
        CronCommand::Resume(a) => {
            let res: CronResult = call("cron.resume", json!({ "id": a.id }))?;
            print!("{}", render_cron_resumed(&res.cron));
            Ok(())
        }
    }
}

pub(crate) fn task(cmd: TaskCommand) -> Result<()> {
    match cmd {
        TaskCommand::List => {
            let list: TaskList = call("task.list", json!({}))?;
            print!("{}", render_task_list(&list.tasks));
        }
        TaskCommand::Show(a) => {
            let show: TaskShow = call("task.show", json!({ "id": a.id }))?;
            print!("{}", render_task_show(&show));
        }
    }
    Ok(())
}

pub(crate) fn thread(cmd: ThreadCommand) -> Result<()> {
    match cmd {
        ThreadCommand::List(a) => {
            let task_id = resolve_task_id(a.task_id)?;
            let list: ThreadList = call("thread.list", json!({ "task_id": task_id }))?;
            print!("{}", render_thread_list(&list.threads));
        }
        ThreadCommand::Show(a) => {
            let show: ThreadShow = call("thread.show", json!({ "id": a.id }))?;
            print!("{}", render_thread_show(&show.thread));
        }
    }
    Ok(())
}

/// `gino-agent action` — ask the host to act: appends a `host_action` event to
/// this run's thread and prints its `seq`.
pub(crate) fn action(a: &ActionArgs) -> Result<()> {
    let params = match a.params.as_deref() {
        None => json!({}),
        Some(raw) => {
            let value: Value = serde_json::from_str(raw).context("params must be valid JSON")?;
            if !value.is_object() {
                bail!("params must be a JSON object");
            }
            value
        }
    };
    let res: ThreadActionResult = call(
        "thread.action",
        json!({ "method": a.method, "params": params }),
    )?;
    println!("{}", res.seq);
    Ok(())
}

// ─── cron handlers ───────────────────────────────────────────────────────────

fn cron_create(a: CreateArgs) -> Result<()> {
    let task_id = resolve_task_id(a.task_id)?;
    if !matches!(a.continuity.as_str(), "isolated" | "shared") {
        bail!(
            "--continuity must be 'isolated' or 'shared' (got '{}')",
            a.continuity
        );
    }
    // Validate the schedule before asking the agent to store it.
    next_run_at_creation(&a.schedule_type, &a.value, now()).with_context(|| {
        format!(
            "invalid schedule: --type {} --value {}",
            a.schedule_type, a.value
        )
    })?;
    let res: CronResult = call(
        "cron.create",
        json!({
            "type": a.schedule_type,
            "value": a.value,
            "prompt": a.prompt,
            "continuity": a.continuity,
            "task_id": task_id,
        }),
    )?;
    // Print just the id so the AI can capture it for later pause/resume/cancel.
    println!("{}", res.cron.id);
    Ok(())
}

fn cron_set_status(method: &str, id: &str) -> Result<()> {
    let res: CronResult = call(method, json!({ "id": id }))?;
    print!("{}", render_cron_status(&res.cron));
    Ok(())
}

fn cron_list(a: TaskFilterArg) -> Result<()> {
    // Without a task id the operator gets every task's active crons; the
    // server's `scoped` flag says which form came back.
    let params = match resolve_task_id(a.task_id) {
        Ok(task_id) => json!({ "task_id": task_id }),
        Err(_) => json!({}),
    };
    let list: CronList = call("cron.list", params)?;
    print!("{}", render_cron_list(&list.crons, list.scoped));
    Ok(())
}

// ─── rendering ───────────────────────────────────────────────────────────────

fn render_system(info: &SystemInfo) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "version       : {}", info.version);
    let _ = writeln!(
        out,
        "agent_id      : {}",
        info.agent_id.as_deref().unwrap_or("(not registered)")
    );
    let _ = writeln!(out, "name          : {}", or_dash(info.name.as_deref()));
    let _ = writeln!(out, "host_url      : {}", or_dash(info.host_url.as_deref()));
    let _ = writeln!(
        out,
        "workspace_dir : {}",
        info.workspace_dir.as_deref().unwrap_or(NOT_AVAILABLE)
    );
    let _ = writeln!(
        out,
        "db_path       : {}",
        info.db_path.as_deref().unwrap_or(NOT_AVAILABLE)
    );
    let _ = writeln!(out, "capabilities  : {}", info.capabilities.join(", "));
    let _ = writeln!(out, "tasks         : {}", info.tasks);
    let _ = writeln!(out, "active_crons  : {}", info.active_crons);
    let _ = writeln!(
        out,
        "threads       : pending={} running={}",
        info.threads.pending, info.threads.running
    );
    out
}

fn render_task_list(tasks: &[TaskSummary]) -> String {
    if tasks.is_empty() {
        return "(no tasks)\n".to_owned();
    }
    let mut out = String::new();
    for t in tasks {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}",
            t.id,
            t.status,
            or_dash(t.kind.as_deref()),
            or_dash(t.name.as_deref())
        );
    }
    out
}

fn render_task_show(show: &TaskShow) -> String {
    let t = &show.task;
    let mut out = String::new();
    let _ = writeln!(out, "task    : {}", t.id);
    let _ = writeln!(out, "name    : {}", or_dash(t.name.as_deref()));
    let _ = writeln!(out, "kind    : {}", or_dash(t.kind.as_deref()));
    let _ = writeln!(out, "status  : {}", t.status);
    let _ = writeln!(out, "created : {}", t.created_at);
    let _ = writeln!(out, "threads : {}", show.threads.len());
    for th in &show.threads {
        let _ = writeln!(
            out,
            "  {}\t{}\t{}\tsession={}",
            th.id,
            th.status,
            th.source,
            or_dash(th.engine_session_id.as_deref())
        );
    }
    let _ = writeln!(out, "crons   : {}", show.crons.len());
    for c in &show.crons {
        let _ = writeln!(
            out,
            "  {}\t{}\t{} {}\tnext={}",
            c.id,
            c.status,
            or_dash(c.schedule_type.as_deref()),
            or_dash(c.schedule_value.as_deref()),
            or_dash(c.next_run.as_deref())
        );
    }
    out
}

fn render_thread_list(threads: &[ThreadSummary]) -> String {
    if threads.is_empty() {
        return "(no threads)\n".to_owned();
    }
    let mut out = String::new();
    for th in threads {
        let _ = writeln!(
            out,
            "{}\t{}\t{}\tattempt={}/{}\tsession={}",
            th.id,
            th.status,
            th.source,
            th.attempt,
            th.max_attempts,
            or_dash(th.engine_session_id.as_deref())
        );
    }
    out
}

fn render_thread_show(th: &ThreadDetail) -> String {
    let s = &th.summary;
    let source = th
        .cron_id
        .as_deref()
        .map_or_else(|| s.source.clone(), |c| format!("{} (cron {c})", s.source));
    let mut out = String::new();
    let _ = writeln!(out, "thread        : {}", s.id);
    let _ = writeln!(out, "task          : {}", s.task_id);
    let _ = writeln!(out, "source        : {source}");
    let _ = writeln!(out, "status        : {}", s.status);
    if let Some(reason) = &th.failure_reason {
        let _ = writeln!(out, "failure_reason: {reason}");
    }
    let _ = writeln!(out, "engine        : {}", th.engine);
    let _ = writeln!(
        out,
        "session_id    : {}",
        or_dash(s.engine_session_id.as_deref())
    );
    let _ = writeln!(out, "attempt       : {}/{}", s.attempt, s.max_attempts);
    if let Some(ms) = th.duration_ms {
        let _ = writeln!(out, "duration_ms   : {ms}");
    }
    let _ = writeln!(out, "prompt        : {}", th.prompt);
    if let Some(result) = &th.result {
        let _ = writeln!(out, "result        : {result}");
    }
    if let Some(error) = &th.error {
        let _ = writeln!(out, "error         : {error}");
    }
    out
}

fn render_cron_status(c: &CronInfo) -> String {
    format!("{} -> {}\n", c.id, c.status)
}

fn render_cron_resumed(c: &CronInfo) -> String {
    format!(
        "{} -> active (next={})\n",
        c.id,
        or_dash(c.next_run.as_deref())
    )
}

/// Render `cron list` output. `scoped` means the list was filtered to one task;
/// the unscoped (all-tasks) form is labeled and carries a `task=` column so the
/// wide scope is never mistaken for the current task's triggers.
fn render_cron_list(crons: &[CronInfo], scoped: bool) -> String {
    let mut out = String::new();
    if !scoped {
        out.push_str(
            "(no task id — listing ACTIVE crons across ALL tasks; pass --task-id to scope)\n",
        );
    }
    if crons.is_empty() {
        out.push_str("(no crons)\n");
        return out;
    }
    for c in crons {
        let task = if scoped {
            String::new()
        } else {
            format!("task={}\t", c.task_id)
        };
        let _ = writeln!(
            out,
            "{id}\t{task}{status}\t{ty} {val}\tnext={next}\tcontinuity={cont}\truns={runs}\tprompt={prompt}",
            id = c.id,
            status = c.status,
            ty = or_dash(c.schedule_type.as_deref()),
            val = or_dash(c.schedule_value.as_deref()),
            next = or_dash(c.next_run.as_deref()),
            cont = c.continuity,
            runs = c.run_count,
            prompt = c.prompt,
        );
    }
    out
}

// ─── shared helpers ──────────────────────────────────────────────────────────

fn workspace_dir() -> PathBuf {
    std::env::var_os("GINO_WORKSPACE_DIR")
        .map_or_else(|| Config::default().paths.workspace_dir, PathBuf::from)
}

/// The task to operate on: explicit `--task-id` wins, else `$GINO_TASK_ID`.
fn resolve_task_id(explicit: Option<String>) -> Result<String> {
    explicit
        .or_else(|| std::env::var("GINO_TASK_ID").ok())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!("no task id — pass --task-id, or run inside a task where GINO_TASK_ID is set")
        })
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn or_dash(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

#[cfg(test)]
mod tests {
    use super::{
        client_error, render_cron_list, render_cron_resumed, render_cron_status, render_system,
        render_task_list, render_task_show, render_thread_list, render_thread_show,
    };
    use crate::agent_api::client::ClientError;
    use crate::agent_api::protocol::{
        CronInfo, ErrorCode, SystemInfo, TaskShow, TaskSummary, ThreadCounts, ThreadDetail,
        ThreadSummary,
    };

    fn cron(id: &str, task_id: &str) -> CronInfo {
        CronInfo {
            id: id.to_owned(),
            task_id: task_id.to_owned(),
            kind: "schedule".to_owned(),
            status: "active".to_owned(),
            schedule_type: Some("interval".to_owned()),
            schedule_value: Some("60000".to_owned()),
            next_run: None,
            last_fired_at: None,
            continuity: "isolated".to_owned(),
            run_count: 0,
            prompt: "do the thing".to_owned(),
            created_at: "2026-07-02T00:00:00.000Z".to_owned(),
            updated_at: "2026-07-02T00:00:00.000Z".to_owned(),
        }
    }

    fn task(id: &str, name: Option<&str>, kind: Option<&str>) -> TaskSummary {
        TaskSummary {
            id: id.to_owned(),
            name: name.map(str::to_owned),
            kind: kind.map(str::to_owned),
            status: "active".to_owned(),
            created_at: "2026-07-01T00:00:00.000Z".to_owned(),
        }
    }

    fn thread(id: &str, session: Option<&str>) -> ThreadSummary {
        ThreadSummary {
            id: id.to_owned(),
            task_id: "t-a".to_owned(),
            status: "succeeded".to_owned(),
            source: "chat".to_owned(),
            attempt: 1,
            max_attempts: 3,
            engine_session_id: session.map(str::to_owned),
        }
    }

    fn system_info(scope: &str, paths: bool) -> SystemInfo {
        SystemInfo {
            scope: scope.to_owned(),
            version: "1.2.3".to_owned(),
            agent_id: Some("agent-1".to_owned()),
            name: Some("box".to_owned()),
            host_url: None,
            capabilities: vec!["claude".to_owned(), "codex".to_owned()],
            workspace_dir: paths.then(|| "/ws".to_owned()),
            db_path: paths.then(|| "/ws/agent.db".to_owned()),
            tasks: 2,
            active_crons: 1,
            threads: ThreadCounts {
                pending: 0,
                running: 1,
            },
        }
    }

    #[test]
    fn system_operator_scope_prints_server_paths() {
        assert_eq!(
            render_system(&system_info("operator", true)),
            "version       : 1.2.3\n\
             agent_id      : agent-1\n\
             name          : box\n\
             host_url      : -\n\
             workspace_dir : /ws\n\
             db_path       : /ws/agent.db\n\
             capabilities  : claude, codex\n\
             tasks         : 2\n\
             active_crons  : 1\n\
             threads       : pending=0 running=1\n"
        );
    }

    #[test]
    fn system_run_scope_marks_withheld_paths() {
        let mut info = system_info("run", false);
        info.agent_id = None;
        info.capabilities = vec!["claude".to_owned()];
        assert_eq!(
            render_system(&info),
            "version       : 1.2.3\n\
             agent_id      : (not registered)\n\
             name          : box\n\
             host_url      : -\n\
             workspace_dir : (not available to this run)\n\
             db_path       : (not available to this run)\n\
             capabilities  : claude\n\
             tasks         : 2\n\
             active_crons  : 1\n\
             threads       : pending=0 running=1\n"
        );
    }

    #[test]
    fn task_list_renders_rows_or_empty_marker() {
        assert_eq!(render_task_list(&[]), "(no tasks)\n");
        let tasks = [
            task("t-a", Some("Alpha"), Some("chat")),
            task("t-b", None, None),
        ];
        assert_eq!(
            render_task_list(&tasks),
            "t-a\tactive\tchat\tAlpha\nt-b\tactive\t-\t-\n"
        );
    }

    #[test]
    fn task_show_renders_threads_and_crons() {
        let mut c = cron("cron-1", "t-a");
        c.next_run = Some("2026-07-02T01:00:00.000Z".to_owned());
        let show = TaskShow {
            task: task("t-a", Some("Alpha"), None),
            threads: vec![thread("th-1", Some("sess-1")), thread("th-2", None)],
            crons: vec![c],
        };
        assert_eq!(
            render_task_show(&show),
            "task    : t-a\n\
             name    : Alpha\n\
             kind    : -\n\
             status  : active\n\
             created : 2026-07-01T00:00:00.000Z\n\
             threads : 2\n\
             \x20 th-1\tsucceeded\tchat\tsession=sess-1\n\
             \x20 th-2\tsucceeded\tchat\tsession=-\n\
             crons   : 1\n\
             \x20 cron-1\tactive\tinterval 60000\tnext=2026-07-02T01:00:00.000Z\n"
        );
        let empty = TaskShow {
            task: task("t-b", None, None),
            threads: vec![],
            crons: vec![],
        };
        assert!(render_task_show(&empty).ends_with("threads : 0\ncrons   : 0\n"));
    }

    #[test]
    fn thread_list_renders_rows_or_empty_marker() {
        assert_eq!(render_thread_list(&[]), "(no threads)\n");
        assert_eq!(
            render_thread_list(&[thread("th-1", Some("sess-1")), thread("th-2", None)]),
            "th-1\tsucceeded\tchat\tattempt=1/3\tsession=sess-1\n\
             th-2\tsucceeded\tchat\tattempt=1/3\tsession=-\n"
        );
    }

    #[test]
    fn thread_show_renders_optional_fields_only_when_present() {
        let full = ThreadDetail {
            summary: thread("th-1", Some("sess-1")),
            cron_id: Some("cron-1".to_owned()),
            failure_reason: Some("timeout".to_owned()),
            engine: "claude".to_owned(),
            duration_ms: Some(42),
            prompt: "hi".to_owned(),
            result: Some("done".to_owned()),
            error: Some("boom".to_owned()),
        };
        assert_eq!(
            render_thread_show(&full),
            "thread        : th-1\n\
             task          : t-a\n\
             source        : chat (cron cron-1)\n\
             status        : succeeded\n\
             failure_reason: timeout\n\
             engine        : claude\n\
             session_id    : sess-1\n\
             attempt       : 1/3\n\
             duration_ms   : 42\n\
             prompt        : hi\n\
             result        : done\n\
             error         : boom\n"
        );
        let bare = ThreadDetail {
            summary: thread("th-2", None),
            cron_id: None,
            failure_reason: None,
            engine: "claude".to_owned(),
            duration_ms: None,
            prompt: "hi".to_owned(),
            result: None,
            error: None,
        };
        assert_eq!(
            render_thread_show(&bare),
            "thread        : th-2\n\
             task          : t-a\n\
             source        : chat\n\
             status        : succeeded\n\
             engine        : claude\n\
             session_id    : -\n\
             attempt       : 1/3\n\
             prompt        : hi\n"
        );
    }

    #[test]
    fn cron_mutations_render_id_and_status() {
        let mut c = cron("cron-1", "t-a");
        c.status = "paused".to_owned();
        assert_eq!(render_cron_status(&c), "cron-1 -> paused\n");
        assert_eq!(render_cron_resumed(&c), "cron-1 -> active (next=-)\n");
        c.next_run = Some("2026-07-02T01:00:00.000Z".to_owned());
        assert_eq!(
            render_cron_resumed(&c),
            "cron-1 -> active (next=2026-07-02T01:00:00.000Z)\n"
        );
    }

    /// Audit P3: without a task id, `cron list` used to widen to every task's
    /// crons with output indistinguishable from the scoped form. The wide form
    /// must be labeled and carry the owning task per line.
    #[test]
    fn unscoped_cron_list_labels_the_wide_scope() {
        let crons = [cron("cron-1", "t-a"), cron("cron-2", "t-b")];
        assert_eq!(
            render_cron_list(&crons, false),
            "(no task id — listing ACTIVE crons across ALL tasks; pass --task-id to scope)\n\
             cron-1\ttask=t-a\tactive\tinterval 60000\tnext=-\tcontinuity=isolated\truns=0\tprompt=do the thing\n\
             cron-2\ttask=t-b\tactive\tinterval 60000\tnext=-\tcontinuity=isolated\truns=0\tprompt=do the thing\n"
        );
    }

    #[test]
    fn scoped_cron_list_has_no_banner_and_no_task_column() {
        let crons = [cron("cron-1", "t-a")];
        assert_eq!(
            render_cron_list(&crons, true),
            "cron-1\tactive\tinterval 60000\tnext=-\tcontinuity=isolated\truns=0\tprompt=do the thing\n"
        );
    }

    #[test]
    fn empty_lists_state_so_in_both_scopes() {
        assert_eq!(render_cron_list(&[], true), "(no crons)\n");
        assert_eq!(
            render_cron_list(&[], false),
            "(no task id — listing ACTIVE crons across ALL tasks; pass --task-id to scope)\n\
             (no crons)\n"
        );
    }

    #[test]
    fn client_errors_read_as_plain_messages() {
        let not_running = client_error(ClientError::NotRunning(std::io::Error::from(
            std::io::ErrorKind::NotFound,
        )));
        assert_eq!(not_running.to_string(), "the agent is not running");
        let api = client_error(ClientError::Api {
            code: ErrorCode::NotFound,
            message: "no such task: t-x".to_owned(),
        });
        assert_eq!(api.to_string(), "no such task: t-x");
    }
}
