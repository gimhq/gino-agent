//! End-to-end §5b scenarios — the deterministic full-loop tests.
//!
//! Each scenario boots the real `gino-agent` binary against an in-process stub
//! host with a scripted fake-`claude` (see [`support`]) and asserts the host
//! read-model mirror. The whole production stack runs unmodified: register →
//! transport (outbox/inbox, at-least-once, reconnect) → executor (drainer,
//! watchdog, retry, resume-safety) → attachment plane.
//!
//! Chat-`message`-driven scenarios (the prompt is `message.text`):
//!
//! * `basic_loop` — register → connect → message → ordered `thread_message`×N →
//!   `thread_result`; `final_seq == N`.
//! * `codex_engine_task_runs_on_the_codex_backend` — a `task_upsert` naming
//!   `engine: "codex"` routes the run onto the codex backend (both engine fakes
//!   on `PATH`): the fake `codex`'s `thread.started` id becomes the thread's
//!   `engine_session_id`, its reasoning / `command_execution` / `agent_message`
//!   items mirror as `thinking` → `tool_use` → `tool_result` → `assistant_text`
//!   with no `parent_tool_use_id`, and the recorded argv is codex's `exec --json`.
//! * `reconnect_replay_dedup` (§5b #4) — drop the WS mid-flight; replayed unacked
//!   frames de-dup on `(threadId, seq)` (no dup messages, no re-run).
//! * `host_action_replays_after_reconnect` — an engine's `gino-agent action`
//!   rides the outbox: unacked, it replays after a reconnect and de-dups.
//! * `parallel_interleave_ordering` (§5b #5) — ≥2 threads reassembled by
//!   `(taskId, threadId, seq)`; `final_seq` == per-thread count.
//! * `failure_timeout_is_retried`, `failure_prose_400_keeps_session`,
//!   `failure_agent_error_not_retried` (§5b #6) — `runner.timeout` (retried),
//!   error prose never classified (a "400"-looking message keeps the
//!   session), unclassified engine errors → `agent.unknown` (not retried).
//! * `attachment_round_trip` (§5b #7) — inbound descriptor → `inputs/` → engine
//!   reads → `output/` → upload → host `attachments`; sha256 verified; cache hit
//!   on repeat.
//!
//! Cron-driven scenarios (Lane I2 — the prompt is the trigger's `crons.prompt`,
//! seeded by `cron_upsert.data.prompt` and snapshotted into `threads.prompt`):
//!
//! * `cron_once_run` (§5b #1) — `task_upsert` + a `once` `cron_upsert` → the
//!   scheduler fires → ordered `thread_message`×N → `thread_result`; the cron
//!   `cron_state` reports one round and `completed`.
//! * `cron_recurring_fires_k_isolated_threads` (§5b #2) — an `interval` cron fired
//!   K× → K isolated threads (distinct deterministic ids); `cron_state.round_count
//!   == K` and host `thread_runs` count == K.
//! * `cron_missed_logs_ledger_without_a_thread` (§5b #3) — a `once` slot past the
//!   catch-up grace fires `missed`: a `cron_state` round with a skip and **no**
//!   `thread_run`.
//! * `cron_crash_restart_no_double_execution` (§5b #8) — kill the runner mid-flight;
//!   on restart the deterministic `thread_id` + `cron_logs UNIQUE(cron_id,
//!   scheduled_at)` prevent a re-fire/re-run while the unsynced outbox result
//!   replays (one `thread_run`, messages de-dup, `round_count` stays 1).
//!
//! Provisioning scenarios (engine config & skills). The runner owns
//! `GINO_WORKSPACE_DIR`, so these assert on the **on-disk** content-addressed store
//! and symlinks it materializes (not the host mirror). Global scope:
//! `engine-config/<target>` is a symlink into `store/<name>/<sha256[:12]>`. Task
//! scope: `threads/<id>/project/<target>`, alongside the isolated
//! `project/workspace/` git area.
//!
//! * `global_provisioning_materializes_file_and_dir` (#1) — register-config
//!   `entries` (a `file` instruction + a `dir` skill) materialize as symlinks into
//!   the store on startup; each entry fetched once.
//! * `config_update_repoints_and_reconciles_add_remove` (#3/#4) — a live
//!   `config_update` repoints a target to new bytes (new store version), adds a
//!   second entry, then removes it.
//! * `gc_collects_unreferenced_task_store_after_restart` (#5) — a repoint orphans
//!   the old store entry; a restart's startup GC collects it, keeping the
//!   referenced one.
//! * `restart_repairs_deleted_task_symlink_without_refetch` (#6) — a deleted
//!   symlink is recreated by startup repair from the present store entry, no
//!   re-fetch.
//! * `task_provisioning_materializes_into_project_and_isolates_workspace` (#2/#7) —
//!   `task_upsert.data.entries` materialize into the per-thread `project/` scope;
//!   the injected config stays out of the isolated `project/workspace/` git area.
//! * `path_traversal_global_entry_is_contained_and_daemon_survives` (#8) — a
//!   `target = "../escape"` entry is rejected without escaping the scope root; a
//!   sibling valid entry still materializes and the daemon keeps serving.
//!
//! GC (#5) and repair (#6) run on the **task** scope. The runner still reuses its
//! persisted identity on a restart (no second `POST /agent/register`), but the
//! GLOBAL set is now restart-durable: the startup `GET /agent/config` re-supplies
//! the host's versioned desired set, and the version gate reconciles the global scope
//! ONLY when that version advances. A restart at the same version takes
//! the repair-only path, so the global manifest + store survive. The task manifest
//! (`tasks.entries` + `config_entries`) is likewise durable, so #5/#6 keep exercising
//! the scope-agnostic `Provisioner::gc`/`repair` on the task scope, while the version
//! gate itself is covered head-on by the restart-durability scenarios below.
//!
//! Restart-durability scenarios (the version gate, global scope):
//!
//! * `restart_same_global_version_is_durable` — a restart that re-fetches the SAME
//!   config version repairs-only: the global symlinks + store survive with ZERO
//!   additional byte fetches (no wipe).
//! * `restart_higher_global_version_reconciles` — a restart whose `GET /agent/config`
//!   serves a BUMPED version + edited set reconciles (repoint / add); the orphaned old
//!   store version is GC'd.
//! * `offline_startup_fetch_keeps_installed_global` — a non-200 `GET /agent/config`
//!   at startup is non-authoritative: the previously-installed global set is kept
//!   (repair-only), never wiped.
//!
//! Memory scenarios (the fake `claude` runs the `SessionStart` hook on a new
//! session, applies `remember:` / `remember-agent:` prompt directives and
//! reports the auto memory settings it was launched with; the scenarios assert
//! the result text and the on-disk `memory/` trees):
//!
//! * `task_memory_reaches_a_new_thread_of_the_same_task_only` — a fact stored by
//!   one thread is injected into a new thread of the same task, never into
//!   another task's fresh tree; `task_delete` removes the task tree. Claude's
//!   auto memory is redirected to `<task dir>/claude`, not disabled.
//! * `agent_memory_reaches_other_tasks_without_their_task_facts` — an agent fact
//!   is injected into another task, ahead of its task section, without the
//!   writer's task fact.
//! * `task_memory_off_for_the_runner_creates_and_injects_no_task_tree` —
//!   `GINO_TASK_MEMORY=off`: no task tree, no `GINO_MEMORY_DIR`, no task section;
//!   Claude's auto memory is disabled.
//! * `task_meta_memory_off_disables_only_that_task` — `meta.memory.task = "off"`
//!   on one task disables its task memory and Claude's auto memory, while
//!   another task's memory stays on with auto memory redirected.
//!
//! ## Hermetic per-test workspace, serialized
//! See [`support`] — each scenario boots against its own temp [`support::Workspace`]
//! (`GINO_WORKSPACE_DIR`/`GINO_DB_PATH`, Lane WP), holding a process-global serial
//! guard so at most one daemon runs at a time. Keep new daemon-spawning scenarios in
//! this single test binary so the lock serializes them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Value, json};

use support::fake_claude::{self, Behavior};
use support::fake_codex;
use support::stub_host::{
    CronSpec, StubHost, build_tar, delivery_id, provisioning_entry, sha256_hex,
};
use support::{RunnerProc, SETTLE, Workspace, wait_until};

/// `assistant_text` is the kind the echo behaviour's `Output` events map to.
const ASSISTANT_TEXT: &str = "assistant_text";

// ---------------------------------------------------------------------------
// Basic loop: register → connect → message → ordered thread_message×N → result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn basic_loop_streams_ordered_messages_and_final_seq() {
    let host = StubHost::start(json!({})).await;
    let behavior = Behavior::echo_lines("sess-basic", 3);
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_message("t-basic", Some("th-basic"), "hello", &[], 1)
        .await;

    let run = host
        .wait_thread_terminal("th-basic", SETTLE)
        .await
        .expect("no thread_result mirrored");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    assert_eq!(run.final_seq, 3, "final_seq must equal the message count");
    assert_eq!(run.engine_session_id.as_deref(), Some("sess-basic"));
    assert_eq!(run.result.as_deref(), Some("done"));

    let messages = host.messages_for("t-basic", "th-basic").await;
    let seqs: Vec<i64> = messages.iter().map(|m| m.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3], "per-thread seq is monotonic from 1");
    assert!(
        messages.iter().all(|m| m.kind == ASSISTANT_TEXT),
        "echo run emits only assistant_text: {messages:?}"
    );
    let contents: Vec<Option<&str>> = messages.iter().map(|m| m.content.as_deref()).collect();
    assert_eq!(
        contents,
        vec![
            Some("assistant line 1"),
            Some("assistant line 2"),
            Some("assistant line 3"),
        ],
        "assistant text mirrored verbatim in order"
    );

    // The runner durably acked the inbound message, and presented its connect token.
    assert!(
        host.msg_acks().await.contains(&delivery_id(1)),
        "missing msg_ack for msgId 1"
    );
    assert_eq!(
        host.observed_connect_token().await.as_deref(),
        Some(host.connect_token.as_str()),
        "runner must present the host-minted connect token (x-internal-token)"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// Engine registry: a task naming `codex` runs on the codex backend
// ---------------------------------------------------------------------------

/// The thread id the fake `codex` announces on `thread.started` — the resume
/// handle the host mirrors as `engine_session_id`.
const CODEX_THREAD_ID: &str = "codex-thread-1";

#[tokio::test]
async fn codex_engine_task_runs_on_the_codex_backend() {
    let host = StubHost::start(json!({})).await;
    // Both fakes are installed: `claude` stays the registry default (and would
    // run the turn if selection fell back), and installing `codex` is what makes
    // the runner register the codex backend at all.
    let behavior = Behavior::echo_lines("sess-claude-unused", 1);
    let runner = RunnerProc::spawn_with_codex(&host, &behavior, CODEX_THREAD_ID).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // The task row's `engine` is what the executor reads at spawn time.
    host.push_task_upsert_with_engine("t-codex", "codex", 1)
        .await;
    host.push_message("t-codex", Some("th-codex"), "hello codex", &[], 2)
        .await;

    let run = host
        .wait_thread_terminal("th-codex", SETTLE)
        .await
        .expect("no thread_result mirrored");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    // Only the codex backend can produce this id: it comes from the fake's
    // `thread.started`, never from the claude fake's `system/init`.
    assert_eq!(
        run.engine_session_id.as_deref(),
        Some(CODEX_THREAD_ID),
        "engine_session_id must be the codex thread id: {run:?}"
    );

    let messages = host.messages_for("t-codex", "th-codex").await;
    let kinds: Vec<&str> = messages.iter().map(|m| m.kind.as_str()).collect();
    assert_eq!(
        kinds,
        vec!["thinking", "tool_use", "tool_result", ASSISTANT_TEXT],
        "codex item stream mirrors in order: {messages:?}"
    );
    let seqs: Vec<i64> = messages.iter().map(|m| m.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3, 4], "per-thread seq is monotonic from 1");

    assert_eq!(
        messages[0].content.as_deref(),
        Some(fake_codex::THINKING),
        "reasoning item → thinking content"
    );
    // The tool name is the codex ITEM KIND, forwarded verbatim (never aliased
    // onto a claude tool name), and the result joins on the same item id.
    assert_eq!(messages[1].tool.as_deref(), Some(fake_codex::TOOL));
    assert_eq!(
        messages[1].tool_use_id.as_deref(),
        Some(fake_codex::TOOL_USE_ID)
    );
    assert_eq!(
        messages[2].tool_use_id.as_deref(),
        Some(fake_codex::TOOL_USE_ID),
        "tool_result joins its tool_use by id"
    );
    let echoed = messages[3].content.clone().unwrap_or_default();
    assert!(
        echoed.starts_with(fake_codex::ECHO_PREFIX) && echoed.contains("hello codex"),
        "assistant text echoes the prompt the runner streamed in: {echoed:?}"
    );

    // Codex reports no sub-agent linkage, so every row is main-agent attributed.
    assert!(
        messages.iter().all(|m| m.parent_tool_use_id.is_none()),
        "codex events carry no parent_tool_use_id: {messages:?}"
    );

    // The argv proves WHICH backend spawned the turn: codex's `exec --json`,
    // with none of the claude engine's flags.
    let argv = fake_codex::recorded_argv(runner.fake_dir());
    assert!(
        argv.iter().any(|a| a == "exec") && argv.iter().any(|a| a == "--json"),
        "codex argv must carry `exec --json`: {argv:?}"
    );
    // `--ask-for-approval` is a TOP-LEVEL flag; codex-cli 0.154.0 exits with
    // `error: unexpected argument` when it follows the subcommand, so the real
    // binary would reject any argv that gets this order wrong.
    if let Some(approval) = argv.iter().position(|a| a == "--ask-for-approval") {
        let exec = argv.iter().position(|a| a == "exec").expect("exec in argv");
        assert!(
            approval < exec,
            "`--ask-for-approval` must precede `exec`: {argv:?}"
        );
    }
    assert!(
        !argv
            .iter()
            .any(|a| a == "--dangerously-skip-permissions" || a == "--output-format"),
        "claude flags must not appear in a codex spawn: {argv:?}"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// §5b #4 — reconnect replay + dedup on (threadId, seq)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconnect_replay_dedup() {
    let host = StubHost::start(json!({})).await;
    // Withhold acks so the run's frames stay in the outbox and replay on reconnect.
    host.set_auto_ack(false);
    let behavior = Behavior::echo_lines("sess-recon", 3);
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_message("t-rc", Some("th-rc"), "hello", &[], 1)
        .await;

    // Run completes, but every frame is unacked (host withheld acks).
    let run = host
        .wait_thread_terminal("th-rc", SETTLE)
        .await
        .expect("no thread_result mirrored");
    assert_eq!(run.status, "succeeded");
    assert!(
        host.wait_message_count("t-rc", "th-rc", 3, SETTLE).await,
        "expected 3 messages before the drop"
    );
    let recv_before = host.message_recv_count().await;

    // Sever the socket and resume acking; the runner reconnects and replays the
    // unacked outbox rows.
    host.drop_connection().await;
    host.set_auto_ack(true);

    let replayed = host.wait_reconnect_replay(recv_before, SETTLE).await;
    assert!(replayed, "reconnect did not replay unacked frames");
    assert!(host.ws_connects().await >= 2, "runner did not reconnect");

    // De-dup: exactly the 3 original messages survive (replay collapses on
    // (taskId, threadId, seq)); the run was not executed twice.
    let messages = host.messages_for("t-rc", "th-rc").await;
    let seqs: Vec<i64> = messages.iter().map(|m| m.seq).collect();
    assert_eq!(
        seqs,
        vec![1, 2, 3],
        "duplicate (threadId, seq) must collapse"
    );
    let run = host.thread_run("th-rc").await.unwrap();
    assert_eq!(run.final_seq, 3, "final_seq stable — no re-run renumbering");
    assert!(
        host.message_recv_count().await > recv_before,
        "a replay must have re-sent frames (at-least-once)"
    );

    runner.shutdown().await;
}

/// A `host_action` an engine records rides the outbox like any transcript
/// event: unacked, it replays after a reconnect and collapses on
/// `(threadId, seq)`.
#[tokio::test]
async fn host_action_replays_after_reconnect() {
    use std::os::unix::fs::PermissionsExt;

    let host = StubHost::start(json!({})).await;
    host.set_auto_ack(false);
    let workspace = Workspace::new().await;
    let fakes = tempfile::tempdir().unwrap();
    let init = json!({ "type": "system", "subtype": "init", "session_id": "sess-act", "model": "stub", "tools": [] });
    let result = json!({ "type": "result", "subtype": "success", "is_error": false, "result": "done", "session_id": "sess-act" });
    let script = format!(
        "#!/usr/bin/env bash\n\
         printf '%s\\n' '{init}'\n\
         \"$GINO_RUNNER_BIN\" action comment '{{\"body\":\"hi\"}}' >/dev/null || exit 1\n\
         printf '%s\\n' '{result}'\n"
    );
    let claude = fakes.path().join("claude");
    std::fs::write(&claude, script).unwrap();
    std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
    let runner = RunnerProc::spawn_in_with_fakes(&host, &workspace, fakes, None);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_message("t-act", Some("th-act"), "act", &[], 1)
        .await;
    let run = host
        .wait_thread_terminal("th-act", SETTLE)
        .await
        .expect("no thread_result mirrored");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    let recv_before = host.message_recv_count().await;

    host.drop_connection().await;
    host.set_auto_ack(true);
    assert!(
        host.wait_reconnect_replay(recv_before, SETTLE).await,
        "reconnect did not replay the unacked host_action"
    );
    assert!(host.ws_connects().await >= 2, "runner did not reconnect");

    let actions: Vec<_> = host
        .messages_for("t-act", "th-act")
        .await
        .into_iter()
        .filter(|m| m.kind == "host_action")
        .collect();
    assert_eq!(actions.len(), 1, "host actions: {actions:?}");
    assert_eq!(
        actions[0].input,
        Some(json!({ "method": "comment", "params": { "body": "hi" } }))
    );
    assert_eq!(
        host.thread_run("th-act").await.unwrap().final_seq,
        actions[0].seq
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// §5b #5 — parallel threads reassembled by (taskId, threadId, seq)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parallel_interleave_ordering() {
    let host = StubHost::start(json!({})).await;
    let behavior = Behavior::echo_lines("sess-par", 2);
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // Two concurrent chat threads under one task. (The runner drains threads
    // serially, so frames batch per-thread on the wire rather than truly
    // interleaving; the assertion is the host-side demux/reassembly contract:
    // each thread is independently ordered 1..=final_seq.)
    host.push_message("t-par", Some("th-a"), "a", &[], 1).await;
    host.push_message("t-par", Some("th-b"), "b", &[], 2).await;

    for thread in ["th-a", "th-b"] {
        let run = host
            .wait_thread_terminal(thread, SETTLE)
            .await
            .unwrap_or_else(|| panic!("no result for {thread}"));
        assert_eq!(run.status, "succeeded", "{thread}: {run:?}");
        assert_eq!(run.final_seq, 2, "{thread} final_seq == per-thread count");
        let seqs: Vec<i64> = host
            .messages_for("t-par", thread)
            .await
            .iter()
            .map(|m| m.seq)
            .collect();
        assert_eq!(seqs, vec![1, 2], "{thread} reassembled in order");
    }

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// §5b #6 — failure / retry / resume-safety
// ---------------------------------------------------------------------------

/// `runner.timeout` is retryable: a stalled engine trips the 1s inactivity
/// watchdog; with `max_attempts = 2` the thread is **rescheduled** (a "retrying
/// after runner.timeout…" status note) before it settles `failed`.
///
/// With the Z2 attempt-0 snapshot (D10) the terminal reason is now `runner.timeout`
/// itself: a chat thread snapshots its resolved `message.text` into `threads.prompt`
/// at attempt 0, so the retry **reuses** that snapshot rather than re-resolving the
/// already-consumed inbox message. The retry stalls and times out again, and the
/// thread settles on `runner.timeout` — not the `runner.invalid_request` the
/// pre-Z2 (prompt-consumed-on-first-attempt) path produced.
#[tokio::test]
async fn failure_timeout_is_retried() {
    // 1s inactivity watchdog; 2 attempts so a retry is observable.
    let config = json!({ "executor": { "inactivityTimeoutSecs": 1, "maxAttempts": 2 } });
    let host = StubHost::start(config).await;
    let behavior = Behavior::Stall {
        session_id: "sess-to".to_owned(),
    };
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_message("t-to", Some("th-to"), "hang", &[], 1)
        .await;

    let run = host
        .wait_thread_terminal("th-to", Duration::from_secs(20))
        .await
        .expect("no terminal thread_result");
    assert_eq!(run.status, "failed", "run: {run:?}");
    // The snapshot reuse means every attempt re-runs the same prompt and times out,
    // so the terminal classification is `runner.timeout` (not the consumed-message
    // `runner.invalid_request`).
    assert_eq!(
        run.failure_reason.as_deref(),
        Some("runner.timeout"),
        "the retried snapshot stalls again → terminal runner.timeout"
    );

    // A retry happened, and the retried failure was a `runner.timeout`: the
    // reschedule emits a `status` note "retrying after runner.timeout: …".
    let note = host
        .messages_for("t-to", "th-to")
        .await
        .into_iter()
        .find(|m| m.kind == "status")
        .expect("a retryable failure must emit a retry status note");
    assert!(
        note.content.unwrap_or_default().contains("runner.timeout"),
        "the retried failure must be classified runner.timeout"
    );

    runner.shutdown().await;
}

/// Regression: an errored result whose PROSE looks like a malformed
/// request ("HTTP 400", "invalid request") carries no structured cause, so it
/// classifies `agent.unknown` — NOT `runner.invalid_request` — and the healthy
/// engine session id survives for resume instead of being discarded on a
/// substring false positive.
#[tokio::test]
async fn failure_prose_400_keeps_session() {
    let config = json!({ "executor": { "maxAttempts": 1 } });
    let host = StubHost::start(config).await;
    let behavior = Behavior::Fail {
        session_id: "sess-inv".to_owned(),
        error: "HTTP 400 invalid request: took 1500ms".to_owned(),
    };
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_message("t-inv", Some("th-inv"), "go", &[], 1)
        .await;

    let run = host
        .wait_thread_terminal("th-inv", SETTLE)
        .await
        .expect("no terminal thread_result");
    assert_eq!(run.status, "failed", "run: {run:?}");
    assert_eq!(run.failure_reason.as_deref(), Some("agent.unknown"));
    assert_eq!(
        run.engine_session_id.as_deref(),
        Some("sess-inv"),
        "a prose false positive must not drop the resume handle"
    );

    runner.shutdown().await;
}

/// An `agent.*` failure is never retried, even with attempts remaining, and (being
/// resume-safe) keeps the session id. The error prose (a 401 message) is never
/// sniffed: with no structured cause the reason is the `agent.unknown` fallback.
#[tokio::test]
async fn failure_agent_error_not_retried() {
    let config = json!({ "executor": { "maxAttempts": 3 } });
    let host = StubHost::start(config).await;
    let behavior = Behavior::Fail {
        session_id: "sess-auth".to_owned(),
        error: "HTTP 401 Unauthorized: invalid x-api-key".to_owned(),
    };
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_message("t-auth", Some("th-auth"), "go", &[], 1)
        .await;

    let run = host
        .wait_thread_terminal("th-auth", SETTLE)
        .await
        .expect("no terminal thread_result");
    assert_eq!(run.status, "failed", "run: {run:?}");
    assert_eq!(run.failure_reason.as_deref(), Some("agent.unknown"));
    // Not retried (no reschedule status note), despite max_attempts == 3.
    let retried = host
        .messages_for("t-auth", "th-auth")
        .await
        .iter()
        .any(|m| m.kind == "status");
    assert!(!retried, "agent.* failures must not be retried");
    assert_eq!(
        run.engine_session_id.as_deref(),
        Some("sess-auth"),
        "a resume-safe failure keeps the session id"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// §5b #7 — attachment round-trip + sha256 + cache hit on repeat
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attachment_round_trip() {
    let host = StubHost::start(json!({})).await;
    let behavior = Behavior::Attachment {
        session_id: "sess-att".to_owned(),
    };
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    let input = b"hello-input";
    let descriptor = host
        .stage_inbound_attachment(
            "att-in-1",
            fake_claude::ATTACHMENT_INPUT_NAME,
            input,
            "text/plain",
        )
        .await;
    let expected_out = fake_claude::attachment_output_for(input);
    let expected_sha = sha256_hex(&expected_out);

    // First turn: inbound download → engine reads inputs/ → writes output/ → upload.
    host.push_message(
        "t-att",
        Some("th-att"),
        "process the file",
        std::slice::from_ref(&descriptor),
        1,
    )
    .await;
    let run = host
        .wait_thread_terminal("th-att", SETTLE)
        .await
        .expect("no terminal thread_result");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    assert!(
        host.wait_upload_count(1, SETTLE).await,
        "the output artifact was never uploaded"
    );

    assert_eq!(
        host.get_count("att-in-1").await,
        1,
        "inbound downloaded once"
    );
    let uploads = host.uploads().await;
    assert_eq!(uploads.len(), 1);
    assert_eq!(uploads[0].name, fake_claude::ATTACHMENT_OUTPUT_NAME);
    assert_eq!(
        uploads[0].sha256, expected_sha,
        "uploaded output sha256 must match the produced bytes"
    );
    assert_eq!(uploads[0].size, expected_out.len());
    assert_eq!(uploads[0].content_type, "text/plain", "guessed from .txt");
    assert!(
        uploads[0].id.starts_with("up-"),
        "host minted an upload id: {}",
        uploads[0].id
    );

    // The terminal result carries the outbound descriptor the host registered.
    let outbound: &Value = run
        .attachments
        .first()
        .expect("thread_result carried no outbound attachment");
    assert_eq!(outbound["name"], json!(fake_claude::ATTACHMENT_OUTPUT_NAME));
    assert_eq!(outbound["sha256"], json!(expected_sha));
    assert_eq!(outbound["direction"], json!("outbound"));

    // Second turn, same inbound descriptor: the content-addressed cache serves it,
    // so there is NO second download (cache hit on repeat).
    host.push_message("t-att", Some("th-att"), "again", &[descriptor], 2)
        .await;
    assert!(
        host.wait_upload_count(2, SETTLE).await,
        "the second turn never re-uploaded"
    );
    assert_eq!(
        host.get_count("att-in-1").await,
        1,
        "repeat must hit the sha256 cache (no second download)"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// Cron scenarios (§5b #1/#2/#3/#8) — the v2 scheduling plane end to end
// ---------------------------------------------------------------------------

/// A whole-second cron slot `secs_ago` seconds before now: its RFC3339 (millis, `Z`)
/// timestamp (a `next_run` / `schedule_value`) **and** its unix-epoch seconds. The
/// pair agree exactly with the scheduler's `parse_iso(next_run)`, so the
/// deterministic isolated thread id ([`isolated_thread_id`]) the fire mints is
/// predictable from the test side. Anchored in the past so the slot is immediately
/// due (`next_run <= now`).
fn past_slot(secs_ago: i64) -> (String, i64) {
    let epoch = Utc::now().timestamp() - secs_ago;
    let at = DateTime::<Utc>::from_timestamp(epoch, 0).expect("valid epoch second");
    (at.to_rfc3339_opts(SecondsFormat::Millis, true), epoch)
}

/// The deterministic thread id an *isolated* cron fire mints (agent-architecture
/// §4): `"<cron_id>@<scheduled_epoch_millis>"` (whole-second slots here, so the
/// epoch seconds scale by 1000).
fn isolated_thread_id(cron_id: &str, epoch: i64) -> String {
    format!("{cron_id}@{}", epoch * 1000)
}

// ---------------------------------------------------------------------------
// §5b #1 — once-cron run: fire → ordered messages → result; cron completes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cron_once_run() {
    let host = StubHost::start(json!({})).await;
    let behavior = Behavior::echo_lines("sess-cron1", 3);
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // Seed the task, then a `once` trigger due a few seconds ago (within the
    // catch-up grace). The runner stores `cron_upsert.data.prompt` into
    // `crons.prompt` and the fire snapshots it into the thread.
    host.push_task_upsert("t-c1", Some("nightly"), Some("job"), Some("active"), 1)
        .await;
    let (slot, epoch) = past_slot(3);
    host.push_cron_upsert(
        "t-c1",
        "cr-1",
        &CronSpec {
            prompt: "summarize the overnight alerts",
            kind: "schedule",
            schedule_type: "once",
            schedule_value: &slot,
            continuity: "isolated",
            next_run: Some(&slot),
            status: None,
        },
        2,
    )
    .await;

    // The fire mints a deterministic isolated thread; the executor runs it like any
    // pending thread → ordered `thread_message`×3 → terminal `thread_result`.
    let tid = isolated_thread_id("cr-1", epoch);
    let run = host
        .wait_thread_terminal(&tid, SETTLE)
        .await
        .expect("no thread_result mirrored for the cron fire");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    assert_eq!(run.task_id, "t-c1");
    assert_eq!(
        run.final_seq, 3,
        "final_seq == the cron run's message count"
    );
    assert_eq!(run.engine_session_id.as_deref(), Some("sess-cron1"));
    assert_eq!(run.result.as_deref(), Some("done"));

    let messages = host.messages_for("t-c1", &tid).await;
    let seqs: Vec<i64> = messages.iter().map(|m| m.seq).collect();
    assert_eq!(
        seqs,
        vec![1, 2, 3],
        "cron transcript ordered under the fire's id"
    );
    assert!(
        messages.iter().all(|m| m.kind == ASSISTANT_TEXT),
        "echo cron run emits only assistant_text: {messages:?}"
    );

    // Exactly one execution, and the cron's ledger summary reports one completed
    // round with no skips.
    assert_eq!(
        host.thread_run_count().await,
        1,
        "a once cron fires exactly one thread"
    );
    assert!(
        host.wait_cron_round("cr-1", 1, SETTLE).await,
        "cron_state never reported the round"
    );
    let cron = host.cron_state("cr-1").await.expect("cron_state mirrored");
    assert_eq!(cron.task_id, "t-c1");
    assert_eq!(cron.round_count, 1, "one fire ⇒ one round");
    assert_eq!(cron.skipped_count, 0, "a dispatched once skips nothing");
    assert_eq!(cron.last_status.as_deref(), Some("dispatched"));
    assert_eq!(
        cron.status.as_deref(),
        Some("completed"),
        "a once is completed after its single fire"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// §5b #2 — recurring: K interval fires → K isolated threads; round_count == K
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cron_recurring_fires_k_isolated_threads() {
    const K: i64 = 3;
    let host = StubHost::start(json!({})).await;
    let behavior = Behavior::echo_lines("sess-cron2", 2);
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_task_upsert("t-c2", Some("recurring"), Some("job"), None, 1)
        .await;

    // Drive K interval fires deterministically. The period is long (60s) so the cron
    // never self-re-fires between rounds; each round is armed by re-`cron_upsert`ing
    // the due slot to a fresh past instant. The real scheduler fires each in turn,
    // minting a distinct deterministic isolated thread.
    let mut thread_ids = Vec::new();
    for round in 1..=K {
        let (slot, epoch) = past_slot(20 - round); // strictly-increasing distinct slots
        host.push_cron_upsert(
            "t-c2",
            "cr-2",
            &CronSpec {
                prompt: "poll the upstream queue",
                kind: "schedule",
                schedule_type: "interval",
                schedule_value: "60000",
                continuity: "isolated",
                next_run: Some(&slot),
                status: None,
            },
            1 + round,
        )
        .await;
        let tid = isolated_thread_id("cr-2", epoch);
        let run = host
            .wait_thread_terminal(&tid, SETTLE)
            .await
            .unwrap_or_else(|| panic!("round {round}: no thread_result for {tid}"));
        assert_eq!(run.status, "succeeded", "round {round}: {run:?}");
        assert_eq!(run.final_seq, 2, "round {round} final_seq");
        thread_ids.push(tid);
    }

    // K distinct isolated threads ran — host `thread_runs` count matches the rounds.
    assert_eq!(
        host.thread_run_count().await,
        usize::try_from(K).unwrap(),
        "each isolated fire mints its own thread_run"
    );
    for tid in &thread_ids {
        assert!(
            host.thread_run(tid).await.is_some(),
            "missing thread_run for {tid}"
        );
    }

    // The local ledger reached exactly K rounds (no spurious extra fires).
    assert!(
        host.wait_cron_round("cr-2", K, SETTLE).await,
        "cron_state never reached K rounds"
    );
    let cron = host.cron_state("cr-2").await.expect("cron_state mirrored");
    assert_eq!(cron.round_count, K, "cron_logs round_count == K");
    assert_eq!(cron.skipped_count, 0, "isolated fires never skip");
    assert_eq!(cron.last_status.as_deref(), Some("dispatched"));

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// §5b #3 — skip/missed ledger: a stale `once` logs `missed`, mints no thread
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cron_missed_logs_ledger_without_a_thread() {
    let host = StubHost::start(json!({})).await;
    // The echo behaviour is installed but must never run — the fire makes no thread.
    let behavior = Behavior::echo_lines("sess-cron3", 3);
    let runner = RunnerProc::spawn(&host, &behavior).await;
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_task_upsert("t-c3", Some("stale"), Some("job"), None, 1)
        .await;
    // A `once` slot ten minutes overdue — well past the 300s catch-up grace — is an
    // offline catch-up the scheduler logs `missed` rather than running stale.
    let (slot, epoch) = past_slot(600);
    host.push_cron_upsert(
        "t-c3",
        "cr-3",
        &CronSpec {
            prompt: "this instruction must never run",
            kind: "schedule",
            schedule_type: "once",
            schedule_value: &slot,
            continuity: "isolated",
            next_run: Some(&slot),
            status: None,
        },
        2,
    )
    .await;

    // The fire surfaces as a `cron_state` round with a skip — not a `thread_run`.
    assert!(
        host.wait_cron_round("cr-3", 1, SETTLE).await,
        "the missed fire never logged a round"
    );
    let cron = host.cron_state("cr-3").await.expect("cron_state mirrored");
    assert_eq!(cron.round_count, 1, "a missed fire is still a ledger round");
    assert_eq!(cron.skipped_count, 1, "a missed fire bumps the skip tally");
    assert_eq!(cron.last_status.as_deref(), Some("missed"));
    assert_eq!(
        cron.status.as_deref(),
        Some("completed"),
        "a fired once completes even when missed"
    );

    // No spurious thread: the id the fire WOULD have minted is absent, and the host
    // mirrored zero executions.
    let would_be = isolated_thread_id("cr-3", epoch);
    assert!(
        host.thread_run(&would_be).await.is_none(),
        "a missed fire must not create a thread"
    );
    assert_eq!(
        host.thread_run_count().await,
        0,
        "no thread_run for a missed fire"
    );

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// §5b #8 — crash/restart durability: no double-fire / double-run on restart
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cron_crash_restart_no_double_execution() {
    let host = StubHost::start(json!({})).await;
    let behavior = Behavior::echo_lines("sess-cron8", 3);
    // A caller-owned hermetic workspace: it (and its db) survives the first runner's
    // death so the restart reopens the SAME durable state.
    let workspace = Workspace::new().await;
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // Withhold acks so the run's result-plane frames stay unacked in the durable
    // outbox and must replay after the restart (the "unsynced outbox replays" half).
    host.set_auto_ack(false);

    host.push_task_upsert("t-c8", Some("durable"), Some("job"), None, 1)
        .await;
    let (slot, epoch) = past_slot(3);
    host.push_cron_upsert(
        "t-c8",
        "cr-8",
        &CronSpec {
            prompt: "do the durable thing once",
            kind: "schedule",
            schedule_type: "once",
            schedule_value: &slot,
            continuity: "isolated",
            next_run: Some(&slot),
            status: None,
        },
        2,
    )
    .await;

    // The fire runs to a terminal result (unacked) before the crash.
    let tid = isolated_thread_id("cr-8", epoch);
    let run = host
        .wait_thread_terminal(&tid, SETTLE)
        .await
        .expect("no thread_result before the crash");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    assert_eq!(run.final_seq, 3);
    assert!(
        host.wait_message_count("t-c8", &tid, 3, SETTLE).await,
        "expected 3 messages before the crash"
    );
    let recv_before = host.message_recv_count().await;
    let terminals_before = host.thread_run(&tid).await.unwrap().terminal_count;

    // Crash: SIGKILL the runner (its graceful shutdown never runs). The unacked
    // outbox rows are committed in the on-disk WAL db the restart reopens.
    runner.shutdown().await;

    // Restart on the SAME workspace/db, acking again.
    host.set_auto_ack(true);
    let connects = host.ws_connects().await;
    let restarted = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(
        host.wait_connects(connects + 1, SETTLE).await,
        "runner never reconnected after restart"
    );

    // On connect the runner replays its unsynced outbox (at-least-once) — proof the
    // result is durable across the crash. The reconnect re-sends the unacked frames
    // (a fresh WS connect + grown recv count), and the terminal result itself
    // replays (terminal_count grows past the pre-crash value).
    assert!(
        host.wait_reconnect_replay(recv_before, SETTLE).await,
        "the restart never replayed the unsynced frames"
    );
    assert!(
        host.wait_thread_terminal_count(&tid, terminals_before + 1, SETTLE)
            .await,
        "the unsynced thread_result must replay on restart"
    );
    let after = host
        .thread_run(&tid)
        .await
        .expect("thread_run still present");

    // Durability: the deterministic thread id + `cron_logs UNIQUE(cron_id,
    // scheduled_at)` admit no re-fire and no re-run. Still one execution, the
    // transcript de-dups to 3, and the ledger stays at one round.
    assert_eq!(
        host.thread_run_count().await,
        1,
        "restart must not create a second thread_run"
    );
    let seqs: Vec<i64> = host
        .messages_for("t-c8", &tid)
        .await
        .iter()
        .map(|m| m.seq)
        .collect();
    assert_eq!(
        seqs,
        vec![1, 2, 3],
        "replayed messages de-dup on (threadId, seq)"
    );
    assert_eq!(
        after.status, "succeeded",
        "the run stays succeeded across restart"
    );
    let cron = host.cron_state("cr-8").await.expect("cron_state mirrored");
    assert_eq!(
        cron.round_count, 1,
        "the once cron does not re-fire on restart (no double-fire)"
    );

    restarted.shutdown().await;
}

// ===========================================================================
// Engine config & skills provisioning (global + task scope), e2e
// ===========================================================================
//
// These scenarios drive the SAME black-box harness (real binary + StubHost + fake
// `claude`), but the runner owns `GINO_WORKSPACE_DIR` (a temp [`Workspace`] the
// harness controls), so the assertions are on the **on-disk** content-addressed
// store + symlinks the provisioning plane materializes:
//
// * GLOBAL scope → `<ws>/engine-config/<target>` (symlink) ─▶
//   `<ws>/store/<name>/<sha256[:12]>` (file, or unpacked-tar dir).
// * TASK scope → `<ws>/threads/<thread_id>/project/<target>` (symlink), with the
//   isolated git working area `<ws>/threads/<thread_id>/project/workspace/`.
//
// The reconcile engine downloads each entry's bytes from
// `GET /agent/attachments/<entry.id>` and verifies `entry.sha256`, so the harness
// stages a blob whose id == the entry id and whose sha == `sha256_hex(bytes)`
// ([`StubHost::stage_blob`] / [`provisioning_entry`]). The on-disk state is
// materialized asynchronously (startup reconcile lands just after the WS connect; a
// `config_update` re-reconcile lands shortly after the frame), so every fs
// assertion polls with [`wait_until`] up to [`SETTLE`] — no fixed sleeps.

/// The git-style short store id (`sha256[:12]`) — the on-disk `store/<name>/<short>`
/// directory component, derived test-side from the entry bytes.
fn store_short(bytes: &[u8]) -> String {
    sha256_hex(bytes)[..12].to_owned()
}

/// The single per-thread `project/` scope dir under `<ws>/threads/*/` (the task
/// hint prefers globbing over hard-coding the sanitized thread id). `None` until a
/// run has materialized it.
fn first_project_dir(ws: &Path) -> Option<PathBuf> {
    std::fs::read_dir(ws.join("threads"))
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("project"))
        .find(|project| project.is_dir())
}

// ---------------------------------------------------------------------------
// #1 GLOBAL — register-config `entries` (file instruction + dir skill) materialize
// ---------------------------------------------------------------------------

#[tokio::test]
async fn global_provisioning_materializes_file_and_dir() {
    let claude_md = b"# Global CLAUDE.md\nbe helpful\n";
    let skill_tar = build_tar(&[
        ("SKILL.md", b"# demo skill\n"),
        ("scripts/run.sh", b"#!/bin/sh\necho hi\n"),
    ]);
    // Build the global descriptors BEFORE start (register-config carries them
    // verbatim); the sha is pure, so staging the bytes can follow the start.
    let file_entry = provisioning_entry("clauderc", "CLAUDE.md", "file", claude_md);
    let dir_entry = provisioning_entry("demo-skill", "skills/demo", "dir", &skill_tar);
    let host = StubHost::start(json!({ "entries": [file_entry, dir_entry] })).await;
    host.stage_blob("clauderc", claude_md).await;
    host.stage_blob("demo-skill", &skill_tar).await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-glob", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // The startup global reconcile materializes the scope just after connect.
    let engine_config = ws.join("engine-config");
    let claude_link = engine_config.join("CLAUDE.md");
    let skill_md = engine_config.join("skills/demo/SKILL.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink() && skill_md.is_file()).await,
        "global scope never materialized under {engine_config:?}"
    );

    // The instruction is a SYMLINK resolving (through the store) to the staged bytes.
    assert!(
        claude_link.is_symlink(),
        "CLAUDE.md must be a symlink, not a copy"
    );
    assert_eq!(std::fs::read(&claude_link).unwrap(), claude_md);
    // The skill dir symlink resolves into the store dir; its files are reachable.
    assert_eq!(std::fs::read(&skill_md).unwrap(), b"# demo skill\n");
    assert_eq!(
        std::fs::read(engine_config.join("skills/demo/scripts/run.sh")).unwrap(),
        b"#!/bin/sh\necho hi\n"
    );
    assert!(
        engine_config.join("skills/demo").is_symlink(),
        "the skill target must be a symlink into the store"
    );

    // The content-addressed store holds both entries at `store/<name>/<short>`.
    assert!(
        ws.join("store/clauderc")
            .join(store_short(claude_md))
            .is_file(),
        "file store entry missing"
    );
    assert!(
        ws.join("store/demo-skill")
            .join(store_short(&skill_tar))
            .is_dir(),
        "dir store entry missing"
    );

    // Each entry was fetched exactly once on this first boot (the manifest scope is
    // 'global'; a later reconcile hits the store/cache and re-fetches nothing).
    assert_eq!(host.get_count("clauderc").await, 1, "file fetched once");
    assert_eq!(host.get_count("demo-skill").await, 1, "skill fetched once");

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// #3/#4 — config_update repoint (same target, new sha) + reconcile add / remove
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_update_repoints_and_reconciles_add_remove() {
    let v1 = b"VERSION-1 claude\n";
    let skill_tar = build_tar(&[("SKILL.md", b"# demo\n")]);
    let file_v1 = provisioning_entry("clauderc", "CLAUDE.md", "file", v1);
    let dir_entry = provisioning_entry("demo-skill", "skills/demo", "dir", &skill_tar);
    let host = StubHost::start(json!({ "entries": [file_v1, dir_entry.clone()] })).await;
    host.stage_blob("clauderc", v1).await;
    host.stage_blob("demo-skill", &skill_tar).await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-cu", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    let engine_config = ws.join("engine-config");
    let claude_link = engine_config.join("CLAUDE.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink()).await,
        "v1 never materialized"
    );
    assert_eq!(std::fs::read(&claude_link).unwrap(), v1);
    let v1_short = store_short(v1);
    assert!(ws.join("store/clauderc").join(&v1_short).is_file());

    // REPOINT (#3): the SAME target with new bytes/sha. The host re-pushes the FULL
    // desired set under an ADVANCED version (startup applied v1 → this is v2), so the
    // runner's version gate reconciles: repoint the symlink and land a new store
    // version.
    let v2 = b"VERSION-2 claude (repointed)\n";
    let file_v2 = host
        .stage_provisioning_entry("clauderc", "CLAUDE.md", "file", v2)
        .await;
    host.push_config_update(
        json!({ "version": 2, "entries": [file_v2.clone(), dir_entry.clone()] }),
    )
    .await;
    assert!(
        wait_until(SETTLE, {
            let link = claude_link.clone();
            move || std::fs::read(&link).ok().as_deref() == Some(&v2[..])
        })
        .await,
        "symlink never repointed to v2"
    );
    let v2_short = store_short(v2);
    assert!(
        ws.join("store/clauderc").join(&v2_short).is_file(),
        "repoint never landed the new store version"
    );
    // Both store versions persist (no GC without a restart — see the GC scenario).
    assert!(
        ws.join("store/clauderc").join(&v1_short).is_file(),
        "old version kept until GC"
    );

    // ADD (#4): a second global instruction (AGENTS.md) joins the desired set.
    let agents = b"# AGENTS.md\nsecond instruction\n";
    let agents_entry = host
        .stage_provisioning_entry("agentsrc", "AGENTS.md", "file", agents)
        .await;
    host.push_config_update(
        json!({ "version": 3, "entries": [file_v2.clone(), dir_entry.clone(), agents_entry] }),
    )
    .await;
    let agents_link = engine_config.join("AGENTS.md");
    assert!(
        wait_until(SETTLE, || agents_link.is_symlink()).await,
        "added AGENTS.md never materialized"
    );
    assert_eq!(std::fs::read(&agents_link).unwrap(), agents);

    // REMOVE (#4): drop AGENTS.md from the desired set (advanced version) → its
    // symlink is removed.
    host.push_config_update(json!({ "version": 4, "entries": [file_v2, dir_entry] }))
        .await;
    assert!(
        wait_until(SETTLE, || !agents_link.exists()
            && !agents_link.is_symlink())
        .await,
        "removed AGENTS.md symlink lingered"
    );
    // The retained entries still resolve (v2 instruction + the skill).
    assert_eq!(std::fs::read(&claude_link).unwrap(), v2);
    assert!(engine_config.join("skills/demo/SKILL.md").is_file());

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// #5 REFCOUNT-GC — a repoint orphans the old store entry; a restart's startup GC
//    collects it while the referenced version survives.
//
// Exercised on the **task** scope. The GLOBAL desired set is NOT durable across a
// restart: the runner reuses its persisted identity (no second `POST /agent/register`),
// so `config.entries` is empty on restart and the startup global reconcile would
// *remove* every installed global row before GC runs — masking selective GC. The
// task scope is durable (`tasks.entries` column + `config_entries` rows persist, and
// the startup global reconcile only touches `scope='global'`), so a restart's GC
// observes exactly one orphan vs. one referenced entry. `Provisioner::gc` is global
// (it refcounts the whole store across all scopes), so this covers the same code.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gc_collects_unreferenced_task_store_after_restart() {
    let host = StubHost::start(json!({})).await;
    let skill_tar = build_tar(&[("SKILL.md", b"# demo\n")]);
    let v1 = b"task instruction v1\n";
    let instr_v1 = host
        .stage_provisioning_entry("task-claude", "CLAUDE.md", "file", v1)
        .await;
    let skill_entry = host
        .stage_provisioning_entry("foo-skill", ".claude/skills/foo", "dir", &skill_tar)
        .await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-gc", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // Run 1: materialize the task scope with instruction v1.
    host.push_task_upsert_with_entries(
        "t-gc",
        Some("gc"),
        Some("job"),
        Some("active"),
        &[instr_v1, skill_entry.clone()],
        1,
    )
    .await;
    // host-v2 §M4: the host owns conversation continuity, so it supplies the chat
    // `threadId` to drive (and later continue) one stable thread. An absent `threadId`
    // would instead mint a fresh thread per message — see the runner unit tests.
    host.push_message("t-gc", Some("t-gc@chat"), "go", &[], 2)
        .await;
    assert_eq!(
        host.wait_thread_terminal("t-gc@chat", SETTLE)
            .await
            .map(|run| run.status),
        Some("succeeded".to_owned()),
        "run 1 never succeeded"
    );
    let v1_short = store_short(v1);
    assert!(
        ws.join("store/task-claude").join(&v1_short).is_file(),
        "instruction v1 store entry missing after run 1"
    );

    // Run 2: edit the task instruction → v2 (same target), then re-run the chat
    // thread. The per-thread reconcile repoints CLAUDE.md to v2; the v1 store entry
    // is now unreferenced (an orphan kept until GC).
    let v2 = b"task instruction v2 (repointed)\n";
    let instr_v2 = host
        .stage_provisioning_entry("task-claude", "CLAUDE.md", "file", v2)
        .await;
    host.push_task_upsert_with_entries("t-gc", None, None, None, &[instr_v2, skill_entry], 3)
        .await;
    // Same `threadId` → the second turn continues the SAME thread (resumes its session),
    // landing a second terminal on `t-gc@chat`.
    host.push_message("t-gc", Some("t-gc@chat"), "again", &[], 4)
        .await;
    assert!(
        host.wait_thread_terminal_count("t-gc@chat", 2, SETTLE)
            .await,
        "run 2 never produced a second terminal result"
    );
    let v2_short = store_short(v2);
    // Both versions are on disk; the row now references v2 (run 2's result landed,
    // so the repoint's manifest upsert is committed).
    assert!(
        ws.join("store/task-claude").join(&v1_short).is_file(),
        "orphaned v1 store entry must persist until GC"
    );
    assert!(
        ws.join("store/task-claude").join(&v2_short).is_file(),
        "referenced v2 store entry missing after run 2"
    );

    // Restart on the SAME workspace: startup GC refcounts the store against the
    // persisted manifest and collects the unreferenced v1, keeping v2.
    runner.shutdown().await;
    let restarted = RunnerProc::spawn_in(&host, &behavior, &workspace);

    assert!(
        wait_until(SETTLE, || !ws
            .join("store/task-claude")
            .join(&v1_short)
            .exists())
        .await,
        "GC never collected the unreferenced v1 store entry"
    );
    assert!(
        ws.join("store/task-claude").join(&v2_short).is_file(),
        "the referenced v2 store entry must survive GC"
    );

    restarted.shutdown().await;
}

// ---------------------------------------------------------------------------
// #6 RESTART-REPAIR — a deleted symlink is recreated from the present store entry
//    on restart, with no re-fetch (the bytes are already in the store).
//
// On the **task** scope (see the GC scenario for why global is not restart-durable
// black-box): the task `config_entries` rows + store survive a restart, and the
// terminal thread is not re-run, so `Provisioner::repair` — not a fresh reconcile —
// is what recreates the deleted symlink at startup.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_repairs_deleted_task_symlink_without_refetch() {
    let host = StubHost::start(json!({})).await;
    let instruction = b"# repairable task CLAUDE.md\n";
    let skill_tar = build_tar(&[("SKILL.md", b"# demo\n")]);
    let instr_entry = host
        .stage_provisioning_entry("task-claude", "CLAUDE.md", "file", instruction)
        .await;
    let skill_entry = host
        .stage_provisioning_entry("foo-skill", ".claude/skills/foo", "dir", &skill_tar)
        .await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-repair", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    host.push_task_upsert_with_entries(
        "t-repair",
        Some("repair"),
        Some("job"),
        Some("active"),
        &[instr_entry, skill_entry],
        1,
    )
    .await;
    // host-v2 §M4: host supplies the chat `threadId` to drive one stable thread.
    host.push_message("t-repair", Some("t-repair@chat"), "go", &[], 2)
        .await;
    assert_eq!(
        host.wait_thread_terminal("t-repair@chat", SETTLE)
            .await
            .map(|run| run.status),
        Some("succeeded".to_owned()),
        "run never succeeded"
    );

    let project = ws.join("threads").join("t-repair@chat").join("project");
    let claude_link = project.join("CLAUDE.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink()).await,
        "task scope never materialized under {project:?}"
    );
    let fetches_before = host.get_count("task-claude").await;
    assert_eq!(
        fetches_before, 1,
        "instruction fetched once on the first run"
    );

    // Corrupt the materialized scope: delete the instruction symlink. The store
    // entry it pointed at stays present on disk.
    std::fs::remove_file(&claude_link).unwrap();
    assert!(!claude_link.exists() && !claude_link.is_symlink());

    // Restart on the SAME workspace. The terminal thread is not re-run, so startup
    // repair (over the persisted manifest) is what recreates the link.
    runner.shutdown().await;
    let restarted = RunnerProc::spawn_in(&host, &behavior, &workspace);

    assert!(
        wait_until(SETTLE, {
            let link = claude_link.clone();
            move || std::fs::read(&link).ok().as_deref() == Some(&instruction[..])
        })
        .await,
        "repair never recreated the deleted symlink"
    );
    // The store entry was present, so repair did not re-fetch the bytes.
    assert_eq!(
        host.get_count("task-claude").await,
        fetches_before,
        "store entry present → no re-fetch on repair"
    );

    restarted.shutdown().await;
}

// ---------------------------------------------------------------------------
// #2/#7 TASK — task_upsert `data.entries` materialize into the per-thread project/
//    scope; the isolated git working area `project/workspace/` is separate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn task_provisioning_materializes_into_project_and_isolates_workspace() {
    let host = StubHost::start(json!({})).await;
    let instruction = b"# task CLAUDE.md\nproject scope\n";
    let skill_tar = build_tar(&[
        ("SKILL.md", b"# foo skill\n"),
        ("scripts/go.sh", b"echo go\n"),
    ]);
    let instr_entry = host
        .stage_provisioning_entry("task-claude", "CLAUDE.md", "file", instruction)
        .await;
    let skill_entry = host
        .stage_provisioning_entry("foo-skill", ".claude/skills/foo", "dir", &skill_tar)
        .await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-task", 2);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // Seed the task (with entries) BEFORE the message that spawns the chat thread,
    // so the entries are persisted when the run materializes the project scope.
    // (The serve loop processes inbound frames in order, so the upsert's persist
    // completes before the message creates the pending thread.)
    host.push_task_upsert_with_entries(
        "t-task",
        Some("provisioned"),
        Some("job"),
        Some("active"),
        &[instr_entry, skill_entry],
        1,
    )
    .await;
    // host-v2 §M4: host supplies the chat `threadId` to drive one stable thread.
    host.push_message("t-task", Some("t-task@chat"), "hello", &[], 2)
        .await;

    let run = host
        .wait_thread_terminal("t-task@chat", SETTLE)
        .await
        .expect("no thread_result for the chat thread");
    assert_eq!(run.status, "succeeded", "run: {run:?}");

    // The per-thread project/ scope (scope = thread id) materialized the task
    // entries. Glob `<ws>/threads/*/project` to stay robust to id sanitization.
    assert!(
        wait_until(SETTLE, || first_project_dir(&ws).is_some()).await,
        "no per-thread project/ dir under {:?}",
        ws.join("threads")
    );
    let project = first_project_dir(&ws).unwrap();
    let claude_link = project.join("CLAUDE.md");
    let skill_md = project.join(".claude/skills/foo/SKILL.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink() && skill_md.is_file()).await,
        "task project scope never materialized under {project:?}"
    );
    assert_eq!(std::fs::read(&claude_link).unwrap(), instruction);
    assert_eq!(std::fs::read(&skill_md).unwrap(), b"# foo skill\n");

    // #7 WORKSPACE ISOLATION: the isolated git working area `project/workspace/`
    // exists, and the injected config lives in `project/` (the parent), NOT inside
    // `workspace/`.
    let inner_workspace = project.join("workspace");
    assert!(
        inner_workspace.is_dir(),
        "project/workspace/ git area missing"
    );
    assert!(
        !inner_workspace.join("CLAUDE.md").exists(),
        "CLAUDE.md must not leak into project/workspace/"
    );
    assert!(
        !inner_workspace.join(".claude").exists(),
        ".claude must not leak into project/workspace/"
    );

    // `git init` the working area and confirm none of the injected files appear as
    // untracked — they are siblings under `project/`, outside this repo.
    let init_ok = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&inner_workspace)
        .status()
        .is_ok_and(|status| status.success());
    if init_ok {
        let output = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(&inner_workspace)
            .output()
            .unwrap();
        let porcelain = String::from_utf8_lossy(&output.stdout);
        assert!(
            !porcelain.contains("CLAUDE.md") && !porcelain.contains(".claude"),
            "git saw the injected config as untracked: {porcelain:?}"
        );
    }

    runner.shutdown().await;
}

// ---------------------------------------------------------------------------
// #8 PATH-TRAVERSAL — a `target = "../escape"` entry is rejected without escaping
//    the scope root; a sibling valid entry still materializes; the daemon survives.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn path_traversal_global_entry_is_contained_and_daemon_survives() {
    let valid = b"# valid CLAUDE.md\n";
    let evil = b"PWNED\n";
    // VALID entry FIRST so the in-order reconcile materializes it before it aborts
    // on the hostile target (a degrade, not a crash).
    let valid_entry = provisioning_entry("clauderc", "CLAUDE.md", "file", valid);
    let evil_entry = provisioning_entry("evil", "../escape", "file", evil);
    let host = StubHost::start(json!({ "entries": [valid_entry, evil_entry] })).await;
    host.stage_blob("clauderc", valid).await;
    host.stage_blob("evil", evil).await; // staged, but rejected pre-fetch

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-trav", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // The sibling valid entry still materializes.
    let claude_link = ws.join("engine-config/CLAUDE.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink()).await,
        "valid sibling entry never materialized"
    );
    assert_eq!(std::fs::read(&claude_link).unwrap(), valid);

    // Nothing escaped the scope root: `<ws>/engine-config/../escape` == `<ws>/escape`
    // is never created (neither a file nor a symlink).
    let escape = ws.join("escape");
    assert!(
        !escape.exists() && !escape.is_symlink(),
        "traversal target escaped to {escape:?}"
    );
    // The evil entry was rejected fail-fast — before any download.
    assert_eq!(
        host.get_count("evil").await,
        0,
        "an unsafe target must be rejected before any fetch"
    );

    // The daemon stays alive and serving: a normal chat message still runs to a
    // terminal result (a crash would leave this hanging).
    // host-v2 §M4: host supplies the chat `threadId` to drive one stable thread.
    host.push_message("t-live", Some("t-live@chat"), "ping", &[], 1)
        .await;
    let run = host
        .wait_thread_terminal("t-live@chat", SETTLE)
        .await
        .expect("daemon stopped serving after the traversal degrade");
    assert_eq!(run.status, "succeeded", "run after degrade: {run:?}");

    runner.shutdown().await;
}

// ===========================================================================
// GLOBAL config version gate / restart durability, e2e
// ===========================================================================
//
// The fix this lane delivers: a restart reuses the persisted identity (no second
// register), so the register-response config is gone — but the startup
// `GET /agent/config` re-supplies the host's VERSIONED desired set, and the version
// gate reconciles the global scope ONLY when the version advances. The stub serves
// the versioned config on BOTH register and `GET /agent/config`; a test bumps the
// version or takes the config endpoint offline to drive each gate branch.

// ---------------------------------------------------------------------------
// SAME version across a restart → repair-only: global scope survives, no wipe,
// no byte re-fetch. (The bug this lane fixes wiped the scope here.)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_same_global_version_is_durable() {
    let claude_md = b"# Global CLAUDE.md durable\n";
    let skill_tar = build_tar(&[("SKILL.md", b"# demo skill\n")]);
    let file_entry = provisioning_entry("clauderc", "CLAUDE.md", "file", claude_md);
    let dir_entry = provisioning_entry("demo-skill", "skills/demo", "dir", &skill_tar);
    let host = StubHost::start(json!({ "entries": [file_entry, dir_entry] })).await;
    host.stage_blob("clauderc", claude_md).await;
    host.stage_blob("demo-skill", &skill_tar).await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-durable", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    // First boot materializes the global scope; each entry fetched exactly once.
    let engine_config = ws.join("engine-config");
    let claude_link = engine_config.join("CLAUDE.md");
    let skill_md = engine_config.join("skills/demo/SKILL.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink() && skill_md.is_file()).await,
        "global scope never materialized on first boot"
    );
    assert_eq!(
        host.get_count("clauderc").await,
        1,
        "file fetched once on boot"
    );
    assert_eq!(
        host.get_count("demo-skill").await,
        1,
        "skill fetched once on boot"
    );
    let file_short = store_short(claude_md);
    let skill_short = store_short(&skill_tar);
    assert!(ws.join("store/clauderc").join(&file_short).is_file());
    assert!(ws.join("store/demo-skill").join(&skill_short).is_dir());

    // The applied version is persisted after the reconcile commits; killing the
    // daemon before that would leave nothing for the restart to keep.
    assert!(
        wait_until(SETTLE, || workspace.applied_global_version().is_some()).await,
        "applied global version never persisted"
    );

    // RESTART on the SAME workspace; the stub still serves the SAME config version.
    // The version gate takes the repair-only path — no reconcile-to-empty (the old
    // bug, since the register response no longer carries `entries`), no re-fetch.
    runner.shutdown().await;
    let connects = host.ws_connects().await;
    let restarted = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(
        host.wait_connects(connects + 1, SETTLE).await,
        "runner never reconnected"
    );

    // Drive a chat run to a terminal result so the restart's startup sequence (where
    // the old wipe happened) has definitely completed before we assert durability.
    // host-v2 §M4: host supplies the chat `threadId` to drive one stable thread.
    host.push_message("t-durable", Some("t-durable@chat"), "ping", &[], 1)
        .await;
    let run = host
        .wait_thread_terminal("t-durable@chat", SETTLE)
        .await
        .expect("restarted daemon never served");
    assert_eq!(run.status, "succeeded", "run after restart: {run:?}");

    // The global symlinks + store entries survive the restart intact...
    assert!(
        claude_link.is_symlink() && std::fs::read(&claude_link).unwrap() == claude_md,
        "global instruction was wiped on a same-version restart (durability regression)"
    );
    assert!(
        skill_md.is_file(),
        "global skill was wiped on a same-version restart"
    );
    assert!(
        ws.join("store/clauderc").join(&file_short).is_file(),
        "file store entry collected on a same-version restart"
    );
    assert!(
        ws.join("store/demo-skill").join(&skill_short).is_dir(),
        "skill store entry collected on a same-version restart"
    );
    // ...with ZERO additional byte fetches (same version → repair-only, no re-fetch).
    assert_eq!(
        host.get_count("clauderc").await,
        1,
        "no re-fetch of the file on a same-version restart"
    );
    assert_eq!(
        host.get_count("demo-skill").await,
        1,
        "no re-fetch of the skill on a same-version restart"
    );

    restarted.shutdown().await;
}

// ---------------------------------------------------------------------------
// HIGHER version on restart → reconcile: repoint + add are applied; the orphaned
// old store version is GC'd; the applied version advances.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_higher_global_version_reconciles() {
    let v1 = b"GLOBAL v1\n";
    let host = StubHost::start(
        json!({ "entries": [provisioning_entry("clauderc", "CLAUDE.md", "file", v1)] }),
    )
    .await;
    host.stage_blob("clauderc", v1).await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-bump", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    let engine_config = ws.join("engine-config");
    let claude_link = engine_config.join("CLAUDE.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink()).await,
        "v1 never materialized"
    );
    assert_eq!(std::fs::read(&claude_link).unwrap(), v1);
    let v1_short = store_short(v1);
    assert!(ws.join("store/clauderc").join(&v1_short).is_file());
    assert_eq!(host.get_count("clauderc").await, 1);

    // Stop, then ADVANCE the served config: repoint CLAUDE.md to v2 and ADD AGENTS.md,
    // under a BUMPED version. On restart the gate sees version 2 > applied 1 and
    // reconciles the new desired set.
    runner.shutdown().await;
    let v2 = b"GLOBAL v2 (repointed)\n";
    let agents = b"# AGENTS.md added\n";
    host.stage_blob("clauderc", v2).await; // repoint the same logical name to new bytes
    host.stage_blob("agentsrc", agents).await;
    host.set_served_config(json!({ "entries": [
        provisioning_entry("clauderc", "CLAUDE.md", "file", v2),
        provisioning_entry("agentsrc", "AGENTS.md", "file", agents),
    ] }))
    .await;
    assert_eq!(
        host.bump_config_version().await,
        2,
        "served version advanced"
    );

    let connects = host.ws_connects().await;

    let restarted = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(
        host.wait_connects(connects + 1, SETTLE).await,
        "runner never reconnected"
    );

    // The repoint lands v2 and the add materializes AGENTS.md.
    let agents_link = engine_config.join("AGENTS.md");
    assert!(
        wait_until(SETTLE, {
            let claude = claude_link.clone();
            let agents_link = agents_link.clone();
            move || {
                std::fs::read(&claude).ok().as_deref() == Some(&v2[..]) && agents_link.is_symlink()
            }
        })
        .await,
        "version bump never reconciled on restart"
    );
    assert_eq!(std::fs::read(&agents_link).unwrap(), agents);
    let v2_short = store_short(v2);
    assert!(
        ws.join("store/clauderc").join(&v2_short).is_file(),
        "v2 store version missing after the bump reconcile"
    );
    // The orphaned v1 store version is GC'd by the same startup sequence.
    assert!(
        wait_until(SETTLE, || !ws
            .join("store/clauderc")
            .join(&v1_short)
            .exists())
        .await,
        "orphaned v1 store version was not GC'd after the version-bump reconcile"
    );

    restarted.shutdown().await;
}

// ---------------------------------------------------------------------------
// OFFLINE startup fetch (non-200 GET /agent/config) → non-authoritative: the
// installed global set is kept (repair-only), never wiped.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offline_startup_fetch_keeps_installed_global() {
    let claude_md = b"# Global CLAUDE.md offline-durable\n";
    let host = StubHost::start(
        json!({ "entries": [provisioning_entry("clauderc", "CLAUDE.md", "file", claude_md)] }),
    )
    .await;
    host.stage_blob("clauderc", claude_md).await;

    let workspace = Workspace::new().await;
    let ws = workspace.dir().to_path_buf();
    let behavior = Behavior::echo_lines("sess-offline", 1);
    let runner = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    let engine_config = ws.join("engine-config");
    let claude_link = engine_config.join("CLAUDE.md");
    assert!(
        wait_until(SETTLE, || claude_link.is_symlink()).await,
        "global scope never materialized"
    );
    assert_eq!(std::fs::read(&claude_link).unwrap(), claude_md);
    let file_short = store_short(claude_md);
    assert!(ws.join("store/clauderc").join(&file_short).is_file());
    assert_eq!(host.get_count("clauderc").await, 1);

    assert!(
        wait_until(SETTLE, || workspace.applied_global_version().is_some()).await,
        "applied global version never persisted"
    );

    // RESTART with GET /agent/config OFFLINE (non-200). The startup fetch fails →
    // no authoritative version → the gate NEVER reconciles-to-empty: the installed
    // global set is kept (repair-only). (This is the exact path the bug wiped.)
    runner.shutdown().await;
    host.set_config_offline(true).await;
    let connects = host.ws_connects().await;
    let restarted = RunnerProc::spawn_in(&host, &behavior, &workspace);
    assert!(
        host.wait_connects(connects + 1, SETTLE).await,
        "runner never reconnected"
    );

    // Drive a chat run to confirm the restart finished its startup sequence...
    host.push_message("t-offline", Some("t-offline@chat"), "ping", &[], 1)
        .await;
    let run = host
        .wait_thread_terminal("t-offline@chat", SETTLE)
        .await
        .expect("restarted daemon never served");
    assert_eq!(
        run.status, "succeeded",
        "run after offline restart: {run:?}"
    );

    // ...then assert the global scope survived intact (the bug would have wiped it).
    assert!(
        claude_link.is_symlink() && std::fs::read(&claude_link).unwrap() == claude_md,
        "offline startup fetch wiped the installed global set"
    );
    assert!(
        ws.join("store/clauderc").join(&file_short).is_file(),
        "store entry collected after an offline restart"
    );
    assert_eq!(
        host.get_count("clauderc").await,
        1,
        "no re-fetch on an offline restart (repair-only)"
    );

    restarted.shutdown().await;
}

// ---------------------------------------------------------------------------
// Memory: task trees per task, one agent tree, injected on a new session
// ---------------------------------------------------------------------------

/// The task fact the memory scenarios store and look for.
const TASK_MARKER: &str = "memory-marker-7f3a";
/// The agent fact the memory scenarios store and look for.
const AGENT_MARKER: &str = "agent-marker-91c2";
/// The `memory-context` header of the task section.
const TASK_SECTION: &str = "## Task memory";
/// The `memory-context` header of the agent section.
const AGENT_SECTION: &str = "## Agent memory";

/// The memory scenarios' fake `claude`.
fn memory_behavior() -> Behavior {
    Behavior::Memory {
        session_id: "sess-memory".to_owned(),
    }
}

/// Run `prompt` as a new chat thread `thread_id` of `task_id` and return the
/// fake's result text (env markers, then the injected memory context).
async fn memory_run(
    host: &StubHost,
    task_id: &str,
    thread_id: &str,
    prompt: &str,
    msg_id: i64,
) -> String {
    host.push_message(task_id, Some(thread_id), prompt, &[], msg_id)
        .await;
    let run = host
        .wait_thread_terminal(thread_id, SETTLE)
        .await
        .expect("no thread_result mirrored");
    assert_eq!(run.status, "succeeded", "run: {run:?}");
    run.result.unwrap_or_default()
}

fn task_memory_path(ws: &Path, task_id: &str) -> PathBuf {
    ws.join("memory/task").join(task_id)
}

/// Assert the fake saw Claude's auto memory redirected to `<task dir>/claude`
/// and not disabled.
fn assert_auto_memory_redirected(result: &str, ws: &Path, task_id: &str) {
    let expected = format!(
        "{}{}",
        fake_claude::AUTO_MEMORY_DIRECTORY,
        task_memory_path(ws, task_id).join("claude").display()
    );
    assert!(
        result.lines().any(|l| l == expected),
        "{expected}: {result}"
    );
    assert!(
        result.contains(fake_claude::AUTO_MEMORY_ENABLED_UNSET),
        "{result}"
    );
    assert!(
        result.contains(fake_claude::DISABLE_AUTO_MEMORY_UNSET),
        "{result}"
    );
}

/// Assert the fake saw Claude's auto memory disabled by both the setting and
/// the env var, with no redirect.
fn assert_auto_memory_disabled(result: &str) {
    assert!(
        result.contains(fake_claude::AUTO_MEMORY_DISABLED),
        "{result}"
    );
    assert!(
        result.contains(fake_claude::DISABLE_AUTO_MEMORY_SET),
        "{result}"
    );
    assert!(
        result.contains(fake_claude::AUTO_MEMORY_DIRECTORY_UNSET),
        "{result}"
    );
}

fn read_index(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("index.md")).unwrap_or_default()
}

/// Push a `task_upsert` carrying `meta`.
async fn push_task_meta(host: &StubHost, task_id: &str, meta: &Value, msg_id: i64) {
    host.push_frame(&json!({
        "type": "task_upsert",
        "taskId": task_id,
        "data": { "status": "active", "meta": meta },
        "msgId": delivery_id(msg_id),
    }))
    .await;
}

#[tokio::test]
async fn task_memory_reaches_a_new_thread_of_the_same_task_only() {
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let runner = RunnerProc::spawn_in(&host, &memory_behavior(), &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");
    let ws = workspace.dir();

    let first = memory_run(
        &host,
        "t-mem",
        "th-mem-1",
        &format!("remember: {TASK_MARKER}"),
        1,
    )
    .await;
    assert!(first.contains(fake_claude::MEMORY_DIR_SET), "{first}");
    assert_auto_memory_redirected(&first, ws, "t-mem");
    assert!(
        !first.contains(TASK_MARKER),
        "stored after the hook ran: {first}"
    );

    // A second, separate thread of the same task starts a new session.
    let second = memory_run(&host, "t-mem", "th-mem-2", "hello", 2).await;
    assert!(second.contains(TASK_SECTION), "{second}");
    assert!(
        second.contains(TASK_MARKER),
        "the task fact is injected: {second}"
    );
    let task_dir = task_memory_path(ws, "t-mem");
    assert!(read_index(&task_dir).contains(TASK_MARKER));
    assert!(task_dir.join("system/definition.md").is_file());

    // A different task gets its own fresh tree and never sees the fact.
    let other = memory_run(&host, "t-mem-other", "th-mem-3", "hello", 3).await;
    assert!(other.contains(TASK_SECTION), "{other}");
    assert!(!other.contains(TASK_MARKER), "task fact leaked: {other}");
    let other_dir = task_memory_path(ws, "t-mem-other");
    assert!(other_dir.join("index.md").is_file());
    assert!(!read_index(&other_dir).contains(TASK_MARKER));

    // `task_delete` removes the task tree only.
    host.push_frame(&json!({ "type": "task_delete", "taskId": "t-mem", "msgId": delivery_id(4) }))
        .await;
    assert!(
        wait_until(SETTLE, || !task_dir.exists()).await,
        "task_delete kept the task memory dir"
    );
    assert!(other_dir.is_dir());
    assert!(ws.join("memory/agent/index.md").is_file());

    runner.shutdown().await;
}

#[tokio::test]
async fn agent_memory_reaches_other_tasks_without_their_task_facts() {
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let runner = RunnerProc::spawn_in(&host, &memory_behavior(), &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    let first = memory_run(
        &host,
        "t-agent-a",
        "th-agent-a",
        &format!("remember: {TASK_MARKER} remember-agent: {AGENT_MARKER}"),
        1,
    )
    .await;
    assert!(first.contains(fake_claude::AGENT_MEMORY_DIR_SET), "{first}");

    let other = memory_run(&host, "t-agent-b", "th-agent-b", "hello", 2).await;
    let agent_at = other.find(AGENT_SECTION).expect("agent section");
    let task_at = other.find(TASK_SECTION).expect("task section");
    assert!(agent_at < task_at, "agent memory comes first: {other}");
    assert!(other.contains(AGENT_MARKER), "agent fact shared: {other}");
    assert!(!other.contains(TASK_MARKER), "task fact leaked: {other}");
    assert!(read_index(&workspace.dir().join("memory/agent")).contains(AGENT_MARKER));

    runner.shutdown().await;
}

#[tokio::test]
async fn task_memory_off_for_the_runner_creates_and_injects_no_task_tree() {
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let fake_dir = fake_claude::install(&memory_behavior());
    let runner = RunnerProc::spawn_in_with_env(
        &host,
        &workspace,
        fake_dir,
        &[("GINO_TASK_MEMORY", std::ffi::OsStr::new("off"))],
        std::process::Stdio::null(),
    );
    assert!(host.wait_connected(SETTLE).await, "runner never connected");

    let result = memory_run(&host, "t-off", "th-off", "hello", 1).await;
    assert!(result.contains(fake_claude::MEMORY_DIR_UNSET), "{result}");
    assert!(!result.contains(TASK_SECTION), "{result}");
    assert_auto_memory_disabled(&result);
    assert!(
        result.contains(fake_claude::AGENT_MEMORY_DIR_SET),
        "{result}"
    );
    assert!(result.contains(AGENT_SECTION), "{result}");
    assert!(!workspace.dir().join("memory/task").exists());

    runner.shutdown().await;
}

#[tokio::test]
async fn task_meta_memory_off_disables_only_that_task() {
    let host = StubHost::start(json!({})).await;
    let workspace = Workspace::new().await;
    let runner = RunnerProc::spawn_in(&host, &memory_behavior(), &workspace);
    assert!(host.wait_connected(SETTLE).await, "runner never connected");
    let ws = workspace.dir();

    push_task_meta(
        &host,
        "t-meta-p",
        &json!({ "memory": { "task": "off" } }),
        1,
    )
    .await;
    let off = memory_run(&host, "t-meta-p", "th-meta-p", "hello", 2).await;
    assert!(off.contains(fake_claude::MEMORY_DIR_UNSET), "{off}");
    assert!(!off.contains(TASK_SECTION), "{off}");
    assert_auto_memory_disabled(&off);
    assert!(!task_memory_path(ws, "t-meta-p").exists());

    let on = memory_run(&host, "t-meta-q", "th-meta-q", "hello", 3).await;
    assert!(on.contains(fake_claude::MEMORY_DIR_SET), "{on}");
    assert!(on.contains(TASK_SECTION), "{on}");
    assert_auto_memory_redirected(&on, ws, "t-meta-q");
    assert!(task_memory_path(ws, "t-meta-q").join("index.md").is_file());

    runner.shutdown().await;
}
