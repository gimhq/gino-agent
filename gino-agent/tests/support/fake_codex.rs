//! The **stub codex engine** for the e2e harness — the codex twin of
//! [`super::fake_claude`].
//!
//! The runner's codex backend spawns a `codex` binary resolved from `PATH`
//! (`crate::engine::codex`), writes the prompt to its stdin, closes the pipe and
//! reads JSONL `ThreadEvent`s off stdout. This module stubs that backend at the
//! same process boundary the claude fake uses: it renders a deterministic `codex`
//! script into a directory the harness prepends to the spawned runner's `PATH`.
//!
//! Installing the script is also what ENABLES the backend: the runner registers
//! the codex engine (and advertises the capability) only when a stat-only probe
//! finds the configured binary on `PATH`, so a scenario that wants codex must
//! install this fake, and every other scenario keeps running claude-only.
//!
//! One scripted behaviour is enough for the codex scenario, so there is no
//! `Behavior` enum here — [`install_into`] renders the single sequence below,
//! parameterised by the thread id it announces:
//!
//! 1. `thread.started` — the resume handle, mirrored as `engine_session_id`
//! 2. `turn.started`
//! 3. `item.completed` `reasoning` → a `thinking` transcript row
//! 4. `item.started` `command_execution` → a `tool_use` row
//! 5. `item.completed` for the SAME id → the matching `tool_result` row
//! 6. `item.completed` `agent_message` echoing the prompt → an `assistant_text` row
//! 7. `turn.completed` → a successful `thread_result`
//!
//! The script also appends its own argv to [`ARGV_LOG`] inside the install dir,
//! so a scenario can assert WHICH backend spawned the turn (codex's `exec
//! --json`, never a claude flag).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::json;

/// The reasoning text the script emits, mirrored as the `thinking` row content.
pub const THINKING: &str = "fake codex thinking";
/// The item kind of the scripted tool call — also the transcript `tool` name,
/// since the codex mapper forwards the item kind verbatim.
pub const TOOL: &str = "command_execution";
/// The scripted tool call's item id, echoed as `tool_use_id` on both the
/// `tool_use` and its matching `tool_result`.
pub const TOOL_USE_ID: &str = "item_cmd_1";
/// The command the scripted tool call reports (carried in the forwarded payload).
pub const COMMAND: &str = "echo hello";
/// The prefix the scripted `agent_message` wraps the echoed prompt in.
pub const ECHO_PREFIX: &str = "codex echo: ";
/// The argv-record file name, written inside the install dir (one argument per
/// line, appended per spawn).
pub const ARGV_LOG: &str = "codex-argv.log";

/// The argv-record path for a dir [`install_into`] was given.
#[must_use]
pub fn argv_log(dir: &Path) -> PathBuf {
    dir.join(ARGV_LOG)
}

/// The arguments the fake `codex` was spawned with, in order, across every spawn.
/// Empty when the script never ran.
#[must_use]
pub fn recorded_argv(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(argv_log(dir))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A single JSONL stdout line, single-quoted for safe embedding in the bash
/// script (the JSON is built with `serde_json`, so it is always valid).
fn emit(line: &serde_json::Value) -> String {
    let json = line.to_string();
    // POSIX single-quote escaping: close, insert an escaped quote, reopen.
    let quoted = format!("'{}'", json.replace('\'', "'\\''"));
    format!("printf '%s\\n' {quoted}\n")
}

/// Render the bash script body announcing `thread_id`.
fn render(thread_id: &str, argv_log: &Path) -> String {
    let mut script = String::from("#!/usr/bin/env bash\nset -u\n");
    // Record the argv (one argument per line) so a scenario can prove the codex
    // backend, not the default one, spawned the turn.
    let _ = writeln!(script, "printf '%s\\n' \"$@\" >> '{}'", argv_log.display());
    // The prompt: read to EOF (the runner writes it then closes the pipe).
    // `tr` keeps a conservative ASCII subset so the echoed text is always valid
    // inside the JSON literal below without a JSON encoder in the script.
    script.push_str("prompt=\"$(cat | tr -cd 'A-Za-z0-9 _.:-')\"\n");

    script.push_str(&emit(
        &json!({ "type": "thread.started", "thread_id": thread_id }),
    ));
    script.push_str(&emit(&json!({ "type": "turn.started" })));
    script.push_str(&emit(&json!({
        "type": "item.completed",
        "item": { "id": "item_reasoning_1", "item_type": "reasoning", "text": THINKING },
    })));
    script.push_str(&emit(&json!({
        "type": "item.started",
        "item": { "id": TOOL_USE_ID, "item_type": TOOL, "command": COMMAND },
    })));
    script.push_str(&emit(&json!({
        "type": "item.completed",
        "item": {
            "id": TOOL_USE_ID,
            "item_type": TOOL,
            "command": COMMAND,
            "exit_code": 0,
            "aggregated_output": "hello",
        },
    })));
    // The one line built by hand: `%s` interpolates the prompt the script just
    // read, which no compile-time `serde_json` value can carry.
    let _ = writeln!(
        script,
        "printf '{{\"type\":\"item.completed\",\"item\":{{\"id\":\"item_msg_1\",\"item_type\":\"agent_message\",\"text\":\"{ECHO_PREFIX}%s\"}}}}\\n' \"$prompt\""
    );
    script.push_str(&emit(&json!({ "type": "turn.completed" })));
    script
}

/// Write an executable `codex` script announcing `thread_id` into `dir` (a
/// directory the harness puts first on the runner's `PATH`, shared with the fake
/// `claude` so both backends are spawnable in one scenario).
///
/// # Panics
/// Panics if the script cannot be written or made executable (a broken test
/// environment, never a runner fault).
pub fn install_into(dir: &Path, thread_id: &str) {
    let path = dir.join("codex");
    let mut file = std::fs::File::create(&path).expect("create fake codex script");
    file.write_all(render(thread_id, &argv_log(dir)).as_bytes())
        .expect("write fake codex script");
    let mut perms = file
        .metadata()
        .expect("stat fake codex script")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod fake codex script");
}
