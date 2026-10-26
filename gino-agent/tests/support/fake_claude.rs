//! The **stub engine** for the §5b e2e harness.
//!
//! The runner's only engine today is the Claude CLI engine
//! (`crate::engine::claude`), which spawns a `claude` binary resolved from `PATH`
//! and drives it over the bkd stream-json control protocol. Rather than reach into
//! the runner's `pub(crate)` `Engine`/`Session` traits (unreachable from an
//! integration-test crate), this module stubs the engine *at the process
//! boundary*: it writes a deterministic `claude` script and the harness prepends
//! its directory to the spawned runner's `PATH`. The script speaks exactly the
//! stream-json lines `crate::engine::claude::events::map_line` parses — a
//! `system/init` (→ `SessionStarted`), zero or more `assistant` text blocks
//! (→ `Output`), and a terminal `result` (→ `Result`) — so a run is fully
//! scripted with no real `claude`, no network and no model.
//!
//! This is the same stubbing strategy as the in-crate `write_fake_claude` smoke
//! test (`src/engine/claude/mod.rs`), lifted into a reusable, behaviour-scripted
//! generator the scenarios drive.
//!
//! Lane I2 extends this (a `Behavior` variant or richer scripting) for the
//! cron-prompt scenarios; the `Behavior` enum is the extension point.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use serde_json::json;
use tempfile::TempDir;

/// A scripted fake-`claude` behaviour. Each spawned `claude` process replays the
/// rendered script once and exits (the executor starts a fresh process per run).
#[derive(Clone, Debug)]
pub enum Behavior {
    /// Emit `system/init` then one `assistant` text block per `lines` entry, then
    /// a successful `result`. Yields one `assistant_text` `thread_message` per
    /// line (ordered `seq` from 1) and a `succeeded` `thread_result`.
    Echo {
        /// The backend session id announced in `system/init` and echoed on
        /// `result` (the thread's `engine_session_id` resume handle).
        session_id: String,
        /// One assistant text block per entry (the transcript the host mirrors).
        lines: Vec<String>,
    },
    /// Emit `system/init`, then go quiet (a bounded `sleep`) without ever
    /// producing a `result` — trips the runner's in-run inactivity watchdog
    /// (`runner.timeout`). The sleep is bounded so an orphaned process cannot
    /// linger; the watchdog kills the session (engine `kill_on_drop`) first.
    Stall {
        /// The backend session id announced in `system/init`.
        session_id: String,
    },
    /// Emit `system/init` then an error `result` whose text is `error`. The
    /// runner's `classify` maps the text to a `FailureReason` (e.g. `"invalid
    /// request"` → `runner.invalid_request`, `"401"` → `agent.provider_auth`,
    /// `"context window"` → `agent.context_overflow`).
    Fail {
        /// The backend session id announced in `system/init`.
        session_id: String,
        /// The error detail carried on the `result` line, fed to `classify`.
        error: String,
    },
    /// Read `../inputs/input.txt` (materialised from an inbound attachment), write
    /// a deterministic `../output/result.txt` (`"processed:" + input`), then
    /// succeed. Exercises the attachment round-trip (materialise → engine reads →
    /// output → upload). The `../` reaches the `inputs/`/`output/` dirs the
    /// attachment plane keeps under the thread `work_dir`: with task provisioning
    /// active the engine cwd is `work_dir/project/`, so those dirs
    /// are siblings of the cwd's parent.
    Attachment {
        /// The backend session id announced in `system/init`.
        session_id: String,
    },
    /// Act on the memory plumbing, then succeed. Without `--resume`, run every
    /// `SessionStart` hook command of the `--settings` JSON whose matcher
    /// includes `startup` (via `sh -c`, inheriting the env) and capture its
    /// stdout. Read the first `user` turn from stdin; a `remember: <token>`
    /// directive appends `<token>` as a line to `$GINO_MEMORY_DIR/index.md`, a
    /// `remember-agent: <token>` one to `$GINO_AGENT_MEMORY_DIR/index.md`. The
    /// `result` text is [`MEMORY_DIR_SET`] or [`MEMORY_DIR_UNSET`], then
    /// [`AGENT_MEMORY_DIR_SET`] or `GINO_AGENT_MEMORY_DIR=unset`, then the
    /// observed auto memory settings — `autoMemoryDirectory=<value|unset>`,
    /// `autoMemoryEnabled=<value|unset>` (from `--settings`) and
    /// `CLAUDE_CODE_DISABLE_AUTO_MEMORY=<value|unset>` (from the env) — each on
    /// its own line, followed by the captured hook output.
    Memory {
        /// The backend session id announced in `system/init`.
        session_id: String,
    },
    /// Write the first `user` turn read from stdin (the prompt as the engine
    /// received it) to [`PROMPT_SEEN_FILE`] in the cwd, then succeed.
    #[allow(dead_code, reason = "not every test crate drives it")]
    Prompt {
        /// The backend session id announced in `system/init`.
        session_id: String,
    },
}

impl Behavior {
    /// Convenience: an [`Behavior::Echo`] with `n` numbered assistant lines.
    #[must_use]
    pub fn echo_lines(session_id: &str, n: usize) -> Self {
        let lines = (1..=n).map(|i| format!("assistant line {i}")).collect();
        Self::Echo {
            session_id: session_id.to_owned(),
            lines,
        }
    }
}

/// The fixed input/output file names the [`Behavior::Attachment`] script uses.
/// The attachment plane keeps `inputs/`/`output/` under the thread `work_dir`,
/// while task provisioning sets the engine cwd to
/// `work_dir/project/`, so the script reaches them via `../inputs`/`../output`.
pub const ATTACHMENT_INPUT_NAME: &str = "input.txt";
/// The output artifact name written by the [`Behavior::Attachment`] script.
pub const ATTACHMENT_OUTPUT_NAME: &str = "result.txt";

/// The deterministic output bytes the attachment script writes for `input`.
#[must_use]
pub fn attachment_output_for(input: &[u8]) -> Vec<u8> {
    let mut out = b"processed:".to_vec();
    out.extend_from_slice(input);
    out
}

/// The file in the engine cwd the [`Behavior::Prompt`] script writes the
/// received `user` turn to.
pub const PROMPT_SEEN_FILE: &str = "prompt-seen.json";

/// The [`Behavior::Memory`] result line when `GINO_MEMORY_DIR` is set.
pub const MEMORY_DIR_SET: &str = "GINO_MEMORY_DIR=set";
/// The [`Behavior::Memory`] result line when `GINO_MEMORY_DIR` is unset.
pub const MEMORY_DIR_UNSET: &str = "GINO_MEMORY_DIR=unset";
/// The [`Behavior::Memory`] result line when `GINO_AGENT_MEMORY_DIR` is set.
pub const AGENT_MEMORY_DIR_SET: &str = "GINO_AGENT_MEMORY_DIR=set";

/// The [`Behavior::Memory`] result line prefix of the `autoMemoryDirectory`
/// setting value.
pub const AUTO_MEMORY_DIRECTORY: &str = "autoMemoryDirectory=";
/// The [`Behavior::Memory`] result line when `autoMemoryDirectory` is unset.
pub const AUTO_MEMORY_DIRECTORY_UNSET: &str = "autoMemoryDirectory=unset";
/// The [`Behavior::Memory`] result line when `autoMemoryEnabled` is `false`.
pub const AUTO_MEMORY_DISABLED: &str = "autoMemoryEnabled=false";
/// The [`Behavior::Memory`] result line when `autoMemoryEnabled` is unset.
pub const AUTO_MEMORY_ENABLED_UNSET: &str = "autoMemoryEnabled=unset";
/// The [`Behavior::Memory`] result line when `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`.
pub const DISABLE_AUTO_MEMORY_SET: &str = "CLAUDE_CODE_DISABLE_AUTO_MEMORY=1";
/// The [`Behavior::Memory`] result line when `CLAUDE_CODE_DISABLE_AUTO_MEMORY`
/// is unset.
pub const DISABLE_AUTO_MEMORY_UNSET: &str = "CLAUDE_CODE_DISABLE_AUTO_MEMORY=unset";

/// The bash body of [`Behavior::Memory`] after `system/init`. The settings JSON
/// is scanned with string matching: the runner writes a single `SessionStart`
/// entry as the last key of `hooks`, so its matcher and commands follow the
/// `"SessionStart":` key. The captured output is JSON-escaped into the
/// `result` line.
const MEMORY_SCRIPT: &str = r#"settings=""
resume=0
prev=""
for a in "$@"; do
  [ "$prev" = --settings ] && settings="$a"
  [ "$a" = --resume ] && resume=1
  prev="$a"
done
setting() {
  case "$settings" in
    *"\"$1\":"*)
      local v="${settings#*\"$1\":}"
      v="${v#\"}"
      printf '%s' "${v%%[\",\}]*}"
      ;;
    *) printf unset ;;
  esac
}
ctx=""
if [ "$resume" = 0 ]; then
  case "$settings" in
    *'"SessionStart":'*)
      seg="${settings#*\"SessionStart\":}"
      matcher="${seg#*\"matcher\":\"}"
      matcher="${matcher%%\"*}"
      case "|$matcher|" in
        *'|startup|'*)
          rest="$seg"
          while [ "${rest#*\"command\":\"}" != "$rest" ]; do
            rest="${rest#*\"command\":\"}"
            ctx="$ctx$(sh -c "${rest%%\"*}" </dev/null)"
          done
          ;;
      esac
      ;;
  esac
fi
prompt=""
while IFS= read -r line; do
  case "$line" in
    *'"type":"user"'*) prompt="$line"; break ;;
  esac
done
token() { local t="${prompt#*"$1"}"; printf '%s\n' "${t%%[\"\\ ]*}"; }
case "$prompt" in
  *'remember: '*) [ -n "${GINO_MEMORY_DIR-}" ] && token 'remember: ' >> "$GINO_MEMORY_DIR/index.md" ;;
esac
case "$prompt" in
  *'remember-agent: '*) [ -n "${GINO_AGENT_MEMORY_DIR-}" ] && token 'remember-agent: ' >> "$GINO_AGENT_MEMORY_DIR/index.md" ;;
esac
out="GINO_MEMORY_DIR=$([ -n "${GINO_MEMORY_DIR-}" ] && echo set || echo unset)
GINO_AGENT_MEMORY_DIR=$([ -n "${GINO_AGENT_MEMORY_DIR-}" ] && echo set || echo unset)
autoMemoryDirectory=$(setting autoMemoryDirectory)
autoMemoryEnabled=$(setting autoMemoryEnabled)
CLAUDE_CODE_DISABLE_AUTO_MEMORY=${CLAUDE_CODE_DISABLE_AUTO_MEMORY-unset}
$ctx"
out="${out//\\/\\\\}"
out="${out//\"/\\\"}"
out="${out//$'\t'/\\t}"
out="${out//$'\n'/\\n}"
"#;

/// A single stream-json stdout line, single-quoted for safe embedding in the bash
/// script (the JSON is built with `serde_json`, so it is always valid).
fn emit(line: &serde_json::Value) -> String {
    let json = line.to_string();
    // POSIX single-quote escaping: close, insert an escaped quote, reopen.
    let quoted = format!("'{}'", json.replace('\'', "'\\''"));
    format!("printf '%s\\n' {quoted}\n")
}

fn init_line(session_id: &str) -> serde_json::Value {
    json!({ "type": "system", "subtype": "init", "session_id": session_id, "model": "stub", "tools": [] })
}

fn assistant_line(text: &str) -> serde_json::Value {
    json!({
        "type": "assistant",
        "message": { "role": "assistant", "content": [ { "type": "text", "text": text } ] }
    })
}

fn success_line(session_id: &str, result: &str) -> serde_json::Value {
    json!({ "type": "result", "subtype": "success", "is_error": false, "result": result, "session_id": session_id })
}

fn error_line(session_id: &str, error: &str) -> serde_json::Value {
    json!({ "type": "result", "subtype": "error", "is_error": true, "result": error, "session_id": session_id })
}

/// Render the bash script body implementing `behavior`.
fn render(behavior: &Behavior) -> String {
    let mut script = String::from("#!/usr/bin/env bash\nset -u\n");
    match behavior {
        Behavior::Echo { session_id, lines } => {
            script.push_str(&emit(&init_line(session_id)));
            for line in lines {
                script.push_str(&emit(&assistant_line(line)));
            }
            script.push_str(&emit(&success_line(session_id, "done")));
        }
        Behavior::Stall { session_id } => {
            script.push_str(&emit(&init_line(session_id)));
            // Bounded so a process the watchdog somehow misses cannot linger.
            script.push_str("sleep 30\n");
        }
        Behavior::Fail { session_id, error } => {
            script.push_str(&emit(&init_line(session_id)));
            script.push_str(&emit(&error_line(session_id, error)));
        }
        Behavior::Attachment { session_id } => {
            use std::fmt::Write as _;
            script.push_str(&emit(&init_line(session_id)));
            // cwd is `work_dir/project/`; the attachment plane keeps
            // `inputs/`/`output/` under `work_dir`, so reach them via `../`.
            script.push_str("mkdir -p ../output\n");
            let _ = writeln!(
                script,
                "c=\"$(cat ../inputs/{ATTACHMENT_INPUT_NAME} 2>/dev/null || true)\""
            );
            let _ = writeln!(
                script,
                "printf 'processed:%s' \"$c\" > ../output/{ATTACHMENT_OUTPUT_NAME}"
            );
            script.push_str(&emit(&assistant_line("wrote output")));
            script.push_str(&emit(&success_line(session_id, "done")));
        }
        Behavior::Memory { session_id } => {
            use std::fmt::Write as _;
            script.push_str(&emit(&init_line(session_id)));
            script.push_str(MEMORY_SCRIPT);
            let _ = writeln!(
                script,
                "printf '{{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"%s\",\"session_id\":\"%s\"}}\\n' \"$out\" '{session_id}'"
            );
        }
        Behavior::Prompt { session_id } => {
            use std::fmt::Write as _;
            script.push_str(&emit(&init_line(session_id)));
            let _ = writeln!(
                script,
                "while IFS= read -r line; do case \"$line\" in *'\"type\":\"user\"'*) printf '%s\\n' \"$line\" > {PROMPT_SEEN_FILE}; break ;; esac; done"
            );
            script.push_str(&emit(&success_line(session_id, "done")));
        }
    }
    script
}

/// Write an executable `claude` script implementing `behavior` into a fresh temp
/// dir and return the dir. The harness prepends `dir.path()` to the runner
/// subprocess `PATH`; the dir (and script) are removed when the returned
/// [`TempDir`] drops.
///
/// # Panics
/// Panics if the script cannot be written or made executable (a broken test
/// environment, never a runner fault).
#[must_use]
pub fn install(behavior: &Behavior) -> TempDir {
    let dir = tempfile::Builder::new()
        .prefix("fake-claude-")
        .tempdir()
        .expect("create fake-claude temp dir");
    let path = dir.path().join("claude");
    let mut file = std::fs::File::create(&path).expect("create fake claude script");
    file.write_all(render(behavior).as_bytes())
        .expect("write fake claude script");
    let mut perms = file
        .metadata()
        .expect("stat fake claude script")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod fake claude script");
    dir
}
