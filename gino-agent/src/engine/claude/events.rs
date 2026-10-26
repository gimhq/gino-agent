//! stream-json line parsing → [`EngineEvent`].
//!
//! Every non-control line on the child's stdout is a stream-json message whose
//! shape mirrors the Claude Agent SDK. This module maps the messages the runner
//! cares about onto engine-agnostic [`EngineEvent`]s:
//!
//! | stdout message              | events                         |
//! |-----------------------------|--------------------------------|
//! | `system` / `init`           | [`EngineEvent::SessionStarted`] (carries `session_id`) |
//! | `assistant`                 | one event per content block, in order: `thinking` → [`EngineEvent::Thinking`], `tool_use` → [`EngineEvent::ToolUse`], all `text` blocks concatenated into one [`EngineEvent::Output`] |
//! | `user`                      | one [`EngineEvent::ToolResult`] per `tool_result` block |
//! | `result`                    | [`EngineEvent::Result`] (error subtypes → [`RunStatus::Error`]); held until `idle` when the CLI reports session state |
//! | `system` / `session_state_changed` | releases the held `Result` on `idle`, else nothing |
//! | `system` / `api_retry`,`hook_*` | [`EngineEvent::Log`]       |
//! | `user` (plain echo), unknown | dropped (empty `Vec`)         |
//!
//! A line's top-level `parent_tool_use_id` attributes EVERY event derived from
//! it to the sub-agent tool call that produced it (`None` = the main agent).
//!
//! Parsing is defensive — missing fields degrade to defaults and a malformed
//! block is skipped, so a single odd line never derails the stream. The consumer
//! persists the session id from `SessionStarted` and maps `Result` onto the host
//! `output` frame.

use serde_json::{Value, json};

use crate::engine::{EngineEvent, LogLevel, RunErrorKind, RunOutcome, RunStatus};

/// Folds a session's stream-json lines into [`EngineEvent`]s, deciding which
/// `result` ends the run.
///
/// One prompt can produce several `result` lines: after a background subagent
/// reports back, the CLI runs another turn and emits another `result`. A CLI
/// that reports session state marks the real end with `session_state_changed`
/// → `idle`, so each `result` is held and only the latest is released then.
/// A CLI that never reports session state has its `result` forwarded at once.
#[derive(Debug, Default)]
pub(super) struct EventMapper {
    /// Whether a `session_state_changed` line has been seen.
    reports_state: bool,
    /// The latest `result`, waiting for `idle`.
    held: Option<RunOutcome>,
}

impl EventMapper {
    /// Map one parsed stdout line to the events it carries, in stream order.
    pub(super) fn map_line(&mut self, value: &Value) -> Vec<EngineEvent> {
        if is_session_state(value) {
            self.reports_state = true;
            if value.get("state").and_then(Value::as_str) == Some("idle") {
                return self.finish().into_iter().collect();
            }
            return Vec::new();
        }
        let events = map_line(value);
        if !self.reports_state {
            return events;
        }
        events
            .into_iter()
            .filter_map(|event| match event {
                EngineEvent::Result(outcome) => {
                    self.held = Some(outcome);
                    None
                }
                other => Some(other),
            })
            .collect()
    }

    /// Release a `result` still held when the child exits.
    pub(super) fn finish(&mut self) -> Option<EngineEvent> {
        self.held.take().map(EngineEvent::Result)
    }
}

/// Whether the line is a `system` / `session_state_changed` message.
fn is_session_state(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("system")
        && value.get("subtype").and_then(Value::as_str) == Some("session_state_changed")
}

/// Map a parsed stdout stream-json line to the [`EngineEvent`]s it carries, in
/// stream order. An empty `Vec` means the line is ignored (a plain `user` prompt
/// echo, an unrecognised type). The caller must have already excluded
/// `control_request`/`control_response` lines.
fn map_line(value: &Value) -> Vec<EngineEvent> {
    let parent = parent_tool_use_id(value);
    match value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "system" => map_system(value).into_iter().collect(),
        "assistant" => map_assistant(value, parent.as_deref()),
        "user" => map_user(value, parent.as_deref()),
        "result" => vec![EngineEvent::Result(map_result(value))],
        _ => Vec::new(),
    }
}

/// The line's sub-agent attribution: the top-level `parent_tool_use_id`, with a
/// missing field or a JSON `null` both meaning "the main agent".
fn parent_tool_use_id(value: &Value) -> Option<String> {
    value
        .get("parent_tool_use_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// `system` messages: `init` carries the session id; everything else
/// (`api_retry`, `hook_*`, …) is a log line.
fn map_system(value: &Value) -> Option<EngineEvent> {
    let subtype = value
        .get("subtype")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if subtype == "init" {
        let session_id = value.get("session_id").and_then(Value::as_str)?.to_owned();
        return Some(EngineEvent::SessionStarted { session_id });
    }
    let level = if subtype == "api_retry" {
        LogLevel::Warn
    } else {
        LogLevel::Debug
    };
    Some(EngineEvent::Log {
        level,
        message: format!("system/{subtype}"),
    })
}

/// `assistant` messages: one event per content block, in block order. All `text`
/// blocks of the message are concatenated into a single [`EngineEvent::Output`]
/// emitted at the position of the FIRST text block; a message with no text block
/// emits no `Output` at all. A `tool_use` block missing its `id` or `name` is
/// skipped, and unknown block types are ignored.
fn map_assistant(value: &Value, parent: Option<&str>) -> Vec<EngineEvent> {
    let Some(blocks) = content_blocks(value) else {
        return Vec::new();
    };
    let text: String = blocks
        .iter()
        .filter(|block| block_type(block) == "text")
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect();

    let mut events = Vec::new();
    let mut text_emitted = false;
    for block in blocks {
        match block_type(block) {
            "thinking" => events.push(EngineEvent::Thinking {
                text: block
                    .get("thinking")
                    .or_else(|| block.get("text"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                parent_tool_use_id: parent.map(str::to_owned),
            }),
            "tool_use" => {
                let (Some(tool_use_id), Some(tool)) = (
                    block.get("id").and_then(Value::as_str),
                    block.get("name").and_then(Value::as_str),
                ) else {
                    continue;
                };
                events.push(EngineEvent::ToolUse {
                    tool_use_id: tool_use_id.to_owned(),
                    tool: tool.to_owned(),
                    input: block.get("input").cloned().unwrap_or(Value::Null),
                    parent_tool_use_id: parent.map(str::to_owned),
                });
            }
            "text" if !text_emitted => {
                text_emitted = true;
                events.push(EngineEvent::Output {
                    text: text.clone(),
                    parent_tool_use_id: parent.map(str::to_owned),
                });
            }
            _ => {}
        }
    }
    events
}

/// `user` messages: the engine echoes tool returns back as `tool_result` blocks.
/// Each becomes an [`EngineEvent::ToolResult`] whose `output` is the frozen
/// `{content, is_error}` shape (protocol §5). A block without a `tool_use_id` is
/// skipped; a plain prompt echo carries no `tool_result` block and yields nothing.
fn map_user(value: &Value, parent: Option<&str>) -> Vec<EngineEvent> {
    let Some(blocks) = content_blocks(value) else {
        return Vec::new();
    };
    blocks
        .iter()
        .filter(|block| block_type(block) == "tool_result")
        .filter_map(|block| {
            let tool_use_id = block.get("tool_use_id").and_then(Value::as_str)?;
            Some(EngineEvent::ToolResult {
                tool_use_id: tool_use_id.to_owned(),
                output: json!({
                    "content": block.get("content").cloned().unwrap_or(Value::Null),
                    "is_error": block
                        .get("is_error")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                }),
                parent_tool_use_id: parent.map(str::to_owned),
            })
        })
        .collect()
}

/// `message.content` when it is an array of blocks, else `None`.
fn content_blocks(value: &Value) -> Option<&Vec<Value>> {
    value
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
}

/// A block's `type`, empty when absent.
fn block_type(block: &Value) -> &str {
    block
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// `result` messages: build the [`RunOutcome`]. A `success` subtype with
/// `is_error != true` is a success; anything else (e.g. `error_max_turns`, or
/// `is_error: true`) is an error carrying the message as its detail.
fn map_result(value: &Value) -> RunOutcome {
    let subtype = value
        .get("subtype")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_error = value
        .get("is_error")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = value
        .get("result")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let session_id = value
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);

    if subtype == "success" && !is_error {
        RunOutcome {
            status: RunStatus::Success,
            result: text,
            session_id,
            error: None,
            error_kind: None,
        }
    } else {
        // The error detail is the result text when present, else the subtype.
        let error = text
            .clone()
            .filter(|s| !s.is_empty())
            .or_else(|| (!subtype.is_empty()).then(|| subtype.to_owned()));
        RunOutcome {
            status: RunStatus::Error,
            result: text,
            session_id,
            error,
            error_kind: error_kind_of(subtype),
        }
    }
}

/// The structured error cause for a non-success `result.subtype`. Exact-match
/// only over the subtypes the CLI emits; anything unrecognised (including a
/// `success` subtype flagged `is_error`) carries no kind and is left to the
/// classifier's conservative fallback.
fn error_kind_of(subtype: &str) -> Option<RunErrorKind> {
    match subtype {
        "error_max_turns" => Some(RunErrorKind::MaxTurns),
        "error_during_execution" => Some(RunErrorKind::Execution),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{EventMapper, map_line};
    use crate::engine::{EngineEvent, LogLevel, RunErrorKind, RunStatus};

    fn result_line(text: &str) -> Value {
        json!({ "type": "result", "subtype": "success", "is_error": false, "result": text })
    }

    fn state_line(state: &str) -> Value {
        json!({ "type": "system", "subtype": "session_state_changed", "state": state })
    }

    fn result_text(event: Option<EngineEvent>) -> Option<String> {
        match event {
            Some(EngineEvent::Result(outcome)) => outcome.result,
            other => panic!("expected a result event, got {other:?}"),
        }
    }

    #[test]
    fn result_is_forwarded_at_once_when_the_cli_reports_no_session_state() {
        let mut mapper = EventMapper::default();
        let mut events = mapper.map_line(&result_line("all done"));
        assert_eq!(events.len(), 1);
        assert_eq!(result_text(events.pop()).as_deref(), Some("all done"));
        assert!(mapper.finish().is_none());
    }

    #[test]
    fn result_is_held_until_the_session_goes_idle() {
        let mut mapper = EventMapper::default();
        assert!(mapper.map_line(&state_line("running")).is_empty());
        assert!(
            mapper
                .map_line(&result_line("subagent still running"))
                .is_empty()
        );
        // The CLI starts another turn on the subagent's report.
        assert_eq!(
            mapper.map_line(&json!({ "type": "system", "subtype": "init", "session_id": "s" })),
            vec![EngineEvent::SessionStarted {
                session_id: "s".to_owned()
            }]
        );
        assert!(mapper.map_line(&result_line("the answer is 4")).is_empty());

        let mut events = mapper.map_line(&state_line("idle"));
        assert_eq!(events.len(), 1);
        assert_eq!(
            result_text(events.pop()).as_deref(),
            Some("the answer is 4")
        );
        assert!(mapper.finish().is_none());
    }

    #[test]
    fn idle_without_a_result_emits_nothing() {
        let mut mapper = EventMapper::default();
        assert!(mapper.map_line(&state_line("running")).is_empty());
        assert!(mapper.map_line(&state_line("idle")).is_empty());
    }

    #[test]
    fn finish_releases_a_result_held_when_the_child_exits() {
        let mut mapper = EventMapper::default();
        mapper.map_line(&state_line("running"));
        assert!(mapper.map_line(&result_line("all done")).is_empty());
        assert_eq!(result_text(mapper.finish()).as_deref(), Some("all done"));
        assert!(mapper.finish().is_none());
    }

    #[test]
    fn init_becomes_session_started() {
        let value = json!({
            "type": "system", "subtype": "init",
            "session_id": "sess-abc", "model": "claude-opus-4-8", "tools": []
        });
        assert_eq!(
            map_line(&value),
            vec![EngineEvent::SessionStarted {
                session_id: "sess-abc".to_owned()
            }]
        );
    }

    #[test]
    fn init_without_session_id_is_dropped() {
        let value = json!({ "type": "system", "subtype": "init" });
        assert!(map_line(&value).is_empty());
    }

    #[test]
    fn api_retry_is_a_warn_log() {
        let value = json!({ "type": "system", "subtype": "api_retry", "attempt": 2 });
        assert_eq!(
            map_line(&value),
            vec![EngineEvent::Log {
                level: LogLevel::Warn,
                message: "system/api_retry".to_owned()
            }]
        );
    }

    #[test]
    fn hook_events_are_debug_logs() {
        let value = json!({ "type": "system", "subtype": "hook_started" });
        let events = map_line(&value);
        let [EngineEvent::Log { level, message }] = events.as_slice() else {
            panic!("expected a log event");
        };
        assert_eq!(*level, LogLevel::Debug);
        assert_eq!(message, "system/hook_started");
    }

    #[test]
    fn successful_result_carries_text_and_session() {
        let value = json!({
            "type": "result", "subtype": "success", "is_error": false,
            "result": "all done", "session_id": "sess-abc"
        });
        let events = map_line(&value);
        let [EngineEvent::Result(outcome)] = events.as_slice() else {
            panic!("expected a result event");
        };
        assert_eq!(outcome.status, RunStatus::Success);
        assert_eq!(outcome.result.as_deref(), Some("all done"));
        assert_eq!(outcome.session_id.as_deref(), Some("sess-abc"));
        assert!(outcome.error.is_none());
        assert!(outcome.error_kind.is_none());
    }

    #[test]
    fn success_prose_never_carries_an_error_kind() {
        // The audit's false positives: error-looking prose ("took 1500ms",
        // "400") in a successful result must not surface a structured cause.
        let value = json!({
            "type": "result", "subtype": "success", "is_error": false,
            "result": "the request took 1500ms and returned 400 rows"
        });
        let events = map_line(&value);
        let [EngineEvent::Result(outcome)] = events.as_slice() else {
            panic!("expected a result event");
        };
        assert_eq!(outcome.status, RunStatus::Success);
        assert!(outcome.error_kind.is_none());
    }

    #[test]
    fn error_subtypes_map_to_structured_kinds() {
        let cases = [
            ("error_max_turns", Some(RunErrorKind::MaxTurns)),
            ("error_during_execution", Some(RunErrorKind::Execution)),
            ("error_never_heard_of", None),
        ];
        for (subtype, kind) in cases {
            let value = json!({ "type": "result", "subtype": subtype, "is_error": true });
            let events = map_line(&value);
            let [EngineEvent::Result(outcome)] = events.as_slice() else {
                panic!("expected a result event for {subtype}");
            };
            assert_eq!(outcome.status, RunStatus::Error, "{subtype}");
            assert_eq!(outcome.error_kind, kind, "{subtype}");
        }
    }

    #[test]
    fn error_subtype_result_is_an_error_outcome() {
        let value = json!({
            "type": "result", "subtype": "error_max_turns",
            "is_error": true, "session_id": "sess-abc"
        });
        let events = map_line(&value);
        let [EngineEvent::Result(outcome)] = events.as_slice() else {
            panic!("expected a result event");
        };
        assert_eq!(outcome.status, RunStatus::Error);
        assert_eq!(outcome.error.as_deref(), Some("error_max_turns"));
        assert_eq!(outcome.session_id.as_deref(), Some("sess-abc"));
        assert_eq!(outcome.error_kind, Some(RunErrorKind::MaxTurns));
    }

    #[test]
    fn is_error_flag_overrides_success_subtype() {
        let value = json!({
            "type": "result", "subtype": "success", "is_error": true,
            "result": "tool failure"
        });
        let events = map_line(&value);
        let [EngineEvent::Result(outcome)] = events.as_slice() else {
            panic!("expected a result event");
        };
        assert_eq!(outcome.status, RunStatus::Error);
        assert_eq!(outcome.error.as_deref(), Some("tool failure"));
        assert!(
            outcome.error_kind.is_none(),
            "a success subtype flagged is_error has no structured cause"
        );
    }

    #[test]
    fn assistant_blocks_map_in_order() {
        let value = json!({
            "type": "assistant",
            "message": { "role": "assistant", "content": [
                { "type": "thinking", "thinking": "let me look" },
                { "type": "text", "text": "Hello" },
                { "type": "tool_use", "id": "tu-1", "name": "Bash",
                  "input": { "command": "ls" } }
            ]}
        });
        assert_eq!(
            map_line(&value),
            vec![
                EngineEvent::Thinking {
                    text: "let me look".to_owned(),
                    parent_tool_use_id: None,
                },
                EngineEvent::Output {
                    text: "Hello".to_owned(),
                    parent_tool_use_id: None,
                },
                EngineEvent::ToolUse {
                    tool_use_id: "tu-1".to_owned(),
                    tool: "Bash".to_owned(),
                    input: json!({ "command": "ls" }),
                    parent_tool_use_id: None,
                },
            ]
        );
    }

    #[test]
    fn assistant_text_blocks_are_concatenated_into_one_output() {
        let value = json!({
            "type": "assistant",
            "message": { "role": "assistant", "content": [
                { "type": "text", "text": "Hello " },
                { "type": "tool_use", "id": "tu-1", "name": "Bash", "input": {} },
                { "type": "text", "text": "world" }
            ]}
        });
        let events = map_line(&value);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, EngineEvent::Output { .. }))
                .count(),
            1
        );
        // Emitted at the position of the FIRST text block, carrying the whole
        // concatenation.
        assert_eq!(
            events[0],
            EngineEvent::Output {
                text: "Hello world".to_owned(),
                parent_tool_use_id: None,
            }
        );
    }

    #[test]
    fn tool_use_only_assistant_message_emits_no_output() {
        let value = json!({
            "type": "assistant",
            "message": { "role": "assistant", "content": [
                { "type": "tool_use", "id": "tu-1", "name": "Read", "input": { "p": 1 } }
            ]}
        });
        assert_eq!(
            map_line(&value),
            vec![EngineEvent::ToolUse {
                tool_use_id: "tu-1".to_owned(),
                tool: "Read".to_owned(),
                input: json!({ "p": 1 }),
                parent_tool_use_id: None,
            }]
        );
    }

    #[test]
    fn malformed_tool_use_block_is_skipped() {
        let value = json!({
            "type": "assistant",
            "message": { "role": "assistant", "content": [
                { "type": "tool_use", "name": "Bash", "input": {} },
                { "type": "tool_use", "id": "tu-2" },
                { "type": "text", "text": "ok" }
            ]}
        });
        assert_eq!(
            map_line(&value),
            vec![EngineEvent::Output {
                text: "ok".to_owned(),
                parent_tool_use_id: None,
            }]
        );
    }

    #[test]
    fn user_tool_result_becomes_a_tool_result_event() {
        let value = json!({
            "type": "user",
            "message": { "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "tu-1", "content": "file listing" }
            ]}
        });
        assert_eq!(
            map_line(&value),
            vec![EngineEvent::ToolResult {
                tool_use_id: "tu-1".to_owned(),
                output: json!({ "content": "file listing", "is_error": false }),
                parent_tool_use_id: None,
            }]
        );
    }

    #[test]
    fn tool_result_error_flag_propagates() {
        let value = json!({
            "type": "user",
            "message": { "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "tu-1",
                  "content": [{ "type": "text", "text": "boom" }], "is_error": true }
            ]}
        });
        assert_eq!(
            map_line(&value),
            vec![EngineEvent::ToolResult {
                tool_use_id: "tu-1".to_owned(),
                output: json!({
                    "content": [{ "type": "text", "text": "boom" }],
                    "is_error": true
                }),
                parent_tool_use_id: None,
            }]
        );
    }

    #[test]
    fn tool_result_without_a_tool_use_id_is_skipped() {
        let value = json!({
            "type": "user",
            "message": { "role": "user", "content": [
                { "type": "tool_result", "content": "orphan" }
            ]}
        });
        assert!(map_line(&value).is_empty());
    }

    #[test]
    fn parent_tool_use_id_attributes_every_event_of_the_line() {
        let value = json!({
            "type": "assistant",
            "parent_tool_use_id": "tu-parent",
            "message": { "role": "assistant", "content": [
                { "type": "thinking", "thinking": "sub" },
                { "type": "text", "text": "hi" },
                { "type": "tool_use", "id": "tu-3", "name": "Grep", "input": {} }
            ]}
        });
        let events = map_line(&value);
        assert_eq!(events.len(), 3);
        for event in &events {
            let parent = match event {
                EngineEvent::Thinking {
                    parent_tool_use_id, ..
                }
                | EngineEvent::Output {
                    parent_tool_use_id, ..
                }
                | EngineEvent::ToolUse {
                    parent_tool_use_id, ..
                } => parent_tool_use_id.as_deref(),
                other => panic!("unexpected event {other:?}"),
            };
            assert_eq!(parent, Some("tu-parent"));
        }

        let sub_result = json!({
            "type": "user",
            "parent_tool_use_id": "tu-parent",
            "message": { "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "tu-3", "content": "hits" }
            ]}
        });
        assert_eq!(
            map_line(&sub_result),
            vec![EngineEvent::ToolResult {
                tool_use_id: "tu-3".to_owned(),
                output: json!({ "content": "hits", "is_error": false }),
                parent_tool_use_id: Some("tu-parent".to_owned()),
            }]
        );
    }

    #[test]
    fn null_parent_tool_use_id_means_the_main_agent() {
        let value = json!({
            "type": "assistant",
            "parent_tool_use_id": Value::Null,
            "message": { "role": "assistant", "content": [
                { "type": "text", "text": "top level" }
            ]}
        });
        assert_eq!(
            map_line(&value),
            vec![EngineEvent::Output {
                text: "top level".to_owned(),
                parent_tool_use_id: None,
            }]
        );
    }

    #[test]
    fn echoed_user_prompt_and_unknown_lines_are_dropped() {
        // A plain prompt echo: content blocks, but no `tool_result` among them.
        assert!(
            map_line(&json!({
                "type": "user",
                "message": { "role": "user", "content": [{ "type": "text", "text": "go" }] }
            }))
            .is_empty()
        );
        assert!(map_line(&json!({ "type": "user", "message": {} })).is_empty());
        assert!(map_line(&json!({ "type": "stream_event" })).is_empty());
    }
}
