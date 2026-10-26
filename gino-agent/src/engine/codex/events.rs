//! `codex exec --json` JSONL line parsing → [`EngineEvent`].
//!
//! Each stdout line is one `ThreadEvent`, tagged by a top-level `type`. This
//! module maps the ones the runner needs onto engine-agnostic [`EngineEvent`]s:
//!
//! | JSONL `type`      | events                                              |
//! |-------------------|-----------------------------------------------------|
//! | `thread.started`  | [`EngineEvent::SessionStarted`] (carries `thread_id`)|
//! | `turn.completed`  | [`EngineEvent::Result`] — success                   |
//! | `turn.failed`     | [`EngineEvent::Result`] — error                     |
//! | `error`           | [`EngineEvent::Log`] — warn (a retry notice, not terminal) |
//! | `item.started`    | [`EngineEvent::ToolUse`] for a tool-ish item        |
//! | `item.updated`    | dropped (empty `Vec`)                               |
//! | `item.completed`  | [`EngineEvent::Output`] / [`EngineEvent::Thinking`] / [`EngineEvent::ToolResult`] / [`EngineEvent::Log`] |
//! | anything else     | dropped (empty `Vec`)                               |
//!
//! DECISION: THE MAPPER IS STATEFUL. Codex spreads one turn's outcome across
//! several lines: `thread.started` carries the thread id (the resume handle) and
//! nothing else, while the terminal `turn.completed` repeats neither the id nor
//! the assistant's final text. The runner's [`RunOutcome`] needs both in one
//! place, so the mapper remembers the id and the last assistant message as the
//! lines go by and folds them into the terminal event.
//!
//! Parsing is defensive throughout, mirroring the claude mapper: an unknown
//! `type` and a missing or wrongly-typed field are DROPPED, never turned into a
//! failure. A malformed line must not derail a turn that is otherwise fine.
//!
//! ## The item events
//!
//! An item is one unit of turn work — an assistant message, a reasoning block,
//! a tool call — and codex reports its life cycle as `item.started`,
//! `item.updated` and `item.completed`, each wrapping the item under `item`.
//! The item's kind is `item.item_type`, with older/looser payloads spelling it
//! `item.type`; both are read, `item_type` first.
//!
//! DECISION: ONLY THE TERMINAL FRAME IS FORWARDED. `item.started` emits the
//! [`EngineEvent::ToolUse`] that opens a tool call, `item.completed` emits the
//! content or the tool return, and `item.updated` emits NOTHING: streaming
//! updates would turn one logical item into several duplicate transcript frames
//! for the host to deduplicate, and the completed frame already carries the
//! final content.
//!
//! DECISION: TOOL NAMES AND PAYLOADS ARE PASSED THROUGH, NOT TRANSLATED. A tool
//! event's `tool` is the codex item kind verbatim (`"command_execution"`,
//! `"file_change"`, …) and its payload is the whole item object minus the
//! envelope keys. Aliasing kinds onto claude's tool names would make the
//! transcript claim codex did something it did not, and the host cannot undo
//! that; forwarding the whole item degrades gracefully across the per-kind and
//! per-version field churn a hand-picked field list would silently lose.
//!
//! DECISION: `parent_tool_use_id` IS ALWAYS `None` HERE. The field means "this
//! was produced inside another tool call", and codex reports no such linkage for
//! its sub-agent-style calls. Inventing one would corrupt the host's
//! attribution, so codex events are all attributed to the main agent.

use serde_json::{Value, json};

use crate::engine::{EngineEvent, LogLevel, RunErrorKind, RunOutcome, RunStatus};

/// The fallback error text for a failed turn whose payload carries nothing
/// readable — an error [`RunOutcome`] must never surface an empty reason.
const UNKNOWN_FAILURE: &str = "codex reported a failed turn";

/// The item kinds that stand for a tool call: these get an [`EngineEvent::ToolUse`]
/// when they start and an [`EngineEvent::ToolResult`] when they complete. Every
/// other kind is content (or bookkeeping) and is handled on completion only.
const TOOL_KINDS: [&str; 5] = [
    "command_execution",
    "file_change",
    "mcp_tool_call",
    "collab_tool_call",
    "web_search",
];

/// Item keys that describe the envelope rather than the call. Stripped from
/// every forwarded payload so a `ToolUse` input and a `ToolResult` content hold
/// the call's own fields and nothing else — the id and the kind already travel
/// as `tool_use_id` and `tool`.
const ENVELOPE_KEYS: [&str; 3] = ["id", "item_type", "type"];

/// Folds a codex JSONL stream into [`EngineEvent`]s, carrying the cross-line
/// state (§the module note) the terminal events need.
#[derive(Debug, Default)]
pub(super) struct EventMapper {
    /// The thread id from `thread.started`, reported on every [`RunOutcome`] as
    /// the session id the next turn resumes from.
    thread_id: Option<String>,
    /// The assistant's most recent final text, reported as a successful turn's
    /// result. Written by every completed `agent_message` item, so the LAST one
    /// of the turn is the one the terminal event reports.
    last_message: Option<String>,
}

impl EventMapper {
    /// A mapper for one child process (one turn).
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Map one parsed JSONL `ThreadEvent` to the events it carries, in order.
    /// An empty `Vec` means "carries nothing" — an unknown `type` is DROPPED
    /// defensively, never a parse failure, mirroring the claude mapper.
    pub(super) fn map_line(&mut self, value: &Value) -> Vec<EngineEvent> {
        match value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "thread.started" => self.thread_started(value).into_iter().collect(),
            "turn.completed" => vec![EngineEvent::Result(RunOutcome {
                status: RunStatus::Success,
                result: self.last_message.clone(),
                session_id: self.thread_id.clone(),
                error: None,
                error_kind: None,
            })],
            "turn.failed" => vec![self.failure(value.get("error"))],
            // A stream-level `error` is a notice (e.g. "Reconnecting...") and
            // the turn keeps running; a fatal one is followed by `turn.failed`.
            "error" => vec![EngineEvent::Log {
                level: LogLevel::Warn,
                message: error_message(Some(value)),
            }],
            "item.started" => item_started(value),
            "item.completed" => self.item_completed(value),
            // Everything else, `item.updated` included, carries nothing the host
            // needs: a streaming update would turn one logical item into several
            // duplicate transcript frames, and the completed frame already has
            // the final content (§the module note).
            _ => Vec::new(),
        }
    }

    /// Capture the resume handle and announce the session. A missing or
    /// non-string `thread_id` captures nothing and emits nothing — resuming a
    /// thread whose id we never learned is not possible, and inventing one would
    /// be worse than running the next turn fresh.
    fn thread_started(&mut self, value: &Value) -> Option<EngineEvent> {
        let thread_id = value.get("thread_id").and_then(Value::as_str)?.to_owned();
        self.thread_id = Some(thread_id.clone());
        Some(EngineEvent::SessionStarted {
            session_id: thread_id,
        })
    }

    /// `item.completed`: the item's content, or a tool call's return.
    ///
    /// - `agent_message` → [`EngineEvent::Output`], and the text is remembered
    ///   as [`Self::last_message`] so the turn's terminal event reports it.
    /// - `reasoning` → [`EngineEvent::Thinking`].
    /// - a tool kind → [`EngineEvent::ToolResult`] carrying the frozen
    ///   `{content, is_error}` shape (protocol §5).
    /// - `error` → an error [`EngineEvent::Log`] and NOTHING ELSE. An error item
    ///   is not a terminal event: the turn still ends with its own `turn.failed`
    ///   or `turn.completed`, and emitting a second [`EngineEvent::Result`] here
    ///   would report the run twice.
    /// - `todo_list` → nothing. DECISION: a todo list is engine bookkeeping, not
    ///   a tool call or assistant output, so forwarding it would put non-content
    ///   noise in the host transcript.
    ///
    /// A non-object item, a missing `item`, an unknown kind and an item whose
    /// content field is missing or wrongly typed all emit nothing.
    fn item_completed(&mut self, value: &Value) -> Vec<EngineEvent> {
        let Some(item) = value.get("item").filter(|item| item.is_object()) else {
            return Vec::new();
        };
        match item_kind(item) {
            "agent_message" => {
                let Some(text) = item.get("text").and_then(Value::as_str) else {
                    return Vec::new();
                };
                self.last_message = Some(text.to_owned());
                vec![EngineEvent::Output {
                    text: text.to_owned(),
                    parent_tool_use_id: None,
                }]
            }
            "reasoning" => reasoning_text(item)
                .map(|text| EngineEvent::Thinking {
                    text,
                    parent_tool_use_id: None,
                })
                .into_iter()
                .collect(),
            // A result nothing can be matched to is worse than no result, so an
            // id-less tool item is dropped exactly as it is on `item.started`.
            kind if TOOL_KINDS.contains(&kind) => {
                let Some(tool_use_id) = item.get("id").and_then(Value::as_str) else {
                    return Vec::new();
                };
                vec![EngineEvent::ToolResult {
                    tool_use_id: tool_use_id.to_owned(),
                    output: json!({
                        "content": item_payload(item),
                        "is_error": is_error_of(item),
                    }),
                    parent_tool_use_id: None,
                }]
            }
            "error" => vec![EngineEvent::Log {
                level: LogLevel::Error,
                message: error_message(Some(item)),
            }],
            _ => Vec::new(),
        }
    }

    /// The error [`RunOutcome`] for a failed turn.
    ///
    /// DECISION: [`RunErrorKind::Execution`]. `failure::classify_outcome` maps it
    /// to `agent.unknown` — non-retryable and resume-safe, the right posture for
    /// an opaque engine failure whose cause the runner cannot inspect. No new
    /// `RunErrorKind` variant is invented for codex; the enum stays
    /// engine-agnostic.
    fn failure(&self, payload: Option<&Value>) -> EngineEvent {
        EngineEvent::Result(RunOutcome {
            status: RunStatus::Error,
            result: None,
            session_id: self.thread_id.clone(),
            error: Some(error_message(payload)),
            error_kind: Some(RunErrorKind::Execution),
        })
    }
}

/// `item.started`: the opening [`EngineEvent::ToolUse`] of a tool call.
///
/// Only the tool-ish kinds emit here — `agent_message`, `reasoning`,
/// `todo_list`, `error` and unknown kinds carry no content until they complete.
/// The item's `id` is the `tool_use_id`; a missing or non-string one DROPS the
/// event, mirroring the claude mapper's treatment of an id-less `tool_use`
/// block, because a call the matching result cannot be joined to is noise.
///
/// `tool` is the item kind verbatim and `input` is the whole item minus
/// [`ENVELOPE_KEYS`], both for the reasons in the module note.
fn item_started(value: &Value) -> Vec<EngineEvent> {
    let Some(item) = value.get("item").filter(|item| item.is_object()) else {
        return Vec::new();
    };
    let kind = item_kind(item);
    if !TOOL_KINDS.contains(&kind) {
        return Vec::new();
    }
    let Some(tool_use_id) = item.get("id").and_then(Value::as_str) else {
        return Vec::new();
    };
    vec![EngineEvent::ToolUse {
        tool_use_id: tool_use_id.to_owned(),
        tool: kind.to_owned(),
        input: item_payload(item),
        parent_tool_use_id: None,
    }]
}

/// An item's kind: `item_type`, falling back to the older/looser `type`. Empty
/// when neither is a string, which matches no arm and so drops the item.
fn item_kind(item: &Value) -> &str {
    item.get("item_type")
        .and_then(Value::as_str)
        .or_else(|| item.get("type").and_then(Value::as_str))
        .unwrap_or_default()
}

/// The item with [`ENVELOPE_KEYS`] removed — what a tool event forwards as its
/// `input` or its `content`.
fn item_payload(item: &Value) -> Value {
    let mut payload = item.clone();
    if let Some(object) = payload.as_object_mut() {
        for key in ENVELOPE_KEYS {
            object.remove(key);
        }
    }
    payload
}

/// Whether a completed tool item failed: an explicit `status: "failed"`, or a
/// present non-zero `exit_code`. Neither field present means success — codex
/// omits both on the kinds that cannot fail that way, and defaulting those to an
/// error would flag every web search as broken.
fn is_error_of(item: &Value) -> bool {
    if item.get("status").and_then(Value::as_str) == Some("failed") {
        return true;
    }
    item.get("exit_code")
        .and_then(Value::as_i64)
        .is_some_and(|code| code != 0)
}

/// A reasoning item's text: the `text` string, else the `summary` array's string
/// entries joined with newlines. `None` when neither yields anything, so an
/// empty reasoning item emits no [`EngineEvent::Thinking`] at all.
fn reasoning_text(item: &Value) -> Option<String> {
    if let Some(text) = item.get("text").and_then(Value::as_str) {
        return Some(text.to_owned());
    }
    let summary = item
        .get("summary")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    (!summary.is_empty()).then_some(summary)
}

/// Read a failure payload's human-readable reason, degrading step by step rather
/// than failing: a nested `message` string, then the payload itself as a string,
/// then its whole JSON serialization, then a fixed fallback.
fn error_message(payload: Option<&Value>) -> String {
    let Some(payload) = payload else {
        return UNKNOWN_FAILURE.to_owned();
    };
    if let Some(message) = payload.get("message").and_then(Value::as_str) {
        return message.to_owned();
    }
    if let Some(text) = payload.as_str() {
        return text.to_owned();
    }
    serde_json::to_string(payload).unwrap_or_else(|_| UNKNOWN_FAILURE.to_owned())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{EventMapper, TOOL_KINDS};
    use crate::engine::{EngineEvent, LogLevel, RunErrorKind, RunStatus};

    #[test]
    fn thread_started_announces_the_session() {
        let mut mapper = EventMapper::new();
        let events = mapper.map_line(&json!({"type": "thread.started", "thread_id": "th-1"}));
        assert_eq!(
            events,
            vec![EngineEvent::SessionStarted {
                session_id: "th-1".to_owned()
            }]
        );
    }

    #[test]
    fn turn_completed_carries_the_captured_thread_id() {
        let mut mapper = EventMapper::new();
        mapper.map_line(&json!({"type": "thread.started", "thread_id": "th-1"}));
        let events = mapper.map_line(&json!({"type": "turn.completed"}));
        let [EngineEvent::Result(outcome)] = events.as_slice() else {
            panic!("expected exactly one Result event, got {events:?}");
        };
        assert_eq!(outcome.status, RunStatus::Success);
        assert_eq!(outcome.session_id.as_deref(), Some("th-1"));
        assert!(outcome.error.is_none());
        assert!(outcome.error_kind.is_none());
    }

    #[test]
    fn turn_failed_extracts_the_nested_message() {
        let mut mapper = EventMapper::new();
        mapper.map_line(&json!({"type": "thread.started", "thread_id": "th-1"}));
        let events = mapper.map_line(&json!({"type": "turn.failed", "error": {"message": "boom"}}));
        let [EngineEvent::Result(outcome)] = events.as_slice() else {
            panic!("expected exactly one Result event, got {events:?}");
        };
        assert_eq!(outcome.status, RunStatus::Error);
        assert_eq!(outcome.error.as_deref(), Some("boom"));
        assert_eq!(outcome.error_kind, Some(RunErrorKind::Execution));
        assert_eq!(outcome.session_id.as_deref(), Some("th-1"));
        assert!(outcome.result.is_none());
    }

    #[test]
    fn turn_failed_degrades_through_string_then_json_then_fallback() {
        let mut mapper = EventMapper::new();
        let string_error = mapper.map_line(&json!({"type": "turn.failed", "error": "plain"}));
        let [EngineEvent::Result(outcome)] = string_error.as_slice() else {
            panic!("expected exactly one Result event, got {string_error:?}");
        };
        assert_eq!(outcome.error.as_deref(), Some("plain"));

        let json_error = mapper.map_line(&json!({"type": "turn.failed", "error": {"code": 7}}));
        let [EngineEvent::Result(outcome)] = json_error.as_slice() else {
            panic!("expected exactly one Result event, got {json_error:?}");
        };
        assert_eq!(outcome.error.as_deref(), Some(r#"{"code":7}"#));

        let bare = mapper.map_line(&json!({"type": "turn.failed"}));
        let [EngineEvent::Result(outcome)] = bare.as_slice() else {
            panic!("expected exactly one Result event, got {bare:?}");
        };
        assert_eq!(
            outcome.error.as_deref(),
            Some("codex reported a failed turn")
        );
    }

    #[test]
    fn stream_level_error_is_a_warning_and_does_not_end_the_turn() {
        let mut mapper = EventMapper::new();
        mapper.map_line(&json!({"type": "thread.started", "thread_id": "th-1"}));
        let events = mapper.map_line(&json!({
            "type": "error",
            "message": "Reconnecting... waiting for network",
        }));
        assert_eq!(
            events,
            vec![EngineEvent::Log {
                level: LogLevel::Warn,
                message: "Reconnecting... waiting for network".to_owned(),
            }]
        );

        // The turn recovers and still ends on its own terminal event.
        let terminal = mapper.map_line(&json!({"type": "turn.completed"}));
        let [EngineEvent::Result(outcome)] = terminal.as_slice() else {
            panic!("expected exactly one Result event, got {terminal:?}");
        };
        assert_eq!(outcome.status, RunStatus::Success);
    }

    #[test]
    fn unknown_and_malformed_lines_are_dropped() {
        let mut mapper = EventMapper::new();
        // An unmapped type, and an `item.completed` with no `item` object at
        // all — both drop rather than failing the line.
        assert!(
            mapper
                .map_line(&json!({"type": "item.completed"}))
                .is_empty()
        );
        assert!(mapper.map_line(&json!({"type": "turn.started"})).is_empty());
        assert!(mapper.map_line(&json!({"nope": true})).is_empty());
        // A `thread.started` with no usable id announces nothing and captures
        // nothing, so a later terminal event still has no session id.
        assert!(
            mapper
                .map_line(&json!({"type": "thread.started"}))
                .is_empty()
        );
        assert!(
            mapper
                .map_line(&json!({"type": "thread.started", "thread_id": 7}))
                .is_empty()
        );
        let events = mapper.map_line(&json!({"type": "turn.completed"}));
        let [EngineEvent::Result(outcome)] = events.as_slice() else {
            panic!("expected exactly one Result event, got {events:?}");
        };
        assert!(outcome.session_id.is_none());
    }

    #[test]
    fn item_started_opens_a_tool_call_for_every_tool_kind() {
        for kind in TOOL_KINDS {
            let mut mapper = EventMapper::new();
            let events = mapper.map_line(&json!({
                "type": "item.started",
                "item": {
                    "id": "it-1",
                    "item_type": kind,
                    "type": kind,
                    "command": "ls -la",
                    "status": "in_progress",
                },
            }));
            assert_eq!(
                events,
                vec![EngineEvent::ToolUse {
                    tool_use_id: "it-1".to_owned(),
                    // The codex kind verbatim — never aliased to a claude tool name.
                    tool: kind.to_owned(),
                    input: json!({ "command": "ls -la", "status": "in_progress" }),
                    parent_tool_use_id: None,
                }],
                "kind {kind} should open a ToolUse"
            );
        }
    }

    #[test]
    fn item_started_reads_the_legacy_type_key_as_the_kind() {
        let mut mapper = EventMapper::new();
        let events = mapper.map_line(&json!({
            "type": "item.started",
            "item": { "id": "it-1", "type": "web_search", "query": "rust" },
        }));
        assert_eq!(
            events,
            vec![EngineEvent::ToolUse {
                tool_use_id: "it-1".to_owned(),
                tool: "web_search".to_owned(),
                input: json!({ "query": "rust" }),
                parent_tool_use_id: None,
            }]
        );
    }

    #[test]
    fn item_started_emits_nothing_for_non_tool_kinds() {
        let mut mapper = EventMapper::new();
        for kind in ["agent_message", "reasoning", "todo_list", "wat"] {
            assert!(
                mapper
                    .map_line(&json!({
                        "type": "item.started",
                        "item": { "id": "it-1", "item_type": kind, "text": "hi" },
                    }))
                    .is_empty(),
                "kind {kind} has no content until it completes"
            );
        }
    }

    #[test]
    fn item_started_without_an_id_is_dropped() {
        let mut mapper = EventMapper::new();
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.started",
                    "item": { "item_type": "command_execution", "command": "ls" },
                }))
                .is_empty()
        );
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.started",
                    "item": { "id": 7, "item_type": "command_execution" },
                }))
                .is_empty()
        );
    }

    #[test]
    fn item_updated_is_always_dropped() {
        let mut mapper = EventMapper::new();
        for kind in ["command_execution", "agent_message", "reasoning"] {
            assert!(
                mapper
                    .map_line(&json!({
                        "type": "item.updated",
                        "item": { "id": "it-1", "item_type": kind, "text": "partial" },
                    }))
                    .is_empty(),
                "a streaming update for {kind} must not duplicate the completed frame"
            );
        }
    }

    #[test]
    fn completed_agent_message_outputs_and_becomes_the_turn_result() {
        let mut mapper = EventMapper::new();
        let events = mapper.map_line(&json!({
            "type": "item.completed",
            "item": { "id": "it-1", "item_type": "agent_message", "text": "all done" },
        }));
        assert_eq!(
            events,
            vec![EngineEvent::Output {
                text: "all done".to_owned(),
                parent_tool_use_id: None,
            }]
        );

        let terminal = mapper.map_line(&json!({"type": "turn.completed"}));
        let [EngineEvent::Result(outcome)] = terminal.as_slice() else {
            panic!("expected exactly one Result event, got {terminal:?}");
        };
        assert_eq!(outcome.result.as_deref(), Some("all done"));
    }

    #[test]
    fn the_last_agent_message_of_a_turn_wins() {
        let mut mapper = EventMapper::new();
        mapper.map_line(&json!({
            "type": "item.completed",
            "item": { "id": "it-1", "item_type": "agent_message", "text": "first" },
        }));
        mapper.map_line(&json!({
            "type": "item.completed",
            "item": { "id": "it-2", "item_type": "agent_message", "text": "second" },
        }));
        // A text-less message must not clear what was already captured.
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.completed",
                    "item": { "id": "it-3", "item_type": "agent_message" },
                }))
                .is_empty()
        );

        let terminal = mapper.map_line(&json!({"type": "turn.completed"}));
        let [EngineEvent::Result(outcome)] = terminal.as_slice() else {
            panic!("expected exactly one Result event, got {terminal:?}");
        };
        assert_eq!(outcome.result.as_deref(), Some("second"));
    }

    #[test]
    fn completed_reasoning_prefers_text_then_falls_back_to_summary() {
        let mut mapper = EventMapper::new();
        let from_text = mapper.map_line(&json!({
            "type": "item.completed",
            "item": { "id": "it-1", "item_type": "reasoning", "text": "weighing options" },
        }));
        assert_eq!(
            from_text,
            vec![EngineEvent::Thinking {
                text: "weighing options".to_owned(),
                parent_tool_use_id: None,
            }]
        );

        let from_summary = mapper.map_line(&json!({
            "type": "item.completed",
            "item": {
                "id": "it-2",
                "item_type": "reasoning",
                "summary": ["step one", 7, "step two"],
            },
        }));
        assert_eq!(
            from_summary,
            vec![EngineEvent::Thinking {
                text: "step one\nstep two".to_owned(),
                parent_tool_use_id: None,
            }]
        );

        // Neither field, and a summary with no strings, carry nothing to show.
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.completed",
                    "item": { "id": "it-3", "item_type": "reasoning" },
                }))
                .is_empty()
        );
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.completed",
                    "item": { "id": "it-4", "item_type": "reasoning", "summary": [7] },
                }))
                .is_empty()
        );
    }

    #[test]
    fn completed_tool_items_return_the_frozen_output_shape() {
        for kind in TOOL_KINDS {
            let mut mapper = EventMapper::new();
            let events = mapper.map_line(&json!({
                "type": "item.completed",
                "item": {
                    "id": "it-1",
                    "item_type": kind,
                    "type": kind,
                    "status": "completed",
                    "output": "done",
                },
            }));
            assert_eq!(
                events,
                vec![EngineEvent::ToolResult {
                    tool_use_id: "it-1".to_owned(),
                    output: json!({
                        "content": { "status": "completed", "output": "done" },
                        "is_error": false,
                    }),
                    parent_tool_use_id: None,
                }],
                "kind {kind} should return a ToolResult"
            );
        }
    }

    #[test]
    fn completed_tool_item_without_an_id_is_dropped() {
        let mut mapper = EventMapper::new();
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.completed",
                    "item": { "item_type": "command_execution", "output": "done" },
                }))
                .is_empty()
        );
    }

    #[test]
    fn tool_result_error_flag_reads_status_then_exit_code() {
        let cases = [
            (json!({ "status": "failed" }), true),
            (json!({ "exit_code": 1 }), true),
            (json!({ "exit_code": 0 }), false),
            (json!({ "status": "completed" }), false),
            (json!({}), false),
        ];
        for (extra, expected) in cases {
            let mut mapper = EventMapper::new();
            let mut item = json!({ "id": "it-1", "item_type": "command_execution" });
            let (Some(item_fields), Some(extra_fields)) = (item.as_object_mut(), extra.as_object())
            else {
                panic!("fixtures are objects");
            };
            for (key, value) in extra_fields {
                item_fields.insert(key.clone(), value.clone());
            }
            let events = mapper.map_line(&json!({ "type": "item.completed", "item": item }));
            let [EngineEvent::ToolResult { output, .. }] = events.as_slice() else {
                panic!("expected exactly one ToolResult event, got {events:?}");
            };
            assert_eq!(
                output.get("is_error"),
                Some(&json!(expected)),
                "is_error for {extra} should be {expected}"
            );
        }
    }

    #[test]
    fn completed_error_item_logs_without_ending_the_turn() {
        let mut mapper = EventMapper::new();
        let events = mapper.map_line(&json!({
            "type": "item.completed",
            "item": { "id": "it-1", "item_type": "error", "message": "sandbox denied" },
        }));
        assert_eq!(
            events,
            vec![EngineEvent::Log {
                level: LogLevel::Error,
                message: "sandbox denied".to_owned(),
            }]
        );

        // An error ITEM is not terminal: the turn still ends on its own event.
        let messageless = mapper.map_line(&json!({
            "type": "item.completed",
            "item": { "id": "it-2", "item_type": "error", "code": 7 },
        }));
        assert_eq!(
            messageless,
            vec![EngineEvent::Log {
                level: LogLevel::Error,
                message: r#"{"code":7,"id":"it-2","item_type":"error"}"#.to_owned(),
            }]
        );
    }

    #[test]
    fn completed_bookkeeping_and_malformed_items_are_dropped() {
        let mut mapper = EventMapper::new();
        // A todo list is engine bookkeeping, not transcript content.
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.completed",
                    "item": { "id": "it-1", "item_type": "todo_list", "items": ["a"] },
                }))
                .is_empty()
        );
        assert!(
            mapper
                .map_line(&json!({
                    "type": "item.completed",
                    "item": { "id": "it-2", "item_type": "wat" },
                }))
                .is_empty()
        );
        // A non-object item and a missing `item` must not panic.
        assert!(
            mapper
                .map_line(&json!({"type": "item.completed", "item": "nope"}))
                .is_empty()
        );
        assert!(
            mapper
                .map_line(&json!({"type": "item.completed", "item": [1, 2]}))
                .is_empty()
        );
        assert!(
            mapper
                .map_line(&json!({"type": "item.completed"}))
                .is_empty()
        );
        // None of it disturbed the turn result.
        let terminal = mapper.map_line(&json!({"type": "turn.completed"}));
        let [EngineEvent::Result(outcome)] = terminal.as_slice() else {
            panic!("expected exactly one Result event, got {terminal:?}");
        };
        assert!(outcome.result.is_none());
    }
}
