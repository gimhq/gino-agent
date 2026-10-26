//! The Claude control protocol over stdio.
//!
//! Claude Code's `-p` print mode with `--input-format stream-json
//! --permission-prompt-tool stdio` speaks a **bidirectional control protocol**:
//! both sides exchange line-delimited JSON over the child's stdin/stdout.
//!
//! * **Host → CLI** control requests drive the session: `initialize`,
//!   `set_permission_mode` (we always set `bypassPermissions`), and `interrupt`
//!   (graceful cancel — the process is *not* killed). User turns are plain `user`
//!   lines, not control requests.
//! * **CLI → host** control requests ask permission: `can_use_tool` (may I run
//!   this tool?) and `hook_callback` (a registered hook fired). Under gino's
//!   bypass-everything policy there is no interactive UI, so the host
//!   **auto-allows** every tool and **auto-approves** every hook.
//!
//! Every request carries a `request_id`; the answer is a `control_response`
//! echoing it. This module is pure framing — it builds the request/response
//! *lines* (no trailing newline; the writer adds that) and classifies inbound
//! control requests. It performs no I/O, so it is exhaustively unit-testable.
//!
//! ## Tolerance
//!
//! The control wire is the SDK's internal format and can drift between claude
//! versions. Parsing is therefore defensive: a missing field degrades to a
//! sensible default rather than failing the line, and an unknown control subtype
//! is answered with an *error* `control_response` (never a panic), so a protocol
//! change logs loudly but keeps the session alive.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

/// The permission mode set immediately after `initialize`. gino containers have
/// no interactive approval UI, so every tool runs under bypass.
const BYPASS_MODE: &str = "bypassPermissions";

/// The `type` discriminator strings on the wire.
pub(crate) const TYPE_CONTROL_REQUEST: &str = "control_request";
pub(crate) const TYPE_CONTROL_RESPONSE: &str = "control_response";

/// Read the `type` discriminator of a parsed stdout line, or `""` if absent.
pub(crate) fn message_type(value: &Value) -> &str {
    value.get("type").and_then(Value::as_str).unwrap_or("")
}

// ---------------------------------------------------------------------------
// Host → CLI: outgoing control requests + user turns
// ---------------------------------------------------------------------------

/// A host → CLI control request envelope: `{type, request_id, request}` where
/// `request` carries the `subtype` and its fields.
#[derive(Debug, Serialize)]
struct ControlRequest {
    #[serde(rename = "type")]
    kind: &'static str,
    request_id: String,
    request: Value,
}

impl ControlRequest {
    fn new(request: Value) -> Self {
        Self {
            kind: TYPE_CONTROL_REQUEST,
            request_id: format!("req-{}", Uuid::new_v4()),
            request,
        }
    }

    fn line(self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}

/// The `initialize` handshake line. `hooks` (when present) registers SDK-side
/// hook callbacks; gino registers its hooks as external commands via `--settings`
/// instead, so this is normally `None`.
pub(crate) fn initialize_line(hooks: Option<Value>) -> Result<String, serde_json::Error> {
    let mut request = json!({ "subtype": "initialize" });
    if let Some(hooks) = hooks
        && let Some(map) = request.as_object_mut()
    {
        map.insert("hooks".to_owned(), hooks);
    }
    ControlRequest::new(request).line()
}

/// The `set_permission_mode` line putting the session into `bypassPermissions`.
pub(crate) fn set_bypass_mode_line() -> Result<String, serde_json::Error> {
    ControlRequest::new(json!({ "subtype": "set_permission_mode", "mode": BYPASS_MODE })).line()
}

/// The `interrupt` line — a graceful turn cancel that leaves the process alive.
pub(crate) fn interrupt_line() -> Result<String, serde_json::Error> {
    ControlRequest::new(json!({ "subtype": "interrupt" })).line()
}

/// A `user` turn line carrying the follow-up message text.
pub(crate) fn user_message_line(text: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string(&json!({
        "type": "user",
        "message": { "role": "user", "content": text },
        "parent_tool_use_id": Value::Null,
    }))
}

// ---------------------------------------------------------------------------
// CLI → host: inbound control requests + the auto-policy response
// ---------------------------------------------------------------------------

/// A classified inbound control request from the CLI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ControlAsk {
    /// The CLI asks to run a tool. Auto-allowed; `input` is echoed back unchanged.
    CanUseTool {
        /// The tool the CLI wants to run.
        tool_name: String,
        /// The tool input, passed straight back as `updatedInput`.
        input: Value,
    },
    /// A registered hook fired and wants a decision. Auto-approved.
    HookCallback {
        /// The callback identifier the CLI is waiting on.
        callback_id: String,
    },
    /// A subtype this runner does not recognise (protocol drift). Answered with
    /// an error response rather than crashing.
    Unknown {
        /// The unrecognised subtype string, for logging and the error reply.
        subtype: String,
    },
}

/// Classify an inbound `control_request` line into its `request_id` and ask.
/// Returns `None` only when the envelope lacks a `request_id` (unanswerable);
/// every other shape degrades to [`ControlAsk::Unknown`].
pub(crate) fn classify(value: &Value) -> Option<(String, ControlAsk)> {
    let request_id = value.get("request_id")?.as_str()?.to_owned();
    let request = value.get("request");
    let field = |name: &str| request.and_then(|r| r.get(name));
    let subtype = field("subtype").and_then(Value::as_str).unwrap_or_default();

    let ask = match subtype {
        "can_use_tool" => ControlAsk::CanUseTool {
            tool_name: field("tool_name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            input: field("input").cloned().unwrap_or(Value::Null),
        },
        "hook_callback" => ControlAsk::HookCallback {
            callback_id: field("callback_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        },
        other => ControlAsk::Unknown {
            subtype: other.to_owned(),
        },
    };
    Some((request_id, ask))
}

/// A host → CLI control response envelope: `{type, response}`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ControlResponse {
    #[serde(rename = "type")]
    kind: String,
    response: ControlResponseBody,
}

/// The body of a [`ControlResponse`], tagged by `subtype`.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "subtype", rename_all = "snake_case")]
enum ControlResponseBody {
    /// A successful answer carrying a subtype-specific `response` payload.
    Success {
        /// The request id being answered.
        request_id: String,
        /// The payload (`{behavior:"allow",…}` for a tool, `{}` for a hook).
        response: Value,
    },
    /// A failure answer carrying an error message.
    Error {
        /// The request id being answered.
        request_id: String,
        /// Why the request could not be honoured.
        error: String,
    },
}

fn success_line(request_id: &str, response: Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(&ControlResponse {
        kind: TYPE_CONTROL_RESPONSE.to_owned(),
        response: ControlResponseBody::Success {
            request_id: request_id.to_owned(),
            response,
        },
    })
}

fn error_line(request_id: &str, error: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string(&ControlResponse {
        kind: TYPE_CONTROL_RESPONSE.to_owned(),
        response: ControlResponseBody::Error {
            request_id: request_id.to_owned(),
            error: error.to_owned(),
        },
    })
}

/// Build the `control_response` line answering `ask` under the bypass-everything
/// policy: allow every tool (echoing its input), approve every hook, and reply
/// with an error to any unknown subtype.
pub(crate) fn auto_response_line(
    request_id: &str,
    ask: &ControlAsk,
) -> Result<String, serde_json::Error> {
    match ask {
        ControlAsk::CanUseTool { input, .. } => success_line(
            request_id,
            json!({ "behavior": "allow", "updatedInput": input }),
        ),
        ControlAsk::HookCallback { .. } => success_line(request_id, json!({})),
        ControlAsk::Unknown { subtype } => error_line(
            request_id,
            &format!("unsupported control request subtype: {subtype}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        BYPASS_MODE, ControlAsk, ControlResponse, auto_response_line, classify, initialize_line,
        interrupt_line, message_type, set_bypass_mode_line, user_message_line,
    };

    fn parse(line: &str) -> Value {
        serde_json::from_str(line).unwrap()
    }

    #[test]
    fn initialize_line_is_a_control_request_with_unique_id() {
        let value = parse(&initialize_line(None).unwrap());
        assert_eq!(message_type(&value), "control_request");
        assert_eq!(value["request"]["subtype"], json!("initialize"));
        assert!(value["request"].get("hooks").is_none());
        let id = value["request_id"].as_str().unwrap();
        assert!(id.starts_with("req-"), "got {id}");

        // A second line must carry a fresh request id.
        let again = parse(&initialize_line(None).unwrap());
        assert_ne!(value["request_id"], again["request_id"]);
    }

    #[test]
    fn initialize_line_embeds_hooks_when_given() {
        let hooks = json!({ "PreCompact": [{ "hooks": [{ "type": "command" }] }] });
        let value = parse(&initialize_line(Some(hooks.clone())).unwrap());
        assert_eq!(value["request"]["hooks"], hooks);
    }

    #[test]
    fn set_mode_line_requests_bypass() {
        let value = parse(&set_bypass_mode_line().unwrap());
        assert_eq!(value["request"]["subtype"], json!("set_permission_mode"));
        assert_eq!(value["request"]["mode"], json!(BYPASS_MODE));
    }

    #[test]
    fn interrupt_line_is_an_interrupt_subtype() {
        let value = parse(&interrupt_line().unwrap());
        assert_eq!(message_type(&value), "control_request");
        assert_eq!(value["request"]["subtype"], json!("interrupt"));
    }

    #[test]
    fn user_message_line_matches_stream_json_shape() {
        let value = parse(&user_message_line("hello there").unwrap());
        assert_eq!(
            value,
            json!({
                "type": "user",
                "message": { "role": "user", "content": "hello there" },
                "parent_tool_use_id": null
            })
        );
    }

    #[test]
    fn classify_reads_a_can_use_tool_request() {
        let line = json!({
            "type": "control_request",
            "request_id": "req-1",
            "request": {
                "subtype": "can_use_tool",
                "tool_name": "Bash",
                "input": { "command": "echo hi" }
            }
        });
        let (id, ask) = classify(&line).unwrap();
        assert_eq!(id, "req-1");
        assert_eq!(
            ask,
            ControlAsk::CanUseTool {
                tool_name: "Bash".to_owned(),
                input: json!({ "command": "echo hi" }),
            }
        );
    }

    #[test]
    fn classify_reads_a_hook_callback_request() {
        let line = json!({
            "type": "control_request",
            "request_id": "req-2",
            "request": { "subtype": "hook_callback", "callback_id": "cb-9" }
        });
        let (id, ask) = classify(&line).unwrap();
        assert_eq!(id, "req-2");
        assert_eq!(
            ask,
            ControlAsk::HookCallback {
                callback_id: "cb-9".to_owned()
            }
        );
    }

    #[test]
    fn classify_degrades_unknown_subtype_but_keeps_the_id() {
        let line = json!({
            "type": "control_request",
            "request_id": "req-3",
            "request": { "subtype": "from_the_future" }
        });
        let (id, ask) = classify(&line).unwrap();
        assert_eq!(id, "req-3");
        assert_eq!(
            ask,
            ControlAsk::Unknown {
                subtype: "from_the_future".to_owned()
            }
        );
    }

    #[test]
    fn classify_returns_none_without_a_request_id() {
        let line = json!({ "type": "control_request", "request": { "subtype": "can_use_tool" } });
        assert!(classify(&line).is_none());
    }

    #[test]
    fn auto_response_allows_a_tool_and_echoes_its_input() {
        let ask = ControlAsk::CanUseTool {
            tool_name: "Bash".to_owned(),
            input: json!({ "command": "echo hi" }),
        };
        let value = parse(&auto_response_line("req-1", &ask).unwrap());
        assert_eq!(
            value,
            json!({
                "type": "control_response",
                "response": {
                    "subtype": "success",
                    "request_id": "req-1",
                    "response": { "behavior": "allow", "updatedInput": { "command": "echo hi" } }
                }
            })
        );
        // The framing round-trips through the typed model.
        let typed: ControlResponse = serde_json::from_value(value).unwrap();
        assert_eq!(typed.kind, "control_response");
    }

    #[test]
    fn auto_response_approves_a_hook_with_an_empty_payload() {
        let ask = ControlAsk::HookCallback {
            callback_id: "cb-9".to_owned(),
        };
        let value = parse(&auto_response_line("req-2", &ask).unwrap());
        assert_eq!(value["response"]["subtype"], json!("success"));
        assert_eq!(value["response"]["request_id"], json!("req-2"));
        assert_eq!(value["response"]["response"], json!({}));
    }

    #[test]
    fn auto_response_errors_an_unknown_subtype_without_crashing() {
        let ask = ControlAsk::Unknown {
            subtype: "from_the_future".to_owned(),
        };
        let value = parse(&auto_response_line("req-3", &ask).unwrap());
        assert_eq!(value["response"]["subtype"], json!("error"));
        assert_eq!(value["response"]["request_id"], json!("req-3"));
        assert!(
            value["response"]["error"]
                .as_str()
                .unwrap()
                .contains("from_the_future")
        );
    }
}
