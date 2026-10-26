//! Wire types of the local agent API: envelopes, error codes and result shapes.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The only protocol version this agent speaks.
pub(crate) const PROTOCOL_VERSION: u64 = 1;

/// Longest accepted request line, excluding the newline.
pub(crate) const MAX_LINE_BYTES: usize = 65536;

/// Stable error codes, serialized as snake_case strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorCode {
    Unauthenticated,
    Forbidden,
    NotFound,
    InvalidParams,
    UnsupportedVersion,
    Unavailable,
    Internal,
}

impl ErrorCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::InvalidParams => "invalid_params",
            Self::UnsupportedVersion => "unsupported_version",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A handler failure, sent back as the response `error` object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ApiError {
    pub(crate) code: ErrorCode,
    pub(crate) message: String,
}

impl ApiError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn unauthenticated() -> Self {
        Self::new(
            ErrorCode::Unauthenticated,
            "this connection is not authenticated",
        )
    }

    pub(crate) fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidParams, message)
    }

    pub(crate) fn unsupported_version() -> Self {
        Self::new(
            ErrorCode::UnsupportedVersion,
            "unsupported protocol version; this agent speaks v1",
        )
    }

    pub(crate) fn unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Unavailable, message)
    }

    /// A generic internal error; the cause is logged, never sent.
    pub(crate) fn internal(cause: &dyn fmt::Display) -> Self {
        tracing::error!(error = %cause, "agent API request failed");
        Self::new(ErrorCode::Internal, "internal error")
    }
}

/// A request line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Request {
    pub(crate) v: u64,
    pub(crate) id: String,
    pub(crate) method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) params: Option<Value>,
}

/// A response line: exactly one of `result` / `error` is present.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct Response {
    pub(crate) v: u64,
    pub(crate) id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<ApiError>,
}

/// A serialized success response line (no trailing newline).
pub(crate) fn success_line(id: &str, result: Value) -> String {
    encode(&Response {
        v: PROTOCOL_VERSION,
        id: Some(id.to_owned()),
        result: Some(result),
        error: None,
    })
}

/// A serialized error response line (no trailing newline); `id` is `null` when
/// the request could not be read far enough to find one.
pub(crate) fn error_line(id: Option<&str>, error: ApiError) -> String {
    encode(&Response {
        v: PROTOCOL_VERSION,
        id: id.map(str::to_owned),
        result: None,
        error: Some(error),
    })
}

fn encode(response: &Response) -> String {
    // Serializing a struct of strings and JSON values cannot fail.
    serde_json::to_string(response).unwrap_or_default()
}

/// `auth` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AuthResult {
    pub(crate) scope: String,
    pub(crate) task_id: String,
    pub(crate) thread_id: String,
}

/// `system.info` result; `workspace_dir`/`db_path` are omitted for run scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SystemInfo {
    pub(crate) scope: String,
    pub(crate) version: String,
    pub(crate) agent_id: Option<String>,
    pub(crate) name: Option<String>,
    pub(crate) host_url: Option<String>,
    pub(crate) capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) workspace_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) db_path: Option<String>,
    pub(crate) tasks: usize,
    pub(crate) active_crons: usize,
    pub(crate) threads: ThreadCounts,
}

/// Pending / running thread counts in [`SystemInfo`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadCounts {
    pub(crate) pending: usize,
    pub(crate) running: usize,
}

/// A task in listings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TaskSummary {
    pub(crate) id: String,
    pub(crate) name: Option<String>,
    pub(crate) kind: Option<String>,
    pub(crate) status: String,
    pub(crate) created_at: String,
}

/// A thread in listings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadSummary {
    pub(crate) id: String,
    pub(crate) task_id: String,
    pub(crate) status: String,
    pub(crate) source: String,
    pub(crate) attempt: i64,
    pub(crate) max_attempts: i64,
    pub(crate) engine_session_id: Option<String>,
}

/// A thread with its run details.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadDetail {
    #[serde(flatten)]
    pub(crate) summary: ThreadSummary,
    pub(crate) cron_id: Option<String>,
    pub(crate) failure_reason: Option<String>,
    pub(crate) engine: String,
    pub(crate) duration_ms: Option<i64>,
    pub(crate) prompt: String,
    pub(crate) result: Option<String>,
    pub(crate) error: Option<String>,
}

/// A cron trigger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CronInfo {
    pub(crate) id: String,
    pub(crate) task_id: String,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) schedule_type: Option<String>,
    pub(crate) schedule_value: Option<String>,
    pub(crate) next_run: Option<String>,
    pub(crate) last_fired_at: Option<String>,
    pub(crate) continuity: String,
    pub(crate) run_count: i64,
    pub(crate) prompt: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

/// `task.list` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TaskList {
    pub(crate) tasks: Vec<TaskSummary>,
}

/// `task.show` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TaskShow {
    pub(crate) task: TaskSummary,
    pub(crate) threads: Vec<ThreadSummary>,
    pub(crate) crons: Vec<CronInfo>,
}

/// `thread.list` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadList {
    pub(crate) threads: Vec<ThreadSummary>,
}

/// `thread.show` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadShow {
    pub(crate) thread: ThreadDetail,
}

/// `cron.list` result; `scoped` is false for the all-tasks active listing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CronList {
    pub(crate) crons: Vec<CronInfo>,
    pub(crate) scoped: bool,
}

/// `cron.create` / `cron.delete` / `cron.pause` / `cron.resume` result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CronResult {
    pub(crate) cron: CronInfo,
}

/// `thread.action` result: the `seq` of the enqueued `host_action` event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ThreadActionResult {
    pub(crate) seq: i64,
}
