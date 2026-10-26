//! Failure taxonomy, classification, retry policy and resume-safety
//! (agent-architecture §6; modelled on Multica `pkg/taskfailure`).
//!
//! Every non-success thread execution is tagged with a [`FailureReason`] that
//! lands in `threads.failure_reason` and rides the wire on
//! [`thread_result.failure_reason`](crate::protocol::frames::ThreadResultData). The
//! taxonomy splits into two groups whose distinction drives policy:
//!
//! * **`runner.*`** — the runner/platform side is at fault (a timeout, an offline
//!   runtime, a malformed request the runner built). These are the **only**
//!   retryable reasons (§6: "retry only `runner.*`").
//! * **`agent.*`** — the engine/provider side failed (auth, quota, a crashed
//!   process, unparseable output). The runner cannot fix these by retrying, so a
//!   fresh attempt would just fail the same way.
//!
//! Two orthogonal policy bits hang off a reason:
//!
//! * [`FailureReason::is_retryable`] — `runner.*` while `attempt < max_attempts`.
//! * [`FailureReason::resume_safe`] — whether the engine session may be resumed on
//!   the next attempt/turn. A *resume-unsafe* reason (e.g. `runner.invalid_request`
//!   or `agent.context_overflow`) poisons the session, so the executor drops
//!   `engine_session_id` and the next turn starts fresh (§6).
//!
//! [`classify_outcome`] maps a turn's *structured* error cause (the engine's
//! parsed `result.subtype`, carried as [`RunErrorKind`]) into a reason;
//! [`classify_engine_error`] does the same for process-level [`EngineError`]s.
//! Error *prose* is never consulted — it is (or quotes) model output, and
//! substring matching against it misclassifies ordinary text ("took 1500ms",
//! "400") into policy-changing reasons. Callers that *know* the cause
//! (the watchdog setting `runner.timeout`) construct the reason directly.
//!
//! Several reasons are part of the spec §6 wire taxonomy but have no
//! constructing code path yet (nothing detects them); those carry per-variant
//! `dead_code` allows below rather than being dropped from the wire contract.

use crate::engine::{EngineError, RunErrorKind};

/// A `runner.*` failure — the runner/platform side is at fault. Retryable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunnerFailure {
    /// The runtime/engine host was offline when the thread was due.
    RuntimeOffline,
    /// A dispatch/run watchdog tripped (`dispatched > Td` / `running > Tr`) or the
    /// engine went inactive.
    Timeout,
    /// The run hit the runner-imposed turn/iteration cap.
    IterationLimit,
    /// The runner refused the work (policy / safety gate).
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no policy gate emits it yet"
    )]
    AgentBlocked,
    /// The runner built a request the backend rejected as malformed.
    InvalidRequest,
}

/// An `agent.*` failure — the engine/provider side failed. Not retryable.
///
/// Only [`ProcessFailure`](Self::ProcessFailure), [`Encryption`](Self::Encryption)
/// and [`Unknown`](Self::Unknown) have constructing code paths today: the
/// engine reports no structured cause finer than `RunErrorKind`, so the
/// provider-specific reasons cannot be detected without prose-matching
/// (banned). They stay declared (wire
/// taxonomy, spec §6) under per-variant allows until a structured signal exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentFailure {
    /// Authentication rejected (bad/expired API key, 401/403).
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    ProviderAuth,
    /// Out of quota / credit / billing rejected the call.
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    ProviderQuota,
    /// Rate limited (429 / too many requests).
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    ProviderRateLimit,
    /// Provider 5xx / overloaded (500/502/503/529).
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    ProviderServerError,
    /// Network/transport failure reaching the provider (DNS, refused, reset, TLS).
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    ProviderNetwork,
    /// The engine process crashed / exited abnormally / could not be spawned.
    ProcessFailure,
    /// The engine produced empty or unparseable output (no usable result).
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    EmptyOrUnparseableOutput,
    /// The conversation exceeded the model's context window.
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    ContextOverflow,
    /// The requested model is unknown / unavailable.
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    ModelUnavailable,
    /// Required engine configuration is missing.
    #[allow(
        dead_code,
        reason = "spec §6 wire taxonomy; no structured detector yet"
    )]
    MissingConfig,
    /// A mapped field of the turn's input did not open, or an output field did
    /// not seal (task-content §4.4). The same state gives the same answer, so a
    /// retry cannot help; the engine session is untouched, so it stays
    /// resumable.
    Encryption,
    /// Unclassified — the catch-all when nothing else matched.
    Unknown,
}

/// The full `threads.failure_reason` taxonomy (agent-architecture §6), split into
/// the retryable `runner.*` group and the non-retryable `agent.*` group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureReason {
    /// A `runner.*` reason — runner/platform fault, retryable.
    Runner(RunnerFailure),
    /// An `agent.*` reason — engine/provider fault, not retryable.
    Agent(AgentFailure),
}

impl FailureReason {
    /// The dotted wire string (`runner.timeout`, `agent.provider_auth`, …) stored
    /// in `threads.failure_reason` and sent on `thread_result.failure_reason`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Runner(r) => match r {
                RunnerFailure::RuntimeOffline => "runner.runtime_offline",
                RunnerFailure::Timeout => "runner.timeout",
                RunnerFailure::IterationLimit => "runner.iteration_limit",
                RunnerFailure::AgentBlocked => "runner.agent_blocked",
                RunnerFailure::InvalidRequest => "runner.invalid_request",
            },
            Self::Agent(a) => match a {
                AgentFailure::ProviderAuth => "agent.provider_auth",
                AgentFailure::ProviderQuota => "agent.provider_quota",
                AgentFailure::ProviderRateLimit => "agent.provider_rate_limit",
                AgentFailure::ProviderServerError => "agent.provider_server_error",
                AgentFailure::ProviderNetwork => "agent.provider_network",
                AgentFailure::ProcessFailure => "agent.process_failure",
                AgentFailure::EmptyOrUnparseableOutput => "agent.empty_or_unparseable_output",
                AgentFailure::ContextOverflow => "agent.context_overflow",
                AgentFailure::ModelUnavailable => "agent.model_unavailable",
                AgentFailure::MissingConfig => "agent.missing_config",
                AgentFailure::Encryption => "agent.encryption",
                AgentFailure::Unknown => "agent.unknown",
            },
        }
    }

    /// `true` for the `runner.*` group.
    pub(crate) fn is_runner(self) -> bool {
        matches!(self, Self::Runner(_))
    }

    /// Whether a fresh attempt may help. Only `runner.*` reasons are retryable
    /// (§6); `agent.*` reasons would fail identically on retry. The caller still
    /// gates on `attempt < max_attempts`.
    pub(crate) fn is_retryable(self) -> bool {
        self.is_runner()
    }

    /// Whether the engine session may be resumed on the next attempt/turn. A
    /// resume-unsafe reason poisons the session — the malformed request or the
    /// overflowing context would recur — so the executor drops `engine_session_id`
    /// and the next turn starts fresh (§6).
    pub(crate) fn resume_safe(self) -> bool {
        !matches!(
            self,
            Self::Runner(RunnerFailure::InvalidRequest)
                | Self::Agent(AgentFailure::ContextOverflow)
        )
    }
}

impl std::fmt::Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Map a turn's structured error cause ([`RunErrorKind`], the engine's parsed
/// `result.subtype`) into a [`FailureReason`]. Only the structured signal is
/// consulted — never the error/result prose.
pub(crate) fn classify_outcome(kind: Option<RunErrorKind>) -> FailureReason {
    match kind {
        Some(RunErrorKind::MaxTurns) => FailureReason::Runner(RunnerFailure::IterationLimit),
        // Fallback policy: an engine-reported error with no more specific
        // structured cause (a generic `error_during_execution`, an unrecognised
        // subtype, `is_error` on a success subtype) folds into `agent.unknown` —
        // non-retryable and resume-safe, so the runner neither burns attempts on
        // an opaque failure nor discards a healthy session handle on a guess.
        Some(RunErrorKind::Execution) | None => FailureReason::Agent(AgentFailure::Unknown),
    }
}

/// Map a process-level [`EngineError`] (the session could not be started or
/// driven) into a [`FailureReason`], keyed on the error *variant*, not its
/// rendered message.
pub(crate) fn classify_engine_error(err: &EngineError) -> FailureReason {
    match err {
        // The engine process could not be spawned, lost its pipes, or its
        // session plumbing failed — the engine side is at fault.
        EngineError::Spawn(_) | EngineError::MissingPipe(_) | EngineError::Closed => {
            FailureReason::Agent(AgentFailure::ProcessFailure)
        }
        // The runner built a control/input message that would not serialize, or
        // the run's isolation is invalid or unusable: either would recur on
        // retry and resume.
        EngineError::Serialize(_) | EngineError::Isolation(_) => {
            FailureReason::Runner(RunnerFailure::InvalidRequest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AgentFailure, FailureReason, RunnerFailure, classify_engine_error, classify_outcome,
    };
    use crate::engine::{EngineError, RunErrorKind};

    #[test]
    fn wire_strings_are_dotted_grouped_for_every_reason() {
        let all = [
            FailureReason::Runner(RunnerFailure::RuntimeOffline),
            FailureReason::Runner(RunnerFailure::Timeout),
            FailureReason::Runner(RunnerFailure::IterationLimit),
            FailureReason::Runner(RunnerFailure::AgentBlocked),
            FailureReason::Runner(RunnerFailure::InvalidRequest),
            FailureReason::Agent(AgentFailure::ProviderAuth),
            FailureReason::Agent(AgentFailure::ProviderQuota),
            FailureReason::Agent(AgentFailure::ProviderRateLimit),
            FailureReason::Agent(AgentFailure::ProviderServerError),
            FailureReason::Agent(AgentFailure::ProviderNetwork),
            FailureReason::Agent(AgentFailure::ProcessFailure),
            FailureReason::Agent(AgentFailure::EmptyOrUnparseableOutput),
            FailureReason::Agent(AgentFailure::ContextOverflow),
            FailureReason::Agent(AgentFailure::ModelUnavailable),
            FailureReason::Agent(AgentFailure::MissingConfig),
            FailureReason::Agent(AgentFailure::Encryption),
            FailureReason::Agent(AgentFailure::Unknown),
        ];
        for reason in all {
            let wire = reason.as_str();
            assert!(
                wire.starts_with("runner.") || wire.starts_with("agent."),
                "{wire} must be dotted-grouped"
            );
            assert_eq!(reason.to_string(), wire, "Display matches as_str");
        }
    }

    #[test]
    fn only_runner_reasons_are_retryable() {
        assert!(FailureReason::Runner(RunnerFailure::Timeout).is_retryable());
        assert!(FailureReason::Runner(RunnerFailure::InvalidRequest).is_retryable());
        assert!(!FailureReason::Agent(AgentFailure::ProviderAuth).is_retryable());
        assert!(!FailureReason::Agent(AgentFailure::ContextOverflow).is_retryable());
        assert!(!FailureReason::Agent(AgentFailure::Encryption).is_retryable());
    }

    #[test]
    fn encryption_failure_is_agent_scoped_and_resume_safe() {
        let reason = FailureReason::Agent(AgentFailure::Encryption);
        assert_eq!(reason.as_str(), "agent.encryption");
        assert!(!reason.is_runner());
        assert!(reason.resume_safe());
    }

    #[test]
    fn resume_unsafe_reasons_poison_the_session() {
        // Poisoning reasons: a malformed request and an overflowing context recur
        // on resume, so the session must not be reused.
        assert!(!FailureReason::Runner(RunnerFailure::InvalidRequest).resume_safe());
        assert!(!FailureReason::Agent(AgentFailure::ContextOverflow).resume_safe());
        // Transient/external failures leave the session resumable.
        assert!(FailureReason::Runner(RunnerFailure::Timeout).resume_safe());
        assert!(FailureReason::Agent(AgentFailure::ProviderRateLimit).resume_safe());
        assert!(FailureReason::Agent(AgentFailure::ProviderNetwork).resume_safe());
    }

    #[test]
    fn classify_outcome_maps_every_structured_kind() {
        // Table-driven over the full RunErrorKind set plus the no-signal case.
        let cases = [
            (
                Some(RunErrorKind::MaxTurns),
                FailureReason::Runner(RunnerFailure::IterationLimit),
            ),
            (
                Some(RunErrorKind::Execution),
                FailureReason::Agent(AgentFailure::Unknown),
            ),
            (None, FailureReason::Agent(AgentFailure::Unknown)),
        ];
        for (kind, reason) in cases {
            assert_eq!(classify_outcome(kind), reason, "{kind:?}");
        }
    }

    #[test]
    fn classify_outcome_ignores_prose_entirely() {
        // Regression: classification takes no text input at all, so
        // error-looking prose ("took 1500ms" → 500, "400" → invalid_request)
        // can never flip policy. The fallback must be resume-safe so a healthy
        // engine_session_id survives an unclassified failure.
        let fallback = classify_outcome(None);
        assert_eq!(fallback, FailureReason::Agent(AgentFailure::Unknown));
        assert!(!fallback.is_retryable());
        assert!(fallback.resume_safe());
    }

    #[test]
    fn classify_engine_error_keys_on_variant() {
        let io = || std::io::Error::other("boom");
        assert_eq!(
            classify_engine_error(&EngineError::Spawn(io())),
            FailureReason::Agent(AgentFailure::ProcessFailure)
        );
        assert_eq!(
            classify_engine_error(&EngineError::MissingPipe("stdin")),
            FailureReason::Agent(AgentFailure::ProcessFailure)
        );
        assert_eq!(
            classify_engine_error(&EngineError::Closed),
            FailureReason::Agent(AgentFailure::ProcessFailure)
        );
        let serialize = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        assert_eq!(
            classify_engine_error(&EngineError::Serialize(serialize)),
            FailureReason::Runner(RunnerFailure::InvalidRequest)
        );
        let isolation = crate::sandbox::IsolationError::UnknownMode("jail".to_owned());
        assert_eq!(
            classify_engine_error(&EngineError::Isolation(isolation)),
            FailureReason::Runner(RunnerFailure::InvalidRequest)
        );
    }

    #[test]
    fn isolation_error_message_keeps_the_cause() {
        let err = EngineError::from(crate::sandbox::IsolationError::UnknownMode(
            "jail".to_owned(),
        ));
        assert_eq!(
            err.to_string(),
            "engine isolation: unknown isolation mode `jail`"
        );
    }
}
