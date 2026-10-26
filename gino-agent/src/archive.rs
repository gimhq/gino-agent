//! The `archive` subcommand — PreCompact transcript archiving.
//!
//! Claude Code is configured (via the `--settings` hook this runner builds) to
//! run `gino-agent archive` just before it compacts a conversation. The hook
//! delivers `{transcript_path, session_id}` as JSON on stdin; this module parses
//! the JSONL transcript and writes a human-readable Markdown archive plus a
//! `sessions-index.json` summary lookup under the runner's workspace.
//!
//! The output directory is **configurable** — `$GINO_ARCHIVE_DIR` when set, else
//! `<workspace>/conversations`, where `<workspace>` comes from [`crate::config`]
//! — never a hardcoded Docker mount.
//! The Markdown layout reproduces the existing TypeScript runner
//! (`container/gino-agent/src/claude-backend.ts`) so archives stay consistent
//! across the rewrite.
//!
//! All timestamps are UTC. Date formatting is done with a small civil-calendar
//! helper rather than pulling a date/time crate.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{info, warn};

/// The maximum characters of a message body kept in the Markdown archive (longer
/// bodies are truncated with an ellipsis), matching the TypeScript runner.
const MAX_BODY_CHARS: usize = 2000;

/// Sidecar lockfile under the conversations dir serializing concurrent `archive`
/// hook processes.
const CONVERSATIONS_LOCK_FILE: &str = ".sessions-index.lock";

/// Errors raised while archiving a transcript.
#[derive(Debug, Error)]
pub(crate) enum ArchiveError {
    /// The hook input could not be read from stdin.
    #[error("reading hook input from stdin: {0}")]
    Stdin(#[source] std::io::Error),
    /// The hook input was not the expected `{transcript_path, session_id}` JSON.
    #[error("parsing hook input: {0}")]
    Input(#[source] serde_json::Error),
    /// The conversations directory could not be created or written.
    #[error("writing archive under {dir}: {source}")]
    Write {
        /// The directory being written.
        dir: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The sessions index could not be serialized.
    #[error("serialising sessions index: {0}")]
    Index(#[source] serde_json::Error),
}

/// The PreCompact hook payload delivered on stdin.
#[derive(Debug, Deserialize)]
struct HookInput {
    /// Path to the JSONL transcript Claude is about to compact.
    transcript_path: String,
    /// The session id, used to look up a human summary.
    #[serde(default)]
    session_id: Option<String>,
}

/// One archived message.
#[derive(Debug, PartialEq, Eq)]
struct Message {
    /// `true` for a user turn, `false` for an assistant turn.
    is_user: bool,
    /// The message text.
    content: String,
}

/// An entry in `sessions-index.json` (camelCase to match the TypeScript runner).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionEntry {
    /// The backend session id.
    session_id: String,
    /// The archive Markdown path.
    full_path: String,
    /// The human summary, if known.
    summary: String,
    /// The first user prompt of the conversation.
    first_prompt: String,
}

/// The `sessions-index.json` document.
#[derive(Debug, Default, Serialize, Deserialize)]
struct SessionsIndex {
    /// All archived sessions.
    entries: Vec<SessionEntry>,
}

/// The directory archives are written into: a non-empty `archive_dir_env`
/// (`GINO_ARCHIVE_DIR`) wins, else `<workspace_dir>/conversations`.
pub(crate) fn conversations_dir(archive_dir_env: Option<PathBuf>, workspace_dir: &Path) -> PathBuf {
    archive_dir_env
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| workspace_dir.join("conversations"))
}

/// Run the `archive` subcommand: read the hook payload from `input`, parse the
/// transcript, and write the Markdown archive + sessions index under
/// `conversations_dir` (see [`conversations_dir`]).
///
/// A missing/empty transcript is a no-op (logged), not an error — the hook fires
/// on every compaction and an empty conversation is unremarkable.
pub(crate) fn run<R: Read>(conversations_dir: &Path, mut input: R) -> Result<(), ArchiveError> {
    let mut raw = String::new();
    input
        .read_to_string(&mut raw)
        .map_err(ArchiveError::Stdin)?;
    if raw.trim().is_empty() {
        info!("archive: empty hook input; nothing to do");
        return Ok(());
    }
    let hook: HookInput = serde_json::from_str(&raw).map_err(ArchiveError::Input)?;

    let transcript_path = Path::new(&hook.transcript_path);
    let Ok(transcript) = fs::read_to_string(transcript_path) else {
        warn!(path = %hook.transcript_path, "archive: transcript not found; skipping");
        return Ok(());
    };

    let messages = parse_transcript(&transcript);
    if messages.is_empty() {
        info!("archive: no messages to archive");
        return Ok(());
    }

    let session_id = hook.session_id.unwrap_or_default();
    // The human summary is written by Claude into the transcript's own project
    // directory; read it from there (read-only), as the TypeScript runner does.
    let summary = transcript_path
        .parent()
        .and_then(|dir| session_summary(&dir.join("sessions-index.json"), &session_id));

    let name = match &summary {
        Some(summary) if !summary.is_empty() => sanitize_filename(summary),
        _ => fallback_name(now_unix()),
    };

    fs::create_dir_all(conversations_dir).map_err(|source| ArchiveError::Write {
        dir: conversations_dir.display().to_string(),
        source,
    })?;

    // Serialize concurrent PreCompact hooks. Decision: an advisory
    // exclusive lock on a sidecar lockfile — each hook is its own short-lived
    // `gino-agent archive` process, so there is no in-process single writer to
    // lean on and the lock must work cross-process. Held (via the binding) across
    // name selection, the Markdown write, and the index update, so two hooks can
    // neither pick the same archive name nor interleave the index
    // read-modify-write; the index write itself is temp+rename (see
    // [`update_index`]) so a crash mid-write never leaves a torn file behind.
    let _dir_lock = lock_conversations_dir(conversations_dir)?;

    let now = now_unix();
    let file_path = unique_archive_path(conversations_dir, &date_stamp(now), &name);
    let markdown = format_markdown(&messages, summary.as_deref(), now);
    fs::write(&file_path, markdown).map_err(|source| ArchiveError::Write {
        dir: file_path.display().to_string(),
        source,
    })?;
    info!(path = %file_path.display(), "archive: wrote conversation");

    update_index(
        conversations_dir,
        &session_id,
        &file_path,
        summary.as_deref(),
        &messages,
    )?;
    Ok(())
}

/// Parse a JSONL transcript into ordered user/assistant text messages. Malformed
/// or contentless lines are skipped (mirrors the TypeScript parser).
fn parse_transcript(content: &str) -> Vec<Message> {
    let mut messages = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let kind = entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let content = entry.get("message").and_then(|m| m.get("content"));
        match kind {
            "user" => {
                if let Some(text) = user_text(content)
                    && !text.is_empty()
                {
                    messages.push(Message {
                        is_user: true,
                        content: text,
                    });
                }
            }
            "assistant" => {
                let text = assistant_text(content);
                if !text.is_empty() {
                    messages.push(Message {
                        is_user: false,
                        content: text,
                    });
                }
            }
            _ => {}
        }
    }
    messages
}

/// A user message's content is either a bare string or an array of blocks whose
/// `text` fields are concatenated.
fn user_text(content: Option<&Value>) -> Option<String> {
    match content? {
        Value::String(text) => Some(text.clone()),
        Value::Array(blocks) => Some(
            blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect(),
        ),
        _ => None,
    }
}

/// An assistant message's content is an array of blocks; only `text` blocks are
/// kept.
fn assistant_text(content: Option<&Value>) -> String {
    content
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<String>()
        })
        .unwrap_or_default()
}

/// Render the archive Markdown, reproducing the TypeScript layout: an `# <title>`
/// heading, an `Archived: <when>` line, a rule, then each message as
/// `**<Sender>**: <body>` with bodies truncated to [`MAX_BODY_CHARS`].
fn format_markdown(messages: &[Message], title: Option<&str>, now_secs: i64) -> String {
    let mut lines = vec![
        format!(
            "# {}",
            title.filter(|t| !t.is_empty()).unwrap_or("Conversation")
        ),
        String::new(),
        format!("Archived: {}", format_archived(now_secs)),
        String::new(),
        "---".to_owned(),
        String::new(),
    ];
    for message in messages {
        let sender = if message.is_user { "User" } else { "Assistant" };
        let body = truncate_chars(&message.content, MAX_BODY_CHARS);
        lines.push(format!("**{sender}**: {body}"));
        lines.push(String::new());
    }
    lines.join("\n")
}

/// Truncate to at most `max` characters, appending `...` when truncated. Operates
/// on `char` boundaries so multi-byte text is never split.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let head: String = text.chars().take(max).collect();
    format!("{head}...")
}

/// Slug a summary into a filename fragment: lowercase, non-alphanumerics collapsed
/// to single dashes, trimmed, capped at 50 characters. A summary with no ASCII
/// alphanumerics at all (e.g. fully non-ASCII) used to slug to the empty string —
/// making every such same-day archive share one name; it now falls
/// back to a content hash, so distinct summaries yield distinct, non-empty names.
fn sanitize_filename(summary: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in summary.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    let slug: String = trimmed.chars().take(50).collect();
    if slug.is_empty() {
        return hashed_slug(summary);
    }
    slug
}

/// A deterministic, non-empty slug for a summary that survives no ASCII
/// characters: `conversation-` plus the first 4 bytes of the summary's SHA-256.
fn hashed_slug(summary: &str) -> String {
    let digest = Sha256::digest(summary.as_bytes());
    format!(
        "conversation-{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

/// Acquire the exclusive advisory lock serializing archive writers for this
/// conversations dir. Blocks until the lock is free (hooks are short-lived);
/// released by the OS when the returned handle drops, clean exit or not.
fn lock_conversations_dir(dir: &Path) -> Result<fs::File, ArchiveError> {
    let path = dir.join(CONVERSATIONS_LOCK_FILE);
    let write_err = |source| ArchiveError::Write {
        dir: path.display().to_string(),
        source,
    };
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(write_err)?;
    file.lock().map_err(write_err)?;
    Ok(file)
}

/// The first free `<stamp>-<name>[-N].md` path under `dir`: same-day archives
/// with identical (or identically-slugged) summaries get `-2`, `-3`, … suffixes
/// instead of overwriting each other. The caller holds the
/// conversations-dir lock, so the existence probe cannot race another hook.
fn unique_archive_path(dir: &Path, stamp: &str, name: &str) -> PathBuf {
    let base = dir.join(format!("{stamp}-{name}.md"));
    if !base.exists() {
        return base;
    }
    let mut counter: u64 = 2;
    loop {
        let candidate = dir.join(format!("{stamp}-{name}-{counter}.md"));
        if !candidate.exists() {
            return candidate;
        }
        counter += 1;
    }
}

/// A fallback archive name when no summary is available: `conversation-HHMM` (UTC).
fn fallback_name(now_secs: i64) -> String {
    let (hour, minute) = hour_minute(now_secs);
    format!("conversation-{hour:02}{minute:02}")
}

/// Look up the human summary for `session_id` in a `sessions-index.json`.
fn session_summary(index_path: &Path, session_id: &str) -> Option<String> {
    let raw = fs::read_to_string(index_path).ok()?;
    let index: SessionsIndex = serde_json::from_str(&raw).ok()?;
    index
        .entries
        .into_iter()
        .find(|entry| entry.session_id == session_id)
        .map(|entry| entry.summary)
}

/// Upsert this archive into `<conversations_dir>/sessions-index.json`, keyed by
/// session id.
fn update_index(
    conversations_dir: &Path,
    session_id: &str,
    file_path: &Path,
    summary: Option<&str>,
    messages: &[Message],
) -> Result<(), ArchiveError> {
    let index_path = conversations_dir.join("sessions-index.json");
    let mut index: SessionsIndex = fs::read_to_string(&index_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();

    let first_prompt = messages
        .iter()
        .find(|message| message.is_user)
        .map(|message| truncate_chars(&message.content, 500))
        .unwrap_or_default();

    let entry = SessionEntry {
        session_id: session_id.to_owned(),
        full_path: file_path.display().to_string(),
        summary: summary.unwrap_or_default().to_owned(),
        first_prompt,
    };

    match index
        .entries
        .iter_mut()
        .find(|existing| existing.session_id == session_id)
    {
        Some(existing) => *existing = entry,
        None => index.entries.push(entry),
    }

    let json = serde_json::to_string_pretty(&index).map_err(ArchiveError::Index)?;
    // Write-temp + rename: the index is never truncated in place, so a crash
    // mid-write (or a reader racing the writer) can never observe a torn file.
    // The caller holds the conversations-dir lock, so the fixed temp name is
    // safe from concurrent writers.
    let tmp_path = conversations_dir.join("sessions-index.json.tmp");
    fs::write(&tmp_path, json).map_err(|source| ArchiveError::Write {
        dir: tmp_path.display().to_string(),
        source,
    })?;
    fs::rename(&tmp_path, &index_path).map_err(|source| ArchiveError::Write {
        dir: index_path.display().to_string(),
        source,
    })
}

// ---------------------------------------------------------------------------
// UTC date/time helpers (no date crate)
// ---------------------------------------------------------------------------

/// Seconds since the Unix epoch, UTC. Clamps a pre-epoch clock to 0.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// Civil (year, month, day) from a count of days since the Unix epoch. Howard
/// Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// `(hour, minute)` of the day for a Unix timestamp (UTC).
fn hour_minute(secs: i64) -> (i64, i64) {
    let day_secs = secs.rem_euclid(86_400);
    (day_secs / 3600, (day_secs % 3600) / 60)
}

/// `YYYY-MM-DD` (UTC) for a Unix timestamp.
fn date_stamp(secs: i64) -> String {
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    format!("{year:04}-{month:02}-{day:02}")
}

/// A human `Mon D, h:MM AM/PM` (UTC) for a Unix timestamp, matching the
/// TypeScript `toLocaleString` shape.
fn format_archived(secs: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (_, month, day) = civil_from_days(secs.div_euclid(86_400));
    let (hour, minute) = hour_minute(secs);
    let month_name = usize::try_from(month - 1)
        .ok()
        .and_then(|idx| MONTHS.get(idx).copied())
        .unwrap_or("Jan");
    let period = if hour < 12 { "AM" } else { "PM" };
    let hour12 = match hour % 12 {
        0 => 12,
        other => other,
    };
    format!("{month_name} {day}, {hour12}:{minute:02} {period}")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use std::path::{Path, PathBuf};

    use super::{
        SessionsIndex, conversations_dir, date_stamp, fallback_name, format_archived,
        parse_transcript, run, sanitize_filename, truncate_chars,
    };

    #[test]
    fn date_helpers_anchor_to_known_epochs() {
        assert_eq!(date_stamp(0), "1970-01-01");
        assert_eq!(date_stamp(86_400), "1970-01-02");
        assert_eq!(format_archived(0), "Jan 1, 12:00 AM");
        // 1970-01-01 13:05:00 UTC → 1 PM.
        assert_eq!(format_archived(13 * 3600 + 5 * 60), "Jan 1, 1:05 PM");
        assert_eq!(fallback_name(13 * 3600 + 5 * 60), "conversation-1305");
    }

    #[test]
    fn sanitize_filename_slugs_and_caps() {
        assert_eq!(sanitize_filename("Hello, World!"), "hello-world");
        assert_eq!(sanitize_filename("  --Trim__me--  "), "trim-me");
        assert_eq!(sanitize_filename(&"x".repeat(80)).len(), 50);
    }

    #[test]
    fn truncate_chars_keeps_multibyte_boundaries() {
        assert_eq!(truncate_chars("héllo", 10), "héllo");
        assert_eq!(truncate_chars("héllo", 2), "hé...");
    }

    #[test]
    fn parse_transcript_extracts_user_and_assistant_text() {
        let jsonl = [
            json!({ "type": "user", "message": { "content": "hi there" } }).to_string(),
            json!({ "type": "assistant", "message": { "content": [
                { "type": "text", "text": "hello " },
                { "type": "tool_use", "name": "Bash" },
                { "type": "text", "text": "back" }
            ]}})
            .to_string(),
            "not json".to_owned(),
            json!({ "type": "system", "message": { "content": "ignored" } }).to_string(),
        ]
        .join("\n");

        let messages = parse_transcript(&jsonl);
        assert_eq!(messages.len(), 2);
        assert!(messages[0].is_user);
        assert_eq!(messages[0].content, "hi there");
        assert!(!messages[1].is_user);
        assert_eq!(messages[1].content, "hello back");
    }

    #[test]
    fn run_writes_markdown_and_index() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();

        // A claude project dir with a transcript and a summary index.
        let project = workspace.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let transcript_path = project.join("transcript.jsonl");
        let transcript = [
            json!({ "type": "user", "message": { "content": "Build me a thing" } }).to_string(),
            json!({ "type": "assistant", "message": { "content": [
                { "type": "text", "text": "On it." }
            ]}})
            .to_string(),
        ]
        .join("\n");
        std::fs::write(&transcript_path, transcript).unwrap();
        std::fs::write(
            project.join("sessions-index.json"),
            json!({ "entries": [
                { "sessionId": "sess-1", "fullPath": "", "summary": "Build a Thing", "firstPrompt": "" }
            ]})
            .to_string(),
        )
        .unwrap();

        let input = json!({
            "transcript_path": transcript_path.display().to_string(),
            "session_id": "sess-1"
        })
        .to_string();

        run(&workspace.join("conversations"), Cursor::new(input)).unwrap();

        // The Markdown archive is named from the summary slug.
        let conversations = workspace.join("conversations");
        let archive = std::fs::read_dir(&conversations)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.contains("build-a-thing.md"))
            .expect("named archive present");
        let body = std::fs::read_to_string(conversations.join(&archive)).unwrap();
        assert!(body.starts_with("# Build a Thing"));
        assert!(body.contains("**User**: Build me a thing"));
        assert!(body.contains("**Assistant**: On it."));

        // The conversations index gained the session entry.
        let index: SessionsIndex = serde_json::from_str(
            &std::fs::read_to_string(conversations.join("sessions-index.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].session_id, "sess-1");
        assert_eq!(index.entries[0].summary, "Build a Thing");
        assert_eq!(index.entries[0].first_prompt, "Build me a thing");
        assert!(index.entries[0].full_path.ends_with(&archive));
    }

    /// Regression: a summary with no ASCII alphanumerics used to slug to
    /// the EMPTY string, so every such same-day archive shared one name. The
    /// content-hash fallback yields distinct, non-empty, deterministic slugs.
    #[test]
    fn non_ascii_summary_slugs_to_distinct_nonempty_names() {
        let first = sanitize_filename("éàü");
        let second = sanitize_filename("çß");
        assert!(
            first.starts_with("conversation-") && first.len() > "conversation-".len(),
            "hash fallback must be non-empty: {first:?}"
        );
        assert!(second.starts_with("conversation-"));
        assert_ne!(first, second, "distinct summaries must not collide");
        // Deterministic: the same summary keeps its name.
        assert_eq!(first, sanitize_filename("éàü"));
    }

    /// Regression: two same-day archives with the SAME summary get
    /// distinct file names (counter suffix) instead of overwriting each other,
    /// and both land in the index.
    #[test]
    fn same_day_identical_summaries_produce_distinct_archives() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path();
        let project = workspace.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let transcript_path = project.join("t.jsonl");
        std::fs::write(
            &transcript_path,
            json!({ "type": "user", "message": { "content": "hi" } }).to_string(),
        )
        .unwrap();
        std::fs::write(
            project.join("sessions-index.json"),
            json!({ "entries": [
                { "sessionId": "sess-1", "fullPath": "", "summary": "Build a Thing", "firstPrompt": "" },
                { "sessionId": "sess-2", "fullPath": "", "summary": "Build a Thing", "firstPrompt": "" }
            ]})
            .to_string(),
        )
        .unwrap();

        for session in ["sess-1", "sess-2"] {
            let input = json!({
                "transcript_path": transcript_path.display().to_string(),
                "session_id": session
            })
            .to_string();
            run(&workspace.join("conversations"), Cursor::new(input)).unwrap();
        }

        let conversations = workspace.join("conversations");
        let names: Vec<String> = std::fs::read_dir(&conversations)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| std::path::Path::new(name).extension() == Some("md".as_ref()))
            .collect();
        assert_eq!(
            names.len(),
            2,
            "the second archive must not overwrite the first: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.ends_with("build-a-thing.md") && !name.contains("thing-2")),
            "base name present: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|name| name.ends_with("build-a-thing-2.md")),
            "collision gets a counter suffix: {names:?}"
        );

        let index: SessionsIndex = serde_json::from_str(
            &std::fs::read_to_string(conversations.join("sessions-index.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(index.entries.len(), 2);
        assert_ne!(
            index.entries[0].full_path, index.entries[1].full_path,
            "index entries point at distinct archives"
        );
    }

    /// Regression: the index update is a read-modify-write; two archive
    /// hooks racing it used to lose entries (a stale read clobbers the other
    /// writer's insert). The conversations-dir advisory lock serializes the
    /// whole archive write, so every concurrent run's entry survives.
    #[test]
    fn concurrent_runs_do_not_lose_index_entries() {
        const PER_THREAD: usize = 20;

        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().to_path_buf();
        let project = workspace.join("project");
        std::fs::create_dir_all(&project).unwrap();
        let transcript_path = project.join("t.jsonl");
        std::fs::write(
            &transcript_path,
            json!({ "type": "user", "message": { "content": "hi" } }).to_string(),
        )
        .unwrap();

        let workers: Vec<_> = ["a", "b"]
            .iter()
            .map(|prefix| {
                let workspace = workspace.clone();
                let transcript = transcript_path.display().to_string();
                let prefix = (*prefix).to_owned();
                std::thread::spawn(move || {
                    for i in 0..PER_THREAD {
                        let input = json!({
                            "transcript_path": transcript,
                            "session_id": format!("sess-{prefix}-{i}")
                        })
                        .to_string();
                        run(&workspace.join("conversations"), Cursor::new(input)).unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }

        let index: SessionsIndex = serde_json::from_str(
            &std::fs::read_to_string(workspace.join("conversations/sessions-index.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            index.entries.len(),
            2 * PER_THREAD,
            "no interleaved index update may lose an entry"
        );
    }

    #[test]
    fn conversations_dir_prefers_a_non_empty_env_path() {
        let workspace = Path::new("/ws");
        assert_eq!(
            conversations_dir(Some(PathBuf::from("/archive")), workspace),
            PathBuf::from("/archive")
        );
        assert_eq!(
            conversations_dir(None, workspace),
            PathBuf::from("/ws/conversations")
        );
        assert_eq!(
            conversations_dir(Some(PathBuf::new()), workspace),
            PathBuf::from("/ws/conversations")
        );
    }

    #[test]
    fn run_writes_into_an_explicit_archive_dir() {
        let dir = tempfile::tempdir().unwrap();
        let transcript_path = dir.path().join("t.jsonl");
        std::fs::write(
            &transcript_path,
            json!({ "type": "user", "message": { "content": "hi" } }).to_string(),
        )
        .unwrap();
        let archive_dir = dir.path().join("elsewhere/archive");
        let input = json!({
            "transcript_path": transcript_path.display().to_string(),
            "session_id": "s"
        })
        .to_string();

        run(&archive_dir, Cursor::new(input)).unwrap();

        assert!(archive_dir.join("sessions-index.json").is_file());
        let markdown = std::fs::read_dir(&archive_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".md"))
            .count();
        assert_eq!(markdown, 1);
        assert!(!dir.path().join("conversations").exists());
    }

    #[test]
    fn run_is_a_noop_for_empty_input() {
        let dir = tempfile::tempdir().unwrap();
        run(
            &dir.path().join("conversations"),
            Cursor::new(String::new()),
        )
        .unwrap();
        assert!(!dir.path().join("conversations").exists());
    }

    #[test]
    fn run_skips_a_missing_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let input =
            json!({ "transcript_path": "/nope/missing.jsonl", "session_id": "s" }).to_string();
        run(&dir.path().join("conversations"), Cursor::new(input)).unwrap();
        assert!(!dir.path().join("conversations").exists());
    }
}
