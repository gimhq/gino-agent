//! What the engine CLIs report about themselves: the models they offer and whether
//! they are signed in (protocol §5, heartbeat `engines`).
//!
//! Both answers come from the CLI, run with the same binary, credentials and config
//! dir as a real run:
//!
//! - claude answers the stream-json `initialize` control request with its `models`,
//!   and `claude auth status --json` with `loggedIn`;
//! - `codex app-server` answers `model/list` (paged) and `account/read` over
//!   line-delimited JSON-RPC.
//!
//! The list is reported as the CLI gives it. Filtering it, or checking a task's
//! model against it, is host policy: the agent passes a requested model through.
//! Every probe is bounded by [`PROBE_TIMEOUT`]; a CLI that fails or hangs leaves
//! the field it would have answered unset.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use super::admin::EngineKind;

/// Bound on one probe step (one CLI invocation).
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound on the `model/list` pages read from codex.
const MAX_MODEL_PAGES: usize = 20;
/// Bound on the output read from `claude auth status`.
const MAX_STATUS_BYTES: u64 = 64 * 1024;

/// Whether an engine CLI is signed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum AuthStatus {
    Authenticated,
    Unauthenticated,
    Unknown,
}

/// One model an engine CLI offers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ModelInfo {
    pub(crate) id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) description: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) is_default: bool,
}

/// The program and environment a probe runs: those of a real run of the engine.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProbeCommand {
    pub(crate) program: PathBuf,
    pub(crate) env: Vec<(String, OsString)>,
    pub(crate) cwd: PathBuf,
}

// The environment holds credentials: only the program is printed.
impl std::fmt::Debug for ProbeCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeCommand")
            .field("program", &self.program)
            .finish_non_exhaustive()
    }
}

impl ProbeCommand {
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(args)
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        if !self.cwd.as_os_str().is_empty() {
            command.current_dir(&self.cwd);
        }
        command
    }

    fn has_env(&self, keys: &[&str]) -> bool {
        self.env
            .iter()
            .any(|(key, value)| keys.contains(&key.as_str()) && !value.is_empty())
    }
}

/// What one probe found; a field the CLI did not answer is `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProbeReport {
    pub(crate) auth: Option<AuthStatus>,
    pub(crate) models: Option<Vec<ModelInfo>>,
}

impl ProbeReport {
    /// The model the CLI runs when none is requested.
    pub(crate) fn default_model(&self) -> Option<&str> {
        self.models
            .as_deref()?
            .iter()
            .find(|model| model.is_default)
            .map(|model| model.id.as_str())
    }
}

/// Probe the CLI of `kind`.
pub(crate) async fn probe(kind: EngineKind, command: &ProbeCommand) -> ProbeReport {
    match kind {
        EngineKind::Claude => ProbeReport {
            auth: Some(claude_auth(command).await),
            models: claude_models(command).await,
        },
        EngineKind::Codex => codex(command).await,
    }
}

// ─── claude ─────────────────────────────────────────────────────────────────

/// Credentials that sign claude in without a login.
const CLAUDE_CREDENTIALS: [&str; 2] = ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"];

/// `claude auth status --json`; a CLI without the subcommand falls back to the
/// configured credentials.
async fn claude_auth(command: &ProbeCommand) -> AuthStatus {
    let status = tokio::time::timeout(PROBE_TIMEOUT, async {
        let mut child = command
            .command(&["auth", "status", "--json"])
            .spawn()
            .ok()?;
        drop(child.stdin.take());
        let mut out = String::new();
        child
            .stdout
            .take()?
            .take(MAX_STATUS_BYTES)
            .read_to_string(&mut out)
            .await
            .ok()?;
        child.wait().await.ok()?.success().then_some(out)
    })
    .await
    .ok()
    .flatten();
    match status.as_deref().and_then(parse_claude_auth) {
        Some(auth) => with_credentials(auth, command, &CLAUDE_CREDENTIALS),
        None => credential_fallback(command, &CLAUDE_CREDENTIALS),
    }
}

/// `loggedIn` of `claude auth status --json`; `None` when the output has no such flag.
fn parse_claude_auth(out: &str) -> Option<AuthStatus> {
    let json = &out[out.find('{')?..=out.rfind('}')?];
    let logged_in = serde_json::from_str::<Value>(json).ok()?["loggedIn"].as_bool()?;
    Some(if logged_in {
        AuthStatus::Authenticated
    } else {
        AuthStatus::Unauthenticated
    })
}

/// A run with a configured key is signed in even when the CLI reports no login
/// (`codex exec` reads `CODEX_API_KEY`, which `app-server` does not). The key is
/// not validated: that would take an API call.
fn with_credentials(auth: AuthStatus, command: &ProbeCommand, keys: &[&str]) -> AuthStatus {
    if auth == AuthStatus::Unauthenticated && command.has_env(keys) {
        AuthStatus::Authenticated
    } else {
        auth
    }
}

/// For a CLI that cannot report its login: a configured credential counts as
/// signed in; without one the state is unknown (a login may live where the agent
/// cannot see it).
fn credential_fallback(command: &ProbeCommand, keys: &[&str]) -> AuthStatus {
    if command.has_env(keys) {
        AuthStatus::Authenticated
    } else {
        AuthStatus::Unknown
    }
}

/// The `models` claude reports in its `initialize` control response.
async fn claude_models(command: &ProbeCommand) -> Option<Vec<ModelInfo>> {
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    tokio::time::timeout(PROBE_TIMEOUT, async {
        let mut child = command
            .command(&[
                "-p",
                "--verbose",
                "--input-format",
                "stream-json",
                "--output-format",
                "stream-json",
            ])
            .spawn()
            .ok()?;
        let (mut stdin, mut lines) = pipes(&mut child)?;
        let request = json!({
            "type": "control_request",
            "request_id": request_id,
            "request": { "subtype": "initialize" },
        });
        write_line(&mut stdin, &request).await?;
        while let Some(line) = lines.next_line().await.ok()? {
            let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if frame["type"] == "control_response"
                && frame["response"]["request_id"] == request_id.as_str()
            {
                return Some(map_claude_models(&frame["response"]["response"]["models"]));
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// claude's `initialize` models: each entry's `resolvedModel` (else its `value`) is
/// the id, deduplicated; the `value: "default"` entry is not a model of its own but
/// marks the one it resolves to as the default (listed first when absent otherwise).
fn map_claude_models(raw: &Value) -> Vec<ModelInfo> {
    fn text<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
        entry[key].as_str().filter(|value| !value.is_empty())
    }
    fn id_of(entry: &Value) -> Option<&str> {
        text(entry, "resolvedModel").or_else(|| text(entry, "value"))
    }
    let entries: Vec<&Value> = raw
        .as_array()
        .map(|entries| entries.iter().filter(|entry| entry.is_object()).collect())
        .unwrap_or_default();
    let is_default_entry = |entry: &Value| entry["value"] == "default";
    let default_id = entries
        .iter()
        .find(|entry| is_default_entry(entry))
        .and_then(|entry| id_of(entry));

    let mut models: Vec<ModelInfo> = Vec::new();
    for entry in entries.iter().filter(|entry| !is_default_entry(entry)) {
        let Some(id) = id_of(entry) else { continue };
        if models.iter().any(|model| model.id == id) {
            continue;
        }
        models.push(ModelInfo {
            id: id.to_owned(),
            name: text(entry, "displayName").map(str::to_owned),
            description: text(entry, "description").map(str::to_owned),
            is_default: Some(id) == default_id,
        });
    }
    if let Some(id) = default_id
        && !models.iter().any(|model| model.id == id)
    {
        models.insert(
            0,
            ModelInfo {
                id: id.to_owned(),
                name: None,
                description: None,
                is_default: true,
            },
        );
    }
    models
}

// ─── codex ──────────────────────────────────────────────────────────────────

/// Credentials that sign codex in without a login.
const CODEX_CREDENTIALS: [&str; 2] = ["CODEX_API_KEY", "OPENAI_API_KEY"];

/// One `codex app-server` session: `initialize`, then `account/read` and the
/// `model/list` pages.
async fn codex(command: &ProbeCommand) -> ProbeReport {
    let report = tokio::time::timeout(PROBE_TIMEOUT, async {
        let mut child = command.command(&["app-server"]).spawn().ok()?;
        let (stdin, lines) = pipes(&mut child)?;
        let mut rpc = JsonRpc {
            stdin,
            lines,
            next_id: 0,
        };
        rpc.call(
            "initialize",
            json!({
                "clientInfo": { "name": "gino-agent", "title": "gino-agent", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": { "experimentalApi": true },
            }),
        )
        .await
        .ok()?;
        rpc.notify("initialized").await?;
        let auth = match rpc.call("account/read", json!({})).await {
            Ok(account) => {
                with_credentials(parse_codex_account(&account), command, &CODEX_CREDENTIALS)
            }
            Err(RpcError::Unsupported) => credential_fallback(command, &CODEX_CREDENTIALS),
            Err(RpcError::Failed) => AuthStatus::Unknown,
        };
        let mut models = Vec::new();
        let mut cursor: Option<String> = None;
        let mut complete = false;
        for _ in 0..MAX_MODEL_PAGES {
            let params = cursor.as_ref().map_or_else(|| json!({}), |c| json!({ "cursor": c }));
            let Ok(page) = rpc.call("model/list", params).await else {
                break;
            };
            let (items, next) = map_codex_models(&page);
            models.extend(items);
            cursor = next;
            if cursor.is_none() {
                complete = true;
                break;
            }
        }
        Some(ProbeReport {
            auth: Some(auth),
            models: complete.then_some(models),
        })
    })
    .await
    .ok()
    .flatten();
    report.unwrap_or_default()
}

/// `account/read`: signed out when codex needs an OpenAI login and has no account.
fn parse_codex_account(account: &Value) -> AuthStatus {
    let requires_auth = account
        .get("requiresOpenaiAuth")
        .or_else(|| account.get("requires_openai_auth"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_account = account.get("account").is_some_and(|a| !a.is_null());
    if requires_auth && !has_account {
        AuthStatus::Unauthenticated
    } else {
        AuthStatus::Authenticated
    }
}

/// One `model/list` page: its models and the next cursor.
fn map_codex_models(page: &Value) -> (Vec<ModelInfo>, Option<String>) {
    let text = |item: &Value, key: &str| {
        item[key]
            .as_str()
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let models = page["data"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(ModelInfo {
                        id: text(item, "id").or_else(|| text(item, "model"))?,
                        name: text(item, "displayName"),
                        description: text(item, "description"),
                        is_default: item["isDefault"].as_bool().unwrap_or(false),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    (models, text(page, "nextCursor"))
}

enum RpcError {
    /// The CLI does not know the method (an older version).
    Unsupported,
    Failed,
}

/// Line-delimited JSON-RPC to `codex app-server`.
struct JsonRpc {
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    next_id: u64,
}

impl JsonRpc {
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id;
        self.next_id += 1;
        write_line(
            &mut self.stdin,
            &json!({ "method": method, "id": id, "params": params }),
        )
        .await
        .ok_or(RpcError::Failed)?;
        while let Some(line) = self.lines.next_line().await.map_err(|_| RpcError::Failed)? {
            let Ok(frame) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if frame["id"] != id {
                continue;
            }
            if let Some(error) = frame.get("error") {
                let unsupported = error["code"] == -32601
                    || error["message"].as_str().is_some_and(|message| {
                        let message = message.to_ascii_lowercase();
                        ["method not found", "not supported", "unknown method"]
                            .iter()
                            .any(|needle| message.contains(needle))
                    });
                return Err(if unsupported {
                    RpcError::Unsupported
                } else {
                    RpcError::Failed
                });
            }
            return Ok(frame.get("result").cloned().unwrap_or(Value::Null));
        }
        Err(RpcError::Failed)
    }

    async fn notify(&mut self, method: &str) -> Option<()> {
        write_line(&mut self.stdin, &json!({ "method": method, "params": {} })).await
    }
}

// ─── shared ─────────────────────────────────────────────────────────────────

fn pipes(child: &mut Child) -> Option<(ChildStdin, Lines<BufReader<ChildStdout>>)> {
    Some((
        child.stdin.take()?,
        BufReader::new(child.stdout.take()?).lines(),
    ))
}

async fn write_line(stdin: &mut ChildStdin, frame: &Value) -> Option<()> {
    let mut line = frame.to_string();
    line.push('\n');
    stdin.write_all(line.as_bytes()).await.ok()?;
    stdin.flush().await.ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]

    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use serde_json::json;

    use super::{
        AuthStatus, EngineKind, ModelInfo, ProbeCommand, map_claude_models, map_codex_models,
        parse_claude_auth, parse_codex_account, probe,
    };

    fn model(id: &str, name: Option<&str>, is_default: bool) -> ModelInfo {
        ModelInfo {
            id: id.to_owned(),
            name: name.map(str::to_owned),
            description: None,
            is_default,
        }
    }

    #[test]
    fn claude_models_resolve_ids_and_mark_the_default() {
        let raw = json!([
            { "value": "default", "resolvedModel": "claude-sonnet-x", "displayName": "Default (recommended)" },
            { "value": "opus", "resolvedModel": "claude-opus-x", "displayName": "Opus" },
            { "value": "claude-sonnet-x", "displayName": "Sonnet", "description": "fast" },
            { "value": "opus", "resolvedModel": "claude-opus-x", "displayName": "Opus again" },
            { "displayName": "no id" },
            "not an object",
        ]);
        assert_eq!(
            map_claude_models(&raw),
            [
                model("claude-opus-x", Some("Opus"), false),
                ModelInfo {
                    description: Some("fast".to_owned()),
                    ..model("claude-sonnet-x", Some("Sonnet"), true)
                },
            ]
        );
    }

    #[test]
    fn a_claude_default_missing_from_the_list_is_listed_first() {
        let raw = json!([
            { "value": "default", "resolvedModel": "claude-new" },
            { "value": "claude-old" },
        ]);
        assert_eq!(
            map_claude_models(&raw),
            [
                model("claude-new", None, true),
                model("claude-old", None, false)
            ]
        );
        assert!(map_claude_models(&json!(null)).is_empty());
    }

    #[test]
    fn claude_auth_status_reads_logged_in() {
        assert_eq!(
            parse_claude_auth("noise {\"loggedIn\": true, \"authMethod\": \"x\"}\n"),
            Some(AuthStatus::Authenticated)
        );
        assert_eq!(
            parse_claude_auth("{\"loggedIn\": false}"),
            Some(AuthStatus::Unauthenticated)
        );
        assert_eq!(parse_claude_auth("error: unknown command"), None);
        assert_eq!(parse_claude_auth("{\"loggedIn\": \"yes\"}"), None);
    }

    #[test]
    fn codex_account_needs_an_account_when_auth_is_required() {
        assert_eq!(
            parse_codex_account(&json!({ "requiresOpenaiAuth": true, "account": null })),
            AuthStatus::Unauthenticated
        );
        assert_eq!(
            parse_codex_account(
                &json!({ "requires_openai_auth": true, "account": { "type": "apiKey" } })
            ),
            AuthStatus::Authenticated
        );
        assert_eq!(
            parse_codex_account(&json!({ "requiresOpenaiAuth": false })),
            AuthStatus::Authenticated
        );
    }

    #[test]
    fn codex_model_pages_map_and_carry_the_cursor() {
        let page = json!({
            "data": [
                { "id": "gpt-a", "model": "gpt-a", "displayName": "GPT A", "isDefault": true },
                { "model": "gpt-b" },
                { "displayName": "no id" },
            ],
            "nextCursor": "c2",
        });
        assert_eq!(
            map_codex_models(&page),
            (
                vec![
                    model("gpt-a", Some("GPT A"), true),
                    model("gpt-b", None, false)
                ],
                Some("c2".to_owned())
            )
        );
        assert_eq!(
            map_codex_models(&json!({ "data": [], "nextCursor": null })).1,
            None
        );
    }

    fn script(dir: &Path, name: &str, body: &str) -> ProbeCommand {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        ProbeCommand {
            program: path,
            env: Vec::new(),
            cwd: dir.to_path_buf(),
        }
    }

    #[tokio::test]
    async fn a_claude_probe_reads_auth_and_the_initialize_models() {
        let dir = tempfile::tempdir().unwrap();
        let mut command = script(
            dir.path(),
            "claude",
            r#"if [ "$1" = auth ]; then echo '{"loggedIn": false}'; exit 0; fi
read -r line
id=$(printf '%s' "$line" | sed 's/.*"request_id":"\([^"]*\)".*/\1/')
echo '{"type":"system","subtype":"init"}'
printf '{"type":"control_response","response":{"request_id":"%s","response":{"models":[{"value":"default","resolvedModel":"m-1"},{"value":"m-1","displayName":"M1"}]}}}\n' "$id"
"#,
        );
        let report = probe(EngineKind::Claude, &command).await;
        assert_eq!(report.auth, Some(AuthStatus::Unauthenticated));
        assert_eq!(report.models, Some(vec![model("m-1", Some("M1"), true)]));
        assert_eq!(report.default_model(), Some("m-1"));

        // A configured key signs the runs in whatever the CLI says.
        command
            .env
            .push(("CLAUDE_CODE_OAUTH_TOKEN".to_owned(), "t".into()));
        assert_eq!(
            probe(EngineKind::Claude, &command).await.auth,
            Some(AuthStatus::Authenticated)
        );

        // A CLI without `auth status` falls back to the configured credential.
        command = script(dir.path(), "old-claude", "exit 1\n");
        command
            .env
            .push(("ANTHROPIC_API_KEY".to_owned(), "k".into()));
        let report = probe(EngineKind::Claude, &command).await;
        assert_eq!(report.auth, Some(AuthStatus::Authenticated));
        assert_eq!(report.models, None);
    }

    #[tokio::test]
    async fn a_codex_probe_reads_the_account_and_every_model_page() {
        let dir = tempfile::tempdir().unwrap();
        let command = script(
            dir.path(),
            "codex",
            r#"[ "$1" = app-server ] || exit 2
while read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*) echo "{\"id\":$id,\"result\":{}}" ;;
    *'"account/read"'*) echo "{\"id\":$id,\"error\":{\"code\":-32601,\"message\":\"method not found\"}}" ;;
    *'"cursor":"p2"'*) echo "{\"id\":$id,\"result\":{\"data\":[{\"id\":\"gpt-b\"}],\"nextCursor\":null}}" ;;
    *'"model/list"'*) echo '{"method":"note"}'; echo "{\"id\":$id,\"result\":{\"data\":[{\"id\":\"gpt-a\",\"isDefault\":true}],\"nextCursor\":\"p2\"}}" ;;
  esac
done
"#,
        );
        let report = probe(EngineKind::Codex, &command).await;
        assert_eq!(
            report.auth,
            Some(AuthStatus::Unknown),
            "no credential to fall back on"
        );
        assert_eq!(
            report.models,
            Some(vec![
                model("gpt-a", None, true),
                model("gpt-b", None, false)
            ])
        );
    }

    #[tokio::test]
    async fn a_missing_cli_reports_nothing_it_could_not_answer() {
        let command = ProbeCommand {
            program: "/nonexistent/codex".into(),
            env: Vec::new(),
            cwd: std::path::PathBuf::new(),
        };
        assert_eq!(
            probe(EngineKind::Codex, &command).await,
            super::ProbeReport::default()
        );
        let claude = probe(EngineKind::Claude, &command).await;
        assert_eq!(
            (claude.auth, claude.models),
            (Some(AuthStatus::Unknown), None)
        );
    }
}
