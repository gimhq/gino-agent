//! Joint suite: the real `gino-agent` binary against mini-host, one scenario per protocol
//! surface. The agent runs with the `e2e/` fake engines, so no LLM credential is needed.
//!
//! Ignored by default; run with the agent binary to test:
//!
//! ```text
//! GINO_AGENT_BIN=/path/to/gino-agent cargo test --test joint -- --ignored --test-threads=1
//! ```
//!
//! `scripts/joint-it.sh` builds the agent and runs this suite. `JOINT_LOG=gino_mini_host=debug`
//! prints the host log; a timeout prints the tail of the agent log.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test harness: a failed step is a test failure"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gino_mini_host::{Config, Host, router};
use serde_json::{Value, json};
use tokio::process::{Child, Command};

const REGISTER_TOKEN: &str = "joint-register-token";
const SETTLE: Duration = Duration::from_secs(20);

/// One mini-host and one agent process with its own workspace.
struct Joint {
    base: String,
    dir: tempfile::TempDir,
    agent: Option<Child>,
    agent_id: String,
}

fn agent_bin() -> PathBuf {
    PathBuf::from(
        std::env::var("GINO_AGENT_BIN").expect("set GINO_AGENT_BIN to the gino-agent binary"),
    )
}

/// The repository's `e2e/` fakes, installed as `claude` and `codex`.
fn install_fakes(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let e2e = Path::new(env!("CARGO_MANIFEST_DIR")).join("../e2e");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for (from, to) in [("fake-claude", "claude"), ("fake-codex", "codex")] {
        let target = bin.join(to);
        std::fs::copy(e2e.join(from), &target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    bin
}

impl Joint {
    /// Start mini-host with `engine` as the initial `config.engine`, then the agent, and wait
    /// until it is registered and online.
    async fn start(engine: Value) -> Self {
        // `JOINT_LOG=gino_mini_host=debug` shows the host's own log beside a failure.
        if let Ok(filter) = std::env::var("JOINT_LOG") {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
                .with_test_writer()
                .try_init();
        }
        let dir = tempfile::tempdir().unwrap();
        let Value::Object(engine) = engine else {
            panic!("engine must be an object")
        };
        let host: Arc<Host> = Host::open(Config {
            register_token: REGISTER_TOKEN.into(),
            db_path: dir.path().join("host.db"),
            engine,
            heartbeat_interval_ms: 1000,
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router(host)).await.unwrap() });
        let mut joint = Self {
            base,
            dir,
            agent: None,
            agent_id: String::new(),
        };
        joint.spawn_agent();
        let agents = joint
            .until("the agent registers and connects", || async {
                let (_, agents) = joint.get("/api/agents").await;
                agents
                    .as_array()
                    .and_then(|a| a.first())
                    .filter(|a| a["online"] == json!(true))
                    .cloned()
            })
            .await;
        agents["id"]
            .as_str()
            .unwrap()
            .clone_into(&mut joint.agent_id);
        joint
    }

    fn workspace(&self) -> PathBuf {
        self.dir.path().join("workspace")
    }

    fn engine_log(&self) -> PathBuf {
        self.dir.path().join("engine.log")
    }

    fn host_db(&self) -> PathBuf {
        self.dir.path().join("host.db")
    }

    /// Start (or restart) the agent on the same workspace.
    fn spawn_agent(&mut self) {
        let bin = install_fakes(self.dir.path());
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.path().join("agent.log"))
            .unwrap();
        let child = Command::new(agent_bin())
            .arg("run")
            .env("PATH", path)
            .env("GINO_HOST_URL", &self.base)
            .env("GINO_REGISTER_TOKEN", REGISTER_TOKEN)
            .env("GINO_AGENT_NAME", "joint")
            .env("GINO_WORKSPACE_DIR", self.workspace())
            .env("GINO_DB_PATH", self.workspace().join("agent.db"))
            .env("RUST_LOG", "info")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(log)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        self.agent = Some(child);
    }

    async fn stop_agent(&mut self) {
        if let Some(mut child) = self.agent.take() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = reqwest::Client::new().request(method, format!("{}{path}", self.base));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    async fn get(&self, path: &str) -> (u16, Value) {
        self.request(reqwest::Method::GET, path, None).await
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    async fn patch(&self, path: &str, body: Value) -> (u16, Value) {
        self.request(reqwest::Method::PATCH, path, Some(body)).await
    }

    async fn agent(&self) -> Value {
        self.get(&format!("/api/agents/{}", self.agent_id)).await.1
    }

    /// Poll `probe` until it yields a value; fail with the agent log after [`SETTLE`].
    async fn until<T, F, Fut>(&self, what: &str, probe: F) -> T
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Option<T>>,
    {
        let deadline = Instant::now() + SETTLE;
        loop {
            if let Some(value) = probe().await {
                return value;
            }
            if Instant::now() >= deadline {
                let log =
                    std::fs::read_to_string(self.dir.path().join("agent.log")).unwrap_or_default();
                let tail: Vec<&str> = log.lines().rev().take(40).collect();
                panic!(
                    "timed out: {what}\nagent log (newest first):\n{}",
                    tail.join("\n")
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Patch the agent's host config and wait until a heartbeat reports the new version.
    async fn configure(&self, patch: Value) -> i64 {
        let (status, body) = self
            .patch(&format!("/api/agents/{}/config", self.agent_id), patch)
            .await;
        assert_eq!(status, 200, "{body}");
        let version = body["version"].as_i64().unwrap();
        self.until("the agent applies the config version", || async {
            (self.agent().await["appliedConfigVersion"] == json!(version)).then_some(())
        })
        .await;
        version
    }

    async fn create_task(&self, body: Value) -> String {
        let (status, created) = self.post("/api/tasks", body).await;
        assert_eq!(status, 201, "{created}");
        created["taskId"].as_str().unwrap().to_owned()
    }

    /// Send `text` to `task` and wait for the terminal result; returns the thread view.
    async fn run(&self, task: &str, body: Value) -> Value {
        let (status, sent) = self
            .post(&format!("/api/tasks/{task}/messages"), body)
            .await;
        assert_eq!(status, 202, "{sent}");
        self.wait(&sent).await
    }

    /// Wait for the result of the message `sent` answered.
    async fn wait(&self, sent: &Value) -> Value {
        let thread = sent["threadId"].as_str().unwrap();
        let after = sent["runs"].as_i64().unwrap();
        let (status, view) = self
            .get(&format!(
                "/api/threads/{thread}/wait?timeoutMs=30000&after={after}"
            ))
            .await;
        assert_eq!(status, 200, "no result: {view}");
        view
    }

    /// The engine invocations recorded by the fakes (`FAKE_ENGINE_LOG`).
    fn engine_calls(&self) -> Vec<Value> {
        std::fs::read_to_string(self.engine_log())
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn flag(argv: &Value, name: &str) -> Option<String> {
    let argv = argv.as_array()?;
    let at = argv.iter().position(|a| a == name)?;
    argv.get(at + 1)?.as_str().map(str::to_owned)
}

fn log_env(joint: &Joint) -> Value {
    json!({ "FAKE_ENGINE_LOG": joint.engine_log().display().to_string(), "JOINT_PROBE": "probe-1" })
}

// ─── enrollment, dispatch, transcript and result ────────────────────────────

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn a_turn_reports_its_transcript_usage_and_the_runner_defaults() {
    let url = "https://u:p@proxy.example:8443/x"; // trufflehog:ignore
    let joint = Joint::start(json!({ "model": "m-default", "anthropicBaseUrl": url })).await;

    let agent = joint.agent().await;
    let capabilities = agent["capabilities"].as_array().unwrap();
    assert!(
        capabilities.contains(&json!("claude")) && capabilities.contains(&json!("codex")),
        "{agent}"
    );
    let expected =
        json!({ "engine": "claude", "model": "m-default", "baseUrlHost": "proxy.example" });
    joint
        .until("a heartbeat reports the effective defaults", || async {
            (joint.agent().await["defaults"] == expected).then_some(())
        })
        .await;
    joint
        .until("a heartbeat lists the engines", || async {
            joint.agent().await["engines"]
                .as_array()
                .filter(|e| !e.is_empty())
                .map(|_| ())
        })
        .await;

    let task = joint.create_task(json!({ "name": "basic" })).await;
    let view = joint.run(&task, json!({ "text": "hello joint" })).await;
    let run = &view["run"];
    assert_eq!(run["status"], "succeeded", "{view}");
    assert!(
        run["result"].as_str().unwrap().contains("hello joint"),
        "{run}"
    );
    assert_eq!(run["engine"], "claude");
    assert_eq!(run["model"], "fake-e2e", "the engine-reported model");
    assert_eq!(
        run["usage"],
        json!({ "inputTokens": 12, "outputTokens": 5, "cacheReadTokens": 3, "costUsd": 0.001 })
    );
    // Ordered by seq, with the sub-agent attribution of protocol §5.
    let messages = view["messages"].as_array().unwrap();
    let seqs: Vec<i64> = messages
        .iter()
        .map(|m| m["seq"].as_i64().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    assert_eq!(run["final_seq"], json!(seqs.last().copied().unwrap()));
    assert!(
        messages
            .iter()
            .any(|m| m["parent_tool_use_id"] == "toolu_e2e_task_1"),
        "{messages:?}"
    );

    // A second message continues the same thread; newThread starts another.
    let again = joint.run(&task, json!({ "text": "second" })).await;
    assert_eq!(again["threadId"], view["threadId"]);
    let fresh = joint
        .run(&task, json!({ "text": "third", "newThread": true }))
        .await;
    assert_ne!(fresh["threadId"], view["threadId"]);

    let (status, deleted) = joint
        .request(reqwest::Method::DELETE, &format!("/api/tasks/{task}"), None)
        .await;
    assert_eq!(status, 200, "{deleted}");
}

// ─── engines and engine options ─────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn a_codex_task_runs_on_codex_and_reports_its_usage() {
    let joint = Joint::start(json!({})).await;
    joint
        .configure(json!({ "engine": { "env": log_env(&joint) } }))
        .await;
    let task = joint
        .create_task(json!({ "engine": "codex", "model": "gpt-joint" }))
        .await;
    let view = joint.run(&task, json!({ "text": "codex please" })).await;
    let run = &view["run"];
    assert_eq!(run["status"], "succeeded", "{view}");
    assert!(
        run["result"].as_str().unwrap().contains("codex please"),
        "{run}"
    );
    assert_eq!(run["engine"], "codex");
    assert_eq!(
        run["model"], "gpt-joint",
        "the task model, as codex reports none"
    );
    assert_eq!(
        run["usage"],
        json!({ "inputTokens": 20, "outputTokens": 4, "cacheReadTokens": 8 })
    );
    let calls = joint.engine_calls();
    let call = calls
        .iter()
        .find(|c| c["engine"] == "codex")
        .expect("codex ran");
    assert_eq!(call["probe"], "probe-1", "engine.env reaches codex");
    assert_eq!(flag(&call["argv"], "--model").as_deref(), Some("gpt-joint"));
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn engine_options_reach_the_engine_and_clear_with_null() {
    let joint = Joint::start(json!({ "model": "m-config" })).await;
    let mcp = json!([
        { "name": "files", "command": "mcp-files", "args": ["/data"], "env": { "TOKEN": "t", "PATH": "/evil" } },
        { "name": "web", "url": "https://mcp.example/mcp" },
        { "name": "bad name", "command": "x" },
    ]);
    joint
        .configure(json!({ "engine": {
            "env": log_env(&joint),
            "fallbackModel": "m-fallback",
            "maxTurns": 7,
            "mcpServers": mcp,
        } }))
        .await;
    let task = joint.create_task(json!({ "model": "m-task" })).await;
    joint.run(&task, json!({ "text": "one" })).await;
    let call = joint.engine_calls().pop().unwrap();
    let argv = &call["argv"];
    assert_eq!(call["probe"], "probe-1", "engine.env reaches claude");
    assert_eq!(
        flag(argv, "--fallback-model").as_deref(),
        Some("m-fallback")
    );
    assert_eq!(flag(argv, "--max-turns").as_deref(), Some("7"));
    assert_eq!(
        flag(argv, "--model").as_deref(),
        Some("m-task"),
        "the task model wins"
    );
    let mcp: Value = serde_json::from_str(&flag(argv, "--mcp-config").unwrap()).unwrap();
    assert_eq!(
        mcp,
        json!({ "mcpServers": {
            "files": { "command": "mcp-files", "args": ["/data"], "env": { "TOKEN": "t" } },
            "web": { "type": "http", "url": "https://mcp.example/mcp" },
        } }),
        "invalid servers and denied env keys are dropped"
    );

    // `null` clears the options, and the task model falls back to the config model.
    joint
        .configure(
            json!({ "engine": { "fallbackModel": null, "maxTurns": null, "mcpServers": null } }),
        )
        .await;
    let (status, body) = joint
        .patch(&format!("/api/tasks/{task}"), json!({ "model": null }))
        .await;
    assert_eq!(status, 200, "{body}");
    joint.run(&task, json!({ "text": "two" })).await;
    let calls = joint.engine_calls();
    let argv = calls.last().unwrap()["argv"].clone();
    for gone in ["--fallback-model", "--max-turns", "--mcp-config"] {
        assert!(flag(&argv, gone).is_none(), "{gone} still set: {argv}");
    }
    assert_eq!(flag(&argv, "--model").as_deref(), Some("m-config"));
    let defaults = joint.agent().await["defaults"].clone();
    assert_eq!(defaults["model"], "m-config");
}

/// The heartbeat entry of engine `name`.
fn engine<'a>(engines: &'a Value, name: &str) -> &'a Value {
    engines
        .as_array()
        .and_then(|engines| engines.iter().find(|e| e["name"] == name))
        .unwrap_or(&Value::Null)
}

fn model_ids(engine: &Value) -> Vec<&str> {
    engine["models"]
        .as_array()
        .map(|models| models.iter().filter_map(|m| m["id"].as_str()).collect())
        .unwrap_or_default()
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn engines_report_models_and_sign_in_and_tasks_are_checked_against_them() {
    let joint = Joint::start(json!({})).await;
    let engines = joint
        .until("the probe reports both engines", || async {
            let engines = joint.agent().await["engines"].clone();
            let probed = ["claude", "codex"]
                .iter()
                .all(|name| engine(&engines, name)["models"].is_array());
            probed.then_some(engines)
        })
        .await;
    let (claude, codex) = (engine(&engines, "claude"), engine(&engines, "codex"));
    assert_eq!(claude["version"], "2.0.0");
    assert_eq!(model_ids(claude), ["fake-e2e", "m-task"]);
    assert_eq!(claude["models"][0]["isDefault"], true);
    assert_eq!(claude["defaultModel"], "fake-e2e", "the CLI's default");
    assert_eq!(model_ids(codex), ["gpt-fake", "gpt-joint"], "every page");
    assert_eq!(codex["defaultModel"], "gpt-fake");
    for e in [claude, codex] {
        assert_eq!(e["auth"], "unauthenticated", "no credential yet: {e}");
    }
    joint
        .until("defaults take the probed model", || async {
            (joint.agent().await["defaults"] == json!({ "engine": "claude", "model": "fake-e2e" }))
                .then_some(())
        })
        .await;

    // Credentials re-probe the engines; `defaultEngine` moves the defaults to codex.
    joint
        .configure(json!({ "engine": {
            "anthropicApiKey": "sk-joint",
            "defaultEngine": "codex",
            "codex": { "openaiApiKey": "sk-joint-codex", "openaiBaseUrl": "https://openai.example/v1" },
        } }))
        .await;
    joint
        .until("the re-probe sees both engines signed in", || async {
            let engines = joint.agent().await["engines"].clone();
            ["claude", "codex"]
                .iter()
                .all(|name| engine(&engines, name)["auth"] == "authenticated")
                .then_some(())
        })
        .await;
    let expected =
        json!({ "engine": "codex", "model": "gpt-fake", "baseUrlHost": "openai.example" });
    joint
        .until("defaults follow the default engine", || async {
            (joint.agent().await["defaults"] == expected).then_some(())
        })
        .await;
    let seen = joint.agent().await.to_string();
    assert!(!seen.contains("sk-joint"), "a key reached the agent view");

    // The host checks a task's engine and model against what the agent reported.
    for (body, reason) in [
        (json!({ "engine": "gemini" }), "does not run engine gemini"),
        (
            json!({ "engine": "claude", "model": "gpt-joint" }),
            "offers no model gpt-joint",
        ),
        (json!({ "model": "m-task" }), "engine codex"),
    ] {
        let (status, rejected) = joint.post("/api/tasks", body).await;
        assert_eq!(status, 400, "{rejected}");
        assert!(
            rejected["error"].as_str().unwrap().contains(reason),
            "{rejected}"
        );
    }
    let task = joint.create_task(json!({ "model": "gpt-joint" })).await;
    let (status, rejected) = joint
        .patch(&format!("/api/tasks/{task}"), json!({ "engine": "claude" }))
        .await;
    assert_eq!(
        status, 400,
        "the stored model is not a claude model: {rejected}"
    );
    let (status, body) = joint
        .patch(
            &format!("/api/tasks/{task}"),
            json!({ "engine": "claude", "model": "m-task" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // A task that names no engine runs on the default engine.
    let task = joint.create_task(json!({ "name": "default engine" })).await;
    let view = joint.run(&task, json!({ "text": "which engine" })).await;
    assert_eq!(view["run"]["status"], "succeeded", "{view}");
    assert_eq!(view["run"]["engine"], "codex");
}

// ─── delivery: replay, interrupt, close ─────────────────────────────────────

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn frames_sent_while_the_agent_is_down_replay_on_reconnect() {
    let mut joint = Joint::start(json!({})).await;
    let task = joint.create_task(json!({ "name": "replay" })).await;
    joint.run(&task, json!({ "text": "before" })).await;

    joint.stop_agent().await;
    joint
        .until("the host sees the agent offline", || async {
            (joint.agent().await["online"] == json!(false)).then_some(())
        })
        .await;
    let (status, sent) = joint
        .post(
            &format!("/api/tasks/{task}/messages"),
            json!({ "text": "while down" }),
        )
        .await;
    assert_eq!((status, &sent["agentOnline"]), (202, &json!(false)));

    // The restarted agent reuses its identity (no second register) and receives the message.
    joint.spawn_agent();
    let view = joint.wait(&sent).await;
    let messages = view["messages"].as_array().unwrap();
    assert!(
        messages.iter().any(|m| m["content"]
            .as_str()
            .is_some_and(|c| c.contains("while down"))),
        "{view}"
    );
    let (_, agents) = joint.get("/api/agents").await;
    assert_eq!(agents.as_array().unwrap().len(), 1, "no second enrollment");
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn an_interrupt_ends_the_running_turn() {
    let joint = Joint::start(json!({})).await;
    let task = joint.create_task(json!({ "name": "interrupt" })).await;
    let (status, sent) = joint
        .post(
            &format!("/api/tasks/{task}/messages"),
            json!({ "text": "sleep:20" }),
        )
        .await;
    assert_eq!(status, 202);
    // Interrupt once the engine runs: its first transcript event has arrived.
    let thread = sent["threadId"].as_str().unwrap().to_owned();
    joint
        .until("the turn starts", || async {
            let view = joint.get(&format!("/api/threads/{thread}")).await.1;
            view["messages"]
                .as_array()
                .filter(|m| !m.is_empty())
                .map(|_| ())
        })
        .await;
    let (status, body) = joint
        .post(&format!("/api/tasks/{task}/interrupt"), json!({}))
        .await;
    assert_eq!((status, body), (200, json!({ "sent": true })));
    let started = Instant::now();
    let (status, view) = joint
        .get(&format!("/api/threads/{thread}/wait?timeoutMs=30000"))
        .await;
    assert_eq!(status, 200, "{view}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the turn ran to completion: {view}"
    );
    assert_ne!(view["run"]["status"], "succeeded", "{view}");
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn close_stops_the_agent() {
    let mut joint = Joint::start(json!({})).await;
    let (status, body) = joint
        .post(
            &format!("/api/agents/{}/close", joint.agent_id),
            json!({ "reason": "stop" }),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let mut child = joint.agent.take().unwrap();
    let exit = tokio::time::timeout(SETTLE, child.wait()).await;
    assert!(exit.is_ok(), "the agent did not exit on close");
}

// ─── attachments and crons ──────────────────────────────────────────────────

async fn stage(joint: &Joint, task: &str, name: &str, bytes: &[u8]) -> Value {
    let response = reqwest::Client::new()
        .post(format!("{}/api/tasks/{task}/attachments", joint.base))
        .header("x-attachment-name", name)
        .header("content-type", "text/plain")
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    response.json().await.unwrap()
}

async fn read_attachment(joint: &Joint, task: &str, id: &str) -> Vec<u8> {
    let response = reqwest::get(format!("{}/api/tasks/{task}/attachments/{id}", joint.base))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.bytes().await.unwrap().to_vec()
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn attachments_travel_both_ways_over_the_byte_channel() {
    let joint = Joint::start(json!({})).await;
    let task = joint.create_task(json!({ "name": "files" })).await;
    let staged = stage(&joint, &task, "in.txt", b"hello-bytes").await;
    let view = joint
        .run(
            &task,
            json!({ "text": "process", "attachments": [staged["id"]] }),
        )
        .await;
    let run = &view["run"];
    assert_eq!(run["status"], "succeeded", "{view}");
    let attachments = run["attachments"].as_array().expect("result attachments");
    let out = attachments
        .iter()
        .find(|a| a["name"] == "in.txt.out")
        .unwrap_or_else(|| panic!("{attachments:?}"));
    assert_eq!(out["direction"], "outbound");
    let bytes = read_attachment(&joint, &task, out["id"].as_str().unwrap()).await;
    assert_eq!(bytes, b"processed:hello-bytes");
}

/// RFC 3339 UTC seconds `offset` from now.
fn rfc3339(offset: i64) -> (String, i64) {
    let secs = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        + offset;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    (text, secs)
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn a_once_cron_fires_and_reports_its_state() {
    let joint = Joint::start(json!({})).await;
    let task = joint.create_task(json!({ "name": "cron" })).await;
    let (slot, epoch) = rfc3339(-2);
    let (status, body) = joint
        .post(
            &format!("/api/tasks/{task}/crons"),
            json!({ "cronId": "cr-joint", "prompt": "nightly report", "scheduleType": "once", "scheduleValue": slot }),
        )
        .await;
    assert_eq!(status, 201, "{body}");
    let cron = joint
        .until("the cron reports a round", || async {
            let (_, crons) = joint.get("/api/crons").await;
            crons
                .as_array()?
                .iter()
                .find(|c| c["cronId"] == "cr-joint" && c["round_count"].as_i64() >= Some(1))
                .cloned()
        })
        .await;
    assert_eq!(cron["taskId"], json!(task));
    let thread = format!("cr-joint@{}", epoch * 1000);
    let (status, view) = joint
        .get(&format!("/api/threads/{thread}/wait?timeoutMs=30000"))
        .await;
    assert_eq!(status, 200, "{view}");
    assert!(
        view["run"]["result"]
            .as_str()
            .unwrap()
            .contains("nightly report"),
        "{view}"
    );
    let (status, _) = joint
        .request(
            reqwest::Method::DELETE,
            &format!("/api/tasks/{task}/crons/cr-joint"),
            None,
        )
        .await;
    assert_eq!(status, 200);
}

// ─── provisioning ───────────────────────────────────────────────────────────

async fn upload_artifact(joint: &Joint, bytes: &[u8]) -> String {
    let response = reqwest::Client::new()
        .post(format!("{}/api/artifacts", joint.base))
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    response.json::<Value>().await.unwrap()["sha256"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        builder.append_data(&mut header, path, *data).unwrap();
    }
    builder.into_inner().unwrap()
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn global_and_task_provisioning_materialize_and_reconcile() {
    let joint = Joint::start(json!({})).await;
    let instruction = b"# global CLAUDE.md\n";
    let skill = tar_of(&[
        ("SKILL.md", b"# demo skill\n"),
        ("scripts/run.sh", b"echo hi\n"),
    ]);
    let instruction_sha = upload_artifact(&joint, instruction).await;
    let skill_sha = upload_artifact(&joint, &skill).await;

    // An entry naming an artifact the host does not hold is refused.
    let (status, _) = joint
        .patch(
            &format!("/api/agents/{}/config", joint.agent_id),
            json!({ "entries": [{ "name": "x", "sha256": "00", "target": "X.md", "kind": "file" }] }),
        )
        .await;
    assert_eq!(status, 400);

    joint
        .configure(json!({ "entries": [
            { "name": "claude-md", "sha256": instruction_sha, "target": "CLAUDE.md", "kind": "file" },
            { "name": "demo-skill", "sha256": skill_sha, "target": "skills/demo", "kind": "dir" },
        ] }))
        .await;
    let global = joint.workspace().join("engine-config");
    assert_eq!(
        std::fs::read(global.join("CLAUDE.md")).unwrap(),
        instruction
    );
    assert_eq!(
        std::fs::read(global.join("skills/demo/scripts/run.sh")).unwrap(),
        b"echo hi\n"
    );

    // A versioned set without the skill removes it.
    joint
        .configure(json!({ "entries": [
            { "name": "claude-md", "sha256": instruction_sha, "target": "CLAUDE.md", "kind": "file" },
        ] }))
        .await;
    assert!(!global.join("skills/demo").exists());

    // Task scope: entries land in the thread's project dir.
    let task_file = b"# task AGENTS.md\n";
    let task_sha = upload_artifact(&joint, task_file).await;
    let task = joint
        .create_task(json!({ "entries": [
            { "name": "agents-md", "sha256": task_sha, "target": "AGENTS.md", "kind": "file" },
        ] }))
        .await;
    joint.run(&task, json!({ "text": "go" })).await;
    let project = std::fs::read_dir(joint.workspace().join("threads"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path().join("project"))
        .find(|p| p.join("AGENTS.md").exists())
        .expect("a project dir with the task entry");
    assert_eq!(std::fs::read(project.join("AGENTS.md")).unwrap(), task_file);
}

// ─── file operations ────────────────────────────────────────────────────────

async fn fs(joint: &Joint, body: Value) -> Value {
    let (status, answer) = joint
        .post(&format!("/api/agents/{}/fs", joint.agent_id), body)
        .await;
    assert_eq!(status, 200, "{answer}");
    answer
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn file_operations_cover_every_op_and_exclusive_races() {
    let joint = Joint::start(json!({})).await;
    let disabled = fs(&joint, json!({ "op": "list", "path": "." })).await;
    assert_eq!(disabled["error"]["code"], "disabled", "{disabled}");
    joint
        .configure(json!({ "remoteOps": { "fs": true } }))
        .await;

    assert_eq!(
        fs(
            &joint,
            json!({ "op": "mkdir", "path": "jt/sub", "recursive": true })
        )
        .await["ok"],
        true
    );
    let put = fs(
        &joint,
        json!({ "op": "put", "path": "jt/a.txt", "content": b64(b"alpha") }),
    )
    .await;
    assert_eq!(put["ok"], true, "{put}");
    let stat = fs(&joint, json!({ "op": "stat", "path": "jt/a.txt" })).await;
    assert_eq!(
        (&stat["stat"]["type"], &stat["stat"]["size"]),
        (&json!("file"), &json!(5))
    );
    let got = fs(&joint, json!({ "op": "get", "path": "jt/a.txt" })).await;
    assert_eq!(got["content"], json!(b64(b"alpha")), "{got}");
    let listed = fs(&joint, json!({ "op": "list", "path": "jt" })).await;
    let names: Vec<&str> = listed["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["a.txt", "sub"]);

    // Exclusive put and rename refuse anything at the destination.
    let refused = fs(
        &joint,
        json!({ "op": "put", "path": "jt/a.txt", "content": b64(b"x"), "exclusive": true }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "exists", "{refused}");
    fs(
        &joint,
        json!({ "op": "put", "path": "jt/b.txt", "content": b64(b"beta") }),
    )
    .await;
    let refused = fs(
        &joint,
        json!({ "op": "rename", "path": "jt/b.txt", "to": "jt/a.txt", "exclusive": true }),
    )
    .await;
    assert_eq!(refused["error"]["code"], "exists", "{refused}");
    let moved = fs(
        &joint,
        json!({ "op": "rename", "path": "jt/b.txt", "to": "jt/c.txt", "exclusive": true }),
    )
    .await;
    assert_eq!(moved["ok"], true, "{moved}");

    // Of concurrent exclusive puts to one path exactly one wins.
    let racers = (0..8).map(|i| {
        let body = json!({ "op": "put", "path": "jt/race.txt", "content": b64(format!("r{i}").as_bytes()), "exclusive": true });
        let joint = &joint;
        async move { fs(joint, body).await }
    });
    let answers = futures_util::future::join_all(racers).await;
    let winners = answers.iter().filter(|a| a["ok"] == true).count();
    assert_eq!(winners, 1, "{answers:?}");
    assert!(
        answers
            .iter()
            .filter(|a| a["ok"] != true)
            .all(|a| a["error"]["code"] == "exists")
    );

    let removed = fs(
        &joint,
        json!({ "op": "remove", "path": "jt", "recursive": true }),
    )
    .await;
    assert_eq!(removed["ok"], true);
    let gone = fs(&joint, json!({ "op": "stat", "path": "jt" })).await;
    assert_eq!(gone["error"]["code"], "not_found");
}

// ─── terminals ──────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn a_terminal_runs_input_and_reports_its_exit() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let joint = Joint::start(json!({})).await;
    joint
        .configure(json!({ "remoteOps": { "pty": true } }))
        .await;
    let url = format!(
        "{}/api/agents/{}/pty",
        joint.base.replace("http", "ws"),
        joint.agent_id
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let send = |frame: Value| Message::Text(frame.to_string().into());
    ws.send(send(
        json!({ "type": "open", "data": { "cols": 80, "rows": 24 } }),
    ))
    .await
    .unwrap();

    let mut next = async || -> Value {
        loop {
            let message = tokio::time::timeout(SETTLE, ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let Message::Text(text) = message {
                return serde_json::from_str(&text).unwrap();
            }
        }
    };
    let ready = next().await;
    assert_eq!(ready["type"], "ready", "{ready}");
    drop(next);

    ws.send(send(
        json!({ "type": "input", "data": { "data": b64(b"echo joint-$((6*7))\nexit 3\n") } }),
    ))
    .await
    .unwrap();
    let mut output = Vec::new();
    let exit = loop {
        let message = tokio::time::timeout(SETTLE, ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let Message::Text(text) = message else {
            continue;
        };
        let frame: Value = serde_json::from_str(&text).unwrap();
        match frame["type"].as_str() {
            Some("output") => {
                use base64::Engine as _;
                output.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(frame["data"]["data"].as_str().unwrap())
                        .unwrap(),
                );
            }
            Some("exit") => break frame,
            _ => {}
        }
    };
    assert!(
        String::from_utf8_lossy(&output).contains("joint-42"),
        "{}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(exit["data"]["exit_code"], 3, "{exit}");
}

// ─── end-to-end encryption ──────────────────────────────────────────────────

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn an_encrypted_task_runs_end_to_end_and_the_host_stores_only_ciphertext() {
    let mut joint = Joint::start(json!({})).await;
    joint
        .configure(json!({ "remoteOps": { "fs": true } }))
        .await;
    let identity = joint
        .until(
            "the runner's identity is pinned and it published KeyPackages",
            || async {
                let identity = joint.agent().await["identity"].clone();
                (identity["keyPackages"]["one_time"].as_i64() >= Some(1)).then_some(identity)
            },
        )
        .await;
    assert_eq!(
        identity["fingerprint"].as_str().unwrap().len(),
        79,
        "{identity}"
    );

    let (status, created) = joint
        .post("/api/tasks", json!({ "name": "secret", "encrypted": true }))
        .await;
    assert_eq!(status, 201, "{created}");
    let task = created["taskId"].as_str().unwrap().to_owned();

    let view = joint
        .run(&task, json!({ "text": "classified hello" }))
        .await;
    let run = &view["run"];
    assert_eq!(run["status"], "succeeded", "{view}");
    assert!(run.get("openError").is_none(), "{view}");
    assert!(
        run["result"].as_str().unwrap().contains("classified hello"),
        "{run}"
    );
    let first = &view["messages"][0];
    assert!(
        first["content"]
            .as_str()
            .unwrap()
            .contains("classified hello"),
        "{first}"
    );

    // A new epoch from the client device reaches the runner as `e2ee_log`; content still flows.
    let (status, epoch) = joint
        .post(&format!("/api/tasks/{task}/e2ee/update"), json!({}))
        .await;
    assert_eq!(status, 200, "{epoch}");
    let staged = stage(&joint, &task, "notes.txt", b"top-secret-bytes").await;
    let view = joint
        .run(
            &task,
            json!({ "text": "after rotation", "attachments": [{ "id": staged["id"], "name": "notes.txt" }] }),
        )
        .await;
    let run = &view["run"];
    assert_eq!(run["status"], "succeeded", "{view}");
    assert!(
        run["result"].as_str().unwrap().contains("after rotation"),
        "{run}"
    );
    let out = run["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "notes.txt.out")
        .cloned()
        .unwrap_or_else(|| panic!("{run}"));
    let bytes = read_attachment(&joint, &task, out["id"].as_str().unwrap()).await;
    assert_eq!(bytes, b"processed:top-secret-bytes");

    // The host's own records hold no plaintext: results, transcripts, outbox and blobs.
    let db = rusqlite::Connection::open(joint.host_db()).unwrap();
    for (table, column) in [
        ("thread_runs", "frame"),
        ("messages", "frame"),
        ("outbox", "frame"),
        ("blobs", "data"),
        ("blobs", "name"),
    ] {
        let leaks: i64 = db
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {table} WHERE CAST({column} AS TEXT) LIKE '%classified hello%'
                        OR CAST({column} AS TEXT) LIKE '%top-secret%' OR CAST({column} AS TEXT) LIKE '%notes.txt%'"
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(leaks, 0, "plaintext in {table}.{column}");
    }

    // After a restart the runner catches up with DS reads and keeps opening content.
    joint.stop_agent().await;
    joint.spawn_agent();
    let view = joint.run(&task, json!({ "text": "after restart" })).await;
    assert_eq!(view["run"]["status"], "succeeded", "{view}");
    assert!(
        view["run"]["result"]
            .as_str()
            .unwrap()
            .contains("after restart"),
        "{view}"
    );

    // A runner holding encrypted work refuses engine-free file access.
    let denied = fs(&joint, json!({ "op": "list", "path": "." })).await;
    assert_eq!(denied["error"]["code"], "denied", "{denied}");
}

#[tokio::test]
#[ignore = "needs GINO_AGENT_BIN"]
async fn an_encrypted_task_is_refused_for_a_runner_without_key_packages() {
    let joint = Joint::start(json!({})).await;
    joint
        .until("the runner published KeyPackages", || async {
            (joint.agent().await["identity"]["keyPackages"]["one_time"].as_i64() >= Some(1))
                .then_some(())
        })
        .await;
    // Drain the pool, including the last-resort KeyPackage, so the next claim finds nothing.
    let db = rusqlite::Connection::open(joint.host_db()).unwrap();
    db.execute("DELETE FROM e2ee_key_packages", []).unwrap();
    let (status, body) = joint.post("/api/tasks", json!({ "encrypted": true })).await;
    assert_eq!(
        (status, &body["error"]),
        (409, &json!("runner_without_encryption")),
        "{body}"
    );
}
