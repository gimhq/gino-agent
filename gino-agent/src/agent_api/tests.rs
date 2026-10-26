//! Socket-level tests for the agent API server and client.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Notify;

use super::client::{Client, ClientError};
use super::protocol::{ErrorCode, MAX_LINE_BYTES};
use super::scope::{NsLinks, is_operator};
use super::server::{Shared, serve_connection, serve_run_peers, serve_run_peers_with};
use super::{AgentApiServer, ApiContext, RunScope, TokenRegistry, socket_path};
use crate::db::{CronRow, Db, TaskRow, ThreadRow};

const TS: &str = "2026-10-24T00:00:00Z";

fn seed_task(db: &Db, id: &str) {
    db.insert_task_row(&TaskRow {
        id: id.to_owned(),
        name: Some(format!("{id} name")),
        kind: None,
        status: "active".to_owned(),
        engine: None,
        model: None,
        workdir: None,
        meta: None,
        created_at: TS.to_owned(),
        updated_at: TS.to_owned(),
    })
    .unwrap();
    db.insert_thread(&ThreadRow {
        id: format!("{id}-thread"),
        task_id: id.to_owned(),
        cron_id: None,
        source: "chat".to_owned(),
        prompt: "hi".to_owned(),
        engine: "claude".to_owned(),
        engine_session_id: None,
        status: "pending".to_owned(),
        failure_reason: None,
        attempt: 0,
        max_attempts: 3,
        work_dir: None,
        started_at: None,
        finished_at: None,
        duration_ms: None,
        result: None,
        error: None,
        created_at: TS.to_owned(),
    })
    .unwrap();
    db.insert_cron(&CronRow {
        id: format!("{id}-cron"),
        task_id: id.to_owned(),
        kind: "schedule".to_owned(),
        prompt: "tick".to_owned(),
        schedule_type: Some("interval".to_owned()),
        schedule_value: Some("60000".to_owned()),
        next_run: Some(TS.to_owned()),
        last_fired_at: None,
        continuity: "isolated".to_owned(),
        run_count: 0,
        status: "active".to_owned(),
        created_at: TS.to_owned(),
        updated_at: TS.to_owned(),
    })
    .unwrap();
}

/// A temp workspace with a db holding tasks `task-a` and `task-b`.
fn context() -> (TempDir, ApiContext) {
    let dir = tempfile::tempdir().unwrap();
    let workspace_dir = dir.path().join("ws");
    std::fs::create_dir_all(&workspace_dir).unwrap();
    let db_path = dir.path().join("agent.db");
    let db = Db::open(&db_path).unwrap();
    seed_task(&db, "task-a");
    seed_task(&db, "task-b");
    let ctx = ApiContext {
        db: Arc::new(Mutex::new(db)),
        nudge: Arc::new(Notify::new()),
        flush: Arc::new(Notify::new()),
        agent_name: Some("tester".to_owned()),
        host_url: Some("http://host.test".to_owned()),
        workspace_dir,
        db_path,
        e2ee: None,
    };
    (dir, ctx)
}

fn shared() -> (TempDir, Arc<Shared>, TokenRegistry) {
    let (dir, ctx) = context();
    let registry = TokenRegistry::default();
    (dir, Arc::new(Shared::new(ctx, registry.clone())), registry)
}

fn run_scope(task: &str) -> RunScope {
    RunScope {
        task_id: task.to_owned(),
        thread_id: format!("{task}-thread"),
    }
}

/// A raw NDJSON connection driven through the per-connection handler.
struct Conn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: u32,
}

impl Conn {
    fn open(shared: &Arc<Shared>, operator: bool) -> Self {
        let (client, server) = UnixStream::pair().unwrap();
        let shared = Arc::clone(shared);
        tokio::spawn(async move { serve_connection(server, &shared, operator).await });
        let (read, writer) = client.into_split();
        Self {
            reader: BufReader::new(read),
            writer,
            next_id: 0,
        }
    }

    async fn send(&mut self, raw: &[u8]) {
        self.writer.write_all(raw).await.unwrap();
    }

    /// The next response line, or `None` at EOF.
    async fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        if self.reader.read_line(&mut line).await.unwrap() == 0 {
            return None;
        }
        Some(serde_json::from_str(&line).unwrap())
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = format!("r{}", self.next_id);
        let line = json!({"v": 1, "id": id, "method": method, "params": params});
        self.send(format!("{line}\n").as_bytes()).await;
        let response = self.recv().await.unwrap();
        assert_eq!(response["id"], json!(id));
        assert_eq!(response["v"], json!(1));
        response
    }
}

fn error_code(response: &Value) -> &str {
    response["error"]["code"].as_str().unwrap_or("<none>")
}

#[tokio::test]
async fn two_requests_on_one_connection_answer_in_order() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    conn.send(
        b"{\"v\":1,\"id\":\"first\",\"method\":\"system.info\"}\n\
          {\"v\":1,\"id\":\"second\",\"method\":\"system.info\",\"params\":{}}\n",
    )
    .await;
    let first = conn.recv().await.unwrap();
    let second = conn.recv().await.unwrap();
    assert_eq!(first["id"], "first");
    assert_eq!(second["id"], "second");
    assert_eq!(first["v"], 1);
    assert_eq!(first["result"]["scope"], "operator");
    assert_eq!(second["result"]["scope"], "operator");
}

#[tokio::test]
async fn malformed_json_gets_null_id_and_the_connection_stays_usable() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    conn.send(b"{not json\n").await;
    let response = conn.recv().await.unwrap();
    assert_eq!(response["v"], 1);
    assert_eq!(response["id"], Value::Null);
    assert_eq!(error_code(&response), "invalid_params");
    let ok = conn.call("system.info", json!({})).await;
    assert_eq!(ok["result"]["scope"], "operator");
}

#[tokio::test]
async fn ill_typed_params_are_invalid() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    conn.send(b"{\"v\":1,\"id\":\"p\",\"method\":\"system.info\",\"params\":[]}\n")
        .await;
    let response = conn.recv().await.unwrap();
    assert_eq!(response["id"], "p");
    assert_eq!(error_code(&response), "invalid_params");
}

#[tokio::test]
async fn a_line_of_exactly_the_limit_is_accepted() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    let head = "{\"v\":1,\"id\":\"big\",\"method\":\"system.info\",\"params\":{\"pad\":\"";
    let tail = "\"}}";
    let pad = "x".repeat(MAX_LINE_BYTES - head.len() - tail.len());
    let line = format!("{head}{pad}{tail}\n");
    assert_eq!(line.len(), MAX_LINE_BYTES + 1);
    conn.send(line.as_bytes()).await;
    let response = conn.recv().await.unwrap();
    assert_eq!(response["id"], "big");
    assert_eq!(response["result"]["scope"], "operator");
}

#[tokio::test]
async fn an_oversized_line_is_rejected_then_the_connection_closes() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    let mut line = vec![b'x'; MAX_LINE_BYTES + 1];
    line.push(b'\n');
    conn.send(&line).await;
    let response = conn.recv().await.unwrap();
    assert_eq!(response["id"], Value::Null);
    assert_eq!(error_code(&response), "invalid_params");
    assert_eq!(
        response["error"]["message"],
        "request line exceeds 65536 bytes"
    );
    assert!(conn.recv().await.is_none(), "connection should close");
}

#[tokio::test]
async fn missing_or_other_version_is_unsupported() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    for raw in [
        "{\"id\":\"x\",\"method\":\"system.info\"}\n",
        "{\"v\":2,\"id\":\"x\",\"method\":\"system.info\"}\n",
        "{\"v\":\"1\",\"id\":\"x\",\"method\":\"system.info\"}\n",
    ] {
        conn.send(raw.as_bytes()).await;
        let response = conn.recv().await.unwrap();
        assert_eq!(response["id"], "x");
        assert_eq!(response["v"], 1);
        assert_eq!(error_code(&response), "unsupported_version");
        assert_eq!(
            response["error"]["message"],
            "unsupported protocol version; this agent speaks v1"
        );
    }
}

#[tokio::test]
async fn unknown_method_is_invalid_params() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    let response = conn.call("nope", json!({})).await;
    assert_eq!(error_code(&response), "invalid_params");
    assert_eq!(response["error"]["message"], "unknown method: nope");
}

#[tokio::test]
async fn a_non_operator_connection_needs_auth() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, false);
    let response = conn.call("system.info", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");
}

#[tokio::test]
async fn auth_returns_the_run_scope() {
    let (_dir, shared, registry) = shared();
    let token = registry.register(run_scope("task-a"));
    let mut conn = Conn::open(&shared, false);
    let response = conn.call("auth", json!({"token": token.as_str()})).await;
    assert_eq!(
        response["result"],
        json!({"scope": "run", "task_id": "task-a", "thread_id": "task-a-thread"})
    );
}

#[tokio::test]
async fn a_bad_token_drops_operator_access() {
    let (_dir, shared, _) = shared();
    let mut conn = Conn::open(&shared, true);
    let response = conn.call("auth", json!({"token": "00".repeat(32)})).await;
    assert_eq!(error_code(&response), "unauthenticated");
    let response = conn.call("system.info", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");
}

#[tokio::test]
async fn a_valid_token_turns_an_operator_connection_run_scoped() {
    let (_dir, shared, registry) = shared();
    let token = registry.register(run_scope("task-a"));
    let mut conn = Conn::open(&shared, true);
    conn.call("auth", json!({"token": token.as_str()})).await;
    let response = conn.call("system.info", json!({})).await;
    assert_eq!(response["result"]["scope"], "run");
}

#[tokio::test]
async fn revocation_unauthenticates_the_next_request() {
    let (_dir, shared, registry) = shared();
    let token = registry.register(run_scope("task-a"));
    let mut conn = Conn::open(&shared, false);
    conn.call("auth", json!({"token": token.as_str()})).await;
    assert_eq!(
        conn.call("system.info", json!({})).await["result"]["scope"],
        "run"
    );
    registry.revoke(token.as_str());
    let response = conn.call("system.info", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");
    let response = conn.call("auth", json!({"token": token.as_str()})).await;
    assert_eq!(error_code(&response), "unauthenticated");
}

#[tokio::test]
async fn the_ninth_connection_per_token_is_unavailable() {
    let (_dir, shared, registry) = shared();
    let token = registry.register(run_scope("task-a"));
    let mut conns = Vec::new();
    for _ in 0..8 {
        let mut conn = Conn::open(&shared, false);
        let response = conn.call("auth", json!({"token": token.as_str()})).await;
        assert_eq!(response["result"]["scope"], "run");
        conns.push(conn);
    }
    let mut ninth = Conn::open(&shared, false);
    let response = ninth.call("auth", json!({"token": token.as_str()})).await;
    assert_eq!(error_code(&response), "unavailable");
    assert_eq!(
        response["error"]["message"],
        "too many connections for this token"
    );
    let response = ninth.call("system.info", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");
    // A different token has its own budget.
    let other = registry.register(run_scope("task-b"));
    let response = ninth.call("auth", json!({"token": other.as_str()})).await;
    assert_eq!(response["result"]["task_id"], "task-b");
}

#[tokio::test]
async fn run_scoped_system_info_is_redacted_and_counts_only_its_task() {
    let (_dir, shared, registry) = shared();
    let token = registry.register(run_scope("task-a"));
    let mut conn = Conn::open(&shared, false);
    conn.call("auth", json!({"token": token.as_str()})).await;
    let info = conn.call("system.info", json!({})).await["result"].clone();
    assert_eq!(
        info,
        json!({
            "scope": "run",
            "version": env!("CARGO_PKG_VERSION"),
            "agent_id": null,
            "name": "tester",
            "host_url": "http://host.test",
            "capabilities": ["claude"],
            "tasks": 1,
            "active_crons": 1,
            "threads": {"pending": 1, "running": 0},
        })
    );
}

#[test]
fn operator_decision() {
    let ns = |user: &str, pid: &str| NsLinks {
        user: PathBuf::from(user),
        pid: PathBuf::from(pid),
    };
    let own = ns("user:[1]", "pid:[2]");
    assert!(is_operator(1000, 1000, Some(&own.clone()), Some(&own)));
    assert!(!is_operator(1001, 1000, Some(&own.clone()), Some(&own)));
    assert!(!is_operator(
        1000,
        1000,
        Some(&ns("user:[9]", "pid:[2]")),
        Some(&own)
    ));
    assert!(!is_operator(
        1000,
        1000,
        Some(&ns("user:[1]", "pid:[9]")),
        Some(&own)
    ));
    assert!(!is_operator(1000, 1000, None, Some(&own)));
    assert!(!is_operator(1000, 1000, Some(&own), None));
}

#[test]
fn run_tokens_are_random_hex_and_redacted_in_debug() {
    let registry = TokenRegistry::default();
    let a = registry.register(run_scope("task-a"));
    let b = registry.register(run_scope("task-a"));
    assert_eq!(a.as_str().len(), 64);
    assert!(
        a.as_str()
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    assert_ne!(a.as_str(), b.as_str());
    assert!(!format!("{a:?}").contains(a.as_str()));
    assert_eq!(registry.lookup(a.as_str()), Some(run_scope("task-a")));
    registry.revoke(a.as_str());
    assert_eq!(registry.lookup(a.as_str()), None);
    assert_eq!(registry.lookup(b.as_str()), Some(run_scope("task-a")));
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Run a blocking client closure off the runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn server_lifecycle_permissions_and_operator_client() {
    let (_dir, ctx) = context();
    let workspace = ctx.workspace_dir.clone();
    let db_path = ctx.db_path.clone();
    let socket = socket_path(&workspace);
    // A loose run dir is tightened and a stale file at the socket path replaced.
    let run_dir = workspace.join("run");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(&socket, b"stale").unwrap();

    let server = AgentApiServer::start(ctx, &workspace).unwrap();
    assert_eq!(mode(&run_dir), 0o700);
    assert_eq!(mode(&socket), 0o600);

    let path = socket.clone();
    let info = blocking(move || {
        let mut client = Client::connect(&path).unwrap();
        let info = client.call("system.info", json!({})).unwrap();
        let err = client.call("nope", json!({})).unwrap_err();
        (info, err)
    })
    .await;
    let (info, err) = info;
    assert_eq!(info["scope"], "operator");
    assert_eq!(info["workspace_dir"], workspace.display().to_string());
    assert_eq!(info["db_path"], db_path.display().to_string());
    assert_eq!(info["tasks"], 2);
    assert_eq!(info["active_crons"], 2);
    assert_eq!(info["threads"], json!({"pending": 2, "running": 0}));
    assert!(
        matches!(err, ClientError::Api { code: ErrorCode::InvalidParams, ref message } if message == "unknown method: nope")
    );

    // A run token through the real socket.
    let token = server.registry().register(run_scope("task-b"));
    let path = socket.clone();
    let (auth, info) = blocking(move || {
        let mut client = Client::connect(&path).unwrap();
        let auth = client.auth(token.as_str()).unwrap();
        (auth, client.call("system.info", json!({})).unwrap())
    })
    .await;
    assert_eq!(auth["task_id"], "task-b");
    assert_eq!(info["scope"], "run");
    assert!(info.get("workspace_dir").is_none());
    assert!(info.get("db_path").is_none());

    server.shutdown().await;
    assert!(!socket.exists(), "socket removed on shutdown");
    let err = blocking(move || Client::connect(&socket).unwrap_err()).await;
    assert!(matches!(err, ClientError::NotRunning(_)));
    assert_eq!(err.to_string(), "the agent is not running");
}

/// A handler fixture that keeps the db and nudge handles the server shares.
struct Fixture {
    _dir: TempDir,
    shared: Arc<Shared>,
    registry: TokenRegistry,
    db: Arc<Mutex<Db>>,
    nudge: Arc<Notify>,
    flush: Arc<Notify>,
}

impl Fixture {
    fn new() -> Self {
        let (dir, ctx) = context();
        let db = Arc::clone(&ctx.db);
        let nudge = Arc::clone(&ctx.nudge);
        let flush = Arc::clone(&ctx.flush);
        let registry = TokenRegistry::default();
        let shared = Arc::new(Shared::new(ctx, registry.clone()));
        Self {
            _dir: dir,
            shared,
            registry,
            db,
            nudge,
            flush,
        }
    }

    fn operator(&self) -> Conn {
        Conn::open(&self.shared, true)
    }

    /// A connection authenticated with a run token for `task`.
    async fn run(&self, task: &str) -> Conn {
        let token = self.registry.register(run_scope(task));
        let mut conn = Conn::open(&self.shared, false);
        let auth = conn.call("auth", json!({"token": token.as_str()})).await;
        assert_eq!(auth["result"]["task_id"], task);
        conn
    }

    /// `cron_state` outbox rows correlated to `cron_id`.
    fn cron_states(&self, cron_id: &str) -> usize {
        self.db
            .lock()
            .unwrap()
            .list_unacked_outbox()
            .unwrap()
            .iter()
            .filter(|r| r.msg_type == "cron_state" && r.thread_id.as_deref() == Some(cron_id))
            .count()
    }
}

fn task_json(id: &str) -> Value {
    json!({"id": id, "name": format!("{id} name"), "kind": null, "status": "active", "created_at": TS})
}

fn thread_json(task: &str) -> Value {
    json!({
        "id": format!("{task}-thread"),
        "task_id": task,
        "status": "pending",
        "source": "chat",
        "attempt": 0,
        "max_attempts": 3,
        "engine_session_id": null,
    })
}

fn cron_json(task: &str) -> Value {
    json!({
        "id": format!("{task}-cron"),
        "task_id": task,
        "kind": "schedule",
        "status": "active",
        "schedule_type": "interval",
        "schedule_value": "60000",
        "next_run": TS,
        "last_fired_at": null,
        "continuity": "isolated",
        "run_count": 0,
        "prompt": "tick",
        "created_at": TS,
        "updated_at": TS,
    })
}

/// `hidden` (for `id`) is the same response as `missing` (for `missing_id`),
/// apart from the request id.
fn assert_hidden(hidden: &Value, missing: &Value, missing_id: &str, id: &str) {
    assert_error(missing, "not_found", None);
    let strip = |v: &Value| {
        let mut v = v.clone();
        v.as_object_mut().unwrap().remove("id");
        v
    };
    let expected = serde_json::to_string(&strip(missing))
        .unwrap()
        .replace(missing_id, id);
    assert_eq!(
        strip(hidden),
        serde_json::from_str::<Value>(&expected).unwrap()
    );
}

fn assert_error(response: &Value, code: &str, message: Option<&str>) {
    assert_eq!(error_code(response), code, "{response}");
    if let Some(message) = message {
        assert_eq!(response["error"]["message"], message);
    }
}

#[tokio::test]
async fn task_methods_respect_scope() {
    let fx = Fixture::new();
    let mut op = fx.operator();
    let list = conn_result(&mut op, "task.list", json!({})).await;
    assert_eq!(
        list,
        json!({"tasks": [task_json("task-a"), task_json("task-b")]})
    );
    let show = conn_result(&mut op, "task.show", json!({"id": "task-b"})).await;
    assert_eq!(
        show,
        json!({"task": task_json("task-b"), "threads": [thread_json("task-b")], "crons": [cron_json("task-b")]})
    );
    let missing = op.call("task.show", json!({"id": "nope"})).await;
    assert_error(&missing, "not_found", Some("no such task: nope"));
    let bad = op.call("task.show", json!({"id": 7})).await;
    assert_error(&bad, "invalid_params", None);
    let extra = op.call("task.list", json!({"x": 1})).await;
    assert_error(&extra, "invalid_params", None);

    let mut run = fx.run("task-a").await;
    let list = conn_result(&mut run, "task.list", json!({})).await;
    assert_eq!(list, json!({"tasks": [task_json("task-a")]}));
    let show = conn_result(&mut run, "task.show", json!({"id": "task-a"})).await;
    assert_eq!(show["task"], task_json("task-a"));
    assert_eq!(show["threads"], json!([thread_json("task-a")]));
    assert_eq!(show["crons"], json!([cron_json("task-a")]));
    let other = run.call("task.show", json!({"id": "task-b"})).await;
    let missing = run.call("task.show", json!({"id": "nope"})).await;
    assert_error(&missing, "not_found", Some("no such task: nope"));
    assert_hidden(&other, &missing, "nope", "task-b");
}

#[tokio::test]
async fn thread_methods_respect_scope() {
    let fx = Fixture::new();
    let mut op = fx.operator();
    let missing_task = op.call("thread.list", json!({})).await;
    assert_error(&missing_task, "invalid_params", Some("task_id is required"));
    let list = conn_result(&mut op, "thread.list", json!({"task_id": "task-b"})).await;
    assert_eq!(list, json!({"threads": [thread_json("task-b")]}));
    let show = conn_result(&mut op, "thread.show", json!({"id": "task-b-thread"})).await;
    let mut detail = thread_json("task-b");
    let extra = json!({
        "cron_id": null,
        "failure_reason": null,
        "engine": "claude",
        "duration_ms": null,
        "prompt": "hi",
        "result": null,
        "error": null,
    });
    detail
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    assert_eq!(show, json!({"thread": detail}));
    let missing = op.call("thread.show", json!({"id": "nope"})).await;
    assert_error(&missing, "not_found", Some("no such thread: nope"));

    let mut run = fx.run("task-a").await;
    let list = conn_result(&mut run, "thread.list", json!({})).await;
    assert_eq!(list, json!({"threads": [thread_json("task-a")]}));
    let own = conn_result(&mut run, "thread.list", json!({"task_id": "task-a"})).await;
    assert_eq!(own, list);
    let other = run.call("thread.list", json!({"task_id": "task-b"})).await;
    assert_error(&other, "forbidden", None);
    let own = conn_result(&mut run, "thread.show", json!({"id": "task-a-thread"})).await;
    assert_eq!(own["thread"]["task_id"], "task-a");
    let other = run
        .call("thread.show", json!({"id": "task-b-thread"}))
        .await;
    let missing = run.call("thread.show", json!({"id": "nope"})).await;
    assert_error(&missing, "not_found", Some("no such thread: nope"));
    assert_hidden(&other, &missing, "nope", "task-b-thread");
}

#[tokio::test]
async fn cron_list_respects_scope() {
    let fx = Fixture::new();
    let mut op = fx.operator();
    let all = conn_result(&mut op, "cron.list", json!({})).await;
    assert_eq!(
        all,
        json!({"crons": [cron_json("task-a"), cron_json("task-b")], "scoped": false})
    );
    let one = conn_result(&mut op, "cron.list", json!({"task_id": "task-b"})).await;
    assert_eq!(one, json!({"crons": [cron_json("task-b")], "scoped": true}));

    let mut run = fx.run("task-a").await;
    let own = conn_result(&mut run, "cron.list", json!({})).await;
    assert_eq!(own, json!({"crons": [cron_json("task-a")], "scoped": true}));
    let other = run.call("cron.list", json!({"task_id": "task-b"})).await;
    assert_error(&other, "forbidden", None);
}

#[tokio::test]
async fn cron_create_validates_and_builds_the_cli_row() {
    let fx = Fixture::new();
    let mut op = fx.operator();
    let params = |extra: Value| {
        let mut p = json!({"type": "interval", "value": "60000", "prompt": "do it"});
        p.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        p
    };
    let no_task = op.call("cron.create", params(json!({}))).await;
    assert_error(&no_task, "invalid_params", Some("task_id is required"));
    let bad_continuity = op
        .call(
            "cron.create",
            params(json!({"task_id": "task-a", "continuity": "forever"})),
        )
        .await;
    assert_error(
        &bad_continuity,
        "invalid_params",
        Some("continuity must be 'isolated' or 'shared' (got 'forever')"),
    );
    let bad_schedule = op
        .call(
            "cron.create",
            json!({"type": "interval", "value": "soon", "prompt": "p", "task_id": "task-a"}),
        )
        .await;
    assert_error(&bad_schedule, "invalid_params", None);
    assert!(
        bad_schedule["error"]["message"]
            .as_str()
            .unwrap()
            .starts_with("invalid schedule: type=interval value=soon: ")
    );
    let unknown_task = op
        .call("cron.create", params(json!({"task_id": "nope"})))
        .await;
    assert_error(&unknown_task, "not_found", Some("no such task: nope"));
    let missing_field = op
        .call(
            "cron.create",
            json!({"type": "interval", "task_id": "task-a"}),
        )
        .await;
    assert_error(&missing_field, "invalid_params", None);

    let mut run = fx.run("task-a").await;
    let other = run
        .call("cron.create", params(json!({"task_id": "task-b"})))
        .await;
    assert_error(&other, "forbidden", None);

    let before = crate::scheduler::now();
    let created = conn_result(&mut run, "cron.create", params(json!({}))).await;
    let cron = &created["cron"];
    let id = cron["id"].as_str().unwrap().to_owned();
    assert!(id.starts_with("cron-"));
    assert!(uuid::Uuid::parse_str(&id["cron-".len()..]).is_ok());
    let row = fx.db.lock().unwrap().get_cron(&id).unwrap().unwrap();
    assert_eq!(row.task_id, "task-a");
    assert_eq!(row.kind, "schedule");
    assert_eq!(row.status, "active");
    assert_eq!(row.continuity, "isolated");
    assert_eq!(row.run_count, 0);
    assert_eq!(row.prompt, "do it");
    assert_eq!(row.schedule_type.as_deref(), Some("interval"));
    assert_eq!(row.schedule_value.as_deref(), Some("60000"));
    assert_eq!(row.last_fired_at, None);
    assert_eq!(row.created_at, row.updated_at);
    let next = crate::scheduler::parse_iso(row.next_run.as_deref().unwrap()).unwrap();
    assert!(next > before);
    assert_eq!(cron["next_run"], json!(row.next_run));
    assert_eq!(cron["created_at"], json!(row.created_at));
    assert_eq!(fx.cron_states(&id), 1);

    let shared = conn_result(
        &mut op,
        "cron.create",
        params(json!({"task_id": "task-b", "continuity": "shared"})),
    )
    .await;
    assert_eq!(shared["cron"]["task_id"], "task-b");
    assert_eq!(shared["cron"]["continuity"], "shared");
}

#[tokio::test]
async fn cron_mutations_update_status_and_enqueue_state() {
    let fx = Fixture::new();
    let mut run = fx.run("task-a").await;
    let cron_b = || fx.db.lock().unwrap().get_cron("task-b-cron").unwrap();
    let before = cron_b();
    for method in ["cron.delete", "cron.pause", "cron.resume"] {
        let other = run.call(method, json!({"id": "task-b-cron"})).await;
        let missing = run.call(method, json!({"id": "nope"})).await;
        assert_error(&missing, "not_found", Some("no such cron: nope"));
        assert_hidden(&other, &missing, "nope", "task-b-cron");
    }
    assert_eq!(cron_b(), before, "another task's cron untouched");
    assert_eq!(fx.cron_states("task-b-cron"), 0);
    let quiet = std::time::Duration::from_millis(50);
    assert!(
        tokio::time::timeout(quiet, fx.nudge.notified())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(quiet, fx.flush.notified())
            .await
            .is_err()
    );

    let mut op = fx.operator();
    let paused_b = conn_result(&mut op, "cron.pause", json!({"id": "task-b-cron"})).await;
    assert_eq!(paused_b["cron"]["status"], "paused");
    assert_eq!(fx.cron_states("task-b-cron"), 1);

    let paused = conn_result(&mut run, "cron.pause", json!({"id": "task-a-cron"})).await;
    assert_eq!(paused["cron"]["status"], "paused");
    assert_eq!(paused["cron"]["next_run"], TS);
    assert_ne!(paused["cron"]["updated_at"], TS);
    assert_eq!(fx.cron_states("task-a-cron"), 1);

    let before = crate::scheduler::now();
    let resumed = conn_result(&mut run, "cron.resume", json!({"id": "task-a-cron"})).await;
    assert_eq!(resumed["cron"]["status"], "active");
    let next = crate::scheduler::parse_iso(resumed["cron"]["next_run"].as_str().unwrap()).unwrap();
    assert!(next > before, "next_run recomputed forward from now");
    assert_eq!(fx.cron_states("task-a-cron"), 2);

    let deleted = conn_result(&mut op, "cron.delete", json!({"id": "task-a-cron"})).await;
    assert_eq!(deleted["cron"]["status"], "cancelled");
    assert_eq!(deleted["cron"]["next_run"], Value::Null);
    assert_eq!(fx.cron_states("task-a-cron"), 3);
    let row = fx
        .db
        .lock()
        .unwrap()
        .get_cron("task-a-cron")
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "cancelled");
    assert_eq!(row.next_run, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_created_cron_is_visible_to_the_scheduler() {
    let (_dir, ctx) = context();
    let workspace = ctx.workspace_dir.clone();
    let nudge = Arc::clone(&ctx.nudge);
    let flush = Arc::clone(&ctx.flush);
    let db = Arc::clone(&ctx.db);
    let server = AgentApiServer::start(ctx, &workspace).unwrap();
    let path = socket_path(&workspace);
    let created = blocking(move || {
        let mut client = Client::connect(&path).unwrap();
        client
            .call(
                "cron.create",
                json!({"type": "interval", "value": "1000", "prompt": "p", "task_id": "task-b"}),
            )
            .unwrap()
    })
    .await;
    let wait = std::time::Duration::from_secs(1);
    tokio::time::timeout(wait, nudge.notified())
        .await
        .expect("scheduler nudged");
    tokio::time::timeout(wait, flush.notified())
        .await
        .expect("outbox flush nudged");
    let id = created["cron"]["id"].as_str().unwrap();
    let active = db.lock().unwrap().list_active_crons().unwrap();
    assert!(active.iter().any(|c| c.id == id));
    server.shutdown().await;
}

/// The `result` of a call that must succeed.
async fn conn_result(conn: &mut Conn, method: &str, params: Value) -> Value {
    let response = conn.call(method, params).await;
    assert!(response.get("error").is_none(), "{method}: {response}");
    response["result"].clone()
}

impl Fixture {
    /// `thread_message` outbox payloads correlated to `thread_id`.
    fn thread_messages(&self, thread_id: &str) -> Vec<Value> {
        self.db
            .lock()
            .unwrap()
            .list_unacked_outbox()
            .unwrap()
            .iter()
            .filter(|r| r.msg_type == "thread_message" && r.thread_id.as_deref() == Some(thread_id))
            .map(|r| serde_json::from_str(&r.payload).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn thread_action_appends_one_host_action_to_the_callers_thread() {
    let fx = Fixture::new();
    fx.db
        .lock()
        .unwrap()
        .set_thread_last_seq("task-a-thread", 4)
        .unwrap();
    let mut run = fx.run("task-a").await;

    let params = json!({"method": "comment", "params": {"body": "hi"}});
    let result = conn_result(&mut run, "thread.action", params).await;
    assert_eq!(result, json!({"seq": 5}));
    tokio::time::timeout(std::time::Duration::from_secs(1), fx.flush.notified())
        .await
        .expect("outbox flush nudged");

    let rows: Vec<_> = fx
        .db
        .lock()
        .unwrap()
        .list_unacked_outbox()
        .unwrap()
        .into_iter()
        .filter(|r| r.msg_type == "thread_message")
        .collect();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].task_id.as_deref(), Some("task-a"));
    assert_eq!(rows[0].thread_id.as_deref(), Some("task-a-thread"));
    let data: Value = serde_json::from_str(&rows[0].payload).unwrap();
    assert_eq!(
        data,
        json!({"seq": 5, "kind": "host_action", "input": {"method": "comment", "params": {"body": "hi"}}})
    );
    let last_seq = fx
        .db
        .lock()
        .unwrap()
        .get_thread_last_seq("task-a-thread")
        .unwrap();
    assert_eq!(last_seq, 5);

    let bare = conn_result(&mut run, "thread.action", json!({"method": "noop"})).await;
    assert_eq!(bare, json!({"seq": 6}));
    let messages = fx.thread_messages("task-a-thread");
    assert_eq!(messages.len(), 2);
    assert_eq!(
        messages[1]["input"],
        json!({"method": "noop", "params": {}})
    );
    assert!(fx.thread_messages("task-b-thread").is_empty());
}

#[tokio::test]
async fn thread_action_rejects_the_operator_and_bad_params() {
    let fx = Fixture::new();
    let mut op = fx.operator();
    let forbidden = op.call("thread.action", json!({"method": "comment"})).await;
    assert_error(&forbidden, "forbidden", None);

    let mut run = fx.run("task-a").await;
    for params in [
        json!({"method": "comment", "threadId": "task-b-thread"}),
        json!({"method": "comment", "thread_id": "task-b-thread"}),
        json!({"method": "comment", "params": [1]}),
        json!({"method": "comment", "params": "x"}),
        json!({"method": ""}),
        json!({}),
        json!({"params": {}}),
    ] {
        let response = run.call("thread.action", params.clone()).await;
        assert_error(&response, "invalid_params", None);
    }
    assert!(fx.thread_messages("task-a-thread").is_empty());
    assert!(fx.thread_messages("task-b-thread").is_empty());
}

/// On an encrypted task only a method its e2ee profile declares may be sent;
/// `gino.task-content.v1` declares none, so the engine gets an error, nothing
/// is appended or enqueued and no `seq` is consumed, whatever the group state.
/// The other task stays unencrypted and unchanged.
#[tokio::test]
async fn thread_action_on_an_encrypted_task_refuses_an_undeclared_method() {
    let fx = Fixture::new();
    fx.db
        .lock()
        .unwrap()
        .set_task_e2ee("task-a", "gino.task-content.v1", "group")
        .unwrap();
    let mut run = fx.run("task-a").await;
    for method in ["comment", "METHOD-MARKER-71c2"] {
        let params = json!({"method": method, "params": {"body": "PARAMS-MARKER-0d9e"}});
        let response = run.call("thread.action", params).await;
        assert_error(&response, "forbidden", None);
        let text = response.to_string();
        assert!(!text.contains("MARKER"), "{text}");
        assert!(text.contains("not declared"), "{text}");
    }
    assert!(fx.thread_messages("task-a-thread").is_empty());
    {
        let db = fx.db.lock().unwrap();
        assert!(
            db.list_unacked_outbox().unwrap().is_empty(),
            "nothing enqueued"
        );
        assert_eq!(
            db.get_thread_last_seq("task-a-thread").unwrap(),
            0,
            "no seq consumed"
        );
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), fx.flush.notified())
            .await
            .is_err(),
        "no outbox flush nudged"
    );

    let mut plain = fx.run("task-b").await;
    let result = conn_result(&mut plain, "thread.action", json!({"method": "comment"})).await;
    assert_eq!(result, json!({"seq": 1}));
    assert_eq!(fx.thread_messages("task-b-thread").len(), 1);
}

/// `thread.show` opens an encrypted task's sealed texts for display; one
/// that does not open shows its error code, never the stored form.
#[tokio::test]
async fn thread_show_of_an_encrypted_task_shows_the_code_when_it_does_not_open() {
    let fx = Fixture::new();
    {
        let db = fx.db.lock().unwrap();
        db.set_task_e2ee("task-a", "gino.task-content.v1", "group")
            .unwrap();
        let mut thread = db.get_thread("task-a-thread").unwrap().unwrap();
        thread.result = Some(r#"{"e2ee":"AAAA"}"#.to_owned());
        db.update_thread(&thread).unwrap();
    }
    let mut op = fx.operator();
    let show = conn_result(&mut op, "thread.show", json!({"id": "task-a-thread"})).await;
    assert_eq!(show["thread"]["result"], "[sealed: not_member]");
    assert_eq!(show["thread"]["prompt"], "[sealed: not_member]");
    assert_eq!(show["thread"]["error"], Value::Null);
    let crons = conn_result(&mut op, "cron.list", json!({"task_id": "task-a"})).await;
    assert_eq!(crons["crons"][0]["prompt"], "[sealed: not_member]");
}

/// A raw connection to a real socket.
async fn socket_conn(path: &Path) -> Conn {
    let (read, writer) = UnixStream::connect(path).await.unwrap().into_split();
    Conn {
        reader: BufReader::new(read),
        writer,
        next_id: 0,
    }
}

#[tokio::test]
async fn a_run_peer_socket_never_grants_operator_and_takes_only_its_token() {
    let fx = Fixture::new();
    let token = fx.registry.register(run_scope("task-a"));
    let other = fx.registry.register(run_scope("task-b"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = serve_run_peers_with(&fx.shared, listener, token.as_str());

    // This test process is a same-uid, same-namespace peer: the operator.
    let mut conn = socket_conn(&path).await;
    let response = conn.call("system.info", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");
    let response = conn.call("task.list", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");
    let response = conn.call("auth", json!({"token": other.as_str()})).await;
    assert_eq!(error_code(&response), "unauthenticated");
    let response = conn.call("task.list", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");

    let auth = conn.call("auth", json!({"token": token.as_str()})).await;
    assert_eq!(auth["result"]["task_id"], "task-a");
    let list = conn_result(&mut conn, "task.list", json!({})).await;
    assert_eq!(list, json!({"tasks": [task_json("task-a")]}));
    let hidden = conn.call("task.show", json!({"id": "task-b"})).await;
    assert_error(&hidden, "not_found", Some("no such task: task-b"));
    let info = conn_result(&mut conn, "system.info", json!({})).await;
    assert_eq!(info["scope"], "run");

    fx.registry.revoke(token.as_str());
    let response = conn.call("task.list", json!({})).await;
    assert_eq!(error_code(&response), "unauthenticated");

    // Dropping the server closes its connections.
    drop(server);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while conn.recv().await.is_some() {}
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn run_peers_need_the_running_server() {
    let dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(dir.path().join("a.sock")).unwrap();
    let err = serve_run_peers(listener, "tok").unwrap_err();
    assert!(err.to_string().contains("not running"), "{err}");

    let (_ws, ctx) = context();
    let workspace = ctx.workspace_dir.clone();
    let server = AgentApiServer::start(ctx, &workspace).unwrap();
    let token = server.registry().register(run_scope("task-b"));
    let path = dir.path().join("b.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let _peers = serve_run_peers(listener, token.as_str()).unwrap();
    let mut conn = socket_conn(&path).await;
    let auth = conn.call("auth", json!({"token": token.as_str()})).await;
    assert_eq!(auth["result"]["task_id"], "task-b");
    server.shutdown().await;
}
