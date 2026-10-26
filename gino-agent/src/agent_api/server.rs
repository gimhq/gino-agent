//! The socket listener and per-connection NDJSON loop.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, warn};

use super::methods::{self, ApiContext};
use super::protocol::{
    ApiError, AuthResult, ErrorCode, MAX_LINE_BYTES, PROTOCOL_VERSION, error_line, success_line,
};
use super::scope::{self, ConnectionGuard, ConnectionLimits, TokenHash, TokenRegistry, token_hash};
use super::socket_path;

/// Concurrent connections across all scopes.
const MAX_CONNECTIONS: usize = 64;
/// A connection with no complete request line for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_mins(1);
/// Per-request handler budget.
const HANDLER_TIMEOUT: Duration = Duration::from_secs(10);

/// The running server's state, reached by per-run listeners.
static RUNNING: Mutex<Weak<Shared>> = Mutex::new(Weak::new());

/// State shared by every connection.
#[derive(Debug)]
pub(super) struct Shared {
    ctx: Arc<ApiContext>,
    registry: TokenRegistry,
    limits: ConnectionLimits,
}

impl Shared {
    pub(super) fn new(ctx: ApiContext, registry: TokenRegistry) -> Self {
        Self {
            ctx: Arc::new(ctx),
            registry,
            limits: ConnectionLimits::default(),
        }
    }
}

/// The running API server.
#[derive(Debug)]
pub(crate) struct AgentApiServer {
    socket: PathBuf,
    registry: TokenRegistry,
    stop: oneshot::Sender<()>,
    accept: JoinHandle<()>,
}

impl AgentApiServer {
    /// Prepare `<workspace_dir>/run`, bind the socket and spawn the accept loop on
    /// the current tokio runtime.
    pub(crate) fn start(ctx: ApiContext, workspace_dir: &Path) -> Result<Self> {
        let socket = socket_path(workspace_dir);
        let run_dir = workspace_dir.join("run");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&run_dir)
            .with_context(|| format!("creating {}", run_dir.display()))?;
        fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", run_dir.display()))?;
        match fs::remove_file(&socket) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("removing stale socket {}", socket.display()));
            }
        }
        let listener =
            UnixListener::bind(&socket).with_context(|| format!("binding {}", socket.display()))?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", socket.display()))?;

        let registry = TokenRegistry::default();
        let shared = Arc::new(Shared::new(ctx, registry.clone()));
        *RUNNING.lock().unwrap_or_else(PoisonError::into_inner) = Arc::downgrade(&shared);
        let (stop, stopped) = oneshot::channel();
        let accept = tokio::spawn(accept_loop(listener, shared, stopped));
        Ok(Self {
            socket,
            registry,
            stop,
            accept,
        })
    }

    /// The registry run tokens are minted in.
    pub(crate) fn registry(&self) -> TokenRegistry {
        self.registry.clone()
    }

    /// Stop accepting, close every connection and remove the socket file.
    pub(crate) async fn shutdown(self) {
        let _ = self.stop.send(());
        if self.accept.await.is_err_and(|err| err.is_panic()) {
            warn!("agent API accept loop panicked");
        }
        if let Err(err) = fs::remove_file(&self.socket)
            && err.kind() != ErrorKind::NotFound
        {
            warn!(error = %err, socket = %self.socket.display(), "removing the agent API socket failed");
        }
    }
}

async fn accept_loop(
    listener: UnixListener,
    shared: Arc<Shared>,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    if connections.len() >= MAX_CONNECTIONS {
                        debug!("agent API connection limit reached; closing");
                        continue;
                    }
                    let shared = Arc::clone(&shared);
                    connections.spawn(async move {
                        let operator = stream
                            .peer_cred()
                            .is_ok_and(|cred| scope::peer_is_operator(&cred));
                        serve(stream, &shared, operator, None).await;
                    });
                }
                Err(err) => {
                    warn!(error = %err, "agent API accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
    connections.shutdown().await;
}

/// A per-run listener whose connections are run peers; stops accepting and
/// closes its connections on drop.
#[derive(Debug)]
pub(crate) struct RunPeerServer {
    accept: JoinHandle<()>,
}

impl Drop for RunPeerServer {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// Serve `listener` for one run on the running server: every connection is a
/// run peer that never gets operator access, whatever its peer credentials,
/// and can only authenticate with `token`.
pub(crate) fn serve_run_peers(listener: UnixListener, token: &str) -> Result<RunPeerServer> {
    let shared = RUNNING
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .upgrade()
        .context("the local agent API is not running")?;
    Ok(serve_run_peers_with(&shared, listener, token))
}

pub(super) fn serve_run_peers_with(
    shared: &Arc<Shared>,
    listener: UnixListener,
    token: &str,
) -> RunPeerServer {
    let shared = Arc::downgrade(shared);
    let bound = token_hash(token);
    let accept = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let Some(shared) = shared.upgrade() else { break };
                        if connections.len() >= MAX_CONNECTIONS {
                            debug!("run peer connection limit reached; closing");
                            continue;
                        }
                        connections.spawn(async move {
                            serve(stream, &shared, false, Some(bound)).await;
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, "run peer accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
    });
    RunPeerServer { accept }
}

/// [`serve`] without a token binding.
#[cfg(test)]
pub(super) async fn serve_connection(stream: UnixStream, shared: &Shared, operator: bool) {
    serve(stream, shared, operator, None).await;
}

/// Serve one connection until EOF, idle timeout, an oversized line or an I/O
/// error. `operator` is the peer-credential decision made at accept time; with
/// `bound`, only the token hashing to it authenticates.
async fn serve(stream: UnixStream, shared: &Shared, operator: bool, bound: Option<TokenHash>) {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    let mut conn = None;
    if operator {
        conn = shared.limits.acquire_operator();
        if conn.is_none() {
            debug!("operator connection limit reached; closing");
            return;
        }
    }
    let mut line = Vec::new();
    loop {
        line.clear();
        let Ok(Ok(read)) =
            tokio::time::timeout(IDLE_TIMEOUT, read_line(&mut reader, &mut line)).await
        else {
            return;
        };
        let (response, close) = match read {
            LineRead::Eof => return,
            LineRead::TooLong => (
                error_line(
                    None,
                    ApiError::invalid_params(format!(
                        "request line exceeds {MAX_LINE_BYTES} bytes"
                    )),
                ),
                true,
            ),
            LineRead::Line => (handle_line(shared, &mut conn, bound, &line).await, false),
        };
        let mut out = response.into_bytes();
        out.push(b'\n');
        if write.write_all(&out).await.is_err() || write.flush().await.is_err() || close {
            return;
        }
    }
}

enum LineRead {
    Line,
    TooLong,
    Eof,
}

/// Read one newline-terminated line into `line` (without the newline), never
/// buffering more than [`MAX_LINE_BYTES`]. A partial line at EOF is dropped.
async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    line: &mut Vec<u8>,
) -> std::io::Result<LineRead> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(LineRead::Eof);
        }
        let (chunk, done) = match available.iter().position(|&b| b == b'\n') {
            Some(at) => (&available[..at], true),
            None => (available, false),
        };
        if line.len() + chunk.len() > MAX_LINE_BYTES {
            return Ok(LineRead::TooLong);
        }
        line.extend_from_slice(chunk);
        let used = chunk.len() + usize::from(done);
        reader.consume(used);
        if done {
            return Ok(LineRead::Line);
        }
    }
}

/// A request that passed envelope validation.
struct Parsed {
    id: String,
    method: String,
    params: Value,
}

/// Validate the envelope; on failure return the id (if readable) and the error.
fn parse_request(line: &[u8]) -> Result<Parsed, (Option<String>, ApiError)> {
    let Ok(Value::Object(mut request)) = serde_json::from_slice::<Value>(line) else {
        return Err((None, ApiError::invalid_params("malformed JSON request")));
    };
    let id = match request.remove("id") {
        Some(Value::String(id)) => Some(id),
        _ => None,
    };
    if request.get("v").and_then(Value::as_u64) != Some(PROTOCOL_VERSION) {
        return Err((id, ApiError::unsupported_version()));
    }
    let Some(id) = id else {
        return Err((None, ApiError::invalid_params("id must be a string")));
    };
    let Some(Value::String(method)) = request.remove("method") else {
        return Err((
            Some(id),
            ApiError::invalid_params("method must be a string"),
        ));
    };
    let params = match request.remove("params") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(params @ Value::Object(_)) => params,
        Some(_) => {
            return Err((
                Some(id),
                ApiError::invalid_params("params must be an object"),
            ));
        }
    };
    Ok(Parsed { id, method, params })
}

async fn handle_line(
    shared: &Shared,
    conn: &mut Option<ConnectionGuard>,
    bound: Option<TokenHash>,
    line: &[u8],
) -> String {
    match parse_request(line) {
        Ok(request) => match respond(shared, conn, bound, request.method, request.params).await {
            Ok(result) => success_line(&request.id, result),
            Err(err) => error_line(Some(&request.id), err),
        },
        Err((id, err)) => error_line(id.as_deref(), err),
    }
}

async fn respond(
    shared: &Shared,
    conn: &mut Option<ConnectionGuard>,
    bound: Option<TokenHash>,
    method: String,
    params: Value,
) -> Result<Value, ApiError> {
    if method == "auth" {
        return auth(shared, conn, bound, &params);
    }
    // Re-checked on every request so a revoked token stops working at once.
    let Some(scope) = conn.as_ref().and_then(|g| g.scope(&shared.registry)) else {
        *conn = None;
        return Err(ApiError::unauthenticated());
    };
    let ctx = Arc::clone(&shared.ctx);
    let handler =
        tokio::task::spawn_blocking(move || methods::dispatch(&ctx, &scope, &method, &params));
    match tokio::time::timeout(HANDLER_TIMEOUT, handler).await {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => Err(ApiError::internal(&err)),
        Err(_) => Err(ApiError::unavailable("request timed out")),
    }
}

/// Replace the connection's scope with the one `token` grants. Any failure
/// leaves the connection with no scope at all.
fn auth(
    shared: &Shared,
    conn: &mut Option<ConnectionGuard>,
    bound: Option<TokenHash>,
    params: &Value,
) -> Result<Value, ApiError> {
    *conn = None;
    let Some(token) = params.get("token").and_then(Value::as_str) else {
        return Err(ApiError::invalid_params("token must be a string"));
    };
    let lookup = match bound {
        Some(hash) if hash != token_hash(token) => None,
        _ => shared.registry.lookup(token),
    };
    let Some(run) = lookup else {
        return Err(ApiError::new(
            ErrorCode::Unauthenticated,
            "invalid or revoked token",
        ));
    };
    let Some(guard) = shared.limits.acquire_token(token) else {
        return Err(ApiError::unavailable("too many connections for this token"));
    };
    *conn = Some(guard);
    serde_json::to_value(AuthResult {
        scope: "run".to_owned(),
        task_id: run.task_id,
        thread_id: run.thread_id,
    })
    .map_err(|err| ApiError::internal(&err))
}
