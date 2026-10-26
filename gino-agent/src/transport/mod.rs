//! Outbound transport.
//!
//! The runner dials *out* — to be NAT/firewall friendly the orchestrator never
//! connects to us. This module owns that outbound side:
//!
//! * [`http`] — the `reqwest` client for `POST /agent/register`,
//!   `GET /agent/config/:id`, and the `POST /agent/output/:id` fallback.
//! * [`ws`] — the reconnecting `tokio-tungstenite` client with outbox-backed
//!   at-least-once delivery, inbox dedup/replay, capped-backoff reconnect (the
//!   delay is bounded, the attempts are not), a periodic heartbeat, and
//!   read-liveness detection of half-open sockets.
//!
//! [`Transport`] is the engine-agnostic facade over the WS side: it works purely
//! on [`crate::protocol::frames`] frames and the [`crate::db`] outbox/inbox, so the
//! engine and scheduler (later L3s) never touch tungstenite. Producers persist
//! outbound frames straight to the durable outbox and poke
//! [`Transport::flush_handle`]; the manager task drains the outbox, dedups the
//! inbox, and forwards inbound frames on an unbounded channel drained via
//! [`Transport::recv`].
//!
//! ## Envelope vs payload (agent-architecture §8/§10)
//!
//! Correlation/delivery metadata lives at the **envelope top level**
//! (`type`, `outboxId`/`msgId`, `taskId`/`threadId`/`cronId`); `data` carries the
//! type-specific business payload only. The two delivery buffers are asymmetric:
//!
//! * **outbox payload = the frame's `data` only.** The correlation ids are written
//!   to the indexed `task_id`/`thread_id` columns; the full `{type, …ids, data,
//!   outboxId}` envelope is *rebuilt on replay* from those columns
//!   ([`build_envelope`]). The host routes purely off the envelope ids.
//! * **inbox payload = the full received frame**, re-delivered verbatim on replay;
//!   the `type` column is the replay *classification* and the correlation columns
//!   are routing indexes.
//!
//! `outboxId`/`msgId` are delivery/ack only; `seq` (inside `data`) is the
//! per-thread continuity contract — the transport ships frames in order but never
//! reorders, and `engine_session_id` is a *value* that stays inside `data`.

mod ds;
pub(crate) mod http;
mod ws;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use secrecy::SecretString;
use serde_json::{Map, Value};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::db::Db;
use crate::protocol::frames::{E2eeCapability, E2eeLiveFrame, InboundFrame};
use crate::remote_ops::RemoteOps;

pub(crate) use self::ds::DsLink;
pub(crate) use self::ws::MAX_INBOX_RETRIES;
use self::ws::WsDriver;

/// Default liveness ping cadence. The TS runner sent no heartbeat; the Rust
/// runner adds one so a silently dead half-open socket is noticed promptly.
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(30);
/// Default read-liveness window: three heartbeat periods with nothing
/// received (each heartbeat also sends a WS ping, so a live peer's pongs keep
/// arriving even when the host has no frames to send).
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(90);
/// Default ack-progress window: transmitted outbox rows that see no ack
/// progress for a full window are retransmitted over the live socket.
const DEFAULT_ACK_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Public configuration / values
// ---------------------------------------------------------------------------

/// Reconnect backoff schedule: exponential from `base`, capped at `max`. The
/// TS runner gave up after 60 consecutive failures; this runner never does
/// (spec §1: the daemon must outlive any host outage) — only the delay
/// is bounded, never the attempts.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BackoffConfig {
    base: Duration,
    max: Duration,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        // TS parity for the delay shape: 1 s base, 10 s ceiling.
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(10),
        }
    }
}

#[cfg(test)]
impl BackoffConfig {
    /// Fast schedule for reconnect/enrollment tests (no second-scale sleeps).
    pub(super) fn for_tests() -> Self {
        Self {
            base: Duration::from_millis(10),
            max: Duration::from_millis(40),
        }
    }
}

/// Knobs for [`Transport::open`]. [`Default`] matches production; tests override
/// the cadence to keep wall-clock low.
#[derive(Clone, Debug)]
pub(crate) struct TransportConfig {
    pub(crate) heartbeat: Duration,
    /// Capabilities every heartbeat carries (`data.capabilities`).
    pub(crate) capabilities: Vec<String>,
    /// Engines the heartbeats carry (`data.engines`) once the probe sets them.
    pub(crate) engines: Arc<std::sync::OnceLock<Vec<crate::engine::admin::EngineInfo>>>,
    /// The e2ee capability every heartbeat carries (`data.e2ee`).
    pub(crate) e2ee: Option<E2eeCapability>,
    /// Receives the live-only e2ee frames (`e2ee_key_package_status`,
    /// `e2ee_response`), which bypass the inbox; without it they are dropped.
    pub(crate) e2ee_live: Option<mpsc::UnboundedSender<E2eeLiveFrame>>,
    /// The e2ee DS request channel: follows the live socket and receives the
    /// `e2ee_response` frames; without it they go to `e2ee_live`.
    pub(crate) e2ee_ds: Option<Arc<DsLink>>,
    /// Read-liveness window: when nothing at all (data or pong) arrives
    /// within it, the connection is treated as dead and redialed. The effective
    /// window never drops below two heartbeat periods, so a slow-heartbeat
    /// configuration cannot starve itself of the pongs it solicits.
    pub(crate) read_timeout: Duration,
    /// Ack-progress window: already-transmitted outbox rows whose acks
    /// make no progress for a full window are retransmitted on the live socket
    /// (flushes alone never resend them — see [`Transport::flush_handle`]).
    pub(crate) ack_timeout: Duration,
    pub(crate) backoff: BackoffConfig,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            heartbeat: DEFAULT_HEARTBEAT,
            capabilities: Vec::new(),
            engines: Arc::default(),
            e2ee: None,
            e2ee_live: None,
            e2ee_ds: None,
            read_timeout: DEFAULT_READ_TIMEOUT,
            ack_timeout: DEFAULT_ACK_TIMEOUT,
            backoff: BackoffConfig::default(),
        }
    }
}

/// An inbound frame handed to the consumer, paired with the inbox row id that
/// holds it. The consumer marks the row processed
/// ([`crate::db::Db::mark_inbox_processed`]) once it has durably handled the
/// frame — until then the row replays on reconnect. A failed apply instead bumps
/// the row's failure counter ([`crate::db::Db::increment_inbox_retry`]); the
/// replay poison policy discards the row after [`MAX_INBOX_RETRIES`] failures.
#[derive(Debug)]
pub(crate) struct Inbound {
    pub(crate) inbox_id: i64,
    pub(crate) frame: InboundFrame,
}

// ---------------------------------------------------------------------------
// Transport facade
// ---------------------------------------------------------------------------

/// Engine-agnostic handle over the reconnecting WS connection. Cheap to hold;
/// the actual IO runs in a spawned manager task.
#[derive(Debug)]
pub(crate) struct Transport {
    inbound_rx: mpsc::UnboundedReceiver<Inbound>,
    cancel: Arc<Cancel>,
    /// Poked to make the manager replay the unacked outbox over the live socket
    /// (the executor/scheduler enqueue frames straight to the outbox, so this is
    /// how a live send is triggered between reconnects).
    flush: Arc<Notify>,
    manager: JoinHandle<()>,
}

impl Transport {
    /// Spawn the manager task that dials `ws_url` (with `connect_token` in the
    /// `x-internal-token` header) **in the background**, drains the outbox, dedups
    /// the inbox, reconnects with capped backoff, and heartbeats. Returns
    /// immediately — the daemon boots and serves local work while the host is
    /// unreachable; outbound frames queue durably in the outbox and replay
    /// once a connection is up.
    pub(crate) fn open(
        ws_url: String,
        connect_token: SecretString,
        db: Arc<Mutex<Db>>,
        config: TransportConfig,
        remote_ops: Arc<RemoteOps>,
    ) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let cancel = Arc::new(Cancel::new());
        let flush = Arc::new(Notify::new());
        let driver = WsDriver {
            ws_url,
            connect_token,
            db,
            inbound_tx,
            cancel: Arc::clone(&cancel),
            flush: Arc::clone(&flush),
            heartbeat: config.heartbeat,
            heartbeat_frame: ws::HeartbeatFrame {
                capabilities: config.capabilities,
                engines: config.engines,
                e2ee: config.e2ee,
            },
            e2ee_live: config.e2ee_live,
            e2ee_ds: config.e2ee_ds,
            read_timeout: config.read_timeout,
            ack_timeout: config.ack_timeout,
            backoff: Backoff::new(config.backoff),
            remote_ops,
        };
        let manager = tokio::spawn(run_manager(driver));
        Self {
            inbound_rx,
            cancel,
            flush,
            manager,
        }
    }

    /// A handle that, when notified, makes the manager transmit the unacked outbox
    /// rows **not yet sent on the current connection**. The executor/scheduler
    /// enqueue result-plane frames straight to the durable outbox and poke this so
    /// those frames stream out promptly instead of waiting for the next reconnect.
    /// A flush never resends already-transmitted rows (flushing under ack
    /// lag used to be O(n²)); full retransmission happens only on reconnect or
    /// when ack progress stalls for a whole ack window — the host dedups on
    /// `(thread_id, seq)` either way.
    pub(crate) fn flush_handle(&self) -> Arc<Notify> {
        Arc::clone(&self.flush)
    }

    /// Await the next inbound frame. Returns `None` once the manager task has
    /// stopped — which reconnect never causes; only shutdown (or an
    /// unexpected task death) closes the channel.
    pub(crate) async fn recv(&mut self) -> Option<Inbound> {
        self.inbound_rx.recv().await
    }

    /// Signal shutdown and wait for the manager task to drain and exit.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();
        if self.manager.await.is_err_and(|err| err.is_panic()) {
            warn!("transport manager task panicked during shutdown");
        }
    }
}

/// The manager task body: dial the *first* connection here — in the background,
/// retrying forever with capped backoff — then hand it to the driver's
/// serve/reconnect loop. Only a shutdown cancel ends the task; an unreachable
/// host never does, so the daemon boots and runs regardless.
async fn run_manager(mut driver: WsDriver) {
    let initial = loop {
        let dialed = tokio::select! {
            () = driver.cancel.cancelled() => return,
            dialed = ws::dial(&driver.ws_url, &driver.connect_token, ws::DIAL_TIMEOUT) => dialed,
        };
        match dialed {
            Ok(stream) => break stream,
            Err(err) => warn!(error = %err, "dial failed; retrying with capped backoff"),
        }
        // Always `Some`: the delay is capped but the attempts are unbounded.
        let Some(delay) = driver.backoff.next_delay() else {
            return;
        };
        tokio::select! {
            () = driver.cancel.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
    };
    driver.backoff.reset();
    driver.run(initial).await;
}

// ---------------------------------------------------------------------------
// Outbox mapping
// ---------------------------------------------------------------------------

/// Rebuild the wire envelope from the outbox correlation columns + `data`.
/// Correlation ids sit at the **envelope top level** (never inside `data`); the
/// host routes/correlates off them without parsing `data`. `secondary_id` is the
/// `thread_id` column, keyed as `cronId` for a `cron_state` frame and `threadId`
/// otherwise (see [`secondary_id_key`]). Used by the `ws` outbox replay, which
/// is the only transmit path — producers write the outbox and poke flush.
pub(super) fn build_envelope(
    msg_type: &str,
    data: &Value,
    task_id: Option<&str>,
    secondary_id: Option<&str>,
    outbox_id: &str,
) -> Value {
    let mut envelope = Map::new();
    envelope.insert("type".to_owned(), Value::from(msg_type));
    if let Some(task_id) = task_id {
        envelope.insert("taskId".to_owned(), Value::from(task_id));
    }
    if let Some(secondary) = secondary_id {
        envelope.insert(
            secondary_id_key(msg_type).to_owned(),
            Value::from(secondary),
        );
    }
    envelope.insert("data".to_owned(), data.clone());
    envelope.insert("outboxId".to_owned(), Value::from(outbox_id));
    Value::Object(envelope)
}

/// The envelope key for the outbox's secondary correlation column: `cronId` for a
/// `cron_state` frame, `threadId` for the thread frames.
fn secondary_id_key(msg_type: &str) -> &'static str {
    if msg_type == "cron_state" {
        "cronId"
    } else {
        "threadId"
    }
}

// ---------------------------------------------------------------------------
// Shared helpers (used by the ws child module)
// ---------------------------------------------------------------------------

/// Lock the shared DB, recovering the guard from a poisoned mutex rather than
/// panicking (Lock 6: no panics in runtime paths). Critical sections are short
/// and synchronous — the guard is never held across an `.await`.
pub(super) fn lock_db(db: &Mutex<Db>) -> MutexGuard<'_, Db> {
    db.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A one-shot, broadcast-style cancellation flag. Cheaper than pulling in
/// `tokio-util` for a single token, and race-free via the
/// "set flag → notify_waiters, check flag → enable → recheck" pattern.
#[derive(Debug)]
pub(super) struct Cancel {
    cancelled: AtomicBool,
    notify: Notify,
}

impl Cancel {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    /// Trip the flag and wake every current waiter. Idempotent.
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Resolve once [`Self::cancel`] has been called (immediately if already).
    pub(super) async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let mut notified = std::pin::pin!(self.notify.notified());
        // `enable` registers interest *before* the recheck, closing the race
        // where `cancel` runs between the check and the await.
        notified.as_mut().enable();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

// ---------------------------------------------------------------------------
// Reconnect backoff
// ---------------------------------------------------------------------------

/// Stateful reconnect backoff. [`Self::next_delay`] yields the delay before the
/// next attempt — always `Some`, since the retry ceiling was removed (
/// reconnect never gives up; the `Option` shape is kept for the driver's call
/// sites). [`Self::reset`] is called after a successful (re)connect.
#[derive(Debug)]
pub(super) struct Backoff {
    config: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    pub(super) fn new(config: BackoffConfig) -> Self {
        Self { config, attempt: 0 }
    }

    pub(super) fn reset(&mut self) {
        self.attempt = 0;
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "the `Option` shape is kept for the ws driver's reconnect call site"
    )]
    pub(super) fn next_delay(&mut self) -> Option<Duration> {
        self.attempt = self.attempt.saturating_add(1);
        let factor = 2u64.checked_pow(self.attempt - 1).unwrap_or(u64::MAX);
        let base_ms = u64::try_from(self.config.base.as_millis()).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(self.config.max.as_millis()).unwrap_or(u64::MAX);
        let ms = base_ms.saturating_mul(factor).min(max_ms);
        Some(Duration::from_millis(ms))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    use super::{Backoff, BackoffConfig, Transport, TransportConfig, build_envelope};
    use crate::db::Db;
    use crate::protocol::frames::{
        E2eeCapability, E2eeLiveFrame, InboundFrame, MessageKind, OutboundFrame, ThreadMessageData,
    };

    // -- pure helpers ------------------------------------------------------

    /// Regression: the delay schedule keeps the TS shape (exponential,
    /// 10 s cap) but never exhausts — the old `max_retries: 60` ceiling turned
    /// a ~10 min host outage into a daemon exit.
    #[test]
    fn backoff_caps_delay_and_never_gives_up() {
        let mut backoff = Backoff::new(BackoffConfig::default());
        // 1 s, 2 s, 4 s, 8 s, then clamped at the 10 s ceiling.
        assert_eq!(backoff.next_delay(), Some(Duration::from_secs(1)));
        assert_eq!(backoff.next_delay(), Some(Duration::from_secs(2)));
        assert_eq!(backoff.next_delay(), Some(Duration::from_secs(4)));
        assert_eq!(backoff.next_delay(), Some(Duration::from_secs(8)));
        // Far past the old 60-attempt budget the delay stays at the cap.
        for _ in 5..=500 {
            assert_eq!(backoff.next_delay(), Some(Duration::from_secs(10)));
        }
        // reset restarts the schedule.
        backoff.reset();
        assert_eq!(backoff.next_delay(), Some(Duration::from_secs(1)));
    }

    fn sample_message_data() -> ThreadMessageData {
        ThreadMessageData {
            seq: 3,
            kind: MessageKind::AssistantText,
            role: Some("assistant".to_owned()),
            content: Some("hi".to_owned()),
            tool: None,
            input: None,
            output: None,
            tool_use_id: None,
            parent_tool_use_id: None,
        }
    }

    #[test]
    fn build_envelope_round_trips_thread_frame_with_ids_at_top_level() {
        // The envelope rebuilt from the outbox columns must parse straight back
        // into the typed frame: ids at the top level, `data` nested, the
        // outbox row id surfacing as `outboxId`.
        let data = sample_message_data();
        let value = serde_json::to_value(&data).unwrap();
        let envelope = build_envelope(
            "thread_message",
            &value,
            Some("t-1"),
            Some("c-9@1718"),
            &crate::protocol::test_delivery_id(43),
        );
        assert_eq!(envelope["type"], json!("thread_message"));
        assert_eq!(envelope["taskId"], json!("t-1"));
        assert_eq!(envelope["threadId"], json!("c-9@1718"));
        assert_eq!(
            envelope["outboxId"],
            json!(crate::protocol::test_delivery_id(43))
        );
        assert_eq!(envelope["data"]["seq"], json!(3));

        let parsed: OutboundFrame = serde_json::from_value(envelope).unwrap();
        assert_eq!(
            parsed,
            OutboundFrame::ThreadMessage {
                task_id: "t-1".to_owned(),
                thread_id: "c-9@1718".to_owned(),
                data,
                outbox_id: Some(crate::protocol::test_delivery_id(43)),
            }
        );
    }

    #[test]
    fn build_envelope_keys_cron_state_secondary_as_cron_id() {
        // The `cron_state` frame's secondary column is its `cronId`, not a thread.
        let data = json!({ "kind": "schedule", "round_count": 1, "skipped_count": 0 });
        let envelope = build_envelope(
            "cron_state",
            &data,
            Some("t-1"),
            Some("cr-7"),
            &crate::protocol::test_delivery_id(5),
        );
        assert_eq!(envelope["cronId"], json!("cr-7"));
        assert!(envelope.get("threadId").is_none());
    }

    // -- integration against a mock WS server ------------------------------

    type ServerWs = WebSocketStream<TcpStream>;

    fn remote_ops_off() -> Arc<crate::remote_ops::RemoteOps> {
        Arc::new(crate::remote_ops::RemoteOps::new(
            false,
            std::path::Path::new("/nonexistent"),
        ))
    }

    fn test_config() -> TransportConfig {
        TransportConfig {
            // Far longer than any test runs, so no heartbeat, read-liveness
            // check, or ack-stall retransmit fires mid-test.
            heartbeat: Duration::from_secs(50),
            capabilities: Vec::new(),
            engines: Arc::default(),
            e2ee: None,
            e2ee_live: None,
            e2ee_ds: None,
            read_timeout: Duration::from_mins(2),
            ack_timeout: Duration::from_mins(2),
            backoff: BackoffConfig::for_tests(),
        }
    }

    async fn next_text(ws: &mut ServerWs) -> String {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => return text.as_str().to_owned(),
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_))) => {}
                other => panic!("expected a text frame, got {other:?}"),
            }
        }
    }

    /// The host's `ack` for a received agent frame, echoing its `outboxId`.
    fn ack_for(frame: &str) -> Message {
        let frame: Value = serde_json::from_str(frame).unwrap();
        Message::text(json!({ "type": "ack", "id": frame["outboxId"] }).to_string())
    }

    async fn wait_until<F: FnMut() -> bool>(mut predicate: F) {
        for _ in 0..200 {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached within timeout");
    }

    /// Live-only e2ee frames reach the e2ee channel without touching the
    /// inbox or drawing a `msg_ack`; the durable `e2ee_log` is recorded,
    /// acked and delivered like any host frame. The heartbeat carries the
    /// e2ee capability.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn e2ee_live_frames_bypass_the_inbox_and_records_use_it() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            for frame in [
                json!({
                    "type": "e2ee_key_package_status",
                    "id": "01jab3x7k2m4n5p6q7r8s90001",
                    "data": { "one_time": 3, "last_resort": true }
                }),
                json!({
                    "type": "e2ee_response", "taskId": "t-1", "reqId": "r-1",
                    "data": { "ok": false, "error": { "code": "not_member" } }
                }),
                json!({
                    "type": "e2ee_log", "taskId": "t-1", "msgId": "01jab3x7k2m4n5p6q7r8s90002",
                    "data": { "seq": 1, "kind": "commit", "epoch": 0, "message": "bQ" }
                }),
            ] {
                ws.send(Message::text(frame.to_string())).await.unwrap();
            }
            // The first agent text frame is the msg_ack of the e2ee_log
            // (nothing for the live frames), then the heartbeat.
            let ack: Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            let heartbeat: Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            (ack, heartbeat, ws)
        });

        let (live_tx, mut live_rx) = mpsc::unbounded_channel();
        let mut transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-e2ee"),
            SecretString::from("tok"),
            Arc::clone(&db),
            TransportConfig {
                heartbeat: Duration::from_millis(1500),
                e2ee: Some(E2eeCapability::basic("cGs".to_owned())),
                e2ee_live: Some(live_tx),
                ..test_config()
            },
            remote_ops_off(),
        );

        let status = live_rx.recv().await.unwrap();
        assert!(matches!(
            status,
            E2eeLiveFrame::KeyPackageStatus { id: Some(ref id), .. } if id == "01jab3x7k2m4n5p6q7r8s90001"
        ));
        assert!(matches!(
            live_rx.recv().await.unwrap(),
            E2eeLiveFrame::Response { .. }
        ));
        let inbound = transport.recv().await.unwrap();
        assert!(matches!(
            inbound.frame,
            InboundFrame::E2eeLog { ref task_id, .. } if task_id == "t-1"
        ));
        let (ack, heartbeat, _ws) = server.await.unwrap();
        assert_eq!(
            ack,
            json!({ "type": "msg_ack", "msgId": "01jab3x7k2m4n5p6q7r8s90002" })
        );
        assert_eq!(heartbeat["type"], json!("heartbeat"));
        assert_eq!(
            heartbeat["data"]["e2ee"]["credential"],
            json!({ "type": "basic", "public_key": "cGs" })
        );
        let rows = db.lock().unwrap().list_unprocessed_inbox().unwrap();
        assert_eq!(rows.len(), 1, "only the durable record is stored");
        assert_eq!(rows[0].msg_type, "e2ee_log");
        assert_eq!(rows[0].task_id.as_deref(), Some("t-1"));
        transport.shutdown().await;
    }

    // The `accept_hdr_async` callback returns tungstenite's own large
    // `Result<Response, ErrorResponse>`; the shape is fixed by the library.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn outbox_replays_in_order_carries_correlation_and_ack_clears() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let (id1, id2) = {
            let guard = db.lock().unwrap();
            // Outbox payload = `data` only; correlation ids ride the columns.
            let id1 = guard
                .enqueue_outbox_correlated(
                    "thread_message",
                    &json!({ "seq": 1, "kind": "assistant_text", "content": "a" }),
                    Some("t-1"),
                    Some("c-1"),
                )
                .unwrap();
            let id2 = guard
                .enqueue_outbox_correlated(
                    "thread_result",
                    &json!({ "status": "succeeded", "duration_ms": 5, "final_seq": 1 }),
                    Some("t-1"),
                    Some("c-1"),
                )
                .unwrap();
            (id1, id2)
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured_token = Arc::new(std::sync::Mutex::new(None::<String>));
        let cap = Arc::clone(&captured_token);

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws =
                tokio_tungstenite::accept_hdr_async(tcp, move |req: &Request, resp: Response| {
                    *cap.lock().unwrap() = req
                        .headers()
                        .get("x-internal-token")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    Ok(resp)
                })
                .await
                .unwrap();
            let first = next_text(&mut ws).await;
            let second = next_text(&mut ws).await;
            ws.send(ack_for(&first)).await.unwrap();
            ws.send(ack_for(&second)).await.unwrap();
            (first, second)
        });

        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-1"),
            SecretString::from("connect-secret"),
            Arc::clone(&db),
            test_config(),
            remote_ops_off(),
        );

        let (first, second) = server.await.unwrap();
        let first: Value = serde_json::from_str(&first).unwrap();
        let second: Value = serde_json::from_str(&second).unwrap();
        // Replayed oldest-first; each envelope is rebuilt from the columns with the
        // correlation ids at the top level and the persisted `data` nested.
        assert_eq!(first["type"], json!("thread_message"));
        assert_eq!(first["outboxId"], json!(id1));
        assert_eq!(first["taskId"], json!("t-1"));
        assert_eq!(first["threadId"], json!("c-1"));
        assert_eq!(first["data"]["content"], json!("a"));
        // Correlation ids must not leak into `data`.
        assert!(first["data"].get("taskId").is_none());
        assert!(first["data"].get("threadId").is_none());
        assert_eq!(second["type"], json!("thread_result"));
        assert_eq!(second["outboxId"], json!(id2));
        assert_eq!(second["threadId"], json!("c-1"));

        assert_eq!(
            captured_token.lock().unwrap().as_deref(),
            Some("connect-secret"),
            "the connect token must travel in the x-internal-token header"
        );

        // Acks clear the outbox.
        wait_until(|| db.lock().unwrap().list_unacked_outbox().unwrap().is_empty()).await;
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn inbound_message_is_persisted_and_msg_acked() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::text(
                r#"{"type":"message","taskId":"t-1","threadId":"c-1","data":{"text":"hello"},"msgId":"01jab3x7k2m4n5p6q7r8s90007"}"#
                    .to_owned(),
            ))
            .await
            .unwrap();
            next_text(&mut ws).await // the msg_ack
        });

        let mut transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-2"),
            SecretString::from("tok"),
            Arc::clone(&db),
            test_config(),
            remote_ops_off(),
        );

        let inbound = transport.recv().await.unwrap();
        match &inbound.frame {
            crate::protocol::frames::InboundFrame::Message {
                task_id,
                thread_id,
                data,
                msg_id,
            } => {
                assert_eq!(task_id, "t-1");
                assert_eq!(thread_id.as_deref(), Some("c-1"));
                assert_eq!(data.text, "hello".into());
                assert_eq!(*msg_id, Some(crate::protocol::test_delivery_id(7)));
            }
            other => panic!("expected a message frame, got {other:?}"),
        }
        // Persisted to the inbox (dedup source of truth) with its correlation ids
        // captured in the indexed columns, and the FULL frame as the payload.
        {
            let guard = db.lock().unwrap();
            let rows = guard.list_unprocessed_inbox().unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].msg_type, "message");
            assert_eq!(rows[0].task_id.as_deref(), Some("t-1"));
            assert_eq!(rows[0].thread_id.as_deref(), Some("c-1"));
            let payload: Value = serde_json::from_str(&rows[0].payload).unwrap();
            assert_eq!(payload["type"], json!("message"));
            assert_eq!(payload["taskId"], json!("t-1"));
            assert_eq!(payload["data"]["text"], json!("hello"));
        }

        let ack: Value = serde_json::from_str(&server.await.unwrap()).unwrap();
        assert_eq!(
            ack,
            json!({ "type": "msg_ack", "msgId": "01jab3x7k2m4n5p6q7r8s90007" })
        );

        transport.shutdown().await;
    }

    #[tokio::test]
    async fn reconnect_replays_unacked_outbox() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let id = {
            db.lock()
                .unwrap()
                .enqueue_outbox_correlated(
                    "thread_result",
                    &json!({ "status": "succeeded", "duration_ms": 1, "final_seq": 0 }),
                    Some("t-1"),
                    Some("c-1"),
                )
                .unwrap()
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // First connection: read the replayed frame, then drop without acking.
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let first = next_text(&mut ws).await;
            drop(ws); // simulate a dropped connection

            // Second connection: the unacked row must be replayed, then we ack it.
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let second = next_text(&mut ws).await;
            ws.send(ack_for(&second)).await.unwrap();
            (first, second)
        });

        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-3"),
            SecretString::from("tok"),
            Arc::clone(&db),
            test_config(),
            remote_ops_off(),
        );

        let (first, second) = server.await.unwrap();
        let first: Value = serde_json::from_str(&first).unwrap();
        let second: Value = serde_json::from_str(&second).unwrap();
        assert_eq!(first["type"], json!("thread_result"));
        assert_eq!(first["outboxId"], json!(id));
        assert_eq!(first["threadId"], json!("c-1"));
        // The very same unacked row is replayed (byte-identical) on the fresh
        // connection — the host de-dups on its own `(thread_id, seq)` key.
        assert_eq!(second["outboxId"], json!(id));
        assert_eq!(second["threadId"], json!("c-1"));

        wait_until(|| db.lock().unwrap().list_unacked_outbox().unwrap().is_empty()).await;
        transport.shutdown().await;
    }

    /// Regression, end to end: the host redelivers the same `msgId` (as it
    /// does after a lost `msg_ack`) — both deliveries are msg_acked, but exactly
    /// ONE inbox row exists and exactly ONE frame reaches the consumer.
    #[tokio::test]
    async fn duplicate_delivery_is_reacked_and_delivered_once() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let frame = r#"{"type":"message","taskId":"t-1","threadId":"c-1","data":{"text":"hello"},"msgId":"01jab3x7k2m4n5p6q7r8s90007"}"#;
            ws.send(Message::text(frame.to_owned())).await.unwrap();
            let first_ack = next_text(&mut ws).await;
            // Simulate a lost msg_ack on the host side: resend the SAME frame.
            ws.send(Message::text(frame.to_owned())).await.unwrap();
            let second_ack = next_text(&mut ws).await;
            (first_ack, second_ack)
        });

        let mut transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-4"),
            SecretString::from("tok"),
            Arc::clone(&db),
            test_config(),
            remote_ops_off(),
        );

        let (first_ack, second_ack) = server.await.unwrap();
        let expected = json!({ "type": "msg_ack", "msgId": "01jab3x7k2m4n5p6q7r8s90007" });
        assert_eq!(serde_json::from_str::<Value>(&first_ack).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<Value>(&second_ack).unwrap(),
            expected,
            "the duplicate delivery is re-acked"
        );

        // Exactly one frame reaches the consumer...
        let inbound = transport.recv().await.unwrap();
        assert!(matches!(
            inbound.frame,
            crate::protocol::frames::InboundFrame::Message { .. }
        ));
        // ...and exactly one inbox row exists (dedup on msg_id).
        assert_eq!(
            db.lock().unwrap().list_unprocessed_inbox().unwrap().len(),
            1,
            "redelivery must not create a second inbox row"
        );
        transport.shutdown().await;
    }

    /// Regression: a host-supplied heartbeat interval of ZERO must not
    /// panic the transport task — the driver clamps it and keeps serving.
    #[tokio::test]
    async fn zero_heartbeat_interval_does_not_panic_the_driver() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::text(
                r#"{"type":"message","taskId":"t-1","threadId":"c-1","data":{"text":"still alive"},"msgId":"01jab3x7k2m4n5p6q7r8s90001"}"#
                    .to_owned(),
            ))
            .await
            .unwrap();
            next_text(&mut ws).await // the msg_ack proves the driver survived
        });

        let mut transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-5"),
            SecretString::from("tok"),
            Arc::clone(&db),
            TransportConfig {
                heartbeat: Duration::ZERO,
                ..test_config()
            },
            remote_ops_off(),
        );

        // The frame flows through a live (un-panicked) driver task.
        let inbound = transport.recv().await.unwrap();
        assert!(matches!(
            inbound.frame,
            crate::protocol::frames::InboundFrame::Message { .. }
        ));
        let ack: Value = serde_json::from_str(&server.await.unwrap()).unwrap();
        assert_eq!(
            ack,
            json!({ "type": "msg_ack", "msgId": "01jab3x7k2m4n5p6q7r8s90001" })
        );
        transport.shutdown().await;
    }

    /// An `fs_request` is answered over the socket without touching the inbox
    /// or the outbox, so it can never be replayed.
    #[tokio::test]
    async fn fs_request_is_answered_live_and_never_persisted() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut responses = Vec::new();
            for (req_id, data) in [
                ("r-1", json!({"op": "mkdir", "path": "d"})),
                ("r-2", json!({"op": "stat", "path": "d"})),
            ] {
                let frame = json!({"type": "fs_request", "reqId": req_id, "data": data});
                ws.send(Message::text(frame.to_string())).await.unwrap();
                responses.push(next_text(&mut ws).await);
            }
            responses
        });

        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-fs"),
            SecretString::from("tok"),
            Arc::clone(&db),
            test_config(),
            Arc::new(crate::remote_ops::RemoteOps::new(true, dir.path())),
        );

        let responses = server.await.unwrap();
        let made: Value = serde_json::from_str(&responses[0]).unwrap();
        assert_eq!(
            made,
            json!({"type": "fs_response", "reqId": "r-1", "data": {"ok": true}})
        );
        let stat: Value = serde_json::from_str(&responses[1]).unwrap();
        assert_eq!(stat["reqId"], json!("r-2"));
        assert_eq!(stat["data"]["stat"]["type"], json!("dir"));
        assert!(dir.path().join("d").is_dir());

        {
            let guard = db.lock().unwrap();
            assert!(guard.list_unprocessed_inbox().unwrap().is_empty());
            assert!(guard.list_unacked_outbox().unwrap().is_empty());
        }
        transport.shutdown().await;
    }

    #[tokio::test]
    async fn pty_disconnect_reaps_process_and_reconnect_never_replays_terminal_frames() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;

        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let dir = tempfile::tempdir().unwrap();
        let ops = Arc::new(crate::remote_ops::RemoteOps::new(false, dir.path()));
        ops.configure(false, true, dir.path());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/pty"),
            SecretString::from("tok"),
            Arc::clone(&db),
            test_config(),
            ops,
        );
        let check = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::text(
                json!({
                    "type": "pty_open", "ptyId": "old",
                    "data": { "argv": ["/bin/sh", "-c", "echo $$; exec sleep 60"] }
                })
                .to_string(),
            ))
            .await
            .unwrap();
            let ready: Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            assert_eq!(ready["type"], "pty_ready");
            let output: Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            let bytes = STANDARD
                .decode(output["data"]["data"].as_str().unwrap())
                .unwrap();
            let pid = String::from_utf8_lossy(&bytes)
                .trim()
                .parse::<i32>()
                .unwrap();
            ws.close(None).await.unwrap();
            drop(ws);

            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            assert_eq!(
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
                Err(nix::errno::Errno::ESRCH)
            );
            ws.send(Message::text(
                json!({ "type": "pty_input", "ptyId": "old", "data": { "data": "eA==" } })
                    .to_string(),
            ))
            .await
            .unwrap();
            ws.send(Message::text(
                json!({ "type": "pty_open", "ptyId": "new", "data": {
                "argv": ["/bin/sh", "-c", "read line; printf '%s' \"$line\"; exit 4"]
            } })
                .to_string(),
            ))
            .await
            .unwrap();
            let ready: Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
            assert_eq!(ready["type"], "pty_ready");
            assert_eq!(ready["ptyId"], "new");
            ws.send(Message::text(json!({ "type": "pty_input", "ptyId": "new", "data": { "data": STANDARD.encode(b"new-session\n") } }).to_string())).await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let frame: Value = serde_json::from_str(&next_text(&mut ws).await).unwrap();
                assert_eq!(frame["ptyId"], "new");
                if frame["type"] == "pty_exit" {
                    assert_eq!(frame["data"]["exit_code"], 4);
                    break;
                }
                assert_eq!(frame["type"], "pty_output");
                bytes.extend(
                    STANDARD
                        .decode(frame["data"]["data"].as_str().unwrap())
                        .unwrap(),
                );
            }
            assert!(String::from_utf8_lossy(&bytes).contains("new-session"));
        };
        tokio::time::timeout(Duration::from_secs(10), check)
            .await
            .unwrap();
        transport.shutdown().await;
        let guard = db.lock().unwrap();
        assert!(guard.list_unprocessed_inbox().unwrap().is_empty());
        assert!(guard.list_unacked_outbox().unwrap().is_empty());
    }

    /// Regression: opening the transport against an unreachable host must
    /// not fail or block — the daemon side stays fully functional (frames
    /// enqueue durably) and the manager task keeps dialing instead of exiting.
    #[tokio::test]
    async fn open_with_unreachable_host_boots_and_keeps_dialing() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        // Bind-then-drop: the freed port refuses every dial.
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-off"),
            SecretString::from("tok"),
            Arc::clone(&db),
            test_config(),
            remote_ops_off(),
        );

        // The producer path works while offline: enqueue a frame's `data` to the
        // durable outbox (as the executor/scheduler do) and poke flush.
        let data = serde_json::to_value(sample_message_data()).unwrap();
        let id = db
            .lock()
            .unwrap()
            .enqueue_outbox_correlated("thread_message", &data, Some("t-1"), Some("c-1"))
            .unwrap();
        transport.flush_handle().notify_one();
        assert_eq!(db.lock().unwrap().list_unacked_outbox().unwrap()[0].id, id);

        // Well past the fast schedule's old 8-attempt test budget: the manager
        // task must still be dialing, not exited (the old code gave up here).
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(
            !transport.manager.is_finished(),
            "the manager task must keep retrying, never exit"
        );
        // And shutdown still completes promptly out of the retry loop.
        transport.shutdown().await;
    }

    /// Regression: the transport survives a failure window far past the
    /// old 60-retry budget, then — once the host comes up — establishes the
    /// connection and flushes the pending outbox as on any reconnect.
    #[tokio::test]
    async fn retries_past_old_budget_then_flushes_outbox_when_host_returns() {
        // More consecutive failures than the removed `max_retries: 60` ceiling.
        const OUTAGE_DIALS: usize = 70;

        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let id = {
            db.lock()
                .unwrap()
                .enqueue_outbox_correlated(
                    "thread_result",
                    &json!({ "status": "succeeded", "duration_ms": 1, "final_seq": 0 }),
                    Some("t-1"),
                    Some("c-1"),
                )
                .unwrap()
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // Failure window: refuse the WS handshake on the first dials.
            for _ in 0..OUTAGE_DIALS {
                let (tcp, _) = listener.accept().await.unwrap();
                drop(tcp);
            }
            // Host is back: accept, expect the replayed outbox row, ack it.
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let frame = next_text(&mut ws).await;
            ws.send(ack_for(&frame)).await.unwrap();
            frame
        });

        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-6"),
            SecretString::from("tok"),
            Arc::clone(&db),
            TransportConfig {
                // Tiny delays so 70 failed attempts stay well under a second.
                backoff: BackoffConfig {
                    base: Duration::from_millis(1),
                    max: Duration::from_millis(2),
                },
                ..test_config()
            },
            remote_ops_off(),
        );

        let frame: Value = serde_json::from_str(&server.await.unwrap()).unwrap();
        assert_eq!(frame["type"], json!("thread_result"));
        assert_eq!(frame["outboxId"], json!(id));
        assert_eq!(frame["threadId"], json!("c-1"));
        wait_until(|| db.lock().unwrap().list_unacked_outbox().unwrap().is_empty()).await;
        transport.shutdown().await;
    }

    /// Regression: under ack lag a flush transmits ONLY the rows not yet
    /// sent on this connection (the old driver replayed the entire unacked
    /// outbox on every flush — O(n²)); a reconnect still replays everything
    /// unacked.
    #[tokio::test]
    async fn flush_is_incremental_under_ack_lag_but_reconnect_replays_all() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Every frame the mock host receives, tagged with its connection index.
        let received = Arc::new(std::sync::Mutex::new(Vec::<(usize, Value)>::new()));
        let drop_gate = Arc::new(tokio::sync::Notify::new());

        let (srv_received, srv_gate) = (Arc::clone(&received), Arc::clone(&drop_gate));
        let server = tokio::spawn(async move {
            // Connection 1: record frames (acking NOTHING — sustained ack lag)
            // until the test asks for a dropped connection.
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            loop {
                tokio::select! {
                    () = srv_gate.notified() => break,
                    message = ws.next() => {
                        if let Some(Ok(Message::Text(text))) = message {
                            let frame: Value = serde_json::from_str(text.as_str()).unwrap();
                            srv_received.lock().unwrap().push((1, frame));
                        }
                    }
                }
            }
            drop(ws);

            // Connection 2: the reconnect replay.
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            for _ in 0..2 {
                let text = next_text(&mut ws).await;
                let frame: Value = serde_json::from_str(&text).unwrap();
                srv_received.lock().unwrap().push((2, frame));
            }
        });

        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-lag"),
            SecretString::from("tok"),
            Arc::clone(&db),
            test_config(),
            remote_ops_off(),
        );
        let flush = transport.flush_handle();

        // Flush 1 ships row 1; the host holds its ack.
        let id1 = db
            .lock()
            .unwrap()
            .enqueue_outbox_correlated(
                "thread_message",
                &json!({ "seq": 1 }),
                Some("t-1"),
                Some("c-1"),
            )
            .unwrap();
        flush.notify_one();
        wait_until(|| received.lock().unwrap().len() == 1).await;

        // Flush 2 must carry ONLY the fresh row 2 — not retransmit row 1.
        let id2 = db
            .lock()
            .unwrap()
            .enqueue_outbox_correlated(
                "thread_message",
                &json!({ "seq": 2 }),
                Some("t-1"),
                Some("c-1"),
            )
            .unwrap();
        flush.notify_one();
        wait_until(|| received.lock().unwrap().len() == 2).await;
        {
            let frames = received.lock().unwrap();
            assert_eq!(frames[0].1["outboxId"], json!(id1));
            assert_eq!(
                frames[1].1["outboxId"],
                json!(id2),
                "a flush under ack lag must not retransmit the already-sent backlog"
            );
        }

        // Reconnect: BOTH still-unacked rows replay on the fresh connection.
        drop_gate.notify_one();
        wait_until(|| received.lock().unwrap().len() == 4).await;
        {
            let frames = received.lock().unwrap();
            assert_eq!(
                frames[2].0, 2,
                "the replay arrives on the second connection"
            );
            assert_eq!(
                frames[2].1["outboxId"],
                json!(id1),
                "reconnect replays all unacked"
            );
            assert_eq!(frames[3].1["outboxId"], json!(id2));
        }

        server.await.unwrap();
        transport.shutdown().await;
    }

    /// A half-open connection — the peer completes the handshake and
    /// then goes completely silent, never reading or writing — is detected by
    /// the read-liveness window and redialed (the old write-only heartbeat left
    /// this to the ~15-minute TCP retransmit timeout).
    #[tokio::test]
    async fn silent_half_open_connection_is_detected_and_redialed() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // Connection 1: handshake, then total silence — the stream is held
            // open (TCP stays established) but never read or written again.
            let (tcp, _) = listener.accept().await.unwrap();
            let silent = tokio_tungstenite::accept_async(tcp).await.unwrap();

            // A second connection arriving proves the client declared the
            // silent one dead and redialed.
            let (tcp, _) = listener.accept().await.unwrap();
            let _redialed = tokio_tungstenite::accept_async(tcp).await.unwrap();
            drop(silent);
        });

        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-silent"),
            SecretString::from("tok"),
            Arc::clone(&db),
            TransportConfig {
                // A fast heartbeat keeps the effective read window at the 1 s
                // clamp floor, so the dead connection is declared quickly.
                heartbeat: Duration::from_millis(100),
                read_timeout: Duration::from_millis(200),
                ..test_config()
            },
            remote_ops_off(),
        );

        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the client must redial within the read-liveness window")
            .unwrap();
        transport.shutdown().await;
    }

    /// When ack progress stalls for a full ack window on a live
    /// connection, the transmitted backlog is retransmitted — the at-least-once
    /// safety valve that incremental flushing removed from the per-flush path.
    #[tokio::test]
    async fn stalled_acks_trigger_a_retransmit_on_the_live_connection() {
        let db = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let id = {
            db.lock()
                .unwrap()
                .enqueue_outbox_correlated(
                    "thread_message",
                    &json!({ "seq": 1 }),
                    Some("t-1"),
                    Some("c-1"),
                )
                .unwrap()
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let first = next_text(&mut ws).await; // the connect replay
            let second = next_text(&mut ws).await; // the ack-stall retransmit
            (first, second)
        });

        let transport = Transport::open(
            format!("ws://{addr}/agent/ws/agent-stall"),
            SecretString::from("tok"),
            Arc::clone(&db),
            TransportConfig {
                // Clamped to the 1 s floor; the stall trips on the second tick.
                ack_timeout: Duration::from_millis(100),
                ..test_config()
            },
            remote_ops_off(),
        );

        let (first, second) = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("the stalled ack must trigger a retransmit on the live socket")
            .unwrap();
        let first: Value = serde_json::from_str(&first).unwrap();
        let second: Value = serde_json::from_str(&second).unwrap();
        assert_eq!(first["outboxId"], json!(id));
        assert_eq!(
            second["outboxId"],
            json!(id),
            "the same unacked row is retransmitted once acks stall"
        );
        transport.shutdown().await;
    }
}
