//! Live-only e2ee Delivery Service requests (protocol §5.3).
//!
//! An `e2ee_request` goes out on the current socket with a runner-minted
//! `reqId`; the `e2ee_response` with the same `reqId` resolves it. Nothing is
//! persisted: a request waits for a socket up to its timeout, and a socket drop
//! fails every request still pending on it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::protocol::frames::{E2eeRequestData, E2eeResponseData, OutboundFrame};

/// A DS request that got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum DsLinkError {
    /// No socket, or no answer, within the timeout.
    #[error("the DS request timed out")]
    Timeout,
    /// The socket dropped before the answer arrived.
    #[error("the connection dropped before the DS answered")]
    Disconnected,
}

/// The current socket: its open count and the queue feeding its sink.
#[derive(Debug, Clone)]
struct Socket {
    generation: u64,
    tx: mpsc::Sender<String>,
}

/// The e2ee request channel over whichever socket is live.
#[derive(Debug)]
pub(crate) struct DsLink {
    socket: watch::Sender<Option<Socket>>,
    pending: Mutex<HashMap<String, oneshot::Sender<E2eeResponseData>>>,
    opens: AtomicU64,
    next_req: AtomicU64,
}

impl Default for DsLink {
    fn default() -> Self {
        Self {
            socket: watch::Sender::new(None),
            pending: Mutex::new(HashMap::new()),
            opens: AtomicU64::new(0),
            next_req: AtomicU64::new(1),
        }
    }
}

impl DsLink {
    /// How many sockets have opened so far.
    pub(crate) fn generation(&self) -> u64 {
        self.opens.load(Ordering::SeqCst)
    }

    /// Socket-open notifications.
    pub(crate) fn connections(&self) -> Connections {
        let mut rx = self.socket.subscribe();
        rx.mark_changed();
        Connections(rx)
    }

    /// Send `data` for `task_id` and await the answer, waiting for a socket
    /// if none is open; both bounded by `timeout`.
    pub(crate) async fn request(
        &self,
        task_id: &str,
        data: E2eeRequestData,
        timeout: Duration,
    ) -> Result<E2eeResponseData, DsLinkError> {
        let deadline = Instant::now() + timeout;
        let mut socket = self.socket.subscribe();
        let tx = match tokio::time::timeout_at(deadline, socket.wait_for(Option::is_some)).await {
            Ok(Ok(current)) => current.as_ref().map(|s| s.tx.clone()),
            Ok(Err(_)) => None,
            Err(_) => return Err(DsLinkError::Timeout),
        }
        .ok_or(DsLinkError::Disconnected)?;
        let req_id = format!("e2ee-{}", self.next_req.fetch_add(1, Ordering::SeqCst));
        let frame = OutboundFrame::E2eeRequest {
            task_id: task_id.to_owned(),
            req_id: req_id.clone(),
            data,
        };
        let text = serde_json::to_string(&frame).map_err(|_| DsLinkError::Disconnected)?;
        let (answer_tx, answer_rx) = oneshot::channel();
        self.pending_map().insert(req_id.clone(), answer_tx);
        let sent = tokio::time::timeout_at(deadline, tx.send(text)).await;
        let result = match sent {
            Ok(Ok(())) => match tokio::time::timeout_at(deadline, answer_rx).await {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(_)) => Err(DsLinkError::Disconnected),
                Err(_) => Err(DsLinkError::Timeout),
            },
            Ok(Err(_)) => Err(DsLinkError::Disconnected),
            Err(_) => Err(DsLinkError::Timeout),
        };
        if result.is_err() {
            self.pending_map().remove(&req_id);
        }
        result
    }

    /// Resolve the request `req_id`; `false` when none is pending.
    pub(crate) fn on_response(&self, req_id: &str, data: E2eeResponseData) -> bool {
        self.pending_map()
            .remove(req_id)
            .is_some_and(|answer| answer.send(data).is_ok())
    }

    /// A socket opened; `tx` feeds its sink.
    pub(crate) fn opened(&self, tx: mpsc::Sender<String>) {
        let generation = self.opens.fetch_add(1, Ordering::SeqCst) + 1;
        self.socket.send_replace(Some(Socket { generation, tx }));
    }

    /// The socket dropped: every pending request fails.
    pub(crate) fn closed(&self) {
        self.socket.send_replace(None);
        self.pending_map().clear();
    }

    fn pending_map(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<E2eeResponseData>>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Socket-open notifications from a [`DsLink`].
#[derive(Debug)]
pub(crate) struct Connections(watch::Receiver<Option<Socket>>);

impl Connections {
    /// Resolve at the next socket open (at once if a socket is open and not
    /// yet reported); `None` once the link is gone.
    pub(crate) async fn opened(&mut self) -> Option<u64> {
        loop {
            self.0.changed().await.ok()?;
            if let Some(socket) = self.0.borrow_and_update().as_ref() {
                return Some(socket.generation);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::{DsLink, DsLinkError};
    use crate::protocol::frames::{E2eeRequestData, E2eeResponseData};

    fn ok() -> E2eeResponseData {
        E2eeResponseData {
            ok: true,
            error: None,
            entries: Some(Vec::new()),
            more: None,
            epoch: None,
            seq: None,
            link: None,
        }
    }

    fn req_id(text: &str) -> String {
        let frame: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(frame["type"], "e2ee_request");
        frame["reqId"].as_str().unwrap().to_owned()
    }

    #[tokio::test]
    async fn a_request_is_answered_by_its_req_id() {
        let link = Arc::new(DsLink::default());
        let (tx, mut rx) = mpsc::channel(4);
        link.opened(tx);
        let answer = {
            let link = Arc::clone(&link);
            tokio::spawn(async move {
                let text = rx.recv().await.unwrap();
                let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(frame["taskId"], "t-1");
                assert_eq!(
                    frame["data"],
                    serde_json::json!({"op": "log", "after_seq": 3})
                );
                assert!(!link.on_response("unknown", ok()));
                assert!(link.on_response(&req_id(&text), ok()));
            })
        };
        let response = link
            .request(
                "t-1",
                E2eeRequestData::Log { after_seq: 3 },
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(response.ok);
        answer.await.unwrap();
        assert_eq!(link.generation(), 1);
    }

    #[tokio::test]
    async fn a_request_waits_for_a_socket_within_its_timeout() {
        let link = DsLink::default();
        let started = tokio::time::Instant::now();
        let result = link
            .request(
                "t-1",
                E2eeRequestData::Link { epoch: 1 },
                Duration::from_millis(50),
            )
            .await;
        assert_eq!(result, Err(DsLinkError::Timeout));
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn an_unanswered_request_times_out() {
        let link = DsLink::default();
        let (tx, _rx) = mpsc::channel(4);
        link.opened(tx);
        let result = link
            .request(
                "t-1",
                E2eeRequestData::Link { epoch: 1 },
                Duration::from_millis(50),
            )
            .await;
        assert_eq!(result, Err(DsLinkError::Timeout));
        assert!(link.pending_map().is_empty());
    }

    #[tokio::test]
    async fn a_socket_drop_fails_pending_requests() {
        let link = Arc::new(DsLink::default());
        let (tx, mut rx) = mpsc::channel(4);
        link.opened(tx);
        let closer = {
            let link = Arc::clone(&link);
            tokio::spawn(async move {
                rx.recv().await.unwrap();
                link.closed();
            })
        };
        let result = link
            .request(
                "t-1",
                E2eeRequestData::Link { epoch: 1 },
                Duration::from_secs(5),
            )
            .await;
        assert_eq!(result, Err(DsLinkError::Disconnected));
        closer.await.unwrap();
    }

    #[tokio::test]
    async fn connections_report_each_open() {
        let link = DsLink::default();
        let mut connections = link.connections();
        let (tx, _rx) = mpsc::channel(4);
        link.opened(tx.clone());
        assert_eq!(connections.opened().await, Some(1));
        link.closed();
        link.opened(tx);
        assert_eq!(connections.opened().await, Some(2));
        // A subscriber that joins while a socket is open sees it at once.
        let mut late = link.connections();
        assert_eq!(late.opened().await, Some(2));
    }
}
