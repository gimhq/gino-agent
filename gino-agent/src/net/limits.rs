//! Per-run caps on live TCP connections and UDP flows.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-run connection and flow caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitsConfig {
    /// Maximum live TCP connections.
    pub max_tcp: usize,
    /// Maximum live UDP flows.
    pub max_udp: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_tcp: 256,
            max_udp: 1024,
        }
    }
}

/// A cap was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitError {
    /// All TCP slots are in use.
    #[error("TCP connection limit reached ({max})")]
    TcpCap {
        /// The configured cap.
        max: usize,
    },
    /// All UDP slots are in use.
    #[error("UDP flow limit reached ({max})")]
    UdpCap {
        /// The configured cap.
        max: usize,
    },
}

/// Live-slot counters of one run; clones share the same counters.
#[derive(Debug, Clone)]
pub struct RunLimits {
    max_tcp: usize,
    max_udp: usize,
    tcp: Arc<Semaphore>,
    udp: Arc<Semaphore>,
}

/// A held TCP slot, released on drop.
#[derive(Debug)]
pub struct TcpPermit(
    #[expect(dead_code, reason = "held only to release the slot on drop")] OwnedSemaphorePermit,
);

/// A held UDP slot, released on drop.
#[derive(Debug)]
pub struct UdpPermit(
    #[expect(dead_code, reason = "held only to release the slot on drop")] OwnedSemaphorePermit,
);

impl RunLimits {
    /// Creates counters for `cfg`; caps above the semaphore maximum are clamped.
    pub fn new(cfg: LimitsConfig) -> Self {
        let max_tcp = cfg.max_tcp.min(Semaphore::MAX_PERMITS);
        let max_udp = cfg.max_udp.min(Semaphore::MAX_PERMITS);
        Self {
            max_tcp,
            max_udp,
            tcp: Arc::new(Semaphore::new(max_tcp)),
            udp: Arc::new(Semaphore::new(max_udp)),
        }
    }

    /// Takes a TCP slot, or fails when all are in use.
    pub fn try_tcp(&self) -> Result<TcpPermit, LimitError> {
        Arc::clone(&self.tcp)
            .try_acquire_owned()
            .map(TcpPermit)
            .map_err(|_| LimitError::TcpCap { max: self.max_tcp })
    }

    /// Takes a UDP slot, or fails when all are in use.
    pub fn try_udp(&self) -> Result<UdpPermit, LimitError> {
        Arc::clone(&self.udp)
            .try_acquire_owned()
            .map(UdpPermit)
            .map_err(|_| LimitError::UdpCap { max: self.max_udp })
    }

    /// Number of held TCP slots.
    #[cfg(test)]
    pub fn live_tcp(&self) -> usize {
        self.max_tcp - self.tcp.available_permits()
    }

    /// Number of held UDP slots.
    #[cfg(test)]
    pub fn live_udp(&self) -> usize {
        self.max_udp - self.udp.available_permits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_tcp: usize, max_udp: usize) -> RunLimits {
        RunLimits::new(LimitsConfig { max_tcp, max_udp })
    }

    #[test]
    fn defaults() {
        assert_eq!(
            LimitsConfig::default(),
            LimitsConfig {
                max_tcp: 256,
                max_udp: 1024
            }
        );
    }

    #[test]
    fn tcp_cap_enforced_at_max_and_released_on_drop() {
        let limits = limits(2, 5);
        let a = limits.try_tcp().unwrap();
        let _b = limits.try_tcp().unwrap();
        assert_eq!(limits.live_tcp(), 2);
        let err = limits.try_tcp().unwrap_err();
        assert_eq!(err, LimitError::TcpCap { max: 2 });
        assert_eq!(err.to_string(), "TCP connection limit reached (2)");
        assert_eq!(limits.live_udp(), 0);
        drop(a);
        assert_eq!(limits.live_tcp(), 1);
        let _c = limits.try_tcp().unwrap();
        assert_eq!(limits.live_tcp(), 2);
    }

    #[test]
    fn udp_cap_enforced_at_max_and_released_on_drop() {
        let limits = limits(5, 1);
        let a = limits.try_udp().unwrap();
        assert_eq!(limits.live_udp(), 1);
        let err = limits.try_udp().unwrap_err();
        assert_eq!(err, LimitError::UdpCap { max: 1 });
        assert_eq!(err.to_string(), "UDP flow limit reached (1)");
        assert_eq!(limits.live_tcp(), 0);
        drop(a);
        assert_eq!(limits.live_udp(), 0);
        assert!(limits.try_udp().is_ok());
    }

    #[test]
    fn default_caps_reached_exactly() {
        let limits = RunLimits::new(LimitsConfig::default());
        let tcp: Vec<_> = (0..256).map(|_| limits.try_tcp().unwrap()).collect();
        assert_eq!(
            limits.try_tcp().unwrap_err().to_string(),
            "TCP connection limit reached (256)"
        );
        let udp: Vec<_> = (0..1024).map(|_| limits.try_udp().unwrap()).collect();
        assert!(limits.try_udp().is_err());
        assert_eq!((limits.live_tcp(), limits.live_udp()), (256, 1024));
        drop((tcp, udp));
        assert_eq!((limits.live_tcp(), limits.live_udp()), (0, 0));
    }

    #[test]
    fn clones_share_counters() {
        let limits = limits(1, 1);
        let other = limits.clone();
        let _permit = limits.try_tcp().unwrap();
        assert_eq!(other.live_tcp(), 1);
        assert!(other.try_tcp().is_err());
    }

    #[tokio::test]
    async fn permits_move_into_spawned_tasks() {
        let limits = limits(1, 1);
        let tcp = limits.try_tcp().unwrap();
        let udp = limits.try_udp().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            rx.await.unwrap();
            drop((tcp, udp));
        });
        assert_eq!((limits.live_tcp(), limits.live_udp()), (1, 1));
        tx.send(()).unwrap();
        task.await.unwrap();
        assert_eq!((limits.live_tcp(), limits.live_udp()), (0, 0));
    }
}
