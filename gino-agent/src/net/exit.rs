//! Per-run transparent exit: terminates the guest's TUN traffic in a user-space
//! TCP/IP stack, answers DNS at the gateway address and relays admitted flows to
//! host sockets.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::{Stream, StreamExt as _};
use nsplane::{PacketSink, PacketSource, PeerId};
use nsplane_dns::{FakePoolConfigError, Server, ServerConfig};
use nsplane_netstack::{
    Admission, NetStack, NetStackConfig, NetStackHandle, PendingFlow, PendingProtocol,
    TransparentConfig, UdpFlow,
};
use nsplane_tun::Tun;
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tokio::time;

use super::decision_log::log_decision;
use super::dns::{DNS_ADDR, GuestResolver};
use super::limits::{LimitError, LimitsConfig, RunLimits, TcpPermit, UdpPermit};
use super::rules::{Decision, DenyReason, Proto, RuleSet};
use super::tun::TunConfig;
use super::upstream::{self, RejectKind, UdpOutcome, UpstreamError};

/// Prefix length of the stack address (the guest's /24).
const STACK_PREFIX_LEN: u8 = 24;
/// Receive and send buffer of every stack TCP socket.
const TCP_BUFFER: usize = 128 * 1024;
/// UDP flows the stack holds at once.
const MAX_UDP_FLOWS: usize = 1024;
/// New flows held for an admission decision at once.
const MAX_PENDING: usize = 256;
/// Peer id handed to the stack's sink; the stack routes by address only.
const PEER: PeerId = PeerId::new(1);
/// Largest UDP datagram relayed from the host.
const MAX_DATAGRAM: usize = 65_535;

/// Settings of one run's exit.
#[derive(Debug, Clone)]
pub struct ExitConfig {
    /// Thread the run belongs to, for decision logs.
    pub thread_id: String,
    /// Allow rules, always-allowed endpoints included.
    pub rules: Arc<RuleSet>,
    /// Live connection and flow caps.
    pub limits: LimitsConfig,
    /// MTU of the guest TUN device.
    pub mtu: u16,
    /// How long a new flow may wait for its decision before the stack refuses it.
    pub admission_timeout: Duration,
    /// Host connect timeout; must be shorter than `admission_timeout`.
    pub connect_timeout: Duration,
    /// A UDP relay without traffic for this long is closed.
    pub udp_idle: Duration,
    /// Always-allowed TCP port on the gateway address forwarded to a host
    /// address (the LLM endpoint on host loopback).
    pub gateway: Option<GatewayForward>,
}

/// TCP to `gateway address:port` is relayed to `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayForward {
    /// Port on the gateway address.
    pub port: u16,
    /// Host address the flow is connected to.
    pub target: SocketAddr,
}

impl ExitConfig {
    /// Default timeouts and limits for `thread_id` and `rules`.
    pub fn new(thread_id: impl Into<String>, rules: Arc<RuleSet>) -> Self {
        Self {
            thread_id: thread_id.into(),
            rules,
            limits: LimitsConfig::default(),
            mtu: TunConfig::default().mtu,
            admission_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            udp_idle: Duration::from_mins(1),
            gateway: None,
        }
    }
}

/// The exit could not be started.
#[derive(Debug, thiserror::Error)]
pub enum ExitError {
    /// `connect_timeout` is not shorter than `admission_timeout`.
    #[error("connect timeout {connect:?} must be shorter than the admission timeout {admission:?}")]
    Timeouts {
        /// The configured connect timeout.
        connect: Duration,
        /// The configured admission timeout.
        admission: Duration,
    },
    /// Called outside a tokio runtime.
    #[error("the network exit needs a tokio runtime")]
    NoRuntime,
    /// Registering the TUN device with the runtime failed.
    #[error("adopt TUN device: {0}")]
    Tun(#[source] io::Error),
    /// The fake address pool could not be created.
    #[error("create fake address pool: {0}")]
    Pool(#[from] FakePoolConfigError),
}

/// A running exit; dropping it stops the packet pumps,
/// the stack, the DNS server, admission and every relay.
#[derive(Debug)]
pub struct Exit {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "held only to abort the tasks on drop")
    )]
    tasks: JoinSet<()>,
}

impl Exit {
    /// Starts the exit on an adopted guest TUN device.
    pub fn start(tun: Tun, cfg: ExitConfig) -> Result<Self, ExitError> {
        check(&cfg)?;
        let (source, sink) = tun.split().map_err(ExitError::Tun)?;
        Self::start_with(source, sink, cfg)
    }

    /// Starts the exit on the guest's packets from `source`, writing the stack's
    /// packets to `sink`.
    pub fn start_with(
        source: impl PacketSource,
        sink: impl PacketSink,
        cfg: ExitConfig,
    ) -> Result<Self, ExitError> {
        check(&cfg)?;
        let dns = Server::new(
            GuestResolver::new(Arc::clone(&cfg.rules))?,
            ServerConfig::default(),
        );
        let (stack, handle) = NetStack::new(stack_config(&cfg));
        let (stack_source, stack_sink) = stack.split();
        let shared = Arc::new(Shared {
            limits: RunLimits::new(cfg.limits),
            cfg,
            dns,
            tcp: Prepared::default(),
            udp: Prepared::default(),
        });

        let mut tasks = JoinSet::new();
        tasks.spawn(pump(source, stack_sink, "guest to stack"));
        tasks.spawn(pump(stack_source, sink, "stack to guest"));
        tasks.spawn(admission_loop(Arc::clone(&shared), handle.clone()));
        tasks.spawn(tcp_loop(Arc::clone(&shared), handle.clone()));
        tasks.spawn(udp_loop(shared, handle));
        Ok(Self { tasks })
    }

    /// Stops everything and waits until the tasks are gone.
    #[cfg(test)]
    pub async fn shutdown(mut self) {
        self.tasks.shutdown().await;
    }
}

fn check(cfg: &ExitConfig) -> Result<(), ExitError> {
    if cfg.connect_timeout >= cfg.admission_timeout {
        return Err(ExitError::Timeouts {
            connect: cfg.connect_timeout,
            admission: cfg.admission_timeout,
        });
    }
    tokio::runtime::Handle::try_current().map_err(|_| ExitError::NoRuntime)?;
    Ok(())
}

fn stack_config(cfg: &ExitConfig) -> NetStackConfig {
    NetStackConfig {
        tcp_rx_buffer: Some(TCP_BUFFER),
        tcp_tx_buffer: Some(TCP_BUFFER),
        max_udp_flows: MAX_UDP_FLOWS,
        transparent: Some(TransparentConfig {
            prefixes: Vec::new(),
            admission: Admission::Decide {
                timeout: cfg.admission_timeout,
                max_pending: MAX_PENDING,
            },
            max_connections: Some(cfg.limits.max_tcp),
            ..TransparentConfig::default()
        }),
        ..NetStackConfig::new(vec![(DNS_ADDR.ip(), STACK_PREFIX_LEN)], cfg.mtu)
    }
}

/// State shared by the exit's tasks.
struct Shared {
    cfg: ExitConfig,
    limits: RunLimits,
    dns: Server<GuestResolver>,
    tcp: Prepared<TcpStream, TcpPermit>,
    udp: Prepared<UdpSocket, UdpPermit>,
}

/// `(guest address, dialed address)` of a flow.
type FlowKey = (SocketAddr, SocketAddr);

/// Prepared host sockets by flow, each tagged with its insertion id.
type Entries<S, P> = HashMap<FlowKey, (u64, Upstream<S, P>)>;

/// A connected host socket and the limit slot it holds.
struct Upstream<S, P> {
    socket: S,
    permit: P,
}

/// Host sockets connected for admitted flows whose stack side has not arrived yet.
struct Prepared<S, P> {
    next_id: AtomicU64,
    entries: Mutex<Entries<S, P>>,
}

impl<S, P> Default for Prepared<S, P> {
    fn default() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<S, P> Prepared<S, P> {
    fn insert(&self, key: FlowKey, upstream: Upstream<S, P>) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(key, (id, upstream));
        id
    }

    fn take(&self, key: &FlowKey) -> Option<Upstream<S, P>> {
        self.lock().remove(key).map(|(_, upstream)| upstream)
    }

    /// Drops the entry for `key` if it is still the one inserted as `id`.
    fn expire(&self, key: &FlowKey, id: u64) {
        let mut entries = self.lock();
        if entries.get(key).is_some_and(|(entry, _)| *entry == id) {
            entries.remove(key);
        }
    }

    fn lock(&self) -> MutexGuard<'_, Entries<S, P>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

async fn pump(source: impl PacketSource, sink: impl PacketSink, direction: &'static str) {
    match nsplane::pump(source, sink, PEER).await {
        Ok(_) => tracing::debug!(direction, "exit packet pump ended"),
        Err(err) => tracing::warn!(direction, error = %err, "exit packet pump failed"),
    }
}

/// Runs `handle` for every item of `items`; the futures it returns run as tasks
/// that are aborted when this future is dropped.
async fn spawn_each<S, F, Fut>(mut items: S, mut handle: F)
where
    S: Stream + Unpin,
    F: FnMut(S::Item) -> Option<Fut>,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            item = items.next() => {
                let Some(item) = item else { break };
                if let Some(task) = handle(item) {
                    tasks.spawn(task);
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    while tasks.join_next().await.is_some() {}
}

async fn admission_loop(shared: Arc<Shared>, handle: NetStackHandle) {
    spawn_each(handle.incoming_pending(), |pending| {
        Some(admit(Arc::clone(&shared), pending))
    })
    .await;
}

async fn tcp_loop(shared: Arc<Shared>, handle: NetStackHandle) {
    spawn_each(handle.incoming_tcp(), |conn| {
        let local = conn.local_addr();
        if local == DNS_ADDR {
            let dns = shared.dns.clone();
            return Some(boxed(async move {
                if let Err(err) = dns.serve_tcp_connection(conn).await {
                    tracing::debug!(error = %err, "guest DNS TCP connection failed");
                }
            }));
        }
        let Some(Upstream { socket, permit }) = shared.tcp.take(&(conn.peer_addr(), local)) else {
            conn.abort();
            return None;
        };
        Some(boxed(async move {
            let outcome = upstream::relay_tcp(conn, socket).await;
            drop(permit);
            tracing::debug!(%local, ?outcome, "guest TCP relay ended");
        }))
    })
    .await;
}

async fn udp_loop(shared: Arc<Shared>, handle: NetStackHandle) {
    let idle = shared.cfg.udp_idle;
    spawn_each(handle.incoming_udp(), |flow| {
        let local = flow.local_addr();
        if local == DNS_ADDR {
            let dns = shared.dns.clone();
            return Some(boxed(async move { dns.serve_udp_flow(flow).await }));
        }
        let Upstream { socket, permit } = shared.udp.take(&(flow.peer_addr(), local))?;
        Some(boxed(async move {
            let outcome = relay_udp(flow, socket, idle).await;
            drop(permit);
            tracing::debug!(%local, ?outcome, "guest UDP relay ended");
        }))
    })
    .await;
}

fn boxed(
    task: impl Future<Output = ()> + Send + 'static,
) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(task)
}

/// Why an allowed flow was still refused.
#[derive(Debug, thiserror::Error)]
enum Refusal {
    #[error(transparent)]
    Limit(#[from] LimitError),
    #[error(transparent)]
    Upstream(#[from] UpstreamError),
}

impl Refusal {
    fn kind(&self) -> &'static str {
        match self {
            Self::Limit(_) => "limit",
            Self::Upstream(err) => match err.kind() {
                RejectKind::Reset => "reset",
                RejectKind::Unreachable => "unreachable",
            },
        }
    }
}

/// Decides one held flow: policy, limits, host address and host connect, then
/// accepts it with the host socket ready, or rejects it.
async fn admit(shared: Arc<Shared>, pending: PendingFlow) {
    let cfg = &shared.cfg;
    let proto = match pending.protocol() {
        PendingProtocol::Tcp => Proto::Tcp,
        PendingProtocol::Udp => Proto::Udp,
    };
    let dst = pending.local_addr();
    let key = (pending.peer_addr(), dst);
    let deny = Decision::Deny {
        reason: DenyReason::NoMatch,
    };

    if dst.ip() == DNS_ADDR.ip() {
        if dst.port() == DNS_ADDR.port() {
            pending.accept();
            return;
        }
        let forward = cfg
            .gateway
            .filter(|gw| proto == Proto::Tcp && gw.port == dst.port());
        let Some(forward) = forward else {
            log_decision(&cfg.thread_id, proto, None, dst.ip(), dst.port(), &deny);
            pending.reject();
            return;
        };
        let always = Decision::Allow { rule_index: None };
        log_decision(&cfg.thread_id, proto, None, dst.ip(), dst.port(), &always);
        let prepared = prepare_tcp(&shared, None, dst, key, Route::Gateway(forward.target)).await;
        settle(&shared, pending, proto, None, dst, key, prepared).await;
        return;
    }
    let name = if GuestResolver::is_fake(dst.ip()) {
        let Some(name) = shared.dns.resolver().lookup(dst.ip()) else {
            log_decision(&cfg.thread_id, proto, None, dst.ip(), dst.port(), &deny);
            pending.reject();
            return;
        };
        Some(name)
    } else {
        None
    };
    let decision = cfg
        .rules
        .decide(name.as_deref(), dst.ip(), dst.port(), proto);
    log_decision(
        &cfg.thread_id,
        proto,
        name.as_deref(),
        dst.ip(),
        dst.port(),
        &decision,
    );
    let route = match decision {
        Decision::Deny { .. } => {
            pending.reject();
            return;
        }
        Decision::Allow { rule_index: None } => Route::AlwaysAllowed,
        Decision::Allow {
            rule_index: Some(_),
        } => Route::Checked,
    };

    let prepared = match proto {
        Proto::Tcp => prepare_tcp(&shared, name.as_deref(), dst, key, route).await,
        Proto::Udp => prepare_udp(&shared, name.as_deref(), dst, key).await,
    };
    settle(&shared, pending, proto, name.as_deref(), dst, key, prepared).await;
}

/// Accepts `pending` when its host socket is ready, or logs the refusal and
/// rejects it.
async fn settle(
    shared: &Shared,
    pending: PendingFlow,
    proto: Proto,
    name: Option<&str>,
    dst: SocketAddr,
    key: FlowKey,
    prepared: Result<u64, Refusal>,
) {
    let cfg = &shared.cfg;
    match prepared {
        Ok(id) => {
            pending.accept();
            // The stack side arrives within the handshake; drop the host socket
            // if it never does.
            time::sleep(cfg.admission_timeout).await;
            match proto {
                Proto::Tcp => shared.tcp.expire(&key, id),
                Proto::Udp => shared.udp.expire(&key, id),
            }
        }
        Err(err) => {
            tracing::warn!(
                target: "gino_agent::net",
                thread_id = cfg.thread_id,
                proto = proto.as_str(),
                target_name = name.unwrap_or("-"),
                target_ip = %dst.ip(),
                port = dst.port(),
                decision = "refused",
                reject_kind = err.kind(),
                reason = %err,
                "network decision"
            );
            pending.reject();
        }
    }
}

/// How the host address of an allowed flow is found.
#[derive(Debug, Clone, Copy)]
enum Route {
    /// Allowed by a rule: forbidden addresses need a covering `cidr` rule.
    Checked,
    /// An always-allowed endpoint: private addresses are fine, local ones not.
    AlwaysAllowed,
    /// The gateway forward: always this host address.
    Gateway(SocketAddr),
}

/// The host address for a flow to `dst`: the resolved `name`, or the literal
/// destination when there is no name.
async fn host_addr(
    rules: &RuleSet,
    name: Option<&str>,
    dst: SocketAddr,
    proto: Proto,
    route: Route,
) -> Result<SocketAddr, UpstreamError> {
    match (route, name) {
        (Route::Gateway(target), _) => Ok(target),
        (Route::AlwaysAllowed, Some(name)) => {
            upstream::resolve_always_allowed(name, dst.port()).await
        }
        (Route::AlwaysAllowed, None) => upstream::check_always_allowed(dst.ip()).map(|()| dst),
        (Route::Checked, Some(name)) => upstream::resolve(name, dst.port(), proto, rules).await,
        (Route::Checked, None) => {
            upstream::check_address(dst.ip(), dst.port(), proto, rules).map(|()| dst)
        }
    }
}

async fn prepare_tcp(
    shared: &Shared,
    name: Option<&str>,
    dst: SocketAddr,
    key: FlowKey,
    route: Route,
) -> Result<u64, Refusal> {
    let permit = shared.limits.try_tcp()?;
    let addr = host_addr(&shared.cfg.rules, name, dst, Proto::Tcp, route).await?;
    let socket = upstream::connect_tcp(addr, shared.cfg.connect_timeout).await?;
    Ok(shared.tcp.insert(key, Upstream { socket, permit }))
}

async fn prepare_udp(
    shared: &Shared,
    name: Option<&str>,
    dst: SocketAddr,
    key: FlowKey,
) -> Result<u64, Refusal> {
    let permit = shared.limits.try_udp()?;
    let addr = host_addr(&shared.cfg.rules, name, dst, Proto::Udp, Route::Checked).await?;
    let socket = upstream::connect_udp(addr).await?;
    Ok(shared.udp.insert(key, Upstream { socket, permit }))
}

/// Relays datagrams between a guest flow and its connected host socket until
/// either side fails or nothing moves for `idle`.
async fn relay_udp(mut flow: UdpFlow, host: UdpSocket, idle: Duration) -> UdpOutcome {
    let reply = flow.reply_handle();
    let mut buf = vec![0; MAX_DATAGRAM];
    loop {
        tokio::select! {
            datagram = flow.recv() => {
                let Some(datagram) = datagram else {
                    return UdpOutcome::GuestClosed;
                };
                if let Err(err) = host.send(&datagram).await {
                    tracing::debug!(error = %err, "host side of UDP relay failed");
                    return UdpOutcome::HostError(RejectKind::Unreachable);
                }
            }
            received = host.recv(&mut buf) => match received {
                Ok(n) => {
                    if let Err(err) = reply.send(&buf[..n]).await {
                        tracing::debug!(error = %err, "guest side of UDP relay failed");
                        return UdpOutcome::GuestClosed;
                    }
                }
                Err(err) => {
                    tracing::debug!(error = %err, "host side of UDP relay failed");
                    return UdpOutcome::HostError(RejectKind::Unreachable);
                }
            },
            () = time::sleep(idle) => return UdpOutcome::IdleTimeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use nsplane_netstack::{NetStackHandle, TcpConnection};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use super::*;
    use crate::net::rules::Rule;

    const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const MTU: u16 = 1500;
    const WAIT: Duration = Duration::from_secs(5);
    /// How long a negative case waits for something that must not happen.
    const QUIET: Duration = Duration::from_millis(300);

    /// An exit wired to an in-memory guest stack, plus local echo servers.
    struct Harness {
        exit: Option<Exit>,
        guest: NetStackHandle,
        /// One message per ICMP port unreachable sent to the guest.
        icmp: mpsc::UnboundedReceiver<()>,
        tcp_port: u16,
        udp_port: u16,
        /// One message per host-side TCP connection that ended.
        tcp_closed: mpsc::UnboundedReceiver<()>,
        _tasks: JoinSet<()>,
    }

    async fn harness(limits: LimitsConfig) -> Harness {
        harness_with(|tcp_port, udp_port, cfg| {
            let rules: Vec<Rule> = [
                format!(r#"{{"host":"localhost","ports":[{tcp_port}]}}"#),
                format!(r#"{{"cidr":"127.0.0.1/32","ports":[{tcp_port}]}}"#),
                format!(r#"{{"host":"localhost","ports":[{udp_port}],"proto":"udp"}}"#),
                format!(r#"{{"cidr":"127.0.0.1/32","ports":[{udp_port}],"proto":"udp"}}"#),
            ]
            .iter()
            .map(|r| serde_json::from_str(r).unwrap())
            .collect();
            cfg.rules = Arc::new(RuleSet::compile(&rules, &[]).unwrap());
            cfg.limits = limits;
        })
        .await
    }

    /// A harness whose exit config (empty rules by default) is adjusted by
    /// `configure` with the echo servers' TCP and UDP ports.
    async fn harness_with(configure: impl FnOnce(u16, u16, &mut ExitConfig)) -> Harness {
        let mut tasks = JoinSet::new();
        let (tcp_port, tcp_closed) = tcp_echo(&mut tasks).await;
        let udp_port = udp_echo(&mut tasks).await;
        let mut cfg = ExitConfig::new("thread-1", Arc::new(RuleSet::compile(&[], &[]).unwrap()));
        configure(tcp_port, udp_port, &mut cfg);
        cfg.mtu = MTU;

        let (guest_stack, guest) = NetStack::new(NetStackConfig::new(
            vec![(IpAddr::V4(GUEST), STACK_PREFIX_LEN)],
            MTU,
        ));
        let (guest_source, guest_sink) = guest_stack.split();
        let (exit_sink, mut exit_out) = nsplane::pipe(1024, MTU);
        let exit = Exit::start_with(guest_source, exit_sink, cfg).unwrap();
        let (icmp_tx, icmp) = mpsc::unbounded_channel();
        tasks.spawn(async move {
            while let Ok(packet) = exit_out.recv().await {
                if is_port_unreachable(packet.as_packet()) {
                    let _ = icmp_tx.send(());
                }
                if guest_sink.send(packet, PEER).await.is_err() {
                    break;
                }
            }
        });
        Harness {
            exit: Some(exit),
            guest,
            icmp,
            tcp_port,
            udp_port,
            tcp_closed,
            _tasks: tasks,
        }
    }

    fn is_port_unreachable(packet: &[u8]) -> bool {
        let Some(&first) = packet.first() else {
            return false;
        };
        let ihl = usize::from(first & 0x0f) * 4;
        first >> 4 == 4
            && packet.get(9) == Some(&1)
            && packet.get(ihl..ihl + 2) == Some(&[3, 3][..])
    }

    async fn tcp_echo(tasks: &mut JoinSet<()>) -> (u16, mpsc::UnboundedReceiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (closed_tx, closed) = mpsc::unbounded_channel();
        tasks.spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let closed_tx = closed_tx.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = closed_tx.send(());
                });
            }
        });
        (port, closed)
    }

    async fn udp_echo(tasks: &mut JoinSet<()>) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tasks.spawn(async move {
            let mut buf = vec![0; MAX_DATAGRAM];
            loop {
                let (n, from) = socket.recv_from(&mut buf).await.unwrap();
                socket.send_to(&buf[..n], from).await.unwrap();
            }
        });
        port
    }

    /// A wire-format A query for `name`.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut msg = vec![0x4a, 0x21, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(u8::try_from(label.len()).unwrap());
            msg.extend_from_slice(label.as_bytes());
        }
        msg.extend_from_slice(&[0, 0, 1, 0, 1]);
        msg
    }

    /// Offset just past the (possibly compressed) name at `at`.
    fn skip_name(msg: &[u8], mut at: usize) -> usize {
        loop {
            let len = msg[at];
            if len & 0xc0 == 0xc0 {
                return at + 2;
            }
            at += 1 + usize::from(len);
            if len == 0 {
                return at;
            }
        }
    }

    /// Sends an A query for `name` to the exit's DNS address; the RCODE and the
    /// first A record of the answer.
    async fn resolve(guest: &NetStackHandle, name: &str) -> (u8, Option<Ipv4Addr>) {
        let mut socket = guest.connect_udp(DNS_ADDR).await.unwrap();
        socket.send(&dns_query(name)).await.unwrap();
        let (msg, from) = time::timeout(WAIT, socket.recv_from())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, DNS_ADDR);
        assert_eq!(msg[..2], [0x4a, 0x21]);
        let rcode = msg[3] & 0x0f;
        let answers = u16::from_be_bytes([msg[6], msg[7]]);
        let mut at = skip_name(&msg, 12) + 4;
        for _ in 0..answers {
            at = skip_name(&msg, at);
            let ty = u16::from_be_bytes([msg[at], msg[at + 1]]);
            let len = usize::from(u16::from_be_bytes([msg[at + 8], msg[at + 9]]));
            at += 10;
            if ty == 1 && len == 4 {
                let a = Ipv4Addr::new(msg[at], msg[at + 1], msg[at + 2], msg[at + 3]);
                return (rcode, Some(a));
            }
            at += len;
        }
        (rcode, None)
    }

    async fn fake_localhost(guest: &NetStackHandle) -> IpAddr {
        let (rcode, addr) = resolve(guest, "localhost").await;
        assert_eq!(rcode, 0);
        let addr = IpAddr::V4(addr.unwrap());
        assert!(GuestResolver::is_fake(addr), "{addr}");
        addr
    }

    async fn connect(guest: &NetStackHandle, dst: SocketAddr) -> io::Result<TcpConnection> {
        time::timeout(WAIT, guest.connect_tcp(dst)).await.unwrap()
    }

    async fn echo(conn: &mut TcpConnection, payload: &[u8]) {
        conn.write_all(payload).await.unwrap();
        let mut buf = vec![0; payload.len()];
        time::timeout(WAIT, conn.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buf, payload);
    }

    fn assert_refused(result: io::Result<TcpConnection>) {
        match result {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused, "{err}"),
            Ok(conn) => panic!("connection to {} was not refused", conn.local_addr()),
        }
    }

    #[tokio::test]
    async fn allowed_name_relays_tcp() {
        let h = harness(LimitsConfig::default()).await;
        let fake = fake_localhost(&h.guest).await;
        let mut conn = connect(&h.guest, SocketAddr::new(fake, h.tcp_port))
            .await
            .unwrap();
        echo(&mut conn, b"hello through the exit").await;
    }

    #[tokio::test]
    async fn literal_ip_inside_cidr_relays_tcp() {
        let h = harness(LimitsConfig::default()).await;
        let dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), h.tcp_port);
        let mut conn = connect(&h.guest, dst).await.unwrap();
        echo(&mut conn, b"literal").await;
    }

    #[tokio::test]
    async fn disallowed_name_is_nxdomain() {
        let h = harness(LimitsConfig::default()).await;
        assert_eq!(resolve(&h.guest, "example.com").await, (3, None));
    }

    #[tokio::test]
    async fn allowed_name_wrong_port_is_refused() {
        let h = harness(LimitsConfig::default()).await;
        let fake = fake_localhost(&h.guest).await;
        let port = if h.tcp_port == 1 { 2 } else { 1 };
        assert_refused(connect(&h.guest, SocketAddr::new(fake, port)).await);
    }

    #[tokio::test]
    async fn literal_ip_outside_cidr_is_refused() {
        let h = harness(LimitsConfig::default()).await;
        let dst = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), h.tcp_port);
        assert_refused(connect(&h.guest, dst).await);
    }

    #[tokio::test]
    async fn unbound_fake_address_and_other_stack_ports_are_refused() {
        let h = harness(LimitsConfig::default()).await;
        let unbound = SocketAddr::new(Ipv4Addr::new(198, 19, 255, 254).into(), h.tcp_port);
        assert_refused(connect(&h.guest, unbound).await);
        let stack = SocketAddr::new(DNS_ADDR.ip(), 80);
        assert_refused(connect(&h.guest, stack).await);
    }

    #[tokio::test]
    async fn dns_over_tcp_is_answered() {
        let h = harness(LimitsConfig::default()).await;
        let mut conn = connect(&h.guest, DNS_ADDR).await.unwrap();
        let query = dns_query("localhost");
        let len = u16::try_from(query.len()).unwrap();
        conn.write_all(&len.to_be_bytes()).await.unwrap();
        conn.write_all(&query).await.unwrap();
        let mut len = [0; 2];
        time::timeout(WAIT, conn.read_exact(&mut len))
            .await
            .unwrap()
            .unwrap();
        let mut msg = vec![0; usize::from(u16::from_be_bytes(len))];
        conn.read_exact(&mut msg).await.unwrap();
        assert_eq!(msg[..2], [0x4a, 0x21]);
        assert_eq!(msg[3] & 0x0f, 0);
        assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 1);
    }

    #[tokio::test]
    async fn allowed_udp_is_relayed() {
        let h = harness(LimitsConfig::default()).await;
        let fake = fake_localhost(&h.guest).await;
        let dst = SocketAddr::new(fake, h.udp_port);
        let mut socket = h.guest.connect_udp(dst).await.unwrap();
        for payload in [&b"first"[..], b"second"] {
            socket.send(payload).await.unwrap();
            let (reply, from) = time::timeout(WAIT, socket.recv_from())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(from, dst);
            assert_eq!(&reply[..], payload);
        }
    }

    #[tokio::test]
    async fn denied_udp_gets_port_unreachable() {
        let mut h = harness(LimitsConfig::default()).await;
        let fake = fake_localhost(&h.guest).await;
        let port = if h.udp_port == 1 { 2 } else { 1 };
        let mut socket = h
            .guest
            .connect_udp(SocketAddr::new(fake, port))
            .await
            .unwrap();
        socket.send(b"denied").await.unwrap();
        time::timeout(WAIT, h.icmp.recv()).await.unwrap().unwrap();
        assert!(time::timeout(QUIET, socket.recv_from()).await.is_err());
    }

    #[tokio::test]
    async fn connection_cap_refuses_the_next_connection() {
        let h = harness(LimitsConfig {
            max_tcp: 2,
            max_udp: 16,
        })
        .await;
        let fake = fake_localhost(&h.guest).await;
        let dst = SocketAddr::new(fake, h.tcp_port);
        let mut first = connect(&h.guest, dst).await.unwrap();
        let mut second = connect(&h.guest, dst).await.unwrap();
        echo(&mut first, b"one").await;
        echo(&mut second, b"two").await;
        assert_refused(connect(&h.guest, dst).await);
    }

    #[tokio::test]
    async fn dropping_the_exit_ends_relays() {
        let mut h = harness(LimitsConfig::default()).await;
        let fake = fake_localhost(&h.guest).await;
        let mut conn = connect(&h.guest, SocketAddr::new(fake, h.tcp_port))
            .await
            .unwrap();
        echo(&mut conn, b"before drop").await;
        drop(h.exit.take());
        // The host side sees its connection closed ...
        time::timeout(WAIT, h.tcp_closed.recv())
            .await
            .unwrap()
            .unwrap();
        // ... and the guest side reads end of stream or an error.
        let mut buf = [0; 16];
        if let Ok(n) = time::timeout(WAIT, conn.read(&mut buf)).await.unwrap() {
            assert_eq!(n, 0);
        }
    }

    #[tokio::test]
    async fn shutdown_stops_the_exit() {
        let mut h = harness(LimitsConfig::default()).await;
        let fake = fake_localhost(&h.guest).await;
        let mut conn = connect(&h.guest, SocketAddr::new(fake, h.tcp_port))
            .await
            .unwrap();
        echo(&mut conn, b"before shutdown").await;
        time::timeout(WAIT, h.exit.take().unwrap().shutdown())
            .await
            .unwrap();
        time::timeout(WAIT, h.tcp_closed.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn gateway_forward_reaches_host_loopback_only_on_its_port() {
        let h = harness_with(|tcp_port, _, cfg| {
            cfg.gateway = Some(GatewayForward {
                port: tcp_port,
                target: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), tcp_port),
            });
        })
        .await;
        let gateway = DNS_ADDR.ip();
        let mut conn = connect(&h.guest, SocketAddr::new(gateway, h.tcp_port))
            .await
            .unwrap();
        echo(&mut conn, b"to the llm").await;

        let other = if h.tcp_port == 1 { 2 } else { 1 };
        assert_refused(connect(&h.guest, SocketAddr::new(gateway, other)).await);
        let loopback = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), h.tcp_port);
        assert_refused(connect(&h.guest, loopback).await);
        assert_eq!(resolve(&h.guest, "example.com").await, (3, None));
    }

    /// A non-loopback address of this machine (routing lookup only, no traffic).
    fn non_loopback_ip() -> Option<IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("192.0.2.1:9").ok()?;
        let ip = socket.local_addr().ok()?.ip();
        upstream::is_forbidden(ip).then_some(ip)
    }

    #[tokio::test]
    async fn always_allowed_private_address_is_relayed() {
        let Some(ip) = non_loopback_ip() else {
            eprintln!("skipping: no private non-loopback address");
            return;
        };
        let listener = TcpListener::bind((ip, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let h = harness_with(|_, _, cfg| {
            let rules = RuleSet::compile(&[], &[]).unwrap();
            cfg.rules = Arc::new(rules.with_always_addr(addr).unwrap());
        })
        .await;
        let mut conn = connect(&h.guest, addr).await.unwrap();
        echo(&mut conn, b"private llm").await;
        let other = SocketAddr::new(ip, if addr.port() == 1 { 2 } else { 1 });
        assert_refused(connect(&h.guest, other).await);
    }

    #[tokio::test]
    async fn connect_timeout_must_be_below_admission_timeout() {
        let rules = Arc::new(RuleSet::compile(&[], &[]).unwrap());
        let mut cfg = ExitConfig::new("thread-1", rules);
        cfg.connect_timeout = cfg.admission_timeout;
        let (sink, source) = nsplane::pipe(4, MTU);
        assert!(matches!(
            Exit::start_with(source, sink, cfg),
            Err(ExitError::Timeouts { .. })
        ));
    }
}
