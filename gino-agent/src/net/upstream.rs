//! Real-address resolution, host sockets and guest/host relays.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time;

use super::rules::{Proto, RuleSet};

/// Per-direction copy buffer of the TCP relay.
const TCP_BUF: usize = 16 * 1024;

/// IPv4 networks refused as real destinations unless a `cidr` rule covers them.
const FORBIDDEN_V4: &[([u8; 4], u32)] = &[
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

/// IPv6 networks refused as real destinations unless a `cidr` rule covers them.
const FORBIDDEN_V6: &[(Ipv6Addr, u32)] = &[
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
];

/// How the guest flow is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// Reset the connection (TCP RST).
    Reset,
    /// Report the destination unreachable.
    Unreachable,
}

/// Failure to resolve or reach a real destination.
#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub struct UpstreamError {
    kind: RejectKind,
    reason: String,
    #[source]
    source: Option<io::Error>,
}

impl UpstreamError {
    fn new(kind: RejectKind, reason: String, source: Option<io::Error>) -> Self {
        Self {
            kind,
            reason,
            source,
        }
    }

    /// How the guest flow should be refused.
    pub fn kind(&self) -> RejectKind {
        self.kind
    }
}

/// True for private, loopback, link-local, documentation, benchmarking,
/// multicast and reserved addresses. IPv4-mapped, IPv4-compatible, NAT64
/// (`64:ff9b::/96`) and 6to4 (`2002::/16`) IPv6 addresses are checked as
/// their embedded IPv4 address.
pub fn is_forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_forbidden(v4),
        // `to_ipv4` also maps `::` and `::1`, which land in 0.0.0.0/8.
        IpAddr::V6(v6) => v6
            .to_ipv4()
            .or_else(|| embedded_v4(v6))
            .map_or_else(|| v6_forbidden(v6), v4_forbidden),
    }
}

/// The IPv4 address carried by a NAT64 well-known-prefix or 6to4 address.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let o = ip.octets();
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]))
    } else if s[0] == 0x2002 {
        Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]))
    } else {
        None
    }
}

fn v4_forbidden(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    FORBIDDEN_V4.iter().any(|&(net, prefix)| {
        let mask = u32::MAX << (32 - prefix);
        ip & mask == u32::from_be_bytes(net)
    })
}

fn v6_forbidden(ip: Ipv6Addr) -> bool {
    let ip = u128::from(ip);
    FORBIDDEN_V6.iter().any(|&(net, prefix)| {
        let mask = u128::MAX << (128 - prefix);
        ip & mask == u128::from(net)
    })
}

/// Accepts `ip` unless it is forbidden and no `cidr` rule covers it for
/// `port` and `proto`.
pub fn check_address(
    ip: IpAddr,
    port: u16,
    proto: Proto,
    rules: &RuleSet,
) -> Result<(), UpstreamError> {
    if !is_forbidden(ip) || rules.cidr_covers(ip, port, proto).is_some() {
        return Ok(());
    }
    Err(UpstreamError::new(
        RejectKind::Reset,
        format!("{ip} is a forbidden destination address"),
        None,
    ))
}

/// Resolves `name` and returns the first address, in resolver order, that
/// passes [`check_address`].
pub async fn resolve(
    name: &str,
    port: u16,
    proto: Proto,
    rules: &RuleSet,
) -> Result<SocketAddr, UpstreamError> {
    resolve_with(name, port, |ip| {
        check_address(ip, port, proto, rules).is_ok()
    })
    .await
}

/// True for loopback and unspecified addresses (also IPv4-mapped), which name
/// the host itself.
pub fn is_local(ip: IpAddr) -> bool {
    let v4_local = |v4: Ipv4Addr| v4.is_loopback() || v4.octets()[0] == 0;
    match ip {
        IpAddr::V4(v4) => v4_local(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(v4_local)
        }
    }
}

/// True for link-local addresses (`169.254.0.0/16`, `fe80::/10`, also
/// IPv4-mapped), which include cloud metadata endpoints.
pub fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.is_unicast_link_local(), |v4| v4.is_link_local()),
    }
}

/// Accepts `ip` for an always-allowed endpoint, which may live on a private
/// network: addresses naming the host itself ([`is_local`]) and link-local
/// addresses are refused.
pub fn check_always_allowed(ip: IpAddr) -> Result<(), UpstreamError> {
    if is_local(ip) || is_link_local(ip) {
        return Err(UpstreamError::new(
            RejectKind::Reset,
            format!("{ip} is a forbidden destination address"),
            None,
        ));
    }
    Ok(())
}

/// Resolves the always-allowed endpoint `name` and returns the first address
/// that passes [`check_always_allowed`].
pub async fn resolve_always_allowed(name: &str, port: u16) -> Result<SocketAddr, UpstreamError> {
    resolve_with(name, port, |ip| check_always_allowed(ip).is_ok()).await
}

async fn resolve_with(
    name: &str,
    port: u16,
    accept: impl Fn(IpAddr) -> bool,
) -> Result<SocketAddr, UpstreamError> {
    let addrs = tokio::net::lookup_host((name, port)).await.map_err(|err| {
        UpstreamError::new(
            RejectKind::Unreachable,
            format!("cannot resolve {name}"),
            Some(err),
        )
    })?;
    let mut any = false;
    for addr in addrs {
        any = true;
        if accept(addr.ip()) {
            return Ok(addr);
        }
    }
    if any {
        Err(UpstreamError::new(
            RejectKind::Reset,
            format!("every address of {name} is forbidden"),
            None,
        ))
    } else {
        Err(UpstreamError::new(
            RejectKind::Unreachable,
            format!("{name} has no addresses"),
            None,
        ))
    }
}

/// Opens a TCP connection to `addr` within `timeout`, with `TCP_NODELAY` set.
pub async fn connect_tcp(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, UpstreamError> {
    let stream = time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| connect_timeout(addr, timeout))?
        .map_err(|err| connect_error(addr, err))?;
    stream
        .set_nodelay(true)
        .map_err(|err| connect_error(addr, err))?;
    Ok(stream)
}

fn connect_timeout(addr: SocketAddr, timeout: Duration) -> UpstreamError {
    UpstreamError::new(
        RejectKind::Unreachable,
        format!("connect to {addr} timed out after {timeout:?}"),
        None,
    )
}

fn connect_error(addr: SocketAddr, err: io::Error) -> UpstreamError {
    // A refusal is mirrored as a reset; everything else (unreachable host or
    // network, other io errors) as unreachable.
    let kind = if err.kind() == io::ErrorKind::ConnectionRefused {
        RejectKind::Reset
    } else {
        RejectKind::Unreachable
    };
    UpstreamError::new(kind, format!("connect to {addr} failed"), Some(err))
}

/// Binds an ephemeral UDP socket of `addr`'s family and connects it to `addr`.
pub async fn connect_udp(addr: SocketAddr) -> Result<UdpSocket, UpstreamError> {
    let local: IpAddr = match addr {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = UdpSocket::bind(SocketAddr::new(local, 0))
        .await
        .map_err(|err| connect_error(addr, err))?;
    socket
        .connect(addr)
        .await
        .map_err(|err| connect_error(addr, err))?;
    Ok(socket)
}

/// How a TCP relay ended.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Both directions reached EOF.
    Closed {
        /// Bytes copied guest → host.
        to_host: u64,
        /// Bytes copied host → guest.
        to_guest: u64,
    },
    /// The host socket failed (reset, abort, broken pipe or other error); the
    /// caller should reset the guest connection.
    HostReset,
    /// The guest side failed; the host socket was aborted with RST.
    GuestReset,
}

#[derive(Debug, Clone, Copy)]
enum Side {
    Guest,
    Host,
}

/// Copies bytes both ways until both directions end. EOF on one side shuts
/// down the write half of the other while the reverse direction keeps going.
pub async fn relay_tcp<G>(guest: G, mut host: TcpStream) -> RelayOutcome
where
    G: AsyncRead + AsyncWrite + Unpin,
{
    let (mut guest_r, mut guest_w) = tokio::io::split(guest);
    let result = {
        let (mut host_r, mut host_w) = host.split();
        tokio::try_join!(
            pump(&mut guest_r, &mut host_w, Side::Guest, Side::Host),
            pump(&mut host_r, &mut guest_w, Side::Host, Side::Guest),
        )
    };
    match result {
        Ok((to_host, to_guest)) => RelayOutcome::Closed { to_host, to_guest },
        Err((Side::Host, err)) => {
            tracing::debug!(error = %err, "host side of relay failed");
            RelayOutcome::HostReset
        }
        Err((Side::Guest, err)) => {
            tracing::debug!(error = %err, "guest side of relay failed");
            // Zero linger turns the close below into an RST.
            if let Err(err) = host.set_zero_linger() {
                tracing::debug!(error = %err, "cannot set zero linger on host socket");
            }
            drop(host);
            RelayOutcome::GuestReset
        }
    }
}

/// Copies `reader` into `writer` until EOF, then shuts `writer` down. Errors
/// carry the side they happened on.
async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    from: Side,
    to: Side,
) -> Result<u64, (Side, io::Error)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; TCP_BUF];
    let mut total = 0;
    loop {
        let n = reader.read(&mut buf).await.map_err(|err| (from, err))?;
        if n == 0 {
            writer.shutdown().await.map_err(|err| (to, err))?;
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await.map_err(|err| (to, err))?;
        writer.flush().await.map_err(|err| (to, err))?;
        total += n as u64;
    }
}

/// How a UDP relay ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpOutcome {
    /// No datagram in either direction for the idle period.
    IdleTimeout,
    /// The guest channel was closed in either direction.
    GuestClosed,
    /// The host socket failed (an ICMP port unreachable surfaces here).
    HostError(RejectKind),
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use tokio::net::TcpListener;

    use super::super::rules::{Ports, Rule};
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    fn cidr_rules(cidr: &str, port: u16, proto: Proto) -> RuleSet {
        let rule = Rule {
            host: None,
            cidr: Some(cidr.to_owned()),
            ports: Ports::List(vec![port]),
            proto,
        };
        RuleSet::compile(&[rule], &[]).unwrap()
    }

    fn no_rules() -> RuleSet {
        RuleSet::compile(&[], &[]).unwrap()
    }

    #[test]
    fn forbidden_table() {
        let forbidden = [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.0",
            "10.255.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.0",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ];
        for ip in forbidden {
            assert!(is_forbidden(v4(ip)), "{ip}");
        }
        let allowed = [
            "1.0.0.0",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.0",
            "192.0.3.0",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
            "223.255.255.255",
            "1.1.1.1",
            "8.8.8.8",
        ];
        for ip in allowed {
            assert!(!is_forbidden(v4(ip)), "{ip}");
        }
        let forbidden6 = [
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fdff::1",
            "ff02::1",
            "2001:db8::1",
            "64:ff9b:1::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::10.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:a00:1::1",
            "2002:c0a8:101::",
        ];
        for ip in forbidden6 {
            assert!(is_forbidden(v6(ip)), "{ip}");
        }
        let allowed6 = [
            "2606:4700::1111",
            "fec0::1",
            "fbff::1",
            "2001:db9::1",
            "64:ff9b:2::1",
            "64:ff9b::1.1.1.1",
            "2002:101:101::1",
            "::ffff:1.1.1.1",
        ];
        for ip in allowed6 {
            assert!(!is_forbidden(v6(ip)), "{ip}");
        }
    }

    #[test]
    fn check_address_refuses_forbidden_unless_cidr_covers() {
        let ip = v4("10.1.2.3");
        let err = check_address(ip, 443, Proto::Tcp, &no_rules()).unwrap_err();
        assert_eq!(err.kind(), RejectKind::Reset);
        assert!(err.to_string().contains("10.1.2.3"), "{err}");

        let rules = cidr_rules("10.0.0.0/8", 443, Proto::Tcp);
        assert!(check_address(ip, 443, Proto::Tcp, &rules).is_ok());
        assert!(check_address(v6("::ffff:10.1.2.3"), 443, Proto::Tcp, &rules).is_ok());
        let other_port = check_address(ip, 80, Proto::Tcp, &rules).unwrap_err();
        assert_eq!(other_port.kind(), RejectKind::Reset);
        let other_proto = check_address(ip, 443, Proto::Udp, &rules).unwrap_err();
        assert_eq!(other_proto.kind(), RejectKind::Reset);

        assert!(check_address(v4("1.1.1.1"), 80, Proto::Udp, &no_rules()).is_ok());
    }

    #[tokio::test]
    async fn resolve_localhost_needs_cidr_rule() {
        let err = resolve("localhost", 8080, Proto::Tcp, &no_rules())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), RejectKind::Reset);

        let rules = cidr_rules("127.0.0.0/8", 8080, Proto::Tcp);
        let addr = resolve("localhost", 8080, Proto::Tcp, &rules)
            .await
            .unwrap();
        assert_eq!(addr, "127.0.0.1:8080".parse().unwrap());

        let err = resolve("localhost", 8081, Proto::Tcp, &rules)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), RejectKind::Reset);
    }

    #[test]
    fn always_allowed_refuses_only_local_and_link_local_addresses() {
        for ip in [
            "10.1.2.3",
            "172.17.0.1",
            "192.168.1.1",
            "fd00::1",
            "1.1.1.1",
        ] {
            let ip = ip.parse().unwrap();
            assert!(check_always_allowed(ip).is_ok(), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "169.254.169.254",
            "169.254.0.1",
            "fe80::1",
            "febf::1",
            "::ffff:169.254.169.254",
        ] {
            let ip = ip.parse().unwrap();
            let err = check_always_allowed(ip).unwrap_err();
            assert_eq!(err.kind(), RejectKind::Reset, "{ip}");
        }
    }

    #[tokio::test]
    async fn resolve_always_allowed_refuses_loopback() {
        let err = resolve_always_allowed("localhost", 8080).await.unwrap_err();
        assert_eq!(err.kind(), RejectKind::Reset);
    }

    #[tokio::test]
    async fn resolve_always_allowed_refuses_link_local() {
        for name in ["169.254.169.254", "fe80::1"] {
            let err = resolve_always_allowed(name, 80).await.unwrap_err();
            assert_eq!(err.kind(), RejectKind::Reset, "{name}");
        }
    }

    #[tokio::test]
    async fn resolve_failure_is_unreachable() {
        let err = resolve("no-such-host.invalid", 80, Proto::Tcp, &no_rules())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), RejectKind::Unreachable);
        assert!(err.source().is_some());
    }

    async fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn connect_tcp_refused_is_reset() {
        let addr = closed_port().await;
        let err = connect_tcp(addr, Duration::from_secs(1)).await.unwrap_err();
        assert_eq!(err.kind(), RejectKind::Reset);
        assert_eq!(
            err.source()
                .and_then(|e| e.downcast_ref::<io::Error>())
                .map(io::Error::kind),
            Some(io::ErrorKind::ConnectionRefused)
        );
    }

    #[tokio::test]
    async fn connect_tcp_sets_nodelay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = connect_tcp(addr, Duration::from_secs(1)).await.unwrap();
        assert!(stream.nodelay().unwrap());
    }

    #[test]
    fn connect_error_mapping() {
        let addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let timeout = connect_timeout(addr, Duration::from_millis(200));
        assert_eq!(timeout.kind(), RejectKind::Unreachable);
        assert!(timeout.to_string().contains("timed out"), "{timeout}");
        let cases = [
            (io::ErrorKind::ConnectionRefused, RejectKind::Reset),
            (io::ErrorKind::HostUnreachable, RejectKind::Unreachable),
            (io::ErrorKind::NetworkUnreachable, RejectKind::Unreachable),
            (io::ErrorKind::PermissionDenied, RejectKind::Unreachable),
        ];
        for (io_kind, kind) in cases {
            assert_eq!(
                connect_error(addr, io::Error::from(io_kind)).kind(),
                kind,
                "{io_kind:?}"
            );
        }
    }

    /// A connected 127.0.0.1 TCP pair: (client, accepted).
    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn relay_tcp_half_close_and_counts() {
        let (guest_relay, mut guest_peer) = tcp_pair().await;
        let (host_relay, mut host_peer) = tcp_pair().await;
        let relay = tokio::spawn(relay_tcp(guest_relay, host_relay));

        guest_peer.write_all(b"ping").await.unwrap();
        guest_peer.shutdown().await.unwrap();
        let mut got = Vec::new();
        host_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");

        host_peer.write_all(b"pong!").await.unwrap();
        drop(host_peer);
        let mut got = Vec::new();
        guest_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"pong!");

        assert_eq!(
            relay.await.unwrap(),
            RelayOutcome::Closed {
                to_host: 4,
                to_guest: 5
            }
        );
    }

    #[tokio::test]
    async fn relay_tcp_duplex_guest() {
        let (guest_relay, mut guest_peer) = tokio::io::duplex(1024);
        let (host_relay, mut host_peer) = tcp_pair().await;
        let relay = tokio::spawn(relay_tcp(guest_relay, host_relay));

        host_peer.write_all(b"hello").await.unwrap();
        let mut buf = [0; 5];
        guest_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        guest_peer.write_all(b"hi").await.unwrap();
        host_peer.read_exact(&mut buf[..2]).await.unwrap();
        assert_eq!(&buf[..2], b"hi");

        host_peer.shutdown().await.unwrap();
        let mut rest = Vec::new();
        guest_peer.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        drop(guest_peer);
        assert_eq!(
            relay.await.unwrap(),
            RelayOutcome::Closed {
                to_host: 2,
                to_guest: 5
            }
        );
    }

    #[tokio::test]
    async fn relay_tcp_host_reset() {
        let (guest_relay, _guest_peer) = tcp_pair().await;
        let (host_relay, host_peer) = tcp_pair().await;
        let relay = tokio::spawn(relay_tcp(guest_relay, host_relay));
        host_peer.set_zero_linger().unwrap();
        drop(host_peer);
        assert_eq!(relay.await.unwrap(), RelayOutcome::HostReset);
    }

    #[tokio::test]
    async fn relay_tcp_guest_error_resets_host() {
        let (guest_relay, guest_peer) = tcp_pair().await;
        let (host_relay, mut host_peer) = tcp_pair().await;
        let relay = tokio::spawn(relay_tcp(guest_relay, host_relay));
        guest_peer.set_zero_linger().unwrap();
        drop(guest_peer);
        assert_eq!(relay.await.unwrap(), RelayOutcome::GuestReset);
        let mut buf = [0; 1];
        let err = host_peer.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    }
}
