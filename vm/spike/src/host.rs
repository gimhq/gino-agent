//! Host-side services for the guest:
//!
//! - a vsock target: a Unix socket that echoes every byte back;
//! - a network port: a Unix socket speaking libkrun's length-prefixed `unixstream` framing,
//!   wrapped with `nsplane-ether` (ARP, single-lease DHCPv4 `10.0.2.15/24` via `10.0.2.2`)
//!   in front of `nsplane-netstack`; every guest TCP connection is proxied to a loopback TCP
//!   backend that answers one line with `echo <line>`.
//!
//! ```text
//! spike-host VSOCK_SOCKET NET_SOCKET BACKEND_ADDR
//! ```

use std::error::Error;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;

use futures_core::Stream;
use nsplane::{PacketSink, PacketSource, PeerId};
use nsplane_ether::{DhcpConfig, EtherConfig, MacAddr, spawn_port, stream};
use nsplane_netstack::{NetStack, NetStackConfig, TcpConnection};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

const GW_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
const GW_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

fn ether_config() -> EtherConfig {
    EtherConfig {
        gateway_ipv4: Some(GW_IP),
        dhcp: Some(DhcpConfig {
            router: Some(GW_IP),
            dns: vec![GW_IP],
            ..DhcpConfig::new(GW_IP, GUEST_IP, 24)
        }),
        ..EtherConfig::new(GW_MAC)
    }
}

async fn vsock_echo(mut conn: UnixStream) -> std::io::Result<()> {
    let mut buf = [0u8; 4096];
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        conn.write_all(&buf[..n]).await?;
    }
}

async fn backend_echo(conn: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
    let mut conn = BufReader::new(conn);
    let mut line = String::new();
    conn.read_line(&mut line).await?;
    let line = line.trim_end();
    println!("backend: {peer} sent {line:?}");
    conn.write_all(format!("echo {line}\n").as_bytes()).await?;
    conn.shutdown().await
}

async fn forward(mut from: impl PacketSource, to: impl PacketSink) {
    while let Ok(packet) = from.recv().await {
        if to.send(packet, PeerId::new(1)).await.is_err() {
            break;
        }
    }
}

async fn proxy(conn: TcpConnection, backend: SocketAddr) -> std::io::Result<()> {
    println!(
        "netstack: tcp {} -> {}",
        conn.peer_addr(),
        conn.local_addr()
    );
    let mut upstream = TcpStream::connect(backend).await?;
    let mut conn = conn;
    tokio::io::copy_bidirectional(&mut conn, &mut upstream).await?;
    Ok(())
}

/// Serves one guest network connection until the guest disconnects.
async fn guest_net(conn: UnixStream, backend: SocketAddr) {
    let (reader, writer) = stream::unix(conn);
    let (source, sink, handle) = spawn_port(reader, writer, ether_config());
    let (stack, net) = NetStack::new(NetStackConfig::new(
        vec![(IpAddr::V4(GW_IP), 24)],
        ether_config().mtu,
    ));
    let (stack_source, stack_sink) = stack.split();
    let to_stack = tokio::spawn(forward(source, stack_sink));
    let to_guest = tokio::spawn(forward(stack_source, sink));
    let mut incoming = net.incoming_tcp();
    let accept = tokio::spawn(async move {
        while let Some(conn) = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)).await {
            tokio::spawn(async move {
                if let Err(err) = proxy(conn, backend).await {
                    println!("netstack: proxy failed: {err}");
                }
            });
        }
    });
    let _ = to_stack.await;
    to_guest.abort();
    accept.abort();
    println!(
        "ether: guest disconnected, guest_mac={:?} {:?}",
        handle.guest_mac(),
        handle.stats()
    );
    drop(net);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [vsock_path, net_path, backend] = args.as_slice() else {
        return Err("usage: spike-host VSOCK_SOCKET NET_SOCKET BACKEND_ADDR".into());
    };
    let backend: SocketAddr = backend.parse()?;
    let vsock = UnixListener::bind(vsock_path)?;
    let net = UnixListener::bind(net_path)?;
    let tcp = TcpListener::bind(backend).await?;
    println!("spike-host: ready");

    tokio::spawn(async move {
        while let Ok((conn, peer)) = tcp.accept().await {
            tokio::spawn(backend_echo(conn, peer));
        }
    });
    tokio::spawn(async move {
        while let Ok((conn, _)) = vsock.accept().await {
            tokio::spawn(vsock_echo(conn));
        }
    });
    tokio::spawn(async move {
        while let Ok((conn, _)) = net.accept().await {
            println!("ether: guest connected");
            tokio::spawn(guest_net(conn, backend));
        }
    });
    tokio::signal::ctrl_c().await?;
    Ok(())
}
