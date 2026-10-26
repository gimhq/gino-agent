//! Guest network setup over rtnetlink, vsock sockets and the agent API
//! forwarder.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{Context, Result};
use futures_util::TryStreamExt as _;
use nix::sys::socket::{AddressFamily, Backlog, SockFlag, SockType, VsockAddr};
use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder};

use super::spec::NetConfig;

/// The virtio-net interface libkrun attaches.
const ETH0: &str = "eth0";
/// vsock CID of the host.
const VMADDR_CID_HOST: u32 = 2;
/// Wildcard vsock CID for listening.
const VMADDR_CID_ANY: u32 = u32::MAX;

/// Bring up `lo` and, when `net` is set, configure eth0 with its address, MTU
/// and a default route via the gateway.
pub(super) fn configure(net: Option<&NetConfig>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime")?;
    runtime.block_on(async {
        let (connection, handle, _) =
            rtnetlink::new_connection().context("opening rtnetlink socket")?;
        let connection = tokio::spawn(connection);
        let result = configure_links(&handle, net).await;
        connection.abort();
        result
    })
}

async fn configure_links(handle: &Handle, net: Option<&NetConfig>) -> Result<()> {
    let lo = link_index(handle, "lo").await?;
    handle
        .link()
        .set(LinkUnspec::new_with_index(lo).up().build())
        .execute()
        .await
        .context("bringing lo up")?;
    let Some(net) = net else {
        return Ok(());
    };
    let eth0 = link_index(handle, ETH0).await?;
    handle
        .address()
        .add(eth0, IpAddr::V4(net.address), net.prefix_len)
        .execute()
        .await
        .with_context(|| format!("adding {}/{} to {ETH0}", net.address, net.prefix_len))?;
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(eth0)
                .mtu(u32::from(net.mtu))
                .up()
                .build(),
        )
        .execute()
        .await
        .with_context(|| format!("setting MTU {} and bringing {ETH0} up", net.mtu))?;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .output_interface(eth0)
        .gateway(net.gateway)
        .build();
    handle
        .route()
        .add(route)
        .execute()
        .await
        .with_context(|| format!("adding default route via {}", net.gateway))
}

async fn link_index(handle: &Handle, name: &str) -> Result<u32> {
    let link = handle
        .link()
        .get()
        .match_name(name.to_owned())
        .execute()
        .try_next()
        .await
        .with_context(|| format!("looking up {name}"))?
        .with_context(|| format!("interface {name} not found"))?;
    Ok(link.header.index)
}

fn vsock_socket() -> Result<OwnedFd> {
    nix::sys::socket::socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .context("creating vsock socket")
}

/// Listen on guest vsock `port` for host connections.
pub(super) fn vsock_listen(port: u32) -> Result<OwnedFd> {
    let fd = vsock_socket()?;
    nix::sys::socket::bind(fd.as_raw_fd(), &VsockAddr::new(VMADDR_CID_ANY, port))
        .with_context(|| format!("binding vsock port {port}"))?;
    nix::sys::socket::listen(&fd, Backlog::new(8).context("vsock backlog")?)
        .with_context(|| format!("listening on vsock port {port}"))?;
    Ok(fd)
}

/// Accept one connection on a vsock listener.
pub(super) fn vsock_accept(listener: &OwnedFd) -> Result<File> {
    let fd = rustix::net::accept(listener).context("accepting vsock connection")?;
    Ok(File::from(fd))
}

/// Connect to host vsock `port`.
fn vsock_connect(port: u32) -> Result<File> {
    let fd = vsock_socket()?;
    nix::sys::socket::connect(fd.as_raw_fd(), &VsockAddr::new(VMADDR_CID_HOST, port))
        .with_context(|| format!("connecting to host vsock port {port}"))?;
    Ok(File::from(fd))
}

/// Bind the agent API socket (mode 0666, so the engine uid can connect) and
/// forward every connection to host vsock `port` on its own threads.
pub(super) fn start_agent_forwarder(socket_path: &str, port: u32) -> Result<()> {
    let path = Path::new(socket_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let listener = UnixListener::bind(path).with_context(|| format!("binding {socket_path}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .with_context(|| format!("setting mode of {socket_path}"))?;
    std::thread::Builder::new()
        .name("agent-api".into())
        .spawn(move || {
            for conn in listener.incoming() {
                match conn {
                    Ok(conn) => {
                        if let Err(err) = forward(conn, port) {
                            eprintln!("guest-init: agent API connection: {err:#}");
                        }
                    }
                    Err(err) => eprintln!("guest-init: accepting agent API connection: {err}"),
                }
            }
        })
        .context("spawning agent API thread")?;
    Ok(())
}

/// Pump bytes both ways between a guest Unix connection and a new host vsock
/// connection, half-closing each direction at EOF.
fn forward(unix: UnixStream, port: u32) -> Result<()> {
    let vsock = vsock_connect(port)?;
    let unix_rx = unix.try_clone().context("cloning agent API connection")?;
    let vsock_tx = vsock.try_clone().context("cloning vsock connection")?;
    std::thread::Builder::new()
        .name("agent-api-up".into())
        .spawn(move || {
            pump(unix_rx, &vsock_tx);
            let _ = rustix::net::shutdown(&vsock_tx, rustix::net::Shutdown::Write);
        })
        .context("spawning agent API thread")?;
    std::thread::Builder::new()
        .name("agent-api-down".into())
        .spawn(move || {
            pump(vsock, &unix);
            let _ = unix.shutdown(Shutdown::Write);
        })
        .context("spawning agent API thread")?;
    Ok(())
}

fn pump(mut from: impl Read, mut to: impl Write) {
    let _ = std::io::copy(&mut from, &mut to);
}
