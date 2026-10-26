//! TUN device creation and configuration in the current network namespace.

use std::io;
use std::net::{IpAddr, Ipv4Addr};

use futures_util::TryStreamExt as _;
use nsplane_tun::{Tun, TunOptions};
use rtnetlink::{Handle, LinkUnspec, RouteMessageBuilder};

/// Address plan of the guest-side TUN device.
///
/// The daemon adopting the device fd must pass the configured MTU: `Tun::split`
/// looks the interface MTU up by name in the caller's network namespace, so the
/// default name (`gino0`) is one unlikely to exist on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// Interface name.
    pub name: String,
    /// Guest address on the interface.
    pub address: Ipv4Addr,
    /// Prefix length of `address`.
    pub prefix_len: u8,
    /// Next hop of the default route.
    pub gateway: Ipv4Addr,
    /// Interface MTU.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "gino0".to_owned(),
            address: Ipv4Addr::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            mtu: 1500,
        }
    }
}

/// Failure while creating or configuring the TUN device.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// Opening /dev/net/tun or TUNSETIFF failed.
    #[error("create TUN device {name} (requires CAP_NET_ADMIN and /dev/net/tun): {source}")]
    Create { name: String, source: io::Error },
    /// The rtnetlink socket could not be opened.
    #[error("open rtnetlink socket: {0}")]
    Netlink(io::Error),
    /// Looking up the interface index failed.
    #[error("look up interface {name}: {source}")]
    Lookup {
        name: String,
        source: rtnetlink::Error,
    },
    /// Adding the interface address failed.
    #[error("set address {address}/{prefix_len} on {name}: {source}")]
    Address {
        name: String,
        address: Ipv4Addr,
        prefix_len: u8,
        source: rtnetlink::Error,
    },
    /// Setting the MTU or bringing the link up failed.
    #[error("set MTU {mtu} and link up on {name}: {source}")]
    LinkUp {
        name: String,
        mtu: u16,
        source: rtnetlink::Error,
    },
    /// Adding the default route failed.
    #[error("add default route via {gateway} on {name}: {source}")]
    Route {
        name: String,
        gateway: Ipv4Addr,
        source: rtnetlink::Error,
    },
}

/// Creates a plain TUN device (IFF_TUN | IFF_NO_PI, no offloads: one raw IP
/// packet per read and write), assigns the address, sets the MTU, brings the
/// link up and adds a default route via the gateway. The device disappears
/// when the last copy of its fd is closed.
pub async fn create_tun(cfg: &TunConfig) -> Result<Tun, TunError> {
    let tun = Tun::create_with(&cfg.name, TunOptions::new().offload(false)).map_err(|source| {
        TunError::Create {
            name: cfg.name.clone(),
            source,
        }
    })?;

    let (connection, handle, _) = rtnetlink::new_connection().map_err(TunError::Netlink)?;
    let connection = tokio::spawn(connection);
    let configured = configure(&handle, cfg).await;
    connection.abort();
    configured.map(|()| tun)
}

async fn configure(handle: &Handle, cfg: &TunConfig) -> Result<(), TunError> {
    let lookup_err = |source| TunError::Lookup {
        name: cfg.name.clone(),
        source,
    };
    let link = handle
        .link()
        .get()
        .match_name(cfg.name.clone())
        .execute()
        .try_next()
        .await
        .map_err(lookup_err)?
        .ok_or_else(|| lookup_err(rtnetlink::Error::RequestFailed))?;
    let index = link.header.index;
    handle
        .address()
        .add(index, IpAddr::V4(cfg.address), cfg.prefix_len)
        .execute()
        .await
        .map_err(|source| TunError::Address {
            name: cfg.name.clone(),
            address: cfg.address,
            prefix_len: cfg.prefix_len,
            source,
        })?;
    handle
        .link()
        .set(
            LinkUnspec::new_with_index(index)
                .mtu(u32::from(cfg.mtu))
                .up()
                .build(),
        )
        .execute()
        .await
        .map_err(|source| TunError::LinkUp {
            name: cfg.name.clone(),
            mtu: cfg.mtu,
            source,
        })?;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .output_interface(index)
        .gateway(cfg.gateway)
        .build();
    handle
        .route()
        .add(route)
        .execute()
        .await
        .map_err(|source| TunError::Route {
            name: cfg.name.clone(),
            gateway: cfg.gateway,
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_guest_plan() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.name, "gino0");
        assert_eq!(cfg.address, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(cfg.prefix_len, 24);
        assert_eq!(cfg.gateway, Ipv4Addr::new(10, 0, 2, 2));
        assert_eq!(cfg.mtu, 1500);
    }

    #[test]
    fn create_error_names_requirements() {
        let err = TunError::Create {
            name: "gino0".to_owned(),
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        };
        let msg = err.to_string();
        assert!(msg.contains("CAP_NET_ADMIN"), "{msg}");
        assert!(msg.contains("/dev/net/tun"), "{msg}");
    }

    /// TUN creation inside a bubblewrap user + network namespace, with the fd
    /// passed back to this (unprivileged) process.
    ///
    /// Run with `GINO_NET_PRIV_TESTS=1 <test binary> --ignored net::tun::tests::privileged`
    /// as a non-root user that can create user namespaces, with `bwrap` on
    /// PATH and `/dev/net/tun` present.
    mod privileged {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        use std::time::Duration;

        use rtnetlink::packet_route::address::AddressAttribute;
        use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags};
        use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
        use tokio::net::{UnixListener, UnixStream};

        use super::*;
        use crate::net::fdpass::{recv_fd, send_fd};

        const GATE_ENV: &str = "GINO_NET_PRIV_TESTS";
        const CHILD_ENV: &str = "GINO_NET_PRIV_CHILD";
        const CHILD_TEST: &str = "net::tun::tests::privileged::sandbox_child_creates_and_sends_tun";
        const STEP_TIMEOUT: Duration = Duration::from_secs(30);
        /// Device number of /dev/net/tun (major 10, minor 200).
        const TUN_RDEV: u64 = 0x0a_c8;

        #[tokio::test]
        #[ignore = "needs bwrap, user namespaces and /dev/net/tun; set GINO_NET_PRIV_TESTS=1"]
        async fn tun_created_in_sandbox_is_passed_back() {
            if std::env::var(GATE_ENV).as_deref() != Ok("1") {
                eprintln!("skipping: set {GATE_ENV}=1 to run privileged TUN tests");
                return;
            }
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("fd.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let mut child = tokio::process::Command::new("bwrap")
                .args([
                    "--unshare-user",
                    "--unshare-net",
                    "--uid",
                    "0",
                    "--gid",
                    "0",
                    "--cap-add",
                    "CAP_NET_ADMIN",
                    "--dev-bind",
                    "/",
                    "/",
                    "--die-with-parent",
                    "--",
                ])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
                .env(CHILD_ENV, &socket)
                .kill_on_drop(true)
                .spawn()
                .unwrap();

            let (stream, _) = tokio::time::timeout(STEP_TIMEOUT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let fd = recv_fd(&stream, STEP_TIMEOUT).await.unwrap();
            let meta = std::fs::File::from(fd.try_clone().unwrap())
                .metadata()
                .unwrap();
            assert!(meta.file_type().is_char_device());
            assert_eq!(meta.rdev(), TUN_RDEV);
            let adopted = Tun::from_fd(fd, TunConfig::default().mtu).unwrap();
            assert!(!adopted.offload().vnet_hdr, "expected a plain TUN device");

            let status = tokio::time::timeout(STEP_TIMEOUT, child.wait())
                .await
                .unwrap()
                .unwrap();
            assert!(status.success(), "sandbox child failed: {status}");
        }

        /// Runs inside the sandbox; a no-op unless started by the test above.
        #[tokio::test]
        #[ignore = "child half of tun_created_in_sandbox_is_passed_back"]
        async fn sandbox_child_creates_and_sends_tun() {
            let Some(socket) = std::env::var_os(CHILD_ENV) else {
                return;
            };
            let cfg = TunConfig::default();
            let tun = create_tun(&cfg).await.unwrap();
            assert_configured(&cfg).await;

            let stream = UnixStream::connect(socket).await.unwrap();
            send_fd(&stream, tun.as_fd(), STEP_TIMEOUT).await.unwrap();
            drop(tun);
        }

        async fn assert_configured(cfg: &TunConfig) {
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            let connection = tokio::spawn(connection);

            let link = handle
                .link()
                .get()
                .match_name(cfg.name.clone())
                .execute()
                .try_next()
                .await
                .unwrap()
                .unwrap();
            let index = link.header.index;
            assert!(link.header.flags.contains(LinkFlags::Up));
            assert!(
                link.attributes
                    .contains(&LinkAttribute::Mtu(u32::from(cfg.mtu)))
            );

            let addresses: Vec<_> = handle
                .address()
                .get()
                .set_link_index_filter(index)
                .execute()
                .try_collect()
                .await
                .unwrap();
            assert!(addresses.iter().any(|a| {
                a.header.prefix_len == cfg.prefix_len
                    && a.attributes
                        .contains(&AddressAttribute::Address(IpAddr::V4(cfg.address)))
            }));

            let routes: Vec<_> = handle
                .route()
                .get(RouteMessageBuilder::<Ipv4Addr>::new().build())
                .execute()
                .try_collect()
                .await
                .unwrap();
            assert!(routes.iter().any(|r| {
                r.header.destination_prefix_length == 0
                    && r.attributes
                        .contains(&RouteAttribute::Gateway(RouteAddress::Inet(cfg.gateway)))
            }));

            connection.abort();
        }
    }
}
