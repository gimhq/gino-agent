//! `spec.json`: the run description the daemon writes into the per-run control
//! share and guest-init reads at boot.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// The per-run control dir holding `spec.json`, on the boot root.
pub(crate) const BOOT_CONTROL_DIR: &str = "/ctl";
/// Where guest-init binds the control dir on the root disk.
pub(crate) const GUEST_CONTROL_DIR: &str = "/run/gino/ctl";
/// File name of the spec inside the control dir.
pub(crate) const SPEC_FILE_NAME: &str = "spec.json";
/// Guest path of the agent API socket.
pub(crate) const GUEST_AGENT_SOCKET: &str = "/run/gino/agent.sock";
/// Default vsock port of the agent API (guest connects to the host).
pub(crate) const DEFAULT_AGENT_API_VSOCK_PORT: u32 = 5000;
/// Default vsock port of the control channel (host connects to the guest).
pub(crate) const DEFAULT_CONTROL_VSOCK_PORT: u32 = 5001;

/// Mount points guest shares may not use or shadow.
const RESERVED_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/run/gino"];
/// Trees inside a reserved prefix shares and binds may use: the engine's
/// memory and conversations mount points.
const ALLOWED_PREFIXES: &[&str] = &["/run/gino/memory", "/run/gino/conversations"];
/// `sockaddr_un.sun_path` capacity minus the terminating NUL.
const MAX_SOCKET_PATH: usize = 107;

/// Everything guest-init needs to start the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestSpec {
    /// Engine program (an absolute guest path, or a name looked up on the
    /// spec's `PATH` in the guest) followed by its arguments.
    pub(crate) argv: Vec<String>,
    /// The engine's complete, ordered environment.
    pub(crate) env: Vec<(String, String)>,
    /// Absolute guest working directory of the engine.
    pub(crate) cwd: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// virtiofs shares to mount, besides the control share.
    pub(crate) mounts: Vec<GuestMount>,
    /// Read-only bind mounts of control share entries, applied after the
    /// shares; virtiofs shares only carry directories, so single files reach
    /// the guest this way.
    #[serde(default)]
    pub(crate) binds: Vec<GuestBind>,
    /// eth0 configuration; absent leaves only `lo`.
    pub(crate) net: Option<GuestNet>,
    /// Agent API forwarder from a guest Unix socket to a host vsock port.
    pub(crate) agent_api: Option<GuestAgentApi>,
    /// Guest vsock port guest-init listens on for the daemon's control channel.
    pub(crate) control_vsock_port: u32,
    /// Start dockerd before the engine.
    #[serde(default)]
    pub(crate) docker: bool,
}

/// One virtiofs share mounted by tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestMount {
    pub(crate) tag: String,
    pub(crate) guest_path: String,
    pub(crate) read_only: bool,
}

/// One read-only bind mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestBind {
    /// File or directory below the control share mount point.
    pub(crate) source: String,
    /// Mount point; created (as the source's kind) when missing.
    pub(crate) target: String,
}

/// eth0 address plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestNet {
    /// Interface address in CIDR form, e.g. `10.0.2.15/24`.
    pub(crate) address: String,
    pub(crate) gateway: String,
    /// Sole resolver written to `/etc/resolv.conf`.
    pub(crate) dns: String,
    pub(crate) mtu: u16,
}

/// Agent API forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestAgentApi {
    /// Host vsock port each guest connection is forwarded to.
    pub(crate) vsock_port: u32,
    /// Guest Unix socket the engine connects to.
    pub(crate) socket_path: String,
}

/// Parsed eth0 configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NetConfig {
    pub(crate) address: Ipv4Addr,
    pub(crate) prefix_len: u8,
    pub(crate) gateway: Ipv4Addr,
    pub(crate) dns: Ipv4Addr,
    pub(crate) mtu: u16,
}

impl GuestSpec {
    /// Parse and validate `spec.json` content.
    pub(crate) fn from_json(json: &str) -> Result<Self> {
        let spec: Self = serde_json::from_str(json).context("parsing spec.json")?;
        spec.validate()?;
        Ok(spec)
    }

    /// Reject specs guest-init cannot apply safely.
    pub(crate) fn validate(&self) -> Result<()> {
        let Some(program) = self.argv.first() else {
            bail!("argv is empty");
        };
        if program.contains('/') {
            check_absolute("argv[0]", program)?;
        } else {
            ensure!(
                !program.is_empty() && program != "." && program != "..",
                "argv[0] `{program}` is not a program name"
            );
        }
        ensure!(
            self.argv.iter().all(|arg| !arg.contains('\0')),
            "argv contains a NUL byte"
        );
        for (name, value) in &self.env {
            ensure!(
                !name.is_empty() && !name.contains(['=', '\0']),
                "invalid environment variable name `{name}`"
            );
            ensure!(
                !value.contains('\0'),
                "environment variable {name} contains a NUL byte"
            );
        }
        check_absolute("cwd", &self.cwd)?;
        ensure!(self.uid != 0 && self.gid != 0, "uid and gid must not be 0");

        let mut tags = HashSet::new();
        let mut paths = HashSet::new();
        for mount in &self.mounts {
            ensure!(!mount.tag.is_empty(), "mount tag is empty");
            ensure!(
                mount.tag != "/dev/root",
                "mount tag `{}` is reserved",
                mount.tag
            );
            ensure!(
                tags.insert(&mount.tag),
                "duplicate mount tag `{}`",
                mount.tag
            );
            check_mount_path(&mount.guest_path)?;
            ensure!(
                paths.insert(&mount.guest_path),
                "duplicate mount guest path {}",
                mount.guest_path
            );
        }

        for bind in &self.binds {
            check_absolute("bind source", &bind.source)?;
            ensure!(
                Path::new(&bind.source) != Path::new(GUEST_CONTROL_DIR)
                    && Path::new(&bind.source).starts_with(GUEST_CONTROL_DIR),
                "bind source {} is not inside {GUEST_CONTROL_DIR}",
                bind.source
            );
            check_mount_path(&bind.target)?;
            ensure!(
                paths.insert(&bind.target),
                "duplicate mount guest path {}",
                bind.target
            );
        }

        if let Some(net) = &self.net {
            net.config()?;
        }
        ensure!(
            self.control_vsock_port != 0,
            "controlVsockPort must not be 0"
        );
        if let Some(api) = &self.agent_api {
            ensure!(api.vsock_port != 0, "agentApi.vsockPort must not be 0");
            ensure!(
                api.vsock_port != self.control_vsock_port,
                "agentApi.vsockPort equals controlVsockPort"
            );
            check_absolute("agentApi.socketPath", &api.socket_path)?;
            ensure!(
                api.socket_path.len() <= MAX_SOCKET_PATH,
                "agentApi.socketPath is longer than {MAX_SOCKET_PATH} bytes"
            );
            ensure!(
                !Path::new(&api.socket_path).starts_with(GUEST_CONTROL_DIR),
                "agentApi.socketPath lies in the read-only control share"
            );
        }
        Ok(())
    }
}

impl GuestNet {
    /// Parse the address plan: the gateway must lie inside the interface
    /// subnet (it is the on-link next hop of the default route).
    pub(crate) fn config(&self) -> Result<NetConfig> {
        let (address, prefix_len) = parse_cidr(&self.address)?;
        let gateway: Ipv4Addr = self
            .gateway
            .parse()
            .with_context(|| format!("invalid net.gateway `{}`", self.gateway))?;
        let dns: Ipv4Addr = self
            .dns
            .parse()
            .with_context(|| format!("invalid net.dns `{}`", self.dns))?;
        ensure!(
            gateway != address && same_subnet(address, gateway, prefix_len),
            "net.gateway {gateway} is not another address in {}",
            self.address
        );
        ensure!(!dns.is_unspecified(), "net.dns must not be 0.0.0.0");
        ensure!(
            self.mtu >= 576,
            "net.mtu {} is outside 576..=65535",
            self.mtu
        );
        Ok(NetConfig {
            address,
            prefix_len,
            gateway,
            dns,
            mtu: self.mtu,
        })
    }
}

/// `a.b.c.d/len` with a unicast address and a prefix of 1..=30.
fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
    let invalid = || format!("invalid net.address `{cidr}` (want a.b.c.d/len)");
    let (address, prefix) = cidr.split_once('/').with_context(invalid)?;
    let address: Ipv4Addr = address.parse().with_context(invalid)?;
    let prefix_len: u8 = prefix.parse().with_context(invalid)?;
    ensure!(
        (1..=30).contains(&prefix_len),
        "{}: prefix out of 1..=30",
        invalid()
    );
    ensure!(
        !address.is_unspecified() && !address.is_broadcast() && !address.is_multicast(),
        "{}: not a unicast address",
        invalid()
    );
    Ok((address, prefix_len))
}

fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = u32::MAX << (32 - u32::from(prefix_len));
    u32::from(a) & mask == u32::from(b) & mask
}

/// An absolute, normalized path (no `.`/`..`, no trailing slash, no NUL).
fn check_absolute(what: &str, path: &str) -> Result<()> {
    let normal = path == "/"
        || (path.starts_with('/')
            && !path.contains('\0')
            && path
                .split('/')
                .skip(1)
                .all(|segment| !matches!(segment, "" | "." | "..")));
    ensure!(normal, "{what} `{path}` is not a normalized absolute path");
    Ok(())
}

/// A share mount point: absolute, not `/` and outside the reserved trees.
fn check_mount_path(path: &str) -> Result<()> {
    check_absolute("mount guest path", path)?;
    ensure!(path != "/", "mount guest path must not be /");
    ensure!(
        !RESERVED_PREFIXES
            .iter()
            .any(|p| Path::new(path).starts_with(p))
            || ALLOWED_PREFIXES
                .iter()
                .any(|p| Path::new(path).starts_with(p)),
        "mount guest path {path} lies in a reserved tree"
    );
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn sample() -> GuestSpec {
        GuestSpec {
            argv: vec![
                "/usr/local/bin/claude".into(),
                "-p".into(),
                "hello world".into(),
            ],
            env: vec![
                ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
                ("HOME".into(), "/var/lib/gino/home/t1".into()),
            ],
            cwd: "/var/lib/gino/threads/t1/work".into(),
            uid: 1000,
            gid: 1000,
            mounts: vec![
                GuestMount {
                    tag: "work".into(),
                    guest_path: "/var/lib/gino/threads/t1/work".into(),
                    read_only: false,
                },
                GuestMount {
                    tag: "skills".into(),
                    guest_path: "/var/lib/gino/skills".into(),
                    read_only: true,
                },
            ],
            binds: vec![GuestBind {
                source: "/run/gino/ctl/view/0".into(),
                target: "/var/lib/gino/threads/t1/work/.engine-home/CLAUDE.md".into(),
            }],
            net: Some(GuestNet {
                address: "10.0.2.15/24".into(),
                gateway: "10.0.2.2".into(),
                dns: "10.0.2.2".into(),
                mtu: 1500,
            }),
            agent_api: Some(GuestAgentApi {
                vsock_port: DEFAULT_AGENT_API_VSOCK_PORT,
                socket_path: GUEST_AGENT_SOCKET.into(),
            }),
            control_vsock_port: DEFAULT_CONTROL_VSOCK_PORT,
            docker: false,
        }
    }

    fn rejects(mutate: impl FnOnce(&mut GuestSpec), needle: &str) {
        let mut spec = sample();
        mutate(&mut spec);
        let err = format!("{:#}", spec.validate().unwrap_err());
        assert!(err.contains(needle), "`{err}` lacks `{needle}`");
    }

    #[test]
    fn json_round_trip_uses_camel_case() {
        let spec = sample();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(
            json.contains(r#""guestPath":"/var/lib/gino/skills""#),
            "{json}"
        );
        assert!(json.contains(r#""controlVsockPort":5001"#), "{json}");
        assert!(json.contains(r#""env":[["PATH","#), "{json}");
        assert_eq!(GuestSpec::from_json(&json).unwrap(), spec);
    }

    #[test]
    fn optional_sections_may_be_absent() {
        let json = r#"{"argv":["/bin/true"],"env":[],"cwd":"/","uid":1000,"gid":1000,
                       "mounts":[],"controlVsockPort":5001}"#;
        let spec = GuestSpec::from_json(json).unwrap();
        assert_eq!(spec.net, None);
        assert_eq!(spec.agent_api, None);
        assert!(spec.binds.is_empty());
        assert!(!spec.docker);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut value = serde_json::to_value(sample()).unwrap();
        value["extra"] = 1.into();
        assert!(GuestSpec::from_json(&value.to_string()).is_err());
        let mut value = serde_json::to_value(sample()).unwrap();
        value["mounts"][0]["mode"] = "rw".into();
        assert!(GuestSpec::from_json(&value.to_string()).is_err());
        let mut value = serde_json::to_value(sample()).unwrap();
        value["net"]["mtu"] = 70000.into();
        assert!(GuestSpec::from_json(&value.to_string()).is_err());
    }

    #[test]
    fn validate_rejects_bad_process_fields() {
        rejects(|s| s.argv.clear(), "argv is empty");
        rejects(|s| s.argv[0] = "bin/claude".into(), "argv[0]");
        rejects(|s| s.argv[0] = "..".into(), "argv[0]");
        rejects(|s| s.argv.push("a\0b".into()), "NUL");
        rejects(|s| s.env.push((String::new(), "x".into())), "variable name");
        rejects(|s| s.env.push(("A=B".into(), "x".into())), "variable name");
        rejects(|s| s.cwd = "work".into(), "cwd");
        rejects(|s| s.cwd = "/a/../b".into(), "cwd");
        rejects(|s| s.cwd = "/a/".into(), "cwd");
        rejects(|s| s.cwd = "/a//b".into(), "cwd");
        rejects(|s| s.cwd = "/a/.".into(), "cwd");
        rejects(|s| s.uid = 0, "must not be 0");
        rejects(|s| s.gid = 0, "must not be 0");
    }

    #[test]
    fn a_program_name_is_looked_up_in_the_guest() {
        let mut spec = sample();
        spec.argv[0] = "claude".into();
        spec.validate().unwrap();
    }

    #[test]
    fn validate_rejects_bad_mounts() {
        rejects(|s| s.mounts[1].tag = "work".into(), "duplicate mount tag");
        rejects(|s| s.mounts[0].tag = "/dev/root".into(), "reserved");
        rejects(|s| s.mounts[0].tag = String::new(), "tag is empty");
        rejects(
            |s| s.mounts[1].guest_path = s.mounts[0].guest_path.clone(),
            "duplicate mount guest path",
        );
        rejects(|s| s.mounts[0].guest_path = "/".into(), "must not be /");
        rejects(|s| s.mounts[0].guest_path = "relative".into(), "normalized");
        rejects(|s| s.mounts[0].guest_path = "/a/./b".into(), "normalized");
        rejects(
            |s| s.mounts[0].guest_path = "/proc/x".into(),
            "reserved tree",
        );
        rejects(
            |s| s.mounts[0].guest_path = "/run/gino/ctl".into(),
            "reserved tree",
        );
        rejects(
            |s| s.mounts[0].guest_path = "/run/gino/memoryx".into(),
            "reserved tree",
        );
        rejects(
            |s| s.binds[0].target = "/run/gino/agent.sock".into(),
            "reserved tree",
        );
    }

    #[test]
    fn memory_and_conversations_mount_points_are_allowed() {
        let mut spec = sample();
        spec.mounts[1].guest_path = "/run/gino/memory/agent".into();
        spec.mounts.push(GuestMount {
            tag: "task-memory".into(),
            guest_path: "/run/gino/memory/task".into(),
            read_only: false,
        });
        spec.binds[0].target = "/run/gino/conversations".into();
        spec.validate().unwrap();
    }

    #[test]
    fn validate_rejects_bad_binds() {
        rejects(
            |s| s.binds[0].source = "/etc/passwd".into(),
            "is not inside /run/gino/ctl",
        );
        rejects(
            |s| s.binds[0].source = GUEST_CONTROL_DIR.into(),
            "is not inside",
        );
        rejects(
            |s| s.binds[0].source = "/run/gino/ctl/../x".into(),
            "normalized",
        );
        rejects(|s| s.binds[0].target = "/proc/x".into(), "reserved tree");
        rejects(
            |s| s.binds[0].target = s.mounts[0].guest_path.clone(),
            "duplicate mount guest path",
        );
    }

    #[test]
    fn validate_rejects_bad_net() {
        let net = |f: fn(&mut GuestNet)| move |s: &mut GuestSpec| f(s.net.as_mut().unwrap());
        rejects(net(|n| n.address = "10.0.2.15".into()), "net.address");
        rejects(net(|n| n.address = "10.0.2.15/33".into()), "prefix");
        rejects(net(|n| n.address = "10.0.2.15/0".into()), "prefix");
        rejects(net(|n| n.address = "0.0.0.0/24".into()), "unicast");
        rejects(net(|n| n.address = "10.0.2/24".into()), "net.address");
        rejects(net(|n| n.gateway = "10.0.3.2".into()), "net.gateway");
        rejects(net(|n| n.gateway = "10.0.2.15".into()), "net.gateway");
        rejects(net(|n| n.gateway = "gw".into()), "net.gateway");
        rejects(net(|n| n.dns = "dns".into()), "net.dns");
        rejects(net(|n| n.dns = "0.0.0.0".into()), "net.dns");
        rejects(net(|n| n.mtu = 575), "net.mtu");
    }

    #[test]
    fn validate_rejects_bad_ports_and_socket() {
        rejects(|s| s.control_vsock_port = 0, "controlVsockPort");
        let api =
            |f: fn(&mut GuestAgentApi)| move |s: &mut GuestSpec| f(s.agent_api.as_mut().unwrap());
        rejects(api(|a| a.vsock_port = 0), "vsockPort must not be 0");
        rejects(api(|a| a.vsock_port = DEFAULT_CONTROL_VSOCK_PORT), "equals");
        rejects(api(|a| a.socket_path = "agent.sock".into()), "socketPath");
        rejects(
            api(|a| a.socket_path = format!("/{}", "s".repeat(107))),
            "longer",
        );
        rejects(
            api(|a| a.socket_path = "/run/gino/ctl/agent.sock".into()),
            "control share",
        );
    }

    #[test]
    fn net_config_is_derived() {
        let mut net = sample().net.unwrap();
        net.mtu = 576;
        assert_eq!(
            net.config().unwrap(),
            NetConfig {
                address: Ipv4Addr::new(10, 0, 2, 15),
                prefix_len: 24,
                gateway: Ipv4Addr::new(10, 0, 2, 2),
                dns: Ipv4Addr::new(10, 0, 2, 2),
                mtu: 576,
            }
        );
        net.mtu = u16::MAX;
        assert!(net.config().is_ok());
    }
}
