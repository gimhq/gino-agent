//! dockerd for runs with Docker enabled.
//!
//! guest-init starts dockerd as guest root before the engine, with its socket
//! group set to the engine's gid so the engine (no supplementary groups) can
//! use it, and stops it after the engine so the root disk is left clean.
//! dockerd's own output goes to a log file on the root disk, never to the
//! console the daemon reads as the engine's stream.

use std::fs::OpenOptions;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

const DOCKERD: &str = "/usr/bin/dockerd";
const DOCKER_SOCKET: &str = "/run/docker.sock";
const DOCKERD_LOG: &str = "/var/log/gino-dockerd.log";
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Bound on dockerd creating its socket.
const START_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on dockerd exiting after `SIGTERM`.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);

/// The dockerd argv: the socket group is the engine's gid; IPv6 NAT stays
/// off (the run network is IPv4).
pub(super) fn dockerd_args(engine_gid: u32) -> Vec<String> {
    vec![
        "--group".into(),
        engine_gid.to_string(),
        "--ip6tables=false".into(),
    ]
}

/// The controllers to enable for child cgroups, from `cgroup.controllers`.
pub(super) fn subtree_control(controllers: &str) -> String {
    controllers
        .split_whitespace()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Enable forwarding and the cgroup controllers, start dockerd and wait for
/// its socket.
pub(super) fn start(engine_gid: u32) -> Result<Child> {
    std::fs::write(IP_FORWARD, "1").context("enabling IPv4 forwarding")?;
    let root = Path::new(CGROUP_ROOT);
    let controllers = std::fs::read_to_string(root.join("cgroup.controllers"))
        .context("reading cgroup.controllers")?;
    std::fs::write(
        root.join("cgroup.subtree_control"),
        subtree_control(&controllers),
    )
    .context("enabling cgroup controllers")?;

    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DOCKERD_LOG)
        .with_context(|| format!("opening {DOCKERD_LOG}"))?;
    let mut child = Command::new(DOCKERD)
        .args(dockerd_args(engine_gid))
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .stdin(Stdio::null())
        .stdout(log.try_clone().context("duplicating the dockerd log")?)
        .stderr(log)
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawning {DOCKERD}"))?;

    let deadline = Instant::now() + START_TIMEOUT;
    while !Path::new(DOCKER_SOCKET).exists() {
        if let Some(status) = child.try_wait().context("waiting for dockerd")? {
            bail!("dockerd exited during startup ({status}); see {DOCKERD_LOG}");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!(
                "dockerd did not create {DOCKER_SOCKET} within {}s; see {DOCKERD_LOG}",
                START_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(POLL);
    }
    Ok(child)
}

/// `SIGTERM` dockerd and wait for it (killing it after [`STOP_TIMEOUT`]).
/// Called after the engine was reaped; dockerd may already have been reaped
/// by the reap loop, which makes this a no-op.
pub(super) fn stop(child: &Child) {
    let Ok(raw) = i32::try_from(child.id()) else {
        return;
    };
    let pid = Pid::from_raw(raw);
    if kill(pid, Signal::SIGTERM).is_err() {
        return;
    }
    let deadline = Instant::now() + STOP_TIMEOUT;
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) if Instant::now() < deadline => std::thread::sleep(POLL),
            Ok(WaitStatus::StillAlive) => {
                let _ = kill(pid, Signal::SIGKILL);
                let _ = waitpid(pid, None);
                return;
            }
            Ok(_) | Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{dockerd_args, subtree_control};

    #[test]
    fn dockerd_socket_group_is_the_engine_gid() {
        assert_eq!(dockerd_args(1000), ["--group", "1000", "--ip6tables=false"]);
    }

    #[test]
    fn every_available_controller_is_enabled() {
        assert_eq!(
            subtree_control("cpuset cpu io memory pids\n"),
            "+cpuset +cpu +io +memory +pids"
        );
        assert_eq!(subtree_control(""), "");
    }
}
