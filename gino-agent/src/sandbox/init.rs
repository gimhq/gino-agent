//! In-sandbox init that supervises the engine process.
//!
//! `sandbox-init` runs as uid 0 of the sandbox's user namespace. With
//! `--ctl-sock` it first creates the guest TUN device and hands it to the
//! daemon, waiting until the daemon's network exit runs. It then moves into a
//! nested user namespace as a non-root uid with no capabilities, spawns the
//! engine with inherited stdio and environment, forwards SIGINT/SIGTERM to it,
//! and exits with the engine's status.

use std::ffi::OsString;
use std::os::fd::AsFd as _;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Args;
use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::unistd::{Gid, Pid, Uid};
use rustix::thread::{CapabilitySet, CapabilitySets};
use tokio::io::AsyncReadExt as _;
use tokio::net::UnixStream;
use tokio::signal::unix::{SignalKind, signal};

use super::NET_READY;
use crate::net::fdpass::send_fd;
use crate::net::tun::{TunConfig, create_tun};

/// Exit code for any failure before or while supervising the engine.
const SETUP_FAILURE: i32 = 125;

/// Bound on each step of the network handover.
const HANDOVER_STEP_TIMEOUT: Duration = Duration::from_secs(20);

/// Arguments of the hidden `sandbox-init` subcommand.
#[derive(Args, Debug)]
pub(crate) struct SandboxInitArgs {
    /// Uid the engine runs as inside the nested user namespace.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) uid: u32,

    /// Gid the engine runs as inside the nested user namespace.
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..))]
    pub(crate) gid: u32,

    /// Daemon control socket the guest TUN device is handed over on.
    #[arg(long)]
    pub(crate) ctl_sock: Option<PathBuf>,

    /// Engine program and its arguments, passed through verbatim.
    #[arg(last = true, required = true)]
    pub(crate) command: Vec<OsString>,
}

/// Run `sandbox-init` and return the process exit code.
///
/// Must be called while the process is still single-threaded.
pub(crate) fn run(args: &SandboxInitArgs) -> i32 {
    let network = match &args.ctl_sock {
        Some(ctl_sock) => hand_over_network(ctl_sock),
        None => Ok(()),
    };
    match network
        .and_then(|()| drop_to_nested_userns(args.uid, args.gid))
        .and_then(|()| supervise(&args.command))
    {
        Ok(code) => code,
        Err(err) => {
            eprintln!("sandbox-init: {err:#}");
            SETUP_FAILURE
        }
    }
}

/// Create the guest TUN device, send it to the daemon over `ctl_sock`, close
/// this copy and wait for the daemon's ready byte. The runtime is gone when
/// this returns, so the process is single-threaded again.
fn hand_over_network(ctl_sock: &Path) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime")?;
    runtime.block_on(async {
        let tun = create_tun(&TunConfig::default())
            .await
            .context("creating the TUN device")?;
        let stream = tokio::time::timeout(HANDOVER_STEP_TIMEOUT, UnixStream::connect(ctl_sock))
            .await
            .context("connecting to the daemon control socket timed out")?
            .context("connecting to the daemon control socket")?;
        send_fd(&stream, tun.as_fd(), HANDOVER_STEP_TIMEOUT)
            .await
            .context("sending the TUN device to the daemon")?;
        drop(tun);
        let mut ready = [0u8; 1];
        let mut stream = stream;
        tokio::time::timeout(HANDOVER_STEP_TIMEOUT, stream.read_exact(&mut ready))
            .await
            .context("waiting for the daemon network exit timed out")?
            .context("waiting for the daemon network exit")?;
        if ready[0] != NET_READY {
            bail!("unexpected reply from the daemon control socket");
        }
        Ok(())
    })
}

/// Enter a new user namespace mapping `uid`/`gid` to the current ids, switch
/// to them and clear every capability set.
fn drop_to_nested_userns(uid: u32, gid: u32) -> Result<()> {
    let (outer_user, outer_group) = (nix::unistd::getuid(), nix::unistd::getgid());

    nix::sched::unshare(CloneFlags::CLONE_NEWUSER).context("unshare(CLONE_NEWUSER)")?;
    std::fs::write("/proc/self/setgroups", "deny").context("writing /proc/self/setgroups")?;
    std::fs::write("/proc/self/gid_map", id_map_line(gid, outer_group.as_raw()))
        .context("writing /proc/self/gid_map")?;
    // The kernel only lets a namespace map onto the outer root uid when its
    // creator held CAP_SETFCAP.
    let uid_map_error = if outer_user.is_root() {
        "writing /proc/self/uid_map (mapping onto outer uid 0 needs CAP_SETFCAP)"
    } else {
        "writing /proc/self/uid_map"
    };
    std::fs::write("/proc/self/uid_map", id_map_line(uid, outer_user.as_raw()))
        .context(uid_map_error)?;

    let gid = Gid::from_raw(gid);
    let uid = Uid::from_raw(uid);
    nix::unistd::setresgid(gid, gid, gid).context("setresgid")?;
    nix::unistd::setresuid(uid, uid, uid).context("setresuid")?;
    // The uid is already non-root once mapped, so the kernel keeps the full
    // capability sets granted by unshare; clear them explicitly.
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        },
    )
    .context("clearing capabilities")?;
    // Execve must not regain capabilities through file capabilities or setuid.
    rustix::thread::set_no_new_privs(true).context("setting no_new_privs")?;

    let status =
        std::fs::read_to_string("/proc/self/status").context("reading /proc/self/status")?;
    for field in ["CapEff", "CapPrm"] {
        if !cap_set_is_empty(&status, field)? {
            bail!("{field} is not empty after dropping capabilities");
        }
    }
    Ok(())
}

/// Spawn the engine, forward SIGINT/SIGTERM to it and return its exit code.
fn supervise(command: &[OsString]) -> Result<i32> {
    let Some((program, args)) = command.split_first() else {
        bail!("no engine program given");
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building runtime")?;
    runtime.block_on(async {
        let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
        let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        let mut child = tokio::process::Command::new(program)
            .args(args)
            .spawn()
            .with_context(|| format!("spawning {}", program.to_string_lossy()))?;
        let pid = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .map(Pid::from_raw)
            .context("engine pid unavailable")?;
        loop {
            tokio::select! {
                status = child.wait() => return Ok(exit_code(status.context("waiting for engine")?)),
                _ = sigint.recv() => forward(pid, Signal::SIGINT),
                _ = sigterm.recv() => forward(pid, Signal::SIGTERM),
            }
        }
    })
}

fn forward(pid: Pid, signal: Signal) {
    if let Err(err) = nix::sys::signal::kill(pid, signal) {
        eprintln!("sandbox-init: forwarding {signal} to engine: {err}");
    }
}

/// One `/proc/self/{uid,gid}_map` line mapping a single id.
fn id_map_line(inner: u32, outer: u32) -> String {
    format!("{inner} {outer} 1")
}

/// Whether the hex capability set `field` (e.g. `CapEff`) in
/// `/proc/<pid>/status` content is empty.
fn cap_set_is_empty(status: &str, field: &str) -> Result<bool> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
        .with_context(|| format!("{field} missing from /proc/self/status"))?;
    let set = u64::from_str_radix(value.trim(), 16)
        .with_context(|| format!("malformed {field} value `{}`", value.trim()))?;
    Ok(set == 0)
}

/// Map the engine's exit status to this process's exit code: the engine's
/// code, or 128 + signal number when it was killed by a signal.
fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|sig| 128 + sig))
        .unwrap_or(SETUP_FAILURE)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use clap::{CommandFactory, Parser};

    use super::{cap_set_is_empty, exit_code, id_map_line};
    use crate::{Cli, Command};

    fn parse(args: &[&str]) -> Result<super::SandboxInitArgs, clap::Error> {
        let cli = Cli::try_parse_from(
            ["gino-agent", "sandbox-init"]
                .iter()
                .chain(args)
                .collect::<Vec<_>>(),
        )?;
        match cli.command {
            Some(Command::SandboxInit(args)) => Ok(args),
            _ => panic!("not sandbox-init"),
        }
    }

    #[test]
    fn id_map_line_maps_one_id() {
        assert_eq!(id_map_line(1000, 0), "1000 0 1");
        assert_eq!(id_map_line(1001, 65534), "1001 65534 1");
    }

    #[test]
    fn cap_set_parsing() {
        let status = "Name:\tgino-agent\nCapAmb:\t0000000000000000\n\
                      CapPrm:\t0000000000000000\nCapEff:\t000001ffffffffff\n";
        assert!(cap_set_is_empty(status, "CapPrm").unwrap());
        assert!(cap_set_is_empty(status, "CapAmb").unwrap());
        assert!(!cap_set_is_empty(status, "CapEff").unwrap());
        assert!(!cap_set_is_empty("CapEff:\t0000000000001000\n", "CapEff").unwrap());
        assert!(cap_set_is_empty("Name:\tx\n", "CapEff").is_err());
        assert!(cap_set_is_empty("CapEff:\tzz\n", "CapEff").is_err());
    }

    #[test]
    fn exit_code_mapping() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(3 << 8)), 3);
        // A raw wait status of N (1..=127) means killed by signal N.
        assert_eq!(exit_code(ExitStatus::from_raw(2)), 130);
        assert_eq!(exit_code(ExitStatus::from_raw(15)), 143);
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }

    #[test]
    fn parses_defaults_and_trailing_command() {
        let args = parse(&["--", "claude", "--dangerously-skip-permissions", "-p", "--"]).unwrap();
        assert_eq!((args.uid, args.gid), (1000, 1000));
        assert_eq!(
            args.command,
            ["claude", "--dangerously-skip-permissions", "-p", "--"].map(OsString::from)
        );
    }

    #[test]
    fn parses_ids_and_keeps_global_looking_flags_for_the_engine() {
        let args = parse(&[
            "--uid", "1001", "--gid", "1002", "--", "codex", "-v", "--host", "x",
        ])
        .unwrap();
        assert_eq!((args.uid, args.gid), (1001, 1002));
        assert_eq!(
            args.command,
            ["codex", "-v", "--host", "x"].map(OsString::from)
        );
    }

    #[test]
    fn parses_the_control_socket() {
        let args = parse(&["--", "claude"]).unwrap();
        assert_eq!(args.ctl_sock, None);
        let args = parse(&["--ctl-sock", "/run/gino/ctl.sock", "--", "claude"]).unwrap();
        assert_eq!(
            args.ctl_sock.as_deref(),
            Some(std::path::Path::new("/run/gino/ctl.sock"))
        );
        assert_eq!(args.command, ["claude"].map(OsString::from));
    }

    #[test]
    fn rejects_missing_command_and_root_ids() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["--"]).is_err());
        assert!(parse(&["claude"]).is_err());
        assert!(parse(&["--uid", "0", "--", "claude"]).is_err());
        assert!(parse(&["--gid", "0", "--", "claude"]).is_err());
    }

    #[test]
    fn subcommand_is_hidden_from_help() {
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("sandbox-init"), "{help}");
        assert!(help.contains("archive"), "{help}");
    }
}
