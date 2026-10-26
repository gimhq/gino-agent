//! `guest-init`: the workload libkrun's init starts in an engine microVM.
//!
//! It runs as the libkrun default `exec` (`/gino-agent guest-init`, default
//! kernel command line) rather than as PID 1: libkrun's `/init.krun` stays
//! PID 1, mounts the virtiofs boot root and turns this process's exit code
//! into the VMM's exit status when it powers the VM off, which a PID 1
//! replacement could only do through a libkrun-specific ioctl. guest-init owns
//! the mount table and reaps the engine's descendants as a child subreaper.
//!
//! Sequence: the switch to the root disk, base mounts, the root filesystem
//! grown to the disk, `spec.json` from the control share, share mounts, `lo`
//! and eth0, the agent API forwarder, the control channel, dockerd when the
//! spec enables Docker, then the engine as the spec's uid/gid with no
//! capabilities and `no_new_privs`, in its own process group, its stdio pipes
//! relayed to the raw-mode console. When the engine ends guest-init kills its
//! process group, flushes its output, stops dockerd, syncs the root disk,
//! reports `EXIT` and exits with the engine's code (128 + signal when killed).
//!
//! Any setup failure prints one `guest-init: <reason>` line and exits with
//! [`SETUP_FAILURE`]; the daemon tells it from an engine status by the
//! missing `EXIT` line.

mod control;
mod disk;
mod docker;
mod mounts;
mod net;
pub(crate) mod spec;
mod stdio;

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use rustix::thread::{CapabilitySet, CapabilitySets};
use std::os::unix::process::CommandExt as _;

use self::control::{Control, EngineStatus};
use self::spec::{GUEST_CONTROL_DIR, GuestSpec, SPEC_FILE_NAME};

/// Exit code of a guest-init setup failure. Distinct from gino-vmm's 120 and
/// libkrun init's 125..=127.
pub(crate) const SETUP_FAILURE: i32 = 121;

/// Process name of libkrun's guest init, PID 1 of every libkrun guest. Its
/// `/init.krun` file is served only at boot, so the workload cannot see it.
const LIBKRUN_INIT: &str = "init.krun";

/// Bound on waiting for the daemon to take the `EXIT` line.
const EXIT_REPORT_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on relaying the engine's remaining output after it ended.
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Run guest-init and return the process exit code.
pub(crate) fn run() -> i32 {
    match ensure_guest().and_then(|()| supervise()) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("guest-init: {err:#}");
            SETUP_FAILURE
        }
    }
}

/// Refuse to run anywhere but inside a libkrun guest, before any side effect.
fn ensure_guest() -> Result<()> {
    let pid1 = std::fs::read_to_string("/proc/1/comm").unwrap_or_default();
    ensure!(
        pid1.trim_end() == LIBKRUN_INIT,
        "not inside a libkrun guest (PID 1 is not {LIBKRUN_INIT}); this subcommand only runs as the VM workload"
    );
    ensure!(nix::unistd::getuid().is_root(), "must run as guest root");
    Ok(())
}

fn supervise() -> Result<i32> {
    // A session without a controlling terminal: the engine's process group
    // then reads the console without job-control stops.
    nix::unistd::setsid().context("setsid")?;
    nix::sys::prctl::set_child_subreaper(true).context("becoming child subreaper")?;

    mounts::apply(&mounts::root_plan())?;
    mounts::apply(&mounts::base_plan())?;
    disk::grow_root()?;

    let spec_path = Path::new(GUEST_CONTROL_DIR).join(SPEC_FILE_NAME);
    let json = std::fs::read_to_string(&spec_path)
        .with_context(|| format!("reading {}", spec_path.display()))?;
    let spec = GuestSpec::from_json(&json)?;
    let net = spec.net.as_ref().map(spec::GuestNet::config).transpose()?;

    mounts::apply(&mounts::spec_plan(&spec, net.as_ref(), Path::exists))?;
    mounts::check_writable_shares(&spec)?;
    net::configure(net.as_ref())?;
    if let Some(api) = &spec.agent_api {
        net::start_agent_forwarder(&api.socket_path, api.vsock_port)?;
    }
    let control = Arc::new(Control::default());
    control.serve(net::vsock_listen(spec.control_vsock_port)?)?;
    let dockerd = spec.docker.then(|| docker::start(spec.gid)).transpose()?;

    stdio::raw_console(std::io::stdin())?;
    let console = stdio::Console::current()?;
    drop_privileges_for_children()?;
    let (program, args) = spec.argv.split_first().context("argv is empty")?;
    // Runs as root: std clears the supplementary groups before setgid/setuid,
    // and the switch to a non-zero uid clears the permitted and effective
    // capability sets.
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&spec.cwd)
        .uid(spec.uid)
        .gid(spec.gid)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning {program}"))?;
    let relay = stdio::Relay::start(&mut child, console);
    let pid = i32::try_from(child.id())
        .map(Pid::from_raw)
        .context("engine pid out of range")?;
    control.engine_started(pid);

    let status = reap_until(pid)?;
    // The group's leftovers would hold the output pipes open.
    let _ = nix::sys::signal::killpg(pid, nix::sys::signal::Signal::SIGKILL);
    relay.finish(OUTPUT_DRAIN_TIMEOUT);
    if let Some(dockerd) = &dockerd {
        docker::stop(dockerd);
    }
    // The VM powers off without unmounting; a kept task disk must be on disk.
    nix::unistd::sync();
    control.engine_exited(status, EXIT_REPORT_TIMEOUT);
    Ok(status.exit_code())
}

/// Clear the inheritable, ambient and bounding capability sets and set
/// `no_new_privs` on this thread, which spawns the engine. guest-init keeps
/// its effective set (it signals the engine), the engine starts with nothing.
fn drop_privileges_for_children() -> Result<()> {
    let current = rustix::thread::capabilities(None).context("reading capabilities")?;
    rustix::thread::set_capabilities(
        None,
        CapabilitySets {
            inheritable: CapabilitySet::empty(),
            ..current
        },
    )
    .context("clearing the inheritable capabilities")?;
    rustix::thread::clear_ambient_capability_set().context("clearing ambient capabilities")?;
    for bit in 0..64 {
        let cap = CapabilitySet::from_bits_retain(1 << bit);
        // Bits past the kernel's last capability read as absent.
        if rustix::thread::capability_is_in_bounding_set(cap).unwrap_or(false) {
            rustix::thread::remove_capability_from_bounding_set(cap)
                .with_context(|| format!("dropping capability {bit} from the bounding set"))?;
        }
    }
    rustix::thread::set_no_new_privs(true).context("setting no_new_privs")?;

    let status = std::fs::read_to_string("/proc/thread-self/status")
        .context("reading /proc/thread-self/status")?;
    for field in ["CapInh", "CapBnd", "CapAmb"] {
        if !cap_set_is_empty(&status, field)? {
            bail!("{field} is not empty after dropping capabilities");
        }
    }
    Ok(())
}

/// Reap every child until the engine `pid` ends.
fn reap_until(pid: Pid) -> Result<EngineStatus> {
    loop {
        match waitpid(None, None) {
            Ok(status) if status.pid() == Some(pid) => {
                if let Some(status) = EngineStatus::from_wait(status) {
                    return Ok(status);
                }
            }
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(err) => return Err(err).context("waiting for the engine"),
        }
    }
}

/// Whether the hex capability set `field` (e.g. `CapBnd`) in
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

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::{cap_set_is_empty, ensure_guest};
    use crate::{Cli, Command};

    #[test]
    fn refuses_to_run_outside_a_libkrun_guest() {
        let err = ensure_guest().unwrap_err();
        assert!(err.to_string().contains("PID 1 is not init.krun"), "{err}");
    }

    #[test]
    fn subcommand_parses_and_is_hidden() {
        let cli = <Cli as clap::Parser>::try_parse_from(["gino-agent", "guest-init"]).unwrap();
        assert!(matches!(cli.command, Some(Command::GuestInit)));
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("guest-init"), "{help}");
    }

    #[test]
    fn cap_set_parsing() {
        let status = "CapInh:\t0000000000000000\nCapBnd:\t000001ffffffffff\n";
        assert!(cap_set_is_empty(status, "CapInh").unwrap());
        assert!(!cap_set_is_empty(status, "CapBnd").unwrap());
        assert!(cap_set_is_empty(status, "CapAmb").is_err());
        assert!(cap_set_is_empty("CapAmb:\tzz\n", "CapAmb").is_err());
    }
}
