//! gino-vmm: boots one libkrun microVM from a JSON run spec on stdin.
//!
//! The spec is the first line of stdin; the rest of stdin, stdout and stderr are the guest's
//! implicit console. On success the process exits with the guest workload's status (libkrun
//! calls `exit` when the VM shuts down); on a spec or configuration error it prints the error to
//! stderr and exits with [`VMM_FAILURE`]. libkrun is compiled into this binary.
//!
//! `gino-vmm --probe` only checks that `/dev/kvm` opens read-write and prints
//! `gino-vmm <version> libkrun <libkrun version>`, then exits 0.

mod ffi;
mod spec;
mod version;
mod vm;

use std::convert::Infallible;
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::AsFd;
use std::process::ExitCode;

use crate::spec::RunSpec;

/// Exit status for errors before the guest runs. Distinct from libkrun's init codes
/// (125 setup failed, 126 not executable, 127 not found).
const VMM_FAILURE: u8 = 120;
const USAGE: &str = "usage: gino-vmm < spec.json | gino-vmm --probe";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Boot the VM described by the spec on stdin.
    Run,
    /// Check KVM access and report the versions, without starting a VM.
    Probe,
}

fn main() -> ExitCode {
    let result = parse_args(std::env::args_os().skip(1)).and_then(|command| match command {
        Command::Run => run().map(|never| match never {}),
        Command::Probe => probe(),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("gino-vmm: {err}");
            ExitCode::from(VMM_FAILURE)
        }
    }
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args.into_iter().map(|arg| {
        arg.into_string()
            .map_err(|arg| format!("argument {} is not UTF-8; {USAGE}", arg.display()))
    });
    match args.next().transpose()?.as_deref() {
        None => return Ok(Command::Run),
        Some("--probe") => {}
        Some(other) => return Err(format!("unexpected argument {other:?}; {USAGE}")),
    }
    match args.next().transpose()? {
        None => Ok(Command::Probe),
        Some(other) => Err(format!("unexpected argument {other:?}; {USAGE}")),
    }
}

fn probe() -> Result<(), String> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|e| format!("/dev/kvm: {e}"))?;
    println!(
        "gino-vmm {} libkrun {}",
        env!("CARGO_PKG_VERSION"),
        version::LIBKRUN_VERSION
    );
    Ok(())
}

fn run() -> Result<Infallible, String> {
    let parent = std::os::unix::process::parent_id();
    ffi::set_parent_death_signal()?;
    if std::os::unix::process::parent_id() != parent {
        return Err("parent exited during startup".to_owned());
    }

    // An unbuffered handle so only the spec line is consumed.
    let mut stdin = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(File::from)
        .map_err(|e| format!("stdin: {e}"))?;
    let spec = RunSpec::parse(&spec::read_line(&mut stdin)?)?;
    drop(stdin);
    spec.check_host_paths()?;

    vm::start(&spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_args(args.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_run_a_vm() {
        assert_eq!(parse(&[]), Ok(Command::Run));
    }

    #[test]
    fn probe_takes_no_arguments() {
        assert_eq!(parse(&["--probe"]), Ok(Command::Probe));
    }

    #[test]
    fn other_arguments_are_rejected() {
        for args in [
            &["spec.json"][..],
            &["--libkrun", "/x"],
            &["--probe", "extra"],
            &["--probe", "--libkrun", "/x"],
            &["--probe", "--probe"],
        ] {
            let err = parse(args).unwrap_err();
            assert!(err.contains("usage: gino-vmm"), "{args:?}: {err}");
        }
    }
}
