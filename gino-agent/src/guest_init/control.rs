//! Control channel to the daemon: a line protocol on a vsock connection the
//! host opens.
//!
//! daemon → guest: `SIGNAL INT|TERM|KILL`, delivered to the engine's process
//! group. guest → daemon: `READY` once the engine runs, `EXIT <code>` or
//! `EXIT signal <n>` when it ends. A daemon connecting late gets the lines
//! already due; a newer connection replaces an older one.

use std::fs::File;
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

use super::net::vsock_accept;

/// How the engine ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EngineStatus {
    Exited(i32),
    Signaled(i32),
}

impl EngineStatus {
    /// The engine's status from a `waitpid` result, if it ended.
    pub(super) fn from_wait(status: WaitStatus) -> Option<Self> {
        match status {
            WaitStatus::Exited(_, code) => Some(Self::Exited(code)),
            WaitStatus::Signaled(_, signal, _) => Some(Self::Signaled(signal as i32)),
            _ => None,
        }
    }

    /// The `EXIT` protocol line (without newline).
    pub(super) fn exit_line(self) -> String {
        match self {
            Self::Exited(code) => format!("EXIT {code}"),
            Self::Signaled(signal) => format!("EXIT signal {signal}"),
        }
    }

    /// guest-init's own exit code, which libkrun's init turns into the VMM's
    /// exit status: the engine's code, or 128 + signal number.
    pub(super) fn exit_code(self) -> i32 {
        match self {
            Self::Exited(code) => code,
            Self::Signaled(signal) => 128 + signal,
        }
    }
}

/// The signal a daemon line requests, or `None` for anything else.
pub(super) fn parse_signal_line(line: &str) -> Option<Signal> {
    match line.trim_end_matches('\r') {
        "SIGNAL INT" => Some(Signal::SIGINT),
        "SIGNAL TERM" => Some(Signal::SIGTERM),
        "SIGNAL KILL" => Some(Signal::SIGKILL),
        _ => None,
    }
}

#[derive(Debug, Default)]
struct State {
    conn: Option<File>,
    engine_pgid: Option<Pid>,
    ready: bool,
    exit: Option<String>,
    exit_sent: bool,
    peer_closed: bool,
}

/// Shared control-channel state.
#[derive(Debug, Default)]
pub(super) struct Control {
    state: Mutex<State>,
    changed: Condvar,
}

impl Control {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Accept daemon connections on `listener` for the rest of the process.
    pub(super) fn serve(self: &Arc<Self>, listener: OwnedFd) -> Result<()> {
        let control = Arc::clone(self);
        std::thread::Builder::new()
            .name("control".into())
            .spawn(move || {
                loop {
                    match vsock_accept(&listener) {
                        Ok(conn) => control.attach(conn),
                        Err(err) => eprintln!("guest-init: {err:#}"),
                    }
                }
            })
            .context("spawning control thread")?;
        Ok(())
    }

    fn attach(self: &Arc<Self>, conn: File) {
        let reader = match conn.try_clone() {
            Ok(reader) => reader,
            Err(err) => {
                eprintln!("guest-init: cloning control connection: {err}");
                return;
            }
        };
        {
            let mut state = self.lock();
            state.conn = Some(conn);
            state.peer_closed = false;
            if state.ready {
                send_locked(&mut state, "READY");
            }
            if let Some(exit) = state.exit.clone()
                && send_locked(&mut state, &exit)
            {
                state.exit_sent = true;
            }
        }
        self.changed.notify_all();
        let control = Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("control-read".into())
            .spawn(move || control.read(reader));
        if let Err(err) = spawned {
            eprintln!("guest-init: spawning control reader: {err}");
        }
    }

    fn read(&self, conn: File) {
        for line in BufReader::new(conn).lines() {
            let Ok(line) = line else { break };
            let Some(signal) = parse_signal_line(&line) else {
                eprintln!("guest-init: ignoring control line `{line}`");
                continue;
            };
            match self.lock().engine_pgid {
                Some(pgid) => {
                    if let Err(err) = nix::sys::signal::killpg(pgid, signal) {
                        eprintln!("guest-init: sending {signal} to the engine: {err}");
                    }
                }
                None => eprintln!("guest-init: no engine to send {signal} to"),
            }
        }
        self.lock().peer_closed = true;
        self.changed.notify_all();
    }

    /// Record the running engine and send `READY`.
    pub(super) fn engine_started(&self, pgid: Pid) {
        let mut state = self.lock();
        state.engine_pgid = Some(pgid);
        state.ready = true;
        send_locked(&mut state, "READY");
    }

    /// Send the `EXIT` line, half-close, and wait up to `timeout` for a daemon
    /// to receive it and close its end, so the line leaves the guest before
    /// the VM powers off.
    pub(super) fn engine_exited(&self, status: EngineStatus, timeout: Duration) {
        let line = status.exit_line();
        let mut state = self.lock();
        state.exit = Some(line.clone());
        if send_locked(&mut state, &line) {
            state.exit_sent = true;
        }
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |s| !s.exit_sent)
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(conn) = &state.conn {
            let _ = rustix::net::shutdown(conn, rustix::net::Shutdown::Write);
        }
        if state.exit_sent {
            let _ = self
                .changed
                .wait_timeout_while(state, timeout, |s| !s.peer_closed)
                .unwrap_or_else(PoisonError::into_inner);
        } else {
            eprintln!("guest-init: no daemon connection to report `{line}` to");
        }
    }
}

/// Write one line to the current connection; drop the connection on error.
fn send_locked(state: &mut State, line: &str) -> bool {
    let Some(conn) = state.conn.as_mut() else {
        return false;
    };
    match conn.write_all(format!("{line}\n").as_bytes()) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("guest-init: writing control line `{line}`: {err}");
            state.conn = None;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::Pid;

    use super::{EngineStatus, parse_signal_line};

    #[test]
    fn signal_lines_map_to_signals() {
        assert_eq!(parse_signal_line("SIGNAL INT"), Some(Signal::SIGINT));
        assert_eq!(parse_signal_line("SIGNAL TERM"), Some(Signal::SIGTERM));
        assert_eq!(parse_signal_line("SIGNAL KILL\r"), Some(Signal::SIGKILL));
        for line in [
            "",
            "SIGNAL",
            "SIGNAL HUP",
            "signal int",
            " SIGNAL INT",
            "SIGNAL INT x",
        ] {
            assert_eq!(parse_signal_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn exit_status_encoding() {
        let pid = Pid::from_raw(42);
        let exited = EngineStatus::from_wait(WaitStatus::Exited(pid, 3)).unwrap();
        assert_eq!(
            (exited.exit_line(), exited.exit_code()),
            ("EXIT 3".into(), 3)
        );
        let ok = EngineStatus::Exited(0);
        assert_eq!((ok.exit_line(), ok.exit_code()), ("EXIT 0".into(), 0));
        let killed =
            EngineStatus::from_wait(WaitStatus::Signaled(pid, Signal::SIGKILL, false)).unwrap();
        assert_eq!(
            (killed.exit_line(), killed.exit_code()),
            ("EXIT signal 9".into(), 137)
        );
        assert_eq!(
            EngineStatus::from_wait(WaitStatus::Stopped(pid, Signal::SIGSTOP)),
            None
        );
        assert_eq!(EngineStatus::from_wait(WaitStatus::StillAlive), None);
    }
}
