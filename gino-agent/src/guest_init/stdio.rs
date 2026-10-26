//! The engine's stdio: pipes relayed to and from the guest console.
//!
//! An engine inheriting the console directly does not work: the real `claude`
//! CLI's stream-json output never reaches the host that way. guest-init gives
//! the engine plain pipes and relays them byte for byte. A terminal console is
//! switched to raw mode first, so its line discipline neither echoes the
//! daemon's input nor rewrites bytes. The relays use plain reads and writes:
//! `std::io::copy` would splice, which the guest's virtio console rejects.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::process::Child;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};

/// Put the terminal `fd` into raw mode; a non-terminal is left alone.
pub(super) fn raw_console(fd: impl AsFd) -> Result<()> {
    let mut attrs = match tcgetattr(fd.as_fd()) {
        Ok(attrs) => attrs,
        Err(Errno::ENOTTY) => return Ok(()),
        Err(err) => return Err(err).context("reading the console's terminal attributes"),
    };
    cfmakeraw(&mut attrs);
    tcsetattr(fd.as_fd(), SetArg::TCSANOW, &attrs).context("setting the console to raw mode")
}

/// The console's stdin, stdout and stderr, as unbuffered files.
pub(super) struct Console {
    pub(super) input: File,
    pub(super) output: File,
    pub(super) error: File,
}

impl Console {
    /// Duplicates of this process's stdio descriptors.
    pub(super) fn current() -> Result<Self> {
        let dup = |fd: std::os::fd::BorrowedFd<'_>| -> Result<File> {
            Ok(File::from(
                fd.try_clone_to_owned().context("duplicating stdio")?,
            ))
        };
        Ok(Self {
            input: dup(std::io::stdin().as_fd())?,
            output: dup(std::io::stdout().as_fd())?,
            error: dup(std::io::stderr().as_fd())?,
        })
    }
}

/// The running relays of one engine's piped stdio.
pub(super) struct Relay {
    done: mpsc::Receiver<()>,
    outputs: usize,
}

impl Relay {
    /// Take `child`'s piped stdio and relay it to and from `console`. The
    /// input relay closes the engine's stdin when the console input ends; it
    /// is not waited for.
    pub(super) fn start(child: &mut Child, console: Console) -> Self {
        let (tx, done) = mpsc::channel();
        if let Some(mut stdin) = child.stdin.take() {
            let mut input = console.input;
            std::thread::spawn(move || {
                let _ = copy(&mut input, &mut stdin);
            });
        }
        let mut outputs = 0;
        if let Some(stdout) = child.stdout.take() {
            outputs += 1;
            spawn_output(stdout, console.output, tx.clone());
        }
        if let Some(stderr) = child.stderr.take() {
            outputs += 1;
            spawn_output(stderr, console.error, tx);
        }
        Self { done, outputs }
    }

    /// Wait up to `timeout` for the engine's stdout and stderr to reach end of
    /// file and be written to the console.
    pub(super) fn finish(self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        for _ in 0..self.outputs {
            let left = deadline.saturating_duration_since(Instant::now());
            if self.done.recv_timeout(left).is_err() {
                return;
            }
        }
    }
}

/// Copy `from` to `to` until end of file, chunk by chunk.
fn copy(from: &mut impl Read, to: &mut impl Write) -> std::io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => to.write_all(&buf[..n])?,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

fn spawn_output<R: Read + Send + 'static>(mut from: R, mut to: File, done: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        if let Err(err) = copy(&mut from, &mut to) {
            let _ = writeln!(
                std::io::stderr(),
                "guest-init: relaying engine output: {err}"
            );
        }
        let _ = to.flush();
        let _ = done.send(());
    });
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::os::fd::OwnedFd;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use nix::sys::termios::{LocalFlags, OutputFlags, tcgetattr};

    use super::{Console, Relay, raw_console};

    #[test]
    fn raw_console_clears_echo_canonical_mode_and_output_processing() {
        let pty = nix::pty::openpty(None, None).unwrap();
        raw_console(&pty.slave).unwrap();
        let attrs = tcgetattr(&pty.slave).unwrap();
        assert!(!attrs.local_flags.contains(LocalFlags::ECHO));
        assert!(!attrs.local_flags.contains(LocalFlags::ICANON));
        assert!(!attrs.local_flags.contains(LocalFlags::ISIG));
        assert!(!attrs.output_flags.contains(OutputFlags::OPOST));
    }

    #[test]
    fn raw_console_leaves_a_non_terminal_alone() {
        let (reader, _writer) = std::io::pipe().unwrap();
        raw_console(&reader).unwrap();
    }

    #[test]
    fn relay_gives_the_engine_pipes_and_copies_every_byte() {
        let (input, mut feed) = std::io::pipe().unwrap();
        let (mut out_reader, output) = std::io::pipe().unwrap();
        let (mut err_reader, error) = std::io::pipe().unwrap();
        let console = Console {
            input: File::from(OwnedFd::from(input)),
            output: File::from(OwnedFd::from(output)),
            error: File::from(OwnedFd::from(error)),
        };
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(r#"[ -t 0 ] && echo tty || echo notty; IFS= read -r line; printf '%s\n' "got:$line"; echo oops >&2"#)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let relay = Relay::start(&mut child, console);
        let long = "x".repeat(10_000);
        feed.write_all(format!("{long}\n").as_bytes()).unwrap();
        child.wait().unwrap();
        relay.finish(Duration::from_secs(5));

        let mut out = String::new();
        out_reader.read_to_string(&mut out).unwrap();
        assert_eq!(out, format!("notty\ngot:{long}\n"));
        let mut err = String::new();
        err_reader.read_to_string(&mut err).unwrap();
        assert_eq!(err, "oops\n");
    }
}
