//! Connection-scoped, bounded terminal sessions.

use std::collections::HashMap;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::{Pid, tcgetpgrp};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::info;

use super::{E2EE_DENIED, RemoteOps};
use crate::scheduler::Cancel;

const MAX_SESSIONS: usize = 8;
const MAX_BYTES: usize = 16 * 1024;
const INPUT_QUEUE: usize = 64;
const DRAIN_IDLE: Duration = Duration::from_millis(100);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Frame {
    #[serde(rename = "type")]
    kind: String,
    pty_id: String,
    #[serde(default)]
    data: Value,
}

impl Frame {
    /// Whether this frame opens a session.
    pub(crate) fn is_open(&self) -> bool {
        self.kind == "pty_open"
    }
}

pub(crate) fn parse(text: &str) -> Option<Frame> {
    if !text.contains("pty_") {
        return None;
    }
    serde_json::from_str::<Frame>(text).ok().filter(|frame| {
        matches!(
            frame.kind.as_str(),
            "pty_open" | "pty_input" | "pty_resize" | "pty_close"
        )
    })
}

#[derive(Debug, Default, Deserialize)]
struct Open {
    argv: Option<Vec<String>>,
    cwd: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct Size {
    cols: u16,
    rows: u16,
}

#[derive(Debug)]
enum Input {
    Bytes(Vec<u8>),
    Resize(Size),
}

#[derive(Debug)]
struct Stop {
    cancel: Cancel,
    /// Why the agent ended the session, when it was not an ordinary close.
    fault: OnceLock<(&'static str, &'static str)>,
}

#[derive(Debug)]
struct Session {
    input: mpsc::Sender<Input>,
    stop: Arc<Stop>,
    task: JoinHandle<()>,
}

/// Dropping the registry requests cleanup; shutdown also joins every worker.
#[derive(Debug, Default)]
pub(crate) struct Sessions {
    sessions: HashMap<String, Session>,
}

impl Sessions {
    /// Handle control frames in socket order; process IO never blocks the socket reader.
    pub(crate) fn handle(&mut self, frame: Frame, ops: &RemoteOps, output: &mpsc::Sender<String>) {
        self.sessions
            .retain(|_, session| !session.task.is_finished());
        let id = frame.pty_id;
        if id.is_empty() || id.len() > 128 {
            return;
        }
        if frame.kind == "pty_open" {
            if self.sessions.contains_key(&id) {
                // A duplicate open must never replace a live process.
                return;
            }
            let (enabled, workspace, epoch) = ops.pty_settings();
            let error = if !enabled {
                Some(("disabled", "Terminal operations are disabled"))
            } else if self.sessions.len() >= MAX_SESSIONS {
                Some(("limit", "Terminal session limit reached"))
            } else {
                None
            };
            if let Some((code, message)) = error {
                let _ = output.try_send(envelope("pty_exit", &id, failure(code, message)));
                return;
            }
            match spawn(&frame.data, &workspace) {
                Ok((pty, child)) => {
                    let (input, receive) = mpsc::channel(INPUT_QUEUE);
                    let stop = Arc::new(Stop {
                        cancel: Cancel::new(),
                        fault: OnceLock::new(),
                    });
                    let task = tokio::spawn(run(
                        id.clone(),
                        pty,
                        child,
                        receive,
                        output.clone(),
                        Arc::clone(&stop),
                        epoch,
                    ));
                    self.sessions.insert(id, Session { input, stop, task });
                }
                Err(error) => {
                    let _ = output.try_send(envelope(
                        "pty_exit",
                        &id,
                        failure("invalid", &error.to_string()),
                    ));
                }
            }
            return;
        }
        let Some(session) = self.sessions.get(&id) else {
            return;
        };
        if frame.kind == "pty_close" {
            session.stop.cancel.cancel();
            return;
        }
        let input = match frame.kind.as_str() {
            "pty_input" => decode_input(&frame.data).map(Input::Bytes),
            "pty_resize" => serde_json::from_value::<Size>(frame.data)
                .ok()
                .filter(|size| valid_size(size.cols, size.rows))
                .map(Input::Resize),
            _ => None,
        };
        let fault = match input.map(|input| session.input.try_send(input)) {
            None => ("invalid", "Malformed terminal input"),
            Some(Err(_)) => ("input_overflow", "Terminal input queue is full"),
            Some(Ok(())) => return,
        };
        let _ = session.stop.fault.set(fault);
        session.stop.cancel.cancel();
    }

    /// Refuse a `pty_open` while the runner holds an encrypted task.
    pub(crate) fn deny_open(&self, frame: &Frame, output: &mpsc::Sender<String>) {
        let id = &frame.pty_id;
        if id.is_empty() || id.len() > 128 || self.sessions.contains_key(id) {
            return;
        }
        info!(
            op = "pty_open",
            reason = "e2ee",
            "refused a remote operation"
        );
        let _ = output.try_send(envelope("pty_exit", id, failure("denied", E2EE_DENIED)));
    }

    /// Whether no session is running.
    pub(crate) fn is_idle(&self) -> bool {
        self.sessions
            .values()
            .all(|session| session.task.is_finished())
    }

    /// End every running session with `denied`: the runner now holds an
    /// encrypted task.
    pub(crate) fn deny_all(&mut self) {
        self.sessions
            .retain(|_, session| !session.task.is_finished());
        for session in self.sessions.values() {
            info!(op = "pty", reason = "e2ee", "closed a terminal session");
            let _ = session.stop.fault.set(("denied", E2EE_DENIED));
            session.stop.cancel.cancel();
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        for session in self.sessions.values() {
            session.stop.cancel.cancel();
        }
        for (_, session) in self.sessions.drain() {
            let _ = session.task.await;
        }
    }
}

impl Drop for Sessions {
    fn drop(&mut self) {
        for session in self.sessions.values() {
            session.stop.cancel.cancel();
        }
    }
}

fn valid_size(cols: u16, rows: u16) -> bool {
    (1..=1000).contains(&cols) && (1..=1000).contains(&rows)
}

fn decode_input(data: &Value) -> Option<Vec<u8>> {
    let encoded = data.get("data")?.as_str()?;
    if encoded.len() > 21848 {
        return None;
    }
    STANDARD
        .decode(encoded)
        .ok()
        .filter(|bytes| bytes.len() <= MAX_BYTES)
}

fn spawn(
    data: &Value,
    workspace: &Path,
) -> anyhow::Result<(pty_process::Pty, tokio::process::Child)> {
    anyhow::ensure!(
        data.to_string().len() <= 65536,
        "Terminal options exceed 64 KiB"
    );
    let opts: Open = serde_json::from_value(data.clone())?;
    let cols = opts.cols.unwrap_or(80);
    let rows = opts.rows.unwrap_or(24);
    anyhow::ensure!(valid_size(cols, rows), "Invalid terminal dimensions");
    let argv = opts.argv.unwrap_or_else(|| vec!["/bin/sh".to_owned()]);
    anyhow::ensure!(
        !argv.is_empty() && argv.len() <= 64,
        "Invalid terminal argv"
    );
    anyhow::ensure!(opts.env.len() <= 64, "Too many environment entries");
    let cwd = opts
        .cwd
        .map_or_else(|| workspace.to_path_buf(), |cwd| workspace.join(cwd));
    let (pty, pts) = pty_process::open()?;
    pty.resize(pty_process::Size::new(rows, cols))?;
    let command = pty_process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(std::env::vars_os().filter(|(name, _)| {
            let name = name.to_string_lossy();
            matches!(
                name.as_ref(),
                "PATH" | "HOME" | "USER" | "LOGNAME" | "LANG" | "TERM" | "COLORTERM"
            ) || name.starts_with("LC_")
        }))
        .env("TERM", "xterm-256color")
        .envs(opts.env)
        .kill_on_drop(true);
    Ok((pty, command.spawn(pts)?))
}

fn envelope(kind: &str, id: &str, data: Value) -> String {
    let mut frame = json!({ "type": kind, "ptyId": id });
    frame["data"] = data;
    frame.to_string()
}

fn failure(code: &str, message: &str) -> Value {
    json!({ "error": { "code": code, "message": message } })
}

async fn emit(output: &mpsc::Sender<String>, kind: &str, id: &str, data: Value) -> bool {
    matches!(
        tokio::time::timeout(IO_TIMEOUT, output.send(envelope(kind, id, data))).await,
        Ok(Ok(()))
    )
}

async fn drain(
    pty: &mut pty_process::Pty,
    output: &mpsc::Sender<String>,
    id: &str,
    natural_exit: bool,
    buffer: &mut [u8],
) -> bool {
    // A child can exit before its final bytes are read; they are already
    // buffered, so an idle read ends the drain even while a descendant still
    // holds the terminal. The deadline bounds a stalled remote consumer.
    let deadline = if natural_exit {
        IO_TIMEOUT
    } else {
        Duration::from_millis(200)
    };
    let drained = tokio::time::timeout(deadline, async {
        while let Ok(Ok(size)) = tokio::time::timeout(DRAIN_IDLE, pty.read(buffer)).await {
            if size == 0 {
                return true;
            }
            if !emit(
                output,
                "pty_output",
                id,
                json!({ "data": STANDARD.encode(&buffer[..size]) }),
            )
            .await
            {
                return false;
            }
        }
        true
    })
    .await;
    matches!(drained, Ok(true))
}

fn exit_result(status: ExitStatus, drained: bool) -> Value {
    let mut result = json!({});
    if let Some(code) = status.code() {
        result["exit_code"] = json!(code);
    }
    if let Some(signal) = status.signal() {
        result["signal"] = json!(signal);
    }
    if !drained {
        result["error"] = failure(
            "slow_consumer",
            "Final terminal output could not be drained",
        )["error"]
            .clone();
    }
    result
}

async fn run(
    id: String,
    mut pty: pty_process::Pty,
    mut child: tokio::process::Child,
    mut input: mpsc::Receiver<Input>,
    output: mpsc::Sender<String>,
    stop: Arc<Stop>,
    mut epoch: watch::Receiver<u64>,
) {
    let pid = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(Pid::from_raw);
    let mut status: Option<ExitStatus> = None;
    let mut result = failure("closed", "Terminal closed");
    let mut buffer = [0_u8; MAX_BYTES];
    if !emit(&output, "pty_ready", &id, json!({})).await {
        stop.cancel.cancel();
    }
    loop {
        tokio::select! {
            biased;
            () = stop.cancel.cancelled() => break,
            _ = epoch.changed() => {
                result = failure("disabled", "Terminal operations were disabled");
                break;
            }
            waited = child.wait() => {
                match waited {
                    Ok(exit) => status = Some(exit),
                    Err(error) => result = failure("io", &error.to_string()),
                }
                break;
            }
            command = input.recv() => {
                let outcome = match command {
                    Some(Input::Bytes(bytes)) => tokio::time::timeout(IO_TIMEOUT, pty.write_all(&bytes)).await
                        .unwrap_or_else(|_| Err(std::io::Error::other("Terminal input timed out"))),
                    Some(Input::Resize(size)) => pty.resize(pty_process::Size::new(size.rows, size.cols)).map_err(std::io::Error::other),
                    None => break,
                };
                if let Err(error) = outcome {
                    result = failure("io", &error.to_string());
                    break;
                }
            }
            read = pty.read(&mut buffer) => {
                match read {
                    Ok(0) => {
                        status = tokio::time::timeout(Duration::from_millis(100), child.wait()).await.ok().and_then(Result::ok);
                        break;
                    },
                    Ok(size) => {
                        tokio::select! {
                            biased;
                            () = stop.cancel.cancelled() => break,
                            _ = epoch.changed() => {
                                result = failure("disabled", "Terminal operations were disabled");
                                break;
                            }
                            sent = emit(&output, "pty_output", &id, json!({ "data": STANDARD.encode(&buffer[..size]) })) => {
                                if !sent {
                                    result = failure("slow_consumer", "Terminal output stalled");
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => {
                        // Linux reports EIO once the slave terminal closes.
                        status = tokio::time::timeout(Duration::from_millis(100), child.wait()).await.ok().and_then(Result::ok);
                        break;
                    }
                    Err(error) => {
                        result = failure("io", &error.to_string());
                        break;
                    }
                }
            }
        }
    }
    // Foreground jobs can have a different process group from their shell.
    if let Ok(foreground) = tcgetpgrp(&pty)
        && foreground.as_raw() > 0
    {
        let _ = killpg(foreground, Signal::SIGKILL);
    }
    if let Some(pid) = pid {
        let _ = killpg(pid, Signal::SIGKILL);
    }
    if status.is_none() {
        let _ = child.kill().await;
    }
    let drained = drain(&mut pty, &output, &id, status.is_some(), &mut buffer).await;
    drop(pty);
    if let Some(exit) = status {
        result = exit_result(exit, drained);
    } else if let Some((code, message)) = stop.fault.get() {
        result = failure(code, message);
    }
    let _ = emit(&output, "pty_exit", &id, result).await;
}

#[cfg(test)]
mod tests;
