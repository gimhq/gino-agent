//! Engine installs managed by the agent: `gino-agent engine status|install|update`.
//!
//! The vendors' official installers run with `HOME` set to the engine home
//! (`<workspace>/engines/home`), so each engine lands in its `.local/bin`.
//! Runs prefer that install over `PATH` (an explicitly configured binary wins).

use std::ffi::OsStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

/// The engine home inside the workspace dir.
const ENGINES_HOME: &str = "engines/home";
/// Where the installers put their binaries, relative to the engine home.
const BIN_DIR: &str = ".local/bin";
const CLAUDE_INSTALLER: &str = "https://claude.ai/install.sh";
const CODEX_INSTALLER: &str = "https://chatgpt.com/codex/install.sh";
/// Bound on `<engine> --version`.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// An engine the agent can install.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum EngineKind {
    Claude,
    Codex,
}

impl EngineKind {
    pub(crate) const ALL: [Self; 2] = [Self::Claude, Self::Codex];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

/// The engine home: `HOME` of the installers.
pub(crate) fn engines_home(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join(ENGINES_HOME)
}

/// The agent-managed binary of `kind`, whether installed or not.
pub(crate) fn managed_binary(workspace_dir: &Path, kind: EngineKind) -> PathBuf {
    engines_home(workspace_dir).join(BIN_DIR).join(kind.name())
}

/// The binary a run of `kind` starts: `explicit` when configured, else the
/// agent-managed install when present, else the bare name on `PATH`.
pub(crate) fn resolve_binary(
    workspace_dir: &Path,
    kind: EngineKind,
    explicit: Option<&Path>,
) -> PathBuf {
    if let Some(binary) = explicit {
        return binary.to_path_buf();
    }
    let managed = managed_binary(workspace_dir, kind);
    if is_executable_file(&managed) {
        managed
    } else {
        PathBuf::from(kind.name())
    }
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// `gino-agent engine …`.
#[derive(clap::Subcommand)]
pub(crate) enum EngineCommand {
    /// Show each engine's binary and version.
    Status,
    /// Install an engine with its official installer into `<workspace>/engines`.
    Install {
        engine: EngineKind,
        /// Release version to install.
        #[arg(long, conflicts_with = "channel")]
        version: Option<String>,
        /// Release channel (claude only): `stable` or `latest`.
        #[arg(long)]
        channel: Option<String>,
    },
    /// Update agent-installed engines (all of them without an argument).
    Update { engine: Option<EngineKind> },
}

/// Run an `engine` subcommand against `workspace_dir`.
pub(crate) fn command(workspace_dir: &Path, command: EngineCommand) -> Result<()> {
    match command {
        EngineCommand::Status => status(workspace_dir),
        EngineCommand::Install {
            engine,
            version,
            channel,
        } => {
            let target = match (version, channel) {
                (Some(version), _) => Target::Version(version),
                (None, Some(channel)) => Target::Channel(channel),
                (None, None) => Target::Default,
            };
            install(workspace_dir, engine, &target)?;
        }
        EngineCommand::Update { engine: Some(kind) } => update(workspace_dir, kind)?,
        EngineCommand::Update { engine: None } => {
            let installed: Vec<_> = EngineKind::ALL
                .into_iter()
                .filter(|kind| is_executable_file(&managed_binary(workspace_dir, *kind)))
                .collect();
            ensure!(
                !installed.is_empty(),
                "no engine is installed in {}",
                engines_home(workspace_dir).display()
            );
            for kind in installed {
                update(workspace_dir, kind)?;
            }
        }
    }
    Ok(())
}

/// What `install` asks the installer for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// The installer's default.
    Default,
    /// A release version.
    Version(String),
    /// A claude release channel (`stable` or `latest`).
    Channel(String),
}

/// A shell command line passed to `bash -c`.
fn installer_script(kind: EngineKind, target: &Target) -> Result<String> {
    let arg = match target {
        Target::Default => None,
        Target::Version(version) => Some(version),
        Target::Channel(channel) => {
            ensure!(
                kind == EngineKind::Claude,
                "codex has no release channels; pass --version"
            );
            ensure!(
                matches!(channel.as_str(), "stable" | "latest"),
                "channel `{channel}` is neither `stable` nor `latest`"
            );
            Some(channel)
        }
    };
    if let Some(arg) = arg {
        ensure!(
            !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')),
            "`{arg}` is not a version or channel"
        );
    }
    Ok(match (kind, arg) {
        (EngineKind::Claude, None) => format!("curl -fsSL {CLAUDE_INSTALLER} | bash"),
        (EngineKind::Claude, Some(arg)) => {
            format!("curl -fsSL {CLAUDE_INSTALLER} | bash -s -- {arg}")
        }
        (EngineKind::Codex, None) => format!("curl -fsSL {CODEX_INSTALLER} | sh"),
        (EngineKind::Codex, Some(arg)) => {
            format!("curl -fsSL {CODEX_INSTALLER} | sh -s -- --release {arg}")
        }
    })
}

/// The command `install` runs for `kind`.
fn install_command(workspace_dir: &Path, kind: EngineKind, target: &Target) -> Result<Command> {
    let mut command = Command::new("bash");
    command
        .arg("-o")
        .arg("pipefail")
        .arg("-c")
        .arg(installer_script(kind, target)?);
    Ok(installer_env(command, workspace_dir))
}

/// The command `update` runs: claude updates itself, codex reruns its installer.
fn update_command(workspace_dir: &Path, kind: EngineKind) -> Result<Command> {
    match kind {
        EngineKind::Claude => {
            let mut command = Command::new(managed_binary(workspace_dir, kind));
            command.arg("update");
            Ok(installer_env(command, workspace_dir))
        }
        EngineKind::Codex => install_command(workspace_dir, kind, &Target::Default),
    }
}

fn installer_env(mut command: Command, workspace_dir: &Path) -> Command {
    command
        .env("HOME", engines_home(workspace_dir))
        .env("CODEX_NON_INTERACTIVE", "1")
        .stdin(Stdio::null());
    command
}

/// Install `kind` into the engine home and print its version.
fn install(workspace_dir: &Path, kind: EngineKind, target: &Target) -> Result<()> {
    std::fs::create_dir_all(engines_home(workspace_dir))
        .with_context(|| format!("creating {}", engines_home(workspace_dir).display()))?;
    run(
        install_command(workspace_dir, kind, target)?,
        kind,
        "install",
    )?;
    verify(workspace_dir, kind)
}

/// Update the agent-managed install of `kind` and print its version.
fn update(workspace_dir: &Path, kind: EngineKind) -> Result<()> {
    ensure!(
        is_executable_file(&managed_binary(workspace_dir, kind)),
        "{} is not installed in {}; run `gino-agent engine install {}`",
        kind.name(),
        engines_home(workspace_dir).display(),
        kind.name()
    );
    run(update_command(workspace_dir, kind)?, kind, "update")?;
    verify(workspace_dir, kind)
}

fn run(mut command: Command, kind: EngineKind, what: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("running the {} {what}", kind.name()))?;
    ensure!(
        status.success(),
        "the {} {what} failed ({status})",
        kind.name()
    );
    Ok(())
}

fn verify(workspace_dir: &Path, kind: EngineKind) -> Result<()> {
    let binary = managed_binary(workspace_dir, kind);
    match version(&binary) {
        Some(version) => {
            println!("{} {version} at {}", kind.name(), binary.display());
            Ok(())
        }
        None => bail!(
            "{} does not report a version after the install",
            binary.display()
        ),
    }
}

/// One engine as the agent would run it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EngineInfo {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) version: Option<String>,
    pub(crate) path: String,
}

/// The engines in `binaries` that resolve to an executable, with their versions.
pub(crate) fn report<'a>(
    binaries: impl IntoIterator<Item = (EngineKind, &'a Path)>,
    path_env: Option<&OsStr>,
) -> Vec<EngineInfo> {
    binaries
        .into_iter()
        .filter_map(|(kind, binary)| {
            let path = crate::sandbox::bwrap::resolve_binary(binary, path_env)?;
            Some(EngineInfo {
                name: kind.name().to_owned(),
                version: version(&path),
                path: path.display().to_string(),
            })
        })
        .collect()
}

/// Print every engine's binary (without a host-configured one) and version.
fn status(workspace_dir: &Path) {
    let binaries = EngineKind::ALL.map(|kind| (kind, resolve_binary(workspace_dir, kind, None)));
    let path_env = std::env::var_os("PATH");
    let found = report(
        binaries.iter().map(|(kind, path)| (*kind, path.as_path())),
        path_env.as_deref(),
    );
    for (kind, _) in &binaries {
        match found.iter().find(|info| info.name == kind.name()) {
            Some(info) => println!(
                "{}\t{}\t{}",
                info.name,
                info.version.as_deref().unwrap_or("?"),
                info.path
            ),
            None => println!("{}\tnot installed", kind.name()),
        }
    }
}

/// `<binary> --version`, reduced to its first token starting with a digit.
fn version(binary: &Path) -> Option<String> {
    let mut child = Command::new(binary)
        .arg("--version")
        .env("DISABLE_AUTOUPDATER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let status = wait_bounded(&mut child)?;
    let mut out = String::new();
    child
        .stdout
        .take()?
        .take(4096)
        .read_to_string(&mut out)
        .ok()?;
    status.success().then(|| parse_version(&out)).flatten()
}

fn wait_bounded(child: &mut std::process::Child) -> Option<ExitStatus> {
    let deadline = Instant::now() + VERSION_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn parse_version(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .find(|word| word.starts_with(|c: char| c.is_ascii_digit()))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn executable(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn explicit_then_managed_then_path() {
        let ws = tempfile::tempdir().unwrap();
        let explicit = Path::new("/opt/codex");
        assert_eq!(
            resolve_binary(ws.path(), EngineKind::Codex, Some(explicit)),
            explicit
        );
        assert_eq!(
            resolve_binary(ws.path(), EngineKind::Claude, None),
            Path::new("claude")
        );
        let managed = ws.path().join("engines/home/.local/bin/claude");
        executable(&managed, "#!/bin/sh\n");
        assert_eq!(resolve_binary(ws.path(), EngineKind::Claude, None), managed);
    }

    #[test]
    fn installer_scripts_pass_only_plain_versions_and_channels() {
        let script = |kind, target| installer_script(kind, &target);
        assert_eq!(
            script(EngineKind::Claude, Target::Default).unwrap(),
            "curl -fsSL https://claude.ai/install.sh | bash"
        );
        assert_eq!(
            script(EngineKind::Claude, Target::Channel("stable".into())).unwrap(),
            "curl -fsSL https://claude.ai/install.sh | bash -s -- stable"
        );
        assert_eq!(
            script(EngineKind::Codex, Target::Version("0.156.1".into())).unwrap(),
            "curl -fsSL https://chatgpt.com/codex/install.sh | sh -s -- --release 0.156.1"
        );
        for bad in ["1.0; rm -rf /", "$(id)", ""] {
            assert!(script(EngineKind::Claude, Target::Version(bad.into())).is_err());
        }
        assert!(script(EngineKind::Codex, Target::Channel("latest".into())).is_err());
        assert!(script(EngineKind::Claude, Target::Channel("beta".into())).is_err());
    }

    #[test]
    fn commands_run_with_the_engine_home() {
        let ws = Path::new("/ws");
        let command = update_command(ws, EngineKind::Claude).unwrap();
        assert_eq!(command.get_program(), "/ws/engines/home/.local/bin/claude");
        assert_eq!(command.get_args().collect::<Vec<_>>(), ["update"]);
        let home = command
            .get_envs()
            .find(|(key, _)| *key == "HOME")
            .and_then(|(_, value)| value);
        assert_eq!(home, Some(OsStr::new("/ws/engines/home")));
        let command = update_command(ws, EngineKind::Codex).unwrap();
        assert_eq!(command.get_program(), "bash");
    }

    #[test]
    fn report_lists_found_engines_with_versions() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join("claude");
        executable(&claude, "#!/bin/sh\necho '2.1.310 (Claude Code)'\n");
        let missing = dir.path().join("codex");
        let found = report(
            [
                (EngineKind::Claude, claude.as_path()),
                (EngineKind::Codex, missing.as_path()),
            ],
            None,
        );
        assert_eq!(
            found,
            [EngineInfo {
                name: "claude".into(),
                version: Some("2.1.310".into()),
                path: claude.display().to_string(),
            }]
        );
    }

    #[test]
    fn versions_are_the_first_numeric_word() {
        assert_eq!(
            parse_version("codex-cli 0.156.1\n").as_deref(),
            Some("0.156.1")
        );
        assert_eq!(
            parse_version("2.1.310 (Claude Code)").as_deref(),
            Some("2.1.310")
        );
        assert_eq!(parse_version("no version"), None);
    }
}
