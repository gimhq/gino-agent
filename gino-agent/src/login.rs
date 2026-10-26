//! `gino-agent login` — mint a long-lived Claude OAuth token for the engine and
//! store it where the daemon reads it.
//!
//! The engine child always runs with `CLAUDE_CONFIG_DIR` pointed at the runner's
//! provisioned config dir, so an operator's `~/.claude` login is invisible to it,
//! and the only other credential source is the host config overlay. This
//! subcommand closes that gap without host involvement: it runs the interactive
//! `claude setup-token` flow (browser authorization, one-year token) under the
//! engine's config dir, has the operator paste the printed token back, and
//! persists it (mode 0600) as `{workspace}/claude-oauth-token`.
//!
//! On startup the daemon folds that file into the engine config as
//! `CLAUDE_CODE_OAUTH_TOKEN` *below* the host layers, so a host-supplied
//! credential still wins when one is configured.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::Paths;
use crate::db::harden_state_dir;

/// The token file inside the workspace dir.
pub(crate) const TOKEN_FILE: &str = "claude-oauth-token";

/// `{workspace}/claude-oauth-token`.
pub(crate) fn token_path(workspace_dir: &Path) -> PathBuf {
    workspace_dir.join(TOKEN_FILE)
}

/// The stored token, trimmed; `None` when the file is absent or blank.
pub(crate) fn read_token(workspace_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(token_path(workspace_dir)).ok()?;
    let token = raw.trim();
    (!token.is_empty()).then(|| token.to_owned())
}

/// Persist `token` (mode 0600 inside the 0700 workspace dir). Rejects a blank token.
pub(crate) fn write_token(workspace_dir: &Path, token: &str) -> Result<PathBuf> {
    let token = token.trim();
    if token.is_empty() {
        bail!("empty token");
    }
    std::fs::create_dir_all(workspace_dir)
        .with_context(|| format!("creating workspace dir {}", workspace_dir.display()))?;
    harden_state_dir(workspace_dir)
        .with_context(|| format!("hardening workspace dir {}", workspace_dir.display()))?;
    let path = token_path(workspace_dir);
    let mut file = open_private(&path).with_context(|| format!("creating {}", path.display()))?;
    writeln!(file, "{token}").with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // `mode` only applies when the file is created; re-tighten an existing one.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::create(path)
}

/// The interactive `login` subcommand: run `claude setup-token` with the engine's
/// `CLAUDE_CONFIG_DIR` (the same dir the daemon resolves — see
/// [`ConfigOverlay::paths_from_env`](crate::config::ConfigOverlay::paths_from_env)),
/// then read the token the operator pastes back and store it under the workspace.
pub(crate) fn run(paths: &Paths) -> Result<()> {
    let engine_config_dir = &paths.engine_config_dir;
    let workspace_dir = &paths.workspace_dir;
    std::fs::create_dir_all(engine_config_dir)
        .with_context(|| format!("creating {}", engine_config_dir.display()))?;

    eprintln!(
        "Running `claude setup-token` (CLAUDE_CONFIG_DIR={}). Follow the browser flow.\n",
        engine_config_dir.display()
    );
    let status = Command::new("claude")
        .arg("setup-token")
        .env("CLAUDE_CONFIG_DIR", engine_config_dir)
        .status()
        .context("running `claude setup-token` (is the `claude` CLI on PATH?)")?;
    if !status.success() {
        bail!("`claude setup-token` exited with {status}");
    }

    eprint!("\nPaste the token printed above: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading the token from stdin")?;
    let path = write_token(workspace_dir, &line).context("storing the token")?;
    eprintln!(
        "Saved to {}. Restart gino-agent to apply it (a host-supplied credential still takes precedence).",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_token(dir.path()), None);
    }

    #[test]
    fn write_then_read_roundtrips_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_token(dir.path(), "  sk-ant-oat01-abc \n").unwrap();
        assert_eq!(path, dir.path().join(TOKEN_FILE));
        assert_eq!(read_token(dir.path()).as_deref(), Some("sk-ant-oat01-abc"));
    }

    #[test]
    fn write_rejects_blank_token_and_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write_token(dir.path(), "  \n").is_err());
        assert!(!token_path(dir.path()).exists());
    }

    #[test]
    fn blank_file_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(token_path(dir.path()), "\n").unwrap();
        assert_eq!(read_token(dir.path()), None);
    }

    #[test]
    fn write_creates_missing_workspace_dir() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("nested").join("ws");
        write_token(&workspace, "tok").unwrap();
        assert_eq!(read_token(&workspace).as_deref(), Some("tok"));
    }

    #[cfg(unix)]
    #[test]
    fn token_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = write_token(dir.path(), "tok").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Overwriting an existing (possibly loosened) file re-tightens it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_token(dir.path(), "tok2").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
