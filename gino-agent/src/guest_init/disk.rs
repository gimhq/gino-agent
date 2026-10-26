//! Online growth of the ext4 root disk to its device size.
//!
//! The base image is only as large as its content; the overlay the daemon
//! creates has the configured virtual size. `resize2fs` on a mounted ext4 grows
//! it in place and does nothing when it already fills the device, so this runs
//! on every boot, after the switch to the root disk (it needs `/proc`).

use std::process::Command;

use anyhow::{Context, Result, ensure};

use super::mounts::ROOT_DEVICE;

/// `resize2fs` from the root image's e2fsprogs.
const RESIZE2FS: &str = "/sbin/resize2fs";

/// Grow the root filesystem to fill [`ROOT_DEVICE`].
pub(super) fn grow_root() -> Result<()> {
    let output = Command::new(RESIZE2FS)
        .arg(ROOT_DEVICE)
        .env_clear()
        .output()
        .with_context(|| format!("running {RESIZE2FS}"))?;
    ensure!(
        output.status.success(),
        "{RESIZE2FS} {ROOT_DEVICE} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}
