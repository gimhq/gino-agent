//! Builds the libkrun context from a validated run spec and enters the VM.

use std::convert::Infallible;
use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;

use crate::ffi;
use crate::spec::{self, RunSpec};

/// `S_IFREG` for overlay file modes.
const S_IFREG: u32 = 0o100_000;

fn c(field: &str, value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("{field}: must not contain NUL"))
}

/// `None` becomes a NULL argument, which keeps libkrun's default for that setting.
fn optional_c(field: &str, value: Option<&str>) -> Result<Option<CString>, String> {
    value.map(|v| c(field, v)).transpose()
}

/// Configures the VM and starts it; returns only on failure.
pub fn start(spec: &RunSpec) -> Result<Infallible, String> {
    ffi::log_errors_to_stderr()?;
    let ctx = ffi::create_ctx()?;
    ffi::set_vm_config(ctx, spec.vcpus, spec.memory_mib)?;
    let kernel = &spec.kernel;
    let initramfs = optional_c("kernel.initramfs", kernel.initramfs.as_deref())?;
    let cmdline = optional_c("kernel.cmdline", kernel.cmdline.as_deref())?;
    ffi::set_kernel(
        ctx,
        &c("kernel.path", &kernel.path)?,
        kernel.format.krun_value(),
        initramfs.as_deref(),
        cmdline.as_deref(),
    )?;

    // No TSI: the only vsock device has no TSI features.
    ffi::disable_implicit_vsock(ctx)?;
    ffi::add_vsock(ctx, 0)?;

    ffi::set_root(ctx, &c("rootDir", &spec.root_dir)?)?;
    for share in &spec.shares {
        ffi::add_virtiofs(
            ctx,
            &c("shares.tag", &share.tag)?,
            &c("shares.hostPath", &share.host_path)?,
            share.read_only,
        )?;
    }
    for disk in &spec.disks {
        ffi::add_disk(
            ctx,
            &c("disks.id", &disk.id)?,
            &c("disks.path", &disk.path)?,
            disk.format.krun_value(),
            disk.read_only,
        )?;
    }
    let root_tag = c("rootTag", spec::ROOT_TAG)?;
    for file in &spec.overlay_files {
        let name = spec::overlay_name(&file.guest_path)
            .ok_or_else(|| format!("overlayFiles: bad guestPath {:?}", file.guest_path))?;
        let meta = std::fs::metadata(&file.host_path)
            .map_err(|e| format!("overlay file {}: {e}", file.host_path))?;
        let data = std::fs::read(&file.host_path)
            .map_err(|e| format!("overlay file {}: {e}", file.host_path))?;
        let mode = S_IFREG | (meta.permissions().mode() & 0o7777);
        ffi::fs_add_overlay_file(
            ctx,
            &root_tag,
            &c("overlayFiles.guestPath", name)?,
            Box::leak(data.into_boxed_slice()),
            mode,
        )?;
    }

    for vsock in &spec.vsock_ports {
        ffi::add_vsock_port(
            ctx,
            vsock.port,
            &c("vsockPorts.hostSocketPath", &vsock.host_socket_path)?,
            vsock.listen,
        )?;
    }
    if let Some(net) = &spec.net {
        let mac = spec::parse_mac(&net.mac)?;
        ffi::add_net_unixstream(ctx, &c("net.unixstreamPath", &net.unixstream_path)?, &mac)?;
    }
    if !spec.console_ports.is_empty() {
        let console = ffi::add_virtio_console_multiport(ctx)?;
        for port in &spec.console_ports {
            for fd in [port.in_fd, port.out_fd] {
                std::fs::metadata(format!("/proc/self/fd/{fd}"))
                    .map_err(|e| format!("console port {:?}: fd {fd}: {e}", port.name))?;
            }
            ffi::add_console_port_inout(
                ctx,
                console,
                &c("consolePorts.name", &port.name)?,
                port.in_fd,
                port.out_fd,
            )?;
        }
    }

    let exec = &spec.exec;
    let args = exec
        .args
        .iter()
        .map(|a| c("exec.args", a))
        .collect::<Result<Vec<_>, _>>()?;
    let env = exec
        .env
        .iter()
        .map(|(k, v)| c("exec.env", &format!("{k}={v}")))
        .collect::<Result<Vec<_>, _>>()?;
    ffi::set_exec(ctx, &c("exec.path", &exec.path)?, &args, &env)?;
    if let Some(workdir) = &exec.workdir {
        ffi::set_workdir(ctx, &c("exec.workdir", workdir)?)?;
    }

    ffi::start_enter(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_strings_map_to_null_or_c_strings() {
        assert_eq!(optional_c("kernel.cmdline", None), Ok(None));
        assert_eq!(
            optional_c("kernel.cmdline", Some("console=hvc0")),
            Ok(Some(c"console=hvc0".to_owned()))
        );
        assert_eq!(
            optional_c("kernel.cmdline", Some("a\0b")),
            Err("kernel.cmdline: must not contain NUL".to_owned())
        );
    }
}
