//! The only module with `unsafe` code: libkrun's context API (compiled into this binary,
//! called directly) and the parent-death signal.

#![allow(unsafe_code)]

use std::convert::Infallible;
use std::ffi::{CStr, CString, c_char, c_int};

/// A libkrun configuration context id.
#[derive(Debug, Clone, Copy)]
pub struct Ctx(u32);

fn check(call: &str, ret: i32) -> Result<u32, String> {
    u32::try_from(ret).map_err(|_| {
        format!(
            "krun_{call}: {}",
            std::io::Error::from_raw_os_error(ret.saturating_neg())
        )
    })
}

/// A NULL-terminated `char *[]` over `strings`, valid while `strings` lives.
fn ptr_array(strings: &[CString]) -> Vec<*const c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain([std::ptr::null()])
        .collect()
}

/// Send libkrun's error log (plain lines, `RUST_LOG` ignored) to stderr, where
/// the caller reads why a VM failed to build.
pub fn log_errors_to_stderr() -> Result<(), String> {
    const STDERR: c_int = 2;
    const KRUN_LOG_LEVEL_ERROR: u32 = 1;
    const KRUN_LOG_STYLE_NEVER: u32 = 2;
    const KRUN_LOG_OPTION_NO_ENV: u32 = 1;
    // SAFETY: fd 2 maps to libkrun's stderr target; no fd ownership is taken.
    let ret = unsafe {
        krun::krun_init_log(
            STDERR,
            KRUN_LOG_LEVEL_ERROR,
            KRUN_LOG_STYLE_NEVER,
            KRUN_LOG_OPTION_NO_ENV,
        )
    };
    check("init_log", ret).map(drop)
}

pub fn create_ctx() -> Result<Ctx, String> {
    check("create_ctx", krun::krun_create_ctx()).map(Ctx)
}

pub fn set_vm_config(ctx: Ctx, vcpus: u8, memory_mib: u32) -> Result<(), String> {
    let ret = krun::krun_set_vm_config(ctx.0, vcpus, memory_mib);
    check("set_vm_config", ret).map(drop)
}

pub fn set_kernel(
    ctx: Ctx,
    path: &CStr,
    format: u32,
    initramfs: Option<&CStr>,
    cmdline: Option<&CStr>,
) -> Result<(), String> {
    let initramfs = initramfs.map_or(std::ptr::null(), CStr::as_ptr);
    let cmdline = cmdline.map_or(std::ptr::null(), CStr::as_ptr);
    // SAFETY: NUL-terminated strings (or NULL initramfs / cmdline) live for the call; libkrun
    // copies them.
    let ret = unsafe { krun::krun_set_kernel(ctx.0, path.as_ptr(), format, initramfs, cmdline) };
    check("set_kernel", ret).map(drop)
}

pub fn set_root(ctx: Ctx, path: &CStr) -> Result<(), String> {
    // SAFETY: NUL-terminated string live for the call; libkrun copies it.
    let ret = unsafe { krun::krun_set_root(ctx.0, path.as_ptr()) };
    check("set_root", ret).map(drop)
}

/// A virtiofs share without a DAX window.
pub fn add_virtiofs(ctx: Ctx, tag: &CStr, path: &CStr, read_only: bool) -> Result<(), String> {
    // SAFETY: NUL-terminated strings live for the call; libkrun copies them.
    let ret = unsafe { krun::krun_add_virtiofs3(ctx.0, tag.as_ptr(), path.as_ptr(), 0, read_only) };
    check("add_virtiofs3", ret).map(drop)
}

/// A virtio-blk device backed by an image file; full sync, no `O_DIRECT`.
pub fn add_disk(
    ctx: Ctx,
    id: &CStr,
    path: &CStr,
    format: u32,
    read_only: bool,
) -> Result<(), String> {
    const KRUN_SYNC_FULL: u32 = 2;
    // SAFETY: NUL-terminated strings live for the call; libkrun copies them.
    let ret = unsafe {
        krun::krun_add_disk3(
            ctx.0,
            id.as_ptr(),
            path.as_ptr(),
            format,
            read_only,
            false,
            KRUN_SYNC_FULL,
        )
    };
    check("add_disk3", ret).map(drop)
}

/// A memory-backed file in the virtiofs device `tag`; libkrun keeps `data` for the VM's
/// lifetime, hence `'static`.
pub fn fs_add_overlay_file(
    ctx: Ctx,
    tag: &CStr,
    path: &CStr,
    data: &'static [u8],
    mode: u32,
) -> Result<(), String> {
    // SAFETY: strings live for the call (copied); `data` lives for the whole process.
    let ret = unsafe {
        krun::krun_fs_add_overlay_file(
            ctx.0,
            tag.as_ptr(),
            path.as_ptr(),
            data.as_ptr(),
            data.len(),
            mode,
            false,
        )
    };
    check("fs_add_overlay_file", ret).map(drop)
}

/// Returns the console id.
pub fn add_virtio_console_multiport(ctx: Ctx) -> Result<u32, String> {
    // SAFETY: plain integer.
    check("add_virtio_console_multiport", unsafe {
        krun::krun_add_virtio_console_multiport(ctx.0)
    })
}

pub fn add_console_port_inout(
    ctx: Ctx,
    console: u32,
    name: &CStr,
    in_fd: c_int,
    out_fd: c_int,
) -> Result<(), String> {
    // SAFETY: NUL-terminated name live for the call; the fds are plain integers that
    // libkrun uses as inherited descriptors.
    let ret =
        unsafe { krun::krun_add_console_port_inout(ctx.0, console, name.as_ptr(), in_fd, out_fd) };
    check("add_console_port_inout", ret).map(drop)
}

pub fn disable_implicit_vsock(ctx: Ctx) -> Result<(), String> {
    check(
        "disable_implicit_vsock",
        krun::krun_disable_implicit_vsock(ctx.0),
    )
    .map(drop)
}

pub fn add_vsock(ctx: Ctx, tsi_features: u32) -> Result<(), String> {
    check("add_vsock", krun::krun_add_vsock(ctx.0, tsi_features)).map(drop)
}

pub fn add_vsock_port(ctx: Ctx, port: u32, path: &CStr, listen: bool) -> Result<(), String> {
    // SAFETY: NUL-terminated string live for the call; libkrun copies it.
    let ret = unsafe { krun::krun_add_vsock_port2(ctx.0, port, path.as_ptr(), listen) };
    check("add_vsock_port2", ret).map(drop)
}

/// A virtio-net device on a unixstream socket path, no offload features, no flags.
pub fn add_net_unixstream(ctx: Ctx, path: &CStr, mac: &[u8; 6]) -> Result<(), String> {
    // SAFETY: NUL-terminated path and a 6-byte MAC live for the call; libkrun copies both.
    let ret =
        unsafe { krun::krun_add_net_unixstream(ctx.0, path.as_ptr(), -1, mac.as_ptr(), 0, 0) };
    check("add_net_unixstream", ret).map(drop)
}

pub fn set_exec(ctx: Ctx, path: &CStr, args: &[CString], env: &[CString]) -> Result<(), String> {
    let (args, env) = (ptr_array(args), ptr_array(env));
    // SAFETY: NUL-terminated strings and NULL-terminated arrays of them live for the call;
    // libkrun copies them.
    let ret = unsafe { krun::krun_set_exec(ctx.0, path.as_ptr(), args.as_ptr(), env.as_ptr()) };
    check("set_exec", ret).map(drop)
}

pub fn set_workdir(ctx: Ctx, path: &CStr) -> Result<(), String> {
    // SAFETY: NUL-terminated string live for the call; libkrun copies it.
    check("set_workdir", unsafe {
        krun::krun_set_workdir(ctx.0, path.as_ptr())
    })
    .map(drop)
}

/// Starts the VM. Returns only on a configuration error; otherwise libkrun exits the
/// process with the guest workload's status.
pub fn start_enter(ctx: Ctx) -> Result<Infallible, String> {
    let ret = krun::krun_start_enter(ctx.0);
    Err(check("start_enter", ret).map_or_else(
        |e| e,
        |_| "krun_start_enter: returned without starting the VM".to_owned(),
    ))
}

/// `PR_SET_PDEATHSIG(SIGKILL)`: the kernel kills this process when the thread that spawned
/// it exits.
pub fn set_parent_death_signal() -> Result<(), String> {
    // SAFETY: prctl with integer arguments only.
    let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!(
            "prctl(PR_SET_PDEATHSIG): {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_returns_become_os_errors() {
        assert_eq!(check("set_root", 3), Ok(3));
        let err = check("set_root", -2).unwrap_err();
        assert!(err.starts_with("krun_set_root: No such file"), "{err}");
    }

    #[test]
    fn ptr_array_is_null_terminated() {
        let strings = [c"a".to_owned(), c"b".to_owned()];
        let ptrs = ptr_array(&strings);
        assert_eq!(ptrs.len(), 3);
        assert_eq!(ptrs[0], strings[0].as_ptr());
        assert!(ptrs[2].is_null());
    }
}
