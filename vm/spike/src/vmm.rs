//! Boots one libkrun microVM and runs a command in it.
//!
//! Loads `libkrun.so.1` with `dlopen`, configures a virtiofs root (libkrunfw kernel and the
//! built-in init), extra virtiofs shares, a vsock device without TSI plus guest-port to
//! host-Unix-socket mappings, and optionally a virtio-net device on a Unix stream with the
//! init's DHCP client. `krun_start_enter` never returns: the process exits with the guest.
//!
//! ```text
//! spike-vmm --root DIR [--share TAG=DIR]... [--vsock PORT=PATH]... [--net PATH]
//!           [--vcpus N] [--mem MIB] [--log-level N] -- PROGRAM [ARGS]...
//! ```

use std::ffi::{CString, c_char};
use std::process::ExitCode;

use libloading::Library;

const NET_FLAG_DHCP_CLIENT: u32 = 1 << 1;
const GUEST_MAC: [u8; 6] = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee];
const GUEST_ENV: &[&str] = &[
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root",
    "TERM=dumb",
];

#[derive(Default)]
struct Args {
    root: String,
    shares: Vec<(String, String)>,
    vsock: Vec<(u32, String)>,
    net: Option<String>,
    vcpus: u8,
    mem: u32,
    log_level: u32,
    argv: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        vcpus: 1,
        mem: 512,
        ..Args::default()
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        if flag == "--" {
            args.argv = it.by_ref().collect();
            break;
        }
        let value = it.next().ok_or(format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--root" => args.root = value,
            "--share" => {
                let (tag, dir) = value.split_once('=').ok_or("--share TAG=DIR")?;
                args.shares.push((tag.into(), dir.into()));
            }
            "--vsock" => {
                let (port, path) = value.split_once('=').ok_or("--vsock PORT=PATH")?;
                args.vsock
                    .push((port.parse().map_err(|_| "bad vsock port")?, path.into()));
            }
            "--net" => args.net = Some(value),
            "--vcpus" => args.vcpus = value.parse().map_err(|_| "bad --vcpus")?,
            "--mem" => args.mem = value.parse().map_err(|_| "bad --mem")?,
            "--log-level" => args.log_level = value.parse().map_err(|_| "bad --log-level")?,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if args.root.is_empty() || args.argv.is_empty() {
        return Err("usage: spike-vmm --root DIR [options] -- PROGRAM [ARGS]...".into());
    }
    Ok(args)
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("argument contains NUL")
}

/// A NULL-terminated `char *[]` over `strings`, valid while `strings` lives.
fn cvec(strings: &[CString]) -> Vec<*const c_char> {
    strings
        .iter()
        .map(|s| s.as_ptr())
        .chain([std::ptr::null()])
        .collect()
}

fn check(name: &str, ret: i32) -> Result<(), String> {
    if ret < 0 {
        Err(format!(
            "{name}: {}",
            std::io::Error::from_raw_os_error(-ret)
        ))
    } else {
        Ok(())
    }
}

macro_rules! sym {
    ($lib:expr, $name:literal, $ty:ty) => {
        // SAFETY: the signature matches the declaration in libkrun.h of the pinned tag.
        *unsafe { $lib.get::<$ty>(concat!($name, "\0").as_bytes()) }
            .map_err(|e| format!("{}: {e}", $name))?
    };
}

fn run(args: Args) -> Result<(), String> {
    // SAFETY: loading libkrun runs no initialisers with preconditions.
    let lib =
        unsafe { Library::new("libkrun.so.1") }.map_err(|e| format!("dlopen libkrun.so.1: {e}"))?;

    let set_log_level = sym!(lib, "krun_set_log_level", unsafe extern "C" fn(u32) -> i32);
    let create_ctx = sym!(lib, "krun_create_ctx", unsafe extern "C" fn() -> i32);
    let set_vm_config = sym!(
        lib,
        "krun_set_vm_config",
        unsafe extern "C" fn(u32, u8, u32) -> i32
    );
    let set_root = sym!(
        lib,
        "krun_set_root",
        unsafe extern "C" fn(u32, *const c_char) -> i32
    );
    let add_virtiofs = sym!(
        lib,
        "krun_add_virtiofs",
        unsafe extern "C" fn(u32, *const c_char, *const c_char) -> i32
    );
    let disable_implicit_vsock = sym!(
        lib,
        "krun_disable_implicit_vsock",
        unsafe extern "C" fn(u32) -> i32
    );
    let add_vsock = sym!(lib, "krun_add_vsock", unsafe extern "C" fn(u32, u32) -> i32);
    let add_vsock_port2 = sym!(
        lib,
        "krun_add_vsock_port2",
        unsafe extern "C" fn(u32, u32, *const c_char, bool) -> i32
    );
    let add_net_unixstream = sym!(
        lib,
        "krun_add_net_unixstream",
        unsafe extern "C" fn(u32, *const c_char, i32, *const u8, u32, u32) -> i32
    );
    let set_exec = sym!(
        lib,
        "krun_set_exec",
        unsafe extern "C" fn(u32, *const c_char, *const *const c_char, *const *const c_char) -> i32
    );
    let start_enter = sym!(lib, "krun_start_enter", unsafe extern "C" fn(u32) -> i32);

    let root = cstr(&args.root);
    let shares: Vec<(CString, CString)> = args
        .shares
        .iter()
        .map(|(t, d)| (cstr(t), cstr(d)))
        .collect();
    let vsock: Vec<(u32, CString)> = args.vsock.iter().map(|(p, s)| (*p, cstr(s))).collect();
    let net = args.net.as_deref().map(cstr);
    let program = cstr(&args.argv[0]);
    let rest: Vec<CString> = args.argv[1..].iter().map(|a| cstr(a)).collect();
    let env: Vec<CString> = GUEST_ENV.iter().map(|e| cstr(e)).collect();
    let (rest_ptrs, env_ptrs) = (cvec(&rest), cvec(&env));

    // SAFETY: every pointer passed below is a live NUL-terminated string or a
    // NULL-terminated array of them, owned by this frame for the whole call.
    unsafe {
        check("krun_set_log_level", set_log_level(args.log_level))?;
        let ctx = create_ctx();
        check("krun_create_ctx", ctx)?;
        let ctx = ctx as u32;
        check(
            "krun_set_vm_config",
            set_vm_config(ctx, args.vcpus, args.mem),
        )?;
        check("krun_disable_implicit_vsock", disable_implicit_vsock(ctx))?;
        check("krun_add_vsock", add_vsock(ctx, 0))?;
        check("krun_set_root", set_root(ctx, root.as_ptr()))?;
        for (tag, dir) in &shares {
            check(
                "krun_add_virtiofs",
                add_virtiofs(ctx, tag.as_ptr(), dir.as_ptr()),
            )?;
        }
        for (port, path) in &vsock {
            check(
                "krun_add_vsock_port2",
                add_vsock_port2(ctx, *port, path.as_ptr(), false),
            )?;
        }
        if let Some(path) = &net {
            check(
                "krun_add_net_unixstream",
                add_net_unixstream(
                    ctx,
                    path.as_ptr(),
                    -1,
                    GUEST_MAC.as_ptr(),
                    0,
                    NET_FLAG_DHCP_CLIENT,
                ),
            )?;
        }
        check(
            "krun_set_exec",
            set_exec(ctx, program.as_ptr(), rest_ptrs.as_ptr(), env_ptrs.as_ptr()),
        )?;
        check("krun_start_enter", start_enter(ctx))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_args().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("spike-vmm: {err}");
            ExitCode::from(125)
        }
    }
}
