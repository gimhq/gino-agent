//! `vm` isolation: the local VM config, the fail-closed host probe and the
//! launch of one engine run inside a `gino-vmm` microVM.
//!
//! The VM config (`engine.isolation.vm`) is read from the local isolation file
//! only. [`ensure_available`] checks once per process that the host can start
//! a VM with it: `/dev/kvm` opens read-write, the configured `gino-vmm` is
//! executable, the kernel and the rootfs image exist and `gino-vmm --probe`
//! loads and accepts libkrun.
//!
//! A launch is prepared by [`prepare`]: a private per-run dir holding the
//! empty boot root, the control share (`spec.json` for guest-init plus copies
//! of the single files and trees guest-init binds read-only), the agent API
//! socket, with a network the virtio-net socket, the root disk (a run overlay,
//! or the task's disk; see [`super::vm_disk`]) and the gino-vmm run spec. [`start`] spawns
//! gino-vmm from a thread that lives as long as the run (gino-vmm's
//! `PR_SET_PDEATHSIG` fires when the spawning thread exits), accepts libkrun's
//! virtio-net stream and runs the run's network exit on it (Ethernet framing,
//! ARP and the gateway MAC by `nsplane-ether`), connects to the guest's
//! control channel and waits for `READY`. The returned [`VmRun`] owns
//! everything; dropping it asks the engine to stop (`SIGNAL TERM`), kills
//! gino-vmm after a grace period, then stops the exit and removes the run dir.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, mpsc};
use std::time::{Duration, Instant};

use nsplane_ether::{EtherConfig, MacAddr, spawn_port};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::bwrap::{ProvisionedGlobals, engine_home, inspect_task_entries};
use super::vm_disk::{DiskStore, RootDisk};
use super::{
    AGENT_MEMORY_DIR_ENV, AGENT_MEMORY_MOUNT, AGENT_SOCK_ENV, CONVERSATIONS_DIR_ENV,
    CONVERSATIONS_MOUNT, IsolationError, Launch, LaunchContext, MEMORY_DIR_ENV, RunDir,
    TASK_MEMORY_MOUNT, engine_auto_memory, snapshot_archives,
};
use crate::agent_api::{RunPeerServer, serve_run_peers};
use crate::engine::EngineError;
use crate::guest_init::SETUP_FAILURE;
use crate::guest_init::spec::{
    DEFAULT_AGENT_API_VSOCK_PORT, DEFAULT_CONTROL_VSOCK_PORT, GUEST_AGENT_SOCKET,
    GUEST_CONTROL_DIR, GuestAgentApi, GuestBind, GuestMount, GuestNet, GuestSpec, SPEC_FILE_NAME,
};
use crate::memory::AgentMemoryAccess;
use crate::net::exit::{Exit, ExitConfig};
use crate::net::tun::TunConfig;

const DEFAULT_VCPUS: u8 = 2;
const MAX_VCPUS: u8 = 32;
const DEFAULT_MEMORY_MIB: u32 = 2048;
const MIN_MEMORY_MIB: u32 = 64;
const MAX_MEMORY_MIB: u32 = 65536;
const DEFAULT_DISK_GIB: u32 = 32;
const MAX_DISK_GIB: u32 = 4096;

const KVM_DEVICE: &str = "/dev/kvm";

/// How long `gino-vmm --probe` may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes of `gino-vmm --probe` stderr kept in a probe error.
const STDERR_TAIL: usize = 1024;

/// `engine.isolation.vm`: the VM a `vm` run boots.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct VmConfig {
    /// Guest kernel image; unset takes the lode resource (see [`LODE_RESOURCES`]).
    #[serde(default)]
    pub(crate) kernel: PathBuf,
    /// Guest root filesystem image (raw ext4), the base of every root disk.
    #[serde(default)]
    pub(crate) rootfs: PathBuf,
    /// The `gino-vmm` binary.
    #[serde(default)]
    pub(crate) vmm: PathBuf,
    /// Whether the removed `libkrun` key is present; `validate` rejects it.
    #[serde(default, rename = "libkrun", deserialize_with = "present")]
    pub(crate) has_libkrun: bool,
    #[serde(default = "default_vcpus")]
    pub(crate) vcpus: u8,
    #[serde(default = "default_memory_mib")]
    pub(crate) memory_mib: u32,
    /// Virtual size of a new root disk.
    #[serde(default = "default_disk_gib")]
    pub(crate) disk_gib: u32,
    /// Start dockerd in the guest before the engine.
    #[serde(default)]
    pub(crate) docker: bool,
}

/// Per path field: the lode resource, the variable lode sets to its installed
/// dir, and the file the resource bundle holds.
const LODE_RESOURCES: [(&str, &str, &str); 3] = [
    ("kernel", "LODE_RESOURCE_KERNEL", "vmlinux"),
    ("rootfs", "LODE_RESOURCE_ROOTFS", "rootfs.ext4"),
    ("vmm", "LODE_RESOURCE_VMM", "gino-vmm"),
];

/// Accept any value, recording only that the key is present.
fn present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer).map(|_| true)
}

fn default_vcpus() -> u8 {
    DEFAULT_VCPUS
}

fn default_memory_mib() -> u32 {
    DEFAULT_MEMORY_MIB
}

fn default_disk_gib() -> u32 {
    DEFAULT_DISK_GIB
}

impl VmConfig {
    fn paths_mut(&mut self) -> [&mut PathBuf; 3] {
        [&mut self.kernel, &mut self.rootfs, &mut self.vmm]
    }

    /// Set each unset path to its file in the installed lode resource, when
    /// `env` names one. lode's dir is the resource's `current` link, so the
    /// path follows resource updates.
    pub(crate) fn fill_from_lode(&mut self, env: impl Fn(&str) -> Option<OsString>) {
        for (path, (_, var, file)) in self.paths_mut().into_iter().zip(LODE_RESOURCES) {
            if path.as_os_str().is_empty()
                && let Some(dir) = env(var).filter(|dir| !dir.is_empty())
            {
                *path = PathBuf::from(dir).join(file);
            }
        }
    }

    /// Reject the removed `libkrun` key and check the paths are set and
    /// absolute and the sizes in range.
    pub(crate) fn validate(&self) -> Result<(), IsolationError> {
        if self.has_libkrun {
            return Err(IsolationError::InvalidVm(
                "`libkrun` is no longer supported: libkrun is compiled into gino-vmm; remove the key"
                    .to_string(),
            ));
        }
        let paths = [&self.kernel, &self.rootfs, &self.vmm];
        for (path, (field, var, _)) in paths.into_iter().zip(LODE_RESOURCES) {
            if path.as_os_str().is_empty() {
                return Err(IsolationError::InvalidVm(format!(
                    "{field} is not set: configure `vm.{field}` or install the lode resource `{field}` ({var})"
                )));
            }
            if !path.is_absolute() {
                return Err(IsolationError::InvalidVm(format!(
                    "{field} `{}` is not absolute",
                    path.display()
                )));
            }
        }
        if !(1..=MAX_VCPUS).contains(&self.vcpus) {
            return Err(IsolationError::InvalidVm(format!(
                "vcpus {} is not in 1..={MAX_VCPUS}",
                self.vcpus
            )));
        }
        if !(MIN_MEMORY_MIB..=MAX_MEMORY_MIB).contains(&self.memory_mib) {
            return Err(IsolationError::InvalidVm(format!(
                "memoryMib {} is not in {MIN_MEMORY_MIB}..={MAX_MEMORY_MIB}",
                self.memory_mib
            )));
        }
        if !(1..=MAX_DISK_GIB).contains(&self.disk_gib) {
            return Err(IsolationError::InvalidVm(format!(
                "diskGib {} is not in 1..={MAX_DISK_GIB}",
                self.disk_gib
            )));
        }
        Ok(())
    }

    fn disk_bytes(&self) -> u64 {
        u64::from(self.disk_gib) << 30
    }
}

/// Resolved VM settings of one `vm` run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VmSettings {
    /// The local isolation file's VM config.
    pub(crate) config: VmConfig,
    /// Extra host paths shared read-only.
    pub(crate) read_paths: Vec<PathBuf>,
    /// Extra host paths shared read-write.
    pub(crate) write_paths: Vec<PathBuf>,
    /// Keep the task's root disk across its runs (`vmDisk: "task"`).
    pub(crate) task_disk: bool,
}

/// Probe the host for `cfg` once per process; the outcome is cached. The VM
/// config comes from the local isolation file, which is read only at startup.
pub(crate) fn ensure_available(cfg: &VmConfig) -> Result<(), IsolationError> {
    static PROBE: OnceLock<Result<(), String>> = OnceLock::new();
    PROBE
        .get_or_init(|| probe(cfg, Path::new(KVM_DEVICE)))
        .clone()
        .map_err(IsolationError::Unavailable)
}

/// Run the probe once, opening `kvm` as the KVM device.
fn probe(cfg: &VmConfig, kvm: &Path) -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(kvm)
        .map_err(|e| format!("cannot open {} read-write: {e}", kvm.display()))?;
    let executable = std::fs::metadata(&cfg.vmm)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0);
    if !executable {
        return Err(format!(
            "gino-vmm `{}` is not an executable file",
            cfg.vmm.display()
        ));
    }
    if !cfg.kernel.is_file() {
        return Err(format!(
            "VM kernel `{}` is not a file",
            cfg.kernel.display()
        ));
    }
    if !cfg.rootfs.is_file() {
        return Err(format!(
            "VM rootfs image `{}` is not a file",
            cfg.rootfs.display()
        ));
    }
    probe_vmm(cfg)
}

/// Run `gino-vmm --probe`, which checks the helper without starting a VM.
fn probe_vmm(cfg: &VmConfig) -> Result<(), String> {
    let mut child = Command::new(&cfg.vmm)
        .arg("--probe")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run {}: {e}", cfg.vmm.display()))?;

    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "gino-vmm probe timed out after {}s",
                    PROBE_TIMEOUT.as_secs()
                ));
            }
            Err(e) => return Err(format!("failed to wait for the gino-vmm probe: {e}")),
        }
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr = Vec::new();
    if let Some(pipe) = child.stderr.take() {
        let _ = pipe.take(64 * 1024).read_to_end(&mut stderr);
    }
    let start = stderr.len().saturating_sub(STDERR_TAIL);
    let stderr = String::from_utf8_lossy(&stderr[start..]);
    let line = stderr.trim().lines().last().unwrap_or_default();
    Err(format!("gino-vmm probe failed ({status}): {line}"))
}

/// Exit status of gino-vmm when it fails before the VM starts.
const VMM_FAILURE: i32 = 120;

/// Prefix of the per-run dir under the temp dir.
const RUN_DIR_PREFIX: &str = "gino-vm-";
/// The boot root inside the run dir: empty but for the agent overlay file.
const BOOT_DIR_NAME: &str = "boot";
/// virtio-blk id of the root disk (`/dev/vda` in the guest).
const ROOT_DISK_ID: &str = "root";
/// The control dir inside the boot root (`BOOT_CONTROL_DIR` in the guest).
const CTL_DIR_NAME: &str = "ctl";
/// Copies guest-init binds, inside the control share.
const VIEW_DIR_NAME: &str = "view";
/// Host end of the control vsock port (libkrun listens there).
const CTL_SOCK_NAME: &str = "ctl.sock";
/// Host end of the agent API vsock port (the daemon listens there).
const AGENT_SOCK_NAME: &str = "agent.sock";
/// Host end of the guest's virtio-net stream (the daemon listens there).
const NET_SOCK_NAME: &str = "net.sock";

/// MAC of the guest's virtio-net device: locally administered, unicast. Every
/// run has its own link, so one fixed address serves all.
const GUEST_MAC: MacAddr = MacAddr([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee]);
/// MAC the exit answers as on the guest link: locally administered, unicast.
const GATEWAY_MAC: MacAddr = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
/// How long libkrun may take to connect to the virtio-net socket.
const NET_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The gino-agent binary inside the guest, injected as an overlay file of the
/// boot root and bound into the root disk by guest-init.
const GUEST_AGENT_EXE: &str = "/gino-agent";
/// `PATH` of the engine in the guest; also where a bare engine name is looked up.
const GUEST_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// `$HOME` and `$TMPDIR` of the engine: the guest's tmpfs `/tmp`.
const GUEST_TMP: &str = "/tmp";

/// Env vars the guest environment sets itself, dropped from the inherited one.
const REPLACED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "GINO_WORKSPACE_DIR",
    "GINO_ARCHIVE_DIR",
    "GINO_SANDBOX",
    "GINO_VM",
    "GINO_RUNNER_BIN",
    AGENT_SOCK_ENV,
    MEMORY_DIR_ENV,
    AGENT_MEMORY_DIR_ENV,
    CONVERSATIONS_DIR_ENV,
];
/// Env var carrying the run's agent API token.
const AGENT_TOKEN_ENV: &str = "GINO_AGENT_TOKEN";
/// Env var naming the gino-agent binary for in-engine tooling.
const RUNNER_BIN_ENV: &str = "GINO_RUNNER_BIN";

/// How long the guest may take to report `READY`.
const READY_TIMEOUT: Duration = Duration::from_mins(1);
/// Pause between control socket connection attempts.
const CONNECT_RETRY: Duration = Duration::from_millis(50);
/// How long the engine gets to stop after `SIGNAL TERM` before gino-vmm is killed.
const TERM_GRACE: Duration = Duration::from_secs(5);
/// gino-vmm liveness polling interval of the run thread.
const POLL_INTERVAL: Duration = Duration::from_millis(20);
/// How long a finished run waits for gino-vmm's status and the `EXIT` line.
const EXIT_REPORT_WAIT: Duration = Duration::from_secs(10);
/// Bytes of gino-vmm stderr kept in a startup failure.
const RUN_STDERR_TAIL: usize = 4096;

/// Host facts a VM launch is built from.
#[derive(Clone, Debug)]
pub(crate) struct VmHost {
    /// The engine's uid/gid in the guest: the daemon's own, so the engine owns
    /// its virtiofs-shared work dir and home there as on the host (virtiofs
    /// reports host ownership and guest root cannot chown through an
    /// unprivileged VMM). Never 0: a root daemon is refused before this.
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The daemon's environment, inherited by the engine like an off or
    /// sandboxed run inherits it.
    pub(crate) env: Vec<(String, String)>,
}

impl VmHost {
    pub(crate) fn current() -> Self {
        Self {
            uid: nix::unistd::getuid().as_raw(),
            gid: nix::unistd::getgid().as_raw(),
            env: std::env::vars_os()
                .filter_map(|(key, value)| {
                    Some((key.into_string().ok()?, value.into_string().ok()?))
                })
                .collect(),
        }
    }
}

/// gino-vmm run spec (see gino-vmm/README.md).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunSpec {
    kernel: RunKernel,
    root_dir: String,
    shares: Vec<RunShare>,
    overlay_files: Vec<RunOverlayFile>,
    disks: Vec<RunDisk>,
    vcpus: u8,
    memory_mib: u32,
    exec: RunExec,
    vsock_ports: Vec<RunVsockPort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    net: Option<RunNet>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunNet {
    unixstream_path: String,
    mac: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RunKernel {
    path: String,
    format: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunShare {
    tag: String,
    host_path: String,
    read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunOverlayFile {
    host_path: String,
    guest_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunDisk {
    id: String,
    path: String,
    format: &'static str,
}

/// libkrun's init runs guest-init with the default kernel command line; see
/// the guest-init module for why it is not PID 1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RunExec {
    path: String,
    args: Vec<String>,
    workdir: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RunVsockPort {
    port: u32,
    host_socket_path: String,
    listen: bool,
}

/// A host file or tree copied into the control share and bound read-only at
/// `target` in the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ViewEntry {
    source: ViewSource,
    target: PathBuf,
}

/// What a [`ViewEntry`] copies.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ViewSource {
    /// One host file or tree.
    Path(PathBuf),
    /// A directory assembled from named host files or trees.
    Dir(Vec<(OsString, PathBuf)>),
    /// A snapshot of the task's archive dirs, capped at `max_bytes`.
    Archives {
        archives: Vec<PathBuf>,
        max_bytes: u64,
    },
}

impl ViewSource {
    fn is_dir(&self) -> bool {
        match self {
            Self::Path(path) => path.is_dir(),
            Self::Dir(_) | Self::Archives { .. } => true,
        }
    }

    /// Copy to `dest`, which must not exist.
    fn copy(&self, dest: &Path) -> std::io::Result<()> {
        match self {
            Self::Path(path) => copy_tree(path, dest, 0),
            Self::Dir(entries) => {
                std::fs::create_dir(dest)?;
                entries
                    .iter()
                    .try_for_each(|(name, path)| copy_tree(path, &dest.join(name), 1))
            }
            Self::Archives {
                archives,
                max_bytes,
            } => snapshot_archives(archives, dest, *max_bytes),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Path(path) => path.display().to_string(),
            Self::Dir(entries) => entries
                .iter()
                .map(|(_, path)| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            Self::Archives { .. } => "the task's conversation archives".to_owned(),
        }
    }
}

/// Everything a VM launch writes and runs, derived from the inputs alone.
#[derive(Clone, Debug, PartialEq, Eq)]
struct VmPlan {
    guest: GuestSpec,
    run_spec: RunSpec,
    /// Copied to `<ctl>/view/<index>`.
    view: Vec<ViewEntry>,
    /// Created on the host before the spawn: the engine home and the bind
    /// targets inside the work dir (directory or file).
    placeholders: Vec<(PathBuf, bool)>,
    /// The run's agent API token, when it has API access.
    agent_token: Option<String>,
}

fn vm_error(message: impl Into<String>) -> EngineError {
    IsolationError::Vm(message.into()).into()
}

/// `path` as UTF-8, which the guest spec and run spec need.
fn utf8(path: &Path) -> Result<String, EngineError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| vm_error(format!("path `{}` is not UTF-8", path.display())))
}

/// The engine's complete guest environment: the inherited one, then the
/// launch env, then the guest's own settings and `mounted` (var, guest path).
/// Later entries replace earlier ones of the same name.
fn guest_env(
    inherited: &[(String, String)],
    launch: &[(String, std::ffi::OsString)],
    config_dir_keys: &[&str],
    work_dir: &Path,
    engine_home: &Path,
    agent_api: bool,
    mounted: &[(&str, &str)],
) -> Result<Vec<(String, String)>, EngineError> {
    let mut env: Vec<(String, String)> = Vec::new();
    let mut set = |key: &str, value: String| {
        env.retain(|(k, _)| k != key);
        env.push((key.to_owned(), value));
    };
    for (key, value) in inherited {
        set(key, value.clone());
    }
    let mut runner_bin = false;
    for (key, value) in launch {
        let value = value
            .to_str()
            .ok_or_else(|| vm_error(format!("env var {key} is not UTF-8")))?;
        runner_bin |= key == RUNNER_BIN_ENV;
        set(key, value.to_owned());
    }
    env.retain(|(key, _)| {
        !REPLACED_ENV.contains(&key.as_str()) && !config_dir_keys.contains(&key.as_str())
    });
    let engine_home = utf8(engine_home)?;
    let mut ours = vec![
        ("PATH", GUEST_PATH.to_owned()),
        ("HOME", GUEST_TMP.to_owned()),
        ("TMPDIR", GUEST_TMP.to_owned()),
        ("GINO_ARCHIVE_DIR", utf8(&work_dir.join("conversations"))?),
        ("GINO_VM", "1".to_owned()),
    ];
    ours.extend(
        config_dir_keys
            .iter()
            .map(|key| (*key, engine_home.clone())),
    );
    ours.extend(mounted.iter().map(|(key, path)| (*key, (*path).to_owned())));
    if agent_api {
        ours.push((AGENT_SOCK_ENV, GUEST_AGENT_SOCKET.to_owned()));
    }
    if runner_bin {
        ours.push((RUNNER_BIN_ENV, GUEST_AGENT_EXE.to_owned()));
    }
    env.extend(ours.into_iter().map(|(key, value)| (key.to_owned(), value)));
    Ok(env)
}

/// Point the hook commands of every `--settings <json>` argument that run the
/// host gino-agent binary `agent_exe` at the guest one, and its auto memory
/// dir at the task memory share via [`engine_auto_memory`]. Arguments that are
/// not JSON (a settings file path) stay as they are.
fn guest_settings_args(argv: &mut [String], agent_exe: &Path, memory_dir: Option<&Path>) {
    let exe = agent_exe.to_str();
    let mut iter = argv.iter_mut();
    while let Some(arg) = iter.next() {
        if arg != "--settings" {
            continue;
        }
        let Some(value) = iter.next() else {
            break;
        };
        let Ok(mut json) = serde_json::from_str::<serde_json::Value>(value) else {
            continue;
        };
        let mut changed = engine_auto_memory(&mut json, memory_dir);
        if let Some(exe) = exe
            && let Some(hooks) = json.get_mut("hooks")
        {
            changed |= guest_hook_commands(hooks, exe);
        }
        if changed && let Ok(rewritten) = serde_json::to_string(&json) {
            *value = rewritten;
        }
    }
}

/// Rewrite every `command` string below `value` that runs `exe` to run
/// [`GUEST_AGENT_EXE`]; reports whether anything changed.
fn guest_hook_commands(value: &mut serde_json::Value, exe: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            let mut changed = false;
            for (key, entry) in map.iter_mut() {
                if key == "command"
                    && let serde_json::Value::String(command) = entry
                {
                    if let Some(rest) = command.strip_prefix(exe)
                        && (rest.is_empty() || rest.starts_with(' '))
                    {
                        *command = format!("{GUEST_AGENT_EXE}{rest}");
                        changed = true;
                    }
                } else {
                    changed |= guest_hook_commands(entry, exe);
                }
            }
            changed
        }
        serde_json::Value::Array(items) => items.iter_mut().fold(false, |changed, item| {
            guest_hook_commands(item, exe) | changed
        }),
        _ => false,
    }
}

/// The value of `key` in the launch env, when set and non-empty.
fn launch_var<'a>(launch: &'a Launch, key: &str) -> Option<&'a std::ffi::OsStr> {
    launch
        .env
        .iter()
        .rev()
        .find(|(k, _)| k == key)
        .map(|(_, value)| value.as_os_str())
        .filter(|value| !value.is_empty())
}

/// Global `CLAUDE.md` and skills at their sandbox places in the engine home,
/// then the task-scope store entries where their links point, and with task
/// memory the conversations view. The skills form one read-only `skills/`
/// dir, as in the sandbox, so the engine cannot add or shadow a skill there.
fn view_entries(ctx: &LaunchContext<'_>, work_dir: &Path, home: &Path) -> Vec<ViewEntry> {
    let mut view = Vec::new();
    if let Some(global) = ctx.global_config_dir {
        let globals = ProvisionedGlobals::inspect(Some(global));
        if globals.claude_md {
            view.push(ViewEntry {
                source: ViewSource::Path(global.join("CLAUDE.md")),
                target: home.join("CLAUDE.md"),
            });
        }
        if !globals.skills.is_empty() {
            view.push(ViewEntry {
                source: ViewSource::Dir(
                    globals
                        .skills
                        .into_iter()
                        .map(|skill| (skill.name, skill.source))
                        .collect(),
                ),
                target: home.join("skills"),
            });
        }
    }
    view.extend(
        inspect_task_entries(work_dir, ctx.workspace_dir)
            .into_iter()
            .map(|entry| ViewEntry {
                source: ViewSource::Path(entry.source),
                target: entry.dest,
            }),
    );
    if ctx.memory_dir.is_some() {
        view.push(ViewEntry {
            source: ViewSource::Archives {
                archives: ctx.task_archives.to_vec(),
                max_bytes: ctx.conversations_max_bytes,
            },
            target: CONVERSATIONS_MOUNT.into(),
        });
    }
    view
}

/// One virtiofs share of a VM run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Share {
    host_path: String,
    guest_path: String,
    tag: String,
    read_only: bool,
}

impl Share {
    /// A share mounted at its host path.
    fn same_path(path: &Path, tag: String, read_only: bool) -> Result<Self, EngineError> {
        let path = utf8(path)?;
        Ok(Self {
            host_path: path.clone(),
            guest_path: path,
            tag,
            read_only,
        })
    }
}

/// virtiofs shares: the work dir, the agent's engine home when `program` is
/// installed there (read-only) and the extra paths at their host paths, the
/// task and agent memory dirs at their in-engine paths. Extra read-only files
/// go to `view` instead.
fn shares(
    ctx: &LaunchContext<'_>,
    settings: &VmSettings,
    program: &Path,
    work_dir: &Path,
    view: &mut Vec<ViewEntry>,
) -> Result<Vec<Share>, EngineError> {
    let mut shares = vec![Share::same_path(work_dir, "work".to_owned(), false)?];
    let engines = crate::engine::admin::engines_home(ctx.workspace_dir);
    if program.starts_with(&engines) {
        shares.push(Share::same_path(&engines, "engines".to_owned(), true)?);
    }
    for (i, path) in settings.read_paths.iter().enumerate() {
        if path.is_dir() {
            shares.push(Share::same_path(path, format!("ro{i}"), true)?);
        } else {
            view.push(ViewEntry {
                source: ViewSource::Path(path.clone()),
                target: path.clone(),
            });
        }
    }
    for (i, path) in settings.write_paths.iter().enumerate() {
        if !path.is_dir() {
            return Err(vm_error(format!(
                "write path `{}` is not a directory; a VM shares directories only",
                path.display()
            )));
        }
        shares.push(Share::same_path(path, format!("rw{i}"), false)?);
    }
    let memory = [
        (ctx.memory_dir, "task-memory", TASK_MEMORY_MOUNT, false),
        (
            ctx.agent_memory_dir,
            "agent-memory",
            AGENT_MEMORY_MOUNT,
            ctx.agent_memory_access == AgentMemoryAccess::Ro,
        ),
    ];
    for (dir, tag, guest_path, read_only) in memory {
        if let Some(dir) = dir {
            shares.push(Share {
                host_path: utf8(dir)?,
                guest_path: guest_path.to_owned(),
                tag: tag.to_owned(),
                read_only,
            });
        }
    }
    Ok(shares)
}

/// The in-engine path vars of the memory shares and the conversations view
/// the run has.
fn mounted_env(ctx: &LaunchContext<'_>) -> Vec<(&'static str, &'static str)> {
    [
        (ctx.memory_dir.is_some(), MEMORY_DIR_ENV, TASK_MEMORY_MOUNT),
        (
            ctx.agent_memory_dir.is_some(),
            AGENT_MEMORY_DIR_ENV,
            AGENT_MEMORY_MOUNT,
        ),
        (
            ctx.memory_dir.is_some(),
            CONVERSATIONS_DIR_ENV,
            CONVERSATIONS_MOUNT,
        ),
    ]
    .into_iter()
    .filter_map(|(on, key, path)| on.then_some((key, path)))
    .collect()
}

/// Build the guest spec and run spec of the VM launch of `direct`; `net_mtu`
/// gives the guest an eth0 with that MTU on the exit's link.
fn plan(
    direct: &Launch,
    ctx: &LaunchContext<'_>,
    settings: &VmSettings,
    host: &VmHost,
    run_dir: &Path,
    net_mtu: Option<u16>,
    root_disk: &Path,
) -> Result<VmPlan, EngineError> {
    let work_dir = ctx
        .work_dir
        .ok_or(IsolationError::Missing("the thread's work dir"))?;
    let agent_exe = ctx
        .self_exe
        .ok_or(IsolationError::Missing("the gino-agent binary path"))?;
    let program = utf8(&direct.program)?;
    let home = engine_home(work_dir);
    let cwd = if direct.cwd.as_os_str().is_empty() {
        work_dir
    } else {
        direct.cwd.as_path()
    };
    let agent_token = launch_var(direct, AGENT_SOCK_ENV)
        .and(launch_var(direct, AGENT_TOKEN_ENV))
        .map(|token| {
            token
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| vm_error(format!("{AGENT_TOKEN_ENV} is not UTF-8")))
        })
        .transpose()?;

    let mut argv = vec![program];
    for arg in &direct.args {
        let arg = arg
            .to_str()
            .ok_or_else(|| vm_error("an engine argument is not UTF-8"))?;
        argv.push(arg.to_owned());
    }
    guest_settings_args(&mut argv, agent_exe, ctx.memory_dir);

    let mut view = view_entries(ctx, work_dir, &home);
    let shares = shares(ctx, settings, &direct.program, work_dir, &mut view)?;
    let mut binds = Vec::new();
    let mut placeholders = vec![(home.clone(), true)];
    for (i, entry) in view.iter().enumerate() {
        binds.push(GuestBind {
            source: format!("{GUEST_CONTROL_DIR}/{VIEW_DIR_NAME}/{i}"),
            target: utf8(&entry.target)?,
        });
        if entry.target.starts_with(work_dir) {
            placeholders.push((entry.target.clone(), entry.source.is_dir()));
        }
    }

    let guest = GuestSpec {
        argv,
        env: guest_env(
            &host.env,
            &direct.env,
            ctx.config_dir_keys,
            work_dir,
            &home,
            agent_token.is_some(),
            &mounted_env(ctx),
        )?,
        cwd: utf8(cwd)?,
        uid: host.uid,
        gid: host.gid,
        mounts: shares
            .iter()
            .map(|share| GuestMount {
                tag: share.tag.clone(),
                guest_path: share.guest_path.clone(),
                read_only: share.read_only,
            })
            .collect(),
        binds,
        net: net_mtu.map(guest_net),
        agent_api: agent_token.as_ref().map(|_| GuestAgentApi {
            vsock_port: DEFAULT_AGENT_API_VSOCK_PORT,
            socket_path: GUEST_AGENT_SOCKET.to_owned(),
        }),
        control_vsock_port: DEFAULT_CONTROL_VSOCK_PORT,
        docker: settings.config.docker,
    };
    guest
        .validate()
        .map_err(|err| vm_error(format!("cannot express the run in the guest: {err:#}")))?;
    let run_spec = run_spec(
        &settings.config,
        agent_exe,
        run_dir,
        root_disk,
        shares,
        agent_token.is_some(),
        net_mtu.is_some(),
    )?;
    Ok(VmPlan {
        guest,
        run_spec,
        view,
        placeholders,
        agent_token,
    })
}

/// The guest side of the exit's link: the address plan of the sandbox TUN
/// device, the gateway as the only resolver.
fn guest_net(mtu: u16) -> GuestNet {
    let tun = TunConfig::default();
    GuestNet {
        address: format!("{}/{}", tun.address, tun.prefix_len),
        gateway: tun.gateway.to_string(),
        dns: tun.gateway.to_string(),
        mtu,
    }
}

/// The gino-vmm run spec: the run dir's boot root, `root_disk`, the control
/// share plus `shares`, the control vsock port, with `agent_api` the agent API
/// one and with `net` the virtio-net device on the run dir's net socket.
fn run_spec(
    config: &VmConfig,
    agent_exe: &Path,
    run_dir: &Path,
    root_disk: &Path,
    shares: Vec<Share>,
    agent_api: bool,
    net: bool,
) -> Result<RunSpec, EngineError> {
    let run_shares = shares
        .into_iter()
        .map(|share| RunShare {
            tag: share.tag,
            host_path: share.host_path,
            read_only: share.read_only,
        })
        .collect();
    let mut vsock_ports = vec![RunVsockPort {
        port: DEFAULT_CONTROL_VSOCK_PORT,
        host_socket_path: utf8(&run_dir.join(CTL_SOCK_NAME))?,
        listen: true,
    }];
    if agent_api {
        vsock_ports.push(RunVsockPort {
            port: DEFAULT_AGENT_API_VSOCK_PORT,
            host_socket_path: utf8(&run_dir.join(AGENT_SOCK_NAME))?,
            listen: false,
        });
    }
    let net = if net {
        Some(RunNet {
            unixstream_path: utf8(&run_dir.join(NET_SOCK_NAME))?,
            mac: GUEST_MAC.to_string(),
        })
    } else {
        None
    };
    Ok(RunSpec {
        kernel: RunKernel {
            path: utf8(&config.kernel)?,
            format: "elf",
        },
        root_dir: utf8(&run_dir.join(BOOT_DIR_NAME))?,
        shares: run_shares,
        overlay_files: vec![RunOverlayFile {
            host_path: utf8(agent_exe)?,
            guest_path: GUEST_AGENT_EXE.to_owned(),
        }],
        disks: vec![RunDisk {
            id: ROOT_DISK_ID.to_owned(),
            path: utf8(root_disk)?,
            format: "qcow2",
        }],
        vcpus: config.vcpus,
        memory_mib: config.memory_mib,
        exec: RunExec {
            path: GUEST_AGENT_EXE.to_owned(),
            args: vec!["guest-init".to_owned()],
            workdir: "/".to_owned(),
        },
        vsock_ports,
        net,
    })
}

/// Maximum directory depth [`copy_tree`] follows.
const MAX_COPY_DEPTH: usize = 32;

/// Copy a file or a directory tree, following symlinks; file modes are kept.
fn copy_tree(source: &Path, dest: &Path, depth: usize) -> std::io::Result<()> {
    if depth > MAX_COPY_DEPTH {
        return Err(std::io::Error::other(format!(
            "{} is nested more than {MAX_COPY_DEPTH} levels deep",
            source.display()
        )));
    }
    if std::fs::metadata(source)?.is_dir() {
        std::fs::create_dir(dest)?;
        for entry in std::fs::read_dir(source)? {
            let entry = entry?;
            copy_tree(&entry.path(), &dest.join(entry.file_name()), depth + 1)?;
        }
        Ok(())
    } else {
        std::fs::copy(source, dest).map(drop)
    }
}

/// The run's agent API listener and token. `Debug` never prints the token.
struct AgentListener {
    listener: std::os::unix::net::UnixListener,
    token: String,
}

impl std::fmt::Debug for AgentListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentListener")
            .field("listener", &self.listener)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The bound virtio-net socket and the settings of the exit served on it.
#[derive(Debug)]
struct NetListener {
    listener: std::os::unix::net::UnixListener,
    exit: ExitConfig,
}

/// A VM run prepared before the spawn: the per-run dir with the control
/// share, the bound agent API and virtio-net sockets and the run spec.
#[derive(Debug)]
pub(crate) struct VmPrepared {
    dir: RunDir,
    vmm: PathBuf,
    /// The run spec as one JSON line, without the newline.
    run_spec: String,
    agent: Option<AgentListener>,
    net: Option<NetListener>,
    disk: RootDisk,
}

/// Compares by identity.
impl PartialEq for VmPrepared {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for VmPrepared {}

/// Prepare the VM launch of `direct`, with a network served by an exit with
/// `net` when set: the returned launch's program is gino-vmm and [`start`]
/// runs it.
pub(crate) fn prepare(
    direct: &Launch,
    ctx: &LaunchContext<'_>,
    settings: &VmSettings,
    host: &VmHost,
    net: Option<ExitConfig>,
) -> Result<Launch, EngineError> {
    if let Some(agent) = ctx.self_exe
        && needs_interpreter(agent).map_err(EngineError::Spawn)?
    {
        return Err(IsolationError::InvalidVm(format!(
            "the gino-agent binary `{}` is dynamically linked; the guest runs it from an empty \
             boot root, so `vm` isolation needs a static build",
            agent.display()
        ))
        .into());
    }
    let dir = RunDir::create(RUN_DIR_PREFIX).map_err(EngineError::Spawn)?;
    let spawn_err = |what: &str, err: std::io::Error| {
        EngineError::Spawn(std::io::Error::new(
            err.kind(),
            format!("preparing the VM run ({what}): {err}"),
        ))
    };
    std::fs::create_dir(dir.0.join(BOOT_DIR_NAME)).map_err(|err| spawn_err("boot root", err))?;
    let disk = root_disk(ctx, settings, &dir.0).map_err(|err| spawn_err("root disk", err))?;
    let plan = plan(
        direct,
        ctx,
        settings,
        host,
        &dir.0,
        net.as_ref().map(|exit| exit.mtu),
        &disk.path,
    )?;

    for (path, is_dir) in &plan.placeholders {
        let created = if *is_dir {
            std::fs::create_dir_all(path)
        } else {
            path.parent()
                .map_or(Ok(()), std::fs::create_dir_all)
                .and_then(|()| {
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .map(drop)
                })
        };
        created.map_err(|err| spawn_err(&path.display().to_string(), err))?;
    }
    let ctl = dir.0.join(BOOT_DIR_NAME).join(CTL_DIR_NAME);
    let view = ctl.join(VIEW_DIR_NAME);
    std::fs::create_dir_all(&view).map_err(|err| spawn_err("control share", err))?;
    for (i, entry) in plan.view.iter().enumerate() {
        entry
            .source
            .copy(&view.join(i.to_string()))
            .map_err(|err| spawn_err(&entry.source.describe(), err))?;
    }
    let spec = serde_json::to_string(&plan.guest)
        .map_err(|err| vm_error(format!("encoding spec.json: {err}")))?;
    std::fs::write(ctl.join(SPEC_FILE_NAME), spec).map_err(|err| spawn_err("spec.json", err))?;
    let run_spec = serde_json::to_string(&plan.run_spec)
        .map_err(|err| vm_error(format!("encoding the run spec: {err}")))?;
    let agent = match plan.agent_token {
        Some(token) => {
            let listener = std::os::unix::net::UnixListener::bind(dir.0.join(AGENT_SOCK_NAME))
                .and_then(|listener| listener.set_nonblocking(true).map(|()| listener))
                .map_err(|err| spawn_err("agent API socket", err))?;
            Some(AgentListener { listener, token })
        }
        None => None,
    };
    let net = match net {
        Some(exit) => {
            let listener = std::os::unix::net::UnixListener::bind(dir.0.join(NET_SOCK_NAME))
                .and_then(|listener| listener.set_nonblocking(true).map(|()| listener))
                .map_err(|err| spawn_err("network socket", err))?;
            Some(NetListener { listener, exit })
        }
        None => None,
    };

    Ok(Launch {
        program: settings.config.vmm.clone(),
        args: Vec::new(),
        env: Vec::new(),
        cwd: PathBuf::new(),
        sandboxed: false,
        net: None,
        conversations: None,
        vm: Some(Arc::new(VmPrepared {
            dir,
            vmm: settings.config.vmm.clone(),
            run_spec,
            agent,
            net,
            disk,
        })),
    })
}

/// The run's root disk: the task's disk when the run asks for it and no other
/// run holds it, else an overlay in `run_dir`.
/// Whether `path` is an ELF64 file with a `PT_INTERP` segment (a dynamically
/// linked executable).
fn needs_interpreter(path: &Path) -> std::io::Result<bool> {
    const PT_INTERP: u32 = 3;
    let mut header = [0u8; 64];
    let mut file = std::fs::File::open(path)?;
    let read = file.read(&mut header)?;
    if read < header.len() || !header.starts_with(b"\x7fELF\x02") {
        return Ok(false);
    }
    let u16_at = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    let mut phoff = [0u8; 8];
    phoff.copy_from_slice(&header[0x20..0x28]);
    let (entsize, count) = (usize::from(u16_at(0x36)), usize::from(u16_at(0x38)));
    if entsize < 4 {
        return Ok(false);
    }
    let mut table = vec![0u8; entsize * count];
    std::io::Seek::seek(
        &mut file,
        std::io::SeekFrom::Start(u64::from_le_bytes(phoff)),
    )?;
    file.read_exact(&mut table)?;
    Ok(table
        .chunks_exact(entsize)
        .any(|entry| u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]) == PT_INTERP))
}

fn root_disk(
    ctx: &LaunchContext<'_>,
    settings: &VmSettings,
    run_dir: &Path,
) -> std::io::Result<RootDisk> {
    let config = &settings.config;
    let store = DiskStore::new(ctx.workspace_dir);
    let base = store.base(&config.rootfs)?;
    if settings.task_disk
        && let Some(task_id) = ctx.task_id
    {
        if let Some(disk) = store.task_disk(task_id, &base, config.disk_bytes())? {
            return Ok(disk);
        }
        tracing::warn!(task = %task_id, "the task disk is in use by another run; using a run disk");
    }
    store.run_disk(run_dir, &base, config.disk_bytes())
}

/// State shared by a [`VmRun`], its monitor and its run thread.
#[derive(Debug, Default)]
struct VmShared {
    /// Writing end of the control connection, while connected.
    control: Mutex<Option<StdUnixStream>>,
    /// The guest's `EXIT` line, once received.
    engine_exit: Mutex<Option<String>>,
}

impl VmShared {
    fn control(&self) -> MutexGuard<'_, Option<StdUnixStream>> {
        self.control.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn engine_exit(&self) -> Option<String> {
        self.engine_exit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Send one control line; a no-op without a connection.
    fn send(&self, line: &str) {
        if let Some(stream) = self.control().as_mut()
            && let Err(err) = stream.write_all(format!("{line}\n").as_bytes())
        {
            tracing::debug!(error = %err, line, "writing a VM control line");
        }
    }

    /// Close the control connection (both directions).
    fn close(&self) {
        if let Some(stream) = self.control().take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// What the run thread is asked to do.
#[derive(Debug)]
enum ThreadRequest {
    Kill,
}

/// A running VM: gino-vmm and everything the run set up. Dropping it stops
/// the run (see the module docs) without blocking the caller.
#[derive(Debug)]
pub(crate) struct VmRun {
    pid: u32,
    shared: Arc<VmShared>,
    status: watch::Receiver<Option<ExitStatus>>,
    requests: mpsc::Sender<ThreadRequest>,
    control_reader: Option<JoinHandle<()>>,
}

impl Drop for VmRun {
    fn drop(&mut self) {
        if let Some(reader) = &self.control_reader {
            reader.abort();
        }
    }
}

impl VmRun {
    /// gino-vmm's pid while it runs.
    pub(crate) fn id(&self) -> Option<u32> {
        self.status.borrow().is_none().then_some(self.pid)
    }

    /// Wait for gino-vmm to exit.
    pub(crate) async fn wait(&mut self) -> Option<ExitStatus> {
        self.status
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|status| *status)
    }

    /// Kill gino-vmm.
    pub(crate) fn start_kill(&self) {
        let _ = self.requests.send(ThreadRequest::Kill);
    }

    /// Deliver SIGINT to the engine's process group in the guest.
    pub(crate) fn interrupt(&self) {
        self.shared.send("SIGNAL INT");
    }

    /// A handle that reports how the run ended.
    pub(crate) fn monitor(&self) -> VmMonitor {
        VmMonitor {
            shared: Arc::clone(&self.shared),
            status: self.status.clone(),
        }
    }
}

/// Reports a VM run's failure once its console closed.
#[derive(Clone, Debug)]
pub(crate) struct VmMonitor {
    shared: Arc<VmShared>,
    status: watch::Receiver<Option<ExitStatus>>,
}

impl VmMonitor {
    /// `None` when the guest reported the engine's exit; otherwise the
    /// runner-side reason naming gino-vmm. Waits a bounded time for the
    /// report.
    pub(crate) async fn failure(&self) -> Option<String> {
        let deadline = Instant::now() + EXIT_REPORT_WAIT;
        loop {
            if let Some(line) = self.shared.engine_exit() {
                tracing::debug!(%line, "engine exit reported by the VM");
                return None;
            }
            let status = *self.status.borrow();
            if let Some(status) = status {
                // The EXIT line may still be in flight from a guest that shut down.
                tokio::time::sleep(CONNECT_RETRY).await;
                if self.shared.engine_exit().is_some() {
                    return None;
                }
                return Some(exit_reason(status, "", "after the engine started"));
            }
            if Instant::now() >= deadline {
                return Some(format!(
                    "gino-vmm did not report the engine's exit within {}s",
                    EXIT_REPORT_WAIT.as_secs()
                ));
            }
            tokio::time::sleep(CONNECT_RETRY).await;
        }
    }
}

/// The runner-side reason of a gino-vmm exit without an `EXIT` line.
fn exit_reason(status: ExitStatus, stderr: &str, when: &str) -> String {
    let lines = || stderr.lines().map(str::trim).filter(|l| !l.is_empty());
    let last = lines().next_back().unwrap_or_default();
    match status.code() {
        Some(VMM_FAILURE) => format!("gino-vmm failed before the VM started: {last}"),
        Some(SETUP_FAILURE) => {
            let line = lines()
                .rfind(|l| l.starts_with("guest-init:"))
                .unwrap_or(last);
            format!("guest-init failed to start the engine: {line}")
        }
        _ if last.is_empty() => {
            format!("gino-vmm exited ({status}) {when} without an engine exit status")
        }
        _ => format!("gino-vmm exited ({status}) {when} without an engine exit status: {last}"),
    }
}

/// Pipes of a started VM run.
#[derive(Debug)]
pub(crate) struct VmPipes {
    pub(crate) stdin: ChildStdin,
    pub(crate) stdout: ChildStdout,
    pub(crate) stderr: ChildStderr,
}

/// Spawn gino-vmm for `prepared`, start its network, wait for the guest's
/// `READY` and return the run and the engine's stdio (the guest console).
pub(crate) async fn start(prepared: Arc<VmPrepared>) -> Result<(VmRun, VmPipes), EngineError> {
    start_with(prepared, NET_ACCEPT_TIMEOUT).await
}

async fn start_with(
    prepared: Arc<VmPrepared>,
    net_timeout: Duration,
) -> Result<(VmRun, VmPipes), EngineError> {
    let prepared =
        Arc::into_inner(prepared).ok_or_else(|| vm_error("the prepared VM run is shared"))?;
    let VmPrepared {
        dir,
        vmm,
        run_spec,
        agent,
        net,
        disk,
    } = prepared;
    let peers = match agent {
        Some(AgentListener { listener, token }) => {
            let listener = tokio::net::UnixListener::from_std(listener)
                .map_err(|err| vm_error(format!("agent API socket: {err}")))?;
            Some(
                serve_run_peers(listener, &token)
                    .map_err(|err| vm_error(format!("serving the agent API: {err:#}")))?,
            )
        }
        None => None,
    };
    let (net_task, net_started) = match net {
        Some(NetListener { listener, exit }) => {
            let listener = tokio::net::UnixListener::from_std(listener)
                .map_err(|err| vm_error(format!("network socket: {err}")))?;
            let (started_tx, started) = tokio::sync::oneshot::channel();
            let task = NetTask(tokio::spawn(serve_network(listener, exit, started_tx)));
            (Some(task), Some(started))
        }
        None => (None, None),
    };
    let ctl_sock = dir.0.join(CTL_SOCK_NAME);
    let shared = Arc::new(VmShared::default());
    let (mut run, std_pipes) = spawn_thread(
        vmm,
        run_spec,
        Teardown {
            _dir: dir,
            _peers: peers,
            _net: net_task,
            _disk: disk,
        },
        Arc::clone(&shared),
    )
    .await?;
    let mut pipes = VmPipes {
        stdin: ChildStdin::from_std(std_pipes.0).map_err(EngineError::Spawn)?,
        stdout: ChildStdout::from_std(std_pipes.1).map_err(EngineError::Spawn)?,
        stderr: ChildStderr::from_std(std_pipes.2).map_err(EngineError::Spawn)?,
    };

    let mut status = run.status.clone();
    if let Some(started) = net_started {
        // libkrun connects when gino-vmm starts, before the guest boots.
        let started = tokio::select! {
            started = tokio::time::timeout(net_timeout, started) => match started {
                Ok(Ok(started)) => started,
                Ok(Err(_)) => Err("the network task ended".to_owned()),
                Err(_) => Err(format!(
                    "gino-vmm did not connect the VM network within {}s",
                    net_timeout.as_secs_f32()
                )),
            },
            status = async { status.wait_for(Option::is_some).await.ok().and_then(|status| *status) } => {
                let stderr = read_tail(&mut pipes.stderr).await;
                Err(status.map_or_else(
                    || "gino-vmm vanished before connecting the VM network".to_owned(),
                    |status| exit_reason(status, &stderr, "before connecting the VM network"),
                ))
            }
        };
        started.map_err(IsolationError::Network)?;
    }
    let ready = tokio::select! {
        ready = tokio::time::timeout(READY_TIMEOUT, connect_ready(&ctl_sock, &shared)) => ready,
        status = async { status.wait_for(Option::is_some).await.ok().and_then(|status| *status) } => {
            let stderr = read_tail(&mut pipes.stderr).await;
            let reason = status.map_or_else(
                || "gino-vmm vanished before the engine started".to_owned(),
                |status| exit_reason(status, &stderr, "before the engine started"),
            );
            return Err(vm_error(reason));
        }
    };
    let reader = ready.map_err(|_| {
        vm_error(format!(
            "the VM did not report READY within {}s",
            READY_TIMEOUT.as_secs()
        ))
    })?;
    run.control_reader = Some(tokio::spawn(control_reader(
        reader,
        ctl_sock,
        Arc::clone(&shared),
        run.status.clone(),
    )));
    Ok((run, pipes))
}

/// Resources released by the run thread once gino-vmm is gone.
#[derive(Debug)]
struct Teardown {
    _dir: RunDir,
    _peers: Option<RunPeerServer>,
    _net: Option<NetTask>,
    /// Released last: a task disk stays locked until gino-vmm is gone.
    _disk: RootDisk,
}

/// The task serving a VM's network; aborting it stops the exit and the
/// Ethernet port.
#[derive(Debug)]
struct NetTask(JoinHandle<()>);

impl Drop for NetTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Accept libkrun's virtio-net stream, run `cfg`'s exit on it behind an
/// Ethernet port, report the start on `started` and keep both running until
/// aborted.
async fn serve_network(
    listener: tokio::net::UnixListener,
    cfg: ExitConfig,
    started: tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    let stream = match listener.accept().await {
        Ok((stream, _)) => stream,
        Err(err) => {
            let _ = started.send(Err(format!("accepting on the network socket: {err}")));
            return;
        }
    };
    // Nothing else may connect once gino-vmm has.
    drop(listener);
    let (reader, writer) = nsplane_ether::stream::unix(stream);
    let (source, sink, _ether) = spawn_port(reader, writer, ether_config(cfg.mtu));
    let exit = match Exit::start_with(source, sink, cfg) {
        Ok(exit) => exit,
        Err(err) => {
            let _ = started.send(Err(format!("starting the network exit: {err}")));
            return;
        }
    };
    let _ = started.send(Ok(()));
    std::future::pending::<()>().await;
    drop(exit);
}

/// The gateway side of the guest link: ARP for the gateway address, no DHCP
/// (guest-init configures eth0 statically).
fn ether_config(mtu: u16) -> EtherConfig {
    EtherConfig {
        gateway_ipv4: Some(TunConfig::default().gateway),
        mtu,
        ..EtherConfig::new(GATEWAY_MAC)
    }
}

type StdPipes = (
    std::process::ChildStdin,
    std::process::ChildStdout,
    std::process::ChildStderr,
);

/// Spawn gino-vmm from a dedicated thread that writes the run spec line and
/// then supervises it until the [`VmRun`] is dropped.
async fn spawn_thread(
    vmm: PathBuf,
    run_spec: String,
    teardown: Teardown,
    shared: Arc<VmShared>,
) -> Result<(VmRun, StdPipes), EngineError> {
    let (spawned_tx, spawned_rx) = tokio::sync::oneshot::channel();
    let (requests, requests_rx) = mpsc::channel();
    let (status_tx, status) = watch::channel(None);
    let thread_shared = Arc::clone(&shared);
    std::thread::Builder::new()
        .name("gino-vmm".into())
        .spawn(move || {
            let mut command = Command::new(&vmm);
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(err) => {
                    let _ = spawned_tx.send(Err(err));
                    return;
                }
            };
            let pipes = (child.stdin.take(), child.stdout.take(), child.stderr.take());
            let (Some(mut stdin), Some(stdout), Some(stderr)) = pipes else {
                let _ = child.kill();
                let _ = child.wait();
                let _ = spawned_tx.send(Err(std::io::Error::other("gino-vmm pipes missing")));
                return;
            };
            if let Err(err) = stdin.write_all(format!("{run_spec}\n").as_bytes()) {
                tracing::debug!(error = %err, "writing the gino-vmm run spec");
            }
            let pid = child.id();
            if spawned_tx.send(Ok((pid, (stdin, stdout, stderr)))).is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            supervise(&mut child, &requests_rx, &status_tx, &thread_shared);
            drop(teardown);
        })
        .map_err(EngineError::Spawn)?;
    let (pid, pipes) = spawned_rx
        .await
        .map_err(|_| vm_error("the gino-vmm thread ended before spawning"))?
        .map_err(|err| {
            EngineError::Spawn(std::io::Error::new(
                err.kind(),
                format!("spawning gino-vmm: {err}"),
            ))
        })?;
    let run = VmRun {
        pid,
        shared,
        status,
        requests,
        control_reader: None,
    };
    Ok((run, pipes))
}

/// Run-thread loop: publish gino-vmm's exit, kill it on request, and once the
/// [`VmRun`] is gone stop the engine (`SIGNAL TERM`, then kill after
/// [`TERM_GRACE`]).
fn supervise(
    child: &mut std::process::Child,
    requests: &mpsc::Receiver<ThreadRequest>,
    status: &watch::Sender<Option<ExitStatus>>,
    shared: &VmShared,
) {
    let exited = loop {
        match child.try_wait() {
            Ok(Some(exit)) => break Some(exit),
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(error = %err, "waiting for gino-vmm");
                break None;
            }
        }
        match requests.recv_timeout(POLL_INTERVAL) {
            Ok(ThreadRequest::Kill) => {
                let _ = child.kill();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if shared.engine_exit().is_none() {
                    shared.send("SIGNAL TERM");
                }
                let deadline = Instant::now() + TERM_GRACE;
                while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
                    std::thread::sleep(POLL_INTERVAL);
                }
                let _ = child.kill();
                let _ = child.wait();
                shared.close();
                return;
            }
        }
    };
    status.send_replace(exited);
    shared.close();
    // Keep the run dir until the run is dropped.
    while requests.recv().is_ok() {}
}

/// Connect to the guest's control channel and read up to its `READY` line,
/// reconnecting while the guest is not listening yet. Leaves the writing end
/// in `shared` and returns the reader.
async fn connect_ready(ctl_sock: &Path, shared: &VmShared) -> BufReader<tokio::net::UnixStream> {
    loop {
        if let Some(reader) = try_connect(ctl_sock, shared).await {
            return reader;
        }
        tokio::time::sleep(CONNECT_RETRY).await;
    }
}

async fn try_connect(
    ctl_sock: &Path,
    shared: &VmShared,
) -> Option<BufReader<tokio::net::UnixStream>> {
    let stream = StdUnixStream::connect(ctl_sock).ok()?;
    let writer = stream.try_clone().ok()?;
    stream.set_nonblocking(true).ok()?;
    let mut reader = BufReader::new(tokio::net::UnixStream::from_std(stream).ok()?);
    *shared.control() = Some(writer);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => {
                shared.close();
                return None;
            }
            Ok(_) if line.trim_end() == "READY" => return Some(reader),
            Ok(_) => tracing::debug!(line = line.trim_end(), "VM control line before READY"),
        }
    }
}

/// Read control lines after `READY`: record `EXIT` and close the connection
/// promptly (guest-init waits for that close before powering off). A
/// connection lost before `EXIT` is re-established while gino-vmm runs.
async fn control_reader(
    mut reader: BufReader<tokio::net::UnixStream>,
    ctl_sock: PathBuf,
    shared: Arc<VmShared>,
    status: watch::Receiver<Option<ExitStatus>>,
) {
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(n) if n > 0 => {
                let line = line.trim_end();
                if line.starts_with("EXIT ") {
                    *shared
                        .engine_exit
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(line.to_owned());
                    shared.close();
                    return;
                }
                if line != "READY" {
                    tracing::debug!(line, "unexpected VM control line");
                }
            }
            _ => {
                shared.close();
                reader = loop {
                    if status.borrow().is_some() {
                        return;
                    }
                    if let Some(reader) = try_connect(&ctl_sock, &shared).await {
                        break reader;
                    }
                    tokio::time::sleep(CONNECT_RETRY).await;
                };
            }
        }
    }
}

/// The tail of an exited gino-vmm's stderr.
async fn read_tail(stderr: &mut ChildStderr) -> String {
    let mut buf = Vec::new();
    let mut limited = stderr.take(64 * 1024);
    let _ = tokio::time::timeout(Duration::from_secs(1), limited.read_to_end(&mut buf)).await;
    let start = buf.len().saturating_sub(RUN_STDERR_TAIL);
    String::from_utf8_lossy(&buf[start..]).into_owned()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{VmConfig, ensure_available, needs_interpreter, probe};
    use crate::sandbox::IsolationError;

    fn parse(raw: &str) -> Result<VmConfig, serde_json::Error> {
        serde_json::from_str(raw)
    }

    fn config(dir: &Path) -> VmConfig {
        VmConfig {
            kernel: dir.join("vmlinux"),
            rootfs: dir.join("rootfs"),
            vmm: dir.join("gino-vmm"),
            has_libkrun: false,
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 32,
            docker: false,
        }
    }

    /// A temp dir with a kernel file, a rootfs image, a fake KVM device file
    /// and a `gino-vmm` script running `vmm_body`.
    fn host(vmm_body: &str) -> (tempfile::TempDir, VmConfig, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path());
        std::fs::write(&cfg.kernel, b"kernel").unwrap();
        std::fs::write(&cfg.rootfs, b"ext4").unwrap();
        std::fs::write(&cfg.vmm, format!("#!/bin/sh\n{vmm_body}\n")).unwrap();
        std::fs::set_permissions(&cfg.vmm, std::fs::Permissions::from_mode(0o755)).unwrap();
        let kvm = tmp.path().join("kvm");
        std::fs::write(&kvm, b"").unwrap();
        (tmp, cfg, kvm)
    }

    #[test]
    fn parses_with_defaults() {
        let cfg =
            parse(r#"{ "kernel": "/vm/vmlinux", "rootfs": "/vm/rootfs", "vmm": "/bin/gino-vmm" }"#)
                .unwrap();
        assert_eq!(cfg, config(Path::new("/vm")).with_vmm("/bin/gino-vmm"));
        cfg.validate().unwrap();

        let cfg = parse(
            r#"{ "kernel": "/k", "rootfs": "/r", "vmm": "/v", "vcpus": 32, "memoryMib": 64 }"#,
        )
        .unwrap();
        assert_eq!((cfg.vcpus, cfg.memory_mib), (32, 64));
        cfg.validate().unwrap();
    }

    impl VmConfig {
        fn with_vmm(mut self, vmm: &str) -> Self {
            self.vmm = vmm.into();
            self
        }

        fn with_paths(mut self, kernel: &str, rootfs: &str, vmm: &str) -> Self {
            self.kernel = kernel.into();
            self.rootfs = rootfs.into();
            self.vmm = vmm.into();
            self
        }
    }

    #[test]
    fn unknown_fields_fail_to_parse() {
        for raw in [
            r#"{ "kernel": "/k", "rootfs": "/r", "vmm": "/v", "memoryMiB": 512 }"#,
            r#"{ "kernel": "/k", "rootfs": "/r", "vmm": "/v", "vcpus": -1 }"#,
        ] {
            assert!(parse(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn lode_resources_fill_the_unset_paths() {
        let env = |name: &str| match name {
            "LODE_RESOURCE_KERNEL" => Some("/srv/lode/resources/kernel/current".into()),
            "LODE_RESOURCE_VMM" => Some("/srv/lode/resources/vmm/current".into()),
            "LODE_RESOURCE_ROOTFS" => Some("/srv/lode/resources/rootfs/current".into()),
            _ => None,
        };
        let mut cfg = parse("{}").unwrap();
        cfg.fill_from_lode(env);
        assert_eq!(
            [&cfg.kernel, &cfg.vmm, &cfg.rootfs].map(|p| p.display().to_string()),
            [
                "/srv/lode/resources/kernel/current/vmlinux",
                "/srv/lode/resources/vmm/current/gino-vmm",
                "/srv/lode/resources/rootfs/current/rootfs.ext4",
            ]
        );
        cfg.validate().unwrap();

        // An explicit path wins over the resource.
        let mut cfg = parse(r#"{ "kernel": "/k", "rootfs": "/r", "vmm": "/v" }"#).unwrap();
        cfg.fill_from_lode(env);
        assert_eq!(cfg, config(Path::new("/")).with_paths("/k", "/r", "/v"));
    }

    #[test]
    fn an_unset_path_names_its_field_and_resource() {
        let mut cfg = parse(r#"{ "kernel": "/k", "vmm": "/v" }"#).unwrap();
        cfg.fill_from_lode(|name| (name == "LODE_RESOURCE_ROOTFS").then(OsString::new));
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, IsolationError::InvalidVm(_)), "{err:?}");
        assert!(
            err.to_string()
                .contains("rootfs is not set: configure `vm.rootfs` or install the lode resource `rootfs` (LODE_RESOURCE_ROOTFS)"),
            "{err}"
        );
    }

    #[test]
    fn validation_checks_paths_and_bounds() {
        let base = config(Path::new("/vm"));
        let invalid = |cfg: VmConfig, needle: &str| {
            let err = cfg.validate().unwrap_err();
            assert!(matches!(err, IsolationError::InvalidVm(_)), "{err:?}");
            assert!(err.to_string().contains(needle), "{err}");
        };
        invalid(
            VmConfig {
                kernel: "vm/vmlinux".into(),
                ..base.clone()
            },
            "kernel `vm/vmlinux` is not absolute",
        );
        invalid(
            VmConfig {
                rootfs: "rootfs".into(),
                ..base.clone()
            },
            "rootfs",
        );
        invalid(base.clone().with_vmm("gino-vmm"), "vmm");
        invalid(
            parse(r#"{ "kernel": "/k", "rootfs": "/r", "vmm": "/v", "libkrun": "/lib/libkrun.so.1" }"#)
                .unwrap(),
            "`libkrun` is no longer supported: libkrun is compiled into gino-vmm",
        );
        for vcpus in [0, 33] {
            invalid(
                VmConfig {
                    vcpus,
                    ..base.clone()
                },
                "vcpus",
            );
        }
        for memory_mib in [63, 65537] {
            invalid(
                VmConfig {
                    memory_mib,
                    ..base.clone()
                },
                "memoryMib",
            );
        }
    }

    #[test]
    fn probe_passes_when_everything_is_in_place() {
        let (_tmp, cfg, kvm) = host(r#"[ "$1" = --probe ] && [ $# -eq 1 ] || exit 3"#);
        probe(&cfg, &kvm).unwrap();
    }

    #[test]
    fn probe_fails_without_kvm() {
        let (tmp, cfg, _) = host("exit 0");
        let err = probe(&cfg, &tmp.path().join("no-kvm")).unwrap_err();
        assert!(err.contains("no-kvm read-write"), "{err}");
    }

    #[test]
    fn probe_fails_for_a_missing_or_non_executable_vmm() {
        let (_tmp, cfg, kvm) = host("exit 0");
        std::fs::set_permissions(&cfg.vmm, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = probe(&cfg, &kvm).unwrap_err();
        assert!(err.contains("is not an executable file"), "{err}");
        std::fs::remove_file(&cfg.vmm).unwrap();
        let err = probe(&cfg, &kvm).unwrap_err();
        assert!(err.contains("is not an executable file"), "{err}");
    }

    #[test]
    fn disk_size_and_docker_parse_and_validate() {
        let cfg = parse(
            r#"{ "kernel": "/k", "rootfs": "/r", "vmm": "/v", "diskGib": 64, "docker": true }"#,
        )
        .unwrap();
        assert_eq!((cfg.disk_gib, cfg.docker), (64, true));
        assert_eq!(cfg.disk_bytes(), 64 << 30);
        cfg.validate().unwrap();
        for gib in [0, 4097] {
            let err = VmConfig {
                disk_gib: gib,
                ..cfg.clone()
            }
            .validate()
            .unwrap_err();
            assert!(err.to_string().contains("diskGib"), "{err}");
        }
    }

    /// A minimal ELF64 header with one program header of type `p_type`.
    fn elf_with_segment(p_type: u32) -> Vec<u8> {
        let mut elf = vec![0u8; 64 + 56];
        elf[..5].copy_from_slice(b"\x7fELF\x02");
        elf[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        elf[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        elf[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&p_type.to_le_bytes());
        elf
    }

    #[test]
    fn only_a_dynamically_linked_agent_needs_an_interpreter() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("agent");
        std::fs::write(&path, elf_with_segment(3)).unwrap();
        assert!(needs_interpreter(&path).unwrap());
        std::fs::write(&path, elf_with_segment(1)).unwrap();
        assert!(!needs_interpreter(&path).unwrap());
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        assert!(!needs_interpreter(&path).unwrap());
    }

    #[test]
    fn probe_fails_for_a_missing_kernel_or_rootfs() {
        let (_tmp, cfg, kvm) = host("exit 0");
        std::fs::remove_file(&cfg.rootfs).unwrap();
        let err = probe(&cfg, &kvm).unwrap_err();
        assert!(
            err.contains("rootfs image") && err.contains("is not a file"),
            "{err}"
        );
        std::fs::remove_file(&cfg.kernel).unwrap();
        let err = probe(&cfg, &kvm).unwrap_err();
        assert!(
            err.contains("kernel") && err.contains("not a file"),
            "{err}"
        );
    }

    #[test]
    fn probe_fails_with_the_vmm_error_line() {
        let (_tmp, cfg, kvm) = host(
            "echo 'starting' >&2\necho 'gino-vmm: probe failed: no usable vCPU' >&2\nexit 120",
        );
        let err = probe(&cfg, &kvm).unwrap_err();
        assert!(err.contains("exit status: 120"), "{err}");
        assert!(
            err.ends_with(": gino-vmm: probe failed: no usable vCPU"),
            "{err}"
        );
    }

    #[test]
    fn ensure_available_is_cached_and_fails_as_unavailable() {
        let cfg = config(Path::new("/nonexistent"));
        let first = ensure_available(&cfg).unwrap_err();
        assert!(matches!(first, IsolationError::Unavailable(_)), "{first:?}");
        let second = ensure_available(&cfg).unwrap_err();
        assert_eq!(first.to_string(), second.to_string());
    }
}

#[cfg(test)]
mod launch_tests {
    use std::ffi::OsString;
    use std::io::{BufRead as _, BufReader as StdBufReader, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use nsplane_ether::{FrameRead as _, FrameWrite as _, MacAddr};
    use serde_json::json;

    use super::{
        VmConfig, VmHost, VmPlan, VmPrepared, VmSettings, exit_reason, guest_settings_args, plan,
        prepare, start, start_with,
    };
    use crate::engine::EngineError;
    use crate::guest_init::spec::{GuestBind, GuestMount, GuestNet, GuestSpec};
    use crate::memory::AgentMemoryAccess;
    use crate::net::exit::GatewayForward;
    use crate::net::rules::{Rule, RuleSet};
    use crate::net::tun::TunConfig;
    use crate::sandbox::{
        Isolation, IsolationError, IsolationMode, Launch, LaunchContext, NetworkMode, SandboxHost,
        launch_vm, wrap,
    };

    const KEYS: [&str; 2] = ["ENGINE_CONFIG_DIR", "ENGINE_OWN_DIR"];
    const TEST_DISK: &str = "/disks/root.qcow2";

    /// A host layout: a VM rootfs image, a thread work dir, a gino-agent
    /// stand-in, a global config dir and a `gino-vmm` script.
    struct Host {
        tmp: tempfile::TempDir,
        root: PathBuf,
        work_dir: PathBuf,
        exe: PathBuf,
        global: PathBuf,
        settings: VmSettings,
    }

    impl Host {
        fn new(vmm_body: &str) -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let root = std::fs::canonicalize(tmp.path()).unwrap();
            let rootfs = root.join("rootfs.ext4");
            std::fs::write(&rootfs, "ext4").unwrap();
            let work_dir = root.join("ws/threads/t1");
            std::fs::create_dir_all(work_dir.join("project")).unwrap();
            let exe = root.join("gino-agent");
            std::fs::write(&exe, "agent").unwrap();
            let global = root.join("global");
            std::fs::create_dir_all(global.join("skills")).unwrap();
            std::fs::write(global.join("CLAUDE.md"), "be nice").unwrap();
            let store = root.join("store/demo");
            std::fs::create_dir_all(&store).unwrap();
            std::fs::write(store.join("SKILL.md"), "demo skill").unwrap();
            std::os::unix::fs::symlink(&store, global.join("skills/demo")).unwrap();
            let vmm = root.join("gino-vmm");
            executable(&vmm, &format!("#!/bin/sh\n{vmm_body}\n"));
            let settings = VmSettings {
                config: VmConfig {
                    kernel: root.join("vmlinux"),
                    rootfs,
                    vmm,
                    has_libkrun: false,
                    vcpus: 2,
                    memory_mib: 1024,
                    disk_gib: 1,
                    docker: false,
                },
                read_paths: Vec::new(),
                write_paths: Vec::new(),
                task_disk: false,
            };
            Self {
                tmp,
                root,
                work_dir,
                exe,
                global,
                settings,
            }
        }

        fn ctx(&self) -> LaunchContext<'_> {
            LaunchContext {
                isolation: Box::leak(Box::default()),
                task_override: None,
                workspace_dir: Box::leak(self.root.join("ws").into_boxed_path()),
                task_id: Some("task-1"),
                thread_id: Some("t1"),
                work_dir: Some(&self.work_dir),
                memory_dir: None,
                agent_memory_dir: None,
                agent_memory_access: crate::memory::AgentMemoryAccess::Rw,
                task_archives: &[],
                conversations_max_bytes: crate::sandbox::DEFAULT_CONVERSATIONS_MAX_BYTES,
                self_exe: Some(&self.exe),
                global_config_dir: Some(&self.global),
                config_dir_keys: &KEYS,
                floored: false,
            }
        }

        fn direct(&self, program: &str, env: &[(&str, &str)]) -> Launch {
            Launch::direct(
                program.into(),
                vec!["-p".to_owned(), "hello world".to_owned()],
                env.iter()
                    .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
                    .collect(),
                self.work_dir.join("project"),
            )
        }

        fn prepare(&self) -> Launch {
            prepare(
                &self.direct("engine", &[]),
                &self.ctx(),
                &self.settings,
                &host(),
                None,
            )
            .unwrap()
        }
    }

    fn executable(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn host() -> VmHost {
        VmHost {
            uid: 1000,
            gid: 1000,
            env: vec![
                ("PATH".into(), "/host/bin".into()),
                ("HOME".into(), "/root".into()),
                ("KEEP".into(), "1".into()),
                ("GINO_TASK_ID".into(), "old".into()),
            ],
        }
    }

    fn prepared(launch: &Launch) -> &VmPrepared {
        launch.vm.as_deref().unwrap()
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn plan_builds_the_guest_spec_and_run_spec() {
        let h = Host::new("exit 0");
        let direct = h.direct(
            "engine",
            &[
                ("ENGINE_CONFIG_DIR", "/ws/engine-config"),
                ("GINO_TASK_ID", "task-1"),
                ("GINO_AGENT_SOCK", "/ws/run/agent.sock"),
                ("GINO_AGENT_TOKEN", "tok"),
                ("GINO_RUNNER_BIN", "/usr/bin/gino-agent"),
                ("GINO_WORKSPACE_DIR", "/ws"),
                ("ANTHROPIC_BASE_URL", "http://127.0.0.1:8080"),
            ],
        );
        let run_dir = Path::new("/run-dir");
        let p = plan(
            &direct,
            &h.ctx(),
            &h.settings,
            &host(),
            run_dir,
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        let work = h.work_dir.to_str().unwrap();
        let home = format!("{work}/.engine-home");
        let env: Vec<(&str, &str)> = p
            .guest
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            env,
            [
                ("KEEP", "1"),
                ("GINO_TASK_ID", "task-1"),
                ("GINO_AGENT_TOKEN", "tok"),
                ("ANTHROPIC_BASE_URL", "http://127.0.0.1:8080"),
                ("PATH", super::GUEST_PATH),
                ("HOME", "/tmp"),
                ("TMPDIR", "/tmp"),
                ("GINO_ARCHIVE_DIR", &format!("{work}/conversations")),
                ("GINO_VM", "1"),
                ("ENGINE_CONFIG_DIR", &home),
                ("ENGINE_OWN_DIR", &home),
                ("GINO_AGENT_SOCK", "/run/gino/agent.sock"),
                ("GINO_RUNNER_BIN", "/gino-agent"),
            ]
        );
        assert_eq!(p.guest.argv, ["engine", "-p", "hello world"]);
        assert_eq!(p.guest.cwd, format!("{work}/project"));
        assert_eq!((p.guest.uid, p.guest.gid), (1000, 1000));
        assert_eq!(
            p.guest.mounts,
            [GuestMount {
                tag: "work".into(),
                guest_path: work.into(),
                read_only: false,
            }]
        );
        assert_eq!(
            p.guest.binds,
            [
                GuestBind {
                    source: "/run/gino/ctl/view/0".into(),
                    target: format!("{home}/CLAUDE.md"),
                },
                GuestBind {
                    source: "/run/gino/ctl/view/1".into(),
                    target: format!("{home}/skills"),
                },
            ]
        );
        assert_eq!(p.guest.net, None);
        let api = p.guest.agent_api.as_ref().unwrap();
        assert_eq!(
            (api.vsock_port, api.socket_path.as_str()),
            (5000, "/run/gino/agent.sock")
        );
        assert_eq!(p.guest.control_vsock_port, 5001);
        assert_eq!(p.agent_token.as_deref(), Some("tok"));
        assert_eq!(
            p.placeholders,
            [
                (PathBuf::from(&home), true),
                (PathBuf::from(format!("{home}/CLAUDE.md")), false),
                (PathBuf::from(format!("{home}/skills")), true),
            ]
        );

        let root = h.root.to_str().unwrap();
        assert_eq!(
            serde_json::to_value(&p.run_spec).unwrap(),
            json!({
                "kernel": {"path": format!("{root}/vmlinux"), "format": "elf"},
                "rootDir": "/run-dir/boot",
                "shares": [
                    {"tag": "work", "hostPath": work, "readOnly": false},
                ],
                "overlayFiles": [{"hostPath": format!("{root}/gino-agent"), "guestPath": "/gino-agent"}],
                "disks": [{"id": "root", "path": TEST_DISK, "format": "qcow2"}],
                "vcpus": 2,
                "memoryMib": 1024,
                "exec": {"path": "/gino-agent", "args": ["guest-init"], "workdir": "/"},
                "vsockPorts": [
                    {"port": 5001, "hostSocketPath": "/run-dir/ctl.sock", "listen": true},
                    {"port": 5000, "hostSocketPath": "/run-dir/agent.sock", "listen": false},
                ],
            })
        );
    }

    #[test]
    fn an_agent_installed_engine_is_shared_read_only() {
        let h = Host::new("exit 0");
        let home = h.root.join("ws/engines/home");
        let claude = home.join(".local/bin/claude");
        let mounts = |program: &Path| {
            plan(
                &h.direct(program.to_str().unwrap(), &[]),
                &h.ctx(),
                &h.settings,
                &host(),
                Path::new("/r"),
                None,
                Path::new(TEST_DISK),
            )
            .unwrap()
            .guest
            .mounts
            .into_iter()
            .map(|m| (m.tag, m.guest_path, m.read_only))
            .collect::<Vec<_>>()
        };
        assert_eq!(
            mounts(&claude)[1..],
            [("engines".to_owned(), home.display().to_string(), true)]
        );
        assert_eq!(mounts(Path::new("claude")).len(), 1);
    }

    #[test]
    fn plan_without_agent_api_or_globals_and_with_extra_paths() {
        let mut h = Host::new("exit 0");
        let readable = h.root.join("ro");
        let ro_file = h.root.join("ro.txt");
        let writable = h.root.join("rw");
        std::fs::create_dir(&readable).unwrap();
        std::fs::write(&ro_file, "x").unwrap();
        std::fs::create_dir(&writable).unwrap();
        h.settings.read_paths = vec![readable.clone(), ro_file.clone()];
        h.settings.write_paths = vec![writable.clone()];
        let mut ctx = h.ctx();
        ctx.global_config_dir = None;
        let p = plan(
            &h.direct("engine", &[("GINO_AGENT_TOKEN", "tok")]),
            &ctx,
            &h.settings,
            &host(),
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        assert_eq!(p.agent_token, None);
        assert_eq!(p.guest.agent_api, None);
        assert!(p.guest.env.iter().all(|(k, _)| k != "GINO_AGENT_SOCK"));
        let tags: Vec<_> = p
            .guest
            .mounts
            .iter()
            .map(|m| (m.tag.as_str(), m.guest_path.clone(), m.read_only))
            .collect();
        assert_eq!(
            tags,
            [
                ("work", h.work_dir.display().to_string(), false),
                ("ro0", readable.display().to_string(), true),
                ("rw0", writable.display().to_string(), false),
            ]
        );
        assert_eq!(p.guest.binds.len(), 1);
        assert_eq!(p.guest.binds[0].target, ro_file.display().to_string());
        let value = serde_json::to_value(&p.run_spec).unwrap();
        assert_eq!(value["vsockPorts"].as_array().unwrap().len(), 1);
        assert_eq!(value["shares"].as_array().unwrap().len(), 3);

        h.settings.write_paths = vec![ro_file];
        let err = plan(
            &h.direct("engine", &[]),
            &h.ctx(),
            &h.settings,
            &host(),
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap_err();
        assert!(err.to_string().contains("is not a directory"), "{err}");
    }

    #[test]
    fn the_engine_program_is_passed_to_the_guest_as_is() {
        let h = Host::new("exit 0");
        for program in ["claude", "/usr/local/bin/codex"] {
            let p = plan(
                &h.direct(program, &[]),
                &h.ctx(),
                &h.settings,
                &host(),
                Path::new("/r"),
                None,
                Path::new(TEST_DISK),
            )
            .unwrap();
            assert_eq!(p.guest.argv[0], program);
        }
        let err = plan(
            &h.direct("bin/claude", &[]),
            &h.ctx(),
            &h.settings,
            &host(),
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap_err();
        assert!(err.to_string().contains("argv[0]"), "{err}");
    }

    #[test]
    fn paths_the_guest_cannot_express_fail_before_spawn() {
        let mut h = Host::new("exit 0");
        h.settings.read_paths = vec!["/proc/sys".into()];
        let err = prepare(
            &h.direct("engine", &[]),
            &h.ctx(),
            &h.settings,
            &host(),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Vm(m)) if m.contains("cannot express")),
            "{err:?}"
        );
        let mut ctx = h.ctx();
        ctx.work_dir = None;
        let err = plan(
            &h.direct("engine", &[]),
            &ctx,
            &h.settings,
            &host(),
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap_err();
        assert!(err.to_string().contains("work dir"), "{err}");
    }

    #[test]
    fn host_hook_commands_in_settings_run_the_guest_binary() {
        let exe = Path::new("/opt/gino/gino-agent");
        let settings = serde_json::json!({
            "model": "x",
            "hooks": {
                "PreCompact": [{ "hooks": [{ "type": "command", "command": "/opt/gino/gino-agent archive" }] }],
                "Stop": [{ "hooks": [
                    { "type": "command", "command": "/opt/gino/gino-agent" },
                    { "type": "command", "command": "/opt/gino/gino-agent-x run" },
                    { "type": "command", "command": "echo /opt/gino/gino-agent" },
                ] }],
            },
        });
        let mut argv: Vec<String> = [
            "/usr/local/bin/claude",
            "--settings",
            &settings.to_string(),
            "--settings",
            "/etc/claude/settings.json",
            "-p",
            "/opt/gino/gino-agent archive",
        ]
        .map(str::to_owned)
        .to_vec();
        guest_settings_args(&mut argv, exe, None);
        let rewritten: serde_json::Value = serde_json::from_str(&argv[2]).unwrap();
        assert_eq!(
            rewritten,
            serde_json::json!({
                "model": "x",
                "hooks": {
                    "PreCompact": [{ "hooks": [{ "type": "command", "command": "/gino-agent archive" }] }],
                    "Stop": [{ "hooks": [
                        { "type": "command", "command": "/gino-agent" },
                        { "type": "command", "command": "/opt/gino/gino-agent-x run" },
                        { "type": "command", "command": "echo /opt/gino/gino-agent" },
                    ] }],
                },
            })
        );
        assert_eq!(argv[4], "/etc/claude/settings.json");
        assert_eq!(argv[6], "/opt/gino/gino-agent archive");

        let untouched = r#"{"hooks":{"PreCompact":[{"hooks":[{"command":"other archive"}]}]}}"#;
        let mut argv = vec!["--settings".to_owned(), untouched.to_owned()];
        guest_settings_args(&mut argv, exe, None);
        assert_eq!(argv[1], untouched);
        let mut argv = vec!["--settings".to_owned()];
        guest_settings_args(&mut argv, exe, None);
        assert_eq!(argv, ["--settings"]);
    }

    #[test]
    fn the_planned_settings_hook_runs_the_guest_binary() {
        let h = Host::new("exit 0");
        let hook = format!(
            r#"{{"hooks":{{"PreCompact":[{{"hooks":[{{"type":"command","command":"{} archive"}}]}}]}}}}"#,
            h.exe.display()
        );
        let mut direct = h.direct("engine", &[]);
        direct.args = vec!["--settings".into(), hook.into()];
        let p = plan(
            &direct,
            &h.ctx(),
            &h.settings,
            &host(),
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        assert_eq!(
            p.guest.argv[2],
            r#"{"hooks":{"PreCompact":[{"hooks":[{"command":"/gino-agent archive","type":"command"}]}]}}"#
        );
    }

    #[test]
    fn the_planned_settings_point_auto_memory_at_the_task_share() {
        let h = Host::new("exit 0");
        let task = h.root.join("ws/memory/task/task-1");
        let host_dir = task.join("claude");
        let settings = json!({
            "autoMemoryDirectory": host_dir.to_str().unwrap(),
            "hooks": { "PreCompact": [{ "hooks": [{ "type": "command", "command": format!("{} archive", h.exe.display()) }] }] },
        });
        let mut direct = h.direct("engine", &[]);
        direct.args = vec!["--settings".into(), settings.to_string().into()];
        let guest_hooks = json!({ "PreCompact": [{ "hooks": [{ "type": "command", "command": "/gino-agent archive" }] }] });

        let mut ctx = h.ctx();
        ctx.memory_dir = Some(&task);
        let p = plan(
            &direct,
            &ctx,
            &h.settings,
            &host(),
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&p.guest.argv[2]).unwrap(),
            json!({ "autoMemoryDirectory": "/run/gino/memory/task/claude", "hooks": guest_hooks })
        );
        assert!(
            !p.guest
                .argv
                .iter()
                .any(|a| a.contains(host_dir.to_str().unwrap()))
        );

        ctx.memory_dir = None;
        let p = plan(
            &direct,
            &ctx,
            &h.settings,
            &host(),
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&p.guest.argv[2]).unwrap(),
            json!({ "autoMemoryEnabled": false, "hooks": guest_hooks })
        );
    }

    #[test]
    fn the_planned_auto_memory_off_settings_stay_as_they_are() {
        let h = Host::new("exit 0");
        let task = h.root.join("ws/memory/task/task-1");
        let settings = r#"{"autoMemoryEnabled":false}"#;
        let mut direct = h.direct("engine", &[("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1")]);
        direct.args = vec!["--settings".into(), settings.into()];
        for memory_dir in [Some(task.as_path()), None] {
            let mut ctx = h.ctx();
            ctx.memory_dir = memory_dir;
            let p = plan(
                &direct,
                &ctx,
                &h.settings,
                &host(),
                Path::new("/r"),
                None,
                Path::new(TEST_DISK),
            )
            .unwrap();
            assert_eq!(p.guest.argv[2], settings);
            assert_eq!(
                env_of(&p, &["CLAUDE_CODE_DISABLE_AUTO_MEMORY"]),
                [("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1")]
            );
        }
    }

    #[test]
    fn prepare_writes_the_control_share_and_drop_removes_the_run_dir() {
        let h = Host::new("exit 0");
        let launch = h.prepare();
        assert_eq!(launch.program, h.settings.config.vmm);
        assert!(launch.args.is_empty() && launch.env.is_empty() && !launch.sandboxed);
        let vm = prepared(&launch);
        let dir = vm.dir.0.clone();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let spec = std::fs::read_to_string(dir.join("boot/ctl/spec.json")).unwrap();
        let spec = GuestSpec::from_json(&spec).unwrap();
        assert_eq!(spec.argv[0], "engine");
        assert_eq!(
            std::fs::read_to_string(dir.join("boot/ctl/view/0")).unwrap(),
            "be nice"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("boot/ctl/view/1/demo/SKILL.md")).unwrap(),
            "demo skill"
        );
        let home = h.work_dir.join(".engine-home");
        assert!(home.join("CLAUDE.md").is_file());
        assert!(home.join("skills").is_dir());
        assert!(vm.run_spec.starts_with('{') && !vm.run_spec.contains('\n'));
        assert!(vm.agent.is_none());
        drop(launch);
        assert!(!dir.exists());
    }

    /// Engine env entries of `p` whose names are `keys`.
    fn env_of<'a>(p: &'a VmPlan, keys: &[&str]) -> Vec<(&'a str, &'a str)> {
        p.guest
            .env
            .iter()
            .filter(|(k, _)| keys.contains(&k.as_str()))
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect()
    }

    const MEMORY_KEYS: [&str; 3] = [
        "GINO_MEMORY_DIR",
        "GINO_AGENT_MEMORY_DIR",
        "GINO_CONVERSATIONS_DIR",
    ];

    /// A direct launch carrying host values of the memory env vars.
    fn memory_direct(h: &Host) -> Launch {
        h.direct(
            "engine",
            &[
                ("GINO_MEMORY_DIR", "/ws/memory/task/task-1"),
                ("GINO_AGENT_MEMORY_DIR", "/ws/memory/agent"),
                ("GINO_CONVERSATIONS_DIR", "/ws/conversations"),
            ],
        )
    }

    #[test]
    fn plan_shares_task_and_agent_memory_at_their_engine_paths() {
        let h = Host::new("exit 0");
        let task = h.root.join("ws/memory/task/task-1");
        let agent = h.root.join("ws/memory/agent");
        for access in [AgentMemoryAccess::Rw, AgentMemoryAccess::Ro] {
            let read_only = access == AgentMemoryAccess::Ro;
            let mut ctx = h.ctx();
            ctx.memory_dir = Some(&task);
            ctx.agent_memory_dir = Some(&agent);
            ctx.agent_memory_access = access;
            let p = plan(
                &memory_direct(&h),
                &ctx,
                &h.settings,
                &host(),
                Path::new("/r"),
                None,
                Path::new(TEST_DISK),
            )
            .unwrap();
            assert_eq!(
                env_of(&p, &MEMORY_KEYS),
                [
                    ("GINO_MEMORY_DIR", "/run/gino/memory/task"),
                    ("GINO_AGENT_MEMORY_DIR", "/run/gino/memory/agent"),
                    ("GINO_CONVERSATIONS_DIR", "/run/gino/conversations"),
                ]
            );
            assert_eq!(
                p.guest.mounts[1..],
                [
                    GuestMount {
                        tag: "task-memory".into(),
                        guest_path: "/run/gino/memory/task".into(),
                        read_only: false,
                    },
                    GuestMount {
                        tag: "agent-memory".into(),
                        guest_path: "/run/gino/memory/agent".into(),
                        read_only,
                    },
                ]
            );
            assert_eq!(
                serde_json::to_value(&p.run_spec.shares[1..]).unwrap(),
                json!([
                    {"tag": "task-memory", "hostPath": task.to_str().unwrap(), "readOnly": false},
                    {"tag": "agent-memory", "hostPath": agent.to_str().unwrap(), "readOnly": read_only},
                ])
            );
            assert_eq!(
                p.guest.binds.last().unwrap(),
                &GuestBind {
                    source: "/run/gino/ctl/view/2".into(),
                    target: "/run/gino/conversations".into(),
                }
            );
            assert!(
                p.placeholders
                    .iter()
                    .all(|(path, _)| path.starts_with(&h.work_dir))
            );
            p.guest.validate().unwrap();
        }
    }

    #[test]
    fn memory_off_drops_the_shares_the_view_and_the_host_env() {
        let h = Host::new("exit 0");
        let mut inherited = host();
        inherited.env.push((
            "GINO_AGENT_MEMORY_DIR".into(),
            "/daemon/memory/agent".into(),
        ));
        let agent = h.root.join("ws/memory/agent");
        let task = h.root.join("ws/memory/task/task-1");

        let p = plan(
            &memory_direct(&h),
            &h.ctx(),
            &h.settings,
            &inherited,
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        assert!(env_of(&p, &MEMORY_KEYS).is_empty(), "{:?}", p.guest.env);
        assert_eq!(p.guest.mounts.len(), 1);
        assert_eq!(p.run_spec.shares.len(), 1);
        assert!(
            p.guest
                .binds
                .iter()
                .all(|b| b.target != "/run/gino/conversations")
        );

        let mut ctx = h.ctx();
        ctx.agent_memory_dir = Some(&agent);
        let p = plan(
            &memory_direct(&h),
            &ctx,
            &h.settings,
            &inherited,
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        assert_eq!(
            env_of(&p, &MEMORY_KEYS),
            [("GINO_AGENT_MEMORY_DIR", "/run/gino/memory/agent")]
        );
        assert_eq!(p.guest.mounts[1].tag, "agent-memory");
        assert_eq!(p.guest.mounts.len(), 2);
        assert!(
            p.guest
                .binds
                .iter()
                .all(|b| b.target != "/run/gino/conversations")
        );

        let mut ctx = h.ctx();
        ctx.memory_dir = Some(&task);
        let p = plan(
            &memory_direct(&h),
            &ctx,
            &h.settings,
            &inherited,
            Path::new("/r"),
            None,
            Path::new(TEST_DISK),
        )
        .unwrap();
        assert_eq!(
            env_of(&p, &MEMORY_KEYS),
            [
                ("GINO_MEMORY_DIR", "/run/gino/memory/task"),
                ("GINO_CONVERSATIONS_DIR", "/run/gino/conversations"),
            ]
        );
        assert_eq!(p.guest.mounts[1].tag, "task-memory");
        assert_eq!(p.guest.mounts.len(), 2);
    }

    #[test]
    fn prepare_snapshots_the_conversations_view_into_the_run_dir() {
        let h = Host::new("exit 0");
        let task = h.root.join("ws/memory/task/task-1");
        std::fs::create_dir_all(&task).unwrap();
        let mut ctx = h.ctx();
        ctx.memory_dir = Some(&task);

        let launch = prepare(&h.direct("engine", &[]), &ctx, &h.settings, &host(), None).unwrap();
        let view = prepared(&launch).dir.0.join("boot/ctl/view/2");
        assert_eq!(std::fs::read_dir(&view).unwrap().count(), 0);
        assert!(launch.conversations.is_none());
        drop(launch);

        let archives: Vec<PathBuf> = ["t0", "t2"]
            .iter()
            .map(|thread| {
                let dir = h.root.join(format!("ws/threads/{thread}/conversations"));
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("a.jsonl"), "0123456789").unwrap();
                dir
            })
            .collect();
        std::os::unix::fs::symlink(h.global.join("CLAUDE.md"), archives[1].join("link.jsonl"))
            .unwrap();
        ctx.task_archives = &archives;
        ctx.conversations_max_bytes = 15;
        let launch = prepare(&h.direct("engine", &[]), &ctx, &h.settings, &host(), None).unwrap();
        let dir = prepared(&launch).dir.0.clone();
        let view = dir.join("boot/ctl/view/2");
        assert_eq!(
            std::fs::read_to_string(view.join("t2/a.jsonl")).unwrap(),
            "0123456789"
        );
        assert!(!view.join("t2/link.jsonl").exists());
        assert!(!view.join("t0").exists());
        let note = std::fs::read_to_string(view.join(crate::sandbox::TRUNCATED_NOTE)).unwrap();
        assert!(note.contains("15 bytes"), "{note}");
        drop(launch);
        assert!(!dir.exists());
    }

    #[test]
    fn the_memory_context_hook_runs_the_guest_binary() {
        let exe = Path::new("/opt/gino/gino-agent");
        for flag in ["", " --agent-read-only"] {
            let settings = json!({ "hooks": {
                "PreCompact": [{ "hooks": [{ "type": "command", "command": "/opt/gino/gino-agent archive" }] }],
                "SessionStart": [{
                    "matcher": "startup|clear|compact",
                    "hooks": [{ "type": "command", "command": format!("/opt/gino/gino-agent memory-context --max-bytes 4096{flag}") }]
                }],
            } });
            let mut argv = vec!["--settings".to_owned(), settings.to_string()];
            guest_settings_args(&mut argv, exe, None);
            let rewritten: serde_json::Value = serde_json::from_str(&argv[1]).unwrap();
            assert_eq!(
                rewritten,
                json!({ "hooks": {
                    "PreCompact": [{ "hooks": [{ "type": "command", "command": "/gino-agent archive" }] }],
                    "SessionStart": [{
                        "matcher": "startup|clear|compact",
                        "hooks": [{ "type": "command", "command": format!("/gino-agent memory-context --max-bytes 4096{flag}") }]
                    }],
                } })
            );
        }
    }

    /// A `vm` isolation with `network`, allowing TCP to `localhost:port`
    /// (loopback needs a cidr rule too) and forwarding a loopback LLM endpoint
    /// on 8080.
    fn networked(h: &Host, network: NetworkMode, port: u16) -> Isolation {
        let rules: Vec<Rule> = [
            format!(r#"{{"host":"localhost","ports":[{port}]}}"#),
            format!(r#"{{"cidr":"127.0.0.1/32","ports":[{port}]}}"#),
        ]
        .iter()
        .map(|rule| serde_json::from_str(rule).unwrap())
        .collect();
        Isolation {
            mode: IsolationMode::Vm,
            network,
            allowlist: (network != NetworkMode::None)
                .then(|| Arc::new(RuleSet::compile(&rules, &[]).unwrap())),
            llm_gateway: (network != NetworkMode::None).then(|| GatewayForward {
                port: 8080,
                target: "127.0.0.1:8080".parse().unwrap(),
            }),
            vm: Some(Arc::new(h.settings.clone())),
            ..Isolation::off()
        }
    }

    fn llm_direct(h: &Host) -> Launch {
        h.direct(
            "engine",
            &[("ANTHROPIC_BASE_URL", "http://127.0.0.1:8080/v1")],
        )
    }

    #[test]
    fn vm_networks_carry_the_exit_and_a_guest_eth0() {
        let h = Host::new("exit 0");
        for network in [NetworkMode::Allowlist, NetworkMode::Full] {
            let isolation = networked(&h, network, 9);
            let launch = launch_vm(llm_direct(&h), &h.ctx(), &isolation, &host()).unwrap();
            let vm = prepared(&launch);
            let dir = vm.dir.0.clone();
            let net = vm.net.as_ref().unwrap();
            assert!(Arc::ptr_eq(
                &net.exit.rules,
                isolation.allowlist.as_ref().unwrap()
            ));
            assert_eq!(net.exit.gateway, isolation.llm_gateway);
            assert_eq!(net.exit.thread_id, "t1");
            assert!(dir.join("net.sock").exists());

            let spec = std::fs::read_to_string(dir.join("boot/ctl/spec.json")).unwrap();
            let spec = GuestSpec::from_json(&spec).unwrap();
            assert_eq!(
                spec.net,
                Some(GuestNet {
                    address: "10.0.2.15/24".into(),
                    gateway: "10.0.2.2".into(),
                    dns: "10.0.2.2".into(),
                    mtu: net.exit.mtu,
                })
            );
            assert_eq!(net.exit.mtu, TunConfig::default().mtu);
            // A loopback LLM endpoint is reached through the gateway.
            let urls: Vec<_> = spec
                .env
                .iter()
                .filter(|(k, _)| k == "ANTHROPIC_BASE_URL")
                .map(|(_, v)| v.as_str())
                .collect();
            assert_eq!(urls, ["http://10.0.2.2:8080/v1"], "{network:?}");

            let run_spec: serde_json::Value = serde_json::from_str(&vm.run_spec).unwrap();
            assert_eq!(
                run_spec["net"],
                json!({
                    "unixstreamPath": dir.join("net.sock").to_str().unwrap(),
                    "mac": "5a:94:ef:e4:0c:ee",
                }),
                "{network:?}"
            );
        }

        let isolation = networked(&h, NetworkMode::None, 9);
        let launch = launch_vm(llm_direct(&h), &h.ctx(), &isolation, &host()).unwrap();
        let vm = prepared(&launch);
        assert!(vm.net.is_none());
        assert!(!vm.dir.0.join("net.sock").exists());
        let run_spec: serde_json::Value = serde_json::from_str(&vm.run_spec).unwrap();
        assert!(run_spec.get("net").is_none());
        let spec = std::fs::read_to_string(vm.dir.0.join("boot/ctl/spec.json")).unwrap();
        let spec = GuestSpec::from_json(&spec).unwrap();
        assert_eq!(spec.net, None);
        assert!(spec.env.contains(&(
            "ANTHROPIC_BASE_URL".into(),
            "http://127.0.0.1:8080/v1".into()
        )));

        let mut isolation = networked(&h, NetworkMode::Full, 9);
        isolation.allowlist = None;
        let err = launch_vm(llm_direct(&h), &h.ctx(), &isolation, &host()).unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Missing(_))),
            "{err:?}"
        );
    }

    #[test]
    fn the_vm_exit_is_configured_like_the_sandbox_one() {
        let h = Host::new("exit 0");
        let isolation = networked(&h, NetworkMode::Allowlist, 9);
        let vm_launch = launch_vm(llm_direct(&h), &h.ctx(), &isolation, &host()).unwrap();
        let vm = &prepared(&vm_launch).net.as_ref().unwrap().exit;
        let bin = h.root.join("bin");
        std::fs::create_dir(&bin).unwrap();
        executable(&bin.join("engine"), "#!/bin/sh\n");
        let sandbox_launch = wrap(
            llm_direct(&h),
            &h.ctx(),
            &Isolation {
                mode: IsolationMode::Sandbox,
                vm: None,
                ..isolation.clone()
            },
            &SandboxHost::fixture(Some(bin.into_os_string())),
        )
        .unwrap();
        let sandbox = &sandbox_launch.net.as_deref().unwrap().exit;
        assert_eq!(format!("{vm:?}"), format!("{sandbox:?}"));
        assert!(Arc::ptr_eq(&vm.rules, &sandbox.rules));
    }

    #[test]
    fn the_guest_and_gateway_macs_are_local_unicast() {
        for mac in [super::GUEST_MAC, super::GATEWAY_MAC] {
            assert!(mac.is_unicast(), "{mac}");
            assert_ne!(mac.0[0] & 0x02, 0, "{mac} is locally administered");
            assert_ne!(mac.0, [0; 6]);
        }
        assert_ne!(super::GUEST_MAC, super::GATEWAY_MAC);
        assert_eq!(super::GUEST_MAC.to_string(), "5a:94:ef:e4:0c:ee");
    }

    fn net_prepare(h: &Host, port: u16) -> Launch {
        let isolation = networked(h, NetworkMode::Allowlist, port);
        launch_vm(llm_direct(h), &h.ctx(), &isolation, &host()).unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_vmm_that_never_connects_the_network_fails_the_run() {
        let h = Host::new("read -r spec\nexec sleep 30");
        let launch = net_prepare(&h, 9);
        let dir = prepared(&launch).dir.0.clone();
        let err = start_with(launch.vm.unwrap(), Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Network(m)) if m == "gino-vmm did not connect the VM network within 0.2s"),
            "{err:?}"
        );
        eventually("the run dir removal", || !dir.exists()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_vmm_exit_before_the_network_connects_fails_the_run() {
        let h = Host::new("read -r spec\necho 'gino-vmm: no net' >&2\nexit 120");
        let launch = net_prepare(&h, 9);
        let err = start(launch.vm.unwrap()).await.unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Network(m)) if m == "gino-vmm failed before the VM started: gino-vmm: no net"),
            "{err:?}"
        );
    }

    /// Ethernet frames of the fake guest's virtio-net stream.
    struct GuestLink {
        reader: nsplane_ether::stream::FramedReader<tokio::net::unix::OwnedReadHalf>,
        writer: nsplane_ether::stream::FramedWriter<tokio::net::unix::OwnedWriteHalf>,
    }

    impl GuestLink {
        async fn send(&mut self, dst: MacAddr, ethertype: u16, payload: &[u8]) {
            let mut frame = Vec::with_capacity(14 + payload.len());
            frame.extend_from_slice(&dst.0);
            frame.extend_from_slice(&GUEST_LINK_MAC.0);
            frame.extend_from_slice(&ethertype.to_be_bytes());
            frame.extend_from_slice(payload);
            self.writer.write_frame(&frame).await.unwrap();
        }

        async fn recv(&mut self) -> Vec<u8> {
            let mut buf = vec![0; nsplane_ether::MAX_FRAME_LEN];
            let len =
                tokio::time::timeout(Duration::from_secs(5), self.reader.read_frame(&mut buf))
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            buf.truncate(len);
            buf
        }
    }

    const GUEST_LINK_MAC: MacAddr = super::GUEST_MAC;
    const ETHERTYPE_IPV4: u16 = 0x0800;
    const ETHERTYPE_ARP: u16 = 0x0806;

    /// A wire-format A query for `name`.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut msg = vec![0x4a, 0x21, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(u8::try_from(label.len()).unwrap());
            msg.extend_from_slice(label.as_bytes());
        }
        msg.extend_from_slice(&[0, 0, 1, 0, 1]);
        msg
    }

    /// Plays libkrun and the guest: connects the virtio-net socket, resolves
    /// the gateway MAC over ARP, then runs a guest TCP/IP stack over the link
    /// that resolves `localhost` at the gateway and echoes through an allowed
    /// loopback server.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn the_guest_reaches_dns_and_an_allowed_server_through_the_vm_link() {
        use nsplane::{PacketBuf, PacketSink as _, PacketSource as _, PeerId};
        use nsplane_ether::{ArpOp, ArpPacket};
        use nsplane_netstack::{NetStack, NetStackConfig};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = server.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = conn.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });

        let h = Host::new("read -r spec\nexec sleep 30");
        let launch = net_prepare(&h, port);
        let dir = prepared(&launch).dir.0.clone();
        let _guest = fake_guest(&dir.join("ctl.sock"), |_, _| {});
        let stream = tokio::net::UnixStream::connect(dir.join("net.sock"))
            .await
            .unwrap();
        let (run, _pipes) = start(launch.vm.unwrap()).await.unwrap();
        let (reader, writer) = nsplane_ether::stream::unix(stream);
        let mut link = GuestLink { reader, writer };

        let guest_ip = std::net::Ipv4Addr::new(10, 0, 2, 15);
        let gateway_ip = std::net::Ipv4Addr::new(10, 0, 2, 2);
        let mut arp = Vec::new();
        ArpPacket {
            op: ArpOp::Request,
            sender_mac: GUEST_LINK_MAC,
            sender_ip: guest_ip,
            target_mac: MacAddr([0; 6]),
            target_ip: gateway_ip,
        }
        .write(&mut arp);
        link.send(MacAddr::BROADCAST, ETHERTYPE_ARP, &arp).await;
        let gateway_mac = loop {
            let frame = link.recv().await;
            if frame[12..14] != ETHERTYPE_ARP.to_be_bytes() {
                continue;
            }
            let reply = ArpPacket::parse(&frame[14..]).unwrap();
            if reply.op == ArpOp::Reply && reply.sender_ip == gateway_ip {
                assert_eq!(frame[..6], GUEST_LINK_MAC.0);
                break reply.sender_mac;
            }
        };
        assert_eq!(gateway_mac, super::GATEWAY_MAC);

        // The guest stack's IP packets, framed both ways.
        let (stack, net) = NetStack::new(NetStackConfig::new(
            vec![(std::net::IpAddr::V4(guest_ip), 24)],
            TunConfig::default().mtu,
        ));
        let (mut stack_source, stack_sink) = stack.split();
        let GuestLink {
            mut reader,
            mut writer,
        } = link;
        tokio::spawn(async move {
            let mut buf = vec![0; nsplane_ether::MAX_FRAME_LEN];
            while let Ok(Some(len)) = reader.read_frame(&mut buf).await {
                if len > 14 && buf[12..14] == ETHERTYPE_IPV4.to_be_bytes() {
                    let packet = PacketBuf::from_packet(&buf[14..len]);
                    if stack_sink.send(packet, PeerId::new(1)).await.is_err() {
                        break;
                    }
                }
            }
        });
        tokio::spawn(async move {
            while let Ok(packet) = stack_source.recv().await {
                let mut frame = Vec::new();
                frame.extend_from_slice(&gateway_mac.0);
                frame.extend_from_slice(&GUEST_LINK_MAC.0);
                frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
                frame.extend_from_slice(packet.as_packet());
                if writer.write_frame(&frame).await.is_err() {
                    break;
                }
            }
        });

        let wait = Duration::from_secs(5);
        let mut dns = net.connect_udp(crate::net::dns::DNS_ADDR).await.unwrap();
        dns.send(&dns_query("localhost")).await.unwrap();
        let (msg, from) = tokio::time::timeout(wait, dns.recv_from())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, crate::net::dns::DNS_ADDR);
        assert_eq!(msg[..2], [0x4a, 0x21]);
        assert_eq!(msg[3] & 0x0f, 0, "NOERROR");
        // The answer's A record is the last four bytes.
        let fake = std::net::Ipv4Addr::new(
            msg[msg.len() - 4],
            msg[msg.len() - 3],
            msg[msg.len() - 2],
            msg[msg.len() - 1],
        );
        assert!(
            crate::net::dns::GuestResolver::is_fake(fake.into()),
            "{fake}"
        );

        let mut conn = tokio::time::timeout(
            wait,
            net.connect_tcp(std::net::SocketAddr::new(fake.into(), port)),
        )
        .await
        .unwrap()
        .unwrap();
        conn.write_all(b"ping").await.unwrap();
        let mut echoed = [0; 4];
        tokio::time::timeout(wait, conn.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"ping");

        drop(run);
        eventually("the run dir removal", || !dir.exists()).await;
    }

    #[test]
    fn exit_reasons_name_gino_vmm_or_guest_init() {
        use std::os::unix::process::ExitStatusExt as _;
        let status = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        assert_eq!(
            exit_reason(
                status(120),
                "x\ngino-vmm: bad spec\n",
                "before the engine started"
            ),
            "gino-vmm failed before the VM started: gino-vmm: bad spec"
        );
        assert_eq!(
            exit_reason(
                status(121),
                "guest-init: share work is not writable\n[ 1.0] reboot\n",
                "before the engine started"
            ),
            "guest-init failed to start the engine: guest-init: share work is not writable"
        );
        assert_eq!(
            exit_reason(status(3), "", "after the engine started"),
            "gino-vmm exited (exit status: 3) after the engine started without an engine exit status"
        );
        assert!(exit_reason(status(137), "oops\n", "w").ends_with(": oops"));
    }

    /// The process `pid` exists and is not a zombie.
    fn alive(pid: u32) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let (_, rest) = stat.rsplit_once(')')?;
                rest.split_whitespace().next().map(|state| state != "Z")
            })
            .unwrap_or(false)
    }

    async fn eventually(what: &str, check: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !check() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A fake guest on the run's control socket: accepts, sends `READY`, then
    /// hands each later line it reads to `on_line` with the connection.
    fn fake_guest(
        ctl: &Path,
        on_line: impl Fn(&str, &mut std::os::unix::net::UnixStream) + Send + 'static,
    ) -> std::thread::JoinHandle<Vec<String>> {
        let listener = StdUnixListener::bind(ctl).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(b"READY\n").unwrap();
            let mut seen = Vec::new();
            let reader = StdBufReader::new(conn.try_clone().unwrap());
            for line in reader.lines() {
                let Ok(line) = line else { break };
                on_line(&line, &mut conn);
                seen.push(line);
            }
            seen
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ready_signal_exit_protocol_and_teardown() {
        let h = Host::new("read -r spec\nprintf '%s\\n' \"$spec\" > \"$0.spec\"\nexec sleep 30");
        let launch = h.prepare();
        let dir = prepared(&launch).dir.0.clone();
        let guest = fake_guest(&dir.join("ctl.sock"), |line, conn| {
            if line == "SIGNAL INT" {
                conn.write_all(b"EXIT signal 2\n").unwrap();
            }
        });
        let (mut run, _pipes) = start(launch.vm.unwrap()).await.unwrap();
        let pid = run.id().unwrap();
        assert!(alive(pid));
        let spec_seen = h.settings.config.vmm.with_extension("spec");
        eventually("the run spec line", || spec_seen.exists()).await;
        let line = std::fs::read_to_string(&spec_seen).unwrap();
        let spec: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(spec["exec"]["args"], json!(["guest-init"]));

        run.interrupt();
        // The daemon closes the control connection right after `EXIT`.
        let seen = tokio::task::spawn_blocking(move || guest.join().unwrap())
            .await
            .unwrap();
        assert_eq!(seen, ["SIGNAL INT"]);
        assert_eq!(run.monitor().failure().await, None);
        assert!(alive(pid), "gino-vmm still runs until the run is dropped");

        run.start_kill();
        assert!(run.wait().await.is_some());
        assert_eq!(run.id(), None);
        assert!(dir.exists(), "the run dir lives as long as the run");
        drop(run);
        eventually("the run dir removal", || !dir.exists()).await;
        let _ = &h.tmp;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dropping_the_run_sends_term_then_stops_gino_vmm() {
        let h = Host::new("read -r spec\nexec sleep 30");
        let launch = h.prepare();
        let dir = prepared(&launch).dir.0.clone();
        let vmm_pid = Arc::new(std::sync::Mutex::new(None::<u32>));
        let pid_for_guest = Arc::clone(&vmm_pid);
        let guest = fake_guest(&dir.join("ctl.sock"), move |line, _| {
            // The guest powers off on TERM: gino-vmm exits.
            if line == "SIGNAL TERM"
                && let Some(pid) = *pid_for_guest.lock().unwrap()
            {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
                    nix::sys::signal::Signal::SIGTERM,
                );
            }
        });
        let (run, _pipes) = start(launch.vm.unwrap()).await.unwrap();
        let pid = run.id().unwrap();
        *vmm_pid.lock().unwrap() = Some(pid);
        let started = Instant::now();
        drop(run);
        eventually("gino-vmm to exit", || !alive(pid)).await;
        eventually("the run dir removal", || !dir.exists()).await;
        assert!(
            started.elapsed() < super::TERM_GRACE,
            "stopped by TERM, not the grace kill"
        );
        let seen = tokio::task::spawn_blocking(move || guest.join().unwrap())
            .await
            .unwrap();
        assert_eq!(seen, ["SIGNAL TERM"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_vmm_ignoring_term_is_killed_after_the_grace() {
        let h = Host::new("read -r spec\ntrap '' TERM\nwhile :; do sleep 1; done");
        let launch = h.prepare();
        let dir = prepared(&launch).dir.0.clone();
        let _guest = fake_guest(&dir.join("ctl.sock"), |_, _| {});
        let (run, _pipes) = start(launch.vm.unwrap()).await.unwrap();
        let pid = run.id().unwrap();
        drop(run);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(alive(pid), "the engine gets its grace period");
        let deadline = Instant::now() + super::TERM_GRACE + Duration::from_secs(5);
        while alive(pid) {
            assert!(
                Instant::now() < deadline,
                "gino-vmm survived the grace period"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        eventually("the run dir removal", || !dir.exists()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn early_vmm_exits_fail_with_a_runner_side_reason() {
        for (body, expected) in [
            (
                "read -r spec\necho 'gino-vmm: invalid run spec: x' >&2\nexit 120",
                "engine isolation: engine VM: gino-vmm failed before the VM started: gino-vmm: invalid run spec: x",
            ),
            (
                "read -r spec\necho 'guest-init: share work is not writable' >&2\necho '[ 0.5] reboot' >&2\nexit 121",
                "engine isolation: engine VM: guest-init failed to start the engine: guest-init: share work is not writable",
            ),
            (
                "read -r spec\necho 'boom' >&2\nexit 7",
                "engine isolation: engine VM: gino-vmm exited (exit status: 7) before the engine started without an engine exit status: boom",
            ),
        ] {
            let h = Host::new(body);
            let launch = h.prepare();
            let dir = prepared(&launch).dir.0.clone();
            let err = start(launch.vm.unwrap()).await.unwrap_err();
            assert!(
                matches!(&err, EngineError::Isolation(IsolationError::Vm(_))),
                "{err:?}"
            );
            assert_eq!(err.to_string(), expected);
            eventually("the run dir removal", || !dir.exists()).await;
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_vmm_exit_without_exit_line_is_reported() {
        let h = Host::new("read -r spec\nsleep 1\necho 'console gone' >&2\nexit 3");
        let launch = h.prepare();
        let dir = prepared(&launch).dir.0.clone();
        let _guest = fake_guest(&dir.join("ctl.sock"), |_, _| {});
        let (run, _pipes) = start(launch.vm.unwrap()).await.unwrap();
        let reason = run.monitor().failure().await.unwrap();
        assert_eq!(
            reason,
            "gino-vmm exited (exit status: 3) after the engine started without an engine exit status"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_spawning_thread_outlives_the_spawn() {
        // gino-vmm sets PR_SET_PDEATHSIG itself; setpriv does it for the fake.
        if !Path::new("/usr/bin/setpriv").exists() {
            return;
        }
        let h = Host::new("read -r spec\nexec setpriv --pdeathsig KILL sleep 30");
        let launch = h.prepare();
        let dir = prepared(&launch).dir.0.clone();
        let _guest = fake_guest(&dir.join("ctl.sock"), |_, _| {});
        let (run, _pipes) = start(launch.vm.unwrap()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(
            alive(run.id().unwrap()),
            "the fake vmm died with a short-lived thread"
        );
        let pid = run.id().unwrap();
        drop(run);
        eventually("gino-vmm to exit", || !alive(pid)).await;
    }

    /// The VM artifacts of a KVM test run, or `None` unless `GINO_VM_TESTS=1`:
    /// `GINO_VM_KERNEL`, `GINO_VM_ROOTFS`, `GINO_VM_VMM` and the gino-agent
    /// binary `GINO_VM_AGENT` (`scripts/vm-it.sh` sets them).
    fn kvm_artifacts() -> Option<(VmConfig, PathBuf)> {
        if std::env::var("GINO_VM_TESTS").ok().as_deref() != Some("1") {
            return None;
        }
        let var = |key: &str| PathBuf::from(std::env::var(key).unwrap());
        let config = VmConfig {
            kernel: var("GINO_VM_KERNEL"),
            rootfs: var("GINO_VM_ROOTFS"),
            vmm: var("GINO_VM_VMM"),
            has_libkrun: false,
            vcpus: 1,
            memory_mib: 512,
            disk_gib: 1,
            docker: false,
        };
        Some((config, var("GINO_VM_AGENT")))
    }

    /// Boots a real VM (see [`kvm_artifacts`]). Needs `/dev/kvm` and a
    /// non-root uid.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
    async fn kvm_boot_runs_an_engine_and_reports_its_exit() {
        use tokio::io::AsyncBufReadExt as _;
        let Some((config, agent)) = kvm_artifacts() else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(tmp.path()).unwrap().join("thread");
        std::fs::create_dir(&work_dir).unwrap();
        let global = tmp.path().join("global");
        std::fs::create_dir(&global).unwrap();
        std::fs::write(global.join("CLAUDE.md"), "global rules\n").unwrap();
        let settings = VmSettings {
            config,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            task_disk: false,
        };
        let ctx = LaunchContext {
            isolation: Box::leak(Box::default()),
            task_override: None,
            workspace_dir: tmp.path(),
            task_id: Some("task-1"),
            thread_id: Some("t1"),
            work_dir: Some(&work_dir),
            memory_dir: None,
            agent_memory_dir: None,
            agent_memory_access: crate::memory::AgentMemoryAccess::Rw,
            task_archives: &[],
            conversations_max_bytes: crate::sandbox::DEFAULT_CONVERSATIONS_MAX_BYTES,
            self_exe: Some(&agent),
            global_config_dir: Some(&global),
            config_dir_keys: &KEYS,
            floored: false,
        };
        let direct = Launch::direct(
            "sh".into(),
            vec![
                "-c".to_owned(),
                "echo \"hi vm=$GINO_VM uid=$(id -u) home=$ENGINE_CONFIG_DIR\"; \
                 touch \"$ENGINE_CONFIG_DIR/written\"; \
                 echo \"rules: $(cat \"$ENGINE_CONFIG_DIR/CLAUDE.md\")\"; \
                 echo x >> \"$ENGINE_CONFIG_DIR/CLAUDE.md\" 2>/dev/null || echo rules-read-only; \
                 exit 3"
                    .to_owned(),
            ],
            Vec::new(),
            work_dir.clone(),
        );
        let launch = prepare(&direct, &ctx, &settings, &VmHost::current(), None).unwrap();
        let started = Instant::now();
        let (mut run, pipes) = start(launch.vm.unwrap()).await.unwrap();
        println!("READY after {:?}", started.elapsed());
        let mut lines = tokio::io::BufReader::new(pipes.stdout).lines();
        let mut out = Vec::new();
        while let Ok(Some(line)) = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
            .await
            .unwrap()
        {
            println!("guest: {line}");
            out.push(line);
        }
        let home = work_dir.join(".engine-home");
        let uid = nix::unistd::getuid().as_raw();
        assert!(
            out.iter()
                .any(|l| l.trim_end() == format!("hi vm=1 uid={uid} home={}", home.display())),
            "{out:?}"
        );
        assert!(
            out.iter().any(|l| l.trim_end() == "rules: global rules"),
            "{out:?}"
        );
        assert!(
            out.iter().any(|l| l.trim_end() == "rules-read-only"),
            "{out:?}"
        );
        assert_eq!(run.monitor().failure().await, None);
        let status = run.wait().await.unwrap();
        println!("gino-vmm {status} after {:?}", started.elapsed());
        assert_eq!(status.code(), Some(3));
        assert!(home.join("written").is_file());
    }

    /// Boots a real VM with an allowlist network (see [`kvm_artifacts`]): an
    /// allowed name resolves at the gateway and the loopback LLM endpoint
    /// answers through the gateway forward.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs KVM and the VM artifacts; run scripts/vm-it.sh"]
    async fn kvm_allowlist_resolves_and_reaches_the_llm_gateway() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let Some((config, agent)) = kvm_artifacts() else {
            return;
        };
        let llm = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = llm.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = llm.accept().await {
                let mut request = [0; 1024];
                let _ = conn.read(&mut request).await;
                let _ = conn
                    .write_all(b"HTTP/1.0 200 OK\r\ncontent-length: 4\r\n\r\npong")
                    .await;
            }
        });
        let tmp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(tmp.path()).unwrap().join("thread");
        std::fs::create_dir(&work_dir).unwrap();
        let settings = VmSettings {
            config,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            task_disk: false,
        };
        let rule: Rule = serde_json::from_str(r#"{"host":"example.com","ports":[443]}"#).unwrap();
        let isolation = Isolation {
            mode: IsolationMode::Vm,
            network: NetworkMode::Allowlist,
            allowlist: Some(Arc::new(RuleSet::compile(&[rule], &[]).unwrap())),
            llm_gateway: Some(GatewayForward {
                port,
                target: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            }),
            vm: Some(Arc::new(settings)),
            ..Isolation::off()
        };
        let ctx = LaunchContext {
            isolation: Box::leak(Box::default()),
            task_override: None,
            workspace_dir: tmp.path(),
            task_id: Some("task-1"),
            thread_id: Some("t1"),
            work_dir: Some(&work_dir),
            memory_dir: None,
            agent_memory_dir: None,
            agent_memory_access: crate::memory::AgentMemoryAccess::Rw,
            task_archives: &[],
            conversations_max_bytes: crate::sandbox::DEFAULT_CONVERSATIONS_MAX_BYTES,
            self_exe: Some(&agent),
            global_config_dir: None,
            config_dir_keys: &KEYS,
            floored: false,
        };
        let direct = Launch::direct(
            "sh".into(),
            vec![
                "-c".to_owned(),
                "echo \"dns: $(getent ahostsv4 example.com | head -n1 | cut -d' ' -f1)\"; \
                 echo \"llm: $(curl -sS --max-time 10 \"$ANTHROPIC_BASE_URL/v1\")\""
                    .to_owned(),
            ],
            vec![(
                "ANTHROPIC_BASE_URL".to_owned(),
                format!("http://127.0.0.1:{port}").into(),
            )],
            work_dir.clone(),
        );
        let launch = launch_vm(direct, &ctx, &isolation, &VmHost::current()).unwrap();
        let (mut run, pipes) = start(launch.vm.unwrap()).await.unwrap();
        let mut stdout = String::new();
        tokio::time::timeout(
            Duration::from_mins(1),
            tokio::io::BufReader::new(pipes.stdout).read_to_string(&mut stdout),
        )
        .await
        .unwrap()
        .unwrap();
        println!("{stdout}");
        let dns = stdout
            .lines()
            .find_map(|l| l.trim_end().strip_prefix("dns: "))
            .unwrap();
        let dns: std::net::IpAddr = dns.parse().unwrap();
        assert!(crate::net::dns::GuestResolver::is_fake(dns), "{dns}");
        assert!(
            stdout.lines().any(|l| l.trim_end() == "llm: pong"),
            "{stdout}"
        );
        assert_eq!(run.monitor().failure().await, None);
        assert_eq!(run.wait().await.unwrap().code(), Some(0));
    }
}
