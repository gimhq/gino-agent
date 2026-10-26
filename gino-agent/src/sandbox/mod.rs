//! Engine isolation: config types and per-run resolution.
//!
//! The config default (`engine.isolation`) and an optional task override
//! (`tasks.meta.isolation`) are kept as raw strings and resolved per run into an
//! [`Isolation`]. Unknown or unsupported values fail the run at resolve time
//! instead of breaking parsing of the whole config overlay.
//!
//! [`launch`] turns an engine's direct launch into the one a run actually
//! spawns: unchanged when off, wrapped in `bwrap` + `sandbox-init` when
//! sandboxed, a `gino-vmm` microVM under `vm`. [`spawn`] starts it. In
//! allowlist mode a sandbox launch also carries a [`NetHandover`]: right after
//! the spawn [`start_network`] receives the guest TUN device and starts the
//! run's network exit. A VM launch carries a [`vm::VmPrepared`] run that
//! [`vm::start`] boots; with a network it also carries the run's exit
//! settings, and the exit runs on the VM's virtio-net stream.

pub(crate) mod bwrap;
pub(crate) mod init;
pub(crate) mod vm;
pub(crate) mod vm_disk;

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as _};
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use nsplane_tun::Tun;
use serde::Deserialize;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use self::bwrap::{
    AGENT_SOCK, CTL_SOCK, CTL_SOCK_NAME, HostRoot, ProvisionedGlobals, RESOLV_CONF_NAME,
    SandboxLayout, bwrap_args, engine_home, host_root, prepare_engine_home, resolve_binary,
};
use self::vm::{VmConfig, VmHost, VmMonitor, VmPrepared, VmRun, VmSettings};
use crate::engine::EngineError;
use crate::memory::AgentMemoryAccess;
use crate::net::exit::{Exit, ExitConfig, GatewayForward};
use crate::net::fdpass::recv_fd;
use crate::net::rules::{AlwaysAllow, Proto, Rule, RuleError, RuleSet, normalize_name};
use crate::net::tun::TunConfig;
use crate::net::upstream::{is_link_local, is_local};

/// Sandbox `$HOME` when the daemon has none.
const DEFAULT_SANDBOX_HOME: &str = "/home/gino";

/// Env var naming the LLM API the engine talks to.
const LLM_BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";

/// Env var naming the daemon's agent API socket.
const AGENT_SOCK_ENV: &str = "GINO_AGENT_SOCK";

/// Env var naming the task memory tree.
pub(crate) const MEMORY_DIR_ENV: &str = "GINO_MEMORY_DIR";

/// Env var naming the agent memory tree.
pub(crate) const AGENT_MEMORY_DIR_ENV: &str = "GINO_AGENT_MEMORY_DIR";

/// In-engine path of the task memory tree.
pub(crate) const TASK_MEMORY_MOUNT: &str = "/run/gino/memory/task";

/// In-engine path of the agent memory tree.
pub(crate) const AGENT_MEMORY_MOUNT: &str = "/run/gino/memory/agent";

/// In-engine path of the read-only view of the task's earlier archives.
pub(crate) const CONVERSATIONS_MOUNT: &str = "/run/gino/conversations";

/// Env var naming the conversations view.
pub(crate) const CONVERSATIONS_DIR_ENV: &str = "GINO_CONVERSATIONS_DIR";

/// Default cap on the bytes copied into the conversations view.
pub(crate) const DEFAULT_CONVERSATIONS_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Note at the conversations view root when archives were left out.
pub(crate) const TRUNCATED_NOTE: &str = "TRUNCATED.md";

/// LLM API endpoint always allowed when no base URL is set.
const DEFAULT_LLM_HOST: &str = "api.anthropic.com";

/// Byte the daemon sends `sandbox-init` once the run's network exit runs.
pub(crate) const NET_READY: u8 = 0x52;

/// How long the daemon waits for `sandbox-init` to hand over the TUN device.
const HANDOVER_TIMEOUT: Duration = Duration::from_secs(30);

/// Bytes of `sandbox-init` stderr kept in a handover error.
const HANDOVER_STDERR_TAIL: usize = 1024;

/// How an engine run is isolated from the host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum IsolationMode {
    /// Run the engine directly (no isolation).
    #[default]
    Off,
    /// Run the engine inside a bubblewrap sandbox.
    Sandbox,
    /// Run the engine inside a VM.
    Vm,
}

/// Network access granted to an isolated run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NetworkMode {
    /// No network access.
    #[default]
    None,
    /// The host's network, unrestricted.
    Full,
    /// Only the destinations in [`Isolation::allowlist`].
    Allowlist,
}

/// Raw isolation block, as found in config (`engine.isolation`) or a task
/// override (`meta.isolation`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct IsolationSpec {
    pub(crate) mode: Option<String>,
    pub(crate) network: Option<NetworkSpec>,
    pub(crate) read_paths: Option<Vec<PathBuf>>,
    pub(crate) write_paths: Option<Vec<PathBuf>>,
    /// Lets a task override loosen the default; read from the config default only.
    pub(crate) allow_task_override: Option<bool>,
    /// The VM a `vm` run boots; read from the local isolation file only.
    pub(crate) vm: Option<VmConfig>,
    /// `vm` only: `run` (default) gives every run a fresh root disk, `task`
    /// keeps the task's root disk across its runs. From the local floor or a
    /// task override.
    pub(crate) vm_disk: Option<String>,
}

/// Raw `network` sub-block of an [`IsolationSpec`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct NetworkSpec {
    pub(crate) mode: Option<String>,
    /// Allowlist rules; read from the config default only.
    pub(crate) allow: Option<Vec<Rule>>,
}

/// Resolved isolation for one run.
#[derive(Clone, Debug)]
pub(crate) struct Isolation {
    pub(crate) mode: IsolationMode,
    pub(crate) network: NetworkMode,
    /// Compiled rules when the network mode is allowlist, or full under `vm`
    /// (every public destination).
    pub(crate) allowlist: Option<Arc<RuleSet>>,
    /// Allowlist only: the LLM endpoint on host loopback, reached by the guest
    /// on the gateway address.
    pub(crate) llm_gateway: Option<GatewayForward>,
    /// Extra host paths mounted read-only.
    pub(crate) read_paths: Vec<PathBuf>,
    /// Extra host paths mounted read-write.
    pub(crate) write_paths: Vec<PathBuf>,
    /// `vm` only: the VM to boot.
    pub(crate) vm: Option<Arc<VmSettings>>,
}

/// Compares the allowlist by identity.
impl PartialEq for Isolation {
    fn eq(&self, other: &Self) -> bool {
        let same_allowlist = match (&self.allowlist, &other.allowlist) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        self.mode == other.mode
            && self.network == other.network
            && same_allowlist
            && self.llm_gateway == other.llm_gateway
            && self.read_paths == other.read_paths
            && self.write_paths == other.write_paths
            && self.vm == other.vm
    }
}

impl Eq for Isolation {}

impl Isolation {
    /// No isolation: the engine runs directly on the host.
    pub(crate) fn off() -> Self {
        Self {
            mode: IsolationMode::Off,
            network: NetworkMode::None,
            allowlist: None,
            llm_gateway: None,
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            vm: None,
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum IsolationError {
    #[error("unknown isolation mode `{0}`")]
    UnknownMode(String),
    #[error("unknown isolation network mode `{0}`")]
    UnknownNetworkMode(String),
    #[error(
        "task meta.isolation would loosen {setting} from `{from}` to `{to}`; \
         set engine.isolation.allowTaskOverride to allow this"
    )]
    OverrideLoosens {
        setting: &'static str,
        from: String,
        to: String,
    },
    #[error("invalid isolation path `{}`: {reason}", path.display())]
    InvalidPath { path: PathBuf, reason: &'static str },
    #[error("invalid isolation vm block: {0}")]
    InvalidVm(String),
    #[error("invalid network allowlist: {0}")]
    InvalidAllowlist(#[source] RuleError),
    #[error("invalid {LLM_BASE_URL_ENV} for the network allowlist")]
    InvalidBaseUrl,
    #[error("{LLM_BASE_URL_ENV} names a link-local address, which is never allowed")]
    LinkLocalBaseUrl,
    #[error(
        "engine.anthropicBaseUrl differs from the daemon's {LLM_BASE_URL_ENV} and no \
         network.allow rule of the local isolation file covers it (loopback never is)"
    )]
    HostBaseUrl,
    #[error("invalid isolation in task meta: {0}")]
    InvalidTaskMeta(#[source] serde_json::Error),
    #[error("engine sandbox is unavailable: {0}")]
    Unavailable(String),
    #[error("engine sandbox needs {0}")]
    Missing(&'static str),
    #[error("engine sandbox network setup failed: {0}")]
    Network(String),
    #[error("engine VM: {0}")]
    Vm(String),
}

/// The `ANTHROPIC_BASE_URL` sources an allowlisted run's LLM endpoint is
/// derived from.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LlmBaseUrl<'a> {
    /// What the engine is launched with; `None` means the default host.
    pub(crate) engine: Option<&'a str>,
    /// The daemon's own, from its process env.
    pub(crate) daemon: Option<&'a str>,
    /// A local isolation floor is configured.
    pub(crate) floored: bool,
}

/// Resolve the effective isolation for a run.
///
/// The override's `mode` and `network.mode` win over the default's; extra paths
/// and allowlist rules come from the config default only. Unless the default
/// sets `allowTaskOverride`, an override may only tighten the default. When the
/// resolved mode is off nothing else is validated. An allowlist also admits the
/// LLM endpoint at `llm.engine` (default `api.anthropic.com:443`); see
/// [`allowlist`] for the floor case.
///
/// `vm` needs the default's `vm` block; a full network under `vm` is an
/// allowlist of every public destination, without the default's rules.
pub(crate) fn resolve(
    default: &IsolationSpec,
    task_override: Option<&IsolationSpec>,
    workspace_dir: &Path,
    llm: LlmBaseUrl<'_>,
) -> Result<Isolation, IsolationError> {
    if let Some(task) = task_override
        && !default.allow_task_override.unwrap_or(false)
    {
        check_tightens(default, task)?;
    }
    let mode = task_override
        .and_then(|o| o.mode.as_deref())
        .or(default.mode.as_deref());
    let mode = match mode {
        None | Some("off") => return Ok(Isolation::off()),
        Some("sandbox") => IsolationMode::Sandbox,
        Some("vm") => IsolationMode::Vm,
        Some(other) => return Err(IsolationError::UnknownMode(other.to_owned())),
    };
    let vm_config = match mode {
        IsolationMode::Vm => Some(default.vm.as_ref().ok_or_else(|| {
            IsolationError::Unavailable(
                "vm mode needs engine.isolation.vm in the local isolation file".into(),
            )
        })?),
        IsolationMode::Off | IsolationMode::Sandbox => None,
    };

    let network = task_override
        .and_then(|o| o.network.as_ref())
        .and_then(|n| n.mode.as_deref())
        .or_else(|| default.network.as_ref().and_then(|n| n.mode.as_deref()));
    let network = match network {
        None | Some("none") => NetworkMode::None,
        Some("full") => NetworkMode::Full,
        Some("allowlist") => NetworkMode::Allowlist,
        Some(other) => return Err(IsolationError::UnknownNetworkMode(other.to_owned())),
    };
    let (allowlist, llm_gateway) = match (network, mode) {
        (NetworkMode::Allowlist, _) => {
            let (rules, gateway) = allowlist(default, llm, false)?;
            (Some(rules), gateway)
        }
        (NetworkMode::Full, IsolationMode::Vm) => {
            let (rules, gateway) = allowlist(default, llm, true)?;
            (Some(rules), gateway)
        }
        (NetworkMode::None | NetworkMode::Full, _) => (None, None),
    };

    let workspace = normalize(workspace_dir);
    let protected = protected_files(&workspace);
    let read_paths = validate_paths(default.read_paths.as_deref(), &workspace, &protected)?;
    let write_paths = validate_paths(default.write_paths.as_deref(), &workspace, &protected)?;
    let vm = match vm_config {
        Some(config) => {
            config.validate()?;
            let vm_disk = task_override
                .and_then(|o| o.vm_disk.as_deref())
                .or(default.vm_disk.as_deref());
            let task_disk = match vm_disk {
                None | Some("run") => false,
                Some("task") => true,
                Some(other) => {
                    return Err(IsolationError::InvalidVm(format!(
                        "vmDisk `{other}` is neither `run` nor `task`"
                    )));
                }
            };
            Some(Arc::new(VmSettings {
                config: config.clone(),
                read_paths: read_paths.clone(),
                write_paths: write_paths.clone(),
                task_disk,
            }))
        }
        None => None,
    };

    Ok(Isolation {
        mode,
        network,
        allowlist,
        llm_gateway,
        read_paths,
        write_paths,
        vm,
    })
}

/// Compile the config default's allow rules plus the always-allowed LLM
/// endpoint. A loopback endpoint is not a rule but the returned gateway
/// forward; an IP-literal one is an always-allowed address; a link-local one
/// is refused. With `public` the default's rules are replaced by rules
/// allowing every public destination.
///
/// Under a local floor only the daemon's own base URL gets this treatment. An
/// engine URL that differs from it gets no always-allow: it must be covered by
/// a floor rule and must not be loopback.
fn allowlist(
    default: &IsolationSpec,
    llm: LlmBaseUrl<'_>,
    public: bool,
) -> Result<(Arc<RuleSet>, Option<GatewayForward>), IsolationError> {
    let endpoint = llm_endpoint(llm.engine)?;
    let rules: &[Rule] = if public {
        &[]
    } else {
        default
            .network
            .as_ref()
            .and_then(|n| n.allow.as_deref())
            .unwrap_or_default()
    };
    let compile = |always: &[AlwaysAllow]| -> Result<RuleSet, RuleError> {
        let rules = RuleSet::compile(rules, always)?;
        Ok(if public {
            rules.allowing_public()
        } else {
            rules
        })
    };
    let host = normalize_name(&endpoint.host);
    let literal = host.parse::<IpAddr>().ok();
    let loopback = host == "localhost" || literal.is_some_and(is_local);
    if llm.floored && llm.engine != llm.daemon {
        let rules = compile(&[]).map_err(IsolationError::InvalidAllowlist)?;
        if loopback || !rules.rule_covers(&host, endpoint.port, Proto::Tcp) {
            return Err(IsolationError::HostBaseUrl);
        }
        return Ok((Arc::new(rules), None));
    }
    if literal.is_some_and(is_link_local) {
        return Err(IsolationError::LinkLocalBaseUrl);
    }
    let (rules, gateway) = if loopback {
        if endpoint.port == 0 {
            return Err(IsolationError::InvalidBaseUrl);
        }
        let target = match literal {
            Some(ip) => SocketAddr::new(ip, endpoint.port),
            None => localhost_addr(endpoint.port),
        };
        let gateway = GatewayForward {
            port: endpoint.port,
            target,
        };
        (compile(&[]), Some(gateway))
    } else if let Some(ip) = literal {
        let addr = SocketAddr::new(ip, endpoint.port);
        let rules = compile(&[]).and_then(|set| set.with_always_addr(addr));
        (rules, None)
    } else {
        (compile(&[endpoint]), None)
    };
    let rules = rules.map_err(IsolationError::InvalidAllowlist)?;
    Ok((Arc::new(rules), gateway))
}

/// `localhost:port` as resolved on the host, IPv4 first; 127.0.0.1 when the
/// lookup yields no loopback address.
fn localhost_addr(port: u16) -> SocketAddr {
    let resolved: Vec<SocketAddr> = ("localhost", port)
        .to_socket_addrs()
        .map(|addrs| addrs.filter(|addr| addr.ip().is_loopback()).collect())
        .unwrap_or_default();
    resolved
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| resolved.first())
        .copied()
        .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port))
}

/// `url` with its host replaced by the guest gateway address; scheme,
/// userinfo, port, path and query are kept.
fn gateway_url(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (Some(userinfo), host_port),
        None => (None, authority),
    };
    let port = match host_port.strip_prefix('[') {
        Some(bracketed) => bracketed.split_once(']')?.1,
        None => host_port.rfind(':').map_or("", |at| &host_port[at..]),
    };
    let userinfo = userinfo.map(|u| format!("{u}@")).unwrap_or_default();
    let gateway = TunConfig::default().gateway;
    Some(format!("{scheme}://{userinfo}{gateway}{port}{tail}"))
}

/// The LLM API endpoint: `llm_base_url`'s host and port, else the default host.
fn llm_endpoint(llm_base_url: Option<&str>) -> Result<AlwaysAllow, IsolationError> {
    match llm_base_url {
        Some(url) => AlwaysAllow::from_url(url).ok_or(IsolationError::InvalidBaseUrl),
        None => Ok(AlwaysAllow {
            host: DEFAULT_LLM_HOST.to_owned(),
            port: 443,
        }),
    }
}

/// `ANTHROPIC_BASE_URL` as the engine sees it: the launch env, else the
/// inherited one. Empty means unset.
fn llm_base_url(env: &[(String, OsString)]) -> Option<String> {
    env.iter()
        .rev()
        .find(|(key, _)| key == LLM_BASE_URL_ENV)
        .map(|(_, value)| value.clone())
        .or_else(|| std::env::var_os(LLM_BASE_URL_ENV))
        .and_then(|value| value.into_string().ok())
        .filter(|value| !value.is_empty())
}

/// The daemon's own `ANTHROPIC_BASE_URL`, from its process env. Empty means
/// unset.
fn daemon_llm_base_url() -> Option<String> {
    llm_base_url(&[])
}

/// Fail when `task` would loosen `default`'s mode or network mode.
///
/// Modes order `off` < `sandbox` < `vm`; network modes order `full` <
/// `allowlist` < `none`. A default that is off confines no network, so any
/// network override tightens it.
fn check_tightens(default: &IsolationSpec, task: &IsolationSpec) -> Result<(), IsolationError> {
    let from = default.mode.as_deref().unwrap_or("off");
    let default_mode = mode_strictness(from)?;
    if let Some(to) = task.mode.as_deref()
        && mode_strictness(to)? < default_mode
    {
        return Err(loosens("isolation.mode", from, to));
    }
    if default_mode == 0 {
        return Ok(());
    }
    let from = network_mode(default).unwrap_or("none");
    if let Some(to) = network_mode(task)
        && network_strictness(to)? < network_strictness(from)?
    {
        return Err(loosens("isolation.network.mode", from, to));
    }
    Ok(())
}

fn network_mode(spec: &IsolationSpec) -> Option<&str> {
    spec.network.as_ref().and_then(|n| n.mode.as_deref())
}

fn mode_strictness(mode: &str) -> Result<u8, IsolationError> {
    match mode {
        "off" => Ok(0),
        "sandbox" => Ok(1),
        "vm" => Ok(2),
        other => Err(IsolationError::UnknownMode(other.to_owned())),
    }
}

fn network_strictness(network: &str) -> Result<u8, IsolationError> {
    match network {
        "full" => Ok(0),
        "allowlist" => Ok(1),
        "none" => Ok(2),
        other => Err(IsolationError::UnknownNetworkMode(other.to_owned())),
    }
}

fn loosens(setting: &'static str, from: &str, to: &str) -> IsolationError {
    IsolationError::OverrideLoosens {
        setting,
        from: from.to_owned(),
        to: to.to_owned(),
    }
}

/// Validate a local isolation floor at load: known modes, valid extra paths,
/// valid allowlist rules and a valid `vm` block, which mode `vm` requires.
pub(crate) fn validate_floor(
    floor: &IsolationSpec,
    workspace_dir: &Path,
) -> Result<(), IsolationError> {
    match floor.mode.as_deref() {
        None | Some("off" | "sandbox") => {}
        Some("vm") => {
            if floor.vm.is_none() {
                return Err(IsolationError::InvalidVm(
                    "mode `vm` needs a `vm` block".into(),
                ));
            }
        }
        Some(other) => return Err(IsolationError::UnknownMode(other.to_owned())),
    }
    if let Some(vm) = &floor.vm {
        vm.validate()?;
    }
    if let Some(network) = network_mode(floor) {
        network_strictness(network)?;
    }
    let workspace = normalize(workspace_dir);
    let protected = protected_files(&workspace);
    validate_paths(floor.read_paths.as_deref(), &workspace, &protected)?;
    validate_paths(floor.write_paths.as_deref(), &workspace, &protected)?;
    let rules = floor
        .network
        .as_ref()
        .and_then(|n| n.allow.as_deref())
        .unwrap_or_default();
    RuleSet::compile(rules, &[]).map_err(IsolationError::InvalidAllowlist)?;
    Ok(())
}

/// Layer a host `engine.isolation` block onto the local floor.
///
/// Only `mode` and `network.mode` are taken from `host`, and only when they
/// tighten the floor (same ordering as a task override); everything else,
/// including `vm`, stays the floor's. Returns the effective default and the
/// host fields ignored.
pub(crate) fn tighten_floor(
    floor: &IsolationSpec,
    host: IsolationSpec,
) -> (IsolationSpec, Vec<&'static str>) {
    let mut effective = floor.clone();
    let mut ignored = Vec::new();
    let floor_mode = floor.mode.as_deref().unwrap_or("off");
    if let Some(to) = host.mode {
        if tightens(mode_strictness, floor_mode, &to) {
            effective.mode = Some(to);
        } else {
            ignored.push("mode");
        }
    }
    let host_network = host.network.unwrap_or_default();
    if let Some(to) = host_network.mode {
        // An off floor confines no network, so any known network mode tightens it.
        let from = if floor_mode == "off" {
            "full"
        } else {
            network_mode(floor).unwrap_or("none")
        };
        if tightens(network_strictness, from, &to) {
            effective
                .network
                .get_or_insert_with(NetworkSpec::default)
                .mode = Some(to);
        } else {
            ignored.push("network.mode");
        }
    }
    if host_network.allow.is_some() {
        ignored.push("network.allow");
    }
    if host.read_paths.is_some() {
        ignored.push("readPaths");
    }
    if host.write_paths.is_some() {
        ignored.push("writePaths");
    }
    if host.allow_task_override.is_some() {
        ignored.push("allowTaskOverride");
    }
    if host.vm.is_some() {
        ignored.push("vm");
    }
    if host.vm_disk.is_some() {
        ignored.push("vmDisk");
    }
    (effective, ignored)
}

/// Whether `to` is at least as strict as `from`; unknown values never are.
fn tightens(strictness: fn(&str) -> Result<u8, IsolationError>, from: &str, to: &str) -> bool {
    matches!((strictness(from), strictness(to)), (Ok(from), Ok(to)) if to >= from)
}

/// Extract the task override from a task's free-form `meta` JSON.
///
/// Missing, non-JSON or non-object meta, or meta without an `isolation` key,
/// means no override; an `isolation` value of the wrong shape is an error.
/// `network.allow` and `vm` are dropped: allowlist rules and the VM config
/// never come from a task.
pub(crate) fn override_from_meta(
    meta: Option<&str>,
) -> Result<Option<IsolationSpec>, IsolationError> {
    let Some(Ok(serde_json::Value::Object(mut map))) = meta.map(serde_json::from_str) else {
        return Ok(None);
    };
    let Some(mut value) = map.remove("isolation") else {
        return Ok(None);
    };
    if let Some(isolation) = value.as_object_mut() {
        isolation.remove("vm");
    }
    if let Some(network) = value
        .get_mut("network")
        .and_then(serde_json::Value::as_object_mut)
    {
        network.remove("allow");
    }
    serde_json::from_value(value)
        .map(Some)
        .map_err(IsolationError::InvalidTaskMeta)
}

/// One engine launch, built but not spawned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Launch {
    pub(crate) program: PathBuf,
    pub(crate) args: Vec<OsString>,
    /// Variables layered onto the inherited environment, in order.
    pub(crate) env: Vec<(String, OsString)>,
    /// Working directory; empty means the current directory.
    pub(crate) cwd: PathBuf,
    /// Whether `program` is `bwrap` wrapping the engine.
    pub(crate) sandboxed: bool,
    /// Allowlist only: the network handover to run after the spawn.
    pub(crate) net: Option<Arc<NetHandover>>,
    /// Sandbox with task memory only: the per-run dir holding the
    /// conversations view, kept for the engine's lifetime.
    pub(crate) conversations: Option<Arc<RunDir>>,
    /// `vm` only: the prepared VM run `program` (gino-vmm) boots.
    pub(crate) vm: Option<Arc<VmPrepared>>,
}

/// Private per-run daemon dir (mode 0700) under the temp dir, holding a run's
/// sockets and files; removed on drop.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RunDir(PathBuf);

impl RunDir {
    fn create(prefix: &str) -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("{prefix}{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_dir_all(&self.0) {
            tracing::debug!(error = %err, "removing a sandbox run dir");
        }
    }
}

/// Daemon side of an allowlist sandbox's network, prepared before the spawn:
/// the bound control socket and the settings of the run's exit.
#[derive(Debug)]
pub(crate) struct NetHandover {
    dir: RunDir,
    listener: UnixListener,
    exit: ExitConfig,
}

/// Compares by identity.
impl PartialEq for NetHandover {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for NetHandover {}

impl NetHandover {
    /// Create the per-run dir with `resolv.conf` and bind the control socket.
    fn prepare(exit: ExitConfig) -> std::io::Result<Self> {
        let dir = RunDir::create("gino-net-")?;
        let gateway = TunConfig::default().gateway;
        std::fs::write(
            dir.0.join(RESOLV_CONF_NAME),
            format!("nameserver {gateway}\n"),
        )?;
        let listener = UnixListener::bind(dir.0.join(CTL_SOCK_NAME))?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            dir,
            listener,
            exit,
        })
    }
}

/// A running allowlist network: the exit and its per-run dir. Dropping it
/// stops the exit and removes the dir.
#[derive(Debug)]
pub(crate) struct NetExit {
    _exit: Exit,
    _dir: RunDir,
}

/// Receive the guest TUN device from the just-spawned sandbox `child`, start
/// the run's exit on it and release the engine. On failure the sandbox is
/// killed and the run fails with [`IsolationError::Network`].
pub(crate) async fn start_network(
    net: Option<Arc<NetHandover>>,
    child: &mut tokio::process::Child,
) -> Result<Option<NetExit>, EngineError> {
    let Some(net) = net else {
        return Ok(None);
    };
    let result = match Arc::into_inner(net) {
        Some(net) => hand_over(net, child).await,
        None => Err("the network handover is shared".to_owned()),
    };
    match result {
        Ok(exit) => Ok(Some(exit)),
        Err(reason) => {
            if let Err(err) = child.start_kill() {
                tracing::debug!(error = %err, "killing the sandbox after a failed network setup");
            }
            Err(IsolationError::Network(reason).into())
        }
    }
}

async fn hand_over(net: NetHandover, child: &mut tokio::process::Child) -> Result<NetExit, String> {
    let NetHandover {
        dir,
        listener,
        exit,
    } = net;
    let handover = tokio::time::timeout(HANDOVER_TIMEOUT, start_exit(listener, exit));
    // `Child::wait` closes stdin; keep it for the engine.
    let stdin = child.stdin.take();
    let exited = tokio::select! {
        result = handover => {
            let exit = result.map_err(|_| {
                format!("no TUN device from the sandbox within {}s", HANDOVER_TIMEOUT.as_secs())
            })??;
            child.stdin = stdin;
            return Ok(NetExit { _exit: exit, _dir: dir });
        }
        status = child.wait() => status,
    };
    let status = exited.map_or_else(|err| err.to_string(), |status| status.to_string());
    let mut stderr = Vec::new();
    if let Some(pipe) = child.stderr.as_mut() {
        let mut limited = pipe.take(64 * 1024);
        let _ =
            tokio::time::timeout(Duration::from_secs(1), limited.read_to_end(&mut stderr)).await;
    }
    let start = stderr.len().saturating_sub(HANDOVER_STDERR_TAIL);
    let tail = String::from_utf8_lossy(&stderr[start..]);
    Err(format!(
        "the sandbox exited ({status}) before handing over its network: {}",
        tail.trim()
    ))
}

/// Accept the sandbox's connection, adopt the TUN device it sends, start the
/// exit and send the ready byte.
async fn start_exit(listener: UnixListener, cfg: ExitConfig) -> Result<Exit, String> {
    let listener = tokio::net::UnixListener::from_std(listener)
        .map_err(|err| format!("control socket: {err}"))?;
    let (mut stream, _) = listener
        .accept()
        .await
        .map_err(|err| format!("accepting on the control socket: {err}"))?;
    // Nothing else may connect once the sandbox has.
    drop(listener);
    let fd = recv_fd(&stream, HANDOVER_TIMEOUT)
        .await
        .map_err(|err| format!("receiving the TUN device: {err}"))?;
    let tun = Tun::from_fd(fd, cfg.mtu).map_err(|err| format!("adopting the TUN device: {err}"))?;
    let exit = Exit::start(tun, cfg).map_err(|err| format!("starting the network exit: {err}"))?;
    stream
        .write_all(&[NET_READY])
        .await
        .map_err(|err| format!("releasing the sandbox: {err}"))?;
    Ok(exit)
}

impl Launch {
    /// The engine run directly on the host.
    pub(crate) fn direct(
        program: PathBuf,
        args: Vec<String>,
        env: Vec<(String, OsString)>,
        cwd: PathBuf,
    ) -> Self {
        Self {
            program,
            args: args.into_iter().map(OsString::from).collect(),
            env,
            cwd,
            sandboxed: false,
            net: None,
            conversations: None,
            vm: None,
        }
    }

    /// A command with piped stdio that kills the child on drop.
    pub(crate) fn command(&self) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if !self.cwd.as_os_str().is_empty() {
            command.current_dir(&self.cwd);
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }
        command
    }
}

/// Per-run inputs deciding whether and how a launch is sandboxed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LaunchContext<'a> {
    /// Configured default (`engine.isolation`).
    pub(crate) isolation: &'a IsolationSpec,
    /// The task's override, if any.
    pub(crate) task_override: Option<&'a IsolationSpec>,
    pub(crate) workspace_dir: &'a Path,
    /// The run's task, which names its `vm` task disk.
    pub(crate) task_id: Option<&'a str>,
    /// The run's thread, for network decision logs.
    pub(crate) thread_id: Option<&'a str>,
    /// The thread's work dir.
    pub(crate) work_dir: Option<&'a Path>,
    /// The task's memory dir on the host.
    pub(crate) memory_dir: Option<&'a Path>,
    /// The agent memory dir on the host.
    pub(crate) agent_memory_dir: Option<&'a Path>,
    /// How the engine may use the agent memory dir.
    pub(crate) agent_memory_access: AgentMemoryAccess,
    /// Host archive dirs of the task's other threads, oldest first.
    pub(crate) task_archives: &'a [PathBuf],
    /// Cap on the bytes copied into the conversations view.
    pub(crate) conversations_max_bytes: u64,
    /// The gino-agent binary.
    pub(crate) self_exe: Option<&'a Path>,
    /// Provisioning dir holding the global `CLAUDE.md` and `skills/`.
    pub(crate) global_config_dir: Option<&'a Path>,
    /// Env keys naming the engine config dir; sandboxed, they name the engine home.
    pub(crate) config_dir_keys: &'a [&'a str],
    /// A local isolation floor is configured.
    pub(crate) floored: bool,
}

/// Host facts a sandboxed launch is built from.
#[derive(Clone, Debug)]
pub(crate) struct SandboxHost {
    /// The probed `bwrap` binary.
    pub(crate) bwrap: PathBuf,
    pub(crate) root: HostRoot,
    /// `PATH` the engine binary is resolved against.
    pub(crate) path_env: Option<OsString>,
    /// Sandbox `$HOME`.
    pub(crate) home: PathBuf,
}

impl SandboxHost {
    fn current(bwrap: PathBuf) -> Self {
        Self {
            bwrap,
            root: host_root(),
            path_env: std::env::var_os("PATH"),
            home: std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map_or_else(|| PathBuf::from(DEFAULT_SANDBOX_HOME), PathBuf::from),
        }
    }
}

#[cfg(test)]
impl SandboxHost {
    /// A fixed host layout that finds binaries on `path_env`.
    pub(crate) fn fixture(path_env: Option<OsString>) -> Self {
        use self::bwrap::RootEntry;
        Self {
            bwrap: "/usr/bin/bwrap".into(),
            root: HostRoot {
                entries: [
                    RootEntry::Symlink("usr/bin".into()),
                    RootEntry::Dir,
                    RootEntry::Absent,
                    RootEntry::Absent,
                ],
                resolv_conf_outside_etc: None,
            },
            path_env,
            home: "/home/gino".into(),
        }
    }
}

/// Resolve the run's isolation and build its launch: `direct` as-is when off,
/// wrapped in `bwrap` when sandboxed. Fails closed when the agent runs as root
/// or `bwrap` is unusable.
pub(crate) fn launch(direct: Launch, ctx: &LaunchContext<'_>) -> Result<Launch, EngineError> {
    launch_as(direct, ctx, nix::unistd::geteuid().as_raw())
}

fn launch_as(direct: Launch, ctx: &LaunchContext<'_>, euid: u32) -> Result<Launch, EngineError> {
    let base_url = llm_base_url(&direct.env);
    let daemon_base_url = daemon_llm_base_url();
    let isolation = resolve(
        ctx.isolation,
        ctx.task_override,
        ctx.workspace_dir,
        LlmBaseUrl {
            engine: base_url.as_deref(),
            daemon: daemon_base_url.as_deref(),
            floored: ctx.floored,
        },
    )?;
    match isolation.mode {
        IsolationMode::Off => Ok(direct),
        IsolationMode::Sandbox => {
            check_not_root(euid)?;
            let bwrap = bwrap::ensure_available()?;
            wrap(direct, ctx, &isolation, &SandboxHost::current(bwrap))
        }
        IsolationMode::Vm => {
            check_not_root(euid)?;
            let vm = isolation
                .vm
                .as_ref()
                .ok_or(IsolationError::Missing("the vm settings"))?;
            vm::ensure_available(&vm.config)?;
            launch_vm(direct, ctx, &isolation, &VmHost::current())
        }
    }
}

/// Prepare the VM launch of a run whose host passed the VM probe. Allowlist
/// and full networks both run the per-run exit, with the allowlist's or the
/// every-public-destination rules.
fn launch_vm(
    mut direct: Launch,
    ctx: &LaunchContext<'_>,
    isolation: &Isolation,
    host: &VmHost,
) -> Result<Launch, EngineError> {
    let vm = isolation
        .vm
        .as_ref()
        .ok_or(IsolationError::Missing("the vm settings"))?;
    let net = match (isolation.network, &isolation.allowlist) {
        (NetworkMode::None, _) => None,
        (NetworkMode::Allowlist | NetworkMode::Full, Some(rules)) => {
            Some(exit_config(ctx, isolation, rules))
        }
        (NetworkMode::Allowlist | NetworkMode::Full, None) => {
            return Err(IsolationError::Missing("the allowlist rules").into());
        }
    };
    gateway_llm_url(&mut direct.env, isolation)?;
    vm::prepare(&direct, ctx, vm, host, net)
}

/// The run's exit settings: `rules`, the LLM gateway forward and the thread
/// for decision logs.
fn exit_config(ctx: &LaunchContext<'_>, isolation: &Isolation, rules: &Arc<RuleSet>) -> ExitConfig {
    let mut exit = ExitConfig::new(ctx.thread_id.unwrap_or("-"), Arc::clone(rules));
    exit.gateway = isolation.llm_gateway;
    exit
}

/// Point a loopback LLM endpoint at the gateway, which forwards it.
fn gateway_llm_url(
    env: &mut Vec<(String, OsString)>,
    isolation: &Isolation,
) -> Result<(), IsolationError> {
    if isolation.llm_gateway.is_none() {
        return Ok(());
    }
    let url = llm_base_url(env)
        .as_deref()
        .and_then(gateway_url)
        .ok_or(IsolationError::InvalidBaseUrl)?;
    env.retain(|(key, _)| key != LLM_BASE_URL_ENV);
    env.push((LLM_BASE_URL_ENV.to_owned(), url.into()));
    Ok(())
}

/// A spawned engine process.
#[derive(Debug)]
pub(crate) enum EngineProcess {
    /// The engine itself, or `bwrap` wrapping it when `sandboxed`; killed on drop.
    Child {
        child: tokio::process::Child,
        sandboxed: bool,
        /// The run's conversations view, removed with the process.
        _conversations: Option<Arc<RunDir>>,
    },
    /// gino-vmm running the engine in a VM; stopped on drop.
    Vm(VmRun),
}

impl EngineProcess {
    /// The host process id while it runs.
    pub(crate) fn id(&self) -> Option<u32> {
        match self {
            Self::Child { child, .. } => child.id(),
            Self::Vm(vm) => vm.id(),
        }
    }

    /// Wait for the process to exit.
    pub(crate) async fn wait(&mut self) {
        match self {
            Self::Child { child, .. } => {
                if let Err(err) = child.wait().await {
                    tracing::debug!(error = %err, "waiting for the engine");
                }
            }
            Self::Vm(vm) => {
                vm.wait().await;
            }
        }
    }

    /// Kill the process without waiting.
    pub(crate) fn start_kill(&mut self) {
        match self {
            Self::Child { child, .. } => {
                if let Err(err) = child.start_kill() {
                    tracing::debug!(error = %err, "killing the engine");
                }
            }
            Self::Vm(vm) => vm.start_kill(),
        }
    }

    /// Deliver SIGINT to the engine: directly, to `sandbox-init` inside
    /// `bwrap` (which does not forward signals), or over the VM's control
    /// channel.
    pub(crate) fn interrupt(&self) {
        match self {
            Self::Child {
                child, sandboxed, ..
            } => {
                let Some(pid) = child.id().and_then(|pid| i32::try_from(pid).ok()) else {
                    return;
                };
                let pid = if *sandboxed {
                    sandbox_init_pid(pid).unwrap_or(pid)
                } else {
                    pid
                };
                if let Err(err) = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGINT,
                ) {
                    tracing::debug!(error = %err, "SIGINT to the engine failed; it is likely gone");
                }
            }
            Self::Vm(vm) => vm.interrupt(),
        }
    }

    /// The VM run's failure reporter.
    pub(crate) fn vm_monitor(&self) -> Option<VmMonitor> {
        match self {
            Self::Child { .. } => None,
            Self::Vm(vm) => Some(vm.monitor()),
        }
    }
}

/// A spawned engine launch: the process, its piped stdio and, in allowlist
/// mode, the running network exit.
#[derive(Debug)]
pub(crate) struct Spawned {
    pub(crate) process: EngineProcess,
    pub(crate) stdin: tokio::process::ChildStdin,
    pub(crate) stdout: tokio::process::ChildStdout,
    pub(crate) stderr: tokio::process::ChildStderr,
    pub(crate) net: Option<NetExit>,
}

/// Spawn `launch`: boot its VM, or run its command and start its network.
pub(crate) async fn spawn(launch: Launch) -> Result<Spawned, EngineError> {
    if let Some(prepared) = launch.vm {
        let (run, pipes) = vm::start(prepared).await?;
        return Ok(Spawned {
            process: EngineProcess::Vm(run),
            stdin: pipes.stdin,
            stdout: pipes.stdout,
            stderr: pipes.stderr,
            net: None,
        });
    }
    let mut child = launch.command().spawn().map_err(EngineError::Spawn)?;
    let net = start_network(launch.net, &mut child).await?;
    let stdin = child
        .stdin
        .take()
        .ok_or(EngineError::MissingPipe("stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or(EngineError::MissingPipe("stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(EngineError::MissingPipe("stderr"))?;
    Ok(Spawned {
        process: EngineProcess::Child {
            child,
            sandboxed: launch.sandboxed,
            _conversations: launch.conversations,
        },
        stdin,
        stdout,
        stderr,
        net,
    })
}

/// Refuse to sandbox from a root daemon: the engine's user namespace maps it
/// onto the daemon's uid, so it would own root's files.
fn check_not_root(euid: u32) -> Result<(), IsolationError> {
    if euid == 0 {
        return Err(IsolationError::Unavailable(
            "the agent runs as root; run it as an unprivileged user".into(),
        ));
    }
    Ok(())
}

/// Which isolation modes a sandboxed launch on this host would start.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SandboxAvailability {
    /// `bwrap` passes its probe and the daemon is not root.
    pub(crate) sandbox: bool,
    /// [`Self::sandbox`] and `/dev/net/tun` exists, so allowlist networking can start.
    pub(crate) allowlist: bool,
    /// The local isolation file has a `vm` block that passes the VM probe and
    /// the daemon is not root.
    pub(crate) vm: bool,
}

/// Probe this host for [`SandboxAvailability`] with the local isolation file's
/// `vm` block; read-only, the `bwrap` and VM probes are cached.
pub(crate) fn probe(vm: Option<&VmConfig>) -> SandboxAvailability {
    availability(
        bwrap::ensure_available().is_ok(),
        vm.is_some_and(|vm| vm::ensure_available(vm).is_ok()),
        nix::unistd::geteuid().as_raw(),
        Path::new("/dev/net/tun").exists(),
    )
}

fn availability(bwrap_ok: bool, vm_ok: bool, euid: u32, tun: bool) -> SandboxAvailability {
    let not_root = check_not_root(euid).is_ok();
    let sandbox = bwrap_ok && not_root;
    SandboxAvailability {
        sandbox,
        allowlist: sandbox && tun,
        vm: vm_ok && not_root,
    }
}

/// Point the `autoMemoryDirectory` of the `--settings` JSON `settings` from
/// below the host task memory tree `memory_dir` to below
/// [`TASK_MEMORY_MOUNT`]; without a mounted tree, or for a directory outside
/// it, drop the key and set `autoMemoryEnabled: false`. Reports whether
/// anything changed.
pub(crate) fn engine_auto_memory(
    settings: &mut serde_json::Value,
    memory_dir: Option<&Path>,
) -> bool {
    let Some(map) = settings.as_object_mut() else {
        return false;
    };
    let Some(dir) = map.get("autoMemoryDirectory") else {
        return false;
    };
    let mounted = dir
        .as_str()
        .zip(memory_dir)
        .and_then(|(dir, memory_dir)| Path::new(dir).strip_prefix(memory_dir).ok())
        .and_then(|rel| {
            Path::new(TASK_MEMORY_MOUNT)
                .join(rel)
                .to_str()
                .map(str::to_owned)
        });
    if let Some(dir) = mounted {
        map.insert("autoMemoryDirectory".to_owned(), dir.into());
    } else {
        map.remove("autoMemoryDirectory");
        map.insert("autoMemoryEnabled".to_owned(), false.into());
    }
    true
}

/// Apply [`engine_auto_memory`] to every `--settings <json>` argument of
/// `args`. Arguments that are not JSON (a settings file path) stay as they are.
fn engine_settings_args(args: &mut [OsString], memory_dir: Option<&Path>) {
    let mut iter = args.iter_mut();
    while let Some(arg) = iter.next() {
        if arg != "--settings" {
            continue;
        }
        let Some(value) = iter.next() else {
            break;
        };
        let Some(mut json) = value
            .to_str()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        else {
            continue;
        };
        if engine_auto_memory(&mut json, memory_dir)
            && let Ok(rewritten) = serde_json::to_string(&json)
        {
            *value = rewritten.into();
        }
    }
}

/// Wrap `direct` in `bwrap` + `sandbox-init` and create the engine home.
#[allow(clippy::too_many_lines)] // one linear launch build
pub(crate) fn wrap(
    direct: Launch,
    ctx: &LaunchContext<'_>,
    isolation: &Isolation,
    host: &SandboxHost,
) -> Result<Launch, EngineError> {
    let work_dir = ctx
        .work_dir
        .ok_or(IsolationError::Missing("the thread's work dir"))?;
    let agent_exe = ctx
        .self_exe
        .ok_or(IsolationError::Missing("the gino-agent binary path"))?;
    let engine_binary =
        resolve_binary(&direct.program, host.path_env.as_deref()).ok_or_else(|| {
            EngineError::Spawn(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("engine binary `{}` not found", direct.program.display()),
            ))
        })?;
    let cwd = if direct.cwd.as_os_str().is_empty() {
        work_dir.to_path_buf()
    } else {
        direct.cwd.clone()
    };
    let net = match (isolation.network, &isolation.allowlist) {
        (NetworkMode::Allowlist, Some(rules)) => Some(
            NetHandover::prepare(exit_config(ctx, isolation, rules)).map_err(EngineError::Spawn)?,
        ),
        (NetworkMode::Allowlist, None) => {
            return Err(IsolationError::Missing("the allowlist rules").into());
        }
        (NetworkMode::None | NetworkMode::Full, _) => None,
    };
    let conversations = ctx
        .memory_dir
        .map(|_| conversations_view(ctx))
        .transpose()
        .map_err(EngineError::Spawn)?;
    let layout = SandboxLayout {
        work_dir: work_dir.to_path_buf(),
        cwd,
        engine_home: engine_home(work_dir),
        global_config_dir: ctx.global_config_dir.map(Path::to_path_buf),
        globals: ProvisionedGlobals::inspect(ctx.global_config_dir),
        engine_binary,
        agent_exe: agent_exe.to_path_buf(),
        home: host.home.clone(),
        network: isolation.network,
        read_paths: isolation.read_paths.clone(),
        write_paths: isolation.write_paths.clone(),
        task_entries: bwrap::inspect_task_entries(work_dir, ctx.workspace_dir),
        net_dir: net.as_ref().map(|net| net.dir.0.clone()),
        agent_sock: direct
            .env
            .iter()
            .find(|(key, value)| key == AGENT_SOCK_ENV && !value.is_empty())
            .map(|(_, value)| PathBuf::from(value)),
        memory_dir: ctx.memory_dir.map(Path::to_path_buf),
        agent_memory_dir: ctx.agent_memory_dir.map(Path::to_path_buf),
        agent_memory_writable: ctx.agent_memory_access == AgentMemoryAccess::Rw,
        conversations_dir: conversations.as_ref().map(|dir| dir.0.clone()),
    };
    prepare_engine_home(&layout).map_err(EngineError::Spawn)?;

    let mut inner: Vec<OsString> = vec![layout.agent_exe.clone().into(), "sandbox-init".into()];
    if net.is_some() {
        inner.extend(["--ctl-sock".into(), CTL_SOCK.into()]);
    }
    inner.extend(["--".into(), layout.engine_binary.clone().into()]);
    let mut args = direct.args;
    engine_settings_args(&mut args, layout.memory_dir.as_deref());
    inner.extend(args);

    // The host workspace root is not mounted, so the engine must not see it.
    let mut env = direct.env;
    gateway_llm_url(&mut env, isolation)?;
    if layout.agent_sock.is_some() {
        env.retain(|(key, _)| key != AGENT_SOCK_ENV);
        env.push((AGENT_SOCK_ENV.to_owned(), AGENT_SOCK.into()));
    }
    env.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            "GINO_WORKSPACE_DIR" | MEMORY_DIR_ENV | AGENT_MEMORY_DIR_ENV | CONVERSATIONS_DIR_ENV
        ) && !ctx.config_dir_keys.contains(&key.as_str())
    });
    let mounts = [
        (
            layout.memory_dir.is_some(),
            MEMORY_DIR_ENV,
            TASK_MEMORY_MOUNT,
        ),
        (
            layout.agent_memory_dir.is_some(),
            AGENT_MEMORY_DIR_ENV,
            AGENT_MEMORY_MOUNT,
        ),
        (
            layout.conversations_dir.is_some(),
            CONVERSATIONS_DIR_ENV,
            CONVERSATIONS_MOUNT,
        ),
    ];
    env.extend(
        mounts
            .into_iter()
            .filter(|(mounted, _, _)| *mounted)
            .map(|(_, key, path)| (key.to_owned(), path.into())),
    );
    env.extend(ctx.config_dir_keys.iter().map(|key| {
        (
            (*key).to_owned(),
            layout.engine_home.clone().into_os_string(),
        )
    }));
    env.extend([
        ("HOME".to_owned(), layout.home.clone().into_os_string()),
        ("TMPDIR".to_owned(), "/tmp".into()),
        (
            "GINO_ARCHIVE_DIR".to_owned(),
            work_dir.join("conversations").into_os_string(),
        ),
        ("GINO_SANDBOX".to_owned(), "1".into()),
    ]);

    Ok(Launch {
        program: host.bwrap.clone(),
        args: bwrap_args(&layout, &host.root, &inner),
        env,
        cwd: direct.cwd,
        sandboxed: true,
        net: net.map(Arc::new),
        conversations: conversations.map(Arc::new),
        vm: None,
    })
}

/// Create the run's conversations view: a private dir holding a snapshot of
/// the task's earlier archives.
fn conversations_view(ctx: &LaunchContext<'_>) -> std::io::Result<RunDir> {
    let dir = RunDir::create("gino-conv-")?;
    snapshot_archives(ctx.task_archives, &dir.0, ctx.conversations_max_bytes)?;
    Ok(dir)
}

/// Copy the top-level regular files of each archive dir into
/// `dest/<name of the archive's parent dir>/`: the newest archive (last in
/// `archives`) and, within one, the newest file first, stopping before
/// `max_bytes` would be exceeded. When files are left out, [`TRUNCATED_NOTE`]
/// at `dest` says so. A source is never followed through a symlink; symlinks,
/// nested dirs, special files and unreadable sources are skipped.
pub(crate) fn snapshot_archives(
    archives: &[PathBuf],
    dest: &Path,
    max_bytes: u64,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    let mut remaining = max_bytes;
    let mut skipped = 0_usize;
    for archive in archives.iter().rev() {
        let Some(name) = archive.parent().and_then(Path::file_name) else {
            continue;
        };
        let (dir, files) = match list_archive(archive) {
            Ok(listed) => listed,
            Err(err) => {
                tracing::debug!(archive = %archive.display(), error = %err, "skipping a conversations archive");
                continue;
            }
        };
        let target = dest.join(name);
        for file in &files {
            if skipped > 0 {
                skipped += 1;
                continue;
            }
            match copy_archive_file(&dir, file, &target, remaining)? {
                Some(copied) => remaining -= copied,
                None => skipped += 1,
            }
        }
    }
    if skipped > 0 {
        std::fs::write(
            dest.join(TRUNCATED_NOTE),
            format!(
                "# Truncated\n\nThis view holds at most {max_bytes} bytes of archived transcripts, \
                 newest first. {skipped} older archive file(s) were left out and are not included.\n"
            ),
        )?;
    }
    Ok(())
}

/// Open `path` as a dir without following a symlink and list its regular
/// files, newest first.
fn list_archive(path: &Path) -> nix::Result<(nix::dir::Dir, Vec<std::ffi::CString>)> {
    use nix::fcntl::{AtFlags, OFlag};
    use nix::sys::stat::{Mode, SFlag, fstatat};

    let mut dir = nix::dir::Dir::open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    let mut names = Vec::new();
    for entry in dir.iter() {
        let name = entry?.file_name().to_owned();
        if name.as_bytes() != b"." && name.as_bytes() != b".." {
            names.push(name);
        }
    }
    let mut files: Vec<_> = names
        .into_iter()
        .filter_map(|name| {
            let stat = fstatat(&dir, name.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW).ok()?;
            (stat.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFREG.bits())
                .then_some((name, (stat.st_mtime, stat.st_mtime_nsec)))
        })
        .collect();
    files.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok((dir, files.into_iter().map(|(name, _)| name).collect()))
}

/// Copy regular file `name` of `dir` into `target` when it fits in `budget`
/// bytes: `Some(bytes copied)`, `Some(0)` for a source skipped, `None` when it
/// does not fit. Only writing the copy is an error.
fn copy_archive_file(
    dir: &nix::dir::Dir,
    name: &std::ffi::CStr,
    target: &Path,
    budget: u64,
) -> std::io::Result<Option<u64>> {
    use std::os::unix::ffi::OsStrExt as _;

    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::{Mode, SFlag, fstat};

    let source = openat(
        dir,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .and_then(|fd| fstat(&fd).map(|stat| (fd, stat)));
    let (fd, stat) = match source {
        Ok((fd, stat)) if stat.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFREG.bits() => {
            (fd, stat)
        }
        Ok(_) => return Ok(Some(0)),
        Err(err) => {
            tracing::debug!(file = ?name, error = %err, "skipping a conversations archive file");
            return Ok(Some(0));
        }
    };
    let size = u64::try_from(stat.st_size).unwrap_or(0);
    if size > budget {
        return Ok(None);
    }
    std::fs::create_dir_all(target)?;
    let mut out =
        std::fs::File::create_new(target.join(std::ffi::OsStr::from_bytes(name.to_bytes())))?;
    let mut source = std::io::Read::take(std::fs::File::from(fd), size);
    let copied = std::io::copy(&mut source, &mut out)?;
    Ok(Some(copied))
}

/// Pid of the first process inside a sandbox (`sandbox-init`), the direct
/// child of `bwrap_pid`.
pub(crate) fn sandbox_init_pid(bwrap_pid: i32) -> Option<i32> {
    let children = format!("/proc/{bwrap_pid}/task/{bwrap_pid}/children");
    if let Some(pid) = std::fs::read_to_string(children)
        .ok()
        .and_then(|list| first_child(&list))
    {
        return Some(pid);
    }
    std::fs::read_dir("/proc")
        .ok()?
        .flatten()
        .find_map(|entry| {
            let pid: i32 = entry.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            (stat_ppid(&stat)? == bwrap_pid).then_some(pid)
        })
}

/// First pid in a `/proc/<pid>/task/<tid>/children` list.
fn first_child(list: &str) -> Option<i32> {
    list.split_whitespace().next()?.parse().ok()
}

/// Parent pid from a `/proc/<pid>/stat` line; `comm` may hold spaces and `)`.
fn stat_ppid(stat: &str) -> Option<i32> {
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// Lexically normalize a path: drops `.` components and trailing slashes.
fn normalize(path: &Path) -> PathBuf {
    path.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
}

/// The agent's own state files an extra path may neither name nor contain: the
/// agent DB with its `-wal`/`-shm` files and the e2ee key files beside it, for
/// the bootstrap DB path and the default DB in the workspace.
fn protected_files(workspace: &Path) -> Vec<PathBuf> {
    let bootstrap = crate::config::bootstrap_db_path();
    let bootstrap = std::path::absolute(&bootstrap).unwrap_or(bootstrap);
    [bootstrap, workspace.join(crate::config::DEFAULT_DB_FILE)]
        .iter()
        .flat_map(|db| {
            let state_dir = crate::e2ee::state_dir(db);
            let sibling = |suffix: &str| {
                let mut name = db.clone().into_os_string();
                name.push(suffix);
                PathBuf::from(name)
            };
            [
                db.clone(),
                sibling("-wal"),
                sibling("-shm"),
                state_dir.join(crate::e2ee::IDENTITY_KEY_FILE),
                state_dir.join(crate::e2ee::STATE_KEY_FILE),
            ]
        })
        .map(|file| normalize(&file))
        .collect()
}

fn validate_paths(
    paths: Option<&[PathBuf]>,
    workspace: &Path,
    protected: &[PathBuf],
) -> Result<Vec<PathBuf>, IsolationError> {
    paths
        .unwrap_or_default()
        .iter()
        .map(|path| {
            let invalid = |reason| IsolationError::InvalidPath {
                path: path.clone(),
                reason,
            };
            if !path.is_absolute() {
                return Err(invalid("not absolute"));
            }
            if path.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(invalid("contains `..`"));
            }
            let normalized = normalize(path);
            if normalized == workspace {
                return Err(invalid("is the workspace root"));
            }
            if workspace.starts_with(&normalized) {
                return Err(invalid("is a parent of the workspace root"));
            }
            if protected.iter().any(|file| file.starts_with(&normalized)) {
                return Err(invalid("is or contains the agent DB or an e2ee key file"));
            }
            Ok(normalized)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::{
        DEFAULT_CONVERSATIONS_MAX_BYTES, Isolation, IsolationError, IsolationMode, IsolationSpec,
        Launch, LaunchContext, LlmBaseUrl, NetworkMode, NetworkSpec, SandboxAvailability,
        SandboxHost, TRUNCATED_NOTE, availability, check_not_root, first_child, launch, launch_as,
        llm_endpoint, override_from_meta, resolve, sandbox_init_pid, snapshot_archives, stat_ppid,
        tighten_floor, validate_floor, validate_paths, wrap,
    };
    use crate::engine::EngineError;
    use crate::memory::AgentMemoryAccess;
    use crate::net::rules::{AlwaysAllow, Decision, Proto, RuleError, RuleSet};
    use crate::sandbox::vm::VmConfig;

    const WORKSPACE: &str = "/var/lib/gino-agent";

    fn spec(mode: Option<&str>, network: Option<&str>) -> IsolationSpec {
        IsolationSpec {
            mode: mode.map(str::to_owned),
            network: network.map(|n| NetworkSpec {
                mode: Some(n.to_owned()),
                ..NetworkSpec::default()
            }),
            ..IsolationSpec::default()
        }
    }

    fn with_paths(mut spec: IsolationSpec, read: &[&str], write: &[&str]) -> IsolationSpec {
        spec.read_paths = Some(read.iter().map(PathBuf::from).collect());
        spec.write_paths = Some(write.iter().map(PathBuf::from).collect());
        spec
    }

    fn allowing(mut spec: IsolationSpec) -> IsolationSpec {
        spec.allow_task_override = Some(true);
        spec
    }

    fn vm_config() -> VmConfig {
        VmConfig {
            kernel: "/nonexistent/vm/vmlinux".into(),
            rootfs: "/nonexistent/vm/rootfs".into(),
            vmm: "/nonexistent/vm/gino-vmm".into(),
            has_libkrun: false,
            vcpus: 2,
            memory_mib: 2048,
            disk_gib: 1,
            docker: false,
        }
    }

    /// `spec` with a `vm` block, as only the local isolation file has.
    fn with_vm(mut spec: IsolationSpec) -> IsolationSpec {
        spec.vm = Some(vm_config());
        spec
    }

    /// No floor: the engine's URL is trusted as is.
    fn unfloored(engine: Option<&str>) -> LlmBaseUrl<'_> {
        LlmBaseUrl {
            engine,
            daemon: engine,
            floored: false,
        }
    }

    fn run(
        default: &IsolationSpec,
        task: Option<&IsolationSpec>,
    ) -> Result<Isolation, IsolationError> {
        resolve(default, task, Path::new(WORKSPACE), LlmBaseUrl::default())
    }

    fn path_error(path: &str) -> IsolationError {
        run(&with_paths(spec(Some("sandbox"), None), &[path], &[]), None).unwrap_err()
    }

    #[test]
    fn absent_mode_resolves_off() {
        assert_eq!(
            run(&IsolationSpec::default(), None).unwrap(),
            Isolation::off()
        );
        assert_eq!(
            run(&spec(None, Some("full")), None).unwrap(),
            Isolation::off()
        );
    }

    #[test]
    fn sandbox_defaults_to_no_network() {
        let iso = run(&spec(Some("sandbox"), None), None).unwrap();
        assert_eq!(iso.mode, IsolationMode::Sandbox);
        assert_eq!(iso.network, NetworkMode::None);

        let iso = run(&spec(Some("sandbox"), Some("none")), None).unwrap();
        assert_eq!(iso.network, NetworkMode::None);
    }

    #[test]
    fn sandbox_with_full_network() {
        let iso = run(&spec(Some("sandbox"), Some("full")), None).unwrap();
        assert_eq!(iso.mode, IsolationMode::Sandbox);
        assert_eq!(iso.network, NetworkMode::Full);
    }

    #[test]
    fn override_beats_default_for_mode_and_network() {
        let default = allowing(spec(Some("sandbox"), Some("none")));
        let iso = run(&default, Some(&spec(None, Some("full")))).unwrap();
        assert_eq!(iso.mode, IsolationMode::Sandbox);
        assert_eq!(iso.network, NetworkMode::Full);

        assert_eq!(
            run(&default, Some(&spec(Some("off"), None))).unwrap(),
            Isolation::off()
        );

        let iso = run(
            &IsolationSpec::default(),
            Some(&spec(Some("sandbox"), None)),
        )
        .unwrap();
        assert_eq!(iso.mode, IsolationMode::Sandbox);
    }

    /// The resolved `(mode, network)`, or the error, of `default` + `task`.
    fn outcome(
        default: &IsolationSpec,
        task: &IsolationSpec,
    ) -> Result<(IsolationMode, NetworkMode), IsolationError> {
        run(default, Some(task)).map(|iso| (iso.mode, iso.network))
    }

    fn assert_loosens(
        default: &IsolationSpec,
        task: &IsolationSpec,
        setting: &str,
        from: &str,
        to: &str,
    ) {
        let err = run(default, Some(task)).unwrap_err();
        assert!(
            matches!(&err, IsolationError::OverrideLoosens { setting: s, from: f, to: t }
                if *s == setting && f == from && t == to),
            "{default:?} + {task:?}: {err:?}"
        );
    }

    fn assert_vm_unavailable(result: Result<(IsolationMode, NetworkMode), IsolationError>) {
        let err = result.unwrap_err();
        assert!(
            matches!(&err, IsolationError::Unavailable(m) if m.contains("engine.isolation.vm")),
            "{err:?}"
        );
    }

    #[test]
    fn mode_override_may_only_tighten() {
        use IsolationMode::{Sandbox, Vm};
        use NetworkMode::None as NoNet;

        // off -> sandbox tightens, also from an absent default.
        for default in [spec(Some("off"), None), IsolationSpec::default()] {
            assert_eq!(
                outcome(&default, &spec(Some("sandbox"), None)).unwrap(),
                (Sandbox, NoNet)
            );
            // vm tightens too, but needs the default's vm block.
            assert_vm_unavailable(outcome(&default, &spec(Some("vm"), None)));
            assert_eq!(
                outcome(&with_vm(default.clone()), &spec(Some("vm"), None)).unwrap(),
                (Vm, NoNet)
            );
            assert_eq!(
                run(&default, Some(&spec(Some("off"), None))).unwrap(),
                Isolation::off()
            );
        }
        // sandbox -> vm tightens.
        assert_vm_unavailable(outcome(
            &spec(Some("sandbox"), None),
            &spec(Some("vm"), None),
        ));
        assert_eq!(
            outcome(
                &with_vm(spec(Some("sandbox"), None)),
                &spec(Some("vm"), None)
            )
            .unwrap(),
            (Vm, NoNet)
        );
        assert_eq!(
            outcome(&with_vm(spec(Some("vm"), None)), &spec(Some("vm"), None)).unwrap(),
            (Vm, NoNet)
        );
        assert_eq!(
            outcome(&spec(Some("sandbox"), None), &spec(Some("sandbox"), None)).unwrap(),
            (Sandbox, NoNet)
        );

        assert_loosens(
            &spec(Some("sandbox"), None),
            &spec(Some("off"), None),
            "isolation.mode",
            "sandbox",
            "off",
        );
        assert_loosens(
            &spec(Some("vm"), None),
            &spec(Some("off"), None),
            "isolation.mode",
            "vm",
            "off",
        );
        assert_loosens(
            &spec(Some("vm"), None),
            &spec(Some("sandbox"), None),
            "isolation.mode",
            "vm",
            "sandbox",
        );
    }

    #[test]
    fn mode_override_loosens_with_allow_task_override() {
        let sandbox = allowing(spec(Some("sandbox"), None));
        assert_eq!(
            run(&sandbox, Some(&spec(Some("off"), None))).unwrap(),
            Isolation::off()
        );
        let vm = allowing(spec(Some("vm"), None));
        assert_eq!(
            run(&vm, Some(&spec(Some("off"), None))).unwrap(),
            Isolation::off()
        );
        assert_eq!(
            outcome(&vm, &spec(Some("sandbox"), None)).unwrap(),
            (IsolationMode::Sandbox, NetworkMode::None)
        );
        let off = allowing(spec(Some("off"), None));
        assert_eq!(
            outcome(&off, &spec(Some("sandbox"), None)).unwrap(),
            (IsolationMode::Sandbox, NetworkMode::None)
        );
        assert_vm_unavailable(outcome(&sandbox, &spec(Some("vm"), None)));
    }

    #[test]
    fn network_override_may_only_tighten() {
        use IsolationMode::Sandbox;
        use NetworkMode::{Allowlist, Full, None as NoNet};

        let sandbox = |network| spec(Some("sandbox"), network);
        let net = |network| spec(None, Some(network));

        // Tightening.
        assert_eq!(
            outcome(&sandbox(Some("full")), &net("allowlist")).unwrap(),
            (Sandbox, Allowlist)
        );
        assert_eq!(
            outcome(&sandbox(Some("allowlist")), &net("allowlist")).unwrap(),
            (Sandbox, Allowlist)
        );
        assert_eq!(
            outcome(&sandbox(Some("full")), &net("none")).unwrap(),
            (Sandbox, NoNet)
        );
        assert_eq!(
            outcome(&sandbox(Some("allowlist")), &net("none")).unwrap(),
            (Sandbox, NoNet)
        );
        assert_eq!(
            outcome(&sandbox(Some("full")), &net("full")).unwrap(),
            (Sandbox, Full)
        );

        // Loosening, including from an absent network (= none).
        for default in [sandbox(None), sandbox(Some("none"))] {
            for to in ["full", "allowlist"] {
                assert_loosens(&default, &net(to), "isolation.network.mode", "none", to);
            }
        }
        assert_loosens(
            &sandbox(Some("allowlist")),
            &net("full"),
            "isolation.network.mode",
            "allowlist",
            "full",
        );
        // The mode is checked first.
        assert_loosens(
            &sandbox(None),
            &spec(Some("off"), Some("full")),
            "isolation.mode",
            "sandbox",
            "off",
        );
    }

    #[test]
    fn network_override_loosens_with_allow_task_override() {
        let allow = |network| allowing(spec(Some("sandbox"), Some(network)));
        let net = |network| spec(None, Some(network));
        assert_eq!(
            outcome(&allow("none"), &net("full")).unwrap(),
            (IsolationMode::Sandbox, NetworkMode::Full)
        );
        assert_eq!(
            outcome(&allow("none"), &net("allowlist")).unwrap(),
            (IsolationMode::Sandbox, NetworkMode::Allowlist)
        );
        assert_eq!(
            outcome(&allow("allowlist"), &net("full")).unwrap(),
            (IsolationMode::Sandbox, NetworkMode::Full)
        );
        assert_eq!(
            outcome(&allow("full"), &net("none")).unwrap(),
            (IsolationMode::Sandbox, NetworkMode::None)
        );
    }

    #[test]
    fn an_off_default_accepts_any_override_network() {
        for default in [IsolationSpec::default(), spec(Some("off"), Some("none"))] {
            for (network, expected) in [
                (None, NetworkMode::None),
                (Some("none"), NetworkMode::None),
                (Some("full"), NetworkMode::Full),
                (Some("allowlist"), NetworkMode::Allowlist),
            ] {
                let result = outcome(&default, &spec(Some("sandbox"), network));
                assert_eq!(result.unwrap(), (IsolationMode::Sandbox, expected));
            }
        }
    }

    #[test]
    fn absent_override_keeps_the_default() {
        let iso = run(&spec(Some("sandbox"), Some("full")), None).unwrap();
        assert_eq!(
            (iso.mode, iso.network),
            (IsolationMode::Sandbox, NetworkMode::Full)
        );
        // An empty override changes nothing either.
        let iso = run(
            &spec(Some("sandbox"), Some("full")),
            Some(&IsolationSpec::default()),
        )
        .unwrap();
        assert_eq!(
            (iso.mode, iso.network),
            (IsolationMode::Sandbox, NetworkMode::Full)
        );
    }

    #[test]
    fn allow_task_override_inside_the_override_is_ignored() {
        let task = allowing(spec(Some("off"), None));
        assert_loosens(
            &spec(Some("sandbox"), None),
            &task,
            "isolation.mode",
            "sandbox",
            "off",
        );
        let default = IsolationSpec {
            allow_task_override: Some(false),
            ..spec(Some("sandbox"), None)
        };
        assert_loosens(&default, &task, "isolation.mode", "sandbox", "off");
    }

    #[test]
    fn invalid_values_never_pass_as_tighter() {
        let err = run(
            &spec(Some("jail"), None),
            Some(&spec(Some("sandbox"), None)),
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::UnknownMode(m) if m == "jail"));
        let err = run(
            &spec(Some("sandbox"), None),
            Some(&spec(Some("jail"), None)),
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::UnknownMode(m) if m == "jail"));
        let err = run(
            &spec(Some("sandbox"), Some("partial")),
            Some(&spec(None, Some("none"))),
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::UnknownNetworkMode(m) if m == "partial"));
        let err = run(
            &spec(Some("sandbox"), None),
            Some(&spec(None, Some("partial"))),
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::UnknownNetworkMode(m) if m == "partial"));
    }

    #[test]
    fn loosen_error_names_the_setting_and_the_opt_in() {
        let err = run(
            &spec(Some("sandbox"), None),
            Some(&spec(None, Some("full"))),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "task meta.isolation would loosen isolation.network.mode from `none` to `full`; \
             set engine.isolation.allowTaskOverride to allow this"
        );
        let err = run(&spec(Some("sandbox"), None), Some(&spec(Some("off"), None))).unwrap_err();
        assert!(
            err.to_string()
                .contains("isolation.mode from `sandbox` to `off`"),
            "{err}"
        );
    }

    #[test]
    fn override_paths_are_ignored() {
        let default = with_paths(spec(Some("sandbox"), None), &["/data/ro"], &["/data/rw"]);
        let task = with_paths(IsolationSpec::default(), &["/etc"], &["relative"]);
        let iso = run(&default, Some(&task)).unwrap();
        assert_eq!(iso.read_paths, [PathBuf::from("/data/ro")]);
        assert_eq!(iso.write_paths, [PathBuf::from("/data/rw")]);
    }

    #[test]
    fn vm_without_a_vm_block_is_unavailable() {
        let err = run(&spec(Some("vm"), None), None).unwrap_err();
        assert_eq!(
            err.to_string(),
            "engine sandbox is unavailable: vm mode needs engine.isolation.vm in the local \
             isolation file"
        );
    }

    #[test]
    fn vm_resolves_with_the_default_vm_block_and_paths() {
        let default = with_vm(with_paths(
            spec(Some("vm"), None),
            &["/data/ro"],
            &["/data/rw"],
        ));
        let iso = run(&default, None).unwrap();
        assert_eq!(
            (iso.mode, iso.network),
            (IsolationMode::Vm, NetworkMode::None)
        );
        assert!(iso.allowlist.is_none());
        let vm = iso.vm.as_deref().unwrap();
        assert_eq!(vm.config, vm_config());
        assert_eq!(vm.read_paths, [PathBuf::from("/data/ro")]);
        assert_eq!(vm.write_paths, [PathBuf::from("/data/rw")]);
        assert_eq!(iso.read_paths, vm.read_paths);

        // A task's vm block never counts.
        let mut task = spec(Some("vm"), None);
        task.vm = Some(VmConfig {
            vmm: "/evil/gino-vmm".into(),
            ..vm_config()
        });
        assert_eq!(run(&default, Some(&task)).unwrap().vm, iso.vm);
        assert!(run(&spec(Some("vm"), None), Some(&task)).is_err());

        // Sandbox and off runs carry no vm settings.
        assert!(
            run(&with_vm(spec(Some("sandbox"), None)), None)
                .unwrap()
                .vm
                .is_none()
        );
    }

    #[test]
    fn vm_disk_comes_from_the_task_or_the_default() {
        let task_disk = |default: &IsolationSpec, task: Option<&IsolationSpec>| {
            run(default, task).map(|iso| iso.vm.unwrap().task_disk)
        };
        let default = with_vm(spec(Some("vm"), None));
        assert!(!task_disk(&default, None).unwrap());
        let task = IsolationSpec {
            vm_disk: Some("task".into()),
            ..IsolationSpec::default()
        };
        assert!(task_disk(&default, Some(&task)).unwrap());
        let per_task = IsolationSpec {
            vm_disk: Some("task".into()),
            ..default.clone()
        };
        assert!(task_disk(&per_task, None).unwrap());
        let run_task = IsolationSpec {
            vm_disk: Some("run".into()),
            ..IsolationSpec::default()
        };
        assert!(!task_disk(&per_task, Some(&run_task)).unwrap());
        let bad = IsolationSpec {
            vm_disk: Some("thread".into()),
            ..IsolationSpec::default()
        };
        assert!(matches!(
            task_disk(&default, Some(&bad)),
            Err(IsolationError::InvalidVm(m)) if m.contains("thread")
        ));
    }

    #[test]
    fn vm_accepts_every_network_mode() {
        let rules = r#"[{ "host": "*.pypi.org", "ports": [443] }]"#;
        let none = run(&with_vm(spec(Some("vm"), Some("none"))), None).unwrap();
        assert_eq!(none.network, NetworkMode::None);
        assert!(none.allowlist.is_none());

        let allowlist = run(
            &with_rules(with_vm(spec(Some("vm"), Some("allowlist"))), rules),
            None,
        )
        .unwrap();
        assert_eq!(allowlist.network, NetworkMode::Allowlist);
        let set = allowlist_of(&allowlist);
        assert!(allows(set, "files.pypi.org", 443));
        assert!(allows(set, "api.anthropic.com", 443));
        assert!(!allows(set, "example.com", 443));

        let full = run(
            &with_rules(with_vm(spec(Some("vm"), Some("full"))), rules),
            None,
        )
        .unwrap();
        assert_eq!(full.network, NetworkMode::Full);
        assert!(allows(
            full.allowlist.as_deref().unwrap(),
            "example.com",
            443
        ));
    }

    #[test]
    fn vm_full_network_allows_every_public_destination_only() {
        use crate::net::upstream::check_address;

        // Floor cidr rules covering private ranges do not apply to full.
        let default = with_rules(
            with_vm(spec(Some("vm"), Some("full"))),
            r#"[{ "cidr": "10.0.0.0/8", "ports": "*" }]"#,
        );
        let iso = run(&default, None).unwrap();
        let rules = iso.allowlist.as_deref().unwrap();
        for proto in [Proto::Tcp, Proto::Udp] {
            assert!(matches!(
                rules.decide(
                    Some("example.com"),
                    "203.0.113.9".parse().unwrap(),
                    8080,
                    proto
                ),
                Decision::Allow {
                    rule_index: Some(_)
                }
            ));
            assert!(matches!(
                rules.decide(None, "1.1.1.1".parse().unwrap(), 53, proto),
                Decision::Allow {
                    rule_index: Some(_)
                }
            ));
        }
        assert!(rules.name_allowed("intranet"));
        assert!(check_address("1.1.1.1".parse().unwrap(), 443, Proto::Tcp, rules).is_ok());
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
        ] {
            let ip = ip.parse().unwrap();
            for proto in [Proto::Tcp, Proto::Udp] {
                assert!(
                    check_address(ip, 443, proto, rules).is_err(),
                    "{ip} {proto:?}"
                );
            }
        }

        // A loopback LLM endpoint is still the gateway forward.
        let iso = resolve(
            &with_vm(spec(Some("vm"), Some("full"))),
            None,
            Path::new(WORKSPACE),
            unfloored(Some("http://127.0.0.1:8080")),
        )
        .unwrap();
        assert_eq!(iso.llm_gateway.map(|gw| gw.port), Some(8080));

        // Sandbox full stays the host network, without rules.
        let iso = run(&spec(Some("sandbox"), Some("full")), None).unwrap();
        assert!(iso.allowlist.is_none());
    }

    #[test]
    fn override_from_meta_drops_the_vm_block() {
        let meta = r#"{ "isolation": { "mode": "vm",
            "vm": { "kernel": "/evil/k", "rootfs": "/evil/r", "vmm": "/evil/v" } } }"#;
        let task = override_from_meta(Some(meta)).unwrap().unwrap();
        assert_eq!(task.mode.as_deref(), Some("vm"));
        assert_eq!(task.vm, None);
        // A malformed vm block is dropped, not an error.
        let meta = r#"{ "isolation": { "vm": "anything" } }"#;
        assert_eq!(override_from_meta(Some(meta)).unwrap().unwrap().vm, None);
    }

    /// `spec` with `network.allow` set from a JSON rule list.
    fn with_rules(mut spec: IsolationSpec, rules: &str) -> IsolationSpec {
        spec.network.get_or_insert_with(NetworkSpec::default).allow =
            Some(serde_json::from_str(rules).unwrap());
        spec
    }

    fn allowlist_of(iso: &Isolation) -> &RuleSet {
        assert_eq!(iso.network, NetworkMode::Allowlist);
        iso.allowlist.as_deref().unwrap()
    }

    const ANY_IP: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7));

    fn allows(rules: &RuleSet, name: &str, port: u16) -> bool {
        matches!(
            rules.decide(Some(name), ANY_IP, port, Proto::Tcp),
            Decision::Allow { .. }
        )
    }

    #[test]
    fn meta_allowlist_tightens_an_off_default() {
        let task = override_from_meta(Some(
            r#"{ "isolation": { "mode": "sandbox", "network": { "mode": "allowlist" } } }"#,
        ))
        .unwrap()
        .unwrap();
        for default in [IsolationSpec::default(), spec(Some("off"), Some("none"))] {
            let iso = run(&default, Some(&task)).unwrap();
            assert_eq!(iso.mode, IsolationMode::Sandbox);
            assert!(allows(allowlist_of(&iso), "api.anthropic.com", 443));
        }
    }

    #[test]
    fn meta_allow_rules_are_ignored() {
        for allow in [
            r#"[{ "host": "evil.example", "ports": "*" }]"#,
            r#"[{ "host": "bad host", "ports": [] }]"#,
            "5",
        ] {
            let meta = format!(
                r#"{{ "isolation": {{ "mode": "sandbox",
                    "network": {{ "mode": "allowlist", "allow": {allow} }} }} }}"#
            );
            let task = override_from_meta(Some(&meta)).unwrap().unwrap();
            assert_eq!(task.network.as_ref().unwrap().allow, None, "{meta}");
            let iso = run(&IsolationSpec::default(), Some(&task)).unwrap();
            assert!(!allowlist_of(&iso).name_allowed("evil.example"), "{meta}");
        }
        // An override built in memory with rules still gets none of them.
        let task = with_rules(
            spec(Some("sandbox"), Some("allowlist")),
            r#"[{ "host": "evil.example", "ports": "*" }]"#,
        );
        let iso = run(&IsolationSpec::default(), Some(&task)).unwrap();
        assert!(!allowlist_of(&iso).name_allowed("evil.example"));
    }

    #[test]
    fn allowlist_holds_only_the_llm_endpoint_without_config_rules() {
        let iso = run(&spec(Some("sandbox"), Some("allowlist")), None).unwrap();
        let rules = allowlist_of(&iso);
        assert_eq!(
            rules.decide(Some("api.anthropic.com"), ANY_IP, 443, Proto::Tcp),
            Decision::Allow { rule_index: None }
        );
        assert!(!allows(rules, "api.anthropic.com", 80));
        assert!(!allows(rules, "example.com", 443));
        assert!(!rules.name_allowed("example.com"));
        assert_eq!(rules.cidr_covers(ANY_IP, 443, Proto::Tcp), None);
    }

    #[test]
    fn allowlist_adds_the_config_rules() {
        let default = with_rules(
            spec(Some("sandbox"), Some("allowlist")),
            r#"[{ "host": "*.pypi.org", "ports": [443] }]"#,
        );
        let iso = run(&default, Some(&spec(None, Some("allowlist")))).unwrap();
        let rules = allowlist_of(&iso);
        assert!(allows(rules, "files.pypi.org", 443));
        assert!(allows(rules, "api.anthropic.com", 443));
        assert!(!allows(rules, "example.com", 443));
    }

    #[test]
    fn config_rules_only_matter_for_allowlist() {
        let bad = r#"[{ "host": "bad host", "ports": "*" }]"#;
        for network in [None, Some("none"), Some("full")] {
            let default = with_rules(spec(Some("sandbox"), network), bad);
            let iso = run(&default, None).unwrap();
            assert!(iso.allowlist.is_none());
        }
    }

    #[test]
    fn invalid_config_rule_is_rejected_with_its_index() {
        let default = with_rules(
            spec(Some("sandbox"), Some("allowlist")),
            r#"[{ "host": "ok.example", "ports": "*" }, { "host": "bad host", "ports": "*" }]"#,
        );
        let err = run(&default, None).unwrap_err();
        assert!(
            matches!(
                &err,
                IsolationError::InvalidAllowlist(RuleError::Host { index: 1, .. })
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("rule 1"), "{err}");
    }

    #[test]
    fn llm_endpoint_follows_the_base_url() {
        let endpoint = |url| llm_endpoint(url).unwrap();
        let expect = |host: &str, port| AlwaysAllow {
            host: host.to_owned(),
            port,
        };
        assert_eq!(endpoint(None), expect("api.anthropic.com", 443));
        assert_eq!(
            endpoint(Some("https://proxy.example")),
            expect("proxy.example", 443)
        );
        assert_eq!(
            endpoint(Some("https://proxy.example:8443/v1")),
            expect("proxy.example", 8443)
        );
        assert_eq!(
            endpoint(Some("http://proxy.example/anthropic")),
            expect("proxy.example", 80)
        );
        assert_eq!(
            endpoint(Some("HTTP://user:pw@proxy.example:8080?x=1")),
            expect("proxy.example", 8080)
        );
        for url in [
            "proxy.example",
            "ftp://proxy.example",
            "https://",
            "https://proxy.example:",
            "https://proxy.example:99999",
        ] {
            let err = llm_endpoint(Some(url)).unwrap_err();
            assert!(matches!(err, IsolationError::InvalidBaseUrl), "{url}");
            assert!(!err.to_string().contains(url), "{err}");
        }
    }

    #[test]
    fn allowlist_admits_the_base_url_endpoint() {
        let default = spec(Some("sandbox"), Some("allowlist"));
        let iso = resolve(
            &default,
            None,
            Path::new(WORKSPACE),
            unfloored(Some("http://proxy.example:8080")),
        )
        .unwrap();
        let rules = allowlist_of(&iso);
        assert!(allows(rules, "proxy.example", 8080));
        assert!(!allows(rules, "api.anthropic.com", 443));
    }

    #[test]
    fn isolation_spec_reads_network_allow() {
        let spec: IsolationSpec = serde_json::from_str(
            r#"{ "mode": "sandbox", "network": { "mode": "allowlist",
                 "allow": [{ "host": "pypi.org", "ports": [443] }] } }"#,
        )
        .unwrap();
        let allow = spec.network.unwrap().allow.unwrap();
        assert_eq!(allow.len(), 1);
        assert_eq!(allow[0].host.as_deref(), Some("pypi.org"));
    }

    #[test]
    fn unknown_values_are_errors() {
        let err = run(&spec(Some("jail"), None), None).unwrap_err();
        assert!(matches!(err, IsolationError::UnknownMode(m) if m == "jail"));

        let err = run(&spec(Some("sandbox"), Some("partial")), None).unwrap_err();
        assert!(matches!(err, IsolationError::UnknownNetworkMode(m) if m == "partial"));

        let err = run(
            &IsolationSpec::default(),
            Some(&spec(Some("Sandbox"), None)),
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::UnknownMode(_)));
    }

    #[test]
    fn invalid_paths_are_errors() {
        for path in [
            "data/cache",
            WORKSPACE,
            "/var/lib/gino-agent/",
            "/var/lib/./gino-agent",
            "/var/lib",
            "/",
            "/data/../etc",
        ] {
            let err = path_error(path);
            assert!(
                matches!(&err, IsolationError::InvalidPath { path: p, .. } if p == Path::new(path)),
                "{path}: {err:?}"
            );
        }
        // Write paths are validated too.
        let err = run(
            &with_paths(spec(Some("sandbox"), None), &[], &["/var"]),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::InvalidPath { .. }));
    }

    #[test]
    fn the_agent_db_and_the_e2ee_key_files_are_never_extra_paths() {
        for name in [
            "agent.db",
            "agent.db-wal",
            "agent.db-shm",
            "e2ee-identity.key",
            "e2ee-state.key",
        ] {
            let path = format!("{WORKSPACE}/{name}");
            let (none, one): (&[&str], &[&str]) = (&[], &[path.as_str()]);
            for (read, write) in [(one, none), (none, one)] {
                let err =
                    run(&with_paths(spec(Some("sandbox"), None), read, write), None).unwrap_err();
                assert!(
                    matches!(
                        &err,
                        IsolationError::InvalidPath {
                            reason: "is or contains the agent DB or an e2ee key file",
                            ..
                        }
                    ),
                    "{path}: {err:?}"
                );
            }
        }
        let key = format!("{WORKSPACE}/e2ee-state.key");
        assert!(matches!(
            validate_floor(
                &with_paths(spec(None, None), &[key.as_str()], &[]),
                Path::new(WORKSPACE),
            ),
            Err(IsolationError::InvalidPath { .. })
        ));
    }

    #[test]
    fn a_state_dir_outside_the_workspace_is_protected_with_its_parents() {
        let protected = [PathBuf::from("/srv/state/e2ee-identity.key")];
        let check = |path: &str| {
            validate_paths(
                Some(&[PathBuf::from(path)]),
                Path::new(WORKSPACE),
                &protected,
            )
        };
        for path in [
            "/srv/state/e2ee-identity.key",
            "/srv/state",
            "/srv/./state/",
        ] {
            assert!(check(path).is_err(), "{path}");
        }
        for path in [
            "/srv/state/sub",
            "/srv/state-other",
            "/srv/state/e2ee-identity.key.bak",
        ] {
            assert!(check(path).is_ok(), "{path}");
        }
    }

    #[test]
    fn sibling_and_nested_paths_are_ok() {
        let default = with_paths(
            spec(Some("sandbox"), None),
            &["/data/cache", "/var/lib/gino-agent-other"],
            &["/var/lib/gino-agent/sub/", "/srv/./out"],
        );
        let iso = run(&default, None).unwrap();
        assert_eq!(
            iso.read_paths,
            [
                PathBuf::from("/data/cache"),
                PathBuf::from("/var/lib/gino-agent-other")
            ]
        );
        assert_eq!(
            iso.write_paths,
            [
                PathBuf::from("/var/lib/gino-agent/sub"),
                PathBuf::from("/srv/out")
            ]
        );
    }

    #[test]
    fn off_skips_path_validation() {
        let default = with_paths(IsolationSpec::default(), &["relative", "/"], &[WORKSPACE]);
        assert_eq!(run(&default, None).unwrap(), Isolation::off());

        let default = allowing(with_paths(
            spec(Some("sandbox"), Some("bogus")),
            &["relative"],
            &[],
        ));
        assert_eq!(
            run(&default, Some(&spec(Some("off"), None))).unwrap(),
            Isolation::off()
        );
    }

    #[test]
    fn override_from_meta_without_isolation_is_none() {
        for meta in [
            None,
            Some(""),
            Some("not json"),
            Some("[1, 2]"),
            Some("\"text\""),
            Some("{}"),
            Some(r#"{ "other": 1 }"#),
        ] {
            assert_eq!(override_from_meta(meta).unwrap(), None, "{meta:?}");
        }
    }

    #[test]
    fn override_from_meta_parses_the_isolation_block() {
        let spec = override_from_meta(Some(
            r#"{ "label": "x", "isolation": { "mode": "sandbox", "network": { "mode": "full" } } }"#,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(spec.mode.as_deref(), Some("sandbox"));
        assert_eq!(spec.network.unwrap().mode.as_deref(), Some("full"));
        assert!(spec.read_paths.is_none());
    }

    #[test]
    fn override_from_meta_rejects_a_malformed_isolation_value() {
        for meta in [
            r#"{ "isolation": "sandbox" }"#,
            r#"{ "isolation": { "mode": 1 } }"#,
            r#"{ "isolation": { "network": "full" } }"#,
            r#"{ "isolation": null }"#,
        ] {
            let err = override_from_meta(Some(meta)).unwrap_err();
            assert!(matches!(err, IsolationError::InvalidTaskMeta(_)), "{meta}");
        }
    }

    const KEYS: [&str; 2] = ["ENGINE_CONFIG_DIR", "ENGINE_OWN_DIR"];

    fn direct(cwd: &Path) -> Launch {
        Launch::direct(
            "engine".into(),
            vec!["-p".to_owned(), "--flag".to_owned()],
            vec![
                ("ENGINE_TOKEN".to_owned(), "secret".into()),
                ("ENGINE_CONFIG_DIR".to_owned(), "/ws/engine-config".into()),
                ("ENGINE_OWN_DIR".to_owned(), "/ws/engine-config".into()),
                ("GINO_TASK_ID".to_owned(), "task-1".into()),
            ],
            cwd.to_path_buf(),
        )
    }

    fn ctx<'a>(
        default: &'a IsolationSpec,
        task: Option<&'a IsolationSpec>,
        work_dir: Option<&'a Path>,
        self_exe: Option<&'a Path>,
    ) -> LaunchContext<'a> {
        LaunchContext {
            isolation: default,
            task_override: task,
            workspace_dir: Path::new(WORKSPACE),
            task_id: Some("task-1"),
            thread_id: Some("th-1"),
            work_dir,
            memory_dir: None,
            agent_memory_dir: None,
            agent_memory_access: crate::memory::AgentMemoryAccess::Rw,
            task_archives: &[],
            conversations_max_bytes: DEFAULT_CONVERSATIONS_MAX_BYTES,
            self_exe,
            global_config_dir: None,
            config_dir_keys: &KEYS,
            floored: false,
        }
    }

    /// A temp dir holding an executable `engine` stub, and a host whose `PATH`
    /// finds it.
    fn stub_host() -> (tempfile::TempDir, PathBuf, SandboxHost) {
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = std::fs::canonicalize(tmp.path()).unwrap().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let engine = bin_dir.join("engine");
        std::fs::write(&engine, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
        let host = SandboxHost::fixture(Some(bin_dir.into_os_string()));
        (tmp, engine, host)
    }

    fn sandboxed() -> Isolation {
        run(&spec(Some("sandbox"), None), None).unwrap()
    }

    fn env_values<'a>(launch: &'a Launch, key: &str) -> Vec<&'a OsString> {
        launch
            .env
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v)
            .collect()
    }

    #[test]
    fn off_launch_is_the_direct_launch() {
        let d = direct(Path::new("/ws/threads/t1/project"));
        let off = IsolationSpec::default();
        assert_eq!(launch(d.clone(), &ctx(&off, None, None, None)).unwrap(), d);

        let default = allowing(spec(Some("sandbox"), None));
        let task = spec(Some("off"), None);
        assert_eq!(
            launch(d.clone(), &ctx(&default, Some(&task), None, None)).unwrap(),
            d
        );
        assert!(!d.sandboxed);
    }

    #[test]
    fn availability_needs_bwrap_and_a_non_root_daemon() {
        let none = SandboxAvailability::default();
        assert_eq!(availability(false, false, 1000, true), none);
        assert_eq!(availability(true, true, 0, true), none);
        assert_eq!(
            availability(true, false, 1000, false),
            SandboxAvailability {
                sandbox: true,
                allowlist: false,
                vm: false,
            }
        );
        assert_eq!(
            availability(true, false, 1000, true),
            SandboxAvailability {
                sandbox: true,
                allowlist: true,
                vm: false,
            }
        );
        assert_eq!(
            availability(false, true, 1000, false),
            SandboxAvailability { vm: true, ..none }
        );
    }

    #[test]
    fn probe_without_a_vm_block_reports_no_vm() {
        assert!(!super::probe(None).vm);
    }

    #[test]
    fn vm_launch_fails_closed() {
        let d = direct(Path::new("/ws/threads/t1/project"));
        let default = with_vm(spec(Some("vm"), Some("full")));
        let ctx = ctx(&default, None, None, None);
        let err = launch_as(d.clone(), &ctx, 0).unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Unavailable(m)) if m.contains("root")),
            "{err:?}"
        );
        // The probe fails on the nonexistent VM paths before anything spawns.
        let err = launch_as(d.clone(), &ctx, 1000).unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Unavailable(_))),
            "{err:?}"
        );
        // Without the vm block the mode itself is unavailable.
        let default = spec(Some("vm"), None);
        let err = launch_as(d, &ctx_for(&default), 1000).unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Unavailable(m)) if m.contains("engine.isolation.vm")),
            "{err:?}"
        );
    }

    fn ctx_for(default: &IsolationSpec) -> LaunchContext<'_> {
        ctx(default, None, None, None)
    }

    #[test]
    fn root_euid_is_refused() {
        let err = check_not_root(0).unwrap_err();
        assert!(matches!(err, IsolationError::Unavailable(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "engine sandbox is unavailable: the agent runs as root; run it as an unprivileged user"
        );
        check_not_root(1000).unwrap();
    }

    #[test]
    fn allowlist_launch_is_refused_only_for_a_root_agent() {
        let d = direct(Path::new("/ws/threads/t1/project"));
        let task = spec(Some("sandbox"), Some("allowlist"));
        let off = IsolationSpec::default();
        let ctx = ctx(&off, Some(&task), None, None);
        let err = launch_as(d.clone(), &ctx, 0).unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Unavailable(m)) if m.contains("root")),
            "{err:?}"
        );
        // Past the root check only host facts can fail it.
        if let Err(err) = launch_as(d, &ctx, 1000) {
            assert!(!err.to_string().contains("root"), "{err:?}");
        }
    }

    fn allowlisted(base_url: Option<&str>) -> Isolation {
        resolve(
            &spec(Some("sandbox"), Some("allowlist")),
            None,
            Path::new(WORKSPACE),
            unfloored(base_url),
        )
        .unwrap()
    }

    #[test]
    fn loopback_llm_endpoint_becomes_the_gateway_forward() {
        for (url, target) in [
            ("http://127.0.0.1:8080/api/llm", "127.0.0.1:8080"),
            ("http://127.0.0.5:8080", "127.0.0.5:8080"),
            ("https://[::1]:9443/v1", "[::1]:9443"),
            ("http://LOCALHOST.:8080/x", "127.0.0.1:8080"),
            ("http://localhost/x", "127.0.0.1:80"),
        ] {
            let iso = allowlisted(Some(url));
            let target: std::net::SocketAddr = target.parse().unwrap();
            let gateway = iso.llm_gateway.unwrap();
            assert_eq!(gateway.port, target.port(), "{url}");
            if url.contains("localhost") || url.contains("LOCALHOST") {
                assert!(gateway.target.ip().is_loopback(), "{url}");
            } else {
                assert_eq!(gateway.target, target, "{url}");
            }
            // Loopback is never a rule.
            let rules = allowlist_of(&iso);
            assert!(!rules.name_allowed("localhost"), "{url}");
            assert!(matches!(
                rules.decide(None, target.ip(), target.port(), Proto::Tcp),
                Decision::Deny { .. }
            ));
        }
        assert!(allowlisted(None).llm_gateway.is_none());
        assert!(
            allowlisted(Some("https://proxy.example"))
                .llm_gateway
                .is_none()
        );
        let err = resolve(
            &spec(Some("sandbox"), Some("allowlist")),
            None,
            Path::new(WORKSPACE),
            unfloored(Some("http://user:pw@127.0.0.1:0/x")),
        )
        .unwrap_err();
        assert!(matches!(err, IsolationError::InvalidBaseUrl), "{err:?}");
        assert!(!err.to_string().contains("pw"), "{err}");

        // Full and none have no gateway.
        for network in ["full", "none"] {
            let iso = resolve(
                &spec(Some("sandbox"), Some(network)),
                None,
                Path::new(WORKSPACE),
                unfloored(Some("http://127.0.0.1:8080")),
            )
            .unwrap();
            assert!(iso.llm_gateway.is_none(), "{network}");
        }
    }

    #[test]
    fn ip_literal_llm_endpoint_is_an_always_allowed_address() {
        for (url, ip, port) in [
            ("http://172.17.0.1:8080/llm", "172.17.0.1", 8080),
            ("https://[fd00::1]/v1", "fd00::1", 443),
        ] {
            let iso = allowlisted(Some(url));
            assert!(iso.llm_gateway.is_none());
            let rules = allowlist_of(&iso);
            let ip = ip.parse().unwrap();
            assert_eq!(
                rules.decide(None, ip, port, Proto::Tcp),
                Decision::Allow { rule_index: None },
                "{url}"
            );
            assert!(matches!(
                rules.decide(None, ip, port + 1, Proto::Tcp),
                Decision::Deny { .. }
            ));
        }
    }

    #[test]
    fn link_local_llm_endpoint_is_refused() {
        for url in [
            "http://169.254.169.254/latest",
            "https://[fe80::1]:8443",
            "http://[::ffff:169.254.169.254]",
        ] {
            for llm in [
                unfloored(Some(url)),
                LlmBaseUrl {
                    floored: true,
                    ..unfloored(Some(url))
                },
            ] {
                let err = resolve(
                    &spec(Some("sandbox"), Some("allowlist")),
                    None,
                    Path::new(WORKSPACE),
                    llm,
                )
                .unwrap_err();
                assert!(matches!(err, IsolationError::LinkLocalBaseUrl), "{url}");
                assert!(!err.to_string().contains("169.254"), "{err}");
            }
        }
    }

    const FLOOR_RULES: &str = r#"[
        { "host": "proxy.example", "ports": [8443] },
        { "cidr": "127.0.0.0/8", "ports": "*" }
    ]"#;

    fn floored(engine: Option<&str>, daemon: Option<&str>) -> Result<Isolation, IsolationError> {
        resolve(
            &with_rules(spec(Some("sandbox"), Some("allowlist")), FLOOR_RULES),
            None,
            Path::new(WORKSPACE),
            LlmBaseUrl {
                engine,
                daemon,
                floored: true,
            },
        )
    }

    #[test]
    fn floor_keeps_the_daemon_llm_endpoint_always_allowed() {
        for url in [None, Some("https://llm.example")] {
            let iso = floored(url, url).unwrap();
            let host = url.map_or("api.anthropic.com", |_| "llm.example");
            assert_eq!(
                allowlist_of(&iso).decide(Some(host), ANY_IP, 443, Proto::Tcp),
                Decision::Allow { rule_index: None },
                "{url:?}"
            );
            assert!(iso.llm_gateway.is_none());
        }
        let url = Some("http://localhost:8080/llm");
        let gateway = floored(url, url).unwrap().llm_gateway.unwrap();
        assert_eq!(gateway.port, 8080);
        assert!(gateway.target.ip().is_loopback());
    }

    #[test]
    fn floor_admits_a_host_llm_url_only_through_a_floor_rule() {
        for daemon in [None, Some("https://llm.example")] {
            let iso = floored(Some("https://proxy.example:8443/v1"), daemon).unwrap();
            assert!(iso.llm_gateway.is_none());
            let rules = allowlist_of(&iso);
            assert_eq!(
                rules.decide(Some("proxy.example"), ANY_IP, 8443, Proto::Tcp),
                Decision::Allow {
                    rule_index: Some(0)
                }
            );
            // No endpoint is always allowed.
            assert!(!allows(rules, "api.anthropic.com", 443));
            assert!(!allows(rules, "llm.example", 443));
        }
    }

    #[test]
    fn floor_refuses_an_uncovered_or_loopback_host_llm_url() {
        for (engine, daemon) in [
            ("https://proxy.example/v1", None),
            ("https://other.example:8443", Some("https://llm.example")),
            ("http://u:pw@127.0.0.1:8080", None),
            ("http://localhost:8080", Some("http://localhost:9090")),
        ] {
            let err = floored(Some(engine), daemon).unwrap_err();
            assert!(matches!(err, IsolationError::HostBaseUrl), "{engine}");
            let message = err.to_string();
            assert!(message.contains("engine.anthropicBaseUrl"), "{message}");
            for part in ["example", "127.0.0.1", "localhost", "pw"] {
                assert!(!message.contains(part), "{message}");
            }
        }
    }

    #[test]
    fn gateway_url_swaps_only_the_host() {
        for (url, want) in [
            (
                "http://127.0.0.1:8080/api/llm",
                "http://10.0.2.2:8080/api/llm",
            ),
            (
                "http://localhost:3000/x?y=1#z",
                "http://10.0.2.2:3000/x?y=1#z",
            ),
            ("https://[::1]:9443", "https://10.0.2.2:9443"),
            ("http://[::1]/v1", "http://10.0.2.2/v1"),
            ("http://localhost?q", "http://10.0.2.2?q"),
            (
                "http://user:p%40ss@127.0.0.1:8080/llm", // trufflehog:ignore
                "http://user:p%40ss@10.0.2.2:8080/llm",  // trufflehog:ignore
            ),
        ] {
            assert_eq!(super::gateway_url(url).as_deref(), Some(want), "{url}");
        }
        assert_eq!(super::gateway_url("localhost:8080"), None);
    }

    fn launch_with_llm_url(base_url: &str, network: &str) -> (tempfile::TempDir, Launch) {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("threads/t1");
        let mut d = direct(&work_dir.join("project"));
        d.env
            .push(("ANTHROPIC_BASE_URL".to_owned(), base_url.into()));
        let isolation = resolve(
            &spec(Some("sandbox"), Some(network)),
            None,
            Path::new(WORKSPACE),
            unfloored(Some(base_url)),
        )
        .unwrap();
        let off = IsolationSpec::default();
        let agent = Path::new("/opt/gino/gino-agent");
        let wrapped = wrap(
            d,
            &ctx(&off, None, Some(&work_dir), Some(agent)),
            &isolation,
            &host,
        )
        .unwrap();
        (tmp, wrapped)
    }

    #[test]
    fn allowlist_launch_hands_over_the_network_and_rewrites_a_loopback_llm_url() {
        let (_tmp, wrapped) =
            launch_with_llm_url("http://u:pw@127.0.0.1:8080/api/llm?k=v", "allowlist");
        assert_eq!(
            env_values(&wrapped, "ANTHROPIC_BASE_URL"),
            ["http://u:pw@10.0.2.2:8080/api/llm?k=v"]
        );
        let args: Vec<&str> = wrapped.args.iter().map(|a| a.to_str().unwrap()).collect();
        let init = args.iter().position(|a| *a == "sandbox-init").unwrap();
        assert_eq!(
            args[init + 1..init + 4],
            ["--ctl-sock", "/run/gino/ctl.sock", "--"]
        );
        assert!(args.contains(&"CAP_NET_ADMIN"));

        let net = wrapped.net.as_deref().unwrap();
        let dir = net.dir.0.clone();
        let meta = std::fs::metadata(&dir).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::read_to_string(dir.join("resolv.conf")).unwrap(),
            "nameserver 10.0.2.2\n"
        );
        assert!(dir.join("ctl.sock").exists());
        assert_eq!(net.exit.thread_id, "th-1");
        assert_eq!(
            net.exit.gateway.map(|gw| gw.target),
            Some("127.0.0.1:8080".parse().unwrap())
        );
        let ctl = format!("{}", dir.join("ctl.sock").display());
        let bind = args.iter().position(|a| *a == ctl).unwrap();
        assert_eq!(args[bind + 1], "/run/gino/ctl.sock");
        // The dir goes with the launch.
        drop(wrapped);
        assert!(!dir.exists());
    }

    fn handover() -> (std::path::PathBuf, std::sync::Arc<super::NetHandover>) {
        let rules = std::sync::Arc::new(RuleSet::compile(&[], &[]).unwrap());
        let net =
            super::NetHandover::prepare(crate::net::exit::ExitConfig::new("th-1", rules)).unwrap();
        (net.dir.0.join("ctl.sock"), std::sync::Arc::new(net))
    }

    fn sandbox_stub(script: &str) -> tokio::process::Child {
        tokio::process::Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    #[tokio::test]
    async fn handover_without_a_tun_device_kills_the_sandbox() {
        let (sock, net) = handover();
        // `exec` so the killed child is the only process holding its stdio.
        let mut child = sandbox_stub("exec sleep 30");
        let connect = tokio::spawn(async move {
            // Connect and close without sending a descriptor.
            drop(tokio::net::UnixStream::connect(sock).await.unwrap());
        });
        let err = super::start_network(Some(net), &mut child)
            .await
            .unwrap_err();
        connect.await.unwrap();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Network(m)) if m.contains("TUN")),
            "{err:?}"
        );
        let status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
    }

    #[tokio::test]
    async fn handover_reports_an_early_sandbox_exit_with_its_stderr() {
        let (_, net) = handover();
        let mut child = sandbox_stub("echo 'sandbox-init: creating the TUN device' >&2; exit 125");
        let err = super::start_network(Some(net), &mut child)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("exited"), "{msg}");
        assert!(msg.contains("creating the TUN device"), "{msg}");
        assert!(
            super::start_network(None, &mut child)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn allowlist_launch_keeps_a_non_loopback_llm_url() {
        let url = "https://proxy.example:8443/v1";
        let (_tmp, wrapped) = launch_with_llm_url(url, "allowlist");
        assert_eq!(env_values(&wrapped, "ANTHROPIC_BASE_URL"), [url]);
        assert_eq!(wrapped.net.as_deref().unwrap().exit.gateway, None);
    }

    #[test]
    fn full_and_none_launches_keep_the_llm_url_and_have_no_handover() {
        let url = "http://127.0.0.1:8080/api/llm";
        for network in ["full", "none"] {
            let (_tmp, wrapped) = launch_with_llm_url(url, network);
            assert_eq!(
                env_values(&wrapped, "ANTHROPIC_BASE_URL"),
                [url],
                "{network}"
            );
            assert!(wrapped.net.is_none());
            assert!(
                !wrapped
                    .args
                    .iter()
                    .any(|a| a == "--ctl-sock" || a == "CAP_NET_ADMIN")
            );
        }
    }

    #[test]
    fn root_euid_fails_only_sandboxed_launches() {
        let d = direct(Path::new("/ws/threads/t1/project"));
        let off = IsolationSpec::default();
        assert_eq!(
            launch_as(d.clone(), &ctx(&off, None, None, None), 0).unwrap(),
            d
        );

        let sandbox = spec(Some("sandbox"), None);
        let err = launch_as(d, &ctx(&sandbox, None, None, None), 0).unwrap_err();
        assert!(
            matches!(&err, EngineError::Isolation(IsolationError::Unavailable(m)) if m.contains("root")),
            "{err:?}"
        );
    }

    #[test]
    fn unsupported_or_unknown_isolation_fails_the_launch() {
        let d = direct(Path::new(""));
        for (default, task) in [
            (spec(Some("vm"), None), None),
            (IsolationSpec::default(), Some(spec(Some("jail"), None))),
            (IsolationSpec::default(), Some(spec(Some("vm"), None))),
            (spec(Some("sandbox"), None), Some(spec(Some("off"), None))),
        ] {
            let err = launch(d.clone(), &ctx(&default, task.as_ref(), None, None)).unwrap_err();
            assert!(matches!(err, EngineError::Isolation(_)), "{err:?}");
        }
    }

    #[test]
    fn sandboxed_launch_wraps_the_engine_in_bwrap_and_sandbox_init() {
        let (tmp, engine, host) = stub_host();
        let work_dir = tmp.path().join("threads/t1");
        let cwd = work_dir.join("project");
        let agent = Path::new("/opt/gino/gino-agent");
        let off = IsolationSpec::default();
        let wrapped = wrap(
            direct(&cwd),
            &ctx(&off, None, Some(&work_dir), Some(agent)),
            &sandboxed(),
            &host,
        )
        .unwrap();

        assert!(wrapped.sandboxed);
        assert_eq!(wrapped.program, Path::new("/usr/bin/bwrap"));
        assert_eq!(wrapped.cwd, cwd);
        let tail: Vec<OsString> = [
            agent.as_os_str(),
            "sandbox-init".as_ref(),
            "--".as_ref(),
            engine.as_os_str(),
            "-p".as_ref(),
            "--flag".as_ref(),
        ]
        .map(OsString::from)
        .to_vec();
        assert_eq!(wrapped.args[wrapped.args.len() - tail.len() - 1], "--");
        assert_eq!(wrapped.args[wrapped.args.len() - tail.len()..], tail[..]);
        let chdir = wrapped.args.iter().position(|a| a == "--chdir").unwrap();
        assert_eq!(wrapped.args[chdir + 1], cwd.as_os_str());

        let home = work_dir.join(".engine-home");
        assert!(home.is_dir());
        for key in KEYS {
            assert_eq!(env_values(&wrapped, key), [home.as_os_str()], "{key}");
        }
        assert_eq!(env_values(&wrapped, "ENGINE_TOKEN"), ["secret"]);
        assert_eq!(env_values(&wrapped, "GINO_TASK_ID"), ["task-1"]);
        assert_eq!(env_values(&wrapped, "HOME"), ["/home/gino"]);
        assert_eq!(env_values(&wrapped, "TMPDIR"), ["/tmp"]);
        assert_eq!(env_values(&wrapped, "GINO_SANDBOX"), ["1"]);
        assert_eq!(
            env_values(&wrapped, "GINO_ARCHIVE_DIR"),
            [work_dir.join("conversations").as_os_str()]
        );
    }

    #[test]
    fn sandboxed_launch_drops_the_workspace_dir() {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("threads/t1");
        let mut d = direct(&work_dir.join("project"));
        d.env.push((
            "GINO_WORKSPACE_DIR".to_owned(),
            "/var/lib/gino-agent".into(),
        ));
        let off = IsolationSpec::default();
        let agent = Path::new("/opt/gino/gino-agent");

        let unwrapped = launch(d.clone(), &ctx(&off, None, Some(&work_dir), Some(agent))).unwrap();
        assert_eq!(
            env_values(&unwrapped, "GINO_WORKSPACE_DIR"),
            ["/var/lib/gino-agent"]
        );

        let wrapped = wrap(
            d,
            &ctx(&off, None, Some(&work_dir), Some(agent)),
            &sandboxed(),
            &host,
        )
        .unwrap();
        assert!(env_values(&wrapped, "GINO_WORKSPACE_DIR").is_empty());
        assert_eq!(env_values(&wrapped, "GINO_TASK_ID"), ["task-1"]);
    }

    #[test]
    fn sandboxed_launch_binds_the_agent_socket_and_rewrites_its_env() {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("threads/t1");
        let mut d = direct(&work_dir.join("project"));
        d.env.extend([
            ("GINO_AGENT_SOCK".to_owned(), "/ws/run/agent.sock".into()),
            ("GINO_AGENT_TOKEN".to_owned(), "tok".into()),
        ]);
        let off = IsolationSpec::default();
        let agent = Path::new("/opt/gino/gino-agent");
        let ctx = ctx(&off, None, Some(&work_dir), Some(agent));

        let unwrapped = launch(d.clone(), &ctx).unwrap();
        assert_eq!(
            env_values(&unwrapped, "GINO_AGENT_SOCK"),
            ["/ws/run/agent.sock"]
        );

        let wrapped = wrap(d, &ctx, &sandboxed(), &host).unwrap();
        assert_eq!(
            env_values(&wrapped, "GINO_AGENT_SOCK"),
            ["/run/gino/agent.sock"]
        );
        assert_eq!(env_values(&wrapped, "GINO_AGENT_TOKEN"), ["tok"]);
        let bind: [OsString; 3] =
            ["--bind", "/ws/run/agent.sock", "/run/gino/agent.sock"].map(OsString::from);
        assert_eq!(wrapped.args.windows(3).filter(|w| *w == bind).count(), 1);

        let wrapped = wrap(direct(&work_dir.join("project")), &ctx, &sandboxed(), &host).unwrap();
        assert!(env_values(&wrapped, "GINO_AGENT_SOCK").is_empty());
        assert!(!wrapped.args.iter().any(|a| a == "/run/gino/agent.sock"));
    }

    /// How often the `bind` triple occurs in `launch`'s argv.
    fn bind_count(launch: &Launch, bind: [&str; 3]) -> usize {
        let bind = bind.map(OsString::from);
        launch.args.windows(3).filter(|w| *w == bind).count()
    }

    const MEMORY_ENV: [&str; 3] = [
        "GINO_MEMORY_DIR",
        "GINO_AGENT_MEMORY_DIR",
        "GINO_CONVERSATIONS_DIR",
    ];

    #[test]
    fn sandboxed_launch_binds_the_memory_trees_and_rewrites_their_env() {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("threads/t1");
        let mut d = direct(&work_dir.join("project"));
        d.env.extend(
            MEMORY_ENV
                .into_iter()
                .zip(["/ws/memory/task/task-1", "/ws/memory/agent", "/stale"])
                .map(|(key, value)| (key.to_owned(), value.into())),
        );
        let off = IsolationSpec::default();
        let agent = Path::new("/opt/gino/gino-agent");
        let task_dir = Path::new("/ws/memory/task/task-1");
        let agent_dir = Path::new("/ws/memory/agent");

        for access in [AgentMemoryAccess::Rw, AgentMemoryAccess::Ro] {
            let mut ctx = ctx(&off, None, Some(&work_dir), Some(agent));
            ctx.memory_dir = Some(task_dir);
            ctx.agent_memory_dir = Some(agent_dir);
            ctx.agent_memory_access = access;
            let wrapped = wrap(d.clone(), &ctx, &sandboxed(), &host).unwrap();
            assert_eq!(
                env_values(&wrapped, "GINO_MEMORY_DIR"),
                ["/run/gino/memory/task"]
            );
            assert_eq!(
                env_values(&wrapped, "GINO_AGENT_MEMORY_DIR"),
                ["/run/gino/memory/agent"]
            );
            assert_eq!(
                bind_count(
                    &wrapped,
                    ["--bind", "/ws/memory/task/task-1", "/run/gino/memory/task"]
                ),
                1
            );
            let flag = if access == AgentMemoryAccess::Rw {
                "--bind"
            } else {
                "--ro-bind"
            };
            assert_eq!(
                bind_count(
                    &wrapped,
                    [flag, "/ws/memory/agent", "/run/gino/memory/agent"]
                ),
                1,
                "{access:?}"
            );
        }

        // Trees that are off are neither mounted nor named, even though the
        // direct launch named them.
        let mut ctx = ctx(&off, None, Some(&work_dir), Some(agent));
        ctx.agent_memory_access = AgentMemoryAccess::Off;
        let wrapped = wrap(d, &ctx, &sandboxed(), &host).unwrap();
        for key in MEMORY_ENV {
            assert!(env_values(&wrapped, key).is_empty(), "{key}");
        }
        assert!(
            !wrapped
                .args
                .iter()
                .any(|a| a.to_str().unwrap().starts_with("/run/gino/memory")
                    || a == "/run/gino/conversations")
        );
        assert!(wrapped.conversations.is_none());
    }

    /// The parsed value following `--settings` in `launch`'s argv.
    fn settings_arg(launch: &Launch) -> serde_json::Value {
        let i = launch.args.iter().position(|a| a == "--settings").unwrap();
        serde_json::from_str(launch.args[i + 1].to_str().unwrap()).unwrap()
    }

    #[test]
    fn sandboxed_launch_points_auto_memory_at_the_mounted_task_tree() {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("threads/t1");
        let hooks = serde_json::json!({
            "PreCompact": [{ "hooks": [{ "type": "command", "command": "/opt/gino/gino-agent archive" }] }],
        });
        let on = serde_json::json!({
            "autoMemoryDirectory": "/ws/memory/task/task-1/claude",
            "hooks": hooks,
        });
        let mut d = direct(&work_dir.join("project"));
        d.args = vec!["--settings".into(), on.to_string().into(), "-p".into()];
        let off = IsolationSpec::default();
        let agent = Path::new("/opt/gino/gino-agent");
        let mut ctx = ctx(&off, None, Some(&work_dir), Some(agent));
        ctx.memory_dir = Some(Path::new("/ws/memory/task/task-1"));

        let wrapped = wrap(d.clone(), &ctx, &sandboxed(), &host).unwrap();
        assert_eq!(
            settings_arg(&wrapped),
            serde_json::json!({
                "autoMemoryDirectory": "/run/gino/memory/task/claude",
                "hooks": hooks,
            })
        );
        assert!(!wrapped.args.iter().any(|a| {
            a.to_str()
                .unwrap()
                .contains("/ws/memory/task/task-1/claude")
        }));

        // Unsandboxed runs keep the host path.
        assert_eq!(launch(d.clone(), &ctx).unwrap(), d);

        // Without the mounted tree auto memory is switched off.
        ctx.memory_dir = None;
        let wrapped = wrap(d, &ctx, &sandboxed(), &host).unwrap();
        assert_eq!(
            settings_arg(&wrapped),
            serde_json::json!({ "autoMemoryEnabled": false, "hooks": hooks })
        );
    }

    #[test]
    fn sandboxed_launch_keeps_auto_memory_off_settings_as_they_are() {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("threads/t1");
        let settings = r#"{"autoMemoryEnabled":false}"#;
        let mut d = direct(&work_dir.join("project"));
        d.args = vec!["--settings".into(), settings.into()];
        d.env
            .push(("CLAUDE_CODE_DISABLE_AUTO_MEMORY".to_owned(), "1".into()));
        let off = IsolationSpec::default();
        let agent = Path::new("/opt/gino/gino-agent");
        for memory_dir in [Some(Path::new("/ws/memory/task/task-1")), None] {
            let mut ctx = ctx(&off, None, Some(&work_dir), Some(agent));
            ctx.memory_dir = memory_dir;
            let wrapped = wrap(d.clone(), &ctx, &sandboxed(), &host).unwrap();
            let i = wrapped.args.iter().position(|a| a == "--settings").unwrap();
            assert_eq!(wrapped.args[i + 1], settings);
            assert_eq!(
                env_values(&wrapped, "CLAUDE_CODE_DISABLE_AUTO_MEMORY"),
                ["1"]
            );
        }
    }

    #[test]
    fn task_memory_mounts_a_read_only_conversations_snapshot() {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("threads/t2");
        let earlier = tmp.path().join("threads/t1/conversations");
        std::fs::create_dir_all(&earlier).unwrap();
        std::fs::write(earlier.join("a.md"), "hello").unwrap();
        let archives = [earlier];
        let off = IsolationSpec::default();
        let mut ctx = ctx(
            &off,
            None,
            Some(&work_dir),
            Some(Path::new("/opt/gino/gino-agent")),
        );
        ctx.memory_dir = Some(Path::new("/ws/memory/task/task-1"));
        ctx.task_archives = &archives;
        let d = direct(&work_dir.join("project"));

        let wrapped = wrap(d.clone(), &ctx, &sandboxed(), &host).unwrap();
        let view = wrapped.conversations.as_deref().unwrap().0.clone();
        assert_eq!(
            std::fs::read_to_string(view.join("t1/a.md")).unwrap(),
            "hello"
        );
        let mode = std::fs::metadata(&view).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert_eq!(
            bind_count(
                &wrapped,
                [
                    "--ro-bind",
                    view.to_str().unwrap(),
                    "/run/gino/conversations"
                ]
            ),
            1
        );
        assert_eq!(
            env_values(&wrapped, "GINO_CONVERSATIONS_DIR"),
            ["/run/gino/conversations"]
        );
        assert_eq!(
            env_values(&wrapped, "GINO_ARCHIVE_DIR"),
            [work_dir.join("conversations").as_os_str()]
        );
        drop(wrapped);
        assert!(!view.exists());

        // Unsandboxed runs get no view.
        assert_eq!(launch(d.clone(), &ctx).unwrap(), d);

        ctx.memory_dir = None;
        let wrapped = wrap(d, &ctx, &sandboxed(), &host).unwrap();
        assert!(wrapped.conversations.is_none());
        assert!(env_values(&wrapped, "GINO_CONVERSATIONS_DIR").is_empty());
        assert!(!wrapped.args.iter().any(|a| a == "/run/gino/conversations"));
    }

    /// `<root>/threads/<thread>/conversations` holding `files` as
    /// `(name, content, mtime in seconds)`.
    fn archive(root: &Path, thread: &str, files: &[(&str, &str, u64)]) -> PathBuf {
        let dir = root.join("threads").join(thread).join("conversations");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content, mtime) in files {
            let path = dir.join(name);
            std::fs::write(&path, content).unwrap();
            std::fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(*mtime))
                .unwrap();
        }
        dir
    }

    /// Every file under `dir`, relative and sorted.
    fn listing(dir: &Path) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    out.push(path.strip_prefix(root).unwrap().display().to_string());
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

    #[test]
    fn snapshot_copies_only_top_level_regular_files() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let secret = root.join("secret");
        std::fs::create_dir(&secret).unwrap();
        std::fs::write(secret.join("key"), "s").unwrap();
        let t1 = archive(root, "t1", &[("a.md", "one", 10), ("index.json", "{}", 11)]);
        symlink(secret.join("key"), t1.join("link.md")).unwrap();
        std::fs::create_dir(t1.join("nested")).unwrap();
        std::fs::write(t1.join("nested/b.md"), "two").unwrap();
        let t2 = root.join("threads/t2/conversations");
        std::fs::create_dir_all(t2.parent().unwrap()).unwrap();
        symlink(&secret, &t2).unwrap();
        let missing = root.join("threads/t3/conversations");

        let dest = root.join("view");
        snapshot_archives(&[t1, t2, missing], &dest, DEFAULT_CONVERSATIONS_MAX_BYTES).unwrap();
        assert_eq!(listing(&dest), ["t1/a.md", "t1/index.json"]);
        assert_eq!(
            std::fs::read_to_string(dest.join("t1/a.md")).unwrap(),
            "one"
        );
    }

    #[test]
    fn snapshot_of_no_archives_is_an_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("view");
        snapshot_archives(&[], &dest, DEFAULT_CONVERSATIONS_MAX_BYTES).unwrap();
        assert!(dest.is_dir());
        assert!(listing(&dest).is_empty());
    }

    #[test]
    fn snapshot_keeps_the_newest_archives_within_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let archives = [
            archive(root, "t1", &[("x.md", "1111", 30)]),
            archive(root, "t2", &[("old.md", "2222", 1), ("new.md", "3333", 2)]),
        ];

        let dest = root.join("under");
        snapshot_archives(&archives, &dest, 12).unwrap();
        assert_eq!(listing(&dest), ["t1/x.md", "t2/new.md", "t2/old.md"]);

        let dest = root.join("ten");
        snapshot_archives(&archives, &dest, 10).unwrap();
        assert_eq!(listing(&dest), ["TRUNCATED.md", "t2/new.md", "t2/old.md"]);
        let note = std::fs::read_to_string(dest.join(TRUNCATED_NOTE)).unwrap();
        assert!(note.contains("10 bytes"), "{note}");
        assert!(note.contains("1 older archive file(s)"), "{note}");

        let dest = root.join("six");
        snapshot_archives(&archives, &dest, 6).unwrap();
        assert_eq!(listing(&dest), ["TRUNCATED.md", "t2/new.md"]);
        let note = std::fs::read_to_string(dest.join(TRUNCATED_NOTE)).unwrap();
        assert!(note.contains("2 older archive file(s)"), "{note}");
    }

    #[test]
    fn sandboxed_launch_without_a_cwd_runs_in_the_work_dir() {
        let (tmp, _, host) = stub_host();
        let work_dir = tmp.path().join("t1");
        let off = IsolationSpec::default();
        let wrapped = wrap(
            direct(Path::new("")),
            &ctx(
                &off,
                None,
                Some(&work_dir),
                Some(Path::new("/opt/gino-agent")),
            ),
            &sandboxed(),
            &host,
        )
        .unwrap();
        let chdir = wrapped.args.iter().position(|a| a == "--chdir").unwrap();
        assert_eq!(wrapped.args[chdir + 1], work_dir.as_os_str());
        assert!(wrapped.cwd.as_os_str().is_empty());
    }

    #[test]
    fn sandboxed_launch_needs_work_dir_agent_and_engine_binary() {
        let (tmp, _, mut host) = stub_host();
        let work_dir = tmp.path().join("t1");
        let agent = Path::new("/opt/gino-agent");
        let off = IsolationSpec::default();
        let err = wrap(
            direct(&work_dir),
            &ctx(&off, None, None, Some(agent)),
            &sandboxed(),
            &host,
        )
        .unwrap_err();
        assert!(
            matches!(err, EngineError::Isolation(IsolationError::Missing(_))),
            "{err:?}"
        );

        let err = wrap(
            direct(&work_dir),
            &ctx(&off, None, Some(&work_dir), None),
            &sandboxed(),
            &host,
        )
        .unwrap_err();
        assert!(
            matches!(err, EngineError::Isolation(IsolationError::Missing(_))),
            "{err:?}"
        );

        host.path_env = None;
        let err = wrap(
            direct(&work_dir),
            &ctx(&off, None, Some(&work_dir), Some(agent)),
            &sandboxed(),
            &host,
        )
        .unwrap_err();
        assert!(
            matches!(&err, EngineError::Spawn(e) if e.kind() == std::io::ErrorKind::NotFound),
            "{err:?}"
        );
        assert!(!work_dir.exists());
    }

    #[test]
    fn children_list_parsing() {
        assert_eq!(first_child("4242 4243 \n"), Some(4242));
        assert_eq!(first_child("17"), Some(17));
        assert_eq!(first_child(""), None);
        assert_eq!(first_child("x 1"), None);
    }

    #[test]
    fn stat_parsing_skips_odd_command_names() {
        assert_eq!(stat_ppid("123 (bwrap) S 100 123 123 0 -1"), Some(100));
        assert_eq!(stat_ppid("124 (a b) c) R 123 1 1"), Some(123));
        assert_eq!(stat_ppid("125 (x)"), None);
        assert_eq!(stat_ppid("garbage"), None);
    }

    #[test]
    fn sandbox_init_pid_finds_the_direct_child() {
        let mut parent = std::process::Command::new("sh")
            .args(["-c", "sleep 30 & wait"])
            .spawn()
            .unwrap();
        let parent_pid = i32::try_from(parent.id()).unwrap();
        let mut child = None;
        for _ in 0..200 {
            child = sandbox_init_pid(parent_pid);
            if child.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let child = child.unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{child}/stat")).unwrap();
        assert_eq!(stat_ppid(&stat), Some(parent_pid));
        let _ = std::process::Command::new("kill")
            .arg(child.to_string())
            .status();
        let _ = parent.kill();
        let _ = parent.wait();

        assert_eq!(sandbox_init_pid(i32::MAX), None);
    }

    fn host(raw: &str) -> IsolationSpec {
        serde_json::from_str(raw).unwrap()
    }

    fn modes(spec: &IsolationSpec) -> (Option<&str>, Option<&str>) {
        (spec.mode.as_deref(), super::network_mode(spec))
    }

    #[test]
    fn host_may_tighten_the_floor() {
        let floor = spec(Some("sandbox"), Some("full"));
        for (raw, expected) in [
            (r#"{ "network": { "mode": "allowlist" } }"#, "allowlist"),
            (r#"{ "network": { "mode": "none" } }"#, "none"),
            (
                r#"{ "mode": "sandbox", "network": { "mode": "full" } }"#,
                "full",
            ),
        ] {
            let (effective, ignored) = tighten_floor(&floor, host(raw));
            assert_eq!(
                modes(&effective),
                (Some("sandbox"), Some(expected)),
                "{raw}"
            );
            assert!(ignored.is_empty(), "{raw}");
        }
        let (effective, ignored) = tighten_floor(
            &spec(Some("sandbox"), Some("allowlist")),
            host(r#"{ "network": { "mode": "none" } }"#),
        );
        assert_eq!(modes(&effective), (Some("sandbox"), Some("none")));
        assert!(ignored.is_empty());
    }

    #[test]
    fn host_may_turn_an_off_floor_into_a_sandbox() {
        for floor in [IsolationSpec::default(), spec(Some("off"), Some("none"))] {
            let (effective, ignored) = tighten_floor(
                &floor,
                host(r#"{ "mode": "sandbox", "network": { "mode": "full" } }"#),
            );
            assert_eq!(modes(&effective), (Some("sandbox"), Some("full")));
            assert!(ignored.is_empty());
        }
    }

    #[test]
    fn host_loosening_is_ignored() {
        for (floor, raw, field) in [
            (spec(Some("sandbox"), None), r#"{ "mode": "off" }"#, "mode"),
            (
                spec(Some("sandbox"), None),
                r#"{ "network": { "mode": "allowlist" } }"#,
                "network.mode",
            ),
            (
                spec(Some("sandbox"), Some("none")),
                r#"{ "network": { "mode": "full" } }"#,
                "network.mode",
            ),
            (
                spec(Some("sandbox"), Some("allowlist")),
                r#"{ "network": { "mode": "full" } }"#,
                "network.mode",
            ),
            (spec(Some("sandbox"), None), r#"{ "mode": "jail" }"#, "mode"),
            (
                spec(Some("sandbox"), Some("full")),
                r#"{ "network": { "mode": "open" } }"#,
                "network.mode",
            ),
        ] {
            let (effective, ignored) = tighten_floor(&floor, host(raw));
            assert_eq!(effective, floor, "{raw}");
            assert_eq!(ignored, [field], "{raw}");
        }
    }

    #[test]
    fn host_paths_rules_and_override_flag_are_ignored() {
        let floor = with_rules(
            with_paths(spec(Some("sandbox"), Some("allowlist")), &["/data/ro"], &[]),
            r#"[{ "host": "*.pypi.org", "ports": [443] }]"#,
        );
        let (effective, ignored) = tighten_floor(
            &floor,
            host(
                r#"{ "network": { "mode": "none", "allow": [{ "host": "evil.example", "ports": "*" }] },
                     "readPaths": ["/etc"], "writePaths": ["/srv"], "allowTaskOverride": true }"#,
            ),
        );
        assert_eq!(
            ignored,
            [
                "network.allow",
                "readPaths",
                "writePaths",
                "allowTaskOverride"
            ]
        );
        assert_eq!(modes(&effective), (Some("sandbox"), Some("none")));
        assert_eq!(effective.read_paths, floor.read_paths);
        assert_eq!(effective.write_paths, floor.write_paths);
        assert_eq!(effective.allow_task_override, None);
        assert_eq!(
            effective.network.as_ref().unwrap().allow,
            floor.network.as_ref().unwrap().allow
        );
    }

    #[test]
    fn task_meta_applies_on_top_of_floor_and_host() {
        let floor = with_rules(
            spec(Some("sandbox"), Some("full")),
            r#"[{ "host": "*.pypi.org", "ports": [443] }]"#,
        );
        let (effective, _) =
            tighten_floor(&floor, host(r#"{ "network": { "mode": "allowlist" } }"#));

        // Loosening the host-tightened default is refused.
        assert_loosens(
            &effective,
            &spec(None, Some("full")),
            "isolation.network.mode",
            "allowlist",
            "full",
        );
        // The file rules plus the LLM endpoint make up the run's allowlist.
        let iso = run(&effective, None).unwrap();
        let rules = allowlist_of(&iso);
        assert!(allows(rules, "files.pypi.org", 443));
        assert!(allows(rules, "api.anthropic.com", 443));
        assert!(!allows(rules, "example.com", 443));
        // Tightening still works.
        let iso = run(&effective, Some(&spec(None, Some("none")))).unwrap();
        assert_eq!(iso.network, NetworkMode::None);

        // allowTaskOverride from the floor still lets a task loosen.
        let (effective, _) = tighten_floor(
            &allowing(floor),
            host(r#"{ "network": { "mode": "none" } }"#),
        );
        let iso = run(&effective, Some(&spec(None, Some("full")))).unwrap();
        assert_eq!(iso.network, NetworkMode::Full);
    }

    #[test]
    fn floor_validation() {
        let workspace = Path::new(WORKSPACE);
        validate_floor(&IsolationSpec::default(), workspace).unwrap();
        validate_floor(
            &with_rules(
                with_paths(
                    spec(Some("sandbox"), Some("allowlist")),
                    &["/data/ro"],
                    &["/data/rw"],
                ),
                r#"[{ "host": "*.pypi.org", "ports": [443] }]"#,
            ),
            workspace,
        )
        .unwrap();

        let err = |floor: IsolationSpec| validate_floor(&floor, workspace).unwrap_err();
        assert!(
            matches!(err(spec(Some("jail"), None)), IsolationError::UnknownMode(m) if m == "jail")
        );
        assert!(matches!(
            err(spec(Some("vm"), None)),
            IsolationError::InvalidVm(_)
        ));
        validate_floor(&with_vm(spec(Some("vm"), Some("allowlist"))), workspace).unwrap();
        validate_floor(&with_vm(spec(Some("sandbox"), None)), workspace).unwrap();
        let mut bad_vm = with_vm(spec(Some("vm"), None));
        bad_vm.vm.as_mut().unwrap().vcpus = 0;
        assert!(matches!(err(bad_vm), IsolationError::InvalidVm(_)));
        assert!(matches!(
            err(spec(Some("sandbox"), Some("open"))),
            IsolationError::UnknownNetworkMode(m) if m == "open"
        ));
        assert!(matches!(
            err(with_paths(spec(None, None), &["data/ro"], &[])),
            IsolationError::InvalidPath {
                reason: "not absolute",
                ..
            }
        ));
        assert!(matches!(
            err(with_paths(spec(None, None), &[], &[WORKSPACE])),
            IsolationError::InvalidPath { .. }
        ));
        // Rules are checked whatever the network mode.
        assert!(matches!(
            err(with_rules(
                spec(Some("sandbox"), Some("full")),
                r#"[{ "host": "ok.example", "ports": "*" }, { "host": "bad host", "ports": "*" }]"#,
            )),
            IsolationError::InvalidAllowlist(RuleError::Host { index: 1, .. })
        ));
    }

    #[test]
    fn host_may_select_vm_but_never_set_the_vm_block() {
        let floor = with_vm(spec(Some("sandbox"), Some("allowlist")));
        let (effective, ignored) = tighten_floor(
            &floor,
            host(
                r#"{ "mode": "vm", "network": { "mode": "none" },
                     "vm": { "kernel": "/evil/k", "rootfs": "/evil/r", "vmm": "/evil/v" } }"#,
            ),
        );
        assert_eq!(modes(&effective), (Some("vm"), Some("none")));
        assert_eq!(effective.vm, floor.vm);
        assert_eq!(ignored, ["vm"]);

        // The host never picks the disk scope.
        let (effective, ignored) = tighten_floor(&floor, host(r#"{ "vmDisk": "task" }"#));
        assert_eq!(effective.vm_disk, None);
        assert_eq!(ignored, ["vmDisk"]);

        // vm -> sandbox loosens the floor and is ignored.
        let floor = with_vm(spec(Some("vm"), None));
        let (effective, ignored) = tighten_floor(&floor, host(r#"{ "mode": "sandbox" }"#));
        assert_eq!(effective, floor);
        assert_eq!(ignored, ["mode"]);
    }
}
