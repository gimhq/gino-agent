//! Bubblewrap launcher for sandboxed engine runs.
//!
//! [`bwrap_args`] is a pure argv builder over a [`SandboxLayout`] and a
//! [`HostRoot`] snapshot; [`host_root`] and [`ensure_available`] are the only
//! parts that look at the real host.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::{
    AGENT_MEMORY_MOUNT, CONVERSATIONS_MOUNT, IsolationError, NetworkMode, TASK_MEMORY_MOUNT,
};
use crate::provisioning::store::store_dir;

/// Host root entries that are mirrored into the sandbox, in argv order.
const ROOT_DIRS: [&str; 4] = ["/bin", "/lib", "/lib64", "/sbin"];

/// How long the availability probe may run before it counts as failed.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bytes of probe stderr kept in the error detail.
const STDERR_TAIL: usize = 512;

/// In-sandbox path of the allowlist control socket.
pub(crate) const CTL_SOCK: &str = "/run/gino/ctl.sock";

/// In-sandbox path of the daemon's local agent API socket.
pub(crate) const AGENT_SOCK: &str = "/run/gino/agent.sock";

/// Control socket file name in the per-run network dir.
pub(crate) const CTL_SOCK_NAME: &str = "ctl.sock";

/// `resolv.conf` file name in the per-run network dir.
pub(crate) const RESOLV_CONF_NAME: &str = "resolv.conf";

/// Shape of one host root entry such as `/bin`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RootEntry {
    /// A symlink, with its raw (unresolved) target.
    Symlink(PathBuf),
    /// A real directory.
    Dir,
    /// Missing, or something else.
    Absent,
}

/// Snapshot of the host's root layout that the sandbox mirrors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostRoot {
    /// `/bin`, `/lib`, `/lib64`, `/sbin`, in [`ROOT_DIRS`] order.
    pub(crate) entries: [RootEntry; 4],
    /// Where `/etc/resolv.conf` resolves to, when that is outside `/etc`.
    pub(crate) resolv_conf_outside_etc: Option<PathBuf>,
}

/// One global skill entry, bound at `<engine_home>/skills/<name>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SkillBind {
    /// Entry name under `<global>/skills`.
    pub(crate) name: OsString,
    /// Canonical target of the entry (symlinks followed).
    pub(crate) source: PathBuf,
    /// Whether `source` is a directory (otherwise a file).
    pub(crate) is_dir: bool,
}

/// Which provisioning globals exist under the global config dir.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProvisionedGlobals {
    /// `<global>/CLAUDE.md` is a file.
    pub(crate) claude_md: bool,
    /// Resolved `<global>/skills` entries, sorted by name; dangling ones skipped.
    pub(crate) skills: Vec<SkillBind>,
}

impl ProvisionedGlobals {
    /// Inspect `global_config_dir` on the host.
    pub(crate) fn inspect(global_config_dir: Option<&Path>) -> Self {
        global_config_dir.map_or_else(Self::default, |dir| Self {
            claude_md: dir.join("CLAUDE.md").is_file(),
            skills: inspect_skills(&dir.join("skills")),
        })
    }
}

/// Resolve every entry of `skills_dir` to its canonical file or dir target.
fn inspect_skills(skills_dir: &Path) -> Vec<SkillBind> {
    let Ok(entries) = fs::read_dir(skills_dir) else {
        return Vec::new();
    };
    let mut skills: Vec<SkillBind> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let source = fs::canonicalize(entry.path()).ok()?;
            let meta = fs::metadata(&source).ok()?;
            (meta.is_dir() || meta.is_file()).then(|| SkillBind {
                name: entry.file_name(),
                source,
                is_dir: meta.is_dir(),
            })
        })
        .collect();
    skills.sort_by(|a, b| a.name.cmp(&b.name));
    skills
}

/// A task-scope store entry, mounted read-only where its link points.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EntryBind {
    /// Canonical store entry.
    pub(crate) source: PathBuf,
    /// The link's absolute target.
    pub(crate) dest: PathBuf,
}

/// Store entries the links under `<work_dir>/project` point at, sorted. Only
/// links with a plain absolute target resolving inside the workspace store
/// count; `project/workspace` is not scanned.
pub(crate) fn inspect_task_entries(work_dir: &Path, workspace_dir: &Path) -> Vec<EntryBind> {
    let Ok(store) = fs::canonicalize(store_dir(workspace_dir)) else {
        return Vec::new();
    };
    let project_dir = work_dir.join("project");
    let workspace = project_dir.join("workspace");
    let mut binds = Vec::new();
    let mut pending = vec![project_dir];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() && path != workspace => pending.push(path),
                Ok(kind) if kind.is_symlink() => binds.extend(entry_bind(&path, &store)),
                _ => {}
            }
        }
    }
    binds.sort();
    binds.dedup();
    binds
}

fn entry_bind(link: &Path, store: &Path) -> Option<EntryBind> {
    let dest = fs::read_link(link).ok()?;
    let plain = dest.is_absolute()
        && dest
            .components()
            .skip(1)
            .all(|c| matches!(c, Component::Normal(_)));
    let source = fs::canonicalize(&dest).ok()?;
    (plain && source.starts_with(store)).then_some(EntryBind { source, dest })
}

/// Everything the sandbox mounts for one engine run (all paths absolute).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SandboxLayout {
    /// This thread's work dir, mounted read-write.
    pub(crate) work_dir: PathBuf,
    /// Engine cwd, inside `work_dir`.
    pub(crate) cwd: PathBuf,
    /// Per-thread engine home, `engine_home(work_dir)`.
    pub(crate) engine_home: PathBuf,
    /// Provisioning dir holding the global `CLAUDE.md` and `skills/`.
    pub(crate) global_config_dir: Option<PathBuf>,
    /// Which globals exist under `global_config_dir`.
    pub(crate) globals: ProvisionedGlobals,
    /// Canonical engine binary.
    pub(crate) engine_binary: PathBuf,
    /// The gino-agent binary, run inside as `sandbox-init`.
    pub(crate) agent_exe: PathBuf,
    /// Sandbox `$HOME` (a tmpfs).
    pub(crate) home: PathBuf,
    pub(crate) network: NetworkMode,
    /// Extra host paths mounted read-only.
    pub(crate) read_paths: Vec<PathBuf>,
    /// Extra host paths mounted read-write.
    pub(crate) write_paths: Vec<PathBuf>,
    /// Store entries behind the task-scope links in the work dir.
    pub(crate) task_entries: Vec<EntryBind>,
    /// Per-run daemon dir holding the control socket and `resolv.conf`; set
    /// in allowlist mode.
    pub(crate) net_dir: Option<PathBuf>,
    /// Host path of the daemon's agent API socket, bound read-write at
    /// `AGENT_SOCK`.
    pub(crate) agent_sock: Option<PathBuf>,
    /// Host task memory dir, bound read-write at `TASK_MEMORY_MOUNT`.
    pub(crate) memory_dir: Option<PathBuf>,
    /// Host agent memory dir, bound at `AGENT_MEMORY_MOUNT`.
    pub(crate) agent_memory_dir: Option<PathBuf>,
    /// Whether `agent_memory_dir` is bound read-write rather than read-only.
    pub(crate) agent_memory_writable: bool,
    /// Per-run conversations view, bound read-only at `CONVERSATIONS_MOUNT`.
    pub(crate) conversations_dir: Option<PathBuf>,
}

impl SandboxLayout {
    /// Global `CLAUDE.md` bind source, when it will be mounted.
    fn global_claude_md(&self) -> Option<PathBuf> {
        self.global_config_dir
            .as_ref()
            .filter(|_| self.globals.claude_md)
            .map(|dir| dir.join("CLAUDE.md"))
    }

    /// Global skill binds, empty when no global config dir is set.
    fn global_skills(&self) -> &[SkillBind] {
        if self.global_config_dir.is_some() {
            &self.globals.skills
        } else {
            &[]
        }
    }
}

/// Per-thread engine home: `<work_dir>/.engine-home`.
pub(crate) fn engine_home(work_dir: &Path) -> PathBuf {
    work_dir.join(".engine-home")
}

/// Inspect the host's `/bin` `/lib` `/lib64` `/sbin` and `/etc/resolv.conf`.
pub(crate) fn host_root() -> HostRoot {
    let entries = ROOT_DIRS.map(|dir| match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::read_link(dir).map_or(RootEntry::Absent, RootEntry::Symlink)
        }
        Ok(meta) if meta.is_dir() => RootEntry::Dir,
        _ => RootEntry::Absent,
    });
    let resolv = Path::new("/etc/resolv.conf");
    let resolv_conf_outside_etc = fs::symlink_metadata(resolv)
        .ok()
        .filter(|meta| meta.file_type().is_symlink())
        .and_then(|_| fs::canonicalize(resolv).ok())
        .filter(|target| !target.starts_with("/etc"));
    HostRoot {
        entries,
        resolv_conf_outside_etc,
    }
}

fn push(args: &mut Vec<OsString>, items: &[&OsStr]) {
    args.extend(items.iter().map(|s| (*s).to_owned()));
}

fn ro_bind(args: &mut Vec<OsString>, path: &Path) {
    push(
        args,
        &["--ro-bind".as_ref(), path.as_os_str(), path.as_os_str()],
    );
}

fn rw_bind(args: &mut Vec<OsString>, path: &Path) {
    push(
        args,
        &["--bind".as_ref(), path.as_os_str(), path.as_os_str()],
    );
}

fn push_task_entries(args: &mut Vec<OsString>, layout: &SandboxLayout) {
    for entry in &layout.task_entries {
        push(
            args,
            &[
                "--ro-bind".as_ref(),
                entry.source.as_os_str(),
                entry.dest.as_os_str(),
            ],
        );
    }
}

/// Mirror `/usr` and the `/bin`-style root entries.
fn push_root(args: &mut Vec<OsString>, host: &HostRoot) {
    ro_bind(args, Path::new("/usr"));
    for (dir, entry) in ROOT_DIRS.iter().zip(&host.entries) {
        match entry {
            RootEntry::Symlink(target) => {
                push(
                    args,
                    &["--symlink".as_ref(), target.as_os_str(), dir.as_ref()],
                );
            }
            RootEntry::Dir => ro_bind(args, Path::new(dir)),
            RootEntry::Absent => {}
        }
    }
}

/// Top-level dirs under the writable `/tmp` and `$HOME` tmpfs mounts that only
/// hold the parents of bind targets; each gets its own tmpfs, remounted
/// read-only after the binds so those parents are not writable.
fn tmpfs_shadows(layout: &SandboxLayout) -> Vec<PathBuf> {
    let roots = [Path::new("/tmp"), layout.home.as_path()];
    let targets: Vec<&Path> = std::iter::once(layout.work_dir.as_path())
        .chain(layout.read_paths.iter().map(PathBuf::as_path))
        .chain(layout.write_paths.iter().map(PathBuf::as_path))
        .chain(layout.task_entries.iter().map(|entry| entry.dest.as_path()))
        .collect();
    let mut shadows: Vec<PathBuf> = targets
        .iter()
        .flat_map(|target| {
            roots.iter().filter_map(|root| {
                let first = target.strip_prefix(root).ok()?.components().next()?;
                Some(root.join(first))
            })
        })
        .filter(|shadow| !roots.contains(&shadow.as_path()) && !targets.contains(&shadow.as_path()))
        .collect();
    shadows.sort();
    shadows.dedup();
    shadows
}

/// Let sandbox-init create the guest TUN device it hands to the daemon.
fn push_tun(args: &mut Vec<OsString>) {
    push(
        args,
        &[
            "--cap-add".as_ref(),
            "CAP_NET_ADMIN".as_ref(),
            "--dev-bind".as_ref(),
            "/dev/net/tun".as_ref(),
            "/dev/net/tun".as_ref(),
        ],
    );
}

/// Bind the per-run `resolv.conf` and control socket from `net_dir`. The
/// former lands where `/etc/resolv.conf` resolves, so a symlink out of /etc
/// still reaches it.
fn push_net_binds(args: &mut Vec<OsString>, net_dir: &Path, host: &HostRoot) {
    let resolv = host
        .resolv_conf_outside_etc
        .as_deref()
        .unwrap_or(Path::new("/etc/resolv.conf"));
    let resolv_src = net_dir.join(RESOLV_CONF_NAME);
    let ctl_src = net_dir.join(CTL_SOCK_NAME);
    push(
        args,
        &[
            "--ro-bind".as_ref(),
            resolv_src.as_os_str(),
            resolv.as_os_str(),
            "--bind".as_ref(),
            ctl_src.as_os_str(),
            CTL_SOCK.as_ref(),
        ],
    );
}

/// Bind the memory trees and the conversations view at their fixed paths.
fn push_memory_binds(args: &mut Vec<OsString>, layout: &SandboxLayout) {
    if let Some(dir) = &layout.memory_dir {
        push(
            args,
            &[
                "--bind".as_ref(),
                dir.as_os_str(),
                TASK_MEMORY_MOUNT.as_ref(),
            ],
        );
    }
    if let Some(dir) = &layout.agent_memory_dir {
        let flag = if layout.agent_memory_writable {
            "--bind"
        } else {
            "--ro-bind"
        };
        push(
            args,
            &[flag.as_ref(), dir.as_os_str(), AGENT_MEMORY_MOUNT.as_ref()],
        );
    }
    if let Some(dir) = &layout.conversations_dir {
        push(
            args,
            &[
                "--ro-bind".as_ref(),
                dir.as_os_str(),
                CONVERSATIONS_MOUNT.as_ref(),
            ],
        );
    }
}

/// Build the full `bwrap` argv (without the program) that runs `inner`.
pub(crate) fn bwrap_args(
    layout: &SandboxLayout,
    host: &HostRoot,
    inner: &[OsString],
) -> Vec<OsString> {
    let mut args = Vec::new();
    push(&mut args, &["--unshare-all".as_ref()]);
    if layout.network == NetworkMode::Full {
        push(&mut args, &["--share-net".as_ref()]);
    }
    push(
        &mut args,
        &[
            "--uid".as_ref(),
            "0".as_ref(),
            "--gid".as_ref(),
            "0".as_ref(),
            // Lets sandbox-init map its nested user namespace onto uid 0; it
            // drops every capability before the engine starts.
            "--cap-add".as_ref(),
            "CAP_SETFCAP".as_ref(),
            "--die-with-parent".as_ref(),
            "--new-session".as_ref(),
            "--as-pid-1".as_ref(),
            "--proc".as_ref(),
            "/proc".as_ref(),
            "--dev".as_ref(),
            "/dev".as_ref(),
            "--tmpfs".as_ref(),
            "/tmp".as_ref(),
            "--tmpfs".as_ref(),
            layout.home.as_os_str(),
        ],
    );
    if layout.net_dir.is_some() {
        push_tun(&mut args);
    }
    let shadows = tmpfs_shadows(layout);
    for shadow in &shadows {
        push(&mut args, &["--tmpfs".as_ref(), shadow.as_os_str()]);
    }

    push_root(&mut args, host);
    ro_bind(&mut args, Path::new("/etc"));
    if layout.network == NetworkMode::Full
        && let Some(resolved) = &host.resolv_conf_outside_etc
    {
        ro_bind(&mut args, resolved);
    }
    if let Some(net_dir) = &layout.net_dir {
        push_net_binds(&mut args, net_dir, host);
    }

    if let Some(install_dir) = layout.engine_binary.parent()
        && !install_dir.starts_with("/usr")
    {
        ro_bind(&mut args, install_dir);
    }
    if !layout.agent_exe.starts_with("/usr") {
        ro_bind(&mut args, &layout.agent_exe);
    }

    for path in &layout.read_paths {
        ro_bind(&mut args, path);
    }
    rw_bind(&mut args, &layout.work_dir);
    for path in &layout.write_paths {
        rw_bind(&mut args, path);
    }
    push_task_entries(&mut args, layout);
    if let Some(sock) = &layout.agent_sock {
        push(
            &mut args,
            &["--bind".as_ref(), sock.as_os_str(), AGENT_SOCK.as_ref()],
        );
    }
    push_memory_binds(&mut args, layout);

    if let Some(src) = layout.global_claude_md() {
        let dest = layout.engine_home.join("CLAUDE.md");
        push(
            &mut args,
            &["--ro-bind".as_ref(), src.as_os_str(), dest.as_os_str()],
        );
    }
    let skills_dir = layout.engine_home.join("skills");
    if !layout.global_skills().is_empty() {
        ro_bind(&mut args, &skills_dir);
    }
    for skill in layout.global_skills() {
        let dest = skills_dir.join(&skill.name);
        push(
            &mut args,
            &[
                "--ro-bind".as_ref(),
                skill.source.as_os_str(),
                dest.as_os_str(),
            ],
        );
    }

    // Everything outside the writable mounts above is read-only.
    push(&mut args, &["--remount-ro".as_ref(), "/".as_ref()]);
    for shadow in &shadows {
        push(&mut args, &["--remount-ro".as_ref(), shadow.as_os_str()]);
    }

    push(
        &mut args,
        &["--chdir".as_ref(), layout.cwd.as_os_str(), "--".as_ref()],
    );
    args.extend(inner.iter().cloned());
    args
}

/// Create the engine home and the mount targets for the globals bound into it.
pub(crate) fn prepare_engine_home(layout: &SandboxLayout) -> std::io::Result<()> {
    fs::create_dir_all(&layout.engine_home)?;
    if layout.global_claude_md().is_some() {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(layout.engine_home.join("CLAUDE.md"))?;
    }
    let skills = layout.global_skills();
    if !skills.is_empty() {
        let skills_dir = layout.engine_home.join("skills");
        fs::create_dir_all(&skills_dir)?;
        for skill in skills {
            let target = skills_dir.join(&skill.name);
            if skill.is_dir {
                fs::create_dir_all(&target)?;
            } else {
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&target)?;
            }
        }
    }
    Ok(())
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Resolve `binary` to a canonical path: paths with a slash directly, bare
/// names via the first executable match on `path_env`.
pub(crate) fn resolve_binary(binary: &Path, path_env: Option<&OsStr>) -> Option<PathBuf> {
    if binary.components().count() > 1 || binary.is_absolute() {
        return fs::canonicalize(binary).ok();
    }
    std::env::split_paths(path_env?)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(binary))
        .find(|candidate| is_executable_file(candidate))
        .and_then(|found| fs::canonicalize(found).ok())
}

/// Argv (without the program) of the availability probe.
fn probe_args(host: &HostRoot) -> Vec<OsString> {
    let mut args = Vec::new();
    push(
        &mut args,
        &["--unshare-all".as_ref(), "--die-with-parent".as_ref()],
    );
    push_root(&mut args, host);
    push(
        &mut args,
        &[
            "--proc".as_ref(),
            "/proc".as_ref(),
            "--dev".as_ref(),
            "/dev".as_ref(),
            "--".as_ref(),
            "/usr/bin/true".as_ref(),
        ],
    );
    args
}

/// Last [`STDERR_TAIL`] bytes of `stderr`, lossily decoded and trimmed.
fn stderr_tail(stderr: &[u8]) -> String {
    let start = stderr.len().saturating_sub(STDERR_TAIL);
    String::from_utf8_lossy(&stderr[start..]).trim().to_owned()
}

/// Run the probe once; resolves `bwrap` on `path_env`.
fn probe(path_env: Option<&OsStr>, host: &HostRoot) -> Result<PathBuf, String> {
    let bwrap = resolve_binary(Path::new("bwrap"), path_env)
        .ok_or_else(|| "bwrap not found on PATH".to_owned())?;
    let mut child = Command::new(&bwrap)
        .args(probe_args(host))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to run {}: {e}", bwrap.display()))?;

    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "bwrap probe timed out after {}s",
                    PROBE_TIMEOUT.as_secs()
                ));
            }
            Err(e) => return Err(format!("failed to wait for bwrap probe: {e}")),
        }
    };
    if status.success() {
        return Ok(bwrap);
    }
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_end(&mut stderr);
    }
    Err(format!(
        "bwrap probe failed ({status}): {}",
        stderr_tail(&stderr)
    ))
}

/// Resolve and probe `bwrap` once per process; the outcome is cached.
pub(crate) fn ensure_available() -> Result<PathBuf, IsolationError> {
    static PROBE: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    PROBE
        .get_or_init(|| probe(std::env::var_os("PATH").as_deref(), &host_root()))
        .clone()
        .map_err(IsolationError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    use super::{
        EntryBind, HostRoot, ProvisionedGlobals, ROOT_DIRS, RootEntry, SandboxLayout, SkillBind,
        bwrap_args, engine_home, ensure_available, host_root, inspect_task_entries,
        prepare_engine_home, probe, probe_args, resolve_binary,
    };
    use crate::sandbox::NetworkMode;

    fn host() -> HostRoot {
        HostRoot {
            entries: [
                RootEntry::Symlink("usr/bin".into()),
                RootEntry::Dir,
                RootEntry::Absent,
                RootEntry::Symlink("usr/sbin".into()),
            ],
            resolv_conf_outside_etc: Some("/run/systemd/resolve/stub-resolv.conf".into()),
        }
    }

    fn skills() -> Vec<SkillBind> {
        vec![
            SkillBind {
                name: "alpha".into(),
                source: "/ws/store/alpha/h1".into(),
                is_dir: true,
            },
            SkillBind {
                name: "beta.md".into(),
                source: "/ws/store/beta.md/h2".into(),
                is_dir: false,
            },
        ]
    }

    fn layout() -> SandboxLayout {
        let work_dir = PathBuf::from("/ws/threads/t1");
        SandboxLayout {
            cwd: work_dir.join("repo"),
            engine_home: engine_home(&work_dir),
            work_dir,
            global_config_dir: Some("/ws/global".into()),
            globals: ProvisionedGlobals {
                claude_md: true,
                skills: skills(),
            },
            engine_binary: "/opt/claude/bin/claude".into(),
            agent_exe: "/opt/gino/gino-agent".into(),
            home: "/home/sandbox".into(),
            network: NetworkMode::None,
            read_paths: vec!["/data/ro1".into(), "/data/ro2".into()],
            write_paths: vec!["/data/rw1".into()],
            task_entries: Vec::new(),
            net_dir: None,
            agent_sock: None,
            memory_dir: None,
            agent_memory_dir: None,
            agent_memory_writable: false,
            conversations_dir: None,
        }
    }

    fn inner() -> Vec<OsString> {
        ["/opt/gino/gino-agent", "sandbox-init", "--", "claude", "-p"]
            .map(OsString::from)
            .to_vec()
    }

    fn args(layout: &SandboxLayout, host: &HostRoot) -> Vec<String> {
        bwrap_args(layout, host, &inner())
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect()
    }

    /// Index of the first occurrence of the `window` sequence.
    fn find(args: &[String], window: &[&str]) -> Option<usize> {
        args.windows(window.len())
            .position(|w| w.iter().zip(window).all(|(a, b)| a == b))
    }

    fn pos(args: &[String], window: &[&str]) -> usize {
        find(args, window).unwrap_or_else(|| panic!("{window:?} not in {args:?}"))
    }

    #[test]
    fn engine_home_is_under_the_work_dir() {
        assert_eq!(
            engine_home(Path::new("/ws/threads/t1")),
            Path::new("/ws/threads/t1/.engine-home")
        );
    }

    #[test]
    fn process_and_namespace_flags_lead() {
        let a = args(&layout(), &host());
        assert_eq!(
            a[..15],
            [
                "--unshare-all",
                "--uid",
                "0",
                "--gid",
                "0",
                "--cap-add",
                "CAP_SETFCAP",
                "--die-with-parent",
                "--new-session",
                "--as-pid-1",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
            ]
        );
        assert!(!a.iter().any(|x| x == "--share-net" || x == "--unshare-net"));
        assert_eq!(a.iter().filter(|x| *x == "--cap-add").count(), 1);
    }

    #[test]
    fn no_network_skips_share_net_and_resolv_conf() {
        let a = args(&layout(), &host());
        assert!(!a.iter().any(|x| x == "--share-net"));
        assert!(!a.iter().any(|x| x.contains("resolv")));
    }

    #[test]
    fn full_network_shares_net_and_binds_resolv_conf_outside_etc() {
        let mut l = layout();
        l.network = NetworkMode::Full;
        let a = args(&l, &host());
        assert_eq!(a[..2], ["--unshare-all", "--share-net"]);
        assert!(!a.iter().any(|x| x == "--unshare-net"));
        let resolv = "/run/systemd/resolve/stub-resolv.conf";
        pos(&a, &["--ro-bind", resolv, resolv]);
        // The resolved file is the only thing under /run.
        assert_eq!(a.iter().filter(|x| x.starts_with("/run")).count(), 2);

        let mut h = host();
        h.resolv_conf_outside_etc = None;
        let a = args(&l, &h);
        assert!(!a.iter().any(|x| x.contains("resolv")));
    }

    /// `args` with every occurrence of each `window` removed.
    fn without(args: &[String], windows: &[&[&str]]) -> Vec<String> {
        let mut out = args.to_vec();
        for window in windows {
            while let Some(at) = find(&out, window) {
                out.drain(at..at + window.len());
            }
        }
        out
    }

    #[test]
    fn allowlist_adds_exactly_the_tun_resolv_and_control_socket_binds() {
        let mut l = layout();
        l.network = NetworkMode::Allowlist;
        l.net_dir = Some("/tmp/gino-net-x".into());
        let mut h = host();
        h.resolv_conf_outside_etc = None;
        let a = args(&l, &h);
        let added: [&[&str]; 4] = [
            &["--cap-add", "CAP_NET_ADMIN"],
            &["--dev-bind", "/dev/net/tun", "/dev/net/tun"],
            &[
                "--ro-bind",
                "/tmp/gino-net-x/resolv.conf",
                "/etc/resolv.conf",
            ],
            &["--bind", "/tmp/gino-net-x/ctl.sock", "/run/gino/ctl.sock"],
        ];
        for window in added {
            assert_eq!(a.windows(window.len()).filter(|w| *w == window).count(), 1);
        }
        // Own network namespace, devices after `--dev`, binds after /etc.
        assert!(!a.iter().any(|x| x == "--share-net"));
        assert!(pos(&a, &["--dev", "/dev"]) < pos(&a, added[1]));
        assert!(pos(&a, &["--ro-bind", "/etc", "/etc"]) < pos(&a, added[2]));
        assert!(pos(&a, added[3]) < pos(&a, &["--remount-ro", "/"]));
        assert_eq!(a.iter().filter(|x| *x == "--cap-add").count(), 2);

        let mut none = layout();
        none.network = NetworkMode::None;
        assert_eq!(without(&a, &added), args(&none, &h));
    }

    #[test]
    fn allowlist_resolv_conf_lands_on_a_target_outside_etc() {
        let mut l = layout();
        l.network = NetworkMode::Allowlist;
        l.net_dir = Some("/tmp/gino-net-x".into());
        let a = args(&l, &host());
        pos(
            &a,
            &[
                "--ro-bind",
                "/tmp/gino-net-x/resolv.conf",
                "/run/systemd/resolve/stub-resolv.conf",
            ],
        );
        assert!(!a.iter().any(|x| x == "/etc/resolv.conf"));
        // The host's own resolver file is not mounted.
        assert!(
            find(
                &a,
                &[
                    "--ro-bind",
                    "/run/systemd/resolve/stub-resolv.conf",
                    "/run/systemd/resolve/stub-resolv.conf"
                ]
            )
            .is_none()
        );
    }

    #[test]
    fn root_entries_follow_the_host_shape() {
        let a = args(&layout(), &host());
        pos(&a, &["--symlink", "usr/bin", "/bin"]);
        pos(&a, &["--ro-bind", "/lib", "/lib"]);
        assert!(!a.iter().any(|x| x == "/lib64"));
        pos(&a, &["--symlink", "usr/sbin", "/sbin"]);
        pos(&a, &["--ro-bind", "/usr", "/usr"]);
        pos(&a, &["--ro-bind", "/etc", "/etc"]);

        let h = HostRoot {
            entries: [
                RootEntry::Dir,
                RootEntry::Symlink("usr/lib".into()),
                RootEntry::Symlink("usr/lib64".into()),
                RootEntry::Absent,
            ],
            resolv_conf_outside_etc: None,
        };
        let a = args(&layout(), &h);
        pos(&a, &["--ro-bind", "/bin", "/bin"]);
        pos(&a, &["--symlink", "usr/lib", "/lib"]);
        pos(&a, &["--symlink", "usr/lib64", "/lib64"]);
        assert!(!a.iter().any(|x| x == "/sbin"));
    }

    #[test]
    fn engine_install_dir_and_agent_exe_are_bound_outside_usr() {
        let a = args(&layout(), &host());
        pos(&a, &["--ro-bind", "/opt/claude/bin", "/opt/claude/bin"]);
        pos(
            &a,
            &["--ro-bind", "/opt/gino/gino-agent", "/opt/gino/gino-agent"],
        );

        let mut l = layout();
        l.engine_binary = "/usr/local/bin/claude".into();
        l.agent_exe = "/usr/bin/gino-agent".into();
        let a = args(&l, &host());
        let binds: Vec<_> = a
            .iter()
            .enumerate()
            .filter(|(_, x)| *x == "--ro-bind")
            .map(|(i, _)| a[i + 1].as_str())
            .collect();
        assert!(!binds.iter().any(|b| *b != "/usr" && b.starts_with("/usr")));
        assert!(!binds.contains(&"/opt/claude/bin"));
    }

    #[test]
    fn mounts_are_in_order_and_flavoured() {
        let a = args(&layout(), &host());
        let tmp = pos(&a, &["--tmpfs", "/tmp"]);
        let home = pos(&a, &["--tmpfs", "/home/sandbox"]);
        let first_bind = a
            .iter()
            .position(|x| x == "--ro-bind" || x == "--bind" || x == "--symlink")
            .unwrap();
        assert!(tmp < home && home < first_bind);

        let ro1 = pos(&a, &["--ro-bind", "/data/ro1", "/data/ro1"]);
        let ro2 = pos(&a, &["--ro-bind", "/data/ro2", "/data/ro2"]);
        let work = pos(&a, &["--bind", "/ws/threads/t1", "/ws/threads/t1"]);
        let rw1 = pos(&a, &["--bind", "/data/rw1", "/data/rw1"]);
        let md = pos(
            &a,
            &[
                "--ro-bind",
                "/ws/global/CLAUDE.md",
                "/ws/threads/t1/.engine-home/CLAUDE.md",
            ],
        );
        let skills = pos(
            &a,
            &[
                "--ro-bind",
                "/ws/threads/t1/.engine-home/skills",
                "/ws/threads/t1/.engine-home/skills",
            ],
        );
        let alpha = pos(
            &a,
            &[
                "--ro-bind",
                "/ws/store/alpha/h1",
                "/ws/threads/t1/.engine-home/skills/alpha",
            ],
        );
        let beta = pos(
            &a,
            &[
                "--ro-bind",
                "/ws/store/beta.md/h2",
                "/ws/threads/t1/.engine-home/skills/beta.md",
            ],
        );
        assert!(
            ro1 < ro2
                && ro2 < work
                && work < rw1
                && rw1 < md
                && md < skills
                && skills < alpha
                && alpha < beta
        );
        assert!(find(&a, &["--bind", "/data/ro1"]).is_none());
        assert!(find(&a, &["--ro-bind", "/data/rw1"]).is_none());
    }

    #[test]
    fn globals_are_bound_only_when_present() {
        let mut l = layout();
        l.globals.claude_md = false;
        let a = args(&l, &host());
        assert!(!a.iter().any(|x| x.ends_with("CLAUDE.md")));
        pos(&a, &["--ro-bind", "/ws/store/alpha/h1"]);

        l.globals = ProvisionedGlobals {
            claude_md: true,
            skills: Vec::new(),
        };
        let a = args(&l, &host());
        assert!(
            !a.iter()
                .any(|x| x.contains("skills") || x.starts_with("/ws/store"))
        );
        pos(&a, &["--ro-bind", "/ws/global/CLAUDE.md"]);

        l.globals.skills = skills();
        l.global_config_dir = None;
        let a = args(&l, &host());
        assert!(!a.iter().any(|x| x.contains(".engine-home")));
    }

    #[test]
    fn chdir_separator_and_inner_come_last() {
        let a = args(&layout(), &host());
        let tail = ["--chdir", "/ws/threads/t1/repo", "--"]
            .into_iter()
            .map(str::to_owned)
            .chain(inner().into_iter().map(|s| s.into_string().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(a[a.len() - tail.len()..], tail[..]);
        assert_eq!(a.iter().filter(|x| *x == "--chdir").count(), 1);
    }

    #[test]
    fn parents_under_writable_tmpfs_get_read_only_shadows() {
        let mut l = layout();
        l.work_dir = "/tmp/e2e/ws/threads/t1".into();
        l.cwd = l.work_dir.clone();
        l.engine_home = engine_home(&l.work_dir);
        l.read_paths = vec!["/home/sandbox/data/ro".into()];
        l.write_paths = vec!["/tmp/rw".into(), "/tmp/e2e/rw".into()];
        let a = args(&l, &host());
        let home = pos(&a, &["--tmpfs", "/home/sandbox"]);
        let e2e = pos(&a, &["--tmpfs", "/tmp/e2e"]);
        let data = pos(&a, &["--tmpfs", "/home/sandbox/data"]);
        assert_eq!(a.iter().filter(|x| *x == "--tmpfs").count(), 4);
        let first_bind = a.iter().position(|x| x == "--ro-bind").unwrap();
        assert!(home < data && data < e2e && e2e < first_bind);

        let root = pos(&a, &["--remount-ro", "/"]);
        let ro_e2e = pos(&a, &["--remount-ro", "/tmp/e2e"]);
        let ro_data = pos(&a, &["--remount-ro", "/home/sandbox/data"]);
        assert!(root < ro_data && ro_data < ro_e2e);
        assert_eq!(a[ro_e2e + 2], "--chdir");
        assert_eq!(a.iter().filter(|x| *x == "--remount-ro").count(), 3);
        // A bind target directly under a tmpfs root needs no shadow.
        assert!(find(&a, &["--tmpfs", "/tmp/rw"]).is_none());
    }

    #[test]
    fn root_is_remounted_read_only_after_every_mount() {
        let a = args(&layout(), &host());
        let remount = pos(&a, &["--remount-ro", "/"]);
        assert_eq!(find(&a[remount + 1..], &["--remount-ro", "/"]), None);
        assert_eq!(a[remount + 2], "--chdir");
        let mount_flags = [
            "--ro-bind",
            "--bind",
            "--symlink",
            "--tmpfs",
            "--proc",
            "--dev",
        ];
        let last_mount = a
            .iter()
            .rposition(|x| mount_flags.contains(&x.as_str()))
            .unwrap();
        assert!(last_mount < remount);
    }

    #[test]
    fn nothing_else_of_the_host_is_mounted() {
        let a = args(&layout(), &host());
        for forbidden in [
            "/run",
            "/var",
            "/ws",
            "/ws/threads",
            "/ws/global",
            "/ws/global/skills",
            "/ws/store",
            "/root",
        ] {
            assert!(!a.iter().any(|x| x == forbidden), "{forbidden} in {a:?}");
        }
        assert!(
            !a.iter()
                .any(|x| x.starts_with("/run") || x.starts_with("/var"))
        );
        assert!(!a.iter().any(|x| x.contains("agent.db")));
    }

    #[test]
    fn agent_socket_is_bound_in_every_network_mode() {
        let bind = ["--bind", "/ws/run/agent.sock", "/run/gino/agent.sock"];
        for network in [NetworkMode::None, NetworkMode::Full, NetworkMode::Allowlist] {
            let mut l = layout();
            l.network = network;
            if network == NetworkMode::Allowlist {
                l.net_dir = Some("/tmp/gino-net-x".into());
            }
            let without_sock = args(&l, &host());
            assert!(!without_sock.iter().any(|x| x.contains("agent.sock")));

            l.agent_sock = Some("/ws/run/agent.sock".into());
            let a = args(&l, &host());
            assert_eq!(a.windows(3).filter(|w| *w == bind).count(), 1);
            let at = pos(&a, &bind);
            // No later mount touches /run, so nothing covers the socket.
            assert!(!a[at + 3..].iter().any(|x| x.starts_with("/run")));
            assert!(at < pos(&a, &["--remount-ro", "/"]));
            if network == NetworkMode::Allowlist {
                assert!(
                    pos(
                        &a,
                        &["--bind", "/tmp/gino-net-x/ctl.sock", "/run/gino/ctl.sock"]
                    ) < at
                );
            }
            // Only the socket file of the workspace is visible.
            assert!(!a.iter().any(|x| x == "/ws/run" || x == "/ws"));
            assert_eq!(without(&a, &[&bind]), without_sock);
        }
    }

    #[test]
    fn memory_trees_and_conversations_view_bind_at_fixed_paths() {
        let base = args(&layout(), &host());
        assert!(
            !base
                .iter()
                .any(|x| x.contains("/run/gino/memory") || x.contains("conversations"))
        );

        let task = ["--bind", "/ws/memory/task/t", "/run/gino/memory/task"];
        let writable = ["--bind", "/ws/memory/agent", "/run/gino/memory/agent"];
        let read_only = ["--ro-bind", "/ws/memory/agent", "/run/gino/memory/agent"];
        let view = ["--ro-bind", "/tmp/gino-conv-x", "/run/gino/conversations"];
        let mut l = layout();
        l.memory_dir = Some("/ws/memory/task/t".into());
        l.agent_memory_dir = Some("/ws/memory/agent".into());
        l.agent_memory_writable = true;
        l.conversations_dir = Some("/tmp/gino-conv-x".into());
        let a = args(&l, &host());
        for bind in [task, writable, view] {
            assert!(pos(&a, &bind) < pos(&a, &["--remount-ro", "/"]));
        }
        assert_eq!(without(&a, &[&task, &writable, &view]), base);

        l.agent_memory_writable = false;
        let a = args(&l, &host());
        assert!(find(&a, &writable).is_none());
        assert_eq!(without(&a, &[&task, &read_only, &view]), base);
    }

    #[test]
    fn prepare_engine_home_creates_only_needed_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let mut l = layout();
        l.work_dir = tmp.path().join("t1");
        l.engine_home = engine_home(&l.work_dir);
        prepare_engine_home(&l).unwrap();
        let md = l.engine_home.join("CLAUDE.md");
        assert!(md.is_file());
        assert_eq!(fs::metadata(&md).unwrap().len(), 0);
        let skills = l.engine_home.join("skills");
        assert!(skills.join("alpha").is_dir());
        let beta = skills.join("beta.md");
        assert!(beta.is_file());
        assert_eq!(fs::metadata(&beta).unwrap().len(), 0);
        assert_eq!(fs::read_dir(&skills).unwrap().count(), 2);
        // Idempotent and non-truncating.
        fs::write(&md, "x").unwrap();
        fs::write(&beta, "y").unwrap();
        prepare_engine_home(&l).unwrap();
        assert_eq!(fs::read_to_string(&md).unwrap(), "x");
        assert_eq!(fs::read_to_string(&beta).unwrap(), "y");

        let tmp = tempfile::tempdir().unwrap();
        l.work_dir = tmp.path().join("t2");
        l.engine_home = engine_home(&l.work_dir);
        l.globals = ProvisionedGlobals::default();
        prepare_engine_home(&l).unwrap();
        assert!(l.engine_home.is_dir());
        assert_eq!(fs::read_dir(&l.engine_home).unwrap().count(), 0);
    }

    #[test]
    fn provisioned_globals_inspects_the_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            ProvisionedGlobals::inspect(Some(tmp.path())),
            ProvisionedGlobals::default()
        );
        fs::write(tmp.path().join("CLAUDE.md"), "").unwrap();
        let skills = tmp.path().join("skills");
        fs::create_dir(&skills).unwrap();
        assert_eq!(
            ProvisionedGlobals::inspect(Some(tmp.path())),
            ProvisionedGlobals {
                claude_md: true,
                skills: Vec::new(),
            }
        );

        let store = fs::canonicalize(tmp.path()).unwrap().join("store");
        fs::create_dir_all(store.join("zeta/h1")).unwrap();
        fs::write(store.join("zeta/h1/SKILL.md"), "").unwrap();
        fs::create_dir_all(store.join("note")).unwrap();
        fs::write(store.join("note/h2"), "").unwrap();
        symlink(store.join("zeta/h1"), skills.join("zeta")).unwrap();
        symlink(store.join("note/h2"), skills.join("note.md")).unwrap();
        symlink(store.join("gone/h3"), skills.join("dangling")).unwrap();
        fs::create_dir(skills.join("local")).unwrap();
        assert_eq!(
            ProvisionedGlobals::inspect(Some(tmp.path())).skills,
            [
                SkillBind {
                    name: "local".into(),
                    source: fs::canonicalize(skills.join("local")).unwrap(),
                    is_dir: true,
                },
                SkillBind {
                    name: "note.md".into(),
                    source: store.join("note/h2"),
                    is_dir: false,
                },
                SkillBind {
                    name: "zeta".into(),
                    source: store.join("zeta/h1"),
                    is_dir: true,
                },
            ]
        );
        assert_eq!(
            ProvisionedGlobals::inspect(None),
            ProvisionedGlobals::default()
        );
    }

    #[test]
    fn task_entries_are_bound_read_only_at_their_link_targets() {
        let mut l = layout();
        l.work_dir = "/tmp/e2e/ws/threads/t1".into();
        l.cwd = l.work_dir.join("project");
        l.engine_home = engine_home(&l.work_dir);
        l.read_paths = Vec::new();
        l.write_paths = Vec::new();
        let before = args(&l, &host());
        l.task_entries = vec![
            EntryBind {
                source: "/tmp/e2e/ws/store/task-md/h1".into(),
                dest: "/tmp/e2e/ws/store/task-md/h1".into(),
            },
            EntryBind {
                source: "/srv/ws/store/skill/h2".into(),
                dest: "/home/sandbox/ws/store/skill/h2".into(),
            },
        ];
        let a = args(&l, &host());
        let file = [
            "--ro-bind",
            "/tmp/e2e/ws/store/task-md/h1",
            "/tmp/e2e/ws/store/task-md/h1",
        ];
        let dir = [
            "--ro-bind",
            "/srv/ws/store/skill/h2",
            "/home/sandbox/ws/store/skill/h2",
        ];
        let work = pos(&a, &["--bind", "/tmp/e2e/ws/threads/t1"]);
        assert!(work < pos(&a, &file) && pos(&a, &file) < pos(&a, &dir));
        assert!(pos(&a, &dir) < pos(&a, &["--remount-ro", "/"]));
        // A target under the writable home tmpfs gets a read-only shadow.
        assert!(pos(&a, &["--tmpfs", "/home/sandbox/ws"]) < work);
        pos(&a, &["--remount-ro", "/home/sandbox/ws"]);
        assert!(
            !a.iter()
                .any(|x| x == "/tmp/e2e/ws/store" || x == "/srv/ws/store")
        );
        assert_eq!(
            without(
                &a,
                &[
                    &file,
                    &dir,
                    &["--tmpfs", "/home/sandbox/ws"],
                    &["--remount-ro", "/home/sandbox/ws"],
                ]
            ),
            before
        );
    }

    #[test]
    fn task_entries_are_the_store_links_under_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let store = root.join("ws/store");
        let work_dir = root.join("ws/threads/t1");
        let project = work_dir.join("project");
        assert!(inspect_task_entries(&work_dir, &root.join("ws")).is_empty());

        fs::create_dir_all(store.join("task-md")).unwrap();
        fs::write(store.join("task-md/h1"), "").unwrap();
        fs::create_dir_all(store.join("skill/h2")).unwrap();
        fs::create_dir_all(project.join("skills")).unwrap();
        fs::create_dir_all(project.join("workspace")).unwrap();
        fs::write(root.join("secret"), "").unwrap();
        symlink(store.join("task-md/h1"), project.join("TASK.md")).unwrap();
        symlink(store.join("skill/h2"), project.join("skills/demo")).unwrap();
        symlink(store.join("skill/h2"), project.join("skills/again")).unwrap();
        // Not counted: outside the store, dangling, relative, non-plain, or
        // inside the git working area.
        symlink(root.join("secret"), project.join("escape")).unwrap();
        symlink(store.join("gone/h3"), project.join("dangling")).unwrap();
        symlink("../../../store/task-md/h1", project.join("relative")).unwrap();
        symlink(
            project.join("../../../store/task-md/h1"),
            project.join("dotted"),
        )
        .unwrap();
        symlink(store.join("task-md/h1"), project.join("workspace/linked")).unwrap();

        let bind = |path: PathBuf| EntryBind {
            source: path.clone(),
            dest: path,
        };
        assert_eq!(
            inspect_task_entries(&work_dir, &root.join("ws")),
            [bind(store.join("skill/h2")), bind(store.join("task-md/h1"))]
        );
    }

    #[test]
    fn resolve_binary_searches_path_and_canonicalizes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let real_dir = root.join("real");
        let link_dir = root.join("links");
        let empty_dir = root.join("empty");
        for d in [&real_dir, &link_dir, &empty_dir] {
            fs::create_dir(d).unwrap();
        }
        let tool = real_dir.join("tool");
        fs::write(&tool, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&tool, link_dir.join("tool")).unwrap();
        // Not executable: skipped.
        fs::write(empty_dir.join("tool"), "").unwrap();

        let path = std::env::join_paths([&empty_dir, &link_dir]).unwrap();
        assert_eq!(
            resolve_binary(Path::new("tool"), Some(&path)),
            Some(tool.clone())
        );
        assert_eq!(
            resolve_binary(&link_dir.join("tool"), None),
            Some(tool.clone())
        );
        assert_eq!(resolve_binary(Path::new("tool"), None), None);
        assert_eq!(resolve_binary(Path::new("missing"), Some(&path)), None);
        assert_eq!(
            resolve_binary(Path::new("tool"), Some(OsStr::new(""))),
            None
        );
        assert_eq!(resolve_binary(&root.join("nope/tool"), None), None);
    }

    #[test]
    fn probe_argv_shape() {
        let a: Vec<String> = probe_args(&host())
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect();
        assert_eq!(
            a,
            [
                "--unshare-all",
                "--die-with-parent",
                "--ro-bind",
                "/usr",
                "/usr",
                "--symlink",
                "usr/bin",
                "/bin",
                "--ro-bind",
                "/lib",
                "/lib",
                "--symlink",
                "usr/sbin",
                "/sbin",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--",
                "/usr/bin/true",
            ]
        );
    }

    #[test]
    fn missing_bwrap_is_unavailable() {
        let err = probe(Some(OsStr::new("")), &host()).unwrap_err();
        assert_eq!(err, "bwrap not found on PATH");
        let err = probe(None, &host()).unwrap_err();
        assert_eq!(err, "bwrap not found on PATH");
        let err = crate::sandbox::IsolationError::Unavailable(err);
        assert!(err.to_string().contains("not found on PATH"), "{err}");
    }

    #[test]
    fn host_root_matches_the_filesystem() {
        let h = host_root();
        for (dir, entry) in ROOT_DIRS.iter().zip(&h.entries) {
            let meta = fs::symlink_metadata(dir);
            match entry {
                RootEntry::Symlink(target) => {
                    assert_eq!(&fs::read_link(dir).unwrap(), target, "{dir}");
                }
                RootEntry::Dir => assert!(meta.unwrap().is_dir(), "{dir}"),
                RootEntry::Absent => assert!(
                    !meta.is_ok_and(|m| m.is_dir() || m.file_type().is_symlink()),
                    "{dir}"
                ),
            }
        }
        if let Some(resolved) = h.resolv_conf_outside_etc {
            assert!(!resolved.starts_with("/etc"));
        }
    }

    #[test]
    fn ensure_available_is_cached_and_fails_as_unavailable() {
        let first = ensure_available();
        let second = ensure_available();
        match (&first, &second) {
            (Ok(a), Ok(b)) => assert_eq!(a, b),
            (Err(a), Err(b)) => {
                assert!(matches!(a, crate::sandbox::IsolationError::Unavailable(_)));
                assert_eq!(a.to_string(), b.to_string());
            }
            _ => panic!("cached probe changed: {first:?} vs {second:?}"),
        }
    }
}
