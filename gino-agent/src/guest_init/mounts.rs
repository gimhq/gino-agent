//! Guest mount table: derived as an ordered list of operations, then applied.
//!
//! libkrun boots from a virtiofs root holding only `/gino-agent`; the root
//! plan mounts the ext4 root disk (`/dev/vda`) at `/newroot`, binds the agent
//! binary into it and switches to it. The disk is writable, so mount points are
//! created directly; `/tmp` and `/run` stay tmpfs, and the shares are separate
//! virtiofs instances with their own flags.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::mount::MsFlags;

use super::spec::{BOOT_CONTROL_DIR, GUEST_CONTROL_DIR, GuestSpec, NetConfig};

/// The root disk: the first virtio-blk device.
pub(super) const ROOT_DEVICE: &str = "/dev/vda";
/// Mount point of the root disk on the boot root.
pub(super) const NEW_ROOT: &str = "/newroot";
/// The agent binary libkrun serves on the boot root.
pub(super) const AGENT_BINARY: &str = "/gino-agent";
/// tmpfs file bind-mounted over `/etc/resolv.conf`.
const RESOLV_CONF_SOURCE: &str = "/run/gino/resolv.conf";
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// One step of the guest mount table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MountOp {
    /// Create a directory and its missing parents.
    Mkdir(PathBuf),
    /// Create an empty file (a bind mount target).
    Touch(PathBuf),
    /// Write a file.
    Write { path: PathBuf, contents: String },
    /// `mount(2)` a filesystem.
    Mount {
        source: String,
        target: PathBuf,
        fstype: &'static str,
        flags: MsFlags,
        data: Option<String>,
    },
    /// Bind-mount `source` over `target`.
    Bind { source: PathBuf, target: PathBuf },
    /// Bind-mount `source` over `target` read-only, creating a missing
    /// `target` (and its parents) as a directory or file like `source`.
    RoBind { source: PathBuf, target: PathBuf },
    /// Move the mount at a path over `/` and chroot into it.
    SwitchRoot(PathBuf),
}

fn mount(
    source: &str,
    target: &str,
    fstype: &'static str,
    flags: MsFlags,
    data: Option<&str>,
) -> MountOp {
    MountOp::Mount {
        source: source.to_owned(),
        target: PathBuf::from(target),
        fstype,
        flags,
        data: data.map(str::to_owned),
    }
}

/// Kernel filesystems and tmpfs on the root disk.
pub(super) fn base_plan() -> Vec<MountOp> {
    let hardened = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
    vec![
        mount("proc", "/proc", "proc", hardened | MsFlags::MS_NOEXEC, None),
        mount(
            "sysfs",
            "/sys",
            "sysfs",
            hardened | MsFlags::MS_NOEXEC,
            None,
        ),
        mount(
            "cgroup2",
            "/sys/fs/cgroup",
            "cgroup2",
            hardened | MsFlags::MS_NOEXEC,
            Some("nsdelegate"),
        ),
        mount(
            "devtmpfs",
            "/dev",
            "devtmpfs",
            MsFlags::MS_NOSUID,
            Some("mode=0755"),
        ),
        MountOp::Mkdir("/dev/pts".into()),
        mount(
            "devpts",
            "/dev/pts",
            "devpts",
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("mode=0620,ptmxmode=0666"),
        ),
        MountOp::Mkdir("/dev/shm".into()),
        mount("tmpfs", "/dev/shm", "tmpfs", hardened, Some("mode=1777")),
        mount("tmpfs", "/tmp", "tmpfs", hardened, Some("mode=1777")),
    ]
}

/// Switch from the boot root to the root disk: mount it at [`NEW_ROOT`]
/// (inode tables of block groups added by growing it stay uninitialised, which
/// ext4 tracks per group), mount its `/run` tmpfs with the control dir bound
/// read-only into it and bind the agent binary, then move it over `/`.
pub(super) fn root_plan() -> Vec<MountOp> {
    let on_root = |path: &str| Path::new(NEW_ROOT).join(path.trim_start_matches('/'));
    let agent = on_root(AGENT_BINARY);
    let run = on_root("/run");
    vec![
        MountOp::Mkdir(NEW_ROOT.into()),
        mount(
            ROOT_DEVICE,
            NEW_ROOT,
            "ext4",
            MsFlags::empty(),
            Some("noinit_itable"),
        ),
        MountOp::Mount {
            source: "tmpfs".to_owned(),
            target: run,
            fstype: "tmpfs",
            flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            data: Some("mode=0755".to_owned()),
        },
        MountOp::RoBind {
            source: BOOT_CONTROL_DIR.into(),
            target: on_root(GUEST_CONTROL_DIR),
        },
        MountOp::Touch(agent.clone()),
        MountOp::Bind {
            source: AGENT_BINARY.into(),
            target: agent,
        },
        MountOp::SwitchRoot(NEW_ROOT.into()),
    ]
}

/// `/etc/resolv.conf` when `net` is set, every share (parents before
/// children), then the binds (likewise). `exists` reports whether a guest
/// path exists before any of these operations run.
pub(super) fn spec_plan(
    spec: &GuestSpec,
    net: Option<&NetConfig>,
    exists: impl Fn(&Path) -> bool,
) -> Vec<MountOp> {
    let mut shares: Vec<_> = spec.mounts.iter().collect();
    shares.sort_by_key(|m| Path::new(&m.guest_path).components().count());
    let mut binds: Vec<_> = spec.binds.iter().collect();
    binds.sort_by_key(|b| Path::new(&b.target).components().count());

    let mut ops = Vec::new();
    if let Some(net) = net {
        ops.push(MountOp::Write {
            path: RESOLV_CONF_SOURCE.into(),
            contents: resolv_conf(net),
        });
        if !exists(Path::new(RESOLV_CONF)) {
            ops.push(MountOp::Touch(RESOLV_CONF.into()));
        }
        ops.push(MountOp::Bind {
            source: RESOLV_CONF_SOURCE.into(),
            target: RESOLV_CONF.into(),
        });
    }
    for share in shares {
        let target = PathBuf::from(&share.guest_path);
        if !exists(&target) {
            ops.push(MountOp::Mkdir(target.clone()));
        }
        let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
        if share.read_only {
            flags |= MsFlags::MS_RDONLY;
        }
        ops.push(MountOp::Mount {
            source: share.tag.clone(),
            target,
            fstype: "virtiofs",
            flags,
            data: None,
        });
    }
    ops.extend(binds.into_iter().map(|bind| MountOp::RoBind {
        source: PathBuf::from(&bind.source),
        target: PathBuf::from(&bind.target),
    }));
    ops
}

/// `/etc/resolv.conf` naming the guest's only resolver.
pub(super) fn resolv_conf(net: &NetConfig) -> String {
    format!("nameserver {}\n", net.dns)
}

/// Whether a directory with `owner`/`group`/`mode` is writable and searchable
/// by `uid`/`gid` without supplementary groups or capabilities.
pub(super) fn writable_by(owner: u32, group: u32, mode: u32, uid: u32, gid: u32) -> bool {
    let bits = if owner == uid {
        mode >> 6
    } else if group == gid {
        mode >> 3
    } else {
        mode
    };
    bits & 0o3 == 0o3
}

/// Run `ops` in order.
pub(super) fn apply(ops: &[MountOp]) -> Result<()> {
    for op in ops {
        match op {
            MountOp::Mkdir(path) => std::fs::create_dir_all(path)
                .with_context(|| format!("creating {}", path.display()))?,
            MountOp::Touch(path) => {
                std::fs::File::create(path)
                    .with_context(|| format!("creating {}", path.display()))?;
            }
            MountOp::Write { path, contents } => std::fs::write(path, contents)
                .with_context(|| format!("writing {}", path.display()))?,
            MountOp::Mount {
                source,
                target,
                fstype,
                flags,
                data,
            } => nix::mount::mount(
                Some(source.as_str()),
                target,
                Some(*fstype),
                *flags,
                data.as_deref(),
            )
            .with_context(|| format!("mounting {fstype} {source} at {}", target.display()))?,
            MountOp::Bind { source, target } => nix::mount::mount(
                Some(source),
                target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .with_context(|| {
                format!("bind-mounting {} at {}", source.display(), target.display())
            })?,
            MountOp::RoBind { source, target } => ro_bind(source, target).with_context(|| {
                format!(
                    "bind-mounting {} read-only at {}",
                    source.display(),
                    target.display()
                )
            })?,
            MountOp::SwitchRoot(new_root) => switch_root(new_root)
                .with_context(|| format!("switching the root to {}", new_root.display()))?,
        }
    }
    Ok(())
}

fn switch_root(new_root: &Path) -> Result<()> {
    std::env::set_current_dir(new_root)?;
    let none = None::<&str>;
    // A mount cannot move away from a shared parent; init.krun's root is shared.
    nix::mount::mount(none, "/", none, MsFlags::MS_REC | MsFlags::MS_PRIVATE, none)?;
    nix::mount::mount(Some("."), "/", none, MsFlags::MS_MOVE, none)?;
    nix::unistd::chroot(".")?;
    std::env::set_current_dir("/")?;
    Ok(())
}

fn ro_bind(source: &Path, target: &Path) -> Result<()> {
    if std::fs::symlink_metadata(target).is_err() {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if std::fs::metadata(source)?.is_dir() {
            std::fs::create_dir(target)?;
        } else {
            std::fs::File::create(target)?;
        }
    }
    let none = None::<&str>;
    nix::mount::mount(Some(source), target, none, MsFlags::MS_BIND, none)?;
    nix::mount::mount(
        none,
        target,
        none,
        MsFlags::MS_BIND
            | MsFlags::MS_REMOUNT
            | MsFlags::MS_RDONLY
            | MsFlags::MS_NOSUID
            | MsFlags::MS_NODEV,
        none,
    )?;
    Ok(())
}

/// Fail unless every read-write share is writable by the engine identity.
///
/// virtiofs reports host ownership (the daemon's uid) and guest root cannot
/// chown through an unprivileged VMM, so the daemon must make the shared
/// directories accessible to the spec's uid/gid (same uid, or group/other
/// write bits).
pub(super) fn check_writable_shares(spec: &GuestSpec) -> Result<()> {
    for share in spec.mounts.iter().filter(|m| !m.read_only) {
        let meta = std::fs::metadata(&share.guest_path)
            .with_context(|| format!("inspecting {}", share.guest_path))?;
        if !writable_by(meta.uid(), meta.gid(), meta.mode(), spec.uid, spec.gid) {
            bail!(
                "share {} at {} (owner {}:{}, mode {:o}) is not writable by engine {}:{}",
                share.tag,
                share.guest_path,
                meta.uid(),
                meta.gid(),
                meta.mode() & 0o7777,
                spec.uid,
                spec.gid
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::super::spec::tests::sample;
    use super::super::spec::{GuestBind, GuestMount};
    use super::*;

    fn exists_in(paths: &[&str]) -> impl Fn(&Path) -> bool {
        let set: HashSet<PathBuf> = paths.iter().map(PathBuf::from).collect();
        move |p| set.contains(p)
    }

    fn targets(ops: &[MountOp]) -> Vec<String> {
        ops.iter()
            .filter_map(|op| match op {
                MountOp::Mount { target, .. }
                | MountOp::Bind { target, .. }
                | MountOp::RoBind { target, .. } => Some(target.display().to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn base_plan_mounts_the_kernel_filesystems_and_tmpfs() {
        assert_eq!(
            targets(&base_plan()),
            [
                "/proc",
                "/sys",
                "/sys/fs/cgroup",
                "/dev",
                "/dev/pts",
                "/dev/shm",
                "/tmp"
            ]
        );
    }

    #[test]
    fn root_plan_switches_to_the_root_disk_with_the_agent_bound() {
        assert_eq!(
            root_plan(),
            vec![
                MountOp::Mkdir("/newroot".into()),
                MountOp::Mount {
                    source: "/dev/vda".into(),
                    target: "/newroot".into(),
                    fstype: "ext4",
                    flags: MsFlags::empty(),
                    data: Some("noinit_itable".into()),
                },
                MountOp::Mount {
                    source: "tmpfs".into(),
                    target: "/newroot/run".into(),
                    fstype: "tmpfs",
                    flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                    data: Some("mode=0755".into()),
                },
                MountOp::RoBind {
                    source: "/ctl".into(),
                    target: "/newroot/run/gino/ctl".into(),
                },
                MountOp::Touch("/newroot/gino-agent".into()),
                MountOp::Bind {
                    source: "/gino-agent".into(),
                    target: "/newroot/gino-agent".into(),
                },
                MountOp::SwitchRoot("/newroot".into()),
            ]
        );
    }

    #[test]
    fn spec_plan_creates_missing_mount_points_directly() {
        let spec = sample();
        let net = spec.net.as_ref().unwrap().config().unwrap();
        let ops = spec_plan(
            &spec,
            Some(&net),
            exists_in(&["/", "/var", "/etc", RESOLV_CONF]),
        );
        assert_eq!(
            ops,
            vec![
                MountOp::Write {
                    path: RESOLV_CONF_SOURCE.into(),
                    contents: "nameserver 10.0.2.2\n".into(),
                },
                MountOp::Bind {
                    source: RESOLV_CONF_SOURCE.into(),
                    target: RESOLV_CONF.into(),
                },
                MountOp::Mkdir("/var/lib/gino/skills".into()),
                MountOp::Mount {
                    source: "skills".into(),
                    target: "/var/lib/gino/skills".into(),
                    fstype: "virtiofs",
                    flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
                    data: None,
                },
                MountOp::Mkdir("/var/lib/gino/threads/t1/work".into()),
                MountOp::Mount {
                    source: "work".into(),
                    target: "/var/lib/gino/threads/t1/work".into(),
                    fstype: "virtiofs",
                    flags: MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                    data: None,
                },
                MountOp::RoBind {
                    source: "/run/gino/ctl/view/0".into(),
                    target: "/var/lib/gino/threads/t1/work/.engine-home/CLAUDE.md".into(),
                },
            ]
        );
    }

    #[test]
    fn shares_and_binds_are_ordered_parents_first() {
        let mut spec = sample();
        spec.binds.push(GuestBind {
            source: "/run/gino/ctl/view/1".into(),
            target: "/opt/store/ab/skill".into(),
        });
        spec.mounts.push(GuestMount {
            tag: "inner".into(),
            guest_path: "/var/lib/gino/threads/t1/work/inner/x".into(),
            read_only: true,
        });
        let ops = spec_plan(&spec, None, exists_in(&["/", "/var/lib/gino/skills"]));
        assert_eq!(
            targets(&ops),
            [
                "/var/lib/gino/skills",
                "/var/lib/gino/threads/t1/work",
                "/var/lib/gino/threads/t1/work/inner/x",
                "/opt/store/ab/skill",
                "/var/lib/gino/threads/t1/work/.engine-home/CLAUDE.md",
            ]
        );
        assert!(!ops.contains(&MountOp::Mkdir("/var/lib/gino/skills".into())));
    }

    #[test]
    fn missing_resolv_conf_is_created() {
        let mut spec = sample();
        spec.mounts.clear();
        spec.binds.clear();
        let net = spec.net.as_ref().unwrap().config().unwrap();
        let ops = spec_plan(&spec, Some(&net), exists_in(&["/", "/etc"]));
        assert_eq!(targets(&ops), [RESOLV_CONF]);
        assert!(ops.contains(&MountOp::Touch(RESOLV_CONF.into())));
        assert!(spec_plan(&spec, None, exists_in(&["/"])).is_empty());
    }

    #[test]
    fn writability_follows_owner_group_other_bits() {
        assert!(writable_by(1000, 1000, 0o40700, 1000, 1000));
        assert!(!writable_by(1000, 1000, 0o40500, 1000, 1000));
        assert!(!writable_by(1001, 1001, 0o40700, 1000, 1000));
        assert!(writable_by(1001, 1000, 0o40770, 1000, 1000));
        assert!(!writable_by(1001, 1000, 0o40707, 1000, 1000));
        assert!(writable_by(1001, 1001, 0o41777, 1000, 1000));
        // The owner class wins even when group or other would allow it.
        assert!(!writable_by(1000, 1000, 0o40577, 1000, 1000));
    }
}
