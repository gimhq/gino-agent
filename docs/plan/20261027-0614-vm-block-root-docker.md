# 20261027-0614-vm-block-root-docker VM block root, task disks and Docker

- **status**: completed
- **createdAt**: 2026-10-27 06:14
- **approvedAt**: 2026-10-27 06:30
- **relatedTask**: 20261027-0613-vm-block-root-docker

## Context

- The guest root is the rootfs tree as libkrun's virtiofs root (`krun_set_root`), remounted
  read-only by guest-init; writable state is tmpfs (`/tmp`, `/run`), missing mount points get an
  overlayfs over their deepest existing ancestor (`guest_init/mounts.rs`). Docker cannot run on it:
  overlay2 rejects a virtiofs upper, tmpfs costs guest memory, and nothing persists between runs.
- gino-vmm builds libkrun 1.19.7 (`43b2f5a`) with `net` only. With `blk`, libkrun exposes
  `krun_add_disk3(id, path, format, ro, direct_io, sync)`; its virtio-blk backend is imago, which
  opens raw, qcow2 and vmdk and, for qcow2, the backing chain (`open_implicit_dependencies_sync`).
  Discard and write-zeroes are supported. imago 0.2.3 can create qcow2 images with a backing file
  (`Qcow2::create_builder(..).backing_path(..)`), so no qemu-img is needed on the host.
- `krun_set_root_disk_remount` makes `init.krun` chroot into the block device before running the
  workload, which would drop the `/gino-agent` overlay file (it lives on the initial root).
- The agent binary is injected as a top-level overlay file; the engine runs as the daemon uid with
  no capabilities and `no_new_privs`. A task may run several threads concurrently (§5).
- Kernel (`vm/kernel/config-x86_64`, tinyconfig + fragment, verified line by line by `build.sh`):
  `olddefconfig` pulls in INTEL_MEI, PCI serial cards, cpufreq/intel_pstate, RAPL/uncore perf,
  MICROCODE, AMD_NB, PCIEASPM, VGA_ARB, HPET_TIMER, SCSI_MOD, extra partition tables and IO
  schedulers, SWAP and the Centaur/Zhaoxin/Hygon CPU support. Docker needs cgroup controllers,
  BPF cgroup, veth, bridge, netfilter/nftables with xt compat, bridge netfilter, keys and tun,
  none of which are enabled. libkrunfw's 6.12 config (same VMM, runs containers) is the reference.
- Microsoft MXC's microVM backend runs NanVix, not Linux, so it has no kernel config to borrow.

## Proposal

**1. Kernel.** In the fragment:

- `# CONFIG_X is not set` for the unused options above (INTEL_MEI, MEI_ME,
  SERIAL_8250_PCI/EXAR/LPSS/MID/PERICOM, CPU_FREQ, X86_INTEL_PSTATE, PERF_EVENTS_INTEL_CSTATE/RAPL/
  UNCORE, MICROCODE, AMD_NB, PCIEASPM, VGA_ARB, HPET_TIMER, SCSI_MOD, MSDOS_PARTITION,
  EFI_PARTITION, MQ_IOSCHED_KYBER, MQ_IOSCHED_DEADLINE, SWAP, CPU_SUP_CENTAUR/ZHAOXIN/HYGON); drop
  any that `build.sh` shows are not user-selectable.
- Enable VIRTIO_BLK, EXT4_FS (+ POSIX_ACL, SECURITY), BLK_DEV, MEMCG, CGROUP_PIDS, CGROUP_SCHED,
  FAIR_GROUP_SCHED, CPUSETS, CGROUP_FREEZER, CGROUP_DEVICE, CGROUP_CPUACCT, BLK_CGROUP,
  CGROUP_BPF, BPF_SYSCALL, KEYS, VETH, BRIDGE, BRIDGE_NETFILTER, TUN, DUMMY, NETFILTER,
  NF_CONNTRACK, NF_NAT, NF_TABLES (+ INET, NAT, MASQ, CT, COMPAT), NETFILTER_XTABLES with the xt
  matches/targets iptables-nft uses for Docker (addrtype, conntrack, MASQUERADE, comment, mark),
  OVERLAY_FS (Docker overlay2).
- Compare `vmlinux` size before and after in the changelog.

**2. gino-vmm.** Enable the `blk` feature. The run spec gains
`disks: [{ id, path, format: "raw"|"qcow2", readOnly }]`, applied with `krun_add_disk3`
(`direct_io` off, sync mode full). Paths are checked like the other host paths.

**3. Base image.** `vm/rootfs/build.sh` additionally writes `rootfs.ext4` (`mkfs.ext4 -d` of the
exported tree in the build container, fixed size plus headroom, deterministic UUID and hash
seed) named by its sha256 (`rootfs-<sha12>.ext4`). The Dockerfile installs docker-ce, containerd,
docker-ce-cli, buildx and compose from Docker's apt repo with pinned versions, plus iptables
(nft backend), and creates the `docker` group. The tree export stays for the bwrap image paths that
use it; `vm.rootfs` in the isolation file becomes the base image path (`vm.rootfs` pointing at a
directory is rejected — no compatibility path).

**4. Disks and the manifest.** The agent owns `<workspace>/vm/disks/`:

```
base/<sha256>.ext4          read-only, hard-linked or copied from the configured image once
tasks/<taskId>/disk.json    manifest: { base, layers: ["root.qcow2"], sizeBytes, createdAt }
tasks/<taskId>/root.qcow2   task overlay (backing = base, absolute path)
<run dir>/root.qcow2        ephemeral overlay
```

- `vm.disk` config: `sizeGib` (virtual size, default 32) and `scope` default `run`.
- Task meta `vmDisk: "task"` keeps a task disk (a separate key: `vm` in task `meta.isolation` is
  dropped, and persistence is not an isolation level); `vm.disk.scope: "task"` makes it the
  default. Otherwise the run gets an ephemeral overlay deleted with the run dir.
- A task disk is single-writer: an exclusive `flock` on `disk.json` for the run's lifetime. A
  concurrent run of the same task logs a warning and gets an ephemeral overlay on the base.
- A changed base (new rootfs) does not rebase existing task disks: the manifest pins its base
  sha; the base file is kept while any manifest references it. Deleting a task deletes its disk
  dir; startup GC removes base files no manifest or config references.
- Overlays are created with imago from the agent (sparse, cluster size 64 KiB, `lazy_refcounts`
  off). The manifest shape maps onto the phase 2 `Volume`/`Manifest` (see the chunk storage plan).

**5. Guest boot.** gino-vmm keeps a virtiofs root, but it is a per-run empty dir holding only the
`/gino-agent` overlay file; the base/overlay is `vda`. guest-init, before its mount table:

1. mounts `/dev/vda` (ext4, rw) at `/newroot`, then `/proc`, `/sys`, `/dev`, cgroup2
   (`/sys/fs/cgroup`, controllers delegated to a `gino` subtree) and tmpfs `/run` under it;
2. bind-mounts `/gino-agent` to `/newroot/gino-agent` and moves the control share;
3. `chroot`s into `/newroot` and applies the existing mount table there (shares, binds, memory
   dirs); the read-only remount of `/` and the overlay-over-ancestor logic go away, since the root
   is writable ext4 and mount points can be created directly. `/tmp` stays tmpfs.

The engine still runs as the daemon uid without capabilities. With `vm.docker: true` (local floor
only), guest-init sets `net.ipv4.ip_forward=1`, starts `dockerd` (data root `/var/lib/docker` on
the root disk, `--iptables` with the nft backend), waits for its socket (30 s bound) and adds the
engine's uid to the `docker` group of the guest. Docker containers reach the network through the
bridge, NAT and the guest's `eth0`, so the run's allowlist exit still decides every connection;
registries must be allowlisted (documented).

**6. Docs and tests.**

- §9e: block root, disks, task scope, Docker, the security note that Docker group membership is
  root in the guest (the VM stays the boundary; a task disk is poisonable only by that task).
  Remove "No Docker in the guest" and the read-only root constraint from `vm/README.md`.
- Unit tests: run spec `disks` validation, manifest and lock handling, overlay creation (imago),
  guest mount plan with the block root, config parsing (`vm.disk`, `vm.docker`).
- KVM suite: boot from base + overlay, write persists across two runs of a task-scoped disk and not
  across ephemeral runs, concurrent run fallback, `docker run hello-world` with `full` network.
- Host `SANDBOX_MODE=vm` real-engine e2e on the new artifacts.

## Risks

- ext4 image builds must be reproducible enough for content addressing; non-determinism only
  costs extra base files, not correctness.
- A crash leaves an overlay with lost unflushed writes (L0 durability); qcow2 metadata stays
  consistent because imago honours FLUSH. A task disk that fails to open is reported, not deleted.
- Docker images fill the task disk; the virtual size caps it, host free space is checked before
  creating an overlay (fail the run when below `sizeGib`/4 free).
- dockerd adds ~1–2 s to boot; it starts only with `vm.docker`.
- The engine-dir share (engine install plan) replaces the claude pinned in the rootfs; until that
  lands the rootfs keeps claude.

## Scope

gino-vmm (spec, ffi, vm), `vm/kernel`, `vm/rootfs`, guest_init (mod, mounts, new boot step),
sandbox/vm.rs and a new disk module, config, task deletion hook, docs, tests, scripts/vm-it.sh.

## Alternatives

- tmpfs `/var/lib/docker`: simplest, but costs guest RAM and persists nothing.
- One raw data disk per run for Docker only: keeps the virtiofs root but gives no persistent
  environment for the rest of the guest.
- `krun_set_root_disk_remount`: loses the `/gino-agent` overlay file; would need the agent binary
  inside every overlay.
- ublk/NBD/vhost-user-blk: need host privileges or a libkrun fork; deferred to the chunk storage
  plan.

## Implementation notes

Where the build differs from the proposal:

- Config: `vm.diskGib` (1..=4096, default 32) and `vm.docker`; the disk scope is `vmDisk`
  (`run`/`task`) in the floor and task `meta.isolation`, ignored from a host overlay. No
  `vm.disk` block.
- A disk is never smaller than its base. The lock is a separate `disk.lock` file, retried for 1 s
  because a concurrently forked child briefly holds a copy of it.
- Boot: the control dir moved into the boot root (`boot/ctl`) and is bound read-only at
  `/run/gino/ctl`, which saves a virtio device: x86_64 libkrun has 11 IRQ slots and the block root
  plus the old control share exhausted them on networked runs. guest-init makes `/` private before
  `MS_MOVE` (init.krun's root is shared), then mounts the kernel filesystems on the new root and
  grows it with `resize2fs` (the crate forbids the unsafe ioctl). cgroup controllers are enabled at
  the root, not in a `gino` subtree.
- Docker: the engine reaches the socket through `dockerd --group <engine gid>` instead of a group
  membership; `--ip6tables=false`; stopped after the engine, then `sync`.
- The agent binary must be static (empty boot root); the daemon rejects a dynamically linked one
  before spawn and `vm-it.sh` builds its test binaries with `crt-static`.
- gino-vmm sends libkrun's error log to stderr so a failed start names its cause.
- Kernel: `DUMMY` dropped again (built in, it adds `dummy0` to every guest).
- `rootfs.ext4` keeps a fixed name next to `rootfs.image`; the bases are content-addressed by the
  daemon. The tree export is gone. busybox-static is in the image for `vm/smoke.sh`.

## Annotations

- 2026-10-27: block root approved; disk persistence follows the task; phase 2 tracked in
  20261027-0614-chunk-block-storage.
