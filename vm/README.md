# vm

Guest image and VMM for the gino agent's `vm` isolation mode. Every build runs in a labelled
sibling container and writes under `<worktree>/.tmp/vm/` (never committed); each script skips work
already done.

| Script | Output |
| --- | --- |
| `vmm/build.sh` | `.tmp/vm/bin/gino-vmm` (static musl, libkrun compiled in; see [gino-vmm](../gino-vmm/README.md#build)) |
| `kernel/build.sh` | `.tmp/vm/kernel/vmlinux` (ELF) + `config`, `fragment.sha256` |
| `rootfs/build.sh` | `.tmp/vm/rootfs/rootfs.ext4` (raw ext4 base image) + `rootfs.image`, `rootfs.versions` |
| `smoke.sh` | runs the three above, probes `gino-vmm`, boots the guest and checks it |
| `release.sh` | release helpers for `release-vm.yml`: stamp, inputs hash, packaging, lode manifest (see [Releases](#releases)) |

## Guest root

The guest boots from an empty per-run virtiofs dir that holds only the gino-agent binary and the
run's control dir; guest-init mounts the root disk (`/dev/vda`, ext4), binds both into it and
switches to it. The daemon gives each run a qcow2 overlay over the image as its root disk: a fresh
one per run, or one kept per task (`vmDisk: "task"`); the image itself is never written. The
filesystem grows online to the configured `diskGib` on each boot. The agent binary must be
statically linked (release builds are), since nothing else is on the boot root.

The image carries Docker Engine; guest-init starts `dockerd` before the engine when the VM config
enables `docker`. Docker's socket group is the engine's gid, which makes the engine root inside
its own VM; the VM boundary still holds.

## Smoke test

```sh
vm/smoke.sh
```

Needs `docker`, `git`, `jq` and `/dev/kvm`. Builds `gino-vmm` through `vmm/build.sh`, the kernel
and the root, then works in sibling containers (`debian:bookworm-slim` by default) with `/dev/kvm`
as uid 1000 and no libkrun library anywhere:

1. runs `gino-vmm --probe`, requires exit 0 and the documented line
   (`gino-vmm <version> libkrun 1.19.7`) and checks that no `libkrun*` file exists in the run
   container;
2. boots the self-built kernel through `gino-vmm` from an empty boot root holding the image's
   static busybox, with `rootfs.ext4` attached read-only as `/dev/vda`; a guest script mounts it
   and prints `uname -r`, its filesystem type and `claude --version` from inside it;
3. checks the output and the `gino-vmm` exit status and prints a PASS/FAIL summary (non-zero exit
   on failure).

Output dirs, images and VM size are overridable; see the header of `smoke.sh`.

The agent's KVM integration suite, `gino-agent/scripts/vm-it.sh`, builds or reuses the same
artifacts (agent-architecture §9e).

`spike/` is the earlier feasibility spike with its own scripts.

## Releases

`kernel`, `vmm` and `rootfs` are released on their own, independent of the agent and of each
other, as the lode resources `gino-agent/<channel>` (`.github/workflows/release-vm.yml`,
`release.sh`):

```sh
gh workflow run release-vm.yml -f channel=kernel   # or vmm, rootfs
```

- A release is `<channel>.<YYYYMMDD-HHMM>` (UTC, the run start) at the `main` commit the run
  started on; its lode version is the same stamp as `YYYY.MMDD.HHMM` (leading zeros dropped), so
  every release is a semver upgrade of the one before.
- `kernel` and `vmm` are released only when their inputs (`vm/kernel/`; `vm/vmm/` and
  `gino-vmm/`) differ from the latest release's. The `rootfs` rolls: it is rebuilt weekly (Monday
  03:17 UTC) and on dispatch, picking up Debian updates, and released only when its pins or
  installed package versions differ from the latest release's.
- Every run builds all three and boots them with `smoke.sh` before publishing anything.
- The release holds `gino-<channel>-linux-x64.tar.gz` (`vmlinux` + `config`, `gino-vmm`, or a
  sparse `rootfs.ext4` + `rootfs.versions`), its `.sig` when the repository secret
  `LODE_SIGNING_KEY` is set, `SHA256SUMS` and `release.lock` (channel, version, commit, inputs
  hash, asset sha256, upstream versions). It and the manifest holders are created with
  `--latest=false`: the agent release must stay the repository latest, which lode's github source
  reads, and the run fails otherwise.
- Each channel's signed `lode/v1` manifest (the newest 10 versions, `stable` at the newest) is
  `manifest.json` on the rolling release `<channel>-manifest`.

Operator `lode.toml` for a vm host (the agent's `vm` block can then omit the three paths):

```toml
[[resource]]
name = "kernel"
manifest = "https://github.com/gimhq/gino-agent/releases/download/kernel-manifest/manifest.json"
asset = "gino-kernel-linux-x64.tar.gz"
required = true

[[resource]]
name = "vmm"
manifest = "https://github.com/gimhq/gino-agent/releases/download/vmm-manifest/manifest.json"
asset = "gino-vmm-linux-x64.tar.gz"
required = true

[[resource]]
name = "rootfs"
manifest = "https://github.com/gimhq/gino-agent/releases/download/rootfs-manifest/manifest.json"
asset = "gino-rootfs-linux-x64.tar.gz"
required = true
```
