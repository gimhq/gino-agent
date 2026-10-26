# gino-vmm

Boots one libkrun microVM for the gino agent's `vm` isolation mode. The daemon spawns
`gino-vmm`, writes a JSON run spec as the first line of its stdin and wires the rest of its stdio
to the guest console. The process lives exactly as long as the VM.

- libkrun **v1.19.7** is compiled in: a Cargo git dependency pinned by rev, with the `net`
  feature. No `libkrun.so` is installed or loaded at run time; the shipped binary is a static
  musl executable.
- `gino-vmm` is an optional helper: hosts without VM support simply do not install it.
- All `unsafe` code is in [`src/ffi.rs`](src/ffi.rs) (`unsafe_code = "deny"` everywhere else).

## Build

Standalone crate (no cargo workspace); `rust-toolchain.toml` pins the toolchain (1.96.0), rustfmt,
clippy and the `x86_64-unknown-linux-musl` target. The build needs a C compiler and, for the musl
target, `musl-gcc` (Debian `musl-tools`); no libclang, no KVM.

The repository's build entry point runs the build in a labelled sibling container:

```sh
vm/vmm/build.sh                    # -> <worktree>/.tmp/vm/bin/gino-vmm
```

It runs `cargo build --profile dist --locked --target x86_64-unknown-linux-musl` with `gino-vmm/`
mounted read-only, fails if the binary has any `NEEDED` entry (it is `static-pie linked`) and
installs it as `$OUT/gino-vmm`. Environment:

| Variable | Default | Meaning |
| --- | --- | --- |
| `OUT` | `<worktree>/.tmp/vm/bin` | output dir |
| `TARGET_DIR` | `<worktree>/.tmp/vm/target` | cargo target dir |
| `IMAGE` | `ai-agent/gino-vmm-build:1.96` | build image, built from [`vm/vmm/Dockerfile`](../vm/vmm/Dockerfile) |
| `CARGO_REGISTRY` / `CARGO_GIT` | `/srv/station/root/.cargo/{registry,git}` | host cargo cache dirs (empty: no mount) |

For development a plain `cargo build` (glibc, host target) is enough. The same command without
`--target` is also the fallback if the musl build is ever dropped:

```sh
cargo build --profile dist --locked --target x86_64-unknown-linux-musl
                                   # target/x86_64-unknown-linux-musl/dist/gino-vmm (static)
cargo build --profile dist --locked
                                   # target/dist/gino-vmm (glibc: libgcc_s, libc, ld-linux)
```

Gates (the CI `vmm` job, run in `gino-vmm/`; it also builds the musl binary and rejects any
`NEEDED` entry):

```sh
cargo fmt --all --check
cargo clippy --release --locked --all-targets
cargo test --release --locked
cargo deny check
cargo shear
```

Warnings are denied through `[lints]` in `Cargo.toml`. Tests need no KVM.

## libkrun

- Dependency: `krun = { package = "libkrun", version = "=1.19.7", git =
  "https://github.com/containers/libkrun.git", rev = "43b2f5aadeebb90f42053c9df2ec8b16583e554f",
  features = ["net"] }`; `net` is what upstream `make NET=1` enables. `src/ffi.rs` calls its
  `krun_*` functions directly, so signatures are checked by the compiler.
- `bzip2` with the `static` feature makes libkrun's bzip2 dependency build from vendored source
  instead of linking the system libbz2 (listed in `cargo-shear`'s `ignored`).
- Cargo.lock pins the whole tree; it started from upstream's v1.19.7 lockfile, so crates.io
  versions match upstream's tested set except `libc` 0.2.191 (needed for `statx` on musl).
- [`deny.toml`](deny.toml) allows the libkrun git source and ignores RUSTSEC-2025-0141 (bincode 2,
  unmaintained, transitive via krun-devices -> imago), each with a reason.
- libkrunfw (libkrun's bundled kernel) cannot be loaded by the static binary (musl's static
  `dlopen` always fails), so the spec's `kernel` is required.

### Bumping libkrun

1. Change `rev` and `version` of the `krun` dependency in `Cargo.toml`.
2. Regenerate Cargo.lock (preferably seeded from upstream's lockfile at the new commit) and check
   that `cargo build --locked` passes for both targets.
3. Bump `LIBKRUN_VERSION` (and the test's `LIBKRUN_COMMIT`) in
   [`src/version.rs`](src/version.rs). A unit test asserts that Cargo.lock has the `libkrun`
   entry with that version and commit, so a missed step fails `cargo test`.
4. Re-check the default kernel command line below, run the gates and `vm/smoke.sh`.

### Sizes

| Artifact | Bytes |
| --- | ---: |
| before: `gino-vmm` (dist, loaded libkrun at run time) | 470,368 |
| before: `libkrun.so.1.19.7` (`make NET=1`), deployed next to it | 5,315,056 |
| after: `gino-vmm` (musl dist, libkrun compiled in) | 3,104,640 |

## Process behaviour

1. `PR_SET_PDEATHSIG(SIGKILL)`, then exits if the parent already changed. The signal fires when
   the parent *thread* that spawned `gino-vmm` exits, so spawn it from a long-lived thread.
2. Reads the spec line from stdin without reading past its newline, parses and validates it, and
   checks that the host directories (`rootDir`, share `hostPath`s) and files (kernel, initramfs,
   overlay files) exist.
3. Builds the libkrun context and calls `krun_start_enter`.

TSI is always disabled: `krun_disable_implicit_vsock` + `krun_add_vsock(ctx, 0)`. The guest's
only network path is the optional virtio-net device.

The guest console is the implicit libkrun console on the inherited stdin (after the spec line),
stdout and stderr. `consolePorts` add named ports on a second virtio-console device.

## Probe

```sh
gino-vmm --probe
```

Takes no further arguments (any other argument is a usage error, exit 120). Opens `/dev/kvm`
read-write, then exits without creating a VM context. Reads no stdin. Success prints exactly one
line on stdout and exits 0:

```text
gino-vmm {CARGO_PKG_VERSION} libkrun {LIBKRUN_VERSION}
```

today `gino-vmm 0.1.0 libkrun 1.19.7` (`CARGO_PKG_VERSION` is this crate's version,
`LIBKRUN_VERSION` the compiled-in libkrun release from `src/version.rs`). A failure is one
`gino-vmm: …` line on stderr (`gino-vmm: /dev/kvm: <error>` when KVM is not accessible) and exit
120. The agent runs it to decide whether `vm` isolation is available; the line format is an
interface contract.

## Exit codes

| Code | Meaning |
| --- | --- |
| guest status | `krun_start_enter` does not return: libkrun exits the process with the workload's status when the VM shuts down |
| 120 | `gino-vmm` failed before the VM started (bad spec, missing host path, usage, `/dev/kvm` access in `--probe`, or libkrun configuration error); the reason is one `gino-vmm: …` line on stderr, after any libkrun error log lines |
| 125 / 126 / 127 | libkrun's init in the guest: cannot set up the environment / cannot execute / cannot find `exec.path` |

## Run spec

One compact JSON object on the first line of stdin (`deny_unknown_fields` at every level;
camelCase keys; a spec carrying the removed `libkrunPath` is rejected as an unknown field).
Everything after the newline is guest console input.

```json
{
  "kernel": {
    "path": "/opt/gino/vm/vmlinux",
    "format": "elf",
    "initramfs": "/opt/gino/vm/initrd.img"
  },
  "rootDir": "/run/gino/r1/boot",
  "shares": [
    { "tag": "work", "hostPath": "/var/lib/gino/threads/t1/work", "readOnly": false },
    { "tag": "skills", "hostPath": "/var/lib/gino/skills", "readOnly": true }
  ],
  "overlayFiles": [
    { "hostPath": "/usr/local/bin/gino-agent", "guestPath": "/gino-agent" }
  ],
  "disks": [
    { "id": "root", "path": "/run/gino/r1/root.qcow2", "format": "qcow2", "readOnly": false }
  ],
  "vcpus": 2,
  "memoryMib": 2048,
  "exec": {
    "path": "/gino-agent",
    "args": ["guest-init"],
    "env": { "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/root" },
    "workdir": "/"
  },
  "vsockPorts": [
    { "port": 5000, "hostSocketPath": "/run/gino/r1/agent.sock", "listen": false }
  ],
  "net": { "unixstreamPath": "/run/gino/r1/net.sock", "mac": "5a:94:ef:e4:0c:ee" },
  "consolePorts": [ { "name": "gino-ctl", "inFd": 3, "outFd": 4 } ]
}
```

| Field | Type | Required | libkrun call | Rules |
| --- | --- | --- | --- | --- |
| `kernel` | object | yes | `krun_set_kernel` | libkrunfw's bundled kernel is not available |
| `kernel.path` | string | yes | | absolute, existing file |
| `kernel.format` | enum | yes | | `raw` (0), `elf` (1), `pe_gz` (2), `image_bz2` (3), `image_gz` (4), `image_zstd` (5) = `KRUN_KERNEL_FORMAT_*` |
| `kernel.initramfs` | string | no | | absolute, existing file |
| `kernel.cmdline` | string | no | | no NUL; absent: libkrun's default (see *Kernel command line*) |
| `rootDir` | string | yes | `krun_set_root` | absolute, existing directory; virtiofs tag `/dev/root`, read-write |
| `shares[]` | array | no | `krun_add_virtiofs3` | no DAX window |
| `shares[].tag` | string | yes | | non-empty, unique, not `/dev/root` |
| `shares[].hostPath` | string | yes | | absolute, existing directory |
| `shares[].readOnly` | bool | no (false) | | |
| `overlayFiles[]` | array | no | `krun_fs_add_overlay_file` | file content is read into memory at start |
| `overlayFiles[].hostPath` | string | yes | | absolute, existing file; mode bits copied |
| `overlayFiles[].guestPath` | string | yes | | `/<name>`, unique: top level of the root filesystem only (libkrun 1.19 places overlay files in a virtual tree whose directories would hide the real ones) |
| `disks[]` | array | no | `krun_add_disk3` | virtio-blk, in order: the first is `/dev/vda`; synchronous flushes, no direct I/O |
| `disks[].id` | string | yes | | non-empty, unique, at most 20 bytes (the virtio-blk serial) |
| `disks[].path` | string | yes | | absolute, existing file; a qcow2 image's backing chain is opened too |
| `disks[].format` | enum | yes | | `raw` (0), `qcow2` (1) |
| `disks[].readOnly` | bool | no (false) | | |
| `vcpus` | integer | yes | `krun_set_vm_config` | 1..=32 |
| `memoryMib` | integer | yes | `krun_set_vm_config` | 64..=65536 |
| `exec.path` | string | yes | `krun_set_exec` | absolute guest path |
| `exec.args` | string[] | no | `krun_set_exec` | arguments after `argv[0]` |
| `exec.env` | object | no | `krun_set_exec` | name → value; names non-empty without `=` |
| `exec.workdir` | string | no | `krun_set_workdir` | absolute guest path |
| `vsockPorts[]` | array | no | `krun_add_vsock_port2` | |
| `vsockPorts[].port` | integer | yes | | unique |
| `vsockPorts[].hostSocketPath` | string | yes | | absolute |
| `vsockPorts[].listen` | bool | no (false) | | false: guest connects to a host listener at the path; true: libkrun listens there and connects to the guest port |
| `net` | object | no | `krun_add_net_unixstream` | absent: no network device |
| `net.unixstreamPath` | string | yes | | absolute; libkrun connects to it at start; no offload features, no flags |
| `net.mac` | string | yes | | `xx:xx:xx:xx:xx:xx`, unicast, non-zero |
| `consolePorts[]` | array | no | `krun_add_virtio_console_multiport` + `krun_add_console_port_inout` | one extra console device holding all ports |
| `consolePorts[].name` | string | yes | | non-empty, unique; the guest sees it in `/sys/class/virtio-ports/*/name` |
| `consolePorts[].inFd` / `outFd` | integer | yes | | inherited open descriptors (host → guest / guest → host) |

`exec.path`, `exec.args` and `exec.env` names and values reach the guest through the kernel
command line as double-quoted words, so they must not contain whitespace, quotes or backslashes;
such specs are rejected. Pass anything richer through a share (for example a JSON file read by the
guest init).

### Device limit

On x86_64 libkrun 1.19.7 gives each virtio-mmio device one of the legacy IRQs 5..=15, so a VM
has at most 11 devices; more fail at start with `RegisterNetDevice(IrqsExhausted)` (or the
matching device). libkrun always adds a balloon, an RNG and the implicit console; the root
virtiofs, every share, every disk, the vsock device, the network device and the console-port
device take one each.

### Kernel command line

Without `kernel.cmdline`, `gino-vmm` passes NULL to `krun_set_kernel` and libkrun builds its
default command line, which mounts the virtiofs root, starts libkrun's init and carries the
`exec` settings. A given `kernel.cmdline` is passed verbatim and **replaces the whole default
prolog**; it is not appended. A replacement that lacks the virtiofs root or `init=/init.krun`
leaves the guest hanging without output. To extend the default, repeat it; in v1.19.7 it is:

```text
reboot=k panic=-1 panic_print=0 nomodule console=hvc0 rootfstype=virtiofs rw quiet no-kvmapf init=/init.krun
```

Not configurable: TSI (always off), the implicit console (always on stdio), virtio-net offload
features.
