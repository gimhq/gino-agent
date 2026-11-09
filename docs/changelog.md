# Changelog

## 2026-10-26 20:40 [progress]

Initial import of the self-contained gino agent: the runner daemon (`gino-agent/`), the
end-to-end encryption core (`gino-e2ee/`) and its TypeScript package (`packages/e2ee/`), the
microVM launcher and guest builds (`gino-vmm/`, `vm/`), the engine skill (`skills/gino/`), the
reference host (`gino-mini-host/`, Rust) and the normative specifications (`docs/protocol.md`
with the frame JSON Schema, `docs/e2ee/`, `docs/agent-architecture.md`). CI covers every crate,
the TypeScript workspace and the wasm build; the release workflow publishes the agent binary.
gino-vmm: zstd-sys 2.1.2 (RUSTSEC-2026-0410); the zstd 0.13 advisories pinned by libkrun 1.19.7
are ignored with reasons in `deny.toml`.
Verification: gino-agent gates (nextest 939 passed), gino-e2ee (82 passed), gino-vmm (24 passed),
gino-mini-host (5 passed), `check:wasm` in the wasm image, `bun run check`,
`gen:e2ee-field-map --check`, and a smoke run of the real agent against `gino-mini-host`
(register, task, message, thread result).

## 2026-10-26 20:50 [progress]

nsplane v0.19.0 -> v0.19.3: the static musl release build of gino-agent compiles again (14.5 MiB
static binary, 6.2 MiB release tar.gz). The workspace overrides katex to 0.19.1
(GHSA-238p-pmpm-9mq7, via @antfu/eslint-config).
Verification: gino-agent gates (nextest 939 passed), the release's musl `dist` build with no
`NEEDED` entries, `bun run check`.

## 2026-10-26 21:30 [progress]

The TypeScript package moves to `sdks/e2ee/` and gains `@gino/e2ee/ds`, the host side of e2ee:
the key directory and MLS Delivery Service (`E2eeRelay`) over a storage port (`E2eeRepo`, with
an in-memory adapter and the `@gino/e2ee/ds/testing` conformance suite), the zod schemas of the
e2ee wire members, the sealed-form check of mapped fields and the relay errors. A host plugs in
storage, its agent channel and a task lookup; it no longer implements the relay itself.
Verification: `bun run check` (76 tests, including the relay with real MLS material and the
memory repository's conformance), `gen:e2ee-field-map --check`.

## 2026-10-27 00:10 [progress]

The repository root is no longer a Bun workspace: `sdks/e2ee` is a standalone package with its
own lockfile, ESLint and TypeScript configuration, and the field-map generator moves to
`sdks/e2ee/scripts/gen-field-map.ts` (`bun run gen:field-map` in `sdks/e2ee`).
Verification: `bun run check` in `sdks/e2ee` (76 passed), `gen:field-map --check`.


## 2026-10-27 08:00 [progress]

`vm` isolation boots from a block root. The guest root is a raw ext4 base image
(`vm/rootfs/build.sh` writes `rootfs.ext4`, now with Docker Engine 29.9.2, containerd 2.4.2,
buildx, compose, iptables and busybox-static); each run gets a qcow2 overlay over it, created by
the daemon with imago under `<workspace>/vm/disks/` and attached through libkrun's virtio-blk
(gino-vmm `disks`, libkrun `blk` feature). `vmDisk: "task"` keeps one overlay per task across its
runs (single writer, removed with the task, its manifest pins the base); `run` (default) discards
it with the run. guest-init boots from an empty per-run virtiofs dir holding the agent binary and
the control dir, switches to the disk, grows it to `vm.diskGib` (default 32) and, with
`vm.docker`, runs `dockerd` with its socket group set to the engine's gid. The agent binary must
be statically linked for `vm` runs; a dynamically linked one fails before spawn. The control
share is gone (x86_64 libkrun has 11 device slots), and gino-vmm forwards libkrun's error log to
stderr. Guest kernel: virtio-blk, ext4, cgroup controllers, BPF, veth, bridge, tun and the
netfilter/nftables set Docker uses; 31 unused options off (14.03 MB of sections, from 13.8 MB).
Verification: gino-agent lib tests, gino-vmm (25 passed), fmt/clippy/deny/typos/shear on both
crates, `vm/smoke.sh` PASS, `scripts/vm-it.sh` (2 KVM unit tests and all 19 `tests/vm.rs`
scenarios, including `docker run hello-world`), and the host's real-engine
`SANDBOX_MODE=vm` e2e with network none, allowlist and `--claude-memory`.

## 2026-10-27 08:15 [progress]

Engine installs managed by the agent: `gino-agent engine status|install|update` runs the vendors'
official installers (`--version`, or `--channel stable|latest` for claude) with
`HOME=<workspace>/engines/home`. Runs start an explicitly configured binary, else the agent
install, else the engine on `PATH`; claude always runs with `DISABLE_AUTOUPDATER=1`. Heartbeats
carry `engines` (`{name, version?, path}`, protocol §5 and the frame schema). A `vm` run of an
agent-installed engine gets the engine home as a read-only share at its host path.

## 2026-10-27 23:10 [progress]

osv-scanner: GHSA-qwgh-2vcv-g2f7 (block-buffer 0.10.4 via digest 0.10, no fixed 0.10 release) is
ignored with a reason in `gino-agent/osv-scanner.toml`.

## 2026-10-28 01:20 [progress]

VM release channels: `kernel`, `vmm` and `rootfs` release on their own through
`.github/workflows/release-vm.yml` (`vm/release.sh`) as the lode resources `gino-agent/<channel>`:
`<channel>.<YYYYMMDD-HHMM>` releases (lode version `YYYY.MMDD.HHMM`), kernel and vmm only when
their inputs change, the rootfs rolling weekly and released when its packages change; every run
boot-checks all three with `vm/smoke.sh`, publishes with `--latest=false` and updates the
channel's signed `lode/v1` manifest on the rolling `<channel>-manifest` release. `release.yml`
builds only `v*` tags; lode-cli v0.4.0. The agent's `vm.kernel` / `vm.rootfs` / `vm.vmm` fall back
to `LODE_RESOURCE_<NAME>` (agent-architecture §9e).
Verification: agent fmt, clippy, deny, shear, nextest (954 passed); actionlint, shellcheck; local
`lode-cli pull` (enforced signatures) of the three real assets, byte-identical to the builds.

## 2026-11-02 00:30 [progress]

Host config updates can clear fields: the runner keeps its own config apart from the host layer,
the RFC 7386 merge patch of the register `config`, `GET /agent/config` and each `config_update`
(`LayeredConfig`). A `null` removes the host's value and the runner's own value (e.g. the local
login token) or the default applies to the next engine run without a restart; before, a removed
endpoint or key stayed live until restart. protocol §3 and agent-architecture describe it.
Verification: fmt, clippy, typos, nextest (958 passed), with a reproducing runner test.

## 2026-11-06 09:30 [progress]

Host integration readiness. A config overlay may carry `version` with or without `entries`:
absent `entries` no longer clears the global set on restart, and heartbeats report the last
applied version as `configVersion`, held back while the overlay's desired set is not in place.
Codex runs now receive `CODEX_API_KEY` and `-c openai_base_url=...`, because `codex exec` ignores
`OPENAI_API_KEY` and `OPENAI_BASE_URL`. A codex 401 or 403 reports `agent.provider_auth`. Releases
publish a test image with fake engines from the new `e2e/`.
Verification: fmt, clippy, unit tests (917 passed), e2e (29 passed); real codex-cli against a local
401/403 endpoint. Not run: the `test-image` job and a joint run against a real host.

## 2026-11-06 09:45 [progress]

External hosts get `docs/host-quickstart.md`, walked through with `gino-mini-host` and the test
image (fake claude and codex). Section 8 of the protocol is regenerated with `configVersion`, and
`gino-agent/tests/protocol_schema.rs` now checks it against the runner's frames in this repo.

## 2026-11-09 12:30 [progress]

nsplane 0.22.1 replaces 0.19.3: admission moves to `NetStackConfig`, and the exit rejects a flow
of a protocol it does not know. The sandbox suite's fake engine now ignores `--version`, because the
daemon's startup probe ran its write probe outside the sandbox. Agent version 0.2.0.
Verification: fmt, clippy, deny, unit tests (917 passed), e2e (29 passed), `sandbox-it.sh` (17
passed), `vm-it.sh` (all scenarios passed).

## 2026-11-09 13:40 [progress]

rusqlite 0.41 brings bundled SQLite past RUSTSEC-2026-0459. `agent_api` tests that start a server
now run one at a time, because they share the process-wide `RUNNING` handle.
Verification: fmt, clippy, deny, shear, all test targets, 12 repeated runs of `agent_api::tests`.
