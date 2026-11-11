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

## 2026-11-09 15:00 [progress]

Dependency refresh before 0.2.0: semver-compatible lockfile updates in all four crates, kernel
6.12.116, rootfs claude 2.1.319, CI on Bun 1.4.4, osv-scanner-action 2.7.0 and trufflehog 3.99.8.
Verification: clippy, tests, deny and shear per crate; `sandbox-it.sh` and `vm-it.sh` on the new
kernel and rootfs.

## 2026-11-09 19:45 [progress]

Major upgrades for 0.2.0: Rust 1.99.1, croner 4 with the five-field grammar pinned, rtnetlink 0.24,
openmls 0.9.2, current GitHub Actions majors and @antfu/eslint-config 10. Held back: ed25519-dalek
and aes-gcm (openmls_rust_crypto 0.6 needs the current majors), bzip2 (libkrun needs 0.5) and
TypeScript 7 (typescript-eslint does not support it).
Verification: clippy, tests, deny per crate; `sandbox-it.sh` (17 passed); `vm-it.sh`; wasm drift check.

## 2026-11-10 16:00 [progress]

Agent 0.3.0, the runner settings a host needs to drive both engines. Protocol additions (all
optional and additive; `protocolVersion` stays 1):
- `config.engine.fallbackModel`, `maxTurns`, `env` and `mcpServers`, each cleared with `null`.
  `env` and MCP server env drop a deny list of credential, loader, proxy and runner keys
  (`CODEX_API_KEY` included). MCP servers reach claude as `--mcp-config` and codex as
  `-c mcp_servers.<name>.*`.
- `task_upsert.engine` / `model` accept `null`, which clears them back to the agent default.
- `thread_result.engine`, `model` and `usage` (`inputTokens`, `outputTokens`,
  `cacheReadTokens?`, `costUsd?`).
- `defaults {engine, model?, baseUrlHost?}` on register and every heartbeat, recomputed after
  `config_update`; it never carries a key or a full URL.
- `fs_request` `put` and `rename` take `exclusive: true`: put links into place with `link(2)`,
  rename uses `RENAME_NOREPLACE` (link + unlink for regular files where the filesystem lacks
  it). Anything at the destination, a dangling symlink included, answers `exists`.
Claude authentication failures (`authentication_failed`, API status 401/403) now classify as
`agent.provider_auth`, like codex. Codex runs get a per-thread `CODEX_HOME` whose `skills/`
holds the global and task-scope skills. The §8 schema covers every new field, and the e2e fakes
take the new flags and report usage.
Verification: gino-agent gates (nextest 991 passed), sandbox-it (17 passed) and vm-it (20 passed)
in the bubblewrap image, the §8 schema test, and the joint suite below.

## 2026-11-10 19:30 [progress]

`gino-mini-host` becomes the reference host: it implements the whole protocol, and other hosts
build on it. New: the attachment byte channel in both directions (single-use inbound blobs,
verified uploads), provisioning artifacts and `entries` validation, config as an RFC 7386 merge
patch with a monotonic `version`, `close`, interrupt, crons, file operations
(`POST /api/agents/{id}/fs`), terminals (an operator WebSocket at `/api/agents/{id}/pty`), and
end-to-end encryption: the key directory with pinning and KeyPackage verification, the
Delivery Service (`log`, `log_from_epoch`, `link`, `put_link`, `commit`), an operator client
device that creates the group and seals and opens task content, and refusal of plaintext on an
encrypted task. `wait?after=<runs>` waits for the next turn on a thread.
A joint suite (`tests/joint.rs`, 13 scenarios) runs the real agent binary against it with the
`e2e/` fake engines; CI runs it against the static release build, and
`scripts/joint-it.sh` runs it locally in a container. Protocol §5.2 now describes the operator
side of a terminal as host-private, with the mini-host as the example.
Verification: mini-host gates (nextest 10 passed, clippy, deny, shear), joint suite 13/13
against gino-agent 0.3.0.

## 2026-11-11 15:50 [progress]

Agent 0.3.1: engine model lists, sign-in state and a configurable default engine. Protocol
additions (optional and additive; `protocolVersion` stays 1):
- Heartbeat `engines[]` items gain `auth` (`authenticated` | `unauthenticated` | `unknown`),
  `models` (`[{id, name?, description?, isDefault?}]`), `defaultModel` and `baseUrlHost`. The agent
  asks each CLI with the binary, credentials and config dir of a real run: claude's stream-json
  `initialize` models and `claude auth status --json`; `codex app-server` `model/list` (every page)
  and `account/read`. A configured key counts as signed in. It probes once the host config is
  known, again after a `config_update` that changes an engine's binary, credentials or config dir,
  and hourly. The list is reported unchanged and a requested model is passed through unchanged.
- `config.engine.defaultEngine` (`claude` | `codex`, `null` clears) picks the engine of a task
  that names none; `defaults` follows it, with that engine's configured model or, on heartbeats,
  its CLI's default.
mini-host rejects a task whose engine the agent does not advertise or whose model the agent's
probe did not list (400). The e2e fakes answer both probes, and a joint scenario covers them.
Verification: gino-agent gates (nextest 1001 passed, clippy, deny, shear), the §8 schema test,
mini-host gates (nextest 10 passed, clippy, deny, shear), joint suite 14/14 against gino-agent
0.3.1. sandbox-it and vm-it were not rerun; the change does not touch the sandbox launch path.
