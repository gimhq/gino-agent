# 20261027-0614-engine-install-update Engine install and update

- **status**: completed
- **createdAt**: 2026-10-27 06:14
- **approvedAt**: 2026-10-27 06:30
- **relatedTask**: 20261027-0613-engine-install-update

## Context

- Engines resolve on `PATH`: claude defaults to `claude`, codex to `engine.codex.binary` or
  `codex`. The CLI (`src/lib.rs`) has no engine management; nothing reports engine versions.
- The VM rootfs pins claude 2.1.308 by sha256; codex is not in the guest.
- Official commands: claude `curl -fsSL https://claude.ai/install.sh | bash [-s stable|latest|<v>]`
  and `claude update` (`DISABLE_AUTOUPDATER=1` stops only the background check); codex
  `curl -fsSL https://chatgpt.com/codex/install.sh | sh`, `codex update` on recent versions, or
  `npm install -g @openai/codex@<v>`.

## Proposal

- **Engine dir**: `<workspace>/engines/` with `HOME`-scoped installs: the installers run with
  `HOME=<workspace>/engines/home` (claude's native installer writes `~/.local/bin/claude` and
  `~/.local/share/claude/versions/<v>`; codex's script gets its install dir env). Resolution order
  per engine: configured explicit binary, the engine dir, `PATH`.
- **CLI**: `gino-agent engine status [claude|codex]`, `engine install <engine> [--version <v> |
  --channel stable|latest]`, `engine update [<engine>]`. Each runs the official command with the
  engine dir env, streams its output, then verifies with `<binary> --version`. A failing command
  exits non-zero with its status; no retries.
- **Runtime**: claude runs with `DISABLE_AUTOUPDATER=1`, so only the agent updates it; an update
  takes effect on the next run (running engines keep their binary; versioned install dirs).
- **Auto update** (optional): `engine.autoUpdate: { enabled, intervalHours }`, default off; runs
  `update` when no run uses that engine, logs the result, never during a run.
- **Version report**: `register`/`heartbeat` gain `engines: [{ name, version, path }]` — additive
  (`docs/protocol.md` §3 and the frame schema); hosts ignore unknown members.
- **VM**: the engine dir is shared read-only into the guest at the same path and prepended to the
  guest `PATH`; the rootfs stops pinning claude. The guest needs a glibc build of the engine (the
  host install must be a glibc host; a musl host's claude is rejected at probe with a clear error).
- **Docs**: §9c engine resolution, the CLI section, protocol field, README.

## Risks

- The installers fetch remote scripts over HTTPS at the operator's command; nothing runs them
  implicitly except the opt-in auto update.
- The installers' layout may change; verification by `--version` catches a broken install.
- Network sandboxes: install/update run unsandboxed as the daemon user, outside any run.

## Scope

New `engine_admin` module and CLI wiring, engine resolution in claude/codex backends, config
(`engine.autoUpdate`), register/heartbeat frames and protocol docs, sandbox/vm share, rootfs
Dockerfile, tests (command construction, resolution order, version parsing, frame field).

## Alternatives

- Pinning engine versions in config and downloading by checksum: reproducible, but duplicates the
  vendors' installers; the official commands were requested.
- Letting the engines self-update: races with running engines and breaks the read-only VM share.

## Implementation notes

- Module `engine::admin` (not a top-level `engine_admin`); the engine home is
  `<workspace>/engines/home`, binaries in its `.local/bin` (both installers honour `HOME`; codex
  also needs `CODEX_NON_INTERACTIVE=1`). `update` runs `claude update` and reruns the codex
  installer.
- `engines` rides on the heartbeat only: register is sent once per enrollment, so a restart would
  never refresh it there. It is probed once in the background at startup (a stuck engine must not
  delay the daemon); earlier heartbeats omit it.
- Not done in this round: `engine.autoUpdate` (optional in the proposal) and the musl-host probe
  check. The heartbeat is serialized once per process, so an in-process update would also leave
  `engines` stale until restart.
- VM: the engine home is shared only when the run's binary is agent-installed, so a VM without one
  keeps its device budget (x86_64 libkrun: 11 devices). The rootfs keeps its claude as the fallback
  on the guest `PATH`; codex installs as a static musl binary and runs in the guest as is.

## Annotations

(none)
