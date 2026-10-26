# gino-agent

The gino agent (data plane): a self-contained runner daemon that enrolls with a host, keeps one
outbound WebSocket open and runs tasks by driving an engine CLI (`claude` or `codex`), with
optional sandbox or microVM isolation and end-to-end encrypted task content.

This repository is the complete, self-deliverable agent side: the daemon, its isolation tooling,
the end-to-end encryption core and the full wire contract. Any host that implements
[`docs/protocol.md`](docs/protocol.md) can drive the agent.

## Layout

| path | contents |
|---|---|
| [`gino-agent/`](gino-agent/README.md) | the runner daemon (Rust) |
| `gino-e2ee/` | end-to-end encryption core (Rust; MLS groups, envelopes, field maps), also built to wasm |
| [`sdks/e2ee/`](sdks/e2ee/README.md) | `@gino/e2ee`, the only TypeScript in the repository (a standalone Bun package): the SDK over the gino-e2ee wasm build — the client helpers and, as `@gino/e2ee/ds`, the host's key directory and Delivery Service — plus the field-map generator (`scripts/gen-field-map.ts`, writes the Rust and TypeScript field maps from `docs/e2ee/*.fieldmap.json`) |
| [`gino-vmm/`](gino-vmm/README.md), [`vm/`](vm/README.md) | the microVM launcher and the guest kernel / root image builds for `vm` isolation |
| `gino-mini-host/` | a minimal reference host (Rust): enrollment, dispatch, transcripts, crons |
| [`skills/gino/`](skills/gino/SKILL.md) | the skill engines use to reach the agent's local CLI |
| `docs/` | the specifications (below) |

## Specifications

- [`docs/protocol.md`](docs/protocol.md) — the host ⇄ agent wire protocol, with the normative frame
  JSON Schema (§8).
- [`docs/agent-architecture.md`](docs/agent-architecture.md) — the agent's architecture.
- [`docs/e2ee/spec.md`](docs/e2ee/spec.md) — the end-to-end encryption framework, with the
  [`task-content`](docs/e2ee/task-content.md) profile, its field map and test vectors.

## Quick start

Build the agent and drive it with the reference host (Rust 1.96 and a C compiler):

```bash
(cd gino-mini-host && cargo run --release)      # listens on 127.0.0.1:3100, register token "dev"

cd gino-agent && cargo build --release
GINO_HOST_URL=http://127.0.0.1:3100 GINO_REGISTER_TOKEN=dev ./target/release/gino-agent run

curl -X POST localhost:3100/api/tasks -d '{"taskId":"demo"}'
curl -X POST localhost:3100/api/tasks/demo/messages -d '{"text":"hello"}'   # → threadId
curl "localhost:3100/api/threads/<threadId>/wait"
```

See [`gino-agent/README.md`](gino-agent/README.md) for the agent's configuration and commands, and
[`gino-mini-host/src/lib.rs`](gino-mini-host/src/lib.rs) (API) and [`src/main.rs`](gino-mini-host/src/main.rs)
(settings) for the reference host.

## Quality gates

| scope | commands |
|---|---|
| `gino-agent/`, `gino-e2ee/`, `gino-vmm/`, `gino-mini-host/` | `cargo fmt --all --check`, `cargo clippy --release --locked --all-targets`, `cargo nextest run --release --locked`, `cargo deny check`, `cargo shear` (agent also `typos` and `cargo hack check --rust-version`) |
| `sdks/e2ee/` (in that directory) | `bun install`, `bun run check`, `bun run gen:field-map --check` |
| `sdks/e2ee/` wasm | `bun run check:wasm` in the image from `gino-e2ee/docker/wasm.Dockerfile` |

CI runs all of them (`.github/workflows/ci.yml`).

## License

[Apache License 2.0](LICENSE).
