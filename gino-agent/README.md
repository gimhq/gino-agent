# gino-agent

The gino data plane: a daemon that enrolls with a host, keeps one outbound WebSocket open, and
runs tasks by driving an engine CLI (`claude` or `codex`). It owns scheduling, execution, retry
and local state (SQLite), and keeps firing crons while the host is unreachable.

Design: [`../docs/agent-architecture.md`](../docs/agent-architecture.md). Wire contract:
[`../docs/protocol.md`](../docs/protocol.md).

## Build and run

Rust 1.96 (pinned in `rust-toolchain.toml`). A C compiler is needed for the bundled SQLite and the
aws-lc-rs crypto provider.

```bash
cargo build --release
GINO_HOST_URL=https://gino.example.com/api \
GINO_REGISTER_TOKEN=<enrollment token> \
./target/release/gino-agent run
```

`GINO_HOST_URL` is the base the agent appends `/agent/*` to. Everything except the bootstrap
inputs below is assigned by the host at registration.

| variable | flag | purpose |
|---|---|---|
| `GINO_HOST_URL` | `--host` | host base URL |
| `GINO_REGISTER_TOKEN`, `GINO_REGISTER_TOKEN_FILE` | `--register-token` (deprecated: visible in argv) | enrollment token, used only to register |
| `GINO_AGENT_NAME` | `--name` | human-readable agent name |
| `GINO_WORKSPACE_DIR` | — | workspace root |
| `GINO_DB_PATH` | — | SQLite database file |
| `GINO_ALLOW_REMOTE_OPS_WITH_E2EE` (`1`/`true`) | `--allow-remote-ops-with-e2ee` | serve the host's remote operations while the runner holds an end-to-end encrypted task (off by default) |

While the runner is a member of any end-to-end encrypted task's group, `fs_request` answers
`denied` and `pty_open` ends with `pty_exit` `denied`, whatever the host's `remoteOps` enables;
terminals opened before the join are closed with `denied` at the next heartbeat. Only the local
opt-in above lifts this (it logs a warning at startup); no host config can set it.

`RUST_LOG` sets log filtering; otherwise `-v` selects debug and `-vv` trace. Logs go to stderr.

## Commands

| command | purpose |
|---|---|
| `run` (default) | run the daemon |
| `system` (alias `info`) | print identity, version, host, paths and live counts |
| `cron create\|list\|pause\|resume\|delete` | manage this agent's scheduled triggers |
| `task list\|show`, `thread list\|show` | inspect tasks and execution threads |
| `login` | mint and store a Claude OAuth token via `claude setup-token` |
| `archive` | PreCompact hook target: archive a transcript read from stdin |

Inside a running task the engine reaches the same CLI through `$GINO_RUNNER_BIN`; see
[`../skills/gino/SKILL.md`](../skills/gino/SKILL.md).

## Source map

| module | role |
|---|---|
| `lib.rs` | CLI and subcommand dispatch |
| `runner.rs` | daemon wiring, inbound frame handling, shutdown |
| `transport/` | reconnecting WebSocket client, HTTP client, outbox flush |
| `protocol.rs` | wire envelopes |
| `db.rs` | SQLite schema, migrations, queries |
| `scheduler.rs` | cron timing loop, fire ledger, queue GC |
| `executor.rs`, `chat.rs` | thread execution, retry, inbound message threading |
| `engine/` | the `Engine`/`Session` abstraction with `claude` and `codex` backends |
| `attachments.rs`, `attachment_source.rs` | the out-of-band byte channel and its cache |
| `provisioning/` | content-addressed store and reconcile for config and skills |
| `remote_ops/` | host-driven file operations and PTY sessions without an engine (each group defaults off) |
| `register.rs`, `config.rs`, `login.rs` | enrollment, layered config, credentials |
| `archive.rs`, `gino_cli.rs` | the `archive` hook and the operator CLI |

## Quality gates

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets
cargo test --locked
cargo deny check
cargo shear
```

Lint policy is in `Cargo.toml`: `unsafe` is forbidden, warnings are errors, and
`unwrap`/`expect`/`panic` are denied outside tests. `tests/e2e.rs` runs the daemon against a stub
host and fake engines; `../gino-mini-host` is a minimal reference host to drive a real agent by
hand.
The privileged engine isolation suites run in sibling containers: `scripts/sandbox-it.sh`
(bubblewrap sandbox) and `scripts/vm-it.sh` (`vm` mode, needs `/dev/kvm`; see
`../docs/agent-architecture.md` §9e).
