# 20261110-1130-mini-host-full-protocol Reference host covering the whole protocol

- **status**: completed
- **createdAt**: 2026-11-10 11:30
- **approvedAt**: 2026-11-10 11:30
- **relatedTask**: 20261110-1130-mini-host-full-protocol

## Decisions

- 2026-11-10: mini-host is the reference other hosts build on. It covers the whole protocol, and
  the v0.3.0 release waits for the joint suite (scope 1–7, option A).

## Context

mini-host is one 1 000-line `lib.rs`: register, config fetch, output fallback, the WebSocket with
replay, tasks, messages, interrupt, crons and transcripts. It drops `config_update`, `close`,
`fs_*`, `pty_*`, every `e2ee_*` frame, the byte channel, provisioning and the new heartbeat and
`thread_result` fields. The agent's own tests cover these against an in-test stub host, never
against a host other projects copy.

## Proposal

Split the crate into modules and add each surface with an operator route and a joint scenario.

1. Structure: `store` (schema), `agent` (register, config, output, socket, frame dispatch),
   `api` (operator routes), then one module per surface below.
2. Config: per-agent host config layer (engine options, `remoteOps`, executor, isolation) with a
   monotonic `version`; operator patches merge (RFC 7386) and push `config_update`. Store and show
   heartbeat `capabilities`, `engines`, `e2ee`, `configVersion`, `defaults`.
3. Results: store `thread_result` `engine`, `model`, `usage`, `encryption_error`, `attachments`.
4. Byte channel: `GET /agent/attachments/{id}`, `GET /agent/attachments?sha256=`,
   `POST /agent/attachments`; operator upload of message attachments and download of result
   attachments.
5. Provisioning: operator artifacts (file or tar dir) with global `entries` (versioned through
   config) and task `entries` on `task_upsert`.
6. File operations: `POST /api/agents/{id}/fs` sends a live `fs_request` and waits for the
   `fs_response`; `put` stages bytes as a single-use ref, `get` reads the upload back.
7. Terminals: `GET /api/agents/{id}/pty` WebSocket bridge (`open`/`ready`/`input`/`output`/
   `resize`/`close`/`exit`), with the §5.2 limits.
8. End-to-end encryption with `gino-e2ee`: key directory pinning, KeyPackage verification and
   pool with `e2ee_key_package_status`, per-task DS log, `e2ee_log`/`e2ee_welcome` delivery,
   `e2ee_request` ops, the `runner_without_encryption` refusal, and an operator-side client
   device that creates the group, adds the runner, seals messages and opens results.
9. Joint suite: `gino-mini-host/tests/joint.rs` starts mini-host in-process and the real agent
   binary with the `e2e/` fake engines (ignored unless `GINO_AGENT_BIN` is set), plus
   `scripts/joint-it.sh` for the release image. One scenario per surface: loop and ordering,
   codex, reconnect replay, interrupt, attachments, crons, global and task provisioning,
   config_update with version and defaults, engine options reaching the engine, null clears,
   usage, every fs op incl. exclusive races, terminals, an encrypted task end to end.
10. Docs: crate docs, `docs/host-quickstart.md`, protocol.md corrections, changelog.

Verification per step: fmt, clippy, deny, shear and tests for mini-host; the joint scenario of the
step against the release-built agent. Before release: the full joint suite in CI and locally.

## Risks

- e2ee DS is the largest piece; the TypeScript `sdks/e2ee` relay is the behavioural reference.
- Joint scenarios must stay deterministic: fake engines only, bounded waits.

## Completion Summary

All ten steps landed. The joint suite passes 13/13 against gino-agent 0.3.0, and the mini-host
gates pass. Two deviations from the proposal:
- The runner never commits its own Update (optional in v1), so the DS `commit` path is covered
  by `tests/e2ee_ds.rs` with a simulated runner instead of a joint scenario.
- CI runs the joint suite against the static musl release build (an artifact of `agent-musl`).
