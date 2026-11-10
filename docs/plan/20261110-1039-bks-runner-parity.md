# 20261110-1039-bks-runner-parity Runner settings, telemetry and exclusive file operations for bks

- **status**: in_progress
- **createdAt**: 2026-11-10 10:39
- **approvedAt**: 2026-11-10 11:00
- **relatedTask**: 20261110-1039-bks-runner-parity

## Decisions

- 2026-11-10: gino and gino-agent are independent repositories that share only the protocol.
  gino-agent implements these features against `docs/protocol.md`, which it maintains with the
  §8 schema. The monorepo code is a reference only: nothing is synced back, and commits here do
  not cite monorepo commits.

## Context

- Source: monorepo `a98236e`, 10 commits from base `3ceec66`, about 2.3k lines. Its plan
  (`docs/plan/20261102-1200-bks-runner-settings.md` there) and tests are the reference.
- The monorepo base and this repo's import already differ (33 files in the agent crate), and
  v0.2.0 added more. A trial `git am -3` on `main`: only the first commit applies cleanly, the
  other nine conflict in `config.rs`, `protocol.rs`, `runner.rs`, the engines and `protocol.md`.
- Three items solve problems v0.2.0 already solved, in different ways:
  - Null clears: the monorepo uses a tri-state `Patch<T>` with a local snapshot; v0.2.0 uses an
    RFC 7386 host layer (`LayeredConfig`). The clean-applying first commit would add the second
    mechanism next to the first.
  - `configVersion`: the monorepo reports the last merged version; v0.2.0 holds it back until
    `entries` reconcile, and bks asked to keep that.
  - Auth: the monorepo classifies claude from structured fields; v0.2.0 classifies codex from
    the client's anchored 401/403 prefix. Both use `RunErrorKind::Auth`.
- The monorepo's §8 schema never got the runner-settings fields (only `exclusive`); its fake
  engines neither accept the new flags nor emit `usage`.
- `fs_request rename` calls `std::fs::rename`, which replaces `to`.

## Proposal

Implement by feature on the v0.2.0 structure, with the monorepo as a reference. Each step adds
its tests first and lands as one commit.

1. Task-level null: `task_upsert.{engine, model}` as absent / null / value. Config-level null
   stays on `LayeredConfig`; the new `engine` fields get null clearing through it.
2. Claude auth from `assistant.error` / `result.api_error_status`, next to the codex prefix rule.
3. `thread_result.{engine, model, usage}` from the claude `result` and codex `turn.completed`.
4. `defaults {engine, model?, baseUrlHost?}` on register and every heartbeat, recomputed after
   each config merge; `configVersion` keeps the v0.2.0 rule.
5. `engine.fallbackModel`, `engine.maxTurns`, `engine.env` (deny list plus `CODEX_API_KEY`),
   `engine.mcpServers` (claude `--mcp-config`, codex `-c mcp_servers.<name>.*`).
6. Codex task skills through a per-thread `CODEX_HOME`, with the monorepo's follow-up that
   sandboxed task skills only join links resolving into the workspace store.
7. Exclusive `put` with `link(2)`.
8. Exclusive `rename` with `rustix::fs::renameat_with(RENAME_NOREPLACE)`; on `EINVAL`, `link` +
   `unlink` for a regular file, `invalid` for a directory. Tests: concurrent renames onto one
   `to` have one winner; a file, directory or dangling symlink at `to` answers `exists`.
9. protocol.md §3, §5, §5.1 and a hand-maintained §8, the source of the schema now that this repo
   owns the protocol; `tests/protocol_schema.rs` also checks the new fields.
10. `e2e/` fakes accept `--fallback-model`, `--max-turns`, `--mcp-config` and emit `usage`.
11. Version 0.3.0, changelog, then the release as for v0.2.0.

Verification per step: fmt, clippy, unit tests, e2e. Before the release: deny, shear,
`sandbox-it.sh`, `vm-it.sh`, and a joint run of the test image against `gino-mini-host`.

## Risks

- The per-thread `CODEX_HOME` changes where codex reads auth, config and sessions; resume
  across the change depends on the shared `sessions/` symlink.
- `engine.env` and `mcpServers` widen what a host can inject; the deny list is the boundary.
- Claude `assistant.error` exists only in some CLI builds; without it the failure stays
  `agent.unknown`.
- Hand-maintained §8 can drift; the schema test covers frames and the listed fields, not every
  type.

## Scope

- In: `gino-agent/src`, its tests, `e2e/`, `docs/protocol.md`, `docs/agent-architecture.md`,
  `docs/host-quickstart.md`, changelog, release.
- Out: bks code, `gino-mini-host` features, the private monorepo.

## Alternatives

- Cherry-pick the ten commits and resolve conflicts: keeps their authorship, but leaves two
  null-clear mechanisms and two `configVersion` rules to untangle afterwards.
