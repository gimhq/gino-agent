# 20261110-1039-bks-runner-parity Runner settings, telemetry and exclusive file operations for bks

- **status**: completed
- **priority**: P1
- **owner**: gino-main-session
- **createdAt**: 2026-11-10 10:39

## Description

bks needs these runner features in a gino-agent release it can run unmodified. gino and
gino-agent are independent repositories that share only the protocol.

Acceptance:

1. Host-settable
   `engine.{fallbackModel, maxTurns, env, mcpServers}` with `null` clearing; `task_upsert`
   `engine` / `model` accept `null`; codex task skills through a per-thread `CODEX_HOME`;
   `thread_result.{engine, model, usage}`; `defaults` on register and heartbeat; claude auth
   failures as `agent.provider_auth`.
2. Exclusive `fs_request put`.
3. New: exclusive `fs_request rename` (`RENAME_NOREPLACE`, `link` + `unlink` fallback for
   files, `invalid` for directories).
4. Kept from v0.2.0: `CODEX_API_KEY`, `-c openai_base_url`, codex `provider_auth`,
   `configVersion` semantics, the test image. `CODEX_API_KEY` joins the `engine.env` deny list.
5. protocol.md §3, §5, §5.1 and §8 cover every field; `tests/protocol_schema.rs` checks them.
6. The fake engines in `e2e/` accept the new claude flags and emit `usage`.
7. Changelog entry and release `v0.3.0` with the binary and the test image.

## ActiveForm

Porting runner settings and exclusive file operations for bks

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261110-1039-bks-runner-parity](../plan/20261110-1039-bks-runner-parity.md). Supersedes the open items of
`20261105-0743-host-integration-readiness`.

- complete: released in v0.3.0
