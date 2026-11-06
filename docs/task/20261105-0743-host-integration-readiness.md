# 20261105-0743-host-integration-readiness Single agent source and host integration readiness

- **status**: in_progress
- **priority**: P1
- **owner**: gino-main-session
- **createdAt**: 2026-11-05 07:43

## Description

An external host (bks) integrates against an agent copy that differs from `gimhq/gino-agent`.
Make one released agent the only integration target and close the contract gaps it found.

Acceptance:

1. `gimhq/gino-agent` is the single source: the runner-settings change from `a476843` is in it,
   its VM and engine changes reach the other copy, and a `v*` release is published from it.
2. protocol.md section 8 is regenerated and matches the prose, including `defaults`,
   `configVersion`, `usage`, the new config fields and heartbeat `engines`.
3. A host may send a monotonic `version` on every overlay. The runner reports it as applied
   whether or not the overlay carries `entries`, and absent `entries` never clears the
   provisioned set, at runtime or on restart.
4. A codex authentication failure reports `agent.provider_auth`.
5. Joint testing needs no monorepo checkout: a released artifact provides the agent with fake
   engines.

## ActiveForm

Consolidating the agent source and closing host integration gaps

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261105-0743-host-integration-readiness](../plan/20261105-0743-host-integration-readiness.md). Item 1 waits on locating `a476843`.
