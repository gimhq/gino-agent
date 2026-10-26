# 20261027-0613-engine-install-update Engine install and update

- **status**: completed
- **priority**: P1
- **owner**: l1-gino
- **createdAt**: 2026-10-27 06:13

## Description

Add `gino-agent engine status|install|update` that installs and updates claude and codex through
their official install and update commands into an agent-owned engine dir, resolve engines from
that dir first, report engine versions to the host, and share the dir read-only into `vm` guests
instead of baking claude into the rootfs.

Acceptance:

- `engine install claude [--version <v>|--channel stable|latest]` and `engine install codex` place
  working binaries under the engine dir; `engine update` upgrades them; `engine status` prints the
  resolved path and version of each engine.
- Runs use the engine dir binaries when present, else `PATH`; claude runs with
  `DISABLE_AUTOUPDATER=1`.
- `register` and `heartbeat` carry engine versions (additive protocol field).
- Optional `engine.autoUpdate` updates idle engines on an interval; off by default.
- `vm` runs execute the shared engine dir; the rootfs no longer pins claude.

## ActiveForm

Adding engine install and update

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261027-0614-engine-install-update](../plan/20261027-0614-engine-install-update.md)

- complete: engine status/install/update, resolution, DISABLE_AUTOUPDATER, heartbeat engines, VM engine share; autoUpdate deferred
