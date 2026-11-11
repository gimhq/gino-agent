# 20261111-1000-engine-models-auth Engine model lists, auth status and per-engine defaults

- **status**: completed
- **task**: [20261111-1000-engine-models-auth](../task/20261111-1000-engine-models-auth.md)

## Decisions

- The probe asks the CLIs, as the latest bkd does: claude answers the stream-json `initialize`
  control request with `models` and `claude auth status --json` with `loggedIn`; `codex
  app-server` answers `model/list` (paged) and `account/read`. Approved by the user 2026-11-11.
- The agent reports the CLI's list unfiltered. Filtering, `[1m]` variants and model validation
  are host policy; the agent passes a requested model through unchanged.
- Additive protocol change; `protocolVersion` stays 1.

## Proposal

1. `engine/probe.rs`: pure parsers (claude init models, auth status JSON, codex `model/list`
   and `account/read`) with unit tests, and bounded probes (15 s) over the engine's run env.
2. `EngineInfo` gains `auth`, `models`, `defaultModel`, `baseUrlHost`; the heartbeat engine list
   becomes updatable. Probe after the host config is applied, after a `config_update` that changes
   the probe inputs, and hourly.
3. `config.engine.defaultEngine`; the executor falls back to it; `defaults` follows it.
4. e2e fakes: `auth status --json`, the init probe, `app-server` with `initialize`,
   `account/read` and `model/list`; signed in only when a credential is configured.
5. mini-host: engine and model checks on task create and PATCH.
6. Joint scenario, agent e2e test, docs, schema, changelog; gates, joint suite, release 0.3.1.

## Risks

- The probe spawns the CLIs outside the sandbox, as the `--version` probe already does.
- A probe that hangs must not block heartbeats: it runs in a background task with a timeout.

## Completion Summary

All six steps landed; joint suite 14/14 against agent 0.3.1. One addition: a configured key
counts as signed in even when the CLI reports no login, because `codex exec` reads
`CODEX_API_KEY` while `codex app-server` does not.
