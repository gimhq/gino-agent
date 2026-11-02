# 20261101-1538-config-update-clear Host config updates can clear fields

- **status**: completed
- **priority**: P1
- **owner**: l1-gino
- **createdAt**: 2026-11-01 15:38

## Description

A `config_update` is merged onto the live config with `Config::apply`, which only overwrites:
an absent key and a `null` both mean "keep". The host cannot remove a value it set earlier
(an `anthropicBaseUrl`, an API key, a model), so the runner keeps the old endpoint and
credential until a restart rebuilds the config from the bootstrap layers and
`GET /agent/config`.

Acceptance:

- Host config payloads (register `config`, `GET /agent/config`, `config_update.data`) are JSON
  merge patches (RFC 7386) over the host layer: an absent key keeps the host value, `null`
  removes it, an object merges, any other value replaces.
- Removing a host value falls back to the agent's own layers (bootstrap, env, the local
  `gino-agent login` token) or the default, without a restart; the next engine run uses it.
- Existing partial updates (`remoteOps`, `executor`, `entries` + `version`) behave as before.
- protocol.md and agent-architecture.md state the semantics.

## ActiveForm

Letting host config updates clear fields

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

Plan: [20261101-1538-config-update-clear](../plan/20261101-1538-config-update-clear.md)

- complete: host config payloads are merge patches over a separate host layer; null clears and falls back to the agent's own value
