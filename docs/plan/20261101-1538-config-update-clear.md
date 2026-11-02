# 20261101-1538-config-update-clear Host config updates can clear fields

- **status**: completed
- **createdAt**: 2026-11-01 15:38
- **approvedAt**: 2026-11-02 00:00
- **relatedTask**: 20261101-1538-config-update-clear

## Context

- `Config::apply` (`gino-agent/src/config.rs`) merges a `ConfigOverlay` field by field with
  `overlay_field` / `overlay_secret`: `Some` overwrites, `None` keeps. Every overlay field is
  `Option<T>`, so a JSON `null` and an absent key both deserialize to `None`.
- The same merge serves every layer: bootstrap/env, the local login token, the register
  `config`, `GET /agent/config` at startup (`fetch_and_apply_config`) and the live
  `config_update` (`apply_config_update` -> `apply_engine_config`, which then rebuilds the
  claude and codex settings for the next run).
- So the host can change a value but never remove one: dropping `engine.anthropicBaseUrl`, an
  API key or a model leaves the old one live until a restart rebuilds the config from the
  bootstrap layers plus a fresh `GET /agent/config`.
- The host sends partial updates today (`{remoteOps}`, `{executor}`, `{entries, version}`);
  `config_update.data` is opaque to host-core, so SDK embedders may send engine settings.

## Proposal

1. **Host layer as a merge patch.** The runner keeps the agent's own config (`base`: bootstrap,
   env, local login token, the identity pins) apart from the host layer, a JSON object built by
   RFC 7386 merge patch from the register `config`, the startup `GET /agent/config` and each
   `config_update.data`: absent keeps, `null` deletes the key, objects merge recursively, any
   other value (arrays included) replaces. The effective config is
   `base.apply(ConfigOverlay::from(host layer))`, recomputed on every update; claude and codex
   settings are rebuilt from it as today.
2. **Fallback.** A removed host key falls back to `base` (e.g. the local login token, an env
   path) or the default, because the host layer no longer carries it.
3. **Unchanged.** `ConfigOverlay`, `Config::apply` and the provisioning gate (`entries` +
   `version` of the incoming update drive the reconcile) stay as they are; the merge is one
   small function on `serde_json::Value`.
4. **Docs.** protocol.md §3 / the `config_update` row: host config payloads are merge patches
   over the host layer, `null` removes a key. agent-architecture: the config layering.

## Tests (RED first)

- merge-patch unit tests: absent keeps, `null` removes, nested merge, arrays replace.
- runner: `config_update {engine: {anthropicBaseUrl, anthropicApiKey}}` then
  `{engine: {anthropicBaseUrl: null, anthropicApiKey: null}}` -> the next engine run has neither
  variable; a host token cleared with a local login token present falls back to the local one.
- Existing config_update, register and refresh tests stay green.

## Risks

- A host that sends `null` today meaning "keep" would now clear. host-core never sends `null`
  in config payloads; embedders get the documented semantics.
- Fields read only at startup (paths, heartbeat, executor limits) still take effect on restart,
  as now.

## Scope

- In: the agent runner config layering, the merge function, tests, protocol and architecture
  docs.
- Out: host-core changes (it sends no `null` today), making startup-only fields live.

## Alternatives

- Field-level `null` handling in `ConfigOverlay` (`Option<Option<T>>` per field): clears to
  the default, not to the agent's own layer (a host clearing its token would also drop the
  local login token), and touches every field.
- Treat each host payload as a full replacement of the host layer: breaks the partial updates
  the host sends today.

## Implementation Notes

- `config.rs`: `merge_patch` (RFC 7386) and `LayeredConfig { base, host, effective }`;
  `update(patch)` merges into a copy of the host layer, parses it as a `ConfigOverlay` and only
  then commits, so an unparseable result changes nothing.
- `runner.rs`: `base` is the bootstrap config plus the identity pins; the register `config`
  (`ResolvedIdentity.host_config`, `null` on reconnect) and the startup fetch go through
  `LayeredConfig::update`; `ServeContext.config` holds the `LayeredConfig` and `config_update`
  updates it before rebuilding the claude and codex settings. The provisioning gate still reads
  the incoming update's `entries` + `version`.
- Verified: RED (`config_update_null_clears_the_endpoint_and_key` failed with "the endpoint must
  be gone"), then fmt, clippy, typos, nextest (958 passed).
