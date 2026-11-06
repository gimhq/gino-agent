# 20261105-0743-host-integration-readiness Single agent source and host integration readiness

- **status**: in_progress
- **createdAt**: 2026-11-05 07:43
- **approvedAt**: 2026-11-05 08:00
- **relatedTask**: 20261105-0743-host-integration-readiness

## Context

- `a476843` is not in this repo, `gimhq/gino`, their branches or the local checkouts, and
  `/srv/gino` does not exist on this machine. `configVersion`, `defaults`, `usage` and
  runner-settings are all absent from this repo, so they arrive only with that commit.
- Section 8 here still has heartbeat `engines`; the deletion reported by bks is in the other
  copy. No generator lives in this repo: `gimhq/gino` holds
  `packages/host-core/scripts/check-frames-schema.ts`, and `gino-agent.ref` there pins `a2402a5`.
- Startup reconcile (`reconcile_global_startup`, `runner.rs`) treats any advanced version as
  authoritative and passes `config.entries`, so a version without `entries` reconciles global
  scope to empty. The live path already requires a version and entries pair. Found by reading;
  no test covers it.
- `AgentFailure::ProviderAuth` has no constructing path for any engine, claude included.
  `failure.rs` bans prose matching and `failure_agent_error_not_retried` pins a 401 message to
  `agent.unknown`. The codex mapper keeps only the error message; a structured status in real
  codex output is unverified.
- This repo has no `e2e/`. `gimhq/gino/e2e` holds `Dockerfile.agent`, `fake-claude`,
  `fake-codex` and `agent-entrypoint.sh`. `v0.1.0` is three commits behind `main`, and
  `release.yml` runs on a published GitHub Release, not a tag push.

## Decisions

- 2026-11-05: `gimhq/gino-agent` is the single source and hosts upgrade to its release. No
  reverse merge into the other copy; anything needed from `a476843` is taken from a spec or
  patch and implemented here.
- Heartbeat `configVersion` is the wire name for the applied overlay version.
- Codex auth classification matches the client's anchored `unexpected status 401|403 ` prefix,
  taken from `codex-cli 0.166.0` output against a local 401 endpoint.

## Progress

- Done: item 3 (presence-aware entries, heartbeat `configVersion`, protocol docs), item 4,
  item 5 (`e2e/` assets, `test-image` job in `release.yml`).
- Open: runner-settings, `defaults` and `usage` need a spec or `a476843`. `frames.ts` in
  `gimhq/gino` needs `configVersion`, and `gino-agent.ref` a bump, after this is pushed.
- Not run: the `test-image` job and a joint run against a real host.

## Audit Findings

- Fixed, HIGH: `codex exec` ignores `OPENAI_API_KEY` and `OPENAI_BASE_URL` on 0.154.0, 0.156.1,
  0.160.0 and 0.166.0. The runner now passes `CODEX_API_KEY` and `-c openai_base_url=...`,
  checked against a local endpoint on 0.154.0 and 0.166.0.
- Fixed, MEDIUM: heartbeat `configVersion` was set before the provisioning reconcile. It now
  moves only after the overlay's desired set is in place.
- Open: the network allowlist always allows only the Anthropic endpoint, so a codex run under
  `allowlist` needs its OpenAI endpoint in `network.allow`, and a loopback `openaiBaseUrl` gets no
  gateway forward. Found by reading `sandbox/mod.rs`; not run.

## Proposal

1. Import `a476843` onto `main` here, then port the VM and engine changes to the other copy.
2. Add a presence-aware entries check so both reconcile paths act only on a version and entries
   pair. Report the last applied overlay version, independent of the provisioning version.
3. Capture a real codex 401, then add `RunErrorKind::Auth`, set only by a narrow match in the
   codex mapper. This is a scoped exception to the prose ban; update `failure.rs` docs and tests.
4. Move the fake engines and Dockerfile here and publish a test image from `release.yml`. Keep
   fake switches out of the production binary.
5. Regenerate section 8 last, after the wire changes, and bump `gino-agent.ref`.
6. Publish `v0.2.0` once all items are in, so bks moves to one version.

## Risks

- Repo histories do not connect, so `a476843` may need a manual port and a conflict review
  against `460f522`, which rebuilt the host config layer.
- A codex error text change silently falls back to `agent.unknown`.
- Sharing `version` between overlays and provisioning relies on `applied` only moving on
  reconcile; a skipped version must not block a later entries update.

## Scope

- In: `gino-agent/src`, `docs/protocol.md`, `docs/agent-architecture.md`, `.github/workflows`,
  new `e2e/`, `gino-agent.ref` and the test assets in `gimhq/gino`.
- Out: bks code, including `gino-joint.ts`.

## Alternatives

- Release flag for fake engines: simpler to fetch, but ships test paths in production.
- Claude structured auth detection: left out unless requested.

## Open Questions

1. Where is `a476843`?
2. Should provider auth cover claude too?
