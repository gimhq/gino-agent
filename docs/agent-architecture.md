# Agent Architecture (data plane)

Specification of the **agent / runner (data plane)** — the `gino-agent/**` Rust daemon. Pairs with
[`protocol.md`](protocol.md) (the wire contract) and the [e2ee specification](e2ee/spec.md). The
agent is self-contained: any host that implements the protocol drives it, and the protocol is the
only coupling between agent and host.

## 1. Principles

1. **`task` is the single global top category.** Per runner, everything — every trigger, every execution,
   every message, every attachment — **belongs to a `task`** (`task_id`). It is the durable anchor for
   "parse the whole conversation/job by task".
2. **Two planes, one bridge (`thread_id`).**
   - *Scheduling plane* (local, runner-authoritative): `crons` + `cron_logs`.
   - *Result plane* (synced to host): `threads → outbox → host`.
3. **References on the wire, bulk out-of-band.** Frames stay small (control/work + descriptors); large bytes
   (attachments/artifacts) move on a separate channel (§9) and never enter the at-least-once queues or the
   transcript.
4. **Host is a read-model + a source**, never on the execution critical path. The runner is authoritative
   for scheduling/execution and is offline-tolerant.
5. **Continuity ≠ transcript.** Runner continuity = `engine_session_id` resume + `work_dir` reuse. The
   durable transcript lives on the host.

## 2. Entity hierarchy

```
task   ── global top category (per runner); everything belongs to it
 ├── crons   (N)   triggers / schedules           — crons.task_id → task
 └── threads (N)   engine executions / conversations — threads.task_id → task
        ▲
 a cron fire ──┘   (isolated → a NEW thread; shared → continue the cron's thread as a turn)
```

- **`task`** — the umbrella. 1 task : N crons, 1 task : N threads. May span multiple engines (a thread
  carries its `engine`).
- **`cron`** — a trigger (schedule / webhook / api) under a task.
- **`thread`** — one engine conversation/execution under a task.
- **`engine_session_id`** — a *field* on a thread, not an entity: the engine's resume context. A shared
  thread reuses one across its turns; it may rotate.

## 3. Runner data model (SQLite)

```sql
tasks(    id PK, name?, kind?, status, created_at, updated_at )          -- global top category

crons(    id PK, task_id → tasks,                                        -- trigger (1 task : N)
          kind,            -- 'schedule' | 'webhook' | 'api'
          prompt,          -- the instruction this cron runs each fire (a cron = a recurring prompt)
          schedule_type,   -- 'cron' | 'interval' | 'once'   (kind='schedule'; else NULL)
          schedule_value, next_run, last_fired_at,
          continuity,      -- 'isolated' (new thread per fire) | 'shared' (one ongoing thread)
          run_count,       -- CACHE; truth = cron_logs
          status,          -- active | paused | completed | cancelled  (once → completed)
          dirty, created_at, updated_at )

threads(  id PK, task_id → tasks,                                        -- engine execution/conversation (1 task : N)
          cron_id? → crons,        -- which trigger spawned it (NULL = chat/api/direct)
          source,                  -- cron | chat | api
          prompt,                  -- RESOLVED instruction snapshot at attempt 0 (from crons.prompt | message.text)
                                   --   so retries/resume reuse it instead of re-resolving
          engine,                  -- 'claude' | 'codex' | …
          engine_session_id?,      -- claude --resume handle (shared thread reuses across turns; may rotate)
          status,                  -- pending | dispatched | running | active | succeeded | failed | cancelled
          failure_reason,          -- taxonomy (§6); NULL on success
          attempt, max_attempts, work_dir,
          started_at, finished_at, duration_ms, result, error, synced,
          created_at )

cron_logs(id PK, cron_id → crons, task_id → tasks,                       -- per-fire ledger (LOCAL, incl. skips)
          round_seq, scheduled_at, fired_at,
          status,                  -- dispatched | skipped | missed | failed (SCHEDULING outcome)
          skip_reason, thread_id?, -- the thread this fire drove (new, or the shared one it added a turn to)
          UNIQUE(cron_id, scheduled_at),   -- firing idempotency / dedup
          created_at )

inbox ( …, task_id, thread_id? )   -- delivery buffer; GC-able after process
outbox( …, task_id, thread_id? )   -- delivery buffer; GC-able after ack

config_entries(  -- installed manifest + store-refcount index for provisioned config/skills (§9b)
  id PK, scope,            -- 'global' | <task_id>
  name, sha256, short,     -- store key: store/<name>/<sha256[:12]>; full sha256 = version/integrity
  target, kind,            -- relative landing path (meta-driven: CLAUDE.md|AGENTS.md|.claude/skills/x); file|dir
  store_path, link_path, installed_at,
  UNIQUE(scope, target) )
```

Per-execution state lives on `threads`.

**End-to-end encryption state** (§10c). The schema is versioned by `PRAGMA user_version`
(`SCHEMA_VERSION` 3); a DB at another version is refused.

```sql
tasks   += e2ee_profile_id?, e2ee_group_id?     -- task_upsert.data.e2ee; once set never changed or cleared
threads += result_outbox_id?                    -- outboxId of the last thread_result (binds its sealed result/error)

e2ee_key_packages( id = 1, store BLOB, last_resort_created_at?, updated_at )  -- KeyPackageStore (private init keys)
e2ee_groups(       task_id PK, group_id, profile_id,
                   snapshot BLOB?,              -- MLS group state; NULL until a Welcome joins
                   last_seq?,                   -- last applied DS log seq
                   status,                      -- pending | member | removed | lost
                   updated_at )
e2ee_key_cache(    task_id, epoch, secrets BLOB, verified, PK(task_id, epoch) )  -- epoch secrets (history walk)
e2ee_log_pending(  task_id, seq, type, payload, received_at,                   -- e2ee_log / e2ee_welcome as received,
                   PK(task_id, seq, type) )                                     --   until applied in seq order
```

- **Sealed at rest.** Every `BLOB` above is AES-256-GCM sealed under the at-rest key
  (`e2ee-state.key`, §10c) with its label as AAD: `e2ee_key_packages`, `e2ee_group:<task>`,
  `e2ee_key_cache:<task>:<epoch>`. A blob that does not open under the key marks the group `lost`
  (the KeyPackage store refuses startup).
- **Content stays sealed.** For an encrypted task, `threads.prompt`, `crons.prompt`,
  `threads.result` and `threads.error` hold the sealed JSON `{"e2ee": "<envelope>"}` exactly as
  received or sent, and `inbox`/`outbox` payloads hold the sealed frames. Plaintext exists only in
  memory for a turn and in the runner-local files of §10c *Trust boundary*.

## 4. Trigger model (`crons`)

- **`kind`** = schedule | webhook | api (only `schedule` wired now).
- **`schedule_type`** (schedule kind) = cron | interval | **once**. A one-shot is a `once` trigger — fires
  once, then `status='completed'`. All timing in `crons.next_run` → one timing loop.
- **`continuity`** = isolated (each fire → a new thread, fresh engine context) | shared (fires continue
  **one** ongoing thread, appending turns, reusing `engine_session_id`).
- **Deterministic id / dedup.** Firing idempotency is `cron_logs UNIQUE(cron_id, scheduled_at)`. An
  *isolated* fire additionally mints a deterministic `thread_id = "<cron_id>@<scheduled_epoch>"`.

## 5. Thread lifecycle

State machine: `pending → dispatched → running → {succeeded | failed | cancelled}` (a *shared* thread stays
`active` between turns).

```
trigger N due / event arrives:
  ├─ dispatchable?
  │   ├─ yes → isolated: threads.insert{id=cron_id@epoch, task_id, cron_id, status='pending'}
  │   │        shared:   reuse cron's open thread (append a turn)
  │   │        cron_logs.insert{round_seq=N, status='dispatched', thread_id}
  │   │        executor: pending → dispatched → running → terminal
  │   │        → outbox(thread_result, thread_id) + streamed thread_message → host
  │   └─ no  → cron_logs.insert{round_seq=N, status='skipped', skip_reason}  (no thread, no outbox)
  └─ crons.update next_run (NULL+completed if once), last_fired_at, run_count++
```

- Executor is **source-agnostic** (`SELECT … FROM threads WHERE status='pending'`). `dispatched` (claimed,
  engine not started) makes stuck startups detectable.
- **Watchdog**: fail `dispatched > Td` / `running > Tr` with `runner.timeout`; an inactivity watchdog kills
  only when the engine emits no events; on `close`/offline, fail orphans.
- Two `status` axes never overlap: `cron_logs.status` (scheduling) vs `threads.status` (engine).
- **Chat threading** — a `message` frame's `threadId` is the continuity switch: **present** → CONTINUE that
  thread (a resting thread re-pends for the new turn, KEEPING `engine_session_id` so the engine conversation
  resumes); **absent** → START A FRESH thread (the runner mints a new unique id, e.g. `<task>@<uuid>`, with
  no carried `engine_session_id`). The outbound `thread_result`/`thread_message` carry the minted id back
  (the executor drives by `thread.id`) so the host records it as the task's `current_thread_id`. There is no
  implicit per-task continue — every absent-`threadId` message is a new thread. (Sequential absent-`threadId`
  messages drain FIFO to their freshly-minted threads.)

## 6. Failure classification, retry, resume-safety

`threads.failure_reason`, two groups:

- **`runner.*`** — `queued_expired`, `runtime_offline`, `timeout`, `iteration_limit`, `agent_blocked`,
  `invalid_request`.
- **`agent.*`** — `provider_auth`, `provider_quota`, `provider_rate_limit`, `provider_server_error`,
  `provider_network`, `process_failure`, `empty_or_unparseable_output`, `context_overflow`,
  `model_unavailable`, `missing_config`, `encryption`, `unknown`.

`classify(rawError)` maps free text → reason. (`invalid_request` is **`runner.*`** — a malformed/incomplete
request is the host/runner's fault, not the provider's.) Then: **retry only `runner.*`** while
`attempt < max_attempts` (and the thread's `prompt` snapshot, §8, makes the retry re-runnable);
**resume-unsafe** reasons — a flagged subset where the engine session may be corrupted (e.g.
`agent.process_failure`, an engine crash mid-turn) — **do not persist `engine_session_id`** (next turn
starts fresh).

**`agent.encryption`** (encrypted tasks, [task-content §4.4](e2ee/task-content.md)): a mapped input
field did not open, or an output field did not seal. It is **non-retryable** (the same state gives the
same answer; the host re-dispatches once the cause is fixed, e.g. after the runner is re-added) and
**resume-safe**: an input that does not open fails before the engine starts, so `engine_session_id` is
kept. A transcript event that does not seal mid-turn stops the turn and kills the engine, so that turn's
resume handle is dropped. The `thread_result` carries `status: "failed"`, `failure_reason:
"agent.encryption"` and `encryption_error {code, epoch?, message?}`, and **no** `result`, `error` or
`attachments`; there is never a plaintext fallback. The runner logs only the code, task id, thread id
and epoch. Codes the runner emits ([spec §11](e2ee/spec.md)): `not_member` (no group state, removed, or no
e2ee state at all),
`epoch_unknown` (group not caught up within 30 s), `history_unavailable` (a missing epoch link),
`plaintext_rejected` (a mapped field in plaintext), `unsupported_version` (an unsupported profile;
a group id that is not the task's derivation is `not_member`), `seal_failed`, and the envelope failures `gino-e2ee` reports (`open_failed`,
`aad_mismatch`, `link_invalid`, `drop_key_mismatch`, `unsupported_suite`, `malformed`). The synchronous reapers (watchdog, offline,
unrunnable) have no content key at hand: an encrypted task's `thread_result` there omits `result`,
`error` and `attachments` instead of sealing them.

## 7. Scheduling plane: `cron_logs`

- Records **every** fire incl. ones producing no thread (`skipped`/`missed`) — so it can't be derived from
  `threads`. Each dispatched row links its `thread_id`.
- **Round-count truth = `cron_logs`** (`MAX(round_seq)`); `crons.run_count` is a cache reconciled at startup.
- **Local-only**: `{round_count, skipped_count, last_status}` rides `cron_state`/`heartbeat`; host derives
  dispatched counts from its mirror by `cron_id`.
- **Catch-up**: `interval` collapses missed periods; `cron` recomputes from wall-clock; `once` fires if
  still future else logs `missed`.

## 8. Continuity vs transcript

- **Thread instruction** = each thread snapshots its **resolved `prompt`** at attempt 0 — from `crons.prompt`
  (cron-fired) or `message.text` (chat/api). Retries and resume reuse the snapshot rather than re-resolving
  (a chat thread's inbox message is consumed once, so without the snapshot a retried `runner.timeout` would
  re-resolve to `runner.invalid_request`).
- **Runner continuity** = `engine_session_id` resume + `work_dir` reuse; no transcript replay. A changed
  resume id downgrades to fresh.
- **Durable transcript = host `messages`** (§11), keyed by `task_id`/`thread_id`, `seq`-ordered,
  `kind`-classified, fed by streamed `thread_message` frames.
- **Runner `inbox`/`outbox` are delivery buffers, not the transcript** — they carry `task_id`/`thread_id` as
  **indexed columns** (correlation/routing) while `payload` stays an opaque JSON blob: **outbox payload = the
  frame's `data`** (the envelope `{type, …ids, data}` is rebuilt on send from columns); **inbox payload = the
  full received frame** (re-delivered verbatim on replay; the `type` column is the replay *classification*).
  GC-able after ack/process. Kept as two tables (sender-queue vs receiver-log — different roles).
- **Concurrency / ordering**: many threads share one WS, so frames interleave. The host **demuxes by
  `threadId`** and **orders each thread by `seq`** (§10) — never by arrival order or `outboxId`.

Parse: whole job `WHERE task_id=?`; one conversation `WHERE task_id=? AND thread_id=? ORDER BY seq`.

## 9. Attachments & file sync (out-of-band)

Code/repos → git; attachments/artifacts → out-of-band object storage (this section).

- **Descriptor on the wire only**: `{ id, name, content_type, size, sha256, ref, direction? }`. Bytes never
  travel in frames.
- **Byte backend, config-selected**: **host-proxy by default** (`GET /agent/attachments/:id` +
  `POST /agent/attachments`, connect-token auth, host streams); **presigned URL / CDN** when object storage
  is configured (S3/MinIO/CloudFront).
- **Materialize into `threads.work_dir`**: inbound → `work_dir/inputs/`; outbound → upload everything under
  `work_dir/output/`; descriptors returned on `thread_result`.
- **Integrity/dedup/safety**: verify `sha256`; content-addressed cache by `sha256` under the workspace dir,
  shared within a workspace, size-cap + LRU GC; size limits (100 MB single / 500 MB per execution) + optional
  content-type allowlist; sanitize names vs `../`; short-lived presigned URLs, not persisted.

## 9b. Engine config & skills provisioning

Engine config (instruction file + skills) is provisioned as **versioned, content-addressed artifacts**, named
by **meta** (engine-agnostic), loaded by **symlink** from one store.

- **Entry** `{ name, sha256, target, kind }` (wire spelling `name` — protocol.md §8 `ConfigEntry`; the
  runner's internal field `id` accepts it as an alias) — `name`=logical name, `sha256`=version/integrity, `target`=
  meta-driven landing path (`CLAUDE.md` | `AGENTS.md` | `design.md` | `.claude/skills/<name>` …),
  `kind`=`file|dir`. A **skill** = a `kind:dir` entry; an **instruction file** = a `kind:file` entry. The
  runner is engine-agnostic; the host sets `target` per engine.
- **Two scopes, same shape**: **global** (root `$ENGINE_CONFIG_DIR/`, via `config.entries`) and **task**
  (root `<thread.work_dir>/project/`, via `task_upsert.data.entries`).
- **Store + symlink**: `store/<name>/<sha256[:12]>` (git-style short id; full `sha256` in the wire ref for
  integrity). `<scope-root>/<target>` is a **symlink** into the store — zero copy, update = repoint, per-name
  version history. Bytes fetched out-of-band, content-addressed by full hash
  (`GET /agent/attachments?sha256=<hex>`, authorized by desired-set membership); **store unified with the §9 attachment
  cache**; refcount/LRU GC.
- **`config_entries`** (§3) = installed manifest + store-refcount index (not a content copy; bytes in the
  store, desired set declared by the host). Drives reconcile (diff desired vs rows), GC (refcount by
  `(name, sha256)`), restart repair (verify/recreate symlinks).
- **`project/` layout** (the thread cwd): `project/<target instruction file>` + `project/.claude/skills/*`
  (symlinks) + **`project/workspace/`** = the git working area (code isolated here → no conflict with
  injected config) + sibling `inputs/output/logs`. Engine launches with `ENGINE_CONFIG_DIR` set and
  `cwd=project/`.
- **Global config VERSION gate (restart durability)**: the global config carries a host-assigned **monotonic
  `version`** served on register / `GET /agent/config` / `config_update`. At startup the runner fetches
  `GET /agent/config` (authoritative — a restart reuses its identity, so the register response no longer
  carries the desired set) and reconciles the global scope **only when the version advances** past the applied
  version (persisted in a durable `config_meta` KV); same/absent version ⇒ **repair-only** (store + manifest
  survive). A *versioned* empty set removes all (authoritative-empty); a *non-versioned / offline* empty set
  never wipes. The task scope is restart-durable already (it persists via `tasks.entries` + `config_entries`).

## 9c. Engine backends (`claude`, `codex`)

The runner holds a **name → backend registry** with a default (`claude`), not one fixed engine. At every
spawn the executor picks the backend in this order: the **task** row's `engine` (the host's
`task_upsert.data.engine`), else the **thread** row's `engine`, else the **default**. The task row is read
at spawn — the same apply-on-next-run policy as the per-task `model` override — so a `task_upsert` that
changes the engine reaches the *next* run without disturbing the one in flight. An **unregistered engine
name is not fatal**: the registry warns and answers the default.

**The claude backend.** One prompt can end in several `result` lines: after a background subagent
reports back, the CLI runs another turn by itself and emits another `result`. The child is started with
`CLAUDE_CODE_EMIT_SESSION_STATE_EVENTS=1`, and the run ends on `system/session_state_changed` → `idle`
with the **latest** `result`. A CLI that never reports session state ends on its first `result`, and a
result still held when the child exits is reported as it is.

**The codex backend.**

- **One `codex exec --json` child per TURN** — unlike claude, a single long-lived child driven over a
  bidirectional control protocol. The prompt is written to the child's stdin, which is then **closed**, and
  the runner reads JSONL `ThreadEvent`s off stdout until the process exits.
- **Continuity is the thread id**: `thread.started` reports it, the runner persists it as the thread's
  `engine_session_id`, and the next turn passes it back as a trailing positional `resume <thread_id>`.
  Rewinding to a message has no codex equivalent, so a resume point is ignored rather than approximated.
- **argv**: `codex exec --json [--model M] [--ask-for-approval P] [--sandbox S] [--skip-git-repo-check]
  [extra args…] [resume <thread_id>]`, with `cwd` = the thread's `project/` dir (§9b).
- **The defaults are deliberate** (all three are configurable):

| flag | default | why |
|---|---|---|
| `--ask-for-approval` | `never` | a turn must never block on an approval prompt the runner has no way to answer |
| `--sandbox` | `danger-full-access` | parity with the claude backend's `--dangerously-skip-permissions`; isolation in this product is the **container** boundary, and a narrower default would make the two backends run the same task differently |
| `--skip-git-repo-check` | on | the per-thread cwd `work_dir/project/` is not a git repository, and `codex exec` refuses to run outside one |

**Event mapping** (codex JSONL → engine-agnostic event → host transcript kind):

| codex event | `EngineEvent` | transcript |
|---|---|---|
| `thread.started` (`thread_id`) | `SessionStarted` | — (persisted as the resume handle) |
| `item.completed` `agent_message` | `Output` | `assistant_text` |
| `item.completed` `reasoning` | `Thinking` | `thinking` |
| `item.started` `command_execution` / `file_change` / `mcp_tool_call` / `collab_tool_call` / `web_search` | `ToolUse` | `tool_use` |
| `item.completed` for those same kinds | `ToolResult` | `tool_result` |
| `item.completed` `error` | `Log` (error) | a log line — **not** terminal |
| `turn.completed` | `Result` (success) | `thread_result` succeeded |
| `turn.failed` | `Result` (error, `Execution` → `agent.unknown`) | `thread_result` failed |
| `error` (stream-level, e.g. a reconnect notice) | `Log` (warn) | a status line — **not** terminal |
| `item.updated`, `todo_list`, anything unknown | — | dropped |

- The tool **name is the codex item kind verbatim** (`command_execution`, `file_change`, …), never aliased
  onto claude's tool names — aliasing would make the transcript claim codex did something it did not.
- `input` and the `tool_result` `content` carry the **whole item minus `id`/`item_type`/`type`**, deliberately
  shape-agnostic: codex item payloads differ per kind and per CLI version, so a hand-picked field list would
  silently drop fields.
- **`parent_tool_use_id` is always absent for codex.** Codex reports no parent linkage and the runner does
  not invent one, so codex transcripts carry no sub-agent attribution (§10).

**Interrupt.** Claude receives an in-band control `interrupt`; codex has no such channel — stdin is already
closed by the time the turn runs — so the runner **SIGINTs the child**, waits a bounded 2 s grace, then kills
it. The cancelled turn settles through the existing executor path: the child dies, stdout hits EOF, the event
stream ends, and `drain_cancelled` settles the thread `cancelled`.

**Config.** The `engine.codex` block — `binary`, `model`, `approvalPolicy`, `sandboxMode`,
`skipGitRepoCheck`, `extraArgs`, plus `openaiApiKey` / `openaiBaseUrl` (handed to the child as
`OPENAI_API_KEY` / `OPENAI_BASE_URL`) — is additive: an absent field leaves the backend default in place. The
provisioned engine config dir (§9b) is exported to a codex child as `ENGINE_CONFIG_DIR` + **`CODEX_HOME`**,
the way it is `ENGINE_CONFIG_DIR` + `CLAUDE_CONFIG_DIR` for claude.

**Engine binaries and installs.** Each backend starts, in this order: an explicitly configured binary
(`engine.codex.binary`; claude has none), else the agent-managed install in
`<workspace>/engines/home/.local/bin/<engine>` when it is executable, else the bare name on `PATH`. The
binary is resolved when the backend's settings are built (startup and `config_update`).

- `gino-agent engine install <claude|codex> [--version V | --channel stable|latest]` runs the vendor's
  official installer (`curl -fsSL https://claude.ai/install.sh | bash`, `curl -fsSL
  https://chatgpt.com/codex/install.sh | sh`) with `HOME=<workspace>/engines/home` and
  `CODEX_NON_INTERACTIVE=1`, then prints `<engine> <version> at <path>` from `<binary> --version`.
  Versions and channels are plain words (`[A-Za-z0-9.+-]`); codex has no channels.
- `gino-agent engine update [<engine>]` runs `claude update` for claude and the codex installer again,
  for one or every agent-installed engine; `gino-agent engine status` prints each engine's resolved
  binary and version. A failing installer exits non-zero; nothing retries.
- claude always runs with `DISABLE_AUTOUPDATER=1`, so only the agent changes its install. An install or
  update takes effect for runs started afterwards; the installers keep versioned directories, so a
  running engine keeps its binary.
- Heartbeats carry `engines` (protocol §5): name, `--version` (10 s bound) and resolved path of each
  engine binary, probed once in the background at startup so a stuck binary cannot delay it;
  heartbeats before the probe finishes omit the field.
- Isolation: the sandbox binds the canonical binary's directory read-only (§9d); a `vm` run of an
  agent-installed engine gets `<workspace>/engines/home` as a read-only virtiofs share at the same path
  (§9e), otherwise the guest image's engine on its `PATH`.

**Operator-visible constraints.**

- The runner registers the codex backend and advertises the `codex` **capability** only when a **stat-probe**
  finds the configured binary. The probe never *executes* the binary.
- **Capabilities are computed once, during the register call.** Installing a codex binary on an
  already-registered runner does not make it codex-capable until it re-registers; a `config_update` reaches
  the settings seam but not the registry until restart.
- The host **matches `task.engine` against the agent's advertised `capabilities.engines` at placement time**
  (both the auto-ranking and manual-assign paths). So the probe decides **routability**, not just
  runnability: a task naming an engine no permitted agent advertises is not rejected — it stays unplaced
  (`no-permitted-agent`) in `pending_assignment`.
- **Known limitation.** If an agent advertised `codex` at register and the binary later disappears (or config
  repoints it), the host keeps routing codex tasks there, and the runner's fall-back-to-default rule means the
  run **completes on claude**; a warning in the agent log is the only signal. That is the trade-off of never
  failing a task on an engine-name mismatch.

## 9d. Native deployment and engine sandbox

Outside a container the runner can confine each engine run (claude or codex) in a **bubblewrap sandbox**.
Isolation is **off by default**; with it off, launches are unchanged.

**Requirements.** A Linux host; `bubblewrap` with `bwrap` on the daemon's `PATH`; unprivileged user
namespaces enabled. Run the agent as a dedicated unprivileged user; a sandboxed run fails closed
before spawn when the agent runs as root. Network mode `allowlist` also needs `/dev/net/tun`.
The runner advertises `sandbox` in `capabilities` (register and every heartbeat) when these hold, and
`sandbox:allowlist` when `/dev/net/tun` is also available (protocol §3).
An agent running as a container's PID 1 must be started with an init (`docker run --init`, compose
`init: true`, or tini) so exited sandbox processes are reaped, until `20261024-2251-agent-pid1-reaping`
lands.

**Config.** The `engine.isolation` block (without a local isolation file, an overlay that sets it
replaces the earlier block wholesale; see *Local isolation file* below):

```json
{ "engine": { "isolation": {
  "mode": "sandbox",
  "network": { "mode": "none" },
  "readPaths": ["/opt/node"],
  "writePaths": ["/data/cache"],
  "allowTaskOverride": false
} } }
```

- `mode` ∈ `off | sandbox | vm`; absent = `off`. `network.mode` ∈ `none | full | allowlist`; absent = `none`.
- `readPaths` / `writePaths` are extra host paths bound read-only / read-write. Each must be absolute,
  contain no `..`, and be neither the workspace root nor a parent of it, and may neither name nor
  contain the agent DB (with its `-wal`/`-shm` files) or the e2ee key files (§10c). They are checked
  only when the resolved mode is not `off`.
- **Per-task override**: `meta.isolation` on the task (`task_upsert`) overrides `mode` and `network.mode`
  only; extra paths always come from the config. Meta that is not a JSON object, or has no `isolation`
  key, means no override.
- **Tighten-only overrides.** Unless the config sets `allowTaskOverride: true` (absent = `false`; the key
  inside `meta.isolation` is ignored), an override may only tighten the default. Modes order
  `off` < `sandbox` < `vm`; network modes order `full` < `allowlist` < `none`, compared against the
  default's effective value (absent mode = `off`, absent network = `none`). A default of `off` confines no
  network, so any network override tightens it. A loosening override (e.g. `sandbox` → `off`, `none` →
  `full`) fails the run with "task meta.isolation would loosen `<setting>` from … to …; set
  engine.isolation.allowTaskOverride to allow this", before any not-supported check; neither value is used
  as a fallback. With `allowTaskOverride: true` the override wins as-is.
- `vm` runs the engine in a microVM (§9e) and needs a `vm` block in the local isolation file. Unknown
  values, an invalid path or a malformed `meta.isolation` fail the run. All of these are classified as `runner.invalid_request` (§6) and
  are not retried.

**Local isolation file.** `GINO_ISOLATION_FILE` (env only, no CLI flag) names an agent-local file
holding the `engine.isolation` block as a JSON object. It is read in `ConfigOverlay::paths_from_env`, so
both the daemon and `gino-agent login` fail at startup on a missing, malformed or invalid file; the
error names the path, and an invalid rule also names its index (`rule <n>: …`). The file is the
**floor**: it becomes the default, and a host `engine.isolation` overlay is layered on the floor (not on
the previous host block) and may only tighten `mode` (`off` < `sandbox` < `vm`) and `network.mode` (`full` <
`allowlist` < `none`). A loosening value, and any host `network.allow`, `readPaths`, `writePaths`,
`allowTaskOverride` or `vm`, is ignored with one warning per field. Without a file the host block replaces the
default as before. The host does not send an `engine.isolation` block yet, so today the file plus task
`meta.isolation` (under the tighten-only rules above) are the only inputs.

**Allowlist.** `network.mode: "allowlist"` gives the engine a network that reaches only listed
destinations:

```json
{ "mode": "sandbox", "network": { "mode": "allowlist", "allow": [
  { "host": "registry.npmjs.org", "ports": [443] },
  { "host": "*.github.com", "ports": [443, 22] },
  { "cidr": "10.20.0.0/16", "ports": "*", "proto": "udp" }
] } }
```

- Each rule has exactly one of `host` (an exact name, or `*.suffix` matching strict subdomains only) or
  `cidr` (IPv4/IPv6 `addr/prefix`, matched against literal-IP destinations). `ports` is a non-empty list
  of non-zero ports or `"*"`; `proto` is `tcp` (default) or `udp`. The first matching rule wins.
- Rules come only from the config default (the local file); `network.allow` in task `meta.isolation` is
  dropped. A task override may still switch the network mode (tighten-only unless `allowTaskOverride`).
- **LLM endpoint, always allowed** (TCP): the host and port of `ANTHROPIC_BASE_URL`, else
  `api.anthropic.com:443`. A loopback base URL (`localhost`, or a loopback / unspecified IP) is
  rewritten for the engine to `10.0.2.2` with the same scheme, userinfo, port, path and query; only that
  gateway port is forwarded to the host loopback address. A non-loopback IP literal is allowed as that exact address and
  port. An always-allowed endpoint is exempt from the private-address refusal (e.g. an LLM proxy on the
  LAN) for its exact host:port; loopback, unspecified and link-local (`169.254.0.0/16`, `fe80::/10`)
  addresses stay refused, and a link-local IP-literal base URL fails the run before spawn. `full` mode
  keeps the original URL.
- **LLM endpoint under a floor.** With a local isolation file the always-allowed endpoint (and the
  loopback gateway forward) comes only from the daemon's own `ANTHROPIC_BASE_URL` (its process env), never
  from a host `engine.anthropicBaseUrl`. A host base URL that differs from the daemon's gets no
  always-allow: it is admitted only when a floor `network.allow` rule already covers its host and port
  over TCP (and then follows the normal rule path, private-address refusal included); a loopback one is
  never admitted. Otherwise the run fails before spawn with an error naming `engine.anthropicBaseUrl`,
  without echoing the URL.
- **DNS.** The engine's `resolv.conf` is `nameserver 10.0.2.2`. Allowed names get a stable fake IPv4
  address from `198.18.0.0/15`, which the exit maps back to the name; the real address is resolved on the
  host. Names matched by neither a host rule nor the LLM endpoint get NXDOMAIN. IPv4 only: `AAAA` (and
  other types) for an allowed name get no data.
- **Refusal.** A flow is decided before the guest handshake completes and, when allowed, only after the
  host connect succeeded; a refused TCP flow gets an RST, a refused UDP flow an ICMP port unreachable —
  never accept-then-close. Private, loopback, link-local and other reserved destinations (also when a
  name resolves to one; IPv4-mapped/NAT64/6to4 forms checked as IPv4) are refused unless a `cidr` rule
  covers them.
- **Limits** per run: 256 live TCP connections, 1024 UDP flows, 128 KiB TCP buffers.
- **Decision log.** Every flow logs one `network decision` event on target `gino_agent::net` with
  `thread_id`, `proto`, `target_name` (`-` when unknown), `target_ip`, `port` and `decision`: `allow`
  (info, `rule_index` or `always`), `deny` (warn, `reason`), or `refused` for an allowed flow that still
  failed (warn, `reject_kind` = `limit` / `reset` / `unreachable`, `reason`).

**Launch chain.** daemon → `bwrap` → `gino-agent sandbox-init` (pid 1) → engine.

- `bwrap` unshares every namespace (`--unshare-all`, `--die-with-parent`, `--new-session`) and runs
  `sandbox-init` as uid/gid 0 of the sandbox user namespace with **only `CAP_SETFCAP`** — needed to map a
  nested user namespace onto that uid 0 (kernel ≥ 5.12).
- `sandbox-init` enters a nested user namespace, switches to **uid/gid 1000**, clears every capability
  set, sets `no_new_privs`, verifies `CapEff`/`CapPrm` are empty, then spawns the engine with the inherited
  stdio and environment and exits with its status (128 + signal when killed). Any setup failure exits
  **125** with a `sandbox-init: …` line on stderr.
- `bwrap` does not forward signals, so `sandbox-init` forwards SIGINT/SIGTERM to the engine; the codex
  interrupt (§9c) SIGINTs `sandbox-init` rather than `bwrap`.
- **Allowlist only:** the daemon creates a private 0700 per-run dir (`$TMPDIR/gino-net-<uuid>`) with the
  control socket and `resolv.conf`. `bwrap` additionally gets `--cap-add CAP_NET_ADMIN`,
  `--dev-bind /dev/net/tun`, that `resolv.conf` read-only, and the socket at `/run/gino/ctl.sock`.
  `sandbox-init --ctl-sock` creates `gino0` (`10.0.2.15/24`, gateway `10.0.2.2`), sends its fd to the
  daemon, closes it and waits for the daemon's ready byte before dropping capabilities and starting the
  engine; any failure exits 125. The daemon receives the fd, starts the run's user-space exit and releases
  the engine (30 s timeout); a setup failure kills the sandbox and fails the run with "engine sandbox
  network setup failed: …". The exit lives as long as the session.
- The stdio stream and the claude control protocol are unchanged.
- The engine binary is resolved on the daemon's `PATH` and canonicalized; its install dir is bound
  read-only unless it is under `/usr`, and so is the agent binary. An engine that needs files elsewhere
  (e.g. a node runtime outside `/usr`) needs them in `readPaths`.

**Mounts.**

| visible | how |
|---|---|
| `/usr`, `/bin` `/lib` `/lib64` `/sbin` (mirroring the host's dirs/symlinks), `/etc` | read-only |
| engine install dir, agent binary, `readPaths` | read-only |
| the thread's `work_dir`, `writePaths` | read-write |
| `/tmp`, `$HOME` (the daemon's, else `/home/gino`) | fresh tmpfs |
| `/proc`, `/dev` | new instances |
| `/run/gino/memory/task` | this task's memory tree, read-write, including Claude's auto memory dir `claude/`; `GINO_MEMORY_DIR`; only with task memory on (§9f) |
| `/run/gino/memory/agent` | the agent memory tree, read-write for `rw`, read-only for `ro`; `GINO_AGENT_MEMORY_DIR`; absent when `off` |
| `/run/gino/conversations` | read-only snapshot of this task's earlier threads' archives; `GINO_CONVERSATIONS_DIR`; only with task memory on |

Not visible: the workspace root and other threads' work dirs, `agent.db`, the global engine config dir
(except the two binds below), other tasks' memory trees, `conversations/` under the workspace (except
this task's snapshot), the rest of `/run`, `/var`.

**Memory and conversations view.** The memory binds follow the thread's effective memory settings
(§9f), so a per-task `meta.memory` `ro` or `off` applies to the sandbox too. The runner replaces any
inherited `GINO_MEMORY_DIR`, `GINO_AGENT_MEMORY_DIR` and `GINO_CONVERSATIONS_DIR` with the in-engine
paths of the mounts the run has, and drops the variable of a tree that is off. The conversations view
is a per-run private 0700 dir (`$TMPDIR/gino-conv-<uuid>`) filled at launch: one subdirectory per
earlier thread of the task (named after its work dir), holding copies of the top-level regular files of
its `conversations/` archive, newest thread and newest file first, up to `GINO_CONVERSATIONS_MAX_BYTES`
(default 8 MiB); files left out are counted in a `TRUNCATED.md` note at the view root. Sources are
opened without following symlinks; symlinks, nested dirs and special files are skipped. The view is
point-in-time: archives written by concurrently running threads appear on the next launch. It lives as
long as the engine process and is removed with it.

**Claude auto memory.** Claude's auto memory dir is `<task memory>/claude/` (§9f). The runner
rewrites `autoMemoryDirectory` in the launch's `--settings` JSON to the in-engine path
`/run/gino/memory/task/claude`; without a task memory mount, or for a dir outside the tree, it
drops the key and sets `autoMemoryEnabled: false` instead. With task memory off, `--settings`
carries `autoMemoryEnabled: false` and the env `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`, so nothing is
written under `.engine-home` or the global engine config dir. Other tasks cannot see it: only this
task's tree is mounted.

**Engine home.** Each thread gets `<work_dir>/.engine-home`, exported as `ENGINE_CONFIG_DIR` plus
`CLAUDE_CONFIG_DIR` (claude) or `CODEX_HOME` (codex). The global `CLAUDE.md` and `skills/` (§9b) are bound
into it read-only when present. `claude login` state in the global dir is **not** visible, so credentials
must come from the environment: `ANTHROPIC_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`, or the host proxy
(`ANTHROPIC_BASE_URL`). The engine also gets `HOME`, `TMPDIR=/tmp` and `GINO_SANDBOX=1`.

**Archive and `gino` CLI.** The PreCompact archive (`gino-agent archive`) writes to `<work_dir>/conversations` via
`GINO_ARCHIVE_DIR`. The in-engine `gino` CLI cannot open the agent DB and reports "agent state is not
available inside the sandbox".
The target design replaces direct DB access with the local agent API (§10b).

**Network.** `none`: own network namespace with loopback only. `full`: the host network
(`--share-net`); when `/etc/resolv.conf` links outside `/etc`, its target is bound read-only.
`allowlist`: own namespace whose default route is the TUN device (see *Allowlist*).

**Fail-closed.** The first sandboxed run resolves `bwrap` and probes it once per process (cached). If
`bwrap` is missing or the probe fails, every sandboxed run fails with "engine sandbox is unavailable: …";
it never falls back to running unconfined.

**Testing.** Privileged integration tests (`tests/sandbox.rs`, `#[ignore]` and gated on
`GINO_SANDBOX_IT=1`) run via `gino-agent/scripts/sandbox-it.sh`: it builds as root in a sibling container
with the moby seccomp profile extended for user namespaces, `/dev/net/tun` and unconfined
AppArmor/system paths, then runs the tests as uid 1000; its memory scenarios cover per-task trees, the
shared agent tree, `ro` refusing writes, the switches and the conversations view. The host repository's real-engine e2e
`SANDBOX_NETWORK=none|allowlist|full ./e2e/run-real-sandbox.sh` (default `none`; `--smoke` skips the
model call) drives the real claude CLI in the sandbox through the host `/llm` proxy; exit 3 means
Anthropic was reached but rate-limited. `--memory` runs the real-binary memory check (task and agent
memory writes, recall from another task, no injection on resume, re-injection after `/compact`), also
with `SANDBOX_MODE=off|vm`.

## 9e. Engine VM mode

`mode: "vm"` runs each engine run in its own libkrun microVM, booted by the `gino-vmm` helper
(gino-vmm/README.md). Like the sandbox it fails closed and never falls back to a weaker mode.

**Requirements.** Linux with KVM: `/dev/kvm` readable and writable by the daemon user (usually the
`kvm` group). A non-root daemon: a root daemon fails every confined run (`vm` included) before spawn,
and `vm` is not advertised. libkrun v1.19.7 (net and blk features) is compiled into `gino-vmm`; the
artifacts are the guest kernel, the guest root image (raw ext4) and the single static `gino-vmm`, built
by `vm/kernel/build.sh`, `vm/rootfs/build.sh` and `vm/vmm/build.sh` (vm/README.md; `vm/smoke.sh`
builds and boots them all). The daemon's own `gino-agent` binary is injected into the guest as
`/gino-agent` and runs from an otherwise empty boot root, so it must be statically linked (the release
build is static musl); a dynamically linked binary fails the run before the VM starts. `gino-vmm` is a
static musl binary with no host library needs.

**Config.** A `vm` block in the local isolation file (`GINO_ISOLATION_FILE`, §9d):

```json
{ "mode": "vm", "network": { "mode": "allowlist", "allow": [] },
  "vm": { "kernel": "/opt/gino/vm/vmlinux", "rootfs": "/opt/gino/vm/rootfs.ext4",
          "vmm": "/opt/gino/bin/gino-vmm", "vcpus": 2, "memoryMib": 2048,
          "diskGib": 32, "docker": false } }
```

- `kernel`, `rootfs` (the ext4 base image), `vmm` are absolute paths. An omitted one is taken from
  the lode resource of the same name: `$LODE_RESOURCE_KERNEL/vmlinux`,
  `$LODE_RESOURCE_ROOTFS/rootfs.ext4`, `$LODE_RESOURCE_VMM/gino-vmm` (lode's `current` link, so a
  resource update applies to the next run); neither set fails the file naming the field and the
  variable. Under lode the block can be `"vm": {}`. `vcpus` 1..=32
  (default 2); `memoryMib` 64..=65536 (default 2048); `diskGib` 1..=4096 (default 32), the root disk
  size (never less than the image); `docker` (default false) starts `dockerd` in the guest before the
  engine. A `libkrun` key is rejected (libkrun is compiled into gino-vmm). The file
  fails to load when `mode` is `vm` without a block, or the block is invalid.
- The block is accepted **only from the local floor**. A host `engine.isolation.vm` is ignored with a
  warning (with or without a floor), and `vm` in task `meta.isolation` is dropped.
- A `vm` block may sit in a floor with another mode, so a host overlay or task meta can tighten to `vm`
  (`off` < `sandbox` < `vm`; tighten-only unless `allowTaskOverride`). Selecting `vm` without a floor
  block fails the run with "vm mode needs engine.isolation.vm in the local isolation file".
- `readPaths` / `writePaths` become extra virtiofs shares at their host paths (a read-only file is
  copied into the control dir instead; a write path must be a directory).
- `vmDisk` (`"run"`, the default, or `"task"`) sits next to `mode` in the floor and in task
  `meta.isolation` (a host overlay's is ignored): `run` gives every run a fresh root disk, `task` keeps
  one per task across its runs (see *Root disk*).

**Fail-closed probe.** Before the first `vm` run (once per process, cached, like the `bwrap` probe):
`/dev/kvm` opens read-write, the configured `gino-vmm` is an executable file, the kernel and rootfs
exist, and `gino-vmm --probe` exits 0 (10 s bound): it opens `/dev/kvm` read-write without creating
a VM and prints `gino-vmm <version> libkrun <version>`. Any failure fails the run with "engine sandbox
is unavailable: …" before spawn. The runner advertises `vm` in `capabilities` (protocol §3) when the floor has a `vm` block, the
probe passes and the daemon is not root.

**Launch chain.** daemon → run thread → `gino-vmm` → libkrun → `init.krun` (PID 1) →
`/gino-agent guest-init` → engine.

- The daemon prepares a private 0700 run dir (`$TMPDIR/gino-vm-<uuid>`) holding the boot root `boot/`
  with the control dir `boot/ctl/` (`spec.json` plus the copies in `ctl/view/`), the run's root disk
  overlay (`root.qcow2`, unless the task keeps one), the per-run sockets `ctl.sock`, `agent.sock` and
  (with a network) `net.sock`, and writes the gino-vmm run spec as the first stdin line.
- `gino-vmm` is spawned from a thread that lives as long as the run, because its
  `PR_SET_PDEATHSIG(SIGKILL)` fires when the spawning *thread* exits; killing the daemon kills the VM.
- libkrun boots with its default kernel command line from the boot root (virtiofs); `init.krun` stays
  PID 1 (it turns the workload's exit code into gino-vmm's exit status) and runs
  `/gino-agent guest-init`, which owns the rest of the mount table and reaps the engine's descendants
  as a child subreaper. The agent binary is an overlay file at `/gino-agent` because libkrun 1.19
  overlay files work only at the top level.
- guest-init mounts the root disk `/dev/vda` (ext4) at `/newroot`, mounts its `/run` tmpfs, binds the
  control dir read-only at `/run/gino/ctl` and the agent binary at `/gino-agent`, moves it over `/`
  and chroots. It then mounts the kernel filesystems and `/tmp`, grows the filesystem to the disk size
  (`resize2fs`), reads `/run/gino/ctl/spec.json` (`GuestSpec`), mounts the shares, brings up `lo` (and
  `eth0` with a network), starts the agent API forwarder, the control channel and (with `docker`)
  `dockerd`, then spawns the engine. Any setup failure prints `guest-init: …` and exits **121** without an `EXIT` line.
- **Engine identity.** The engine runs as the **daemon's uid/gid** (non-root, enforced; uid 1000 in
  the test harnesses), with every capability set cleared, `no_new_privs`, its own session and process
  group. virtiofs reports host files as owned by the daemon uid and guest root cannot chown through an
  unprivileged VMM, so running as that uid lets the engine own its work dir and home in the guest as on
  the host; host work-dir modes are not widened.
- **Stdio.** gino-vmm's stdio is the daemon's engine pipes; libkrun maps piped stdio to console ports
  (no tty), and stdin EOF reaches the engine. guest-init gives the engine plain pipes and relays them
  byte for byte (plain read/write loops; raw mode when the console is a terminal), draining the
  engine's output before it reports `EXIT` — the console is never handed to the engine. The stream and
  the claude control protocol are unchanged.

**Shares and guest paths.**

| guest path | how |
|---|---|
| `/` | the run's root disk: a qcow2 overlay over the base image, writable (see *Root disk*) |
| `/run/gino/ctl` | the per-run control dir from the boot root, bound read-only |
| the thread's `work_dir` | read-write virtiofs share at the **same absolute path** |
| `<work_dir>/.engine-home` | inside the work dir; `CLAUDE_CONFIG_DIR` / `CODEX_HOME` / `ENGINE_CONFIG_DIR` |
| global `CLAUDE.md`, `skills/` | copied into the control dir, bound read-only at the engine home's `CLAUDE.md` and one assembled `skills/` dir |
| task-scope store entries | copied into the control dir, bound read-only where their links point |
| `readPaths` / `writePaths` | virtiofs shares at their host paths (ro / rw) |
| `<workspace>/engines/home` | read-only virtiofs share (`engines`) at its host path, only when the run's engine binary is agent-installed (§9c) |
| `/run/gino/memory/task` | virtiofs share (`task-memory`) of this task's memory tree, read-write, including Claude's auto memory dir `claude/`; `GINO_MEMORY_DIR`; only with task memory on (§9f) |
| `/run/gino/memory/agent` | virtiofs share (`agent-memory`) of the agent memory tree, read-write for `rw`, a read-only share for `ro`; `GINO_AGENT_MEMORY_DIR`; absent when `off` |
| `/run/gino/conversations` | the conversations view (§9d) copied into the control dir (`ctl/view/<n>`) and bound read-only; `GINO_CONVERSATIONS_DIR`; only with task memory on |
| `/tmp`, `/run`, `/etc/resolv.conf` | tmpfs (`resolv.conf` bound from a tmpfs file) |

virtiofs shares only directories, so the single files and the skills/store entries are **copied**
into the control dir for every run (a per-run cost proportional to their size). guest-init creates a
missing share mount point or bind target on the root disk. The engine gets `HOME=TMPDIR=/tmp`, `GINO_VM=1`, `GINO_ARCHIVE_DIR`
(`<work_dir>/conversations`) and `GINO_RUNNER_BIN=/gino-agent` when the launch sets it; the PreCompact
archive hook runs `/gino-agent archive` inside the guest. The memory env vars name the guest paths of
the memory shares and the view the run has, as in the sandbox; the view is the same capped,
point-in-time snapshot, kept in the run dir and removed with it. `GuestSpec` validation admits shares
and binds inside `/run/gino` only under `/run/gino/memory` and `/run/gino/conversations`.
Claude auto memory works as in the sandbox: the `--settings` JSON passed to the guest (hook commands
already rewritten to `/gino-agent`) carries `autoMemoryDirectory` = `/run/gino/memory/task/claude`,
or `autoMemoryEnabled: false` plus `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` with task memory off; nothing
is written under `<work_dir>/.engine-home`, and other tasks' trees are never shared.

**Network.** TSI is never used (gino-vmm disables it); the only path out is an optional virtio-net
device.

- `none`: no network device, no `eth0`; `lo` only.
- `allowlist`: libkrun connects the virtio-net device to `net.sock`; the daemon wraps the stream with
  `nsplane-ether` (Ethernet framing, ARP, gateway MAC) and runs the run's user-space exit on it with the
  same rules, limits, DNS on `10.0.2.2`, LLM gateway and decision log as the sandbox allowlist (§9d).
  guest-init configures `eth0` statically (`10.0.2.15/24`, gateway and resolver `10.0.2.2`).
- `full`: the same exit with an allow-all public rule set (`RuleSet::allowing_public`) instead of the
  floor rules; loopback, private, link-local and other reserved destinations stay refused.

**Control channel and cancel.** A vsock port with `listen: true`: libkrun listens on `ctl.sock` and
connects to guest-init. Line protocol: daemon → guest `SIGNAL INT|TERM|KILL` (to the engine's process
group); guest → daemon `READY` once the engine runs (60 s bound) and `EXIT <code>` / `EXIT signal <n>`
before powering off. The `EXIT` line is the engine status; without it (gino-vmm exit 120, guest-init
121, crash, panic) the run fails with a runner-side reason naming gino-vmm and its status and stderr
tail. The codex interrupt sends `SIGNAL INT`. Session end or cancel sends `SIGNAL TERM`, kills gino-vmm
after a 5 s grace, stops the network exit and removes the run dir; neither a daemon kill nor a cancel
leaves a gino-vmm or VM process.

**Agent API over vsock.** guest-init listens on `/run/gino/agent.sock` (the engine's `GINO_AGENT_SOCK`)
and forwards each connection to vsock CID 2; libkrun maps that port to the per-run host socket
`agent.sock`, served by the daemon. Every connection there is a **run peer**: it must present the run's
token, is scoped exactly like a sandboxed run, and never gets operator access (the VMM is a same-uid
process, so peer credentials prove nothing there) (§10b).

**Root disk.** The daemon keeps its disks under `<workspace>/vm/disks/`: the base image is
hard-linked (or copied across filesystems) to `base/<sha256>.ext4`, keyed by content and cached in
`base/index.json` by device, inode, size and mtime, and bases no task pins are removed when the image
changes. Each run's root disk is a qcow2 overlay over the base, created by the daemon (imago) with the
configured size (never below the base), so the base is never written. A run needs a quarter of that
size free on the disks' filesystem, else it fails before spawn. With `vmDisk: "run"` the overlay lives
in the run dir and goes with it. With `vmDisk: "task"` it is `tasks/<task_id>/root.qcow2` with a
manifest (`disk.json`: base hash, layers, size, creation time) that pins its base, so the task keeps
its installed packages and files across runs, even after the image changes; one run holds it at a time
(a lock file), and a concurrent run of the same task gets a fresh run disk with a warning. The task's
disk is removed with the task. guest-init `sync`s before reporting `EXIT`.

**Docker.** With `docker: true` guest-init enables IPv4 forwarding and every cgroup v2 controller,
starts `dockerd` (`--group <engine gid> --ip6tables=false`, log in `/var/log/gino-dockerd.log` on
the root disk) and waits up to 30 s for `/run/docker.sock`; after the engine exits it stops dockerd
(`SIGTERM`, `SIGKILL` after 10 s). Containers and images live on the root disk, so a task disk keeps
them. The socket group makes the engine root-equivalent inside its own VM; the VM boundary is what
confines it. Container traffic leaves through the run's network like the engine's own.

**Limitations.** No nested virtualization in the guest. Each run reserves its own guest memory
(`memoryMib`) and vCPUs. On x86_64 libkrun has 11 device slots (gino-vmm/README.md *Device limit*):
balloon, RNG, console, boot root, root disk, vsock, the work share and (with a network) the network
device leave three or four for the engine home (when the run's engine is agent-installed), the memory
shares and the `readPaths` / `writePaths` directories; a run
needing more fails before the VM starts with libkrun's `IrqsExhausted` in the reason. KVM tests do not run in CI.

**Testing.** `gino-agent/scripts/vm-it.sh` runs the KVM suite (`tests/vm.rs` and the ignored `kvm_*`
unit tests) in sibling containers as uid 1000 with `/dev/kvm`, plus a fail-closed run without the
device. It builds or reuses the guest artifacts under `.tmp/vm`, builds the test binaries statically
linked (`crt-static`), and passes them through `GINO_VM_TESTS=1`, `GINO_VM_KERNEL`, `GINO_VM_ROOTFS`,
`GINO_VM_VMM`, `GINO_VM_AGENT` (plus `GINO_VM_PUBLIC_IP`, `GINO_VM_IT_LOGS`,
`GINO_VM_NO_KVM`). The run network is `192.88.99.0/24` by default (`PUBLIC_SUBNET` / `PUBLIC_IP`
override) so `full` has a public destination; the script is not safe to run concurrently on one host.
`tests/vm.rs` has the same memory scenarios as the sandbox suite.
The host repository's real-engine harness `SANDBOX_MODE=vm [SANDBOX_NETWORK=none|allowlist] bash e2e/run-real-sandbox.sh`
drives the real claude CLI in a microVM; the credential comes from the env, else
`CLAUDE_API_KEY_FILE` (read into `GINO_PROXY_ANTHROPIC_API_KEY`), else staged
`~/.claude/.credentials.json`. Its agent container uses the default bookworm base with the static
`gino-vmm` from `vm/vmm/build.sh`; the injected gino-agent is a static build.

## 9f. Agent and task memory

Engines forget everything between threads; memory gives them persistent, file-based notes that they
read and edit with ordinary file tools. No database, no embeddings. Two trees live under
`<workspace_dir>/memory/` on the agent, the agent-local source of truth:

| Tree | Path | Shared by | Engine env |
| --- | --- | --- | --- |
| agent | `memory/agent/` | every task on the agent | `GINO_AGENT_MEMORY_DIR` |
| task | `memory/task/<task_id>/` | every thread of one task | `GINO_MEMORY_DIR` |

Each tree holds `index.md` (core memory plus a map of the other files) and `system/definition.md`
(how to store, prune and correct memory). The templates are tree-specific
(`gino-agent/src/memory/{index,definition,agent-index,agent-definition}.md`); the agent definition
explains the shared scope and forbids task-private and owner-private data.

**Scope.** A task tree is task-local: other tasks never see it, the same rule as the run scope, and
a task never migrates between agents, so its memory never moves either. A task id that is not a
single plain path component gets no task memory (logged; the run proceeds without it).

**Configuration.** Agent-local environment variables; an invalid value fails startup:

| Variable | Values | Default |
| --- | --- | --- |
| `GINO_TASK_MEMORY` | `on` \| `off` | `on` |
| `GINO_AGENT_MEMORY_ACCESS` | `rw` \| `ro` \| `off` | `rw` |
| `GINO_MEMORY_MAX_BYTES` | positive byte count, per tree | `1048576` (1 MiB) |
| `GINO_CONVERSATIONS_MAX_BYTES` | positive byte count, cap on the conversations view of an isolated run | `8388608` (8 MiB) |

A task's optional `meta.memory` `{task, agent}` (field defined in [`protocol.md`](protocol.md) §5)
is read at launch like `meta.isolation` and only tightens these values (`on` > `off`;
`rw` > `ro` > `off`): a loosening value is ignored with a warning, and a malformed one fails the run
before spawn as `runner.invalid_request`. The effective values are resolved per thread at launch
and logged (`memory settings resolved`); a change applies to the next thread. A tree that is `off`
is not created, exported or injected; with both off the session gets no memory context at all (no
`SessionStart` hook, no codex prefix).

**Scaffold.** Before launch the executor scaffolds each enabled tree: it creates the directories
with mode 0700 and writes only missing files. Existing files are never overwritten — the content is
agent-owned. A scaffold failure is logged and the run proceeds without that tree.

**Injection.** `gino-agent memory-context [--max-bytes N] [--agent-read-only]` reads only
`GINO_AGENT_MEMORY_DIR` and `GINO_MEMORY_DIR` from its environment and prints the agent section
first, then the task section, each with `index.md` and `system/definition.md`. Every file is capped
at 16384 characters with a truncation notice; a tree over `--max-bytes` gets a size warning;
`--agent-read-only` marks the agent section read-only.

- **claude**: the runner-built `--settings` (next to the PreCompact archive hook, §9c) carries a
  `SessionStart` hook with matcher `startup|clear|compact` running
  `gino-agent memory-context --max-bytes <GINO_MEMORY_MAX_BYTES>` (plus `--agent-read-only` for
  `ro`). Resume injects nothing; compaction re-injects the context.
- **codex**: no hooks; the runner prepends the same rendering to the first prompt of a thread that
  has no `engine_session_id`.

**Claude native memory.** Claude Code's own auto memory is kept per task in the task tree instead
of under the engine config dir.

- **Mechanism**: with task memory on, the runner-built `--settings` (the same JSON object as the
  hooks, emitted also when no hooks are set) carries `autoMemoryDirectory` with the absolute path
  `<task memory>/claude`: the host path in unsandboxed launches, `/run/gino/memory/task/claude`
  inside sandbox and vm, where the value is rewritten as part of the launch rewrite of the
  isolation modes (§9d, §9e). The `--settings` flag outranks user and project settings; Claude
  loads that dir's `MEMORY.md` at session start.
- **Layout**: `claude/` holds Claude's `MEMORY.md` index and its topic files, managed by Claude.
  The scaffold creates `claude/` with mode 0700 whenever the task tree is enabled, also in an
  existing tree, and never touches its files.
- **Off**: when task memory resolves off (`GINO_TASK_MEMORY=off`, `meta.memory.task=off`, or no
  valid task id), `--settings` carries `autoMemoryEnabled: false` instead and the launch env gets
  `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`; the env var also stops Claude from hand-writing memory files
  on request. Nothing is written to the global engine config dir.
- **Coexistence**: `memory-context` names `$GINO_MEMORY_DIR/claude/` after the task section but
  never injects its contents; codex gets the same line, so it can read Claude's notes. The task
  `system/definition.md` template says the same: gino's `index.md` tree is the cross-engine store
  for facts every engine must know, and facts meant for the whole agent belong in agent memory.
- **Limits and operations**: `claude/` is part of the task tree, so the size cap counts it,
  `task_delete` removes it, and the admin fs operations see it.

**Exposure.** In sandbox and vm isolation only this task's tree is mounted, at
`/run/gino/memory/task`, and the agent tree at `/run/gino/memory/agent` (read-only for `ro`); with
task memory on the run also gets `GINO_CONVERSATIONS_DIR`, a read-only, capped snapshot of this task's
earlier threads' archives taken at launch. Details are in the isolation tables of §9d (sandbox) and
§9e (vm). In unsandboxed (`off`) isolation both env values carry host paths and `ro` cannot be
enforced: the engine runs as the agent user on the host paths and can write the agent tree. Unsandboxed
runs get no conversations view: the archive dirs there are host dirs shared across tasks, so none is
exposed.

**Limits.** The size cap is soft: over it the injected context carries a warning; nothing is
deleted or refused. Parallel threads of one task (or tasks sharing the agent tree) are
last-writer-wins; there is no file locking. The conversations view is point-in-time: archives of
concurrently running threads appear on the next launch.

**Lifecycle.** A host `task_delete` (applied as a cancel) removes the task tree, best-effort (a
failure is logged, never replayed). The agent tree is removed only by the operator. Operators see
and edit both trees through the existing admin fs operations (§10, `fs_request`); there is no
memory-specific API.

**Risk.** The agent tree is a channel between tasks. On agents shared between owners (owner-pinned
dispatch, public agents) a task can leak into or poison it; use `ro` there (agent-wide or per task)
together with sandbox or vm isolation, which enforce it.

**Deferred.** Host-side sync or snapshot of memory, restoring memory onto another agent, carrying
memory into a follow-up task, an admin memory UI, file locking between parallel threads, any vector
or embedding store.

## 10. Transport & protocol

WS primary (at-least-once via outbox/inbox + ack/msg_ack); HTTP for register/config/output + attachment proxy.

**Envelope vs payload.** Correlation/delivery metadata lives at the **envelope top level**; `data` carries
the type-specific business payload only:

```json
{ "type": "thread_message", "outboxId": "01jab3x7k2m4n5p6q7r8s9t0vw", "taskId": "t-1", "threadId": "c-9@1718…",
  "data": { "seq": 3, "kind": "assistant_text", "content": "…" } }
```

- Envelope: `type`, `outboxId`/`msgId` (delivery, lowercase ULIDs minted by the sender), **`taskId`/`threadId`/`cronId` (correlation)**.
- `data`: business fields only — **never** the correlation ids. `engine_session_id` is a *value* of the
  thread and stays in `data` (stored, not routed-by).
- The host routes/correlates by the **envelope** ids without parsing `data`, mirroring the runner's
  `inbox`/`outbox` correlation columns and the host read-model keys.

**host → agent** (envelope ids · data)

| type | envelope | data |
|---|---|---|
| `task_upsert` / `task_delete` | taskId | `{name?, kind?, …, e2ee?: {profile_id, group_id}}` |
| `cron_upsert` / `cron_delete` | taskId, cronId | `{kind, prompt, schedule_type?, schedule_value?, continuity, …}` |
| `message` | taskId, threadId? | `{text, attachments?}` |
| `interrupt` / `close` / `config_update` / `ack` | — | — |
| `fs_request` (live-only) | reqId | `{op, path, to?, recursive?, ref? + sha256? + size?, upload?}` |
| `e2ee_log` / `e2ee_welcome` | taskId | `{seq, kind, epoch, message, drop_public_key?}` / `{welcome, seq}` (DS records, through the inbox) |
| `e2ee_key_package_status` (live-only) | id? (the answered `outboxId`) | `{one_time, last_resort, rejected?}` |
| `e2ee_response` (live-only) | taskId, reqId | `{ok, error?, entries?, more?, epoch?, seq?, link?}` |

**agent → host** (envelope ids · data)

| type | envelope | data |
|---|---|---|
| `thread_result` | taskId, threadId | `{status, result?, error?, failure_reason?, engine_session_id?, duration_ms, final_seq, attachments?, encryption_error?}` |
| `thread_message` | taskId, threadId | `{seq, kind, role?, content?, tool?, input?, output?, tool_use_id?, parent_tool_use_id?}` |
| `cron_state` | taskId, cronId | `{kind, schedule_type?, …, round_count, skipped_count, last_status}` |
| `heartbeat` | — | `{activeThreads?, …, e2ee?}` |
| `e2ee_key_packages` | — | `{one_time?, last_resort?}` (through the outbox) |
| `e2ee_request` (live-only) | taskId, reqId | `{op: "log", after_seq}` / `{op: "link", epoch}` (the runner sends no other op) |
| `fs_response` (live-only) | reqId | `{ok, entries? \| stat? \| sha256 + size, error?}` |
| `msg_ack` | top-level `msgId` | — |

`kind` ∈ `{user_input, assistant_text, thinking, tool_use, tool_result, status, error}` (`thinking`/`log`
config-filterable). Bytes never in frames — only descriptors.

On an encrypted task the mapped fields of `message`, `cron_upsert`, `thread_message` and `thread_result`
travel as `{"e2ee": "<base64url envelope>"}` ([task-content §2](e2ee/task-content.md)); the runner opens
and seals them as described in §10c. The live-only e2ee frames bypass `inbox`/`outbox` like `fs_*`.

The runner emits `assistant_text`, `thinking`, `tool_use`, `tool_result`, `status` and `error`;
`user_input` is defined but not emitted by the runner. `parent_tool_use_id` is present on every event
produced inside a sub-agent (a `Task` tool call) and absent for the main agent's own events — absence
means the main agent. `tool_use_id` is the engine's id for a `tool_use` block, echoed on the matching
`tool_result`, so a reader can pair a call with its return value; `tool_result.output` carries
`{content, is_error}`. Attribution introduces **no hierarchy**: `seq` stays a single per-thread monotonic
stream across all kinds, and there are no sub-threads or parent tasks.

**Engine-free file operations (`remote_ops/`).** `fs_request` lets the host list, stat, read, write,
create, rename and remove files without prompting an engine (protocol §5.1). The transport recognizes the
frame **before** the inbox write and answers it off the socket task: the operation runs on the blocking
pool and its `fs_response` is sent straight to the socket, like `heartbeat`. Neither frame touches `inbox`
or `outbox`, so nothing is replayed after a reconnect, and a response produced for a dropped connection is
discarded. **File contents never ride in a frame**: `put` downloads the blob the host staged on the
attachment byte channel (§9) into a temp file beside the destination, verifies its sha256 and renames it
into place; `get` uploads the file to the byte channel under the name the host chose. Both go through
the attachment backend directly — no content-type allowlist and no copy in the content-addressed cache —
and are bounded by the single-attachment size limit. The group is **off** until the host-assigned config sets `remoteOps.fs` (register config,
`GET /agent/config`, or a live `config_update`); the agent has no local switch and answers `disabled`
meanwhile. **Paths are not confined**: a relative path resolves against `workspace_dir`, an absolute one is
used as given — whoever holds the host's admin token can reach every file the agent's uid can, on every
agent where the group is enabled. Standalone command requests remain deferred.

**Interactive terminals (`remote_ops/pty.rs`).** `remoteOps.pty` enables connection-scoped
`pty_*` frames (protocol §5.2). `pty-process` supplies asynchronous PTY allocation and process
spawning. Each session has ordered bounded input, raw-byte output, resize, cancellation and
explicit child reaping. Disabling PTY revokes active sessions through a configuration epoch.
The socket owns the session registry and a bounded live output channel; both are discarded
and workers joined before reconnect. No terminal frame enters inbox/outbox or starts an engine.

**Multiplexing & ordering (one WS, N parallel threads).** Concurrent threads' frames interleave. The host
**demuxes by `threadId`**, **orders each thread's transcript by `seq`** (per-thread monotonic, assigned
serially by the runner), and writes idempotently on `(thread_id, seq)` (dedup, since at-least-once replay can
duplicate). `thread_result.final_seq` lets the host verify it received `1..final_seq`. `outboxId` is
delivery/ack only; `seq` is the per-thread continuity contract.

## 10b. Local agent API

**Purpose.** A local, per-workspace API through which in-engine tools (the `gino` CLI, skills, a future VM
guest) read and change agent state. It is the one contract they all follow. Target design: **nothing
outside the daemon opens `agent.db`** — the in-engine CLI becomes a client of this API instead of opening
the database itself.

**Transport.** Unix stream socket at `<workspace_dir>/run/agent.sock`.

- The daemon creates `<workspace_dir>/run` with mode **0700** (and chmods an existing dir to 0700), removes
  any stale file at the socket path, binds, then sets the socket file to **0600**.
- The socket lives as long as the daemon: on shutdown the listener stops, open connections close and the
  socket file is removed (best-effort).
- A `vm` run (§9e) reaches the API over vsock: guest-init forwards `/run/gino/agent.sock` to a per-run host
  socket (`agent.sock` in the run dir) whose every connection is a run peer that must present the run's
  token — never operator, regardless of peer credentials.

**Framing.** Newline-delimited JSON (UTF-8). One request per line, exactly one response line per request,
in order; a connection may carry any number of requests.

```json
{"v":1,"id":"1","method":"cron.list","params":{}}
{"v":1,"id":"1","result":{"crons":[],"scoped":true}}
{"v":1,"id":"2","method":"thread.show","params":{"id":"nope"}}
{"v":1,"id":"2","error":{"code":"not_found","message":"no such thread: nope"}}
```

- `params` is optional (absent = `{}`) and must be a JSON object when present.
- `id` is a client-chosen string, echoed verbatim; it is `null` in the response when the line could not be
  parsed far enough to read a string `id`.
- Every response carries `"v":1` and exactly one of `result` / `error` (`{code, message}`).

**Limits and timeouts.**

| limit | value | on violation |
|---|---|---|
| request line length (excluding `\n`) | 65536 bytes | one `invalid_params` response (id `null`, "request line exceeds 65536 bytes"), then the connection is closed |
| idle connection (no complete request line) | 60 s | connection closed |
| method handler | 10 s | `unavailable` ("request timed out") |
| concurrent connections, total | 64 | connection closed immediately, no response |
| concurrent authenticated connections per run token | 8 | that `auth` returns `unavailable` ("too many connections for this token"); the connection stays unauthenticated |
| concurrent operator connections | 8 | connection closed immediately, no response (counted separately from run tokens) |

**Versioning.** `v` must be the integer `1`. A missing or different `v` returns `unsupported_version`
("unsupported protocol version; this agent speaks v1"). Future versions bump `v`; the daemon answers only
versions it implements.

**Authentication.** A connection's scope is either **operator** (full access) or **run**
(`{task_id, thread_id}`); a new connection has no scope unless it qualifies as operator. Any method other
than `auth` on a connection without scope returns `unauthenticated`.

- **Run tokens.** 256 random bits from `/dev/urandom`, hex-encoded (64 lowercase hex chars). The registry
  stores only the SHA-256 of each token mapped to its scope, so lookups never compare the raw secret. The
  executor registers a token **before spawning** an engine run and **revokes** it when the run ends. The
  engine receives `GINO_AGENT_SOCK` (socket path as seen by the engine), `GINO_AGENT_TOKEN`, and the
  existing `GINO_TASK_ID` / `GINO_THREAD_ID`.
- **`auth`** `{"token":"<hex>"}` → `{"scope":"run","task_id":"…","thread_id":"…"}`. An unknown or revoked
  token returns `unauthenticated` and leaves the connection with **no** scope — an operator connection that
  presents a bad token loses operator access too.
- **Revocation.** Once revoked, every later request on a connection that authenticated with the token gets
  `unauthenticated`, and new `auth` with it fails.
- **Operator access.** At accept time the server reads the peer credentials (`SO_PEERCRED`). The connection
  is operator-scoped iff the peer uid equals the daemon's uid **and** the peer pid is known **and** the
  targets of `/proc/<pid>/ns/user` and `/proc/<pid>/ns/pid` equal the daemon's own
  (`/proc/self/ns/{user,pid}`). Any read failure → not operator. A sandboxed engine runs in nested
  namespaces, so it never gets operator access even when its outer uid matches. Operator connections need
  no `auth`.
- **A presented token always wins:** an operator connection that authenticates with a valid token becomes
  run-scoped.

**Run-scope rules.** A run-scoped caller only sees and changes its own `task_id`:

- an explicit `task_id` param that is not its own → `forbidden`;
- a task, thread or cron named by id that belongs to another task → `not_found`, with exactly the
  response a missing id gets, so another task's objects are indistinguishable from nonexistent ones
  (and nothing is changed);
- listings are filtered to its own task; `system.info` is redacted (below).

**Threat-model limit.** Unsandboxed engines run as the daemon's uid and can read another engine's token
from `/proc/<pid>/environ`, so run scope is a hard boundary **only under the engine sandbox** (§9d,
separate PID namespace) — matching the isolation model.

**Object shapes.** Field names are snake_case; optional DB columns are `null` when empty.

| shape | fields |
|---|---|
| TaskSummary | `id, name, kind, status, created_at` (`name`/`kind` nullable) |
| ThreadSummary | `id, task_id, status, source, attempt, max_attempts, engine_session_id` |
| ThreadDetail | ThreadSummary + `cron_id, failure_reason, engine, duration_ms, prompt, result, error` |
| CronInfo | `id, task_id, kind, status, schedule_type, schedule_value, next_run, last_fired_at, continuity, run_count, prompt, created_at, updated_at` |

**Methods.**

| method | params | result |
|---|---|---|
| `auth` | `{token}` | `{scope:"run", task_id, thread_id}` |
| `system.info` | `{}` | see below |
| `task.list` | `{}` | `{tasks:[TaskSummary]}` |
| `task.show` | `{id}` | `{task:TaskSummary, threads:[ThreadSummary], crons:[CronInfo]}` |
| `thread.list` | `{task_id?}` | `{threads:[ThreadSummary]}` |
| `thread.show` | `{id}` | `{thread:ThreadDetail}` |
| `thread.action` | `{method, params?}` | `{seq}` |
| `cron.create` | `{type:"cron"\|"interval"\|"once", value, prompt, continuity?="isolated", task_id?}` | `{cron:CronInfo}` |
| `cron.list` | `{task_id?}` | `{crons:[CronInfo], scoped:bool}` |
| `cron.delete` | `{id}` | `{cron:CronInfo}` (status `cancelled`, `next_run` null) |
| `cron.pause` | `{id}` | `{cron:CronInfo}` (status `paused`, `next_run` kept) |
| `cron.resume` | `{id}` | `{cron:CronInfo}` (status `active`, `next_run` recomputed) |

- **`system.info`.** Operator:
  `{"scope":"operator","version","agent_id","name","host_url","capabilities":["claude"],"workspace_dir","db_path","tasks":N,"active_crons":N,"threads":{"pending":N,"running":N}}`.
  Run: the same without `workspace_dir` / `db_path`, `"scope":"run"`, and counts covering only the caller's
  own task. `version` is the crate version; `agent_id` the persisted identity's id (`null` if not
  registered); `name` / `host_url` the daemon config `agent_name` / `host_url` (nullable). It never
  includes the connect token, the enrollment token or any other task's data.
- **`task.list`.** Run: only its own task, if it exists.
- **`task.show`.** Missing, or (run scope) another task's id → `not_found` ("no such task: <id>").
- **`thread.list`.** Run: defaults to (and only allows) its own task. Operator: `task_id` required
  (`invalid_params` "task_id is required").
- **`thread.show`.** Missing, or (run scope) another task's thread → `not_found` ("no such thread: <id>").
- **`thread.action`.** Run scope only; operator → `forbidden` ("thread.action requires a run token").
  `method` is a non-empty string, `params` an optional JSON object; any other field (no task or thread
  id can be named) → `invalid_params`. The daemon appends one `thread_message` to the token's own thread,
  exactly like an engine event: in one transaction it takes the thread's next `seq` (the counter the
  executor uses, `threads.last_seq`) and enqueues the outbox row correlated with the token's
  `task_id`/`thread_id`, then nudges the transport flush. `data` is
  `{seq, kind:"host_action", input:{method, params}}`, with `params` `{}` when not given. The call returns
  once the event is enqueued; no host reply is awaited. `method` and `params` are opaque to the agent: the
  host defines them and applies each event once, keyed by `(threadId, seq)` (protocol §5). CLI:
  `gino action <method> ['<json params>']` (`$GINO_RUNNER_BIN action …`) prints the `seq`; params that are
  not valid JSON or not an object fail before any call. On an encrypted task (decided from the task row,
  whatever the group state) a `method` not declared by the profile's host-action table
  ([task-content §2.1](e2ee/task-content.md); empty for `gino.task-content.v1`, so every method) →
  `forbidden` ("host actions are not available on this end-to-end encrypted task: the method is not
  declared by its e2ee profile"; the method is not echoed), nothing appended, no `seq` consumed: the
  method stays cleartext. A declared method is sealed in the same transaction, bound to the `seq` it
  takes (`input.params` sealed except the declared plain paths); the engine holds no key. If the task
  cannot seal (group not ready, no e2ee state) the call returns `unavailable` ("the task is end-to-end
  encrypted and the action cannot be sealed: <code>"), nothing is enqueued and no `seq` is consumed.
  Unencrypted tasks accept any non-empty `method`.
- **`cron.create`.** Run: task defaults to its own; operator: `task_id` required. A `continuity` other than
  `isolated`/`shared` → `invalid_params` ("continuity must be 'isolated' or 'shared' (got '<x>')"); a
  schedule rejected by `next_run_at_creation` → `invalid_params` ("invalid schedule: type=<t> value=<v>:
  <reason>"); unknown task → `not_found` ("no such task: <id>"). The row is built like the CLI's
  `cron create`: id `cron-<uuid v4>`, kind `schedule`, status `active`, `run_count` 0,
  `created_at` = `updated_at` = now. On an encrypted task the prompt is stored sealed as
  `cron_upsert.data.prompt` under the current epoch; a prompt that cannot be sealed returns
  `unavailable` and is never stored in plaintext.
- **`cron.list`.** Run: all of its own task's crons (every status), `scoped:true`. Operator: with
  `task_id` → that task's crons, `scoped:true`; without → active crons across all tasks, `scoped:false`.
- **`cron.delete` / `cron.pause` / `cron.resume`.** Missing, or (run scope) another task's cron →
  `not_found` ("no such cron: <id>"), with no side effects. `cron.resume` recomputes `next_run` forward from now via
  `next_run_at_creation` (`null` if that fails).
- **Sealed values on display.** `thread.show` (`prompt`, `result`, `error`), `task.show`, `cron.list`
  and the cron mutations (`prompt`) open an encrypted task's sealed values in the daemon for display
  (the runner trust boundary, §10c); a value that does not open reads `[sealed: <code>]`.
- **Cron side effects.** Every successful cron mutation (`create`, `delete`, `pause`, `resume`) updates
  `updated_at`, enqueues a `cron_state` outbox row (best-effort; a failure is logged, not returned), then
  nudges the scheduler and the transport flush.

**Error codes** (stable snake_case strings).

| code | meaning |
|---|---|
| `unauthenticated` | no valid scope on this connection (no `auth` yet, bad token, revoked token) |
| `forbidden` | an explicit `task_id` param outside the caller's scope; a run-only method on an operator connection |
| `not_found` | the referenced task / thread / cron does not exist, or is outside the caller's scope |
| `invalid_params` | malformed JSON, missing / ill-typed fields, invalid schedule, unknown method ("unknown method: <name>") |
| `unsupported_version` | `v` missing or not `1` |
| `unavailable` | handler timeout, connection limits, daemon shutting down |
| `internal` | unexpected daemon-side failure (e.g. a database error); generic message |

**Reachability.** The protocol is the same everywhere; only the path differs.

| run | socket as seen by the engine |
|---|---|
| unsandboxed | `<workspace_dir>/run/agent.sock` directly |
| sandboxed (§9d) | bound read-write at `/run/gino/agent.sock` |
| VM (§9e) | `/run/gino/agent.sock` in the guest, forwarded over vsock to a per-run host socket that accepts run peers only |

## 10c. E2ee runner flow

The runner role of end-to-end encryption ([spec](e2ee/spec.md), profile
[`gino.task-content.v1`](e2ee/task-content.md), wire contract protocol §5.3). It lives in
`gino-agent/src/e2ee/` on top of the `gino-e2ee` crate (MLS via OpenMLS); other modules call `e2ee`,
never `gino-e2ee` directly. A plaintext task is untouched by all of this.

**Identity and at-rest keys.** Two 32-byte key files in the state directory — the directory of the agent
DB (`e2ee::state_dir`; by default the workspace root, next to `agent.db`):

| file | holds |
|---|---|
| `e2ee-identity.key` | Ed25519 seed of the runner's MLS identity (BasicCredential) |
| `e2ee-state.key` | AES-256-GCM key sealing the e2ee blobs of the agent DB at rest (§3) |

- Created on first start with mode `0600` (`O_NOFOLLOW`); refused at startup when the mode is wider than
  `0600`, the length is not 32 bytes or the path is not a regular file (a symlink included). Both load
  before registration, which advertises the identity.
- The identity fingerprint (spec §3.5) is logged at startup (`e2ee identity key`). The key bytes are never
  printed, never placed in an engine's environment or arguments, never bound into a sandbox or VM, and
  never exposed by the local API (§10b); sandbox `readPaths`/`writePaths` refuse them (§9d).
- The key files and the DB belong together: a KeyPackage store that does not open under `e2ee-state.key`
  stops startup; a group snapshot that does not open marks that task's group `lost`.

**Capability.** `POST /agent/register` and every `heartbeat` carry `e2ee {versions: [1], mls_suites: [1],
credential: {type: "basic", public_key}}`.

**KeyPackage pool.** The runner keeps 10 one-time KeyPackages at the host, tops up when the host reports
fewer than 5, and keeps a current last-resort KeyPackage, replaced when the host holds none or when less
than 28 of its 84 days remain (checked hourly). A runner without KeyPackage state (fresh or lost DB)
publishes the initial pool once. Each publication persists the sealed store and enqueues the
`e2ee_key_packages` upload in one transaction, the store first. One upload is in flight at a time: only the
`e2ee_key_package_status` whose `id` equals the upload's `outboxId` (or a later status) can trigger the
next publication — a status that may predate the upload never does; an answer with `rejected` waits for the
next status. A `key_changed` rejection logs that an operator must re-pin the runner's key at the host.

**Task marker.** `task_upsert.data.e2ee {profile_id, group_id}` is recorded on the task row
(once set never changed or cleared; a different later value is logged and ignored) and creates the
task's `e2ee_groups` row as `pending`. A profile other than `gino.task-content.v1`, or a group id that is
not the task's derivation (spec §2.3), marks it `lost`.

**Group state (DS-ordered).** The runner never commits: its group advances only by the host's DS log.

- `e2ee_log` / `e2ee_welcome` arrive durably through the inbox and are buffered as received in
  `e2ee_log_pending`, then applied strictly in `seq` order. A Welcome joins the group (status `member`,
  the KeyPackage store persisted with it); log entries before the runner's Welcome wait
  for it; replays are dropped; a failing entry stops the log (never skipped). A commit that removes the
  runner sets `removed`. Each change persists the key cache, the sealed snapshot and the consumed record
  in one transaction before it counts.
- **Catch-up.** A gap in the buffered `seq`s, every socket open (for every task where the runner is a
  `member`) and content of a newer epoch read the log over the live socket: `e2ee_request {op: "log",
  after_seq}`, following `more`. `DsLink` (`src/transport/ds.rs`) pairs `e2ee_request`/`e2ee_response` by
  `reqId`, bounds each request at 10 s and fails pending requests on disconnect.
- Opening or sealing first waits until the task's buffered records are applied and its catch-up after the
  last socket open is done, at most 30 s; then `epoch_unknown`.

**History.** Content of an older epoch opens through the backward epoch-link walk (spec §7): a link the
walk misses is fetched with `e2ee_request {op: "link", epoch}`; the DS holding none gives
`history_unavailable`. Recovered epoch secrets are written to `e2ee_key_cache` (sealed) so a later open
needs no walk. The runner writes no links (`put_link`) and does not use `log_from_epoch`.

**Inbound: open before the turn.** An encrypted task's input stays sealed in the DB (`threads.prompt`,
`crons.prompt`, inbox frames, attachment names). Right before a run the executor opens it in memory — a
cron thread's prompt as `cron_upsert.data.prompt`, any other prompt and its attachment names as `message`
fields. Inbound attachment bytes are file envelopes: the verified envelope is what the attachment cache
keeps, and the opened plaintext is written to `work_dir/inputs/` under the opened name. A drop-sealed
`message.data.text` (webhooks, spec §9) is opened with the drop key and handed to the engine like any
prompt. A field that does not open, or a mapped field in plaintext (`plaintext_rejected`), fails the thread
with `agent.encryption` (§6) before the engine is spawned; a transport/IO failure downloading an envelope
stays `runner.runtime_offline`.

**Outbound: seal before the outbox.** Every mapped field is sealed under the current epoch inside the DB
transaction that enqueues the frame, so `outbox` and `threads` only ever hold ciphertext.

- `thread_message` (engine events and `thread.action`): `seq` = `threads.last_seq + 1` is taken first and
  bound in the AAD; only after sealing succeeds are `last_seq` bumped and the row enqueued. A failure writes
  nothing and consumes no `seq`. Mid-turn this stops the turn (`agent.encryption`, engine killed); from
  `thread.action` the engine gets an error (§10b).
- `thread_result`: the `outboxId` is minted first (`db::new_delivery_id`) and bound in the AAD of `result`
  and `error` (`delivery:{outboxId}`); the row is enqueued under that id (`enqueue_outbox_with_id`), and
  `threads.result`/`threads.error` keep the sealed values with `threads.result_outbox_id` recording the
  binding for the local API.
- Output files: each `work_dir/output/` file is sealed as a file envelope and uploaded as `<sha256>.bin`,
  `application/octet-stream`, the descriptor `sha256`/`size` describing the envelope and its `name` (the
  real name) sealed with the `thread_result`. Only the envelope is cached. A file that does not seal fails
  the turn with `agent.encryption`.
- A frame that cannot be sealed is never sent; the synchronous reapers send an encrypted task's
  `thread_result` without `result`, `error` and `attachments` (§6). There is no HTTP output path: every
  frame goes through the outbox.

**Remote operations.** While the runner is a `member` of any task group (a DB read failure counts as
member), `fs_request` answers `{ok: false, error: {code: "denied"}}` and `pty_open` ends with `pty_exit`
`denied`, whatever the host's `remoteOps` says; terminals opened before the runner joined end `denied` at
the next heartbeat tick. The runner-local opt-in `--allow-remote-ops-with-e2ee` /
`GINO_ALLOW_REMOTE_OPS_WITH_E2EE` lifts the refusal and logs a warning at startup; it is a bootstrap flag
only — no host config, overlay or local API method can set it.

**Agent DB loss.** With the key files kept and the DB gone, the runner registers again as a new agent id
(the enrollment token is needed) with the same identity key, publishes a fresh KeyPackage pool and holds no
group state. Turns of an encrypted task fail `agent.encryption` with `not_member` ("no group state for this
task; re-add this runner") until a client member commits Remove(old leaf) + Add(a fresh KeyPackage); the
runner then joins and recovers history through the epoch links. Losing `e2ee-state.key` with the DB kept stops
startup once the DB holds a KeyPackage store (it no longer opens); losing `e2ee-identity.key` is a new
identity the host refuses (`key_changed`) until an operator re-pins it.

**Trust boundary.** Encryption keeps content off the host, not out of the runner. Inside the runner content
is plaintext: the engine receives the opened prompt, engine-local state (session files under the engine
home), the memory trees (§9f), `work_dir` (materialized inputs, outputs before sealing) and the workspace
hold it, and the engine's model provider receives it. The local API shows opened values to its callers.

## 11. Host-side read models (mirror; otherwise host-private)

- **`tasks`** — mirror of the top-level entity.
- **`crons`** — trigger defs (from `cron_state`).
- **`thread_runs`** — one row per execution (from `thread_result`), keyed by `thread_id`, with `task_id`,
  `cron_id`, `status`, `failure_reason`, `duration_ms`.
- **`messages`** — durable transcript `{task_id, thread_id, seq, kind, role, content, tool, input, output,
  created_at}` (from `thread_message`); the conversation-parse source. **Composite key `(task_id, thread_id,
  seq)`** (index/grouping); minimal uniqueness/dedup `(thread_id, seq)` (thread_id is globally unique →
  determines task_id). Order a thread by `seq`; order threads within a task by `thread.created_at`.
- **`attachments`** — `{id, task_id, thread_id, name, content_type, size, sha256, ref, direction}`,
  referenced from `messages` by `id`.
- `task_id ↔ delivery channel` mapping stays host-private.

## 12. Identifiers

| id | layer | meaning | cardinality |
|---|---|---|---|
| **`task_id`** | top | global category per runner; everything belongs to it | the anchor |
| **`cron_id`** | child of task | a trigger/schedule | 1 task : N |
| **`thread_id`** | child of task | one engine execution/conversation | 1 task : N |
| **`engine_session_id`** | *field on thread* | the engine (claude) `--resume` handle | per-thread, may rotate / be shared across a shared thread's turns |

"session" is **only** `engine_session_id` (a field), never an entity.
