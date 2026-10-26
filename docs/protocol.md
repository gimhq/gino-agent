# Host ⇄ Agent Protocol (the contract)

This document is the **single coupling point** between the two otherwise-independent
architectures:

- **Host** (control plane) — any implementation of this protocol: orchestration, launchers,
  storage, UI. [`gino-mini-host`](../gino-mini-host/src/lib.rs) is a minimal reference host.
- **Agent / runner** (data plane) — `gino-agent/**`, Rust. Executes work via engines.

Each side implements this protocol independently and is versioned and
deployable on its own. Anything not specified here is private to one side and must not be
assumed by the other. If a change needs both sides to agree, it is a change to *this
document* (and the protocol version) — nothing else.

The model is **task / cron / thread**. It pairs with the data-plane spec
[`docs/agent-architecture.md`](agent-architecture.md) (§10 transport, §12 identifiers) and
the [e2ee specification](e2ee/spec.md). The runner types live in `gino-agent/src/protocol.rs`.

## 1. Versioning

- The protocol carries a `protocolVersion` (integer, current = **1**).
- The agent sends `protocolVersion` in `POST /agent/register`; the host returns the
  version it will speak in the register response. If they cannot agree, the host returns
  `register_error { reason: "unsupported_protocol" }` and the agent exits.
- Compatibility rule: **additive only within a major version** — new optional envelope
  fields and new envelope `type`s are non-breaking; receivers MUST ignore unknown
  `type`s and unknown fields. Removals/renames/semantics changes bump the version.

## 2. Transport

- **WebSocket is the primary, bidirectional channel** for all work and results.
- **HTTP** is used only for enrollment + bootstrap + a pre-WS output fallback + the
  attachment byte channel: `POST /agent/register`, `GET /agent/config/:agentId`,
  `POST /agent/output/:agentId`, and (host-proxy backend) `GET /agent/attachments/:id`
  (an attachment by descriptor id), `GET /agent/attachments?sha256=<hex>` (a
  config/skill artifact in the agent's desired set, content-addressed — the
  provisioning fetch), and `POST /agent/attachments` (upload: bytes ride the raw
  body; metadata rides the `x-attachment-name` / `x-attachment-sha256` headers or
  equivalent query params; the response is the flat descriptor JSON `{id, name,
  content_type, size, sha256, ref, direction}`). A descriptor's `ref` is a
  byte-channel path the agent resolves against its host base URL
  (`/agent/attachments/<id>`) — never a host-internal storage path.
- **Live-only frames** ride the same WebSocket but bypass both delivery buffers: the
  `fs_request` / `fs_response` pair (§5) is never persisted, acked or replayed. It is
  correlated by a host-minted top-level `reqId`, and a request can only be sent to an
  agent that is connected right now.
- The agent always **dials out** to the host (NAT/firewall friendly). The host never
  connects into the agent; out-of-band control is the host's launcher's job, not part of this protocol.

## 3. Enrollment — `POST /agent/register`

Unauthenticated by connect token; carries the bootstrap **register token** instead.

Request:
```json
{ "registerToken": "<secret>", "protocolVersion": 1,
  "name": "<human label?>", "capabilities": ["claude", ...],
  "version": "<agent build version?>", "platform": "<arch-os?>", "source": "docker|vm|bare?",
  "e2ee": { "versions": [1], "mls_suites": [1],
            "credential": { "type": "basic", "public_key": "<base64url Ed25519 key>" } } }
```
Response (success):
```json
{ "agentId": "<host-generated>", "connectToken": "<per-agent secret>",
  "config": { "agentId": "...", "wsUrl": "/agent/ws/<agentId>",
              "configUrl": "/agent/config/<agentId>", "outputUrl": "/agent/output/<agentId>",
              "heartbeatIntervalMs": 30000, "protocolVersion": 1,
              "entries": [ { "name": "...", "sha256": "...", "target": "...", "kind": "file|dir" } ],
              "version": 0,
              "remoteOps": { "fs": false, "pty": false },
              "executor": { "runningTimeoutSecs": 3600 } } }
```

`config.entries` is the GLOBAL-scope desired provisioning set and `config.version`
the host-assigned monotonic global config version (agent-architecture §9b): the
agent reconciles the global scope only when `version` advances past its applied
version. The same two fields are delivered on `GET /agent/config/:agentId`
(which returns the config object FLAT, not nested under `config`) and on
`config_update`.
`config.remoteOps` carries the host-set switches for engine-free operations (§5); every
group is `false` until an operator enables it for that agent. It is delivered the same
three ways. The agent has no local switch and never sets it itself: a `remote_ops` value
in the register body's `capabilities` is ignored.
`config.executor` carries host-set, per-agent executor limits: `dispatchedTimeoutSecs`,
`runningTimeoutSecs`, `inactivityTimeoutSecs` and `maxAttempts`, each an optional positive
integer, except that `inactivityTimeoutSecs` may be 0, which disables the agent's inactivity
watchdog. Only the keys an operator set are present (`{}` when none); an absent key keeps the
agent's default. It is delivered on register and `GET /agent/config/:agentId`, and pushed as
`config_update { "executor": {...} }` when an operator changes it. The agent reads the limits
when it builds its executor, so a change takes effect at the agent's next start.
Response (failure): `{ "register_error": { "reason": "invalid_register_token | rate_limited | invalid_body | registration_disabled | unsupported_protocol" } }`.

Rules:
- The host generates `agentId`. The agent does not choose it.
- The **connect token** authenticates the WS + HTTP config/output/attachments (header
  `x-internal-token`). It is **never** the register token; the agent persists it locally
  (`connect.token`) and reuses it on reconnect — no re-register needed.
- The host is the authority for `config` (credentials/engine settings arrive via the
  host's config layer).
- `capabilities` advertises the engines the runner can **actually run** — a runtime property
  (the agent probes for each engine's binary at registration), not a build constant. The host
  matches a task's `engine` (§7 `task_upsert`) against that list when **placing** the task, so an
  engine no permitted agent advertises leaves the task unplaced rather than failing it.
  Two further values describe isolation, not engines: `sandbox` when a sandboxed engine launch is
  possible (the bubblewrap probe passes and the daemon is not root), and `sandbox:allowlist` when
  allowlist network mode is also possible (`/dev/net/tun` is available; only sent alongside
  `sandbox`), then `vm` when microVM isolation is possible (the local isolation file has a `vm` block,
  the vm probe passes and the daemon is not root; agent-architecture §9e). The same list rides on every `heartbeat` (§5), so a change reaches the host without
  re-enrollment.
- `e2ee` (optional, additive) is the runner's end-to-end encryption capability, exactly the object
  of [e2ee spec](e2ee/spec.md) §10: `versions` (supported envelope versions), `mls_suites` (MLS
  suite ids as JSON integers), `credential.type` (`basic`) and `credential.public_key` (the raw
  32-byte Ed25519 identity key, base64url without padding). The runner is e2ee-capable iff the
  object is present, `versions` contains `1`, `mls_suites` contains `1` and `public_key` decodes
  to 32 bytes; receivers ignore unknown members. The host's key directory pins the first key it
  sees for the `agentId` (spec §3.5). Like `capabilities`, the object rides on every `heartbeat`
  (§5) so the directory holds the latest copy; a different `public_key` for the same `agentId` is
  never applied silently but recorded as a key change awaiting an operator re-pin. A runner
  without the object never receives encrypted work (§5.3).
- `config.engine.isolation` (optional, additive) is the host-delivered default isolation for engine
  runs, delivered the same three ways as `config.entries`:
  `{"mode"?: "off|sandbox|vm", "network"?: {"mode"?: "none|full|allowlist", "allow"?: [rule]},
  "readPaths"?: [abs path], "writePaths"?: [abs path], "allowTaskOverride"?: bool}` (field semantics:
  agent-architecture §9d). Without an agent-local isolation file the block replaces the agent's
  previous default wholesale; with one, the file is a floor and the agent honors only a tightening
  `mode` / `network.mode`, ignoring the rest with a warning.

## 4. WebSocket framing + delivery guarantee

`GET /agent/ws/:agentId` with header `x-internal-token: <connectToken>`.

### 4.1 Envelope vs payload (the core rule)

Every frame is one JSON object. **Correlation/delivery metadata lives at the envelope top
level; `data` carries the type-specific business payload only.**

```json
{ "type": "thread_message", "outboxId": "01jab3x7k2m4n5p6q7r8s9t0vw", "taskId": "t-1", "threadId": "c-9@1718…",
  "data": { "seq": 3, "kind": "assistant_text", "content": "…" } }
```

- **Envelope** keys: `type`; the delivery ids `outboxId` (agent → host) / `msgId`
  (host → agent); the correlation ids
  `taskId` / `threadId` / `cronId`; and `reqId` on live-only file requests or `ptyId` on live terminal sessions.
- **`data`**: business fields only — it **never** repeats the correlation ids. In
  particular `engine_session_id` is a *value* of a thread (the engine `--resume` handle),
  so it lives **inside `data`** on `thread_result` (stored, not routed-by).
- The host routes and correlates by the **envelope** ids *without parsing `data`*,
  mirroring the runner's `inbox`/`outbox` correlation columns and the host read-model keys.
- Which ids are present depends on the frame (see §5). `interrupt` MAY carry `taskId` to
  scope the cancel to one task; `close` and the acks carry no correlation ids; deletes
  carry only their identity ids and no `data`.

### 4.2 Delivery — at-least-once both ways

- Sender persists each outbound frame (outbox) before sending; unacked frames replay on
  reconnect.
- **Delivery ids are ULIDs**: 26 lowercase Crockford base32 characters
  (`^[0-7][0-9a-hjkmnp-tv-z]{25}$`), minted by the sender from a monotonic generator and
  used as its outbox row key. Ids from a recreated or restored sender database never collide
  with ids the receiver has already seen, and replay order is the ids' string order.
- **Agent→host**: every durable frame carries `outboxId`; the host replies
  `{ "type": "ack", "id": <outboxId> }` after the durable mirror write and the agent clears
  the outbox row on that ack.
- **Host→agent**: every durable frame carries `msgId`; the agent dedups inbound frames on
  `msgId` and replies `{ "type": "msg_ack", "msgId": <msgId> }` once it has durably stored
  the frame, which stops host replay.
- Receivers MUST be idempotent (dedupe by id; see §6) and MUST ignore unknown `type`s and
  unknown fields.

## 5. Frame catalog

`data` casing: business fields are snake_case (`engine_session_id`, `duration_ms`,
`final_seq`, `round_count`, `schedule_type`, …) except `heartbeat.activeThreads`. Envelope
ids are camelCase (`taskId`, `threadId`, `cronId`, `outboxId`, `msgId`). An attachment
descriptor is `{id, name, content_type, size, sha256, ref, direction?}` (§9 of
agent-architecture); bytes never travel in frames.

**agent → host**

| type | envelope ids | data | meaning |
|---|---|---|---|
| `thread_result` | `taskId`, `threadId` | `{status, result?, error?, failure_reason?, engine_session_id?, duration_ms, final_seq, attachments?, encryption_error?}` | terminal outcome of one execution (mirror → `thread_runs`) |
| `thread_message` | `taskId`, `threadId` | `{seq, kind, role?, content?, tool?, input?, output?, tool_use_id?, parent_tool_use_id?}` | one ordered transcript event (mirror → `messages`) |
| `cron_state` | `taskId`, `cronId` | `{kind, schedule_type?, schedule_value?, continuity?, next_run?, status?, round_count, skipped_count, last_status?}` | local scheduling-ledger summary (mirror → `crons`) |
| `heartbeat` | — | `{activeThreads?, capabilities?, engines?, e2ee?, …}` | liveness (interval from `config.heartbeatIntervalMs`); `capabilities` and `e2ee` are the same values as on register (§3); `engines` lists the engine binaries the agent starts, `{name, version?, path}` each, probed in the background at startup (heartbeats before the probe finishes omit it) |
| `fs_response` | `reqId` | `{ok, entries? \| stat? \| sha256 + size, error?}` | answers the `fs_request` with the same `reqId`; live-only |
| `e2ee_key_packages` | — | `{one_time?, last_resort?}` | publish KeyPackages to the host's key directory (§5.3) |
| `e2ee_request` | `taskId`, `reqId` | `{op, …}` | one Delivery Service operation on the task's group (§5.3); live-only |
| `msg_ack` | (top-level `msgId`) | — | durably stored an inbound host frame |

**host → agent**

| type | envelope ids | data | meaning |
|---|---|---|---|
| `task_upsert` | `taskId` | `{name?, kind?, status?, engine?, model?, workdir?, meta?, entries?, e2ee?}` | seed/modify a task (the global top entity); `engine`/`model`/`workdir`/`meta` are the task definition, `entries` the task-scope provisioning set (M8), `e2ee` marks an encrypted task (§5.3) |
| `task_delete` | `taskId` | — | remove a task |
| `cron_upsert` | `taskId`, `cronId` | `{kind, prompt, schedule_type?, schedule_value?, continuity, next_run?, status?}` | seed/modify a trigger under a task; `prompt` (required) is the recurring instruction the cron runs each fire |
| `cron_delete` | `taskId`, `cronId` | — | remove a trigger |
| `message` | `taskId`, `threadId?` | `{text, attachments?}` | user/system input for a task (optionally a live thread) |
| `interrupt` | `taskId?` | — | graceful cancel of the current turn (engine stays alive); with `taskId`, scoped: the agent interrupts only if that task owns the in-flight turn. Delivery is LIVE-ONLY (at-most-once): the host sends it to an online agent and never replays it on reconnect — a stale cancel must not fire against a future turn |
| `close` | — | `{reason?}` (`stop\|restart\|remove`) | runner-level wind-down and exit (agent removal / launcher stop), **not** per-task close — per-task close = `task_upsert{status:"closed"}` + scoped `interrupt` |
| `config_update` | — | `{entries, version, <config fields>}` | live config change (the §3 global overlay; `data` is required — `entries` + `version` drive the version-gated reconcile) |
| `fs_request` | `reqId` | `{op, path, to?, recursive?, ref? + sha256? + size?, upload?}` | one engine-free file operation; live-only (never queued, never replayed) |
| `e2ee_key_package_status` | (top-level `id?`) | `{one_time, last_resort, rejected?}` | the runner's KeyPackage pool at the host (§5.3); live-only |
| `e2ee_log` | `taskId` | `{seq, kind, epoch, message, drop_public_key?}` | one handshake log entry of the task's group (§5.3) |
| `e2ee_welcome` | `taskId` | `{welcome, seq}` | a Welcome adding the runner to the task's group (§5.3) |
| `e2ee_response` | `taskId`, `reqId` | `{ok, error?, entries?, more?, epoch?, seq?, link?}` | answers the `e2ee_request` with the same `reqId` (§5.3); live-only |
| `ack` | (top-level `id`) | — | acked an agent outbound frame |

Every durable frame additionally carries its top-level delivery id (`outboxId` agent →
host, `msgId` host → agent; §4.2); the "envelope ids" columns above list the correlation
ids only.

Field semantics:
- `kind` (`thread_message`) is an open string; the recognized set is
  `{user_input, assistant_text, thinking, tool_use, tool_result, status, error, host_action}` —
  a receiver stores an unrecognized `kind` opaquely instead of rejecting the
  frame (additive-compatibility, §1). `thinking`/`status` are config-filterable.
- `host_action` (`thread_message.kind`) is an action the engine asked the host to take,
  recorded by the agent on the caller's own thread (agent-architecture §10b `thread.action`);
  `input` is `{method, params}`, both defined by the host and opaque to the agent. The agent
  awaits no reply; the host applies each event once, keyed by `(threadId, seq)`, and records
  the outcome on its side. A host that does not know the kind stores it opaquely.
- `status` (`thread_result`) is a terminal thread state ∈ `{succeeded, failed, cancelled}`.
- `failure_reason` follows the taxonomy in agent-architecture §6 (`runner.*` / `agent.*`);
  NULL on success. `agent.encryption` (non-retryable) is an end-to-end encryption failure
  and comes with `encryption_error` (§5.3). A resume-unsafe failure (e.g. `agent.invalid_request`) omits
  `engine_session_id` so the next turn starts fresh.
- `seq` (`thread_message`) is per-thread monotonic (assigned serially by the runner);
  `final_seq` (`thread_result`) is the last `seq` emitted on the thread (see §6).
- `tool_use_id` (`thread_message`) is the engine's id for a `tool_use` block, echoed on
  the matching `tool_result`, so a receiver can pair a call with its return value.
- `parent_tool_use_id` (`thread_message`) attributes the event to the parent tool call
  that produced it: it is PRESENT on every event produced INSIDE a sub-agent (a `Task`
  tool call) and ABSENT for the main agent's own events — absence therefore means "the
  main agent". It introduces no hierarchy in the task/thread model: `seq` stays a single
  per-thread monotonic stream across all kinds, and attribution is a per-message property
  only.
- `output` on a `tool_result` (`thread_message`) carries `{content, is_error}` —
  `content` is the engine's `tool_result` block content verbatim (any JSON value) and
  `is_error` is the block's boolean flag (`false` when the engine omits it).
- `round_count` / `skipped_count` (`cron_state`) are the runner-local `cron_logs` summary;
  the host derives dispatched counts from its own mirror by `cron_id`.
- `threadId` (`message`, host→agent) selects continuity. The HOST mints conversation
  thread ids (globally unique ULIDs, §6) and records each one as the task's
  `current_thread_id` BEFORE emitting the frame; every `message` a conforming host sends
  carries a `threadId`. On the agent: **present + known** → CONTINUE that thread (resume
  its stored `engine_session_id`); **present + unknown** → CREATE ON FIRST SIGHT — the
  agent creates a fresh thread under the host-supplied id with no carried session. Every
  conversation starts via create-on-first-sight (the first message of a task, an explicit
  new-thread request, and the fresh thread after an orphaned task is re-placed). An
  **absent** `threadId` is tolerated defensively (the field stays optional on the wire):
  the agent derives a deterministic thread id — stable across at-least-once replays — and
  returns it on the resulting `thread_result`/`thread_message` frames; there is no
  implicit per-task continue on an absent `threadId`. Cron-fired thread ids are the one
  agent-minted family the host sees (`<cronId>@<epoch>` / `<cronId>@shared`, §7): they
  arrive only on agent→host frames and are never a task's `current_thread_id`.
- `meta.memory` (`task_upsert`) is an optional, additive field (protocol version
  unchanged): `{task?: "on"|"off", agent?: "rw"|"ro"|"off"}`; unknown keys are rejected and
  `meta` itself stays an open record. The host validates the shape on task creation (admin
  `POST /admin/tasks`, SDK `host.tasks.create`; invalid → 400 `INVALID_TASK_MEMORY`) and
  forwards `meta` unchanged. The agent applies it per task: `task` switches that task's
  task-scoped memory on/off, `agent` limits that task's access to the agent-scoped memory
  (layout: [`docs/agent-architecture.md`](agent-architecture.md)). Values can only tighten
  the agent-local settings `GINO_TASK_MEMORY` (default `on`) and `GINO_AGENT_MEMORY_ACCESS`
  (default `rw`); a loosening value is ignored with a warning, and an absent key means the
  agent-local setting applies.

The agent is **authoritative for scheduling and execution**; `thread_result` / `cron_state`
are mirror-only writes on the host (read model). The host is a sink for results and a
source for config + work — never on the execution critical path.

### 5.1 Engine-free file operations (`fs_request` / `fs_response`)

The host can operate on an agent's files directly, without prompting an engine.

- `op` ∈ `list`, `stat`, `mkdir`, `remove`, `rename`, and the two transfers `put`, `get`.
- **Paths are not confined to a root.** A relative `path` (and `to`) resolves against the
  agent's workspace directory; an absolute one is used as given. The agent's container and
  uid are the only boundary.
- **File bytes never ride in a frame** — they move over the attachment byte channel (§2),
  whole file at a time:
  - `put {path, ref, sha256, size}` — the host has staged the bytes; the agent downloads
    `ref` (a `/agent/attachments/<id>` path) into a temporary file beside `path`, verifies
    the sha256, and renames it into place, so the destination is replaced atomically or not
    at all. The parent directory must exist. An existing destination keeps its permission
    bits, and a symlink is written through to its target.
  - `get {path, upload}` — the agent uploads the file with `POST /agent/attachments` under
    the name `upload` and answers `{ok, sha256, size}`; the host reads the bytes back by
    that name and digest. `path` must be a regular file.
  - The staged bytes are single-use: `ref` is served only to the agent it was minted for
    and only while the request is pending, and the host deletes them when the transfer
    settles. Only the host mints `ref` and `upload`; a caller cannot supply them.
  - A file larger than the agent's single-attachment limit is refused with `too_large`
    before any bytes move; the host additionally caps what it accepts for a `put`.
- `recursive` lets `mkdir` create parents and `remove` delete a non-empty directory.
  `remove` on a symlink removes the link, never its target.
- `list` returns `entries: [{name, type, size, mtime_ms?}]` sorted by name; `stat` returns
  `stat: {type, size, mtime_ms?}`. `type` ∈ `file`, `dir`, `symlink`, `other`.
- A failure is `{ok: false, error: {code, message}}` with `code` ∈ `disabled`, `not_found`,
  `exists`, `too_large`, `invalid`, `denied`, `io`.
- **Enablement is host-driven.** The agent answers `disabled` until its host-assigned
  config carries `remoteOps.fs = true` (§3). There is no agent-side switch.
- **Encrypted tasks.** While the agent is a member of any encrypted task's group (§5.3) it
  answers every request with `{ok: false, error: {code: "denied"}}`, whatever `remoteOps`
  says, unless a runner-local setting opts in. The host has no override.
- **Live-only.** The request carries no `msgId`/`outboxId`; neither side persists either
  frame. The host refuses a request for an offline agent at once, and fails every pending
  request when the agent's socket drops. A response that arrives for an unknown `reqId` is
  ignored. A peer that does not implement the frames ignores them (§4.2), so the host times
  the request out.

### 5.2 Interactive terminals (live-only)

Terminals share the agent socket with file and work frames. Every terminal frame carries a
host-minted `ptyId` at the envelope top level and has no delivery ID or acknowledgment.

| Direction | Type | Data |
|---|---|---|
| host → agent | `pty_open` | `{argv?, cwd?, env?, cols?, rows?}` |
| host → agent | `pty_input` | `{data}` (base64 bytes) |
| host → agent | `pty_resize` | `{cols, rows}` |
| host → agent | `pty_close` | none |
| agent → host | `pty_ready` | `{}` |
| agent → host | `pty_output` | `{data}` (base64 bytes) |
| agent → host | `pty_exit` | `{exit_code?, signal?, error?: {code, message}}` |

- `remoteOps.pty` defaults to false. Host configuration enables it independently of `fs`;
  disabling it ends existing terminals, including across a rapid disable/re-enable.
- While the agent is a member of any encrypted task's group (§5.3) it answers `pty_open` with
  `pty_exit {error: {code: "denied"}}`, whatever `remoteOps` says, unless a runner-local setting
  opts in. The host has no override.
- Default argv is `[/bin/sh]`; default size is 80 columns by 24 rows. Dimensions must be
  integers in 1–1000. Relative cwd resolves against the current workspace; absolute cwd is
  honored. Existing sessions keep their original cwd. The terminal inherits only normal
  user/path/locale variables, plus `TERM=xterm-256color` and explicitly supplied `env`.
- Open options are capped at 64 KiB, with at most 64 argv items and environment entries.
  Input/output chunks contain at most 16 KiB of decoded bytes. Each agent permits eight
  sessions; input queues hold 64 chunks, the connection output queue holds 64 frames, and
  the host's unread output buffer is capped at 256 KiB per terminal. Slow consumers close.
  There is no flow control: input that overflows the queue ends the terminal with
  `input_overflow`, and a malformed input or resize frame ends it with `invalid`.
- `pty_ready` confirms successful spawn before output or input. The host defaults to a
  30-second open timeout, including when an older agent ignores the new frame types.
- Input and resize commands are processed in arrival order. Natural completion drains final
  output before `pty_exit`; a descendant that still holds the terminal does not delay it.
  Close terminates the shell and its foreground/process group and reaps the direct child.
  Independently detached processes are outside terminal ownership.
- A terminal belongs to one connection: agent disconnect, replacement, host shutdown, client
  cancellation or disabling the group ends it. Reconnect never restores it or replays bytes.
  Unknown terminal IDs and another agent's responses are ignored. Protocol version stays 2.

The Host SDK exposes `host.agents.openPty(agentId, options?, signal?)`. It resolves after
`pty_ready` to `{id, write(Uint8Array), resize(cols, rows), close(), output, exited}`. `output`
is a byte `ReadableStream`; `exited` resolves to the exit payload. The optional AbortSignal
also cancels a pending open. Canceling the output stream closes the terminal.

The optional Hono admin bridge (enabled by injecting `upgradeWebSocket`) uses:

1. `POST /admin/agents/:id/pty-ticket`, with normal admin authorization, returns
   `{success: true, data: {ticket, expiresAt}}`. Tickets expire in 30 seconds, are single-use,
   are scoped to the agent, and cannot authorize any other admin route.
2. `GET /admin/agents/:id/pty?ticket=...` upgrades the browser connection. Non-browser clients
   may use the normal admin authorization instead. A supplied Origin must match the Origin
   from the authenticated ticket request (or the request URL origin when absent). This works
   through TLS termination without trusting forwarded headers. Direct admin upgrades require
   the request URL origin. The standalone app limits tickets and upgrades to 30 requests per
   minute per IP.
3. Within five seconds, send `{type: "open", data: {...options}}`. Wait for
   `{type: "ready", data: {ptyId}}`, then send `input` / `resize` / `close` using the same
   data shapes above. The server emits `output` and `exit`. One socket owns one terminal;
   messages do not take a client-selected ptyId. The browser's pending send buffer is bounded.

Standalone paths are prefixed with `/api` (and the configured base path, when present).
Ticket responses are not cacheable; request logs omit query strings.

### 5.3 End-to-end encryption

Task content can be end-to-end encrypted between the client devices and the runner, with the
host as an untrusted relay and MLS Delivery Service (DS). The cryptography, the DS contract and
the failure codes are the [e2ee framework spec](e2ee/spec.md); how it applies to tasks (which
fields are sealed, AAD templates, runner and host rules) is the
[task-content profile](e2ee/task-content.md) with its field map
[`task-content.fieldmap.json`](e2ee/task-content.fieldmap.json). This section defines only the
frames and fields that carry it. Every field below is optional and additive (protocol version
unchanged). Binary values are base64url without padding (spec §5.1) unless stated otherwise;
`seq` and `epoch` are JSON integers.

**Encrypted task.** `task_upsert.data.e2ee = {profile_id, group_id}` marks the task as
encrypted: `profile_id` is `gino.task-content.v1` and `group_id` the 32-byte MLS group id
(spec §2.3, scope id = `taskId`), which the runner checks against its own derivation. The
history policy lives in the MLS group context, not here. Absent means unchanged; once a task is
encrypted it stays encrypted.
Everything else on `task_upsert` stays cleartext.

**Sealed fields.** A mapped field of an encrypted task carries the sealed form
`{"e2ee": "<base64url envelope>"}` (exactly one member, spec §12.4) in place of its plaintext
value. The mapped fields are those of the field map:

| frame | path |
|---|---|
| `message` | `data.text`, `data.attachments[].name` |
| `cron_upsert` | `data.prompt` |
| `thread_message` | `data.content`; `data.input` (when `kind ≠ host_action`); `data.input.params` (when `kind = host_action`, split by `data.input.method`, see below); `data.output.content` |
| `thread_result` | `data.result`, `data.error`, `data.attachments[].name` |

Host actions (`thread_message` with `kind = host_action`): `data.input.method` stays cleartext,
and `data.input.params` follows the `keyed_plain` rule of [spec §12.5](e2ee/spec.md) keyed on
`data.input.method`. For a method the profile's table lists, the params listed there stay
plaintext and every other param position is sealed individually as `{"e2ee": …}`, so `params`
is an object mixing plain and sealed members (for example `{"issue_id": "I-1", "body":
{"e2ee": "…"}}`). A method not in the table is sealed whole. The gino task-content table
([task-content §2.1](e2ee/task-content.md)) is empty, so every host action of an encrypted task
has its `params` sealed whole and the host only stores and relays it.

Attachment bytes of an encrypted task are a file envelope uploaded under an opaque name; the
descriptor's other fields describe the envelope (profile §2). The frame schema accepts either
form on every mapped field; the rule that mapped fields are sealed exactly when the task is
encrypted is enforced by the endpoints: a plaintext mapped value on an encrypted task is refused
with `plaintext_rejected` (the host neither stores nor forwards the frame), and on a task that is
not encrypted the sealed form is never interpreted. Cleartext fields an AAD template references
(`taskId`, `threadId`, `seq`, `outboxId`, attachment `sha256`) are stored and returned unchanged
with the sealed value; `outboxId` is therefore required on an encrypted task's `thread_result`.
Sealing happens before the outbox enqueue, so only ciphertext is persisted, replayed (§4.2) or
posted to `POST /agent/output/:agentId`.

**Failures.** A runner that cannot open a turn's input or seal its output ends the thread with
`thread_result {status: "failed", failure_reason: "agent.encryption", encryption_error}` and no
`result`, `error` or attachments. `encryption_error = {code, epoch?, message?}`: `code` is a
spec §11 code (`not_member`, `epoch_unknown`, `history_unavailable`, `link_invalid`,
`open_failed`, `aad_mismatch`, `plaintext_rejected`, `unsupported_version`, `unsupported_suite`,
`malformed`, `drop_key_mismatch`, `seal_failed`) kept an open string so a later code never makes
a durable frame unparseable; `epoch` is the epoch involved where §11 defines one; `message` is a
short diagnostic. None of them ever contains plaintext, AAD values or key material. The host
stores and shows `encryption_error` as received. `agent.encryption` is non-retryable; there is
never a plaintext fallback.

**Downgrade refusal.** Dispatching or assigning an encrypted task to a runner that is not
e2ee-capable (§3) or has no leaf in the task's group fails with HTTP **409
`runner_without_encryption`**. The task is never downgraded to plaintext.

**KeyPackages.** The runner publishes KeyPackages (spec §2.7) with the durable
`e2ee_key_packages {one_time?: [kp], last_resort?: kp}` (acked by `ack`). The host verifies
each against spec §3.5 under the pinned identity key; a new `last_resort` replaces the previous
one. The host answers with the live-only `e2ee_key_package_status {one_time, last_resort,
rejected?}`: `one_time` is the number of unclaimed one-time KeyPackages, `last_resort` whether a
current last-resort KeyPackage is held, and `rejected: [{code, index?}]` the refused KeyPackages
of the answered upload (`index` into its `one_time`, absent for its `last_resort`; `code` ∈
`malformed`, `unsupported_suite`, `key_changed` for a key awaiting an operator re-pin). The
answering status carries the upload's `outboxId` as top-level `id`. The host also sends a status
(without `id` and `rejected`) when the socket opens and after each claim, so the runner tops its
pool up (profile §4.1: at least 10 one-time, top up below 5) and replaces its last-resort
KeyPackage before it expires.

**Delivery to the runner.** For each encrypted task placed on the runner, the host delivers the
group's DS records as durable host→agent frames (`msgId`, `msg_ack`, §4.2), minted in log order:

- `e2ee_log {seq, kind, epoch, message, drop_public_key?}`: one handshake log entry (spec §3.1).
  `kind` ∈ `commit`, `proposal`, `key_history`, `key_history_sealed`; `epoch` is the epoch the
  entry was sent in; `message` the exact bytes (an `MLSMessage`, or a key-history sealed
  envelope); `drop_public_key` (32 bytes) on `commit` entries, the drop key of epoch
  `epoch + 1`.
- `e2ee_welcome {welcome, seq}`: a Welcome whose new members include a KeyPackage the runner
  published, with the `seq` of its commit. The runner continues the log after `seq`. The host
  keeps the Welcome until the runner's `msg_ack` or until the runner leaves the group.

The host sends a task's records in `seq` order, a Welcome before the entries that follow its
commit. At-least-once delivery may repeat a record; the runner dedups on `msgId` and on
`(taskId, seq)`, processes entries strictly in `seq` order and never skips a `commit`. On a gap
(an entry whose `seq` is not the next one), after a reconnect, or after losing its database, the
runner catches up with `e2ee_request` reads before opening content of a newer epoch. These
records are independent of the per-thread ordering of §6: the group log is ordered per task by
its own `seq`. Epoch links are not pushed; the runner reads them on demand.

**Delivery Service operations.** The runner sends the live-only `e2ee_request {op, …}` with
`taskId` and a runner-minted `reqId`; the host answers with the live-only `e2ee_response
{ok, error?, entries?, more?, epoch?, seq?, link?}` with the same `taskId` and `reqId`. Neither
is persisted, acked or replayed; an unanswered request (socket drop, a host that does not know
the frames) times out on the runner and is retried after reconnecting. `epoch` in a response is
the group's current epoch.

| `op` | request fields | success response |
|---|---|---|
| `log` | `after_seq` | `entries` with `seq > after_seq`, in order; `more: true` if truncated (read again after the last `seq`) |
| `log_from_epoch` | `epoch` | `entries` from the first entry whose `epoch` is at least `epoch`; `more` as above |
| `link` | `epoch` | `link`: the stored epoch-link record for `epoch` (spec §5.6), absent if none |
| `put_link` | `epoch`, `link` | `{ok: true}`: a missing epoch link written (repair, spec §7.4) |
| `commit` | `commit`, `drop_public_key`, `epoch_link?`, `key_history?: [{kind, message}]` | `seq` of the accepted commit; `epoch` is the new epoch |

- `commit` submits the runner's own Update commit (a PublicMessage) as one unit (spec §3.2):
  the drop public key of the new epoch, its epoch link when the history policy calls for one,
  and optional key-history entries (`kind` ∈ `key_history`, `key_history_sealed`). Runners never
  commit membership changes, so there is no Welcome. The first valid commit per epoch wins; a
  later one is answered `{ok: false, error: {code: "epoch_conflict"}, epoch}`, after which the
  runner discards its pending commit and catches up. If the response is lost, the runner reads
  the log: its commit is accepted iff the entry at that epoch carries its exact bytes.
- `put_link` for an epoch that already has a link is answered `{ok: false, error: {code:
  "link_exists"}, link}` with the stored record.
- `error.code` is a DS rejection code (spec §3.8): `epoch_conflict`, `link_exists`,
  `plaintext_rejected`, `malformed`, `not_member`, `scope_exists`, or `unsupported_suite`;
  `error.message` is optional. Reads are served only to current members of the group
  (`not_member` otherwise).

## 6. Multiplexing & ordering (one WS, N parallel threads)

Many threads share one connection, so their frames interleave. The receiver MUST NOT assume
arrival order or `outboxId` order across threads:

- **Demux by `threadId`.** Each thread is an independent stream.
- **Order each thread by `seq`.** `thread_message.seq` is per-thread monotonic; the
  transcript for a thread is `ORDER BY seq`, not by arrival or `outboxId`.
- **Idempotent write on `(threadId, seq)`.** At-least-once replay can duplicate a frame;
  the host de-dupes on `(threadId, seq)` (and `(taskId, threadId, seq)` as the composite
  key — `threadId` is globally unique, so it determines `taskId`).
- **Completeness via `final_seq`.** `thread_result.final_seq` is the last `seq` the thread
  emitted, letting the host verify it received `1..=final_seq`.
- `outboxId` is delivery/ack only; `seq` is the per-thread continuity contract.

Parse model: a whole job is `WHERE task_id = ?`; one conversation is
`WHERE task_id = ? AND thread_id = ? ORDER BY seq`; threads within a task are ordered by
`thread.created_at` (seq is per-thread, not per-task).

## 7. What is NOT in the protocol

- How the agent runs an engine (Claude `-p` control protocol, etc.) — agent-private.
- How/where a runner is started and out-of-band managed — host-private (launchers).
- Scheduling internals — the runner's `cron_logs` ledger, deterministic `thread_id`,
  dedup, retry, and watchdog are runner-local; only the `cron_state` summary is shared.
- The `task_id ↔ delivery channel` mapping — host-private routing.
- Storage schemas on either side — private; only the envelopes above are shared.
- Running a command or opening a terminal on the agent without an engine — not part of
  the protocol yet; only the file operations of §5.1 are.
- Attachment **bytes** — only descriptors ride frames; bytes move on the separate channel
  (§2 / agent-architecture §9).

## 8. Frame JSON Schema (generated)

The machine-checkable JSON Schema for the frame catalog (§5). It is normative: a host
implementation checks that its own frame catalog exports this schema. `AnyFrame` is
the union of the agent→host (`AgentFrame`) and host→agent (`HostFrame`) catalogs; both are
also exposed under `$defs`. Frames and their `data` objects are **open** — additive fields
validate (protocol §1/§4.2) — while an unknown `type` matches no member and is rejected.

```json
{
  "title": "Gino host ⇄ agent protocol — frame catalog",
  "description": "`AnyFrame` = a valid frame in either direction. Frames and `data` objects are open (additive-compatible): unknown fields are accepted, unknown `type`s are rejected. See protocol.md §4–§6.",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "anyOf": [
    {
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "thread_result"
            },
            "taskId": {
              "type": "string"
            },
            "threadId": {
              "type": "string"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "status": {
                  "type": "string",
                  "enum": [
                    "succeeded",
                    "failed",
                    "cancelled"
                  ]
                },
                "result": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "error": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "failure_reason": {
                  "type": "string"
                },
                "engine_session_id": {
                  "type": "string"
                },
                "duration_ms": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "final_seq": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "attachments": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "id": {
                        "type": "string"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "object",
                            "properties": {
                              "e2ee": {
                                "type": "string",
                                "minLength": 1,
                                "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                              }
                            },
                            "required": [
                              "e2ee"
                            ],
                            "additionalProperties": false
                          }
                        ]
                      },
                      "content_type": {
                        "type": "string"
                      },
                      "size": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "sha256": {
                        "type": "string"
                      },
                      "ref": {
                        "type": "string"
                      },
                      "direction": {
                        "type": "string",
                        "enum": [
                          "inbound",
                          "outbound"
                        ]
                      }
                    },
                    "required": [
                      "id",
                      "name",
                      "content_type",
                      "size",
                      "sha256",
                      "ref"
                    ],
                    "additionalProperties": {}
                  }
                },
                "encryption_error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 0,
                      "maximum": 9007199254740991
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code"
                  ],
                  "additionalProperties": {}
                }
              },
              "required": [
                "status",
                "duration_ms",
                "final_seq"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "threadId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "thread_message"
            },
            "taskId": {
              "type": "string"
            },
            "threadId": {
              "type": "string"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "seq": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "kind": {
                  "type": "string"
                },
                "role": {
                  "type": "string"
                },
                "content": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "tool": {
                  "type": "string"
                },
                "input": {},
                "output": {},
                "tool_use_id": {
                  "type": "string"
                },
                "parent_tool_use_id": {
                  "type": "string"
                }
              },
              "required": [
                "seq",
                "kind"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "threadId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "cron_state"
            },
            "taskId": {
              "type": "string"
            },
            "cronId": {
              "type": "string"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "kind": {
                  "type": "string"
                },
                "schedule_type": {
                  "type": "string"
                },
                "schedule_value": {
                  "type": "string"
                },
                "continuity": {
                  "type": "string"
                },
                "next_run": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                },
                "round_count": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "skipped_count": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "last_status": {
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "round_count",
                "skipped_count"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "cronId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "heartbeat"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "activeThreads": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "capabilities": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                "engines": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "name": {
                        "type": "string"
                      },
                      "version": {
                        "type": "string"
                      },
                      "path": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "name",
                      "path"
                    ],
                    "additionalProperties": {}
                  }
                },
                "e2ee": {
                  "type": "object",
                  "properties": {
                    "versions": {
                      "type": "array",
                      "items": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      }
                    },
                    "mls_suites": {
                      "type": "array",
                      "items": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      }
                    },
                    "credential": {
                      "type": "object",
                      "properties": {
                        "type": {
                          "type": "string"
                        },
                        "public_key": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "type",
                        "public_key"
                      ],
                      "additionalProperties": {}
                    }
                  },
                  "required": [
                    "versions",
                    "mls_suites",
                    "credential"
                  ],
                  "additionalProperties": {}
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "fs_response"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "ok": {
                  "type": "boolean"
                },
                "entries": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "type": {
                        "type": "string"
                      },
                      "size": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "mtime_ms": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "name": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "type",
                      "size",
                      "name"
                    ],
                    "additionalProperties": {}
                  }
                },
                "stat": {
                  "type": "object",
                  "properties": {
                    "type": {
                      "type": "string"
                    },
                    "size": {
                      "type": "integer",
                      "minimum": -9007199254740991,
                      "maximum": 9007199254740991
                    },
                    "mtime_ms": {
                      "type": "integer",
                      "minimum": -9007199254740991,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "type",
                    "size"
                  ],
                  "additionalProperties": {}
                },
                "sha256": {
                  "type": "string"
                },
                "size": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code",
                    "message"
                  ],
                  "additionalProperties": {}
                }
              },
              "required": [
                "ok"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_ready"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {},
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_output"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "data": {
                  "type": "string",
                  "maxLength": 21848,
                  "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
                }
              },
              "required": [
                "data"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_exit"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "exit_code": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "signal": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code",
                    "message"
                  ],
                  "additionalProperties": {}
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_key_packages"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "one_time": {
                  "type": "array",
                  "items": {
                    "type": "string",
                    "minLength": 1,
                    "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                  }
                },
                "last_resort": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_request"
            },
            "taskId": {
              "type": "string"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "oneOf": [
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "log"
                    },
                    "after_seq": {
                      "type": "integer",
                      "minimum": 0,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "op",
                    "after_seq"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "log_from_epoch"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 0,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "op",
                    "epoch"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "link"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 1,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "op",
                    "epoch"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "put_link"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 1,
                      "maximum": 9007199254740991
                    },
                    "link": {
                      "type": "string",
                      "minLength": 1,
                      "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                    }
                  },
                  "required": [
                    "op",
                    "epoch",
                    "link"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "commit"
                    },
                    "commit": {
                      "type": "string",
                      "minLength": 1,
                      "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                    },
                    "drop_public_key": {
                      "type": "string",
                      "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                    },
                    "epoch_link": {
                      "type": "string",
                      "minLength": 1,
                      "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                    },
                    "key_history": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "kind": {
                            "type": "string",
                            "enum": [
                              "key_history",
                              "key_history_sealed"
                            ]
                          },
                          "message": {
                            "type": "string",
                            "minLength": 1,
                            "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                          }
                        },
                        "required": [
                          "kind",
                          "message"
                        ],
                        "additionalProperties": {}
                      }
                    }
                  },
                  "required": [
                    "op",
                    "commit",
                    "drop_public_key"
                  ],
                  "additionalProperties": {}
                }
              ]
            }
          },
          "required": [
            "type",
            "taskId",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "msg_ack"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "msgId"
          ],
          "additionalProperties": {}
        }
      ]
    },
    {
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "task_upsert"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "name": {
                  "type": "string"
                },
                "kind": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                },
                "engine": {
                  "type": "string"
                },
                "model": {
                  "type": "string"
                },
                "workdir": {
                  "type": "string"
                },
                "meta": {
                  "type": "object",
                  "properties": {},
                  "additionalProperties": {}
                },
                "entries": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "name": {
                        "type": "string"
                      },
                      "sha256": {
                        "type": "string"
                      },
                      "target": {
                        "type": "string"
                      },
                      "kind": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "name",
                      "sha256",
                      "target",
                      "kind"
                    ],
                    "additionalProperties": {}
                  }
                },
                "e2ee": {
                  "type": "object",
                  "properties": {
                    "profile_id": {
                      "type": "string"
                    },
                    "group_id": {
                      "type": "string",
                      "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                    }
                  },
                  "required": [
                    "profile_id",
                    "group_id"
                  ],
                  "additionalProperties": {}
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "task_delete"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "taskId"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "cron_upsert"
            },
            "taskId": {
              "type": "string"
            },
            "cronId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "kind": {
                  "type": "string"
                },
                "prompt": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "schedule_type": {
                  "type": "string"
                },
                "schedule_value": {
                  "type": "string"
                },
                "continuity": {
                  "type": "string"
                },
                "next_run": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "prompt",
                "continuity"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "cronId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "cron_delete"
            },
            "taskId": {
              "type": "string"
            },
            "cronId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "taskId",
            "cronId"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "message"
            },
            "taskId": {
              "type": "string"
            },
            "threadId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "text": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "attachments": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "id": {
                        "type": "string"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "object",
                            "properties": {
                              "e2ee": {
                                "type": "string",
                                "minLength": 1,
                                "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                              }
                            },
                            "required": [
                              "e2ee"
                            ],
                            "additionalProperties": false
                          }
                        ]
                      },
                      "content_type": {
                        "type": "string"
                      },
                      "size": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "sha256": {
                        "type": "string"
                      },
                      "ref": {
                        "type": "string"
                      },
                      "direction": {
                        "type": "string",
                        "enum": [
                          "inbound",
                          "outbound"
                        ]
                      }
                    },
                    "required": [
                      "id",
                      "name",
                      "content_type",
                      "size",
                      "sha256",
                      "ref"
                    ],
                    "additionalProperties": {}
                  }
                }
              },
              "required": [
                "text"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "interrupt"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "close"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "config_update"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {},
              "additionalProperties": {}
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "fs_request"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "op": {
                  "type": "string",
                  "enum": [
                    "list",
                    "stat",
                    "mkdir",
                    "remove",
                    "rename",
                    "put",
                    "get"
                  ]
                },
                "path": {
                  "type": "string",
                  "minLength": 1
                },
                "to": {
                  "type": "string",
                  "minLength": 1
                },
                "recursive": {
                  "type": "boolean"
                },
                "ref": {
                  "type": "string"
                },
                "sha256": {
                  "type": "string"
                },
                "size": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "upload": {
                  "type": "string"
                }
              },
              "required": [
                "op",
                "path"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_open"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "argv": {
                  "minItems": 1,
                  "maxItems": 64,
                  "type": "array",
                  "items": {
                    "type": "string",
                    "maxLength": 4096
                  }
                },
                "cwd": {
                  "type": "string",
                  "maxLength": 4096
                },
                "env": {
                  "type": "object",
                  "propertyNames": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[^=\\0]+$"
                  },
                  "additionalProperties": {
                    "type": "string",
                    "maxLength": 4096
                  }
                },
                "cols": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                },
                "rows": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_input"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "data": {
                  "type": "string",
                  "maxLength": 21848,
                  "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
                }
              },
              "required": [
                "data"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_resize"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "cols": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                },
                "rows": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                }
              },
              "required": [
                "cols",
                "rows"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_close"
            },
            "ptyId": {
              "type": "string"
            }
          },
          "required": [
            "type",
            "ptyId"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_key_package_status"
            },
            "id": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "one_time": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "last_resort": {
                  "type": "boolean"
                },
                "rejected": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "code": {
                        "type": "string"
                      },
                      "index": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9007199254740991
                      }
                    },
                    "required": [
                      "code"
                    ],
                    "additionalProperties": {}
                  }
                }
              },
              "required": [
                "one_time",
                "last_resort"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_log"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "seq": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 9007199254740991
                },
                "kind": {
                  "type": "string",
                  "enum": [
                    "commit",
                    "proposal",
                    "key_history",
                    "key_history_sealed"
                  ]
                },
                "epoch": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "message": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                },
                "drop_public_key": {
                  "type": "string",
                  "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                }
              },
              "required": [
                "seq",
                "kind",
                "epoch",
                "message"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_welcome"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "welcome": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                },
                "seq": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 9007199254740991
                }
              },
              "required": [
                "welcome",
                "seq"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_response"
            },
            "taskId": {
              "type": "string"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "ok": {
                  "type": "boolean"
                },
                "error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code"
                  ],
                  "additionalProperties": {}
                },
                "entries": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "seq": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 9007199254740991
                      },
                      "kind": {
                        "type": "string",
                        "enum": [
                          "commit",
                          "proposal",
                          "key_history",
                          "key_history_sealed"
                        ]
                      },
                      "epoch": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9007199254740991
                      },
                      "message": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                      },
                      "drop_public_key": {
                        "type": "string",
                        "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                      }
                    },
                    "required": [
                      "seq",
                      "kind",
                      "epoch",
                      "message"
                    ],
                    "additionalProperties": {}
                  }
                },
                "more": {
                  "type": "boolean"
                },
                "epoch": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "seq": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 9007199254740991
                },
                "link": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                }
              },
              "required": [
                "ok"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "ack"
            },
            "id": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "id"
          ],
          "additionalProperties": {}
        }
      ]
    }
  ],
  "$defs": {
    "AgentFrame": {
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "thread_result"
            },
            "taskId": {
              "type": "string"
            },
            "threadId": {
              "type": "string"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "status": {
                  "type": "string",
                  "enum": [
                    "succeeded",
                    "failed",
                    "cancelled"
                  ]
                },
                "result": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "error": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "failure_reason": {
                  "type": "string"
                },
                "engine_session_id": {
                  "type": "string"
                },
                "duration_ms": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "final_seq": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "attachments": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "id": {
                        "type": "string"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "object",
                            "properties": {
                              "e2ee": {
                                "type": "string",
                                "minLength": 1,
                                "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                              }
                            },
                            "required": [
                              "e2ee"
                            ],
                            "additionalProperties": false
                          }
                        ]
                      },
                      "content_type": {
                        "type": "string"
                      },
                      "size": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "sha256": {
                        "type": "string"
                      },
                      "ref": {
                        "type": "string"
                      },
                      "direction": {
                        "type": "string",
                        "enum": [
                          "inbound",
                          "outbound"
                        ]
                      }
                    },
                    "required": [
                      "id",
                      "name",
                      "content_type",
                      "size",
                      "sha256",
                      "ref"
                    ],
                    "additionalProperties": {}
                  }
                },
                "encryption_error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 0,
                      "maximum": 9007199254740991
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code"
                  ],
                  "additionalProperties": {}
                }
              },
              "required": [
                "status",
                "duration_ms",
                "final_seq"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "threadId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "thread_message"
            },
            "taskId": {
              "type": "string"
            },
            "threadId": {
              "type": "string"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "seq": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "kind": {
                  "type": "string"
                },
                "role": {
                  "type": "string"
                },
                "content": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "tool": {
                  "type": "string"
                },
                "input": {},
                "output": {},
                "tool_use_id": {
                  "type": "string"
                },
                "parent_tool_use_id": {
                  "type": "string"
                }
              },
              "required": [
                "seq",
                "kind"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "threadId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "cron_state"
            },
            "taskId": {
              "type": "string"
            },
            "cronId": {
              "type": "string"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "kind": {
                  "type": "string"
                },
                "schedule_type": {
                  "type": "string"
                },
                "schedule_value": {
                  "type": "string"
                },
                "continuity": {
                  "type": "string"
                },
                "next_run": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                },
                "round_count": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "skipped_count": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "last_status": {
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "round_count",
                "skipped_count"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "cronId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "heartbeat"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "activeThreads": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "capabilities": {
                  "type": "array",
                  "items": {
                    "type": "string"
                  }
                },
                "engines": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "name": {
                        "type": "string"
                      },
                      "version": {
                        "type": "string"
                      },
                      "path": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "name",
                      "path"
                    ],
                    "additionalProperties": {}
                  }
                },
                "e2ee": {
                  "type": "object",
                  "properties": {
                    "versions": {
                      "type": "array",
                      "items": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      }
                    },
                    "mls_suites": {
                      "type": "array",
                      "items": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      }
                    },
                    "credential": {
                      "type": "object",
                      "properties": {
                        "type": {
                          "type": "string"
                        },
                        "public_key": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "type",
                        "public_key"
                      ],
                      "additionalProperties": {}
                    }
                  },
                  "required": [
                    "versions",
                    "mls_suites",
                    "credential"
                  ],
                  "additionalProperties": {}
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "fs_response"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "ok": {
                  "type": "boolean"
                },
                "entries": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "type": {
                        "type": "string"
                      },
                      "size": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "mtime_ms": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "name": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "type",
                      "size",
                      "name"
                    ],
                    "additionalProperties": {}
                  }
                },
                "stat": {
                  "type": "object",
                  "properties": {
                    "type": {
                      "type": "string"
                    },
                    "size": {
                      "type": "integer",
                      "minimum": -9007199254740991,
                      "maximum": 9007199254740991
                    },
                    "mtime_ms": {
                      "type": "integer",
                      "minimum": -9007199254740991,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "type",
                    "size"
                  ],
                  "additionalProperties": {}
                },
                "sha256": {
                  "type": "string"
                },
                "size": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code",
                    "message"
                  ],
                  "additionalProperties": {}
                }
              },
              "required": [
                "ok"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_ready"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {},
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_output"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "data": {
                  "type": "string",
                  "maxLength": 21848,
                  "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
                }
              },
              "required": [
                "data"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_exit"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "exit_code": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "signal": {
                  "type": "integer",
                  "minimum": -9007199254740991,
                  "maximum": 9007199254740991
                },
                "error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code",
                    "message"
                  ],
                  "additionalProperties": {}
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_key_packages"
            },
            "outboxId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "one_time": {
                  "type": "array",
                  "items": {
                    "type": "string",
                    "minLength": 1,
                    "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                  }
                },
                "last_resort": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_request"
            },
            "taskId": {
              "type": "string"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "oneOf": [
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "log"
                    },
                    "after_seq": {
                      "type": "integer",
                      "minimum": 0,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "op",
                    "after_seq"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "log_from_epoch"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 0,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "op",
                    "epoch"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "link"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 1,
                      "maximum": 9007199254740991
                    }
                  },
                  "required": [
                    "op",
                    "epoch"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "put_link"
                    },
                    "epoch": {
                      "type": "integer",
                      "minimum": 1,
                      "maximum": 9007199254740991
                    },
                    "link": {
                      "type": "string",
                      "minLength": 1,
                      "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                    }
                  },
                  "required": [
                    "op",
                    "epoch",
                    "link"
                  ],
                  "additionalProperties": {}
                },
                {
                  "type": "object",
                  "properties": {
                    "op": {
                      "type": "string",
                      "const": "commit"
                    },
                    "commit": {
                      "type": "string",
                      "minLength": 1,
                      "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                    },
                    "drop_public_key": {
                      "type": "string",
                      "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                    },
                    "epoch_link": {
                      "type": "string",
                      "minLength": 1,
                      "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                    },
                    "key_history": {
                      "type": "array",
                      "items": {
                        "type": "object",
                        "properties": {
                          "kind": {
                            "type": "string",
                            "enum": [
                              "key_history",
                              "key_history_sealed"
                            ]
                          },
                          "message": {
                            "type": "string",
                            "minLength": 1,
                            "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                          }
                        },
                        "required": [
                          "kind",
                          "message"
                        ],
                        "additionalProperties": {}
                      }
                    }
                  },
                  "required": [
                    "op",
                    "commit",
                    "drop_public_key"
                  ],
                  "additionalProperties": {}
                }
              ]
            }
          },
          "required": [
            "type",
            "taskId",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "msg_ack"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "msgId"
          ],
          "additionalProperties": {}
        }
      ]
    },
    "HostFrame": {
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "oneOf": [
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "task_upsert"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "name": {
                  "type": "string"
                },
                "kind": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                },
                "engine": {
                  "type": "string"
                },
                "model": {
                  "type": "string"
                },
                "workdir": {
                  "type": "string"
                },
                "meta": {
                  "type": "object",
                  "properties": {},
                  "additionalProperties": {}
                },
                "entries": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "name": {
                        "type": "string"
                      },
                      "sha256": {
                        "type": "string"
                      },
                      "target": {
                        "type": "string"
                      },
                      "kind": {
                        "type": "string"
                      }
                    },
                    "required": [
                      "name",
                      "sha256",
                      "target",
                      "kind"
                    ],
                    "additionalProperties": {}
                  }
                },
                "e2ee": {
                  "type": "object",
                  "properties": {
                    "profile_id": {
                      "type": "string"
                    },
                    "group_id": {
                      "type": "string",
                      "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                    }
                  },
                  "required": [
                    "profile_id",
                    "group_id"
                  ],
                  "additionalProperties": {}
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "task_delete"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "taskId"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "cron_upsert"
            },
            "taskId": {
              "type": "string"
            },
            "cronId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "kind": {
                  "type": "string"
                },
                "prompt": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "schedule_type": {
                  "type": "string"
                },
                "schedule_value": {
                  "type": "string"
                },
                "continuity": {
                  "type": "string"
                },
                "next_run": {
                  "type": "string"
                },
                "status": {
                  "type": "string"
                }
              },
              "required": [
                "kind",
                "prompt",
                "continuity"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "cronId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "cron_delete"
            },
            "taskId": {
              "type": "string"
            },
            "cronId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "taskId",
            "cronId"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "message"
            },
            "taskId": {
              "type": "string"
            },
            "threadId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "text": {
                  "anyOf": [
                    {
                      "type": "string"
                    },
                    {
                      "type": "object",
                      "properties": {
                        "e2ee": {
                          "type": "string",
                          "minLength": 1,
                          "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                        }
                      },
                      "required": [
                        "e2ee"
                      ],
                      "additionalProperties": false
                    }
                  ]
                },
                "attachments": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "id": {
                        "type": "string"
                      },
                      "name": {
                        "anyOf": [
                          {
                            "type": "string"
                          },
                          {
                            "type": "object",
                            "properties": {
                              "e2ee": {
                                "type": "string",
                                "minLength": 1,
                                "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                              }
                            },
                            "required": [
                              "e2ee"
                            ],
                            "additionalProperties": false
                          }
                        ]
                      },
                      "content_type": {
                        "type": "string"
                      },
                      "size": {
                        "type": "integer",
                        "minimum": -9007199254740991,
                        "maximum": 9007199254740991
                      },
                      "sha256": {
                        "type": "string"
                      },
                      "ref": {
                        "type": "string"
                      },
                      "direction": {
                        "type": "string",
                        "enum": [
                          "inbound",
                          "outbound"
                        ]
                      }
                    },
                    "required": [
                      "id",
                      "name",
                      "content_type",
                      "size",
                      "sha256",
                      "ref"
                    ],
                    "additionalProperties": {}
                  }
                }
              },
              "required": [
                "text"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "interrupt"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "close"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "config_update"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {},
              "additionalProperties": {}
            }
          },
          "required": [
            "type"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "fs_request"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "op": {
                  "type": "string",
                  "enum": [
                    "list",
                    "stat",
                    "mkdir",
                    "remove",
                    "rename",
                    "put",
                    "get"
                  ]
                },
                "path": {
                  "type": "string",
                  "minLength": 1
                },
                "to": {
                  "type": "string",
                  "minLength": 1
                },
                "recursive": {
                  "type": "boolean"
                },
                "ref": {
                  "type": "string"
                },
                "sha256": {
                  "type": "string"
                },
                "size": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "upload": {
                  "type": "string"
                }
              },
              "required": [
                "op",
                "path"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_open"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "argv": {
                  "minItems": 1,
                  "maxItems": 64,
                  "type": "array",
                  "items": {
                    "type": "string",
                    "maxLength": 4096
                  }
                },
                "cwd": {
                  "type": "string",
                  "maxLength": 4096
                },
                "env": {
                  "type": "object",
                  "propertyNames": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "pattern": "^[^=\\0]+$"
                  },
                  "additionalProperties": {
                    "type": "string",
                    "maxLength": 4096
                  }
                },
                "cols": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                },
                "rows": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                }
              },
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_input"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "data": {
                  "type": "string",
                  "maxLength": 21848,
                  "pattern": "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
                }
              },
              "required": [
                "data"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_resize"
            },
            "ptyId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "cols": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                },
                "rows": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 1000
                }
              },
              "required": [
                "cols",
                "rows"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "ptyId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "pty_close"
            },
            "ptyId": {
              "type": "string"
            }
          },
          "required": [
            "type",
            "ptyId"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_key_package_status"
            },
            "id": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "one_time": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "last_resort": {
                  "type": "boolean"
                },
                "rejected": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "code": {
                        "type": "string"
                      },
                      "index": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9007199254740991
                      }
                    },
                    "required": [
                      "code"
                    ],
                    "additionalProperties": {}
                  }
                }
              },
              "required": [
                "one_time",
                "last_resort"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_log"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "seq": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 9007199254740991
                },
                "kind": {
                  "type": "string",
                  "enum": [
                    "commit",
                    "proposal",
                    "key_history",
                    "key_history_sealed"
                  ]
                },
                "epoch": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "message": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                },
                "drop_public_key": {
                  "type": "string",
                  "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                }
              },
              "required": [
                "seq",
                "kind",
                "epoch",
                "message"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_welcome"
            },
            "taskId": {
              "type": "string"
            },
            "msgId": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            },
            "data": {
              "type": "object",
              "properties": {
                "welcome": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                },
                "seq": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 9007199254740991
                }
              },
              "required": [
                "welcome",
                "seq"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "e2ee_response"
            },
            "taskId": {
              "type": "string"
            },
            "reqId": {
              "type": "string"
            },
            "data": {
              "type": "object",
              "properties": {
                "ok": {
                  "type": "boolean"
                },
                "error": {
                  "type": "object",
                  "properties": {
                    "code": {
                      "type": "string"
                    },
                    "message": {
                      "type": "string"
                    }
                  },
                  "required": [
                    "code"
                  ],
                  "additionalProperties": {}
                },
                "entries": {
                  "type": "array",
                  "items": {
                    "type": "object",
                    "properties": {
                      "seq": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 9007199254740991
                      },
                      "kind": {
                        "type": "string",
                        "enum": [
                          "commit",
                          "proposal",
                          "key_history",
                          "key_history_sealed"
                        ]
                      },
                      "epoch": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 9007199254740991
                      },
                      "message": {
                        "type": "string",
                        "minLength": 1,
                        "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                      },
                      "drop_public_key": {
                        "type": "string",
                        "pattern": "^[\\w-]{42}[AEIMQUYcgkosw048]$"
                      }
                    },
                    "required": [
                      "seq",
                      "kind",
                      "epoch",
                      "message"
                    ],
                    "additionalProperties": {}
                  }
                },
                "more": {
                  "type": "boolean"
                },
                "epoch": {
                  "type": "integer",
                  "minimum": 0,
                  "maximum": 9007199254740991
                },
                "seq": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 9007199254740991
                },
                "link": {
                  "type": "string",
                  "minLength": 1,
                  "pattern": "^(?:[\\w-]{4})*(?:[\\w-][AQgw]|[\\w-]{2}[AEIMQUYcgkosw048])?$"
                }
              },
              "required": [
                "ok"
              ],
              "additionalProperties": {}
            }
          },
          "required": [
            "type",
            "taskId",
            "reqId",
            "data"
          ],
          "additionalProperties": {}
        },
        {
          "type": "object",
          "properties": {
            "type": {
              "type": "string",
              "const": "ack"
            },
            "id": {
              "type": "string",
              "pattern": "^[0-7][0-9a-hjkmnp-tv-z]{25}$"
            }
          },
          "required": [
            "type",
            "id"
          ],
          "additionalProperties": {}
        }
      ]
    }
  }
}
```
