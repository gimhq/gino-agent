# Profile: gino task content (`gino.task-content.v1`)

This profile applies the [e2ee framework](spec.md) to gino's task flow (clients ↔ host ↔
runner) over the frames of [`protocol.md`](../protocol.md) §5. The machine-readable field map is
[`task-content.fieldmap.json`](task-content.fieldmap.json); where this text and the map
disagree, the map is wrong and is fixed.

New frames and fields for the DS role, enrollment and `encryption_error` are defined by the
protocol, not here; this profile names the information they must carry.

## 1. Scope and group

| item | value |
|---|---|
| profile id | `gino.task-content.v1` |
| scope | one task |
| scope id | the task id (`taskId` on every frame) |
| group id | spec §2.3 with `P = "gino.task-content.v1"`, `S = taskId` |
| default history policy | `full` |
| members | the runner(s) the task is placed on, and the client devices of the users with access to the task |

- **Who commits membership.** Client members acting for an owner or admin of the task create the
  group, add and remove members, and change the history policy. They write the epoch link with
  every commit (spec §7.2).
- **Runners never commit membership.** A runner MAY commit an Update of its own leaf (with its
  link); this is optional in v1.
- **Placement.** Before a task is dispatched to a runner, a client member claims one of the
  runner's KeyPackages and adds it. A runner whose agent DB was lost publishes fresh KeyPackages;
  a client commits Remove(old leaf) + Add(new KeyPackage) and the runner recovers history through
  the epoch links. Until then the runner fails turns of that task with `not_member`.
- **Drops.** Inbound webhooks and other writers without membership seal `message.data.text` to
  the task's current drop public key (spec §9).

## 2. Sealed fields

The field map seals these values on frames of an encrypted task. Everything else stays
cleartext.

| frame | path | kind | envelopes | sealed by |
|---|---|---|---|---|
| `message` | `data.text` | text | content, drop | client member (prompt), drop sender (webhook) |
| `message` | `data.attachments[].name` | text | content | client member |
| `message` | `data.attachments[]` bytes | blob | file | client member |
| `cron_upsert` | `data.prompt` | text | content | client member |
| `thread_message` | `data.content` (every kind) | text | content | runner |
| `thread_message` | `data.input` when `data.kind ≠ host_action` (tool inputs) | json | content | runner |
| `thread_message` | `data.input.params` when `data.kind = host_action`, split by `data.input.method` (§2.1) | json | content | runner (daemon) |
| `thread_message` | `data.output.content` (tool outputs) | json | content | runner |
| `thread_result` | `data.result` | text | content | runner |
| `thread_result` | `data.error` | text | content | runner |
| `thread_result` | `data.attachments[].name` | text | content | runner |
| `thread_result` | `data.attachments[]` bytes | blob | file | runner |

Notes:

- **Attachments.** The bytes are uploaded as a file envelope (spec §5.4) under an opaque upload
  name (`<sha256>.bin`) with `content_type` `application/octet-stream`; `sha256` and `size`
  describe the envelope. The descriptor's `name` carries the sealed real name. The real content
  type is inferred from the opened name. The name's location binds the blob's `sha256`, so a
  name cannot be paired with another blob.
- **Host actions.** See §2.1.
- **Tool results.** `data.output.is_error` stays cleartext; only `data.output.content` is sealed.

### 2.1 Host actions

`data.input.method` stays cleartext: the host dispatches on it. `data.input.params` follows the
`keyed_plain` rule of spec §12.5 with discriminator `data.input.method` and the table below:
for each method, the parameter paths the host needs in plaintext to apply the action. Every
other parameter is sealed individually (location `…|field:input.params.<concrete path>`).

| method | plain parameter paths |
|---|---|
| — | — |

On an encrypted task **only a method listed in this table may appear**. The method is
cleartext, and drops are unauthenticated (spec §9): anyone who can send channel or webhook text to
an encrypted task can steer the engine, so an undeclared method could carry content to the relay
in plaintext. A method not in the table is refused: the runner never emits it (`thread.action`
returns an error to the engine, appends nothing and consumes no `seq`), and the host never stores
it (§5).

The table is **empty**: the gino host applies no host actions today. Encrypted tasks of this
profile therefore emit no host actions.

A host that executes actions declares each method and its plain paths in a revision of this
profile (a new profile id, spec §10); the declared paths are then visible to the host as
metadata, and every other parameter of a declared method is sealed. A parameter key on a concrete
path that contains `.` or `|` is refused by the daemon's sealer, and `thread.action` returns an
error to the engine.

### 2.2 Cleartext metadata

- envelope ids: `taskId`, `threadId`, `cronId`, `outboxId`, `msgId`, `reqId`, `ptyId`;
- `thread_message`: `seq`, `kind`, `role`, `tool`, `tool_use_id`, `parent_tool_use_id`,
  `input.method` (host actions; only a method declared in §2.1, none in this profile) and the
  host-action parameters declared plain in §2.1, `output.is_error`;
- `thread_result`: `status`, `failure_reason`, `engine_session_id`, `duration_ms`, `final_seq`,
  the new `encryption_error`, and the attachment descriptor fields other than `name`
  (`id`, `content_type`, `size`, `sha256`, `ref`, `direction`);
- `message`: the attachment descriptor fields other than `name`;
- `task_upsert` whole (`name`, `kind`, `status`, `engine`, `model`, `workdir`, `meta`,
  `entries`): the task definition and provisioning are host configuration;
- `cron_upsert` other than `prompt`; `cron_state`, `heartbeat`, `config_update`, `close`,
  `interrupt`, `task_delete`, `cron_delete`, acks.

### 2.3 Live-only remote operations

`fs_request` / `fs_response` (§5.1) and the terminal frames (§5.2) give the host plaintext
access to the workspace. They are **not sealed**; a runner holding any encrypted task refuses
them by default (§4.6).

## 3. AAD templates

Placeholders are spec §12.3 paths in the frame.

| frame | path | location template |
|---|---|---|
| `message` | `data.text` | `scope:{taskId}\|frame:message\|field:text` |
| `message` | `data.attachments[].name` | `scope:{taskId}\|frame:message\|attachment:{data.attachments[].sha256}\|field:name` |
| `message`, `thread_result` | `data.attachments[]` bytes | `scope:{taskId}\|field:file` |
| `cron_upsert` | `data.prompt` | `scope:{taskId}\|frame:cron_upsert\|field:prompt` |
| `thread_message` | `data.content` | `scope:{taskId}\|frame:thread_message\|thread:{threadId}\|seq:{data.seq}\|field:content` |
| `thread_message` | `data.input` | `scope:{taskId}\|frame:thread_message\|thread:{threadId}\|seq:{data.seq}\|field:input` |
| `thread_message` | `data.input.params` (sealed whole; a split part appends `.<concrete path>`, spec §12.5) | `scope:{taskId}\|frame:thread_message\|thread:{threadId}\|seq:{data.seq}\|field:input.params` |
| `thread_message` | `data.output.content` | `scope:{taskId}\|frame:thread_message\|thread:{threadId}\|seq:{data.seq}\|field:output.content` |
| `thread_result` | `data.result` | `scope:{taskId}\|frame:thread_result\|thread:{threadId}\|delivery:{outboxId}\|field:result` |
| `thread_result` | `data.error` | `scope:{taskId}\|frame:thread_result\|thread:{threadId}\|delivery:{outboxId}\|field:error` |
| `thread_result` | `data.attachments[].name` | `scope:{taskId}\|frame:thread_result\|thread:{threadId}\|attachment:{data.attachments[].sha256}\|field:name` |

- Client-sealed values (`message`, `cron_upsert`) bind only the task and the field: the client
  seals before the host mints `msgId`, `threadId` or `cronId`. Replaying such a value within the
  same task needs an actively malicious relay, which the threat model excludes (spec §6).
- Runner-sealed values bind the thread and `seq` (transcript) or the `thread_result`'s own
  `outboxId` (a thread has many turns and a turn may emit no `thread_message`). `outboxId` is
  therefore **required** on an encrypted task's `thread_result`, and the host stores it with the
  result (spec §12.3).
- The blob location is the same for inbound and outbound files; the binding to its frame is
  through the sealed name.

## 4. Runner rules

### 4.1 Identity and state

- The identity key is an Ed25519 seed (32 bytes) in the runner's state directory, mode `0600`,
  next to `connect.token`. It is never placed in the engine's environment, arguments, sandbox
  binds, workspace, logs or the local agent API. Its fingerprint (spec §3.5) is logged at
  startup.
- The runner advertises the capability object of spec §10 and keeps at least 10 one-time
  KeyPackages at the host, topping up when fewer than 5 remain, plus a current last-resort
  KeyPackage.
- MLS group state (one snapshot per task) and the epoch-secret cache live in the agent DB,
  encrypted at rest under a 32-byte key in a separate `0600` file in the state directory.
- Handshake log entries are processed strictly in DS order (spec §3.1), and an offline runner
  catches up before opening content of a newer epoch.

### 4.2 Inbound

- Every mapped field of a turn's input (`message` text and attachments, a cron's `prompt`) is
  opened **before** the turn starts. If any open fails, there is no turn: the runner ends the
  thread with `thread_result {status: "failed", failure_reason: "agent.encryption",
  encryption_error: {code, epoch?}}` and no `result`, `error` or attachments.
- A mapped field in plaintext on an encrypted task is `plaintext_rejected`, handled the same way.
- Drop plaintext (`message.data.text` sealed as a drop) is handed to the engine like any prompt;
  it has the trust of host-written framing, not of a member.

### 4.3 Outbound

- Every mapped field is sealed under the current epoch's `k_e` **before the outbox enqueue**, so
  only ciphertext is persisted, replayed and delivered. The outbox is the only outbound path for
  an encrypted task; there is no HTTP output fallback. This covers transcript events, results,
  errors and output files, and the daemon's `thread.action` path (the local API seals in the daemon; the engine holds no key; if sealing
  fails the call returns an error to the engine and no event is appended).
- `thread.action` on an encrypted task refuses a method not declared in §2.1 before sealing:
  it returns an error to the engine (without echoing the method), appends nothing and consumes no
  `seq`. The task row decides, not the group state.
- `seq` and the `thread_result` `outboxId` are assigned before sealing.
- A frame that cannot be sealed is not sent; the thread fails with `agent.encryption` and
  `encryption_error.code = "seal_failed"` (or the more specific code).

### 4.4 Failures

- `agent.encryption` is a non-retryable member of the `agent.*` failure taxonomy
  ([agent-architecture](../agent-architecture.md) §6): retrying with the same state gives the
  same answer. The host re-dispatches once the cause is fixed (for example after the runner is
  re-added).
- `encryption_error` is metadata only; the runner logs the code, task id, thread id and epoch
  only.
- There is never a plaintext fallback.

### 4.5 Trust boundary

Inside the runner, content is plaintext: engine-local state (session files under the engine
home), memory trees and the workspace hold it, and the engine's model provider receives it.
Encryption keeps content off the host, not out of the runner.

### 4.6 Remote operations

While the runner holds any encrypted task (is a member of any task group), it refuses
`fs_request` with `{ok: false, error: {code: "denied"}}` and `pty_open` with `pty_exit
{error: {code: "denied"}}`, whatever `remoteOps` says. A runner-local setting may opt in; the
host has no override.

## 5. Host (relay) rules

The host implements the DS contract of spec §3. In addition:

- A task's encrypted flag is set when its scope is registered and never cleared.
- Dispatching or assigning an encrypted task to a runner without the `e2ee` capability, or
  without a leaf in the task's group, returns **409 `runner_without_encryption`**; the task is
  never downgraded to plaintext.
- Mapped fields of an encrypted task are accepted only in the sealed form (`plaintext_rejected`),
  from clients (`message`, `cron_upsert` input) and from runners (`thread_message`,
  `thread_result`).
- An inbound `host_action` on an encrypted task whose `input.method` is not declared in §2.1 is
  acked and dropped like `plaintext_rejected`: never stored or relayed, counted, and logged
  without the method.
- Sealed values and the cleartext fields their locations reference are stored and returned byte
  for byte; `encryption_error` is shown as received.
- Webhook payloads for an encrypted task are sealed as drops to the current drop public key
  before they are stored or forwarded.
- The host honours the runner's remote-ops refusal; there is no override.
