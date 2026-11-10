# Host quickstart

The shortest path to a host that drives a `gino-agent`. [`protocol.md`](protocol.md) is the
contract; where this guide and the contract differ, the contract wins.
[`gino-mini-host`](../gino-mini-host/src/lib.rs) is the reference host: it implements the whole
protocol, including file operations, terminals, provisioning and the e2ee Delivery Service, and
its module docs map each part of the protocol to the code. §8 of the protocol is a JSON Schema
you can validate your frames against.

## Try it

Run the reference host:

```bash
cd gino-mini-host
MINI_HOST_REGISTER_TOKEN=dev-token cargo run
```

Run an agent with fake engines, so no LLM credentials are needed. The test image is published
from each release, starting with the first after `v0.1.0`:

```bash
docker run --rm --network host \
  -e GINO_HOST_URL=http://127.0.0.1:3100 \
  -e GINO_REGISTER_TOKEN=dev-token \
  -e GINO_AGENT_NAME=demo \
  ghcr.io/gimhq/gino-agent-test:<tag>
```

Create a task and read the result:

```bash
HOST=http://127.0.0.1:3100
TASK=$(curl -s -X POST $HOST/api/tasks -H 'content-type: application/json' \
  -d '{"name":"demo"}' | jq -r .taskId)
THREAD=$(curl -s -X POST $HOST/api/tasks/$TASK/messages -H 'content-type: application/json' \
  -d '{"text":"hello"}' | jq -r .threadId)
curl -s "$HOST/api/threads/$THREAD/wait?timeoutMs=20000" | jq .
```

`/api/*` belongs to the mini-host, not to the protocol. Your host exposes its own operator API.

To wait for the next turn on the same thread, pass the run count the message call returned:
`/api/threads/$THREAD/wait?after=<runs>`.

## The joint suite

`gino-mini-host/tests/joint.rs` runs a real agent binary (with the `e2e/` fake engines) against
the mini-host: turns and usage, both engines, engine options, replay after a restart,
interrupt, close, attachments, crons, provisioning, every file operation, terminals and an
encrypted task end to end. CI runs it against each release build. To run it locally:

```bash
GINO_AGENT_BIN=/path/to/gino-agent cargo test --release --test joint -- --ignored
```

or `gino-mini-host/scripts/joint-it.sh`, which builds the agent and runs the suite in a container.

## What a host must implement

The agent always dials out, and everything it needs comes from these four endpoints.
`GINO_HOST_URL` is the base it appends `/agent/*` to.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /agent/register` | `registerToken` in the body | Enroll; returns `agentId`, `connectToken` and `config` |
| `GET /agent/config/:agentId` | `x-internal-token: <connectToken>` | Config at each start, returned flat |
| `GET /agent/ws/:agentId` | `x-internal-token: <connectToken>` | The WebSocket that carries all work |
| `POST /agent/output/:agentId` | `x-internal-token: <connectToken>` | Output sent before the WebSocket is up |

Attachments and provisioning add the `/agent/attachments` byte channel (protocol §2). A host
that sends neither can skip it.

## The flow

1. **Enroll.** Check `registerToken` and `protocolVersion`, mint an `agentId` and a
   `connectToken`, and answer with `config`. The agent keeps the token and reconnects without
   registering again. Rejections are `{"register_error": {"reason": "..."}}` (protocol §3).
2. **Accept the WebSocket.** Check the token against the `agentId`.
3. **Create a task.** Send `task_upsert`, then `message`. Every host frame carries a ULID
   `msgId`:

   ```json
   {"type": "task_upsert", "msgId": "<ulid>", "taskId": "t-1", "data": {"name": "demo"}}
   {"type": "message", "msgId": "<ulid>", "taskId": "t-1", "data": {"text": "hello"}}
   ```

4. **Stop replay.** The agent answers `{"type": "msg_ack", "msgId": "<ulid>"}` once the frame is
   stored. Resend unacked frames after a reconnect.
5. **Store the output.** `thread_message` frames arrive in `seq` order, and `thread_result` ends the
   turn. After a durable write, answer each `outboxId` with `{"type": "ack", "id": "<outboxId>"}`.
   Expect replays and dedupe by id.

Live-only frames such as `fs_request`, the terminal frames and `interrupt` are never queued,
acked or replayed.

## Rules that are easy to miss

- Ignore unknown `type`s and unknown fields, in both directions (protocol §1).
- Correlation ids live on the envelope. `data` never repeats them (protocol §4.1).
- `config_update.data` is a JSON merge patch: an absent key keeps the value and `null` removes it.
- Send a monotonic `version` with each config change. `heartbeat.configVersion` reports the last
  one applied, so it tells you when a change took effect. It stays behind while an overlay's
  `entries` have not reconciled.
- Absent `entries` leaves the provisioned set alone. `entries: []` removes every global entry.
- Reports of a failed thread carry `failure_reason`, split into `runner.*` and `agent.*`
  ([taxonomy](agent-architecture.md)). `agent.provider_auth` means the provider refused the engine's
  credentials.
- `capabilities` lists what the agent can run. Place a task naming `engine: "codex"` only on an
  agent that advertises `codex`.
