# @gino/e2ee

The gino end-to-end encryption core for TypeScript: the `gino-e2ee` crate compiled to wasm
behind a typed API. It implements [`docs/e2ee/spec.md`](../../docs/e2ee/spec.md): envelopes,
epoch links and key history, the backward walk, field maps (with the generated
`taskContentFieldMap`) and MLS scope groups.

```ts
import { FieldMapEngine, Identity, init, KeyPackageStore, ScopeGroup } from "@gino/e2ee";

await init(); // fetches wasm/gino_e2ee_bg.wasm (Bun, browsers); or init(bytes) / initSync(bytes)

const alice = Identity.generate();
const group = ScopeGroup.create(alice, "gino.task-content.v1", "t-1");
const engine = FieldMapEngine.forProfile("gino.task-content.v1");
const sealed = group.sealFrame(engine, "message", { type: "message", taskId: "t-1", data: { text: "hi" } });
const snapshot = group.snapshot(); // store encrypted at rest, after every state-changing call
```

Binary values are `Uint8Array`; JSON wire values are base64url without padding. Failures throw
`E2eeError` with the spec §11 `code` (and `epoch` where §11 has one), or a local group code
(`log_gap`, `commit_pending`, `no_pending_commit`, `storage`). `withEpochLinks` fetches the epoch
links a walk misses from the DS and retries.

## Client helpers

`E2eeClient` drives encrypted tasks (`gino.task-content.v1`) through the host admin API with an
injected `fetch`, base URL (the admin root, e.g. `https://host/api/admin`) and bearer token. A
device's secrets never leave it: persist `client.snapshot()` (or take it from the `onSnapshot`
hook, called after every state-changing call) encrypted at rest and pass it to
`E2eeClient.restore`. The snapshot holds the identity seed, the KeyPackage private keys, one MLS
group per task and the identity fingerprints the device pinned per party.

```ts
await init();
const client = E2eeClient.create("laptop", { baseUrl, token, onSnapshot: save });
await client.enroll({ oneTime: 10 });                // identity key + KeyPackages
const { taskId } = await client.createEncryptedTask({ owner_id, engine, model }, { policy: "full" });
await client.addRunner(taskId, agentId);             // claim, commit, assign
const file = client.sealAttachment(taskId, "notes.md", bytes);
const descriptor = await client.uploadAttachment(taskId, file); // envelope under `<sha256>.bin`
await client.sendPrompt(taskId, "summarize", { attachments: [descriptor] });
const transcript = await client.openTranscript(taskId, threadId);
const result = await client.openResult(taskId, threadId);
```

- **Directory**: `enroll({ oneTime? })` enrolls the identity key with its capability and publishes
  one-time KeyPackages and a last-resort one; `publishKeyPackages(oneTime, lastResort?)` tops
  the pool up. KeyPackage private keys are persisted before the upload.
- **Tasks and membership**: `createEncryptedTask(input, { policy? })` mints the ULID task id,
  creates the group at epoch 0 and creates the task with its epoch-0 drop key.
  `addRunner(taskId, agentId, { assign?, keyHistory? })` and `addMember(taskId, partyId,
  { keyHistory? })` claim a KeyPackage and commit the Add; they refuse a key that differs from the
  directory's fingerprint or from the device's pin (`E2eeClientError` `key_changed`, also the
  host's 409 while a key change is pending) and return `keyChangeWarning` when the directory
  reports one. `removeMember`, `rotate` (an Update of the device's own leaf) and `setPolicy`
  follow the same pattern: catch up, submit the commit unit, merge it on acceptance; on
  `epoch_conflict` discard it, catch up and retry once. A lost response is settled from the log.
  `assign(taskId, agentId)` places the task.
- **Joining and catching up**: `join(taskId)` joins another device of a member from its newest
  Welcome, acks its Welcomes and catches up; `sync(taskId)` applies pending log entries in `seq`
  order.
- **Sealing**: `sealPrompt`, `sendPrompt`, `sealCronPrompt` (for the cron routes) and
  `sealAttachment` (a file envelope with its opaque upload name `<sha256>.bin` and a descriptor
  whose sealed `name` binds the envelope's `sha256`) seal through the field map engine, so
  locations match the profile.
- **Attachments**: `uploadAttachment(taskId, sealed)` uploads the envelope through
  `POST /admin/tasks/:id/attachments` and returns the message descriptor (sealed name, `id`,
  `ref`); `listAttachments(taskId, threadId?)` lists the task's stored descriptors (names stay
  sealed) and `downloadAttachment(taskId, attachmentId)` returns an attachment's envelope bytes.
- **Opening**: `openTranscript`, `openResult` (the AAD binds the run's `outboxId`) and
  `openOutputFile(descriptor, bytes)` (bytes must match the descriptor's `sha256`) fetch missing
  epoch links from the links route and return each sealed value as `{ ok: true, value }` or
  `{ ok: false, error }` with its `E2eeError` (`history_unavailable`, `open_failed`, …), so one
  unreadable value does not fail the rest.

Host refusals throw `E2eeClientError` with the HTTP `status`, the error `code` and `details`.

## Delivery Service inspection

Keyless checks of public MLS structures for a relay acting as DS (spec §3). Rejections throw
`E2eeError` with `code` `malformed` (or `unsupported_suite` for a KeyPackage suite other than
`0x0001`) and a short non-secret `reason`.

- `inspectKeyPackage(bytes, now?)` → `{ ref, publicKey, lastResort, notBefore, notAfter }`:
  full KeyPackage validation (signatures, suite, lifetime at `now` in Unix seconds, default the
  current time, the §2.5 capabilities, BasicCredential of the 32-byte Ed25519 key). The caller
  compares `publicKey` with the pinned key.
- `inspectMessage(bytes)` → `{ groupId, epoch, contentType, senderLeaf, adds, removes,
  proposalRefs, updatesPath }` for a PublicMessage: `adds` are the KeyPackageRefs of Add
  proposals and `removes` the leaf indexes of Remove proposals carried by value, in order;
  `proposalRefs` are proposals a commit carries by reference. Membership is not verified.
- `welcomeRecipients(bytes)` → the `new_member` KeyPackageRefs of a Welcome, in order.

## Host side (`@gino/e2ee/ds`)

The relay a host runs for encrypted tasks (protocol §5.3, spec §3): the key directory (identity
pinning, key-change warnings, client enrollment, KeyPackage pools) and the MLS Delivery Service
(scope registration, commit acceptance, the handshake log, epoch links, Welcomes and their
delivery to runners). It is framework-free and synchronous and never holds a key that opens
content. The host supplies storage and its agent channel:

```ts
import { E2eeRelay, memoryE2eeRepo } from "@gino/e2ee/ds";

const relay = new E2eeRelay({
  repo: memoryE2eeRepo(),                 // or an adapter of `E2eeRepo` over the host's database
  agents: {
    isOnline: agentId => sockets.has(agentId),
    send: (agentId, frame) => sockets.get(agentId)?.send(JSON.stringify({ v: 1, ...frame })),
    enqueue: (agentId, frame) => outbox.append(agentId, frame), // durable, replayed until msg_ack
  },
  taskExists: taskId => tasks.has(taskId),
  logger, emit, clock, wasm,              // optional
});
```

The host wires the agent frames to it: `observeAgentCapability` on every `register` and
`heartbeat`, `pushStatus` when a socket opens, `acceptAgentKeyPackages` for
`e2ee_key_packages`, `handleAgentRequest` for `e2ee_request` and `onMessageAck` with the frame
behind each `msg_ack`. Its admin surface maps onto `enrollClient`, `parties`, `repin`,
`publishKeyPackages`, `claimKeyPackage`, `registerScope`, `submitCommit`, `submitProposal`,
`readLog`, `epochLink`, `putEpochLink`, `welcomes` and `ackWelcome`. `findPlaintextField`
checks that an encrypted task's frame carries every mapped field sealed.

Failures throw `RelayError` (`statusCode`, `code`, `details`, `toJSON()` = the error envelope):
`RelayNotFoundError` (404), `RelayValidationError` (422) and `E2eeDsError` with the DS code
(`epoch_conflict`, `link_exists`, `scope_exists` 409; `not_member` 403; `malformed` 422). The
zod schemas of the e2ee wire members (`SealedValue`, `E2eeCapability`, `E2eeRequestData`, …) are
exported for the host's frame validation. An `E2eeRepo` adapter proves its invariants with
`describeE2eeRepoConformance` from `@gino/e2ee/ds/testing`.

## Wasm artifact

The built module and its wasm-bindgen glue (`--target web`) are committed in `wasm/`, so
`bun install && bun test` needs no Rust toolchain. The build is reproducible (pinned toolchain,
wasm-bindgen-cli and binaryen in `gino-e2ee/docker/wasm.Dockerfile`, remapped source paths), so
CI checks it for drift. Both commands need that image's tools:

```sh
docker build --label ai-agent=true -t ai-agent/gino-e2ee-wasm:1.96 \
  -f gino-e2ee/docker/wasm.Dockerfile gino-e2ee/docker
bun run build:wasm   # rebuild wasm/ after changing gino-e2ee
bun run check:wasm   # rebuild into a temp dir and fail if wasm/ differs
```
