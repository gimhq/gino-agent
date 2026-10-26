import type { Applied, CommitUnit, HistoryPolicy, KeyHistoryOffer, SealedValue } from "../index";
import type { AdminEndpoint } from "./http";
import { E2eeError } from "../errors";
import { taskContentFieldMap } from "../field-map.generated";
import {
  buildLocation,
  decodeB64url,
  encodeB64url,
  FieldMapEngine,
  fingerprint,
  Identity,
  inspectKeyPackage,
  KeyPackageStore,
  ScopeGroup,
  sealFile,
  withEpochLinks,
} from "../index";
import { AdminApi, E2eeClientError, ulid } from "./http";

export type { AdminEndpoint, FetchLike } from "./http";
export { E2eeClientError } from "./http";

const PROFILE = taskContentFieldMap.profile;

/**
 * Everything a client device keeps between sessions: its identity seed, its
 * KeyPackage private keys, one MLS group snapshot per task and the identity
 * fingerprints it pinned per party. All of it is secret except `clientId`
 * and `pins`; the caller stores it encrypted at rest and never sends it.
 */
export interface DeviceSnapshot {
  clientId: string;
  identity: Uint8Array;
  keyPackages: Uint8Array;
  groups: Record<string, Uint8Array>;
  pins: Record<string, string>;
}

export interface E2eeClientOptions extends AdminEndpoint {
  /** Called with a fresh snapshot after every state-changing call; persist it. */
  onSnapshot?: (snapshot: DeviceSnapshot) => void | Promise<void>;
}

/** A pending identity key change the directory reports for a party. */
export interface KeyChangeWarning {
  pinned_fingerprint: string;
  pending_fingerprint: string;
  pending_fingerprint_display: string;
  changed_at: number;
}

export interface PartySummary {
  partyId: string;
  fingerprint: string;
  fingerprint_display: string;
  key_change_warning?: KeyChangeWarning;
}

export interface PartyView extends PartySummary {
  kind: "agent" | "client";
  public_key: string;
  capability: Record<string, unknown> | null;
  capable: boolean;
  key_packages: { one_time: number; last_resort: boolean };
}

export interface KeyPackagePoolStatus {
  one_time: number;
  last_resort: boolean;
  rejected?: Array<{ code: string; index?: number }>;
}

/** The task fields of `POST /admin/tasks` other than `id` and `e2ee`. */
export interface EncryptedTaskInput {
  owner_id: string;
  engine: string;
  model: string;
  workdir?: string;
  meta?: Record<string, unknown>;
  name?: string;
  kind?: string;
  status?: string;
}

/** The host's task view (`e2ee` is set for an encrypted task). */
export interface TaskView {
  id: string;
  agentId: string | null;
  status: string;
  e2ee: { profile_id: string; group_id: string; epoch: number; drop_public_key: string } | null;
  [key: string]: unknown;
}

/** An accepted commit: its `seq` and the new epoch. */
export interface CommitResult {
  seq: number;
  epoch: number;
}

export interface MemberAdded extends CommitResult {
  /** The added party as the directory reported it with the claimed KeyPackage. */
  party: PartySummary;
  /** A pending key change of the party; the KeyPackage was still made under its pinned key. */
  keyChangeWarning?: KeyChangeWarning;
  /** The claimed KeyPackage was the party's last-resort one. */
  lastResort: boolean;
}

export interface RunnerAdded extends MemberAdded {
  /** The `POST /admin/tasks/:id/assign` result, when assigned. */
  dispatch?: unknown;
}

/** A sealed attachment ready to upload: the descriptor fields and the file envelope bytes. */
export interface SealedAttachment {
  /** Upload the envelope under this opaque name. */
  uploadName: string;
  envelope: Uint8Array;
  descriptor: { name: SealedValue; content_type: "application/octet-stream"; size: number; sha256: string };
}

/** An attachment descriptor of a message, its `name` sealed. */
export interface AttachmentDescriptorInput {
  id: string;
  name: SealedValue;
  content_type: string;
  size: number;
  sha256: string;
  ref: string;
  direction?: "inbound" | "outbound";
}

export interface SentMessage {
  threadId: string;
  msgId: string;
  seeded: boolean;
}

/** One opened value: its plaintext, or the e2ee failure that value alone hit. */
export type Opened<T> = { ok: true; value: T } | { ok: false; error: E2eeError };

/** A transcript event with each sealed field opened on its own. */
export interface OpenedMessage {
  seq: number;
  kind: string;
  role: string | null;
  tool: string | null;
  toolUseId: string | null;
  parentToolUseId: string | null;
  createdAt: number;
  content?: Opened<string>;
  input?: Opened<unknown>;
  /** The whole `output` with `content` opened (`is_error` stays as stored). */
  output?: Opened<unknown>;
}

export interface OpenedResult {
  status: string;
  outboxId: string | null;
  failureReason: string | null;
  encryptionError: unknown;
  result?: Opened<string>;
  error?: Opened<string>;
}

/** A runner output file as the host stores it (`name` sealed). */
/** A task attachment descriptor as `GET /admin/tasks/:id/attachments` lists it; an `OutputFileDescriptor` for `openOutputFile`. */
export interface TaskAttachment {
  id: string;
  taskId: string;
  threadId: string;
  name: SealedValue;
  contentType: string;
  size: number;
  sha256: string;
  direction: "inbound" | "outbound";
  createdAt: number;
}

export interface OutputFileDescriptor {
  taskId: string;
  threadId: string;
  name: SealedValue;
  sha256: string;
}

interface TranscriptRow {
  seq: number;
  kind: string;
  role: string | null;
  content: unknown;
  tool: string | null;
  input: unknown;
  output: unknown;
  toolUseId: string | null;
  parentToolUseId: string | null;
  createdAt: number;
}

interface ThreadRun {
  status: string;
  outboxId: string | null;
  result: unknown;
  error: unknown;
  failureReason: string | null;
  encryptionError: unknown;
}

interface ThreadPage {
  run: ThreadRun | null;
  messages: TranscriptRow[];
}

interface LogPage {
  entries: Array<{ seq: number; kind: "commit" | "proposal" | "key_history" | "key_history_sealed"; epoch: number; message: string; drop_public_key?: string }>;
  more: boolean;
  epoch: number;
}

const TRANSCRIPT_PAGE = 200;

function fileLocation(taskId: string): string {
  const rule = taskContentFieldMap.frames.message!.fields.find(f => f.kind === "blob")!;
  return buildLocation(rule.aad, { taskId });
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * A client device driving encrypted tasks through the host admin API
 * (`gino.task-content.v1`): enrollment, group membership, sealing input and
 * opening the runner's output. Secrets stay on the device; persist
 * {@link E2eeClient.snapshot} (or the `onSnapshot` hook) encrypted at rest.
 * Requires `init()` of the wasm module first.
 */
export class E2eeClient {
  readonly clientId: string;
  readonly identity: Identity;
  private keyPackages: KeyPackageStore;
  private readonly groups = new Map<string, ScopeGroup>();
  private readonly pins: Map<string, string>;
  private readonly api: AdminApi;
  private readonly onSnapshot: E2eeClientOptions["onSnapshot"];
  private engineInstance: FieldMapEngine | undefined;

  private constructor(options: E2eeClientOptions, clientId: string, identity: Identity, keyPackages: KeyPackageStore, pins: Record<string, string>) {
    this.api = new AdminApi(options);
    this.onSnapshot = options.onSnapshot;
    this.clientId = clientId;
    this.identity = identity;
    this.keyPackages = keyPackages;
    this.pins = new Map(Object.entries(pins));
  }

  /** A new device with a fresh identity. */
  static create(clientId: string, options: E2eeClientOptions): E2eeClient {
    return new E2eeClient(options, clientId, Identity.generate(), new KeyPackageStore(), {});
  }

  static restore(snapshot: DeviceSnapshot, options: E2eeClientOptions): E2eeClient {
    const client = new E2eeClient(options, snapshot.clientId, Identity.fromSeed(snapshot.identity), KeyPackageStore.restore(snapshot.keyPackages), snapshot.pins);
    for (const [taskId, group] of Object.entries(snapshot.groups))
      client.groups.set(taskId, ScopeGroup.restore(group));
    return client;
  }

  /** The device's party id at the host directory. */
  get partyId(): string {
    return `client:${this.clientId}`;
  }

  get fingerprint(): string {
    return fingerprint(this.identity.publicKey);
  }

  /** The task's group on this device, if it is a member. */
  group(taskId: string): ScopeGroup | undefined {
    return this.groups.get(taskId);
  }

  snapshot(): DeviceSnapshot {
    const groups: Record<string, Uint8Array> = {};
    for (const [taskId, group] of this.groups)
      groups[taskId] = group.snapshot();
    return {
      clientId: this.clientId,
      identity: this.identity.seed,
      keyPackages: this.keyPackages.snapshot(),
      groups,
      pins: Object.fromEntries(this.pins),
    };
  }

  private async persist(): Promise<void> {
    await this.onSnapshot?.(this.snapshot());
  }

  private get engine(): FieldMapEngine {
    this.engineInstance ??= FieldMapEngine.forProfile(PROFILE);
    return this.engineInstance;
  }

  private requireGroup(taskId: string): ScopeGroup {
    const group = this.groups.get(taskId);
    if (!group)
      throw new E2eeError({ code: "not_member" });
    return group;
  }

  // -------------------------------------------------------------------------
  // Directory

  /** Enrolls the identity key, then publishes `oneTime` one-time KeyPackages and a last-resort one. */
  async enroll(options: { oneTime?: number } = {}): Promise<{ party: PartyView; keyPackages: KeyPackagePoolStatus }> {
    const publicKey = encodeB64url(this.identity.publicKey);
    const party = await this.api.post<PartyView>("/e2ee/clients", {
      client_id: this.clientId,
      public_key: publicKey,
      capability: { versions: [1], mls_suites: [1], credential: { type: "basic", public_key: publicKey } },
    });
    const keyPackages = await this.publishKeyPackages(options.oneTime ?? 10, true);
    return { party, keyPackages };
  }

  /** Generates and publishes KeyPackages; their private keys are persisted before the upload. */
  async publishKeyPackages(oneTime: number, lastResort = false): Promise<KeyPackagePoolStatus> {
    const pool = Array.from({ length: oneTime }, () => encodeB64url(this.keyPackages.generate(this.identity)));
    const resort = lastResort ? encodeB64url(this.keyPackages.generate(this.identity, true)) : undefined;
    await this.persist();
    return this.api.post<KeyPackagePoolStatus>(`/e2ee/parties/${encodeURIComponent(this.partyId)}/key-packages`, {
      ...(pool.length > 0 ? { one_time: pool } : {}),
      ...(resort !== undefined ? { last_resort: resort } : {}),
    });
  }

  // -------------------------------------------------------------------------
  // Tasks and membership

  /** Mints the task id, creates its group at epoch 0 and creates the encrypted task. */
  async createEncryptedTask(input: EncryptedTaskInput, options: { policy?: HistoryPolicy } = {}): Promise<{ taskId: string; task: TaskView }> {
    const taskId = ulid();
    const group = ScopeGroup.create(this.identity, PROFILE, taskId, options.policy ?? "full");
    const created = await this.api.post<{ task: TaskView }>("/tasks", {
      ...input,
      id: taskId,
      e2ee: {
        profile_id: PROFILE,
        group_id: encodeB64url(group.groupId),
        drop_public_key: encodeB64url(group.dropPublicKey()),
        creator: this.partyId,
      },
    }).catch((error: unknown) => {
      group.free();
      throw error;
    });
    this.groups.set(taskId, group);
    await this.persist();
    return { taskId, task: created.task };
  }

  /** Adds a runner to the task's group, then assigns the task to it unless `assign` is false. */
  async addRunner(taskId: string, agentId: string, options: { assign?: boolean; keyHistory?: KeyHistoryOffer } = {}): Promise<RunnerAdded> {
    const added = await this.addMember(taskId, agentId, options);
    if (options.assign === false)
      return added;
    return { ...added, dispatch: await this.assign(taskId, agentId) };
  }

  /**
   * Claims one of the party's KeyPackages and commits its addition. Refuses a
   * KeyPackage whose key is not the directory's fingerprint or differs from
   * the key this device pinned for the party (`key_changed`); the host
   * refuses claims while a key change is pending (409 `key_changed`).
   */
  async addMember(taskId: string, partyId: string, options: { keyHistory?: KeyHistoryOffer } = {}): Promise<MemberAdded> {
    const claim = await this.api.post<{ key_package: string; last_resort: boolean; party: PartySummary }>(
      `/e2ee/parties/${encodeURIComponent(partyId)}/key-packages/claim`,
    );
    const keyPackage = decodeB64url(claim.key_package);
    const claimed = fingerprint(inspectKeyPackage(keyPackage).publicKey);
    const pinned = this.pins.get(partyId);
    if (claimed !== claim.party.fingerprint || (pinned !== undefined && pinned !== claimed))
      throw new E2eeClientError("key_changed", `the identity key of ${partyId} changed`);
    if (pinned === undefined)
      this.pins.set(partyId, claimed);
    const accepted = await this.submit(taskId, group => group.addMembers(this.identity, [keyPackage], options.keyHistory));
    return {
      ...accepted,
      party: claim.party,
      lastResort: claim.last_resort,
      ...(claim.party.key_change_warning ? { keyChangeWarning: claim.party.key_change_warning } : {}),
    };
  }

  /** Commits the removal of a member, identified by the key the directory pinned for it. */
  async removeMember(taskId: string, partyId: string): Promise<CommitResult> {
    const party = await this.api.get<PartyView>(`/e2ee/parties/${encodeURIComponent(partyId)}`);
    const publicKey = decodeB64url(party.public_key);
    return this.submit(taskId, group => group.removeMembers(this.identity, [publicKey]));
  }

  /** Commits an Update of this device's own leaf. */
  rotate(taskId: string): Promise<CommitResult> {
    return this.submit(taskId, group => group.selfUpdate(this.identity));
  }

  setPolicy(taskId: string, policy: HistoryPolicy): Promise<CommitResult> {
    return this.submit(taskId, group => group.setPolicy(this.identity, policy));
  }

  /** Places the task on a runner (409 `runner_without_encryption` unless it holds a leaf). */
  assign(taskId: string, agentId: string): Promise<unknown> {
    return this.api.post(`/tasks/${encodeURIComponent(taskId)}/assign`, { agent_id: agentId });
  }

  /**
   * Catches up, then submits the commit `build` makes as one unit. On
   * `epoch_conflict` the pending commit is discarded, the group catches up
   * and the commit is rebuilt and submitted once more.
   */
  private async submit(taskId: string, build: (group: ScopeGroup) => CommitUnit): Promise<CommitResult> {
    const group = this.requireGroup(taskId);
    await this.sync(taskId);
    for (let attempt = 0; ; attempt++) {
      const unit = build(group);
      let accepted: CommitResult;
      try {
        accepted = await this.api.post<CommitResult>(`/e2ee/scopes/${encodeURIComponent(taskId)}/commits`, {
          party_id: this.partyId,
          commit: encodeB64url(unit.commit),
          drop_public_key: encodeB64url(unit.dropPublicKey),
          ...(unit.welcome ? { welcome: encodeB64url(unit.welcome) } : {}),
          ...(unit.epochLink ? { epoch_link: encodeB64url(unit.epochLink) } : {}),
          ...(unit.keyHistory.length > 0 ? { key_history: unit.keyHistory.map(r => ({ kind: r.kind, message: encodeB64url(r.bytes) })) } : {}),
        });
      }
      catch (error) {
        const seq = error instanceof E2eeClientError ? undefined : await this.findCommit(taskId, unit).catch(() => undefined);
        if (seq !== undefined) {
          accepted = { seq, epoch: unit.epoch + 1 };
        }
        else {
          group.commitRejected();
          await this.persist();
          if (attempt > 0 || !(error instanceof E2eeClientError) || error.code !== "epoch_conflict")
            throw error;
          await this.sync(taskId);
          continue;
        }
      }
      group.commitAccepted(accepted.seq);
      await this.persist();
      return accepted;
    }
  }

  /** After a lost response: the `seq` of the commit if the log holds it at its epoch. */
  private async findCommit(taskId: string, unit: CommitUnit): Promise<number | undefined> {
    const page = await this.readLog(taskId, `from_epoch=${unit.epoch}`);
    const entry = page.entries.find(e => e.kind === "commit" && e.epoch === unit.epoch);
    return entry && sameBytes(decodeB64url(entry.message), unit.commit) ? entry.seq : undefined;
  }

  private readLog(taskId: string, cursor: string): Promise<LogPage> {
    return this.api.get<LogPage>(`/e2ee/scopes/${encodeURIComponent(taskId)}/log?party_id=${encodeURIComponent(this.partyId)}&${cursor}`);
  }

  /** Joins a task's group from this device's newest Welcome for it, acks its Welcomes and catches up. */
  async join(taskId: string): Promise<ScopeGroup> {
    const party = encodeURIComponent(this.partyId);
    const welcomes = await this.api.get<Array<{ id: number; seq: number; welcome: string }>>(
      `/e2ee/parties/${party}/welcomes?task_id=${encodeURIComponent(taskId)}`,
    );
    const newest = welcomes.reduce<(typeof welcomes)[number] | undefined>((best, w) => (best && best.seq > w.seq ? best : w), undefined);
    if (!newest)
      throw new E2eeClientError("no_welcome", `no Welcome for task ${taskId}`);
    const group = ScopeGroup.join(this.keyPackages, PROFILE, taskId, decodeB64url(newest.welcome), newest.seq);
    this.groups.get(taskId)?.free();
    this.groups.set(taskId, group);
    await this.persist();
    for (const welcome of welcomes)
      await this.api.post(`/e2ee/parties/${party}/welcomes/${welcome.id}/ack`);
    await this.sync(taskId);
    return group;
  }

  /** Applies the task's pending log entries in `seq` order. */
  async sync(taskId: string): Promise<Applied[]> {
    const group = this.requireGroup(taskId);
    const applied: Applied[] = [];
    for (;;) {
      const page = await this.readLog(taskId, `after_seq=${group.seq}`);
      for (const entry of page.entries) {
        applied.push(group.apply({
          seq: entry.seq,
          kind: entry.kind,
          epoch: entry.epoch,
          bytes: decodeB64url(entry.message),
          dropPublicKey: entry.drop_public_key === undefined ? null : decodeB64url(entry.drop_public_key),
        }));
      }
      if (!page.more || page.entries.length === 0)
        break;
    }
    if (applied.length > 0)
      await this.persist();
    return applied;
  }

  // -------------------------------------------------------------------------
  // Sealing input

  /** Seals a prompt as `message.data.text` under the current epoch. */
  sealPrompt(taskId: string, text: string): SealedValue {
    const frame = { type: "message", taskId, data: { text } };
    return this.requireGroup(taskId).sealFrame<{ data: { text: SealedValue } }>(this.engine, "message", frame).data.text;
  }

  /** Seals a cron's `prompt` (`cron_upsert.data.prompt`) for `POST`/`PUT /admin/tasks/:id/crons`. */
  sealCronPrompt(taskId: string, prompt: string): SealedValue {
    const frame = { type: "cron_upsert", taskId, data: { prompt } };
    return this.requireGroup(taskId).sealFrame<{ data: { prompt: SealedValue } }>(this.engine, "cron_upsert", frame).data.prompt;
  }

  /**
   * Seals a file as a file envelope and its real name bound to the envelope's
   * `sha256`. Upload `envelope` under `uploadName` as
   * `application/octet-stream` (`uploadAttachment`), then send `descriptor`
   * with the upload's `id` and `ref`.
   */
  sealAttachment(taskId: string, name: string, bytes: Uint8Array): SealedAttachment {
    const group = this.requireGroup(taskId);
    const { epoch, k } = group.current();
    const sealed = sealFile(k, epoch, fileLocation(taskId), bytes);
    const frame = { type: "message", taskId, data: { attachments: [{ name, sha256: sealed.sha256 }] } };
    const sealedName = group.sealFrame<{ data: { attachments: Array<{ name: SealedValue }> } }>(this.engine, "message", frame).data.attachments[0]!.name;
    return {
      uploadName: `${sealed.sha256}.bin`,
      envelope: sealed.envelope,
      descriptor: { name: sealedName, content_type: "application/octet-stream", size: sealed.size, sha256: sealed.sha256 },
    };
  }

  /** Uploads a sealed attachment's envelope and returns its message descriptor (sealed name, the upload's `id` and `ref`). */
  async uploadAttachment(taskId: string, attachment: SealedAttachment): Promise<AttachmentDescriptorInput> {
    const query = `name=${encodeURIComponent(attachment.uploadName)}&sha256=${attachment.descriptor.sha256}`;
    const uploaded = await this.api.postBytes<{ id: string; ref: string }>(`/tasks/${encodeURIComponent(taskId)}/attachments?${query}`, attachment.envelope);
    return { ...attachment.descriptor, id: uploaded.id, ref: uploaded.ref };
  }

  /** Seals `text` and sends it with the given (already sealed) attachment descriptors. */
  sendPrompt(taskId: string, text: string, options: { attachments?: AttachmentDescriptorInput[]; newThread?: boolean } = {}): Promise<SentMessage> {
    return this.api.post<SentMessage>(`/tasks/${encodeURIComponent(taskId)}/message`, {
      text: this.sealPrompt(taskId, text),
      ...(options.attachments ? { attachments: options.attachments } : {}),
      ...(options.newThread !== undefined ? { new_thread: options.newThread } : {}),
    });
  }

  // -------------------------------------------------------------------------
  // Opening output

  private fetchLink(taskId: string, epoch: number): Promise<Uint8Array | null> {
    return this.api.get<{ link?: string }>(`/e2ee/scopes/${encodeURIComponent(taskId)}/links/${epoch}?party_id=${encodeURIComponent(this.partyId)}`)
      .then(r => (r.link === undefined ? null : decodeB64url(r.link)));
  }

  /** Opens one value, fetching the epoch links the backward walk misses. */
  private async openValue<T>(taskId: string, open: (group: ScopeGroup) => T): Promise<Opened<T>> {
    const group = this.requireGroup(taskId);
    try {
      return { ok: true, value: await withEpochLinks(group, epoch => this.fetchLink(taskId, epoch), () => open(group)) };
    }
    catch (error) {
      if (error instanceof E2eeError)
        return { ok: false, error };
      throw error;
    }
  }

  private openField<T>(taskId: string, frameType: string, frame: { data: Record<string, unknown> }, field: string): Promise<Opened<T>> {
    return this.openValue(taskId, group => group.openFrame<{ data: Record<string, T> }>(this.engine, frameType, frame).data[field]!);
  }

  /** Catches up when still a member, so content of newer epochs opens. */
  private async catchUp(taskId: string): Promise<void> {
    if (this.requireGroup(taskId).isMember)
      await this.sync(taskId);
  }

  private async readThread(taskId: string, threadId: string, after: number, limit: number): Promise<ThreadPage> {
    return this.api.get<ThreadPage>(`/tasks/${encodeURIComponent(taskId)}?thread=${encodeURIComponent(threadId)}&after=${after}&limit=${limit}`);
  }

  /** Reads a thread's whole transcript and opens each sealed field on its own. */
  async openTranscript(taskId: string, threadId: string): Promise<OpenedMessage[]> {
    await this.catchUp(taskId);
    const opened: OpenedMessage[] = [];
    for (let after = 0; ;) {
      const page = await this.readThread(taskId, threadId, after, TRANSCRIPT_PAGE);
      for (const row of page.messages) {
        const message: OpenedMessage = {
          seq: row.seq,
          kind: row.kind,
          role: row.role,
          tool: row.tool,
          toolUseId: row.toolUseId,
          parentToolUseId: row.parentToolUseId,
          createdAt: row.createdAt,
        };
        for (const field of ["content", "input", "output"] as const) {
          if (row[field] == null)
            continue;
          const frame = { type: "thread_message", taskId, threadId, data: { seq: row.seq, kind: row.kind, [field]: row[field] } };
          message[field] = await this.openField<never>(taskId, "thread_message", frame, field);
        }
        opened.push(message);
      }
      if (page.messages.length < TRANSCRIPT_PAGE)
        break;
      after = page.messages.at(-1)!.seq;
    }
    await this.persist();
    return opened;
  }

  /** Reads a thread's run and opens its `result` and `error` (their AAD binds the run's `outboxId`); `null` before any result. */
  async openResult(taskId: string, threadId: string): Promise<OpenedResult | null> {
    await this.catchUp(taskId);
    const { run } = await this.readThread(taskId, threadId, 0, 1);
    if (!run)
      return null;
    const opened: OpenedResult = { status: run.status, outboxId: run.outboxId, failureReason: run.failureReason, encryptionError: run.encryptionError };
    for (const field of ["result", "error"] as const) {
      if (run[field] == null)
        continue;
      const frame = { type: "thread_result", taskId, threadId, outboxId: run.outboxId, data: { [field]: run[field] } };
      opened[field] = await this.openField<string>(taskId, "thread_result", frame, field);
    }
    await this.persist();
    return opened;
  }

  /** Lists a task's attachment descriptors, optionally of one thread. */
  listAttachments(taskId: string, threadId?: string): Promise<TaskAttachment[]> {
    const query = threadId !== undefined ? `?thread=${encodeURIComponent(threadId)}` : "";
    return this.api.get<TaskAttachment[]>(`/tasks/${encodeURIComponent(taskId)}/attachments${query}`);
  }

  /** Downloads an attachment's stored bytes (a file envelope); open an output file with `openOutputFile`. */
  downloadAttachment(taskId: string, attachmentId: string): Promise<Uint8Array> {
    return this.api.getBytes(`/tasks/${encodeURIComponent(taskId)}/attachments/${encodeURIComponent(attachmentId)}`);
  }

  /**
   * Opens a runner output file: its sealed name (bound to the envelope's
   * `sha256`) and the file envelope `bytes`, which must match that `sha256`.
   */
  async openOutputFile(file: OutputFileDescriptor, bytes: Uint8Array): Promise<{ name: Opened<string>; content: Opened<Uint8Array> }> {
    await this.catchUp(file.taskId);
    const frame = { type: "thread_result", taskId: file.taskId, threadId: file.threadId, data: { attachments: [{ name: file.name, sha256: file.sha256 }] } };
    const name = await this.openValue(file.taskId, group =>
      group.openFrame<{ data: { attachments: Array<{ name: string }> } }>(this.engine, "thread_result", frame).data.attachments[0]!.name);
    const content: Opened<Uint8Array> = await sha256Hex(bytes) !== file.sha256
      ? { ok: false, error: new E2eeError({ code: "malformed", reason: "sha256 mismatch" }) }
      : await this.openValue(file.taskId, group => group.open(bytes, fileLocation(file.taskId)));
    await this.persist();
    return { name, content };
  }
}
