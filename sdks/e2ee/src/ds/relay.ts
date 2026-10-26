// The host as MLS Delivery Service (e2ee spec §3.1–§3.4, §3.6, §3.7;
// protocol §5.3).
//
// Per encrypted task (scope id = task id) the DS keeps the scope record, the
// group's members as tracked from accepted commits, the handshake log, the
// epoch links and the queued Welcomes. It checks framing only: it never holds
// a key that opens content, and it never logs or emits message bytes,
// Welcomes, links or key material.
import type { MessageInfo, SealedValue } from "@gino/e2ee";
import type { AckedFrame } from "./delivery";
import type { E2eeMemberRow, E2eePartyKind, E2eeScopeRow } from "./repo";
import type { E2eeLogEntry, E2eeResponseData } from "./schemas";
import { buildLocation, decodeB64url, encodeB64url, envelopeHeader, groupId, inspectMessage, sealDrop as sealDropEnvelope, taskContentFieldMap, toSealedValue, welcomeRecipients } from "@gino/e2ee";
import { sameBytes, toHex } from "./bytes";
import { ackWelcomeFrame, deliverLog, deliverWelcome, E2EE_LOG_PAGE_LIMIT, logEntryData } from "./delivery";
import { CLIENT_PARTY_PREFIX, E2eeDirectory } from "./directory";
import { E2eeDsError, RelayNotFoundError } from "./errors";
import { E2eeRequestData } from "./schemas";

/** The only scope profile: gino task content. */
export const E2EE_PROFILE_ID = "gino.task-content.v1";

/** The location template of `message.data.text`, the field a drop seals. */
const MESSAGE_TEXT_LOCATION = taskContentFieldMap.frames.message?.fields.find(f => f.path === "data.text")?.aad ?? "";

/** An agent's `e2ee_request` frame: `taskId` and `reqId` route the live-only answer. */
export interface E2eeRequestFrame {
  taskId?: string | null | undefined;
  reqId?: string | null | undefined;
  data?: unknown;
}

/** An epoch-link record is exactly this long (e2ee spec §5.6). */
const EPOCH_LINK_LENGTH = 124;
const MLS10 = 1;
const WIRE_FORMAT_PRIVATE_MESSAGE = 2;
const CONTENT_TYPE_APPLICATION = 1;

/** Scope registration by the group creator (e2ee spec §3.6, §2.8). */
export interface E2eeScopeRegistration {
  /** Must be `gino.task-content.v1`. */
  profile_id: string;
  /** base64url of `groupId(profile_id, taskId)`. */
  group_id: string;
  /** The epoch-0 drop public key, base64url (32 bytes). */
  drop_public_key: string;
  /** The creator's party id: an enrolled client (`client:<clientId>`); it holds leaf 0. */
  creator: string;
}

/** One leaf of a scope's group as tracked from the log. */
export interface E2eeScopeMember {
  leaf_index: number;
  party_id: string;
  kind: E2eePartyKind;
}

/** A scope record with its members. Binary values are base64url. */
export interface E2eeScopeView {
  task_id: string;
  profile_id: string;
  group_id: string;
  /** The current epoch. */
  epoch: number;
  /** The drop public key of the current epoch. */
  drop_public_key: string;
  created_at: number;
  members: E2eeScopeMember[];
}

/** A key-history entry submitted with a commit (e2ee spec §5.7). */
export interface E2eeKeyHistorySubmission {
  kind: "key_history" | "key_history_sealed";
  /** base64url. */
  message: string;
}

/** A commit unit submitted by a client party (e2ee spec §3.2). Binary values are base64url. */
export interface E2eeCommitSubmission {
  party_id: string;
  /** The commit, an `MLSMessage` PublicMessage. */
  commit: string;
  /** The drop public key of the new epoch (32 bytes). */
  drop_public_key: string;
  /** The Welcome; required iff the commit adds members. */
  welcome?: string | undefined;
  /** The epoch-link record of the new epoch. */
  epoch_link?: string | undefined;
  key_history?: E2eeKeyHistorySubmission[] | undefined;
}

/** A proposal submitted by a member (an `MLSMessage` PublicMessage, base64url). */
export interface E2eeProposalSubmission {
  party_id: string;
  proposal: string;
}

/** An accepted log write: its `seq` and the epoch after it. */
export interface E2eeAccepted {
  seq: number;
  epoch: number;
}

/** A page of a scope's log, in `seq` order, with the current epoch. */
export interface E2eeLogPageView {
  entries: E2eeLogEntry[];
  /** True when entries past the page exist; read again after the last `seq`. */
  more: boolean;
  epoch: number;
}

/** Where a log read starts: after a `seq`, or at the first entry of an epoch. */
export type E2eeLogCursor = { afterSeq: number } | { fromEpoch: number };

/** A queued Welcome of a party, with the `seq` of its commit. */
export interface E2eeWelcomeView {
  id: number;
  task_id: string;
  seq: number;
  /** base64url. */
  welcome: string;
}

interface CommitInput {
  commit: string;
  drop_public_key: string;
  welcome?: string | undefined;
  epoch_link?: string | undefined;
  key_history?: E2eeKeyHistorySubmission[] | undefined;
}

function malformed(message: string): E2eeDsError {
  return new E2eeDsError("malformed", message);
}

function notMember(message: string): E2eeDsError {
  return new E2eeDsError("not_member", message);
}

function decode(text: string, field: string): Uint8Array {
  try {
    return decodeB64url(text);
  }
  catch {
    throw malformed(`${field} is not base64url`);
  }
}

function partyKind(partyId: string): E2eePartyKind {
  return partyId.startsWith(CLIENT_PARTY_PREFIX) ? "client" : "agent";
}

/**
 * The cleartext framing of an `MLSMessage` PrivateMessage (RFC 9420 §6):
 * version, wire format, the group id vector, the epoch and the content type.
 * `null` when the bytes do not start like one.
 */
function privateMessageFraming(bytes: Uint8Array): { groupId: Uint8Array; epoch: number; contentType: number } | null {
  if (bytes.length < 5) {
    return null;
  }
  const version = (bytes[0]! << 8) | bytes[1]!;
  const wireFormat = (bytes[2]! << 8) | bytes[3]!;
  if (version !== MLS10 || wireFormat !== WIRE_FORMAT_PRIVATE_MESSAGE) {
    return null;
  }
  // RFC 9420 §2.1.2 variable-length vector: the top two bits give the length of the length.
  let at = 4;
  const prefix = bytes[at]! >> 6;
  if (prefix === 3) {
    return null;
  }
  const width = 1 << prefix;
  if (at + width > bytes.length) {
    return null;
  }
  let length = bytes[at]! & 0x3F;
  for (let i = 1; i < width; i++) {
    length = length * 256 + bytes[at + i]!;
  }
  at += width;
  if (at + length + 9 > bytes.length) {
    return null;
  }
  const group = bytes.subarray(at, at + length);
  at += length;
  let epoch = 0;
  for (let i = 0; i < 8; i++) {
    epoch = epoch * 256 + bytes[at + i]!;
  }
  if (!Number.isSafeInteger(epoch)) {
    return null;
  }
  return { groupId: group, epoch, contentType: bytes[at + 8]! };
}

/**
 * The key directory (`E2eeDirectory`) plus the MLS Delivery Service of the
 * encrypted tasks.
 *
 * Scopes: a task becomes encrypted when its creator registers the scope
 * (`registerScope`); it stays encrypted. Commits from clients
 * (`submitCommit`) and runners (`e2ee_request` op `commit`) go through the
 * same acceptance checks (e2ee spec §3.2); the first valid commit per epoch
 * wins. Every agent party holding a leaf receives the group's records as
 * durable `e2ee_welcome` / `e2ee_log` frames. Rejections throw `E2eeDsError`
 * (DS code + HTTP status); an unknown task or scope throws `RelayNotFoundError`.
 */
export class E2eeRelay extends E2eeDirectory {
  private scopeView(scope: E2eeScopeRow): E2eeScopeView {
    return {
      task_id: scope.taskId,
      profile_id: scope.profileId,
      group_id: encodeB64url(scope.groupId),
      epoch: scope.epoch,
      drop_public_key: encodeB64url(scope.dropPublicKey),
      created_at: scope.createdAt,
      members: this.repo.listMembers(scope.taskId).map(m => ({ leaf_index: m.leafIndex, party_id: m.partyId, kind: partyKind(m.partyId) })),
    };
  }

  private requireScope(taskId: string): E2eeScopeRow {
    this.ready();
    const scope = this.repo.getScope(taskId);
    if (!scope) {
      throw new RelayNotFoundError("e2ee scope", taskId);
    }
    return scope;
  }

  private requireMember(taskId: string, partyId: string): void {
    if (!this.repo.isMember(taskId, partyId)) {
      throw notMember("the party is not a member of the group");
    }
  }

  /** Inspect a PublicMessage of the scope's group with the expected content type. */
  private inspectFor(scope: E2eeScopeRow, bytes: Uint8Array, contentType: "commit" | "proposal"): MessageInfo {
    let info: MessageInfo;
    try {
      info = inspectMessage(bytes);
    }
    catch {
      throw malformed(`not a ${contentType} PublicMessage`);
    }
    if (info.contentType !== contentType) {
      throw malformed(`expected a ${contentType}, got a ${info.contentType}`);
    }
    if (!sameBytes(info.groupId, scope.groupId)) {
      throw malformed("the group id is not the scope's");
    }
    return info;
  }

  /** The message's epoch is current and its sender leaf is the submitter's (e2ee spec §3.2 checks 3 and 5). */
  private checkSender(scope: E2eeScopeRow, members: E2eeMemberRow[], info: MessageInfo, partyId: string): void {
    if (info.epoch !== scope.epoch) {
      throw new E2eeDsError("epoch_conflict", "the message is not for the current epoch", scope.epoch);
    }
    if (!members.some(m => m.partyId === partyId)) {
      throw notMember("the submitter is not a member of the group");
    }
    if (members.find(m => m.leafIndex === info.senderLeaf)?.partyId !== partyId) {
      throw notMember("the sender leaf is not the submitter's");
    }
  }

  /** Epoch-link framing (e2ee spec §3.4): 124 bytes, header type `epoch_link`, header epoch = the key. */
  private checkLink(bytes: Uint8Array, epoch: number): Uint8Array {
    if (bytes.length !== EPOCH_LINK_LENGTH) {
      throw malformed("an epoch link is 124 bytes");
    }
    let header: ReturnType<typeof envelopeHeader>;
    try {
      header = envelopeHeader(bytes);
    }
    catch {
      throw malformed("bad epoch link header");
    }
    if (header.type !== "epoch_link" || header.epoch !== epoch) {
      throw malformed(`not an epoch link for epoch ${epoch}`);
    }
    return bytes;
  }

  /** Key-history framing (e2ee spec §3.1) for an entry sent in `epoch`. */
  private checkKeyHistory(scope: E2eeScopeRow, entry: E2eeKeyHistorySubmission, epoch: number): Uint8Array {
    const bytes = decode(entry.message, "key_history.message");
    if (entry.kind === "key_history_sealed") {
      let header: ReturnType<typeof envelopeHeader>;
      try {
        header = envelopeHeader(bytes);
      }
      catch {
        throw malformed("bad key-history sealed envelope header");
      }
      if (header.type !== "key_history_sealed" || header.epoch !== epoch) {
        throw malformed(`not a key-history sealed envelope for epoch ${epoch}`);
      }
      return bytes;
    }
    const framing = privateMessageFraming(bytes);
    if (!framing || framing.contentType !== CONTENT_TYPE_APPLICATION) {
      throw malformed("key_history is not an application PrivateMessage");
    }
    if (!sameBytes(framing.groupId, scope.groupId) || framing.epoch !== epoch) {
      throw malformed(`key_history is not for this group at epoch ${epoch}`);
    }
    return bytes;
  }

  /** Enqueue the entries each agent member has not been sent yet. */
  private deliverToMembers(taskId: string): void {
    const agents = new Set(this.repo.listMembers(taskId).map(m => m.partyId).filter(p => partyKind(p) === "agent"));
    for (const agentId of agents) {
      deliverLog(this.deps, taskId, agentId);
    }
  }

  /** Commit acceptance (e2ee spec §3.2), shared by clients and runners; runners may not change membership. */
  private acceptCommit(taskId: string, partyId: string, input: CommitInput, runner: boolean): E2eeAccepted {
    const scope = this.requireScope(taskId);
    const commit = decode(input.commit, "commit");
    const info = this.inspectFor(scope, commit, "commit");
    if (info.proposalRefs.length > 0) {
      throw malformed("commits must carry their proposals by value");
    }
    const members = this.repo.listMembers(taskId);
    this.checkSender(scope, members, info, partyId);
    const dropPublicKey = decode(input.drop_public_key, "drop_public_key");
    if (dropPublicKey.length !== 32) {
      throw malformed("drop_public_key is 32 bytes");
    }
    if (runner && (info.adds.length > 0 || info.removes.length > 0)) {
      throw malformed("runners do not commit membership changes");
    }

    let welcome: Uint8Array | undefined;
    if (info.adds.length === 0) {
      if (input.welcome !== undefined) {
        throw malformed("a welcome is only sent with a commit that adds members");
      }
    }
    else {
      if (input.welcome === undefined) {
        throw malformed("a commit that adds members needs a welcome");
      }
      welcome = decode(input.welcome, "welcome");
      let recipients: Uint8Array[];
      try {
        recipients = welcomeRecipients(welcome);
      }
      catch {
        throw malformed("welcome is not a Welcome");
      }
      const added = new Set(info.adds.map(toHex));
      const named = new Set(recipients.map(toHex));
      if (added.size !== named.size || [...added].some(ref => !named.has(ref))) {
        throw malformed("the welcome's recipients are not the commit's adds");
      }
    }
    const addedParties = info.adds.map((ref) => {
      const party = this.repo.partyOfKeyPackageRef(toHex(ref));
      if (!party) {
        throw malformed("an added KeyPackage was not handed out by this host");
      }
      return party;
    });

    const epoch = scope.epoch + 1;
    const epochLink = input.epoch_link === undefined ? undefined : this.checkLink(decode(input.epoch_link, "epoch_link"), epoch);
    const keyHistory = (input.key_history ?? []).map(entry => ({ kind: entry.kind, bytes: this.checkKeyHistory(scope, entry, epoch) }));

    const occupied = new Set(members.map(m => m.leafIndex));
    const removeLeaves = [...new Set(info.removes)];
    for (const leaf of removeLeaves) {
      if (!occupied.delete(leaf)) {
        throw malformed(`leaf ${leaf} is blank`);
      }
    }
    // New members take the leftmost blank leaves, then extend the tree (RFC 9420 §12.1.1).
    let next = 0;
    const add = addedParties.map((addedParty) => {
      while (occupied.has(next)) {
        next += 1;
      }
      occupied.add(next);
      return { leafIndex: next, partyId: addedParty };
    });
    const welcomeParties = [...new Set(addedParties)];

    const now = this.deps.clock();
    const result = this.repo.acceptCommit({
      taskId,
      expectedEpoch: scope.epoch,
      bytes: commit,
      submitterPartyId: partyId,
      dropPublicKey,
      ...(epochLink ? { epochLink } : {}),
      ...(keyHistory.length > 0 ? { keyHistory } : {}),
      ...(welcome ? { welcomes: welcomeParties.map(p => ({ partyId: p, bytes: welcome })) } : {}),
      ...(removeLeaves.length > 0 ? { removeLeaves } : {}),
      ...(add.length > 0 ? { add } : {}),
      acceptedAt: now,
    });
    if (!result.ok) {
      if (result.code === "no_scope") {
        throw new RelayNotFoundError("e2ee scope", taskId);
      }
      throw new E2eeDsError("epoch_conflict", "the message is not for the current epoch", result.epoch);
    }

    const removedLeaves = new Set(removeLeaves);
    const removed = [...new Set(members.filter(m => removedLeaves.has(m.leafIndex)).map(m => m.partyId))]
      .filter(p => !this.repo.isMember(taskId, p));
    for (const removedParty of removed) {
      this.repo.dropUnackedWelcomes(taskId, removedParty);
      if (partyKind(removedParty) === "agent") {
        // The removed runner learns of its removal from the commit, and receives nothing after it.
        deliverLog(this.deps, taskId, removedParty, result.seq);
      }
    }
    if (welcome) {
      for (const joiner of welcomeParties.filter(p => partyKind(p) === "agent")) {
        deliverWelcome(this.deps, taskId, joiner, result.seq, welcome);
      }
    }
    this.deliverToMembers(taskId);

    this.deps.logger.info({ taskId, seq: result.seq, epoch: result.epoch, submitter: partyId, added: welcomeParties, removed }, "e2ee commit accepted");
    this.deps.emit("e2ee.commit", { taskId, seq: result.seq, epoch: result.epoch, submitter: partyId, added: welcomeParties, removed });
    return { seq: result.seq, epoch: result.epoch };
  }

  private rejected(taskId: string, partyId: string, err: unknown): void {
    if (err instanceof E2eeDsError) {
      this.deps.logger.debug({ taskId, partyId, code: err.dsCode, reason: err.message }, "e2ee DS request rejected");
    }
  }

  /** Run `fn`, logging a DS rejection (code and reason only) before rethrowing it. */
  private guarded<T>(taskId: string, partyId: string, fn: () => T): T {
    try {
      return fn();
    }
    catch (err) {
      this.rejected(taskId, partyId, err);
      throw err;
    }
  }

  /**
   * Register the scope of an encrypted task (e2ee spec §3.6): epoch 0, the
   * epoch-0 drop key, and the creator at leaf 0. A scope is never replaced.
   * @throws RelayNotFoundError unknown task or creator party; `E2eeDsError`
   * `malformed` (422) for a creator that is not a client, another profile, a
   * group id other than `groupId(profile_id, taskId)` or a drop key that is
   * not 32 bytes; `scope_exists` (409) when the task already has a scope.
   */
  registerScope(taskId: string, input: E2eeScopeRegistration): E2eeScopeView {
    this.ready();
    if (!this.deps.taskExists(taskId)) {
      throw new RelayNotFoundError("task", taskId);
    }
    const dropPublicKey = this.checkScope(taskId, input);
    const inserted = this.repo.insertScopeIfAbsent({
      taskId,
      profileId: input.profile_id,
      groupId: groupId(input.profile_id, taskId),
      dropPublicKey,
      creatorPartyId: input.creator,
      createdAt: this.deps.clock(),
    });
    if (!inserted) {
      throw new E2eeDsError("scope_exists", "the task already has a scope");
    }
    this.deps.logger.info({ taskId, creator: input.creator }, "e2ee scope registered");
    this.deps.emit("e2ee.scope_registered", { taskId, creator: input.creator });
    return this.scopeView(this.requireScope(taskId));
  }

  /**
   * The checks of `registerScope` other than the task's existence, for a task
   * id that is not stored yet. Returns the decoded drop public key.
   * @throws as `registerScope`.
   */
  checkScope(taskId: string, input: E2eeScopeRegistration): Uint8Array {
    this.ready();
    const creator = this.repo.getParty(input.creator);
    if (!creator) {
      throw new RelayNotFoundError("e2ee party", input.creator);
    }
    if (creator.kind !== "client") {
      throw malformed("the scope creator must be an enrolled client");
    }
    if (input.profile_id !== E2EE_PROFILE_ID) {
      throw malformed(`unknown profile_id; expected ${E2EE_PROFILE_ID}`);
    }
    if (!sameBytes(decode(input.group_id, "group_id"), groupId(input.profile_id, taskId))) {
      throw malformed("group_id is not the group id of this task");
    }
    const dropPublicKey = decode(input.drop_public_key, "drop_public_key");
    if (dropPublicKey.length !== 32) {
      throw malformed("drop_public_key is 32 bytes");
    }
    return dropPublicKey;
  }

  /** The scope of a task with its members, or `undefined` when the task is not encrypted. */
  scope(taskId: string): E2eeScopeView | undefined {
    this.ready();
    const scope = this.repo.getScope(taskId);
    return scope ? this.scopeView(scope) : undefined;
  }

  /** Whether the task is encrypted (has a scope); once true, always true. */
  isEncrypted(taskId: string): boolean {
    return this.repo.getScope(taskId) != null;
  }

  /** Whether the party holds a leaf of the task's group. */
  isMember(taskId: string, partyId: string): boolean {
    return this.repo.isMember(taskId, partyId);
  }

  /** The drop public key of the task's current epoch (base64url), or `undefined` when the task is not encrypted. */
  currentDropPublicKey(taskId: string): string | undefined {
    this.ready();
    const scope = this.repo.getScope(taskId);
    return scope ? encodeB64url(scope.dropPublicKey) : undefined;
  }

  /**
   * Seal `text` as a drop (e2ee spec §9) for the task's `message.data.text`:
   * to the current epoch's drop public key, at the field's location. Returns
   * `undefined` when the task is not encrypted. The plaintext is neither
   * stored nor logged.
   */
  sealDrop(taskId: string, text: string): SealedValue | undefined {
    this.ready();
    const scope = this.repo.getScope(taskId);
    if (!scope) {
      return undefined;
    }
    const location = buildLocation(MESSAGE_TEXT_LOCATION, { taskId });
    return toSealedValue(sealDropEnvelope(scope.dropPublicKey, scope.epoch, location, new TextEncoder().encode(text)));
  }

  /**
   * Accept a client's commit unit (e2ee spec §3.2): stored with its epoch
   * link and key-history entries, Welcomes queued per added party, the
   * membership updated and the records delivered to the agent members.
   * @throws RelayNotFoundError unknown scope; `E2eeDsError` `epoch_conflict`
   * (409, with the current epoch), `not_member` (403) or `malformed` (422).
   */
  submitCommit(taskId: string, input: E2eeCommitSubmission): E2eeAccepted {
    return this.guarded(taskId, input.party_id, () => this.acceptCommit(taskId, input.party_id, input, false));
  }

  /**
   * Append a proposal of a member at the current epoch (no epoch advance).
   * @throws as `submitCommit`.
   */
  submitProposal(taskId: string, input: E2eeProposalSubmission): E2eeAccepted {
    return this.guarded(taskId, input.party_id, () => {
      const scope = this.requireScope(taskId);
      const bytes = decode(input.proposal, "proposal");
      const info = this.inspectFor(scope, bytes, "proposal");
      this.checkSender(scope, this.repo.listMembers(taskId), info, input.party_id);
      const result = this.repo.appendEntry({ taskId, expectedEpoch: scope.epoch, kind: "proposal", bytes, submitterPartyId: input.party_id, acceptedAt: this.deps.clock() });
      if (!result.ok) {
        if (result.code === "no_scope") {
          throw new RelayNotFoundError("e2ee scope", taskId);
        }
        throw new E2eeDsError("epoch_conflict", "the message is not for the current epoch", result.epoch);
      }
      this.deliverToMembers(taskId);
      return { seq: result.seq, epoch: scope.epoch };
    });
  }

  /**
   * The epoch link stored for `epoch` (base64url), or `undefined`. Served to current members only.
   * @throws RelayNotFoundError unknown scope; `E2eeDsError` `not_member` (403).
   */
  epochLink(taskId: string, epoch: number, partyId: string): string | undefined {
    return this.guarded(taskId, partyId, () => {
      this.requireScope(taskId);
      this.requireMember(taskId, partyId);
      const link = this.repo.getEpochLink(taskId, epoch);
      return link ? encodeB64url(link) : undefined;
    });
  }

  /**
   * Store a missing epoch link (repair, e2ee spec §3.4, §7.4) from a current
   * member. The first link per epoch wins.
   * @throws RelayNotFoundError unknown scope; `E2eeDsError` `not_member` (403),
   * `malformed` (422: bad framing, or an epoch above the current one) or
   * `link_exists` (409, with the stored link).
   */
  putEpochLink(taskId: string, epoch: number, partyId: string, link: string): void {
    this.guarded(taskId, partyId, () => {
      const scope = this.requireScope(taskId);
      this.requireMember(taskId, partyId);
      if (!Number.isSafeInteger(epoch) || epoch < 1 || epoch > scope.epoch) {
        throw malformed(`no link can be stored for epoch ${epoch}`);
      }
      const put = this.repo.putEpochLinkIfAbsent(taskId, epoch, this.checkLink(decode(link, "link"), epoch));
      if (!put.inserted) {
        throw new E2eeDsError("link_exists", "a link is already stored for this epoch", undefined, encodeB64url(put.bytes));
      }
    });
  }

  /**
   * A page of the scope's log (at most `E2EE_LOG_PAGE_LIMIT` entries) after a
   * `seq` or from an epoch, with the current epoch. Served to current members only.
   * @throws RelayNotFoundError unknown scope; `E2eeDsError` `not_member` (403).
   */
  readLog(taskId: string, partyId: string, cursor: E2eeLogCursor): E2eeLogPageView {
    return this.guarded(taskId, partyId, () => {
      const scope = this.requireScope(taskId);
      this.requireMember(taskId, partyId);
      const page = "afterSeq" in cursor
        ? this.repo.readLog(taskId, cursor.afterSeq, E2EE_LOG_PAGE_LIMIT)
        : this.repo.readLogFromEpoch(taskId, cursor.fromEpoch, E2EE_LOG_PAGE_LIMIT);
      return { entries: page.entries.map(logEntryData), more: page.more, epoch: scope.epoch };
    });
  }

  /** The party's unacked Welcomes (only `taskId`'s when given), oldest first. */
  welcomes(partyId: string, taskId?: string): E2eeWelcomeView[] {
    this.ready();
    return this.repo.listUnackedWelcomes(partyId, taskId).map(w => ({ id: w.id, task_id: w.taskId, seq: w.seq, welcome: encodeB64url(w.bytes) }));
  }

  /**
   * Acknowledge one of the party's Welcomes; it is no longer listed.
   * @throws RelayNotFoundError when the party has no such Welcome.
   */
  ackWelcome(partyId: string, id: number): void {
    if (!this.repo.ackWelcome(partyId, id, this.deps.clock())) {
      throw new RelayNotFoundError("e2ee welcome", String(id));
    }
  }

  /**
   * Hook for an agent's `msg_ack` of a durable frame: an acked `e2ee_welcome`
   * acks its Welcome. Any other frame is ignored.
   */
  onMessageAck(agentId: string, frame: AckedFrame): void {
    ackWelcomeFrame(this.deps, agentId, frame);
  }

  private runAgentRequest(agentId: string, taskId: string, request: E2eeRequestData): E2eeResponseData {
    switch (request.op) {
      case "log":
        return { ok: true, ...this.readLog(taskId, agentId, { afterSeq: request.after_seq }) };
      case "log_from_epoch":
        return { ok: true, ...this.readLog(taskId, agentId, { fromEpoch: request.epoch }) };
      case "link": {
        const link = this.epochLink(taskId, request.epoch, agentId);
        return { ok: true, epoch: this.requireScope(taskId).epoch, ...(link !== undefined ? { link } : {}) };
      }
      case "put_link":
        this.putEpochLink(taskId, request.epoch, agentId, request.link);
        return { ok: true, epoch: this.requireScope(taskId).epoch };
      case "commit":
        return { ok: true, ...this.guarded(taskId, agentId, () => this.acceptCommit(taskId, agentId, request, true)) };
    }
  }

  private failure(taskId: string, err: E2eeDsError): E2eeResponseData {
    const epoch = err.epoch ?? this.repo.getScope(taskId)?.epoch;
    return {
      ok: false,
      error: { code: err.dsCode, message: err.message },
      ...(epoch !== undefined ? { epoch } : {}),
      ...(err.link !== undefined ? { link: err.link } : {}),
    };
  }

  /**
   * Answer an agent's live-only `e2ee_request` with the live-only
   * `e2ee_response` (same `taskId` + `reqId`). An unknown scope answers
   * `not_member`; a schema-invalid request `malformed`; a frame without
   * `taskId` or `reqId` is dropped.
   */
  handleAgentRequest(agentId: string, frame: E2eeRequestFrame): void {
    const { taskId, reqId } = frame;
    if (taskId == null || reqId == null) {
      return;
    }
    let data: E2eeResponseData;
    const parsed = E2eeRequestData.safeParse(frame.data);
    if (!parsed.success) {
      data = this.failure(taskId, malformed("invalid e2ee_request"));
    }
    else {
      try {
        data = this.runAgentRequest(agentId, taskId, parsed.data);
      }
      catch (err) {
        if (err instanceof E2eeDsError) {
          data = this.failure(taskId, err);
        }
        else if (err instanceof RelayNotFoundError) {
          data = this.failure(taskId, notMember("unknown scope"));
        }
        else {
          throw err;
        }
      }
    }
    this.deps.agents.send(agentId, { type: "e2ee_response", taskId, reqId, data });
  }
}
