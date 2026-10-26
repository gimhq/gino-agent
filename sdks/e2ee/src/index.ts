import initWasm, * as wasm from "../wasm/gino_e2ee.js";
import { call, E2eeError } from "./errors";

export * from "./client";
export type { E2eeErrorCode, EncryptionErrorCode } from "./errors";
export { E2eeError } from "./errors";
export * from "./field-map.generated";

/** Where the wasm module comes from: a URL to fetch, its bytes or a compiled module. */
export type WasmSource = URL | string | Response | BufferSource | WebAssembly.Module;

let ready: Promise<void> | undefined;

/**
 * Loads the wasm module once. Without `source` it fetches
 * `wasm/gino_e2ee_bg.wasm` next to the package (Bun and browsers); pass the
 * bytes or a compiled module where `fetch` cannot read the package files.
 */
export function init(source?: WasmSource): Promise<void> {
  ready ??= initWasm({ module_or_path: source ?? new URL("../wasm/gino_e2ee_bg.wasm", import.meta.url) })
    .then(() => undefined);
  return ready;
}

/** Loads the wasm module synchronously from its bytes or a compiled module. */
export function initSync(module: BufferSource | WebAssembly.Module): void {
  wasm.initSync({ module });
  ready ??= Promise.resolve();
}

// ---------------------------------------------------------------------------
// Encoding, ids and locations

/** The secrets of one epoch: the content key `k_e` and the drop seed `d_e`. */
export interface EpochSecrets {
  k: Uint8Array;
  d: Uint8Array;
}

/** A history policy (spec §2.4, §7.1). */
export type HistoryPolicy = "full" | "from_join" | { from_epoch: number };

export type EnvelopeType = "content" | "file" | "drop" | "epoch_link" | "key_history" | "key_history_sealed";

/** The sealed wire form of a mapped value (spec §12.4). */
export interface SealedValue {
  e2ee: string;
}

export function splitSecrets(bytes: Uint8Array): EpochSecrets {
  return { k: bytes.slice(0, 32), d: bytes.slice(32, 64) };
}

/** base64url without padding. */
export function encodeB64url(bytes: Uint8Array): string {
  return wasm.encodeB64url(bytes);
}

/** Strict base64url without padding (spec §5.1); anything else is `malformed`. */
export function decodeB64url(text: string): Uint8Array {
  return call(() => wasm.decodeB64url(text));
}

/** The 32-byte group id of a profile and scope (spec §2.3). */
export function groupId(profile: string, scope: string): Uint8Array {
  return call(() => wasm.groupId(profile, scope));
}

/** The canonical fingerprint of an Ed25519 public key (spec §3.5). */
export function fingerprint(publicKey: Uint8Array): string {
  return call(() => wasm.fingerprint(publicKey));
}

/** The display form of a fingerprint: 16 groups of 4. */
export function fingerprintDisplay(publicKey: Uint8Array): string {
  return call(() => wasm.fingerprintDisplay(publicKey));
}

/** Resolves an AAD template against a frame (spec §12.3). */
export function buildLocation(template: string, frame: unknown, element?: number): string {
  return call(() => wasm.buildLocation(template, JSON.stringify(frame), element));
}

/** Checks a location string (spec §6). */
export function parseLocation(text: string): string {
  return call(() => wasm.parseLocation(text));
}

/** The `extension_data` of a history policy. */
export function encodeHistoryPolicy(policy: HistoryPolicy): Uint8Array {
  return call(() => wasm.encodeHistoryPolicy(JSON.stringify(policy)));
}

/** The history policy of an `extension_data`. */
export function decodeHistoryPolicy(data: Uint8Array): HistoryPolicy {
  return JSON.parse(call(() => wasm.decodeHistoryPolicy(data))) as HistoryPolicy;
}

/** The type and epoch of an envelope header (spec §5.2). */
export function envelopeHeader(envelope: Uint8Array): { type: EnvelopeType; epoch: number } {
  return JSON.parse(call(() => wasm.envelopeHeader(envelope))) as { type: EnvelopeType; epoch: number };
}

export function toSealedValue(envelope: Uint8Array): SealedValue {
  return { e2ee: encodeB64url(envelope) };
}

/** The envelope of a mapped value: not sealed is `plaintext_rejected`, a bad sealed form `malformed`. */
export function fromSealedValue(value: unknown): Uint8Array {
  return call(() => wasm.fromSealedValue(JSON.stringify(value) ?? "null"));
}

/** Decodes an opened `text` or `json` plaintext (spec §12.4). */
export function decodePlaintext(plaintext: Uint8Array, kind: "text" | "json"): unknown {
  return JSON.parse(call(() => wasm.decodePlaintext(plaintext, kind)));
}

// ---------------------------------------------------------------------------
// Envelopes

/** Seals a content envelope under `k_e` of `epoch` (spec §5.3). */
export function sealContent(k: Uint8Array, epoch: number, location: string, plaintext: Uint8Array): Uint8Array {
  return call(() => wasm.sealContent(k, BigInt(epoch), location, plaintext));
}

export function openContent(k: Uint8Array, envelope: Uint8Array, location: string): Uint8Array {
  return call(() => wasm.openContent(k, envelope, location));
}

/** A file envelope with its attachment descriptor `sha256` and `size` (spec §5.4). */
export interface SealedFile {
  envelope: Uint8Array;
  sha256: string;
  size: number;
}

export function fileDigest(envelope: Uint8Array): SealedFile {
  return { envelope, sha256: wasm.fileSha256(envelope), size: envelope.length };
}

export function sealFile(k: Uint8Array, epoch: number, location: string, bytes: Uint8Array): SealedFile {
  return fileDigest(call(() => wasm.sealFile(k, BigInt(epoch), location, bytes)));
}

export function openFile(k: Uint8Array, envelope: Uint8Array, location: string): Uint8Array {
  return call(() => wasm.openFile(k, envelope, location));
}

/** The drop key pair of a drop seed `d_e` (spec §4.4). */
export function deriveDropKeyPair(d: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array } {
  return call(() => {
    const pair = wasm.DropKeyPair.derive(d);
    try {
      return { publicKey: pair.publicKey, privateKey: pair.privateKey };
    }
    finally {
      pair.free();
    }
  });
}

/** Seals a drop envelope to the drop public key of `epoch` (spec §5.5). */
export function sealDrop(publicKey: Uint8Array, epoch: number, location: string, plaintext: Uint8Array): Uint8Array {
  return call(() => wasm.sealDrop(publicKey, BigInt(epoch), location, plaintext));
}

/** Opens a drop envelope with the drop seed of its epoch. The plaintext is untrusted input. */
export function openDrop(d: Uint8Array, envelope: Uint8Array, location: string): Uint8Array {
  return call(() => wasm.openDrop(d, envelope, location));
}

/** Throws `drop_key_mismatch` if a logged drop public key differs from the one derived from `d_e`. */
export function verifyDropPublicKey(d: Uint8Array, epoch: number, publicKey: Uint8Array): void {
  call(() => wasm.verifyDropPublicKey(d, BigInt(epoch), publicKey));
}

/** Seals the epoch link carrying `E_epoch` under `k_next`, the content key of `epoch + 1` (spec §5.6). */
export function sealEpochLink(scope: string, epoch: number, secrets: EpochSecrets, kNext: Uint8Array): Uint8Array {
  return call(() => wasm.sealEpochLink(scope, BigInt(epoch), secrets.k, secrets.d, kNext));
}

/** Opens the epoch link stored for `epoch + 1` and returns `E_epoch`. */
export function openEpochLink(scope: string, epoch: number, kNext: Uint8Array, link: Uint8Array): EpochSecrets {
  return splitSecrets(call(() => wasm.openEpochLink(scope, BigInt(epoch), kNext, link)));
}

/** A key-history record sent in `epoch` (spec §5.7). */
export interface KeyHistory {
  epoch: number;
  entries: Array<{ epoch: number } & EpochSecrets>;
}

interface KeyHistoryJson {
  epoch: number;
  entries: Array<{ epoch: number; k: string; d: string }>;
}

function keyHistoryToJson(history: KeyHistory): string {
  const entries = history.entries.map(e => ({ epoch: e.epoch, k: encodeB64url(e.k), d: encodeB64url(e.d) }));
  return JSON.stringify({ epoch: history.epoch, entries });
}

function keyHistoryFromJson(text: string): KeyHistory {
  const json = JSON.parse(text) as KeyHistoryJson;
  const entries = json.entries.map(e => ({ epoch: e.epoch, k: decodeB64url(e.k), d: decodeB64url(e.d) }));
  return { epoch: json.epoch, entries };
}

/** The MLS application data of a key-history record. */
export function encodeKeyHistory(history: KeyHistory): Uint8Array {
  return call(() => wasm.encodeKeyHistory(keyHistoryToJson(history)));
}

export function decodeKeyHistory(payload: Uint8Array): KeyHistory {
  return keyHistoryFromJson(call(() => wasm.decodeKeyHistory(payload)));
}

/** Seals a key-history record to the leaf at `leafIndex` with its encryption key. */
export function sealKeyHistoryToLeaf(history: KeyHistory, scope: string, leafIndex: number, leafPublicKey: Uint8Array): Uint8Array {
  return call(() => wasm.sealKeyHistoryToLeaf(keyHistoryToJson(history), scope, leafIndex, leafPublicKey));
}

/** Opens a key-history envelope sealed to the leaf at `leafIndex`. */
export function openKeyHistorySealed(scope: string, leafIndex: number, leafPrivateKey: Uint8Array, envelope: Uint8Array): KeyHistory {
  return keyHistoryFromJson(call(() => wasm.openKeyHistorySealed(scope, leafIndex, leafPrivateKey, envelope)));
}

// ---------------------------------------------------------------------------
// History and field maps

/** Fetches the epoch link stored for an epoch from the DS; `null` if absent. */
export type FetchLink = (epoch: number) => Promise<Uint8Array | null> | Uint8Array | null;

interface LinkTarget {
  addLink: (epoch: number, link: Uint8Array) => void;
  neededLink: (epoch: number) => number | undefined;
}

/**
 * Runs `operation` on `target`, fetching each epoch link the backward walk
 * misses (`history_unavailable`) and retrying, until it succeeds or a link is
 * absent.
 */
export async function withEpochLinks<T>(target: LinkTarget, fetchLink: FetchLink, operation: () => T): Promise<T> {
  const fetched = new Set<number>();
  for (;;) {
    try {
      return operation();
    }
    catch (error) {
      if (!(error instanceof E2eeError) || error.code !== "history_unavailable" || error.epoch === undefined)
        throw error;
      const needed = target.neededLink(error.epoch);
      if (needed === undefined || fetched.has(needed))
        throw error;
      fetched.add(needed);
      const link = await fetchLink(needed);
      if (link === null)
        throw error;
      target.addLink(needed, link);
    }
  }
}

function optionalNumber(value: bigint | undefined): number | undefined {
  return value === undefined ? undefined : Number(value);
}

/**
 * A field map's engine (spec §12): seals and opens whole frames. The
 * generated maps are the plain data of this package's `*FieldMap` exports.
 */
export class FieldMapEngine {
  /** @internal */
  readonly inner: wasm.FieldMap;

  /** @internal */
  constructor(inner: wasm.FieldMap) {
    this.inner = inner;
  }

  /** The engine of a generated profile map, e.g. `gino.task-content.v1`. */
  static forProfile(profile: string): FieldMapEngine {
    const inner = wasm.FieldMap.forProfile(profile);
    if (inner === undefined)
      throw new E2eeError({ code: "malformed" });
    return new FieldMapEngine(inner);
  }

  get profile(): string {
    return this.inner.profile;
  }

  /** Seals every mapped value of `frame` under `k_e` of `epoch`. */
  sealFrame<T = unknown>(frameType: string, frame: unknown, epoch: number, k: Uint8Array): T {
    return JSON.parse(call(() => this.inner.sealFrame(frameType, JSON.stringify(frame), BigInt(epoch), k))) as T;
  }
}

/**
 * The epoch secrets of one scope over an in-memory key cache, with the
 * backward walk over the epoch links added with `addLink` (spec §7.3).
 */
export class History implements LinkTarget {
  private readonly inner: wasm.History;

  constructor(scope: string, epoch: number, secrets: EpochSecrets) {
    this.inner = call(() => new wasm.History(scope, BigInt(epoch), secrets.k, secrets.d));
  }

  get currentEpoch(): number {
    return Number(this.inner.currentEpoch);
  }

  /** Caches the secrets of an epoch below the current one. */
  cacheSecrets(epoch: number, secrets: EpochSecrets, verified: boolean): void {
    call(() => this.inner.cacheSecrets(BigInt(epoch), secrets.k, secrets.d, verified));
  }

  addLink(epoch: number, link: Uint8Array): void {
    this.inner.addLink(BigInt(epoch), link);
  }

  neededLink(epoch: number): number | undefined {
    return optionalNumber(call(() => this.inner.neededLink(BigInt(epoch))));
  }

  secrets(epoch: number): EpochSecrets {
    return splitSecrets(call(() => this.inner.secrets(BigInt(epoch))));
  }

  /** Opens a content, file or drop envelope at `location`. */
  open(envelope: Uint8Array, location: string): Uint8Array {
    return call(() => this.inner.open(envelope, location));
  }

  openFrame<T = unknown>(engine: FieldMapEngine, frameType: string, frame: unknown): T {
    return JSON.parse(call(() => this.inner.openFrame(engine.inner, frameType, JSON.stringify(frame)))) as T;
  }

  free(): void {
    this.inner.free();
  }
}

// ---------------------------------------------------------------------------
// Delivery Service inspection

/** The public facts of a valid KeyPackage (spec §3.5). */
export interface KeyPackageInfo {
  /** The KeyPackageRef (RFC 9420 §5.2). */
  ref: Uint8Array;
  /** The raw Ed25519 public key of the credential and leaf. */
  publicKey: Uint8Array;
  lastResort: boolean;
  /** Lifetime bounds, seconds since the Unix epoch. */
  notBefore: number;
  notAfter: number;
}

interface KeyPackageInfoJson {
  ref: string;
  public_key: string;
  last_resort: boolean;
  not_before: number;
  not_after: number;
}

/**
 * Validates an uploaded KeyPackage at `now` (seconds since the Unix epoch,
 * default the current time): signatures, suite `0x0001`, lifetime,
 * capabilities and credential. A wrong suite throws `unsupported_suite`,
 * anything else `malformed`.
 */
export function inspectKeyPackage(bytes: Uint8Array, now?: number): KeyPackageInfo {
  const time = BigInt(now ?? Math.floor(Date.now() / 1000));
  const json = JSON.parse(call(() => wasm.inspectKeyPackage(bytes, time))) as KeyPackageInfoJson;
  return {
    ref: decodeB64url(json.ref),
    publicKey: decodeB64url(json.public_key),
    lastResort: json.last_resort,
    notBefore: json.not_before,
    notAfter: json.not_after,
  };
}

/** The cleartext framing of a PublicMessage and the membership changes it carries (spec §3.2). */
export interface MessageInfo {
  groupId: Uint8Array;
  epoch: number;
  contentType: "commit" | "proposal" | "application";
  senderLeaf: number;
  /** The KeyPackageRef of each Add proposal carried by value, in order. */
  adds: Uint8Array[];
  /** The leaf index of each Remove proposal carried by value, in order. */
  removes: number[];
  /** The ProposalRefs of proposals a commit carries by reference. */
  proposalRefs: Uint8Array[];
  updatesPath: boolean;
}

interface MessageInfoJson {
  group_id: string;
  epoch: number;
  content_type: MessageInfo["contentType"];
  sender_leaf: number;
  adds: string[];
  removes: number[];
  proposal_refs: string[];
  updates_path: boolean;
}

/**
 * Inspects an `MLSMessage` PublicMessage without any key. Another wire
 * format or a non-member sender throws `malformed`. Membership is not
 * verified.
 */
export function inspectMessage(bytes: Uint8Array): MessageInfo {
  const json = JSON.parse(call(() => wasm.inspectMessage(bytes))) as MessageInfoJson;
  return {
    groupId: decodeB64url(json.group_id),
    epoch: json.epoch,
    contentType: json.content_type,
    senderLeaf: json.sender_leaf,
    adds: json.adds.map(decodeB64url),
    removes: json.removes,
    proposalRefs: json.proposal_refs.map(decodeB64url),
    updatesPath: json.updates_path,
  };
}

/** The `new_member` KeyPackageRefs of a Welcome, in order (spec §3.3); anything else throws `malformed`. */
export function welcomeRecipients(bytes: Uint8Array): Uint8Array[] {
  return call(() => wasm.welcomeRecipients(bytes)).map(decodeB64url);
}

// ---------------------------------------------------------------------------
// MLS

/** A party's Ed25519 identity (spec §2.2). The seed never leaves the party. */
export class Identity {
  /** @internal */
  readonly inner: wasm.Identity;

  private constructor(inner: wasm.Identity) {
    this.inner = inner;
  }

  static generate(): Identity {
    return new Identity(call(() => wasm.Identity.generate()));
  }

  static fromSeed(seed: Uint8Array): Identity {
    return new Identity(call(() => wasm.Identity.fromSeed(seed)));
  }

  get seed(): Uint8Array {
    return this.inner.seed;
  }

  /** The raw 32-byte Ed25519 public key. */
  get publicKey(): Uint8Array {
    return this.inner.publicKey;
  }

  free(): void {
    this.inner.free();
  }
}

/** A party's KeyPackage private keys, kept until a Welcome consumes them (spec §2.7). */
export class KeyPackageStore {
  /** @internal */
  readonly inner: wasm.KeyPackageStore;

  constructor(inner?: wasm.KeyPackageStore) {
    this.inner = inner ?? new wasm.KeyPackageStore();
  }

  /** Generates a KeyPackage (TLS-serialized `MLSMessage`) and keeps its private keys. */
  generate(identity: Identity, lastResort = false): Uint8Array {
    return call(() => this.inner.generate(identity.inner, lastResort));
  }

  /** The store as opaque bytes, stored encrypted at rest by the caller. */
  snapshot(): Uint8Array {
    return call(() => this.inner.snapshot());
  }

  static restore(snapshot: Uint8Array): KeyPackageStore {
    return new KeyPackageStore(call(() => wasm.KeyPackageStore.restore(snapshot)));
  }

  free(): void {
    this.inner.free();
  }
}

/** A commit submitted to the DS as one unit (spec §3.2). */
export interface CommitUnit {
  epoch: number;
  commit: Uint8Array;
  /** The drop public key of epoch `epoch + 1`. */
  dropPublicKey: Uint8Array;
  welcome: Uint8Array | null;
  epochLink: Uint8Array | null;
  keyHistory: Array<{ kind: "key_history" | "key_history_sealed"; bytes: Uint8Array }>;
}

export type LogEntryKind = "commit" | "proposal" | "key_history" | "key_history_sealed";

/** One entry of a scope's handshake log as served by the DS (spec §3.1). */
export interface LogEntry {
  seq: number;
  kind: LogEntryKind;
  epoch: number;
  bytes: Uint8Array;
  /** For a commit: the drop public key logged for epoch `epoch + 1`. */
  dropPublicKey?: Uint8Array | null;
}

/** The effect of one applied log entry. */
export type Applied
  = | { type: "replayed" }
    | { type: "commit"; epoch: number; selfRemoved: boolean }
    | { type: "proposal" }
    | { type: "key_history" }
    | { type: "skipped" };

interface CommitUnitJson {
  epoch: number;
  commit: string;
  drop_public_key: string;
  welcome: string | null;
  epoch_link: string | null;
  key_history: Array<{ kind: "key_history" | "key_history_sealed"; bytes: string }>;
}

function commitUnit(text: string): CommitUnit {
  const json = JSON.parse(text) as CommitUnitJson;
  return {
    epoch: json.epoch,
    commit: decodeB64url(json.commit),
    dropPublicKey: decodeB64url(json.drop_public_key),
    welcome: json.welcome === null ? null : decodeB64url(json.welcome),
    epochLink: json.epoch_link === null ? null : decodeB64url(json.epoch_link),
    keyHistory: json.key_history.map(r => ({ kind: r.kind, bytes: decodeB64url(r.bytes) })),
  };
}

/** Key history the committer of an Add attaches for the joiners (spec §7.5). */
export interface KeyHistoryOffer {
  /** The lowest epoch offered. */
  fromEpoch: number;
  /** One envelope per joiner leaf instead of one MLS message to the group. */
  sealed?: boolean;
}

/**
 * The MLS group of one scope (spec §2.8, §3, §7) with its key cache and the
 * epoch links added with `addLink`. Persist it with `snapshot()` after every
 * state-changing call.
 */
export class ScopeGroup implements LinkTarget {
  private readonly inner: wasm.ScopeGroup;

  private constructor(inner: wasm.ScopeGroup) {
    this.inner = inner;
  }

  /** Creates the group of `scope` at epoch 0 with `identity` as the only member. */
  static create(identity: Identity, profile: string, scope: string, policy: HistoryPolicy = "full"): ScopeGroup {
    return new ScopeGroup(call(() => wasm.ScopeGroup.create(identity.inner, profile, scope, JSON.stringify(policy))));
  }

  /** Joins from a Welcome delivered with the `seq` of its commit (spec §3.3). */
  static join(keyPackages: KeyPackageStore, profile: string, scope: string, welcome: Uint8Array, seq: number): ScopeGroup {
    return new ScopeGroup(call(() => wasm.ScopeGroup.join(keyPackages.inner, profile, scope, welcome, BigInt(seq))));
  }

  /** The group state and key cache as opaque bytes; they hold epoch secrets, so store them encrypted at rest. */
  snapshot(): Uint8Array {
    return call(() => this.inner.snapshot());
  }

  static restore(snapshot: Uint8Array): ScopeGroup {
    return new ScopeGroup(call(() => wasm.ScopeGroup.restore(snapshot)));
  }

  get scope(): string {
    return this.inner.scope;
  }

  get profile(): string {
    return this.inner.profile;
  }

  get groupId(): Uint8Array {
    return this.inner.groupId;
  }

  get epoch(): number {
    return Number(this.inner.epoch);
  }

  /** The `seq` of the last applied log entry. */
  get seq(): number {
    return Number(this.inner.seq);
  }

  get isMember(): boolean {
    return this.inner.isMember;
  }

  get hasPendingCommit(): boolean {
    return this.inner.hasPendingCommit;
  }

  policy(): HistoryPolicy {
    return JSON.parse(call(() => this.inner.policy())) as HistoryPolicy;
  }

  /** The members' Ed25519 public keys in leaf order. */
  members(): Uint8Array[] {
    return this.inner.members().map(decodeB64url);
  }

  /** The current epoch and its secrets `(k_e, d_e)`, for sealing. */
  current(): { epoch: number } & EpochSecrets {
    const secrets = splitSecrets(call(() => this.inner.currentSecrets()));
    return { epoch: this.epoch, ...secrets };
  }

  /** The drop public key of the current epoch. */
  dropPublicKey(): Uint8Array {
    return call(() => this.inner.dropPublicKey());
  }

  addLink(epoch: number, link: Uint8Array): void {
    this.inner.addLink(BigInt(epoch), link);
  }

  neededLink(epoch: number): number | undefined {
    return optionalNumber(call(() => this.inner.neededLink(BigInt(epoch))));
  }

  /** The secrets of `epoch`, from the cache or the backward walk. */
  secrets(epoch: number): EpochSecrets {
    return splitSecrets(call(() => this.inner.secrets(BigInt(epoch))));
  }

  /** Seals a content envelope under the current epoch. */
  sealContent(location: string, plaintext: Uint8Array): Uint8Array {
    const { epoch, k } = this.current();
    return sealContent(k, epoch, location, plaintext);
  }

  /** Opens a content, file or drop envelope at `location`. */
  open(envelope: Uint8Array, location: string): Uint8Array {
    return call(() => this.inner.open(envelope, location));
  }

  sealFrame<T = unknown>(engine: FieldMapEngine, frameType: string, frame: unknown): T {
    return JSON.parse(call(() => this.inner.sealFrame(engine.inner, frameType, JSON.stringify(frame)))) as T;
  }

  openFrame<T = unknown>(engine: FieldMapEngine, frameType: string, frame: unknown): T {
    return JSON.parse(call(() => this.inner.openFrame(engine.inner, frameType, JSON.stringify(frame)))) as T;
  }

  /** Commits the addition of the parties of `keyPackages`. */
  addMembers(identity: Identity, keyPackages: Uint8Array[], keyHistory?: KeyHistoryOffer): CommitUnit {
    const encoded = keyPackages.map(encodeB64url);
    const from = keyHistory === undefined ? undefined : BigInt(keyHistory.fromEpoch);
    return commitUnit(call(() => this.inner.addMembers(identity.inner, encoded, from, keyHistory?.sealed ?? false)));
  }

  /** Commits the removal of the members with the given Ed25519 public keys. */
  removeMembers(identity: Identity, publicKeys: Uint8Array[]): CommitUnit {
    return commitUnit(call(() => this.inner.removeMembers(identity.inner, publicKeys.map(encodeB64url))));
  }

  /** Commits an Update of this member's own leaf. */
  selfUpdate(identity: Identity): CommitUnit {
    return commitUnit(call(() => this.inner.selfUpdate(identity.inner)));
  }

  setPolicy(identity: Identity, policy: HistoryPolicy): CommitUnit {
    return commitUnit(call(() => this.inner.setPolicy(identity.inner, JSON.stringify(policy))));
  }

  /** The DS accepted the pending commit at `seq`: merges it. */
  commitAccepted(seq: number): void {
    call(() => this.inner.commitAccepted(BigInt(seq)));
  }

  /** The DS rejected the pending commit: discards it. */
  commitRejected(): void {
    call(() => this.inner.commitRejected());
  }

  /** Applies the next log entry, strictly in `seq` order. */
  apply(entry: LogEntry): Applied {
    const json = JSON.stringify({
      seq: entry.seq,
      kind: entry.kind,
      epoch: entry.epoch,
      bytes: encodeB64url(entry.bytes),
      drop_public_key: entry.dropPublicKey == null ? null : encodeB64url(entry.dropPublicKey),
    });
    const applied = JSON.parse(call(() => this.inner.apply(json))) as
      | Exclude<Applied, { type: "commit" }>
      | { type: "commit"; epoch: number; self_removed: boolean };
    return applied.type === "commit"
      ? { type: "commit", epoch: applied.epoch, selfRemoved: applied.self_removed }
      : applied;
  }

  free(): void {
    this.inner.free();
  }
}
