/* tslint:disable */
/* eslint-disable */

/**
 * A drop key pair derived from a drop seed `d_e` (spec §4.4).
 */
export class DropKeyPair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Derives the pair of `d_e`.
     */
    static derive(d_e: Uint8Array): DropKeyPair;
    /**
     * The private key.
     */
    readonly privateKey: Uint8Array;
    /**
     * The 32-byte X25519 public key.
     */
    readonly publicKey: Uint8Array;
}

/**
 * A field map (spec §12): a generated profile map, or an inline one.
 */
export class FieldMap {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The generated map of `profile`, or `undefined`.
     */
    static forProfile(profile: string): FieldMap | undefined;
    /**
     * A map from field-map JSON (spec §12.1), for inline maps of test
     * vectors. The map is never freed.
     */
    static fromJson(json: string): FieldMap;
    /**
     * Seals every mapped value of a JSON frame under `k_e` of `epoch` and
     * returns the JSON frame with the sealed forms in place.
     */
    sealFrame(frame_type: string, frame: string, epoch: bigint, k_e: Uint8Array, random?: Uint8Array | null): string;
    /**
     * The profile id.
     */
    readonly profile: string;
}

/**
 * The epoch secrets of one scope over an in-memory key cache, with the
 * backward walk over the epoch links added with `addLink` (spec §7.3).
 */
export class History {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Adds the epoch link stored for `epoch`.
     */
    addLink(epoch: bigint, link: Uint8Array): void;
    /**
     * Caches the secrets of an epoch below the current one.
     */
    cacheSecrets(epoch: bigint, k_e: Uint8Array, d_e: Uint8Array, verified: boolean): void;
    /**
     * The epoch of the next link the walk to `epoch` needs, or `undefined`
     * if the secrets of `epoch` are cached.
     */
    neededLink(epoch: bigint): bigint | undefined;
    /**
     * A history at the current `epoch` with its secrets.
     */
    constructor(scope: string, epoch: bigint, k_e: Uint8Array, d_e: Uint8Array);
    /**
     * Opens every mapped value of a JSON frame.
     */
    openFrame(map: FieldMap, frame_type: string, frame: string): string;
    /**
     * Opens a content, file or drop envelope at `location`.
     */
    open(envelope: Uint8Array, location_text: string): Uint8Array;
    /**
     * `k_e || d_e` of `epoch`, from the cache or the walk.
     */
    secrets(epoch: bigint): Uint8Array;
    /**
     * The current epoch.
     */
    readonly currentEpoch: bigint;
}

/**
 * A party's Ed25519 identity (spec §2.2).
 */
export class Identity {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The identity of a 32-byte Ed25519 seed.
     */
    static fromSeed(seed: Uint8Array): Identity;
    /**
     * A fresh identity.
     */
    static generate(): Identity;
    /**
     * The raw 32-byte Ed25519 public key.
     */
    readonly publicKey: Uint8Array;
    /**
     * The 32-byte seed.
     */
    readonly seed: Uint8Array;
}

/**
 * A party's KeyPackage private keys (spec §2.7).
 */
export class KeyPackageStore {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Generates a KeyPackage (TLS-serialized `MLSMessage`) and keeps its
     * private keys.
     */
    generate(identity: Identity, last_resort: boolean): Uint8Array;
    /**
     * An empty store.
     */
    constructor();
    /**
     * A store from `snapshot` bytes.
     */
    static restore(snapshot: Uint8Array): KeyPackageStore;
    /**
     * The store as opaque bytes.
     */
    snapshot(): Uint8Array;
}

/**
 * The MLS group of one scope (spec §2.8, §3, §7) with its key cache and
 * the epoch links added with `addLink`.
 */
export class ScopeGroup {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Adds the epoch link stored for `epoch`.
     */
    addLink(epoch: bigint, link: Uint8Array): void;
    /**
     * Commits the addition of the parties of base64url KeyPackages and
     * returns the JSON commit unit. With `key_history_from`, key history
     * from that epoch is attached for the joiners, sealed to each joiner's
     * leaf if `key_history_sealed`.
     */
    addMembers(identity: Identity, key_packages: string[], key_history_from: bigint | null | undefined, key_history_sealed: boolean): string;
    /**
     * Applies the next JSON log entry `{"seq", "kind", "epoch", "bytes",
     * "drop_public_key"?}` and returns the JSON effect.
     */
    apply(entry: string): string;
    /**
     * The DS accepted the pending commit at `seq`: merges it.
     */
    commitAccepted(seq: bigint): void;
    /**
     * The DS rejected the pending commit: discards it.
     */
    commitRejected(): void;
    /**
     * Creates the group of `scope` at epoch 0 with `identity` as the only
     * member, under a JSON history policy.
     */
    static create(identity: Identity, profile: string, scope: string, policy: string): ScopeGroup;
    /**
     * `k_e || d_e` of the current epoch.
     */
    currentSecrets(): Uint8Array;
    /**
     * The drop public key of the current epoch.
     */
    dropPublicKey(): Uint8Array;
    /**
     * Joins from a Welcome delivered with the `seq` of its commit.
     */
    static join(key_packages: KeyPackageStore, profile: string, scope: string, welcome: Uint8Array, seq: bigint): ScopeGroup;
    /**
     * The members' Ed25519 public keys in leaf order, base64url.
     */
    members(): string[];
    /**
     * The epoch of the next link the walk to `epoch` needs, or `undefined`
     * if the secrets of `epoch` are cached.
     */
    neededLink(epoch: bigint): bigint | undefined;
    /**
     * Opens every mapped value of a JSON frame.
     */
    openFrame(map: FieldMap, frame_type: string, frame: string): string;
    /**
     * Opens a content, file or drop envelope at `location`.
     */
    open(envelope: Uint8Array, location_text: string): Uint8Array;
    /**
     * The JSON history policy of the current epoch.
     */
    policy(): string;
    /**
     * Commits the removal of the members with the given base64url Ed25519
     * public keys and returns the JSON commit unit.
     */
    removeMembers(identity: Identity, public_keys: string[]): string;
    /**
     * A group from `snapshot` bytes.
     */
    static restore(snapshot: Uint8Array): ScopeGroup;
    /**
     * Seals every mapped value of a JSON frame under the current epoch.
     */
    sealFrame(map: FieldMap, frame_type: string, frame: string): string;
    /**
     * `k_e || d_e` of `epoch`, from the cache or the walk.
     */
    secrets(epoch: bigint): Uint8Array;
    /**
     * Commits an Update of this member's own leaf.
     */
    selfUpdate(identity: Identity): string;
    /**
     * Commits a new JSON history policy.
     */
    setPolicy(identity: Identity, policy: string): string;
    /**
     * The group state and its key cache as opaque bytes. They hold epoch
     * secrets: the caller stores them encrypted at rest.
     */
    snapshot(): Uint8Array;
    /**
     * The current epoch.
     */
    readonly epoch: bigint;
    /**
     * The 32-byte group id.
     */
    readonly groupId: Uint8Array;
    /**
     * Whether a commit awaits the DS answer.
     */
    readonly hasPendingCommit: boolean;
    /**
     * Whether this party still holds a leaf.
     */
    readonly isMember: boolean;
    /**
     * The profile id.
     */
    readonly profile: string;
    /**
     * The scope id.
     */
    readonly scope: string;
    /**
     * The `seq` of the last applied log entry.
     */
    readonly seq: bigint;
}

/**
 * Resolves an AAD template against a JSON frame (spec §12.3).
 */
export function buildLocation(template: string, frame: string, element?: number | null): string;

/**
 * Strict base64url without padding (spec §5.1).
 */
export function decodeB64url(text: string): Uint8Array;

/**
 * The JSON history policy of an `extension_data`.
 */
export function decodeHistoryPolicy(data: Uint8Array): string;

/**
 * The JSON key-history record of an MLS application data payload.
 */
export function decodeKeyHistory(payload: Uint8Array): string;

/**
 * Decodes an opened plaintext of kind `text` or `json` (spec §12.4) and
 * returns the value as JSON.
 */
export function decodePlaintext(plaintext: Uint8Array, kind: string): string;

/**
 * base64url without padding.
 */
export function encodeB64url(bytes: Uint8Array): string;

/**
 * The `extension_data` of a history policy given as JSON (`"full"`,
 * `"from_join"` or `{"from_epoch": N}`).
 */
export function encodeHistoryPolicy(policy: string): Uint8Array;

/**
 * The MLS application data of a key-history record given as JSON
 * `{"epoch", "entries": [{"epoch", "k", "d"}]}` (spec §5.7).
 */
export function encodeKeyHistory(history: string): Uint8Array;

/**
 * The header of an envelope as JSON `{"type": <name>, "epoch": <integer>}`.
 */
export function envelopeHeader(envelope: Uint8Array): string;

/**
 * The lower-case hex SHA-256 of a file envelope (the descriptor `sha256`).
 */
export function fileSha256(envelope: Uint8Array): string;

/**
 * The canonical fingerprint of an Ed25519 public key (spec §3.5).
 */
export function fingerprint(public_key: Uint8Array): string;

/**
 * The display form of a fingerprint.
 */
export function fingerprintDisplay(public_key: Uint8Array): string;

/**
 * The envelope of a JSON mapped value (spec §12.4).
 */
export function fromSealedValue(value: string): Uint8Array;

/**
 * The 32-byte group id of a profile and scope (spec §2.3).
 */
export function groupId(profile: string, scope: string): Uint8Array;

/**
 * Validates an uploaded KeyPackage at `now` (seconds since the Unix epoch)
 * and returns JSON `{"ref", "public_key", "last_resort", "not_before",
 * "not_after"}`.
 */
export function inspectKeyPackage(bytes: Uint8Array, now: bigint): string;

/**
 * Inspects a PublicMessage and returns JSON `{"group_id", "epoch",
 * "content_type", "sender_leaf", "adds", "removes", "proposal_refs",
 * "updates_path"}`.
 */
export function inspectMessage(bytes: Uint8Array): string;

/**
 * The per-envelope key `k_msg` (spec §4.3).
 */
export function messageKey(k_e: Uint8Array, salt: Uint8Array): Uint8Array;

/**
 * Opens a content envelope.
 */
export function openContent(k_e: Uint8Array, envelope: Uint8Array, location_text: string): Uint8Array;

/**
 * Opens a drop envelope with the drop seed of its epoch.
 */
export function openDrop(d_e: Uint8Array, envelope: Uint8Array, location_text: string): Uint8Array;

/**
 * Opens the epoch link stored for `epoch + 1` and returns `k_e || d_e`.
 */
export function openEpochLink(scope: string, epoch: bigint, k_next: Uint8Array, link: Uint8Array): Uint8Array;

/**
 * Opens a file envelope.
 */
export function openFile(k_e: Uint8Array, envelope: Uint8Array, location_text: string): Uint8Array;

/**
 * Opens a key-history envelope sealed to the leaf at `leaf_index` and
 * returns the JSON record.
 */
export function openKeyHistorySealed(scope: string, leaf_index: number, leaf_private_key: Uint8Array, envelope: Uint8Array): string;

/**
 * Checks a location string (spec §6) and returns it.
 */
export function parseLocation(text: string): string;

/**
 * Seals a content envelope (spec §5.3).
 */
export function sealContent(k_e: Uint8Array, epoch: bigint, location_text: string, plaintext: Uint8Array, random?: Uint8Array | null): Uint8Array;

/**
 * Seals a drop envelope to the drop public key of `epoch` (spec §5.5).
 */
export function sealDrop(public_key: Uint8Array, epoch: bigint, location_text: string, plaintext: Uint8Array): Uint8Array;

/**
 * Seals the epoch link carrying `E_epoch` under `k_next` (spec §5.6).
 */
export function sealEpochLink(scope: string, epoch: bigint, k_e: Uint8Array, d_e: Uint8Array, k_next: Uint8Array, random?: Uint8Array | null): Uint8Array;

/**
 * Seals a file envelope (spec §5.4).
 */
export function sealFile(k_e: Uint8Array, epoch: bigint, location_text: string, bytes: Uint8Array, random?: Uint8Array | null): Uint8Array;

/**
 * Seals a JSON key-history record to the leaf at `leaf_index` with its
 * encryption key.
 */
export function sealKeyHistoryToLeaf(history: string, scope: string, leaf_index: number, leaf_public_key: Uint8Array): Uint8Array;

/**
 * The sealed form `{"e2ee": "<base64url>"}` of an envelope, as JSON.
 */
export function toSealedValue(envelope: Uint8Array): string;

/**
 * Compares a logged drop public key of `epoch` with the one derived from
 * `d_e` (`drop_key_mismatch`).
 */
export function verifyDropPublicKey(d_e: Uint8Array, epoch: bigint, public_key: Uint8Array): void;

/**
 * The base64url `new_member` KeyPackageRefs of a Welcome, in order.
 */
export function welcomeRecipients(bytes: Uint8Array): string[];

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_dropkeypair_free: (a: number, b: number) => void;
    readonly __wbg_fieldmap_free: (a: number, b: number) => void;
    readonly __wbg_history_free: (a: number, b: number) => void;
    readonly __wbg_identity_free: (a: number, b: number) => void;
    readonly __wbg_keypackagestore_free: (a: number, b: number) => void;
    readonly __wbg_scopegroup_free: (a: number, b: number) => void;
    readonly buildLocation: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly decodeB64url: (a: number, b: number) => [number, number, number, number];
    readonly decodeHistoryPolicy: (a: number, b: number) => [number, number, number, number];
    readonly decodeKeyHistory: (a: number, b: number) => [number, number, number, number];
    readonly decodePlaintext: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly dropkeypair_derive: (a: number, b: number) => [number, number, number];
    readonly dropkeypair_privateKey: (a: number) => [number, number];
    readonly dropkeypair_publicKey: (a: number) => [number, number];
    readonly encodeB64url: (a: number, b: number) => [number, number];
    readonly encodeHistoryPolicy: (a: number, b: number) => [number, number, number, number];
    readonly encodeKeyHistory: (a: number, b: number) => [number, number, number, number];
    readonly envelopeHeader: (a: number, b: number) => [number, number, number, number];
    readonly fieldmap_forProfile: (a: number, b: number) => number;
    readonly fieldmap_fromJson: (a: number, b: number) => [number, number, number];
    readonly fieldmap_profile: (a: number) => [number, number];
    readonly fieldmap_sealFrame: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly fileSha256: (a: number, b: number) => [number, number];
    readonly fingerprint: (a: number, b: number) => [number, number, number, number];
    readonly fingerprintDisplay: (a: number, b: number) => [number, number, number, number];
    readonly fromSealedValue: (a: number, b: number) => [number, number, number, number];
    readonly groupId: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly history_addLink: (a: number, b: bigint, c: number, d: number) => void;
    readonly history_cacheSecrets: (a: number, b: bigint, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly history_currentEpoch: (a: number) => bigint;
    readonly history_neededLink: (a: number, b: bigint) => [number, bigint, number, number];
    readonly history_new: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly history_open: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly history_openFrame: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly history_secrets: (a: number, b: bigint) => [number, number, number, number];
    readonly identity_fromSeed: (a: number, b: number) => [number, number, number];
    readonly identity_generate: () => [number, number, number];
    readonly identity_publicKey: (a: number) => [number, number];
    readonly identity_seed: (a: number) => [number, number];
    readonly inspectKeyPackage: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly inspectMessage: (a: number, b: number) => [number, number, number, number];
    readonly keypackagestore_generate: (a: number, b: number, c: number) => [number, number, number, number];
    readonly keypackagestore_new: () => number;
    readonly keypackagestore_restore: (a: number, b: number) => [number, number, number];
    readonly keypackagestore_snapshot: (a: number) => [number, number, number, number];
    readonly messageKey: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly openContent: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly openDrop: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly openEpochLink: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly openFile: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly openKeyHistorySealed: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly parseLocation: (a: number, b: number) => [number, number, number, number];
    readonly scopegroup_addLink: (a: number, b: bigint, c: number, d: number) => void;
    readonly scopegroup_addMembers: (a: number, b: number, c: number, d: number, e: number, f: bigint, g: number) => [number, number, number, number];
    readonly scopegroup_apply: (a: number, b: number, c: number) => [number, number, number, number];
    readonly scopegroup_commitAccepted: (a: number, b: bigint) => [number, number];
    readonly scopegroup_commitRejected: (a: number) => [number, number];
    readonly scopegroup_create: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly scopegroup_currentSecrets: (a: number) => [number, number, number, number];
    readonly scopegroup_dropPublicKey: (a: number) => [number, number, number, number];
    readonly scopegroup_epoch: (a: number) => bigint;
    readonly scopegroup_groupId: (a: number) => [number, number];
    readonly scopegroup_hasPendingCommit: (a: number) => number;
    readonly scopegroup_isMember: (a: number) => number;
    readonly scopegroup_join: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: bigint) => [number, number, number];
    readonly scopegroup_members: (a: number) => [number, number];
    readonly scopegroup_neededLink: (a: number, b: bigint) => [number, bigint, number, number];
    readonly scopegroup_open: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly scopegroup_openFrame: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly scopegroup_policy: (a: number) => [number, number, number, number];
    readonly scopegroup_profile: (a: number) => [number, number];
    readonly scopegroup_removeMembers: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly scopegroup_restore: (a: number, b: number) => [number, number, number];
    readonly scopegroup_scope: (a: number) => [number, number];
    readonly scopegroup_sealFrame: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly scopegroup_secrets: (a: number, b: bigint) => [number, number, number, number];
    readonly scopegroup_selfUpdate: (a: number, b: number) => [number, number, number, number];
    readonly scopegroup_seq: (a: number) => bigint;
    readonly scopegroup_setPolicy: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly scopegroup_snapshot: (a: number) => [number, number, number, number];
    readonly sealContent: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly sealDrop: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly sealEpochLink: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly sealFile: (a: number, b: number, c: bigint, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly sealKeyHistoryToLeaf: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly toSealedValue: (a: number, b: number) => [number, number];
    readonly verifyDropPublicKey: (a: number, b: number, c: bigint, d: number, e: number) => [number, number];
    readonly welcomeRecipients: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
