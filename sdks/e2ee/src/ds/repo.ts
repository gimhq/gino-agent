// The storage port of the relay: the key directory, KeyPackages, scopes, the
// handshake log, epoch links, Welcomes and delivery cursors.

// ─── Rows ───

/** Which side of the protocol a directory party is. */
export type E2eePartyKind = "agent" | "client";

/** One directory party: its pinned Ed25519 key, a pending key change, and its latest `e2ee` capability. */
export interface E2eePartyRow {
  partyId: string;
  kind: E2eePartyKind;
  /** Pinned Ed25519 public key, 32 bytes. */
  publicKey: Uint8Array;
  /** SHA-256 of `publicKey`, 64 lower-case hex characters. */
  fingerprint: string;
  capability: Record<string, unknown> | null;
  pendingPublicKey: Uint8Array | null;
  pendingFingerprint: string | null;
  keyChangedAt: number | null;
  pinnedAt: number;
  updatedAt: number;
}

/** Insert shape for `E2eeRepo.pinPartyIfAbsent`; `pinnedAt` defaults to the write time, `updatedAt` to `pinnedAt`. */
export interface NewE2eePartyRow {
  partyId: string;
  kind: E2eePartyKind;
  publicKey: Uint8Array;
  fingerprint: string;
  capability?: Record<string, unknown> | null;
  pinnedAt?: number;
  updatedAt?: number;
}

/** One stored KeyPackage of a party. `notAfter` is unix SECONDS (the KeyPackage lifetime). */
export interface E2eeKeyPackageRow {
  /** KeyPackageRef, hex; unique. */
  ref: string;
  partyId: string;
  bytes: Uint8Array;
  lastResort: boolean;
  notAfter: number;
  createdAt: number;
}

/** Insert shape for the KeyPackage writes; one-time vs last-resort is the method's choice. */
export interface NewE2eeKeyPackageRow {
  ref: string;
  partyId: string;
  bytes: Uint8Array;
  notAfter: number;
  createdAt?: number;
}

/** A party's KeyPackage pool level: unexpired one-time KeyPackages and whether an unexpired last-resort one exists. */
export interface E2eeKeyPackageCounts {
  oneTime: number;
  lastResort: boolean;
}

/** The scope record of an encrypted task (scope id = task id). */
export interface E2eeScopeRow {
  taskId: string;
  profileId: string;
  /** MLS group id, 32 bytes. */
  groupId: Uint8Array;
  /** Current epoch; starts at 0. */
  epoch: number;
  /** Drop public key of the current epoch, 32 bytes. */
  dropPublicKey: Uint8Array;
  creatorPartyId: string;
  createdAt: number;
}

/** Insert shape for `E2eeRepo.insertScopeIfAbsent`; the scope starts at epoch 0. */
export interface NewE2eeScopeRow {
  taskId: string;
  profileId: string;
  groupId: Uint8Array;
  dropPublicKey: Uint8Array;
  creatorPartyId: string;
  createdAt?: number;
}

/** One leaf of a scope's group as tracked from the log. */
export interface E2eeMemberRow {
  taskId: string;
  leafIndex: number;
  partyId: string;
}

/** Handshake log entry kinds (e2ee spec §3.1). */
export type E2eeLogKind = "commit" | "proposal" | "key_history" | "key_history_sealed";

/** One handshake log entry, stored byte for byte. */
export interface E2eeLogEntryRow {
  taskId: string;
  /** Starts at 1, +1 per entry, never reused. */
  seq: number;
  kind: E2eeLogKind;
  /** The epoch the entry was sent in. */
  epoch: number;
  bytes: Uint8Array;
  /** `commit` entries: the drop public key of epoch `epoch + 1`; otherwise null. */
  dropPublicKey: Uint8Array | null;
  submitterPartyId: string;
  acceptedAt: number;
}

/** A queued Welcome for one party, with the `seq` of the commit that added it. `id` is storage-generated. */
export interface E2eeWelcomeRow {
  id: number;
  taskId: string;
  partyId: string;
  seq: number;
  bytes: Uint8Array;
  createdAt: number;
  ackedAt: number | null;
}

// ─── E2eeRepo ───

/** A Welcome handed to `E2eeRepo.acceptCommit`, queued for `partyId`. */
export interface E2eeWelcomeInput {
  readonly partyId: string;
  readonly bytes: Uint8Array;
}

/** A key-history entry appended after its commit. */
export interface E2eeKeyHistoryInput {
  readonly kind: "key_history" | "key_history_sealed";
  readonly bytes: Uint8Array;
}

/** One commit unit (e2ee spec §3.2), with the membership delta already computed by the caller. */
export interface E2eeCommitUnit {
  readonly taskId: string;
  /** The epoch the commit was sent in; must equal the scope's current epoch. */
  readonly expectedEpoch: number;
  readonly bytes: Uint8Array;
  readonly submitterPartyId: string;
  /** Drop public key of epoch `expectedEpoch + 1`. */
  readonly dropPublicKey: Uint8Array;
  /** Epoch-link record for epoch `expectedEpoch + 1`. */
  readonly epochLink?: Uint8Array;
  readonly keyHistory?: readonly E2eeKeyHistoryInput[];
  readonly welcomes?: readonly E2eeWelcomeInput[];
  /** Leaves removed by the commit; applied before `add`. */
  readonly removeLeaves?: readonly number[];
  /** Leaves added by the commit (an existing leaf index is overwritten). */
  readonly add?: readonly { readonly leafIndex: number; readonly partyId: string }[];
  /** Defaults to `Date.now()`; stamps every entry and Welcome of the unit. */
  readonly acceptedAt?: number;
}

/** A non-commit log entry for `E2eeRepo.appendEntry`. */
export interface E2eeEntryInput {
  readonly taskId: string;
  /** Must equal the scope's current epoch; recorded as the entry's epoch. */
  readonly expectedEpoch: number;
  readonly kind: Exclude<E2eeLogKind, "commit">;
  readonly bytes: Uint8Array;
  readonly submitterPartyId: string;
  /** Defaults to `Date.now()`. */
  readonly acceptedAt?: number;
}

/** Why a log write wrote nothing: the scope is unknown, or its epoch moved (`epoch` = the current one). */
export type E2eeLogRefusal
  = | { readonly ok: false; readonly code: "no_scope" }
    | { readonly ok: false; readonly code: "epoch_conflict"; readonly epoch: number };

export type E2eeCommitResult
  = | { readonly ok: true; readonly seq: number; readonly epoch: number; readonly keyHistorySeqs: number[] }
    | E2eeLogRefusal;

export type E2eeAppendResult = { readonly ok: true; readonly seq: number } | E2eeLogRefusal;

/** A capped window of log entries in `seq` order; `more` is true when entries past the window exist. */
export interface E2eeLogPage {
  entries: E2eeLogEntryRow[];
  more: boolean;
}

/** Outcome of `E2eeRepo.putEpochLinkIfAbsent`: whether this call stored it, and the stored bytes (first link wins). */
export interface E2eeLinkPut {
  inserted: boolean;
  bytes: Uint8Array;
}

/**
 * Storage of the relay acting as MLS Delivery Service. It never holds a key
 * that opens content; everything here is public keys, opaque MLS bytes and
 * bookkeeping. Validation (framing, signatures, group id checks,
 * authorization) is the relay's job before calling.
 *
 * The invariants an adapter MUST keep:
 *   • binary values go in and come out as `Uint8Array`, byte for byte, and
 *     never alias a caller's buffer;
 *   • the FIRST key of a party is pinned — a later key is only recorded as a
 *     pending change until `repinParty`;
 *   • a claimed one-time KeyPackage is deleted in the same unit, so no two
 *     claims return it; the last-resort KeyPackage is returned, never deleted
 *     by a claim; expired KeyPackages are never returned;
 *   • a scope is inserted once and never replaced or deleted (there is no
 *     delete method; a host should also refuse deleting a task that has a
 *     scope);
 *   • log `seq` starts at 1 per scope, grows by exactly 1 per entry and is
 *     never reused; a write whose expected epoch is not the scope's current
 *     epoch writes nothing;
 *   • the first epoch link per `(taskId, epoch)` wins;
 *   • every multi-row method below is one all-or-nothing unit.
 *
 * Every method is synchronous, like the relay itself.
 */
export interface E2eeRepo {
  // directory

  /**
   * Pin a party's first key: INSERT when absent and return the stored row;
   * when the party exists, change nothing and return the existing row (first
   * key wins, whatever key this call carries).
   */
  pinPartyIfAbsent: (row: NewE2eePartyRow) => E2eePartyRow;
  /**
   * Record a key change: set `pendingPublicKey` / `pendingFingerprint` /
   * `keyChangedAt = now` and `updatedAt = now`. The pinned key is never
   * touched. Returns `false` for an unknown party.
   */
  recordKeyChange: (partyId: string, publicKey: Uint8Array, fingerprint: string, now: number) => boolean;
  /**
   * Operator re-pin, ATOMIC: the pending key becomes the pinned key
   * (`pinnedAt = updatedAt = now`), the pending fields are cleared, and every
   * stored KeyPackage of the party is deleted. Returns the updated row, or
   * `undefined` (nothing changed) when the party is unknown or has no pending key.
   */
  repinParty: (partyId: string, now: number) => E2eePartyRow | undefined;
  /** Replace the party's latest capability and stamp `updatedAt = now`. No-op for an unknown party. */
  setPartyCapability: (partyId: string, capability: Record<string, unknown> | null, now: number) => void;
  getParty: (partyId: string) => E2eePartyRow | undefined;
  /** Every party, in insertion order. */
  listParties: () => E2eePartyRow[];

  // KeyPackages — `ref` UNIQUE; `notAfter` is unix seconds, `now` is epoch-ms

  /** Store a one-time KeyPackage, IDEMPOTENT on `ref`: an existing ref keeps its row and returns `false`. */
  insertKeyPackage: (row: NewE2eeKeyPackageRow) => boolean;
  /**
   * Store the party's last-resort KeyPackage, ATOMIC: the party's previous
   * last-resort KeyPackage (and any row with the same `ref`) is deleted and
   * this one inserted.
   */
  putLastResortKeyPackage: (row: NewE2eeKeyPackageRow) => void;
  /**
   * Claim one KeyPackage of `partyId`, ATOMIC: delete the party's expired
   * KeyPackages (`notAfter < floor(now / 1000)`), then take the oldest
   * one-time KeyPackage (`createdAt` asc, ties in insertion order) and delete
   * it, else return the last-resort one WITHOUT deleting it, else
   * `undefined`. A returned KeyPackage records `ref → partyId` in the claims
   * map (`claimedAt = now`), so `partyOfKeyPackageRef` resolves it after the
   * one-time row is gone.
   */
  claimKeyPackage: (partyId: string, now: number) => E2eeKeyPackageRow | undefined;
  /** The party's unexpired pool at `now` (epoch-ms; expired = `notAfter < floor(now / 1000)`). */
  keyPackageCounts: (partyId: string, now: number) => E2eeKeyPackageCounts;
  /** The party a KeyPackageRef belongs to: the claims map first, then stored KeyPackages. */
  partyOfKeyPackageRef: (ref: string) => string | undefined;

  // scopes + members

  /**
   * Create a scope at epoch 0, ATOMIC with its member leaf 0 = `creatorPartyId`.
   * Returns `false` and changes nothing when the task already has a scope
   * (never replaced).
   */
  insertScopeIfAbsent: (row: NewE2eeScopeRow) => boolean;
  getScope: (taskId: string) => E2eeScopeRow | undefined;
  /** A scope's members, by `leafIndex` ascending. */
  listMembers: (taskId: string) => E2eeMemberRow[];
  /** Whether `partyId` holds any leaf of the scope. */
  isMember: (taskId: string, partyId: string) => boolean;

  // handshake log

  /**
   * Accept one commit unit, ATOMIC (e2ee spec §3.2). When the scope is
   * unknown → `no_scope`; when its epoch differs from `expectedEpoch` →
   * `epoch_conflict` with the current epoch; either way nothing is written.
   * Otherwise, in one unit: append the commit at the next seq with `epoch =
   * expectedEpoch` and `dropPublicKey`; advance the scope to `expectedEpoch +
   * 1` with the new drop key; store `epochLink` for epoch `expectedEpoch + 1`
   * when given and absent; append the key-history entries (epoch
   * `expectedEpoch + 1`) at the following seqs in input order; queue each
   * Welcome with the commit's seq; remove `removeLeaves`, then write `add`.
   */
  acceptCommit: (unit: E2eeCommitUnit) => E2eeCommitResult;
  /** Append a proposal / key-history entry at the next seq, guarded like `acceptCommit` (nothing written on refusal). */
  appendEntry: (entry: E2eeEntryInput) => E2eeAppendResult;
  /** Entries with `seq > afterSeq`, in `seq` order, at most `limit`. */
  readLog: (taskId: string, afterSeq: number, limit: number) => E2eeLogPage;
  /** Entries from the first entry whose `epoch >= epoch` onwards, in `seq` order, at most `limit`. */
  readLogFromEpoch: (taskId: string, epoch: number, limit: number) => E2eeLogPage;
  /** The scope's highest `seq`, `0` when the log is empty. */
  lastSeq: (taskId: string) => number;

  // epoch links — `(taskId, epoch)` PK

  /** Store a link when absent. FIRST link wins: a later call stores nothing and returns `inserted: false` with the stored bytes. */
  putEpochLinkIfAbsent: (taskId: string, epoch: number, bytes: Uint8Array) => E2eeLinkPut;
  getEpochLink: (taskId: string, epoch: number) => Uint8Array | undefined;

  // Welcomes

  /** Unacked Welcomes of a party (only `taskId`'s when given), ascending by `id`. */
  listUnackedWelcomes: (partyId: string, taskId?: string) => E2eeWelcomeRow[];
  /** Set `ackedAt = now` on Welcome `id` of `partyId` (a foreign party's ack is a no-op). Returns `true` iff a row was updated. */
  ackWelcome: (partyId: string, id: number, now: number) => boolean;
  /** Delete the party's UNACKED Welcomes for a task (it left the group). Returns the count deleted. */
  dropUnackedWelcomes: (taskId: string, partyId: string) => number;

  // delivery cursors — `(taskId, partyId)` PK, over log `seq`

  /** The last log `seq` pushed to the party, `0` when none. */
  readDeliveryCursor: (taskId: string, partyId: string) => number;
  /** MONOTONIC: store `seq` only when greater than the stored value (creating the row when absent), `updatedAt = now`. Returns `true` iff it moved. */
  advanceDeliveryCursor: (taskId: string, partyId: string, seq: number, now: number) => boolean;
}
