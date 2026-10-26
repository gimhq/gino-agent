// An in-memory `E2eeRepo`: the reference adapter, for tests and single-process hosts.
import type {
  E2eeKeyPackageRow,
  E2eeLogEntryRow,
  E2eeLogPage,
  E2eeMemberRow,
  E2eePartyRow,
  E2eeRepo,
  E2eeScopeRow,
  E2eeWelcomeRow,
  NewE2eeKeyPackageRow,
} from "./repo";

const copy = (bytes: Uint8Array): Uint8Array => new Uint8Array(bytes);
const copyOrNull = (bytes: Uint8Array | null): Uint8Array | null => (bytes ? copy(bytes) : null);

function cloneParty(p: E2eePartyRow): E2eePartyRow {
  return {
    ...p,
    publicKey: copy(p.publicKey),
    pendingPublicKey: copyOrNull(p.pendingPublicKey),
    capability: p.capability === null ? null : structuredClone(p.capability),
  };
}
const cloneKeyPackage = (k: E2eeKeyPackageRow): E2eeKeyPackageRow => ({ ...k, bytes: copy(k.bytes) });
const cloneScope = (s: E2eeScopeRow): E2eeScopeRow => ({ ...s, groupId: copy(s.groupId), dropPublicKey: copy(s.dropPublicKey) });
const cloneEntry = (e: E2eeLogEntryRow): E2eeLogEntryRow => ({ ...e, bytes: copy(e.bytes), dropPublicKey: copyOrNull(e.dropPublicKey) });
const cloneWelcome = (w: E2eeWelcomeRow): E2eeWelcomeRow => ({ ...w, bytes: copy(w.bytes) });

/** Unix seconds of an epoch-ms instant (the unit of `notAfter`). */
const seconds = (now: number): number => Math.floor(now / 1000);

export function memoryE2eeRepo(): E2eeRepo {
  const parties = new Map<string, E2eePartyRow>();
  let keyPackages: E2eeKeyPackageRow[] = []; // insertion order
  const claims = new Map<string, { partyId: string; claimedAt: number }>();
  const scopes = new Map<string, E2eeScopeRow>();
  let members: E2eeMemberRow[] = [];
  const logs = new Map<string, E2eeLogEntryRow[]>(); // per task, seq order
  const links = new Map<string, Uint8Array>(); // key: `${taskId} ${epoch}`
  let welcomes: E2eeWelcomeRow[] = []; // id order
  let nextWelcomeId = 1;
  const cursors = new Map<string, number>(); // key: `${taskId} ${partyId}`

  const linkKey = (taskId: string, epoch: number): string => `${taskId} ${epoch}`;
  const cursorKey = (taskId: string, partyId: string): string => `${taskId} ${partyId}`;
  const logOf = (taskId: string): E2eeLogEntryRow[] => {
    let log = logs.get(taskId);
    if (!log) {
      log = [];
      logs.set(taskId, log);
    }
    return log;
  };
  const lastSeqOf = (taskId: string): number => logs.get(taskId)?.at(-1)?.seq ?? 0;
  const page = (rows: E2eeLogEntryRow[], limit: number): E2eeLogPage => ({
    entries: rows.slice(0, limit).map(cloneEntry),
    more: rows.length > limit,
  });

  return {
    pinPartyIfAbsent(row) {
      const existing = parties.get(row.partyId);
      if (existing) {
        return cloneParty(existing);
      }
      const pinnedAt = row.pinnedAt ?? Date.now();
      const stored: E2eePartyRow = {
        partyId: row.partyId,
        kind: row.kind,
        publicKey: copy(row.publicKey),
        fingerprint: row.fingerprint,
        capability: row.capability == null ? null : structuredClone(row.capability),
        pendingPublicKey: null,
        pendingFingerprint: null,
        keyChangedAt: null,
        pinnedAt,
        updatedAt: row.updatedAt ?? pinnedAt,
      };
      parties.set(stored.partyId, stored);
      return cloneParty(stored);
    },
    recordKeyChange(partyId, publicKey, fingerprint, now) {
      const row = parties.get(partyId);
      if (!row) {
        return false;
      }
      row.pendingPublicKey = copy(publicKey);
      row.pendingFingerprint = fingerprint;
      row.keyChangedAt = now;
      row.updatedAt = now;
      return true;
    },
    repinParty(partyId, now) {
      const row = parties.get(partyId);
      if (!row || row.pendingPublicKey === null || row.pendingFingerprint === null) {
        return undefined;
      }
      row.publicKey = row.pendingPublicKey;
      row.fingerprint = row.pendingFingerprint;
      row.pendingPublicKey = null;
      row.pendingFingerprint = null;
      row.keyChangedAt = null;
      row.pinnedAt = now;
      row.updatedAt = now;
      keyPackages = keyPackages.filter(k => k.partyId !== partyId);
      return cloneParty(row);
    },
    setPartyCapability(partyId, capability, now) {
      const row = parties.get(partyId);
      if (row) {
        row.capability = capability === null ? null : structuredClone(capability);
        row.updatedAt = now;
      }
    },
    getParty(partyId) {
      const row = parties.get(partyId);
      return row ? cloneParty(row) : undefined;
    },
    listParties() {
      return [...parties.values()].map(cloneParty);
    },

    insertKeyPackage(row: NewE2eeKeyPackageRow) {
      if (keyPackages.some(k => k.ref === row.ref)) {
        return false;
      }
      keyPackages.push({ ref: row.ref, partyId: row.partyId, bytes: copy(row.bytes), lastResort: false, notAfter: row.notAfter, createdAt: row.createdAt ?? Date.now() });
      return true;
    },
    putLastResortKeyPackage(row: NewE2eeKeyPackageRow) {
      const stored: E2eeKeyPackageRow = { ref: row.ref, partyId: row.partyId, bytes: copy(row.bytes), lastResort: true, notAfter: row.notAfter, createdAt: row.createdAt ?? Date.now() };
      keyPackages = [...keyPackages.filter(k => k.ref !== row.ref && !(k.partyId === row.partyId && k.lastResort)), stored];
    },
    claimKeyPackage(partyId, now) {
      const nowSec = seconds(now);
      keyPackages = keyPackages.filter(k => !(k.partyId === partyId && k.notAfter < nowSec));
      const mine = keyPackages.filter(k => k.partyId === partyId);
      // Stable sort: equal `createdAt` keeps insertion order.
      const oneTime = mine.filter(k => !k.lastResort).sort((a, b) => a.createdAt - b.createdAt)[0];
      const claimed = oneTime ?? mine.find(k => k.lastResort);
      if (!claimed) {
        return undefined;
      }
      if (oneTime) {
        keyPackages = keyPackages.filter(k => k !== oneTime);
      }
      claims.set(claimed.ref, { partyId, claimedAt: now });
      return cloneKeyPackage(claimed);
    },
    keyPackageCounts(partyId, now) {
      const nowSec = seconds(now);
      const live = keyPackages.filter(k => k.partyId === partyId && k.notAfter >= nowSec);
      return { oneTime: live.filter(k => !k.lastResort).length, lastResort: live.some(k => k.lastResort) };
    },
    partyOfKeyPackageRef(ref) {
      return claims.get(ref)?.partyId ?? keyPackages.find(k => k.ref === ref)?.partyId;
    },

    insertScopeIfAbsent(row) {
      if (scopes.has(row.taskId)) {
        return false;
      }
      scopes.set(row.taskId, {
        taskId: row.taskId,
        profileId: row.profileId,
        groupId: copy(row.groupId),
        epoch: 0,
        dropPublicKey: copy(row.dropPublicKey),
        creatorPartyId: row.creatorPartyId,
        createdAt: row.createdAt ?? Date.now(),
      });
      members = [...members.filter(m => m.taskId !== row.taskId), { taskId: row.taskId, leafIndex: 0, partyId: row.creatorPartyId }];
      return true;
    },
    getScope(taskId) {
      const row = scopes.get(taskId);
      return row ? cloneScope(row) : undefined;
    },
    listMembers(taskId) {
      return members.filter(m => m.taskId === taskId).sort((a, b) => a.leafIndex - b.leafIndex).map(m => ({ ...m }));
    },
    isMember(taskId, partyId) {
      return members.some(m => m.taskId === taskId && m.partyId === partyId);
    },

    acceptCommit(unit) {
      const scope = scopes.get(unit.taskId);
      if (!scope) {
        return { ok: false, code: "no_scope" };
      }
      if (scope.epoch !== unit.expectedEpoch) {
        return { ok: false, code: "epoch_conflict", epoch: scope.epoch };
      }
      // Nothing below can fail, so the unit is all-or-nothing.
      const acceptedAt = unit.acceptedAt ?? Date.now();
      const newEpoch = unit.expectedEpoch + 1;
      const log = logOf(unit.taskId);
      const seq = lastSeqOf(unit.taskId) + 1;
      log.push({ taskId: unit.taskId, seq, kind: "commit", epoch: unit.expectedEpoch, bytes: copy(unit.bytes), dropPublicKey: copy(unit.dropPublicKey), submitterPartyId: unit.submitterPartyId, acceptedAt });
      scope.epoch = newEpoch;
      scope.dropPublicKey = copy(unit.dropPublicKey);
      if (unit.epochLink && !links.has(linkKey(unit.taskId, newEpoch))) {
        links.set(linkKey(unit.taskId, newEpoch), copy(unit.epochLink));
      }
      const keyHistorySeqs = (unit.keyHistory ?? []).map((k, i) => {
        log.push({ taskId: unit.taskId, seq: seq + 1 + i, kind: k.kind, epoch: newEpoch, bytes: copy(k.bytes), dropPublicKey: null, submitterPartyId: unit.submitterPartyId, acceptedAt });
        return seq + 1 + i;
      });
      for (const w of unit.welcomes ?? []) {
        welcomes.push({ id: nextWelcomeId++, taskId: unit.taskId, partyId: w.partyId, seq, bytes: copy(w.bytes), createdAt: acceptedAt, ackedAt: null });
      }
      const removed = new Set([...(unit.removeLeaves ?? []), ...(unit.add ?? []).map(a => a.leafIndex)]);
      members = [
        ...members.filter(m => m.taskId !== unit.taskId || !removed.has(m.leafIndex)),
        ...(unit.add ?? []).map(a => ({ taskId: unit.taskId, leafIndex: a.leafIndex, partyId: a.partyId })),
      ];
      return { ok: true, seq, epoch: newEpoch, keyHistorySeqs };
    },
    appendEntry(entry) {
      const scope = scopes.get(entry.taskId);
      if (!scope) {
        return { ok: false, code: "no_scope" };
      }
      if (scope.epoch !== entry.expectedEpoch) {
        return { ok: false, code: "epoch_conflict", epoch: scope.epoch };
      }
      const seq = lastSeqOf(entry.taskId) + 1;
      logOf(entry.taskId).push({ taskId: entry.taskId, seq, kind: entry.kind, epoch: entry.expectedEpoch, bytes: copy(entry.bytes), dropPublicKey: null, submitterPartyId: entry.submitterPartyId, acceptedAt: entry.acceptedAt ?? Date.now() });
      return { ok: true, seq };
    },
    readLog(taskId, afterSeq, limit) {
      return page((logs.get(taskId) ?? []).filter(e => e.seq > afterSeq), limit);
    },
    readLogFromEpoch(taskId, epoch, limit) {
      const log = logs.get(taskId) ?? [];
      const first = log.findIndex(e => e.epoch >= epoch);
      return page(first < 0 ? [] : log.slice(first), limit);
    },
    lastSeq(taskId) {
      return lastSeqOf(taskId);
    },

    putEpochLinkIfAbsent(taskId, epoch, bytes) {
      const key = linkKey(taskId, epoch);
      const stored = links.get(key);
      if (stored) {
        return { inserted: false, bytes: copy(stored) };
      }
      links.set(key, copy(bytes));
      return { inserted: true, bytes: copy(bytes) };
    },
    getEpochLink(taskId, epoch) {
      const stored = links.get(linkKey(taskId, epoch));
      return stored ? copy(stored) : undefined;
    },

    listUnackedWelcomes(partyId, taskId) {
      return welcomes
        .filter(w => w.partyId === partyId && w.ackedAt === null && (taskId === undefined || w.taskId === taskId))
        .map(cloneWelcome);
    },
    ackWelcome(partyId, id, now) {
      const row = welcomes.find(w => w.id === id && w.partyId === partyId);
      if (!row) {
        return false;
      }
      row.ackedAt = now;
      return true;
    },
    dropUnackedWelcomes(taskId, partyId) {
      const before = welcomes.length;
      welcomes = welcomes.filter(w => !(w.taskId === taskId && w.partyId === partyId && w.ackedAt === null));
      return before - welcomes.length;
    },

    readDeliveryCursor(taskId, partyId) {
      return cursors.get(cursorKey(taskId, partyId)) ?? 0;
    },
    advanceDeliveryCursor(taskId, partyId, seq, _now) {
      const key = cursorKey(taskId, partyId);
      if (seq <= (cursors.get(key) ?? 0)) {
        return false;
      }
      cursors.set(key, seq);
      return true;
    },
  };
}
