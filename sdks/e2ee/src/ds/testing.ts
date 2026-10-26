// E2eeRepo conformance: the invariants every `E2eeRepo` adapter must keep,
// asserted against a fresh empty repository per test. Written against the
// harness primitives so it mounts under `bun test` and under `node --test`
// (`node:test` + the `expect` package).
import type { E2eeCommitUnit, E2eeRepo, NewE2eeScopeRow } from "./repo";

/** An adapter under test: `open` returns a fresh empty repository. */
export interface E2eeRepoTarget {
  name: string;
  open: () => { repo: E2eeRepo; close: () => void };
}

// Method signatures on purpose (bivariant parameters): both `bun:test`'s
// `expect` and the npm `expect` package (Jest's implementation, used by the
// `node --test` runs) must satisfy this surface structurally.
/* eslint-disable ts/method-signature-style */
/** The matchers the suite uses — the common subset of bun:test and Jest `expect`. */
export interface ConformanceMatchers {
  toBe(expected: unknown): void;
  toEqual(expected: unknown): void;
  toMatchObject(expected: object): void;
  toBeUndefined(): void;
  toBeNull(): void;
  toThrow(expected?: unknown): void;
  toHaveLength(length: number): void;
  toBeGreaterThan(expected: number): void;
  readonly not: ConformanceMatchers;
}

export interface ConformanceExpect {
  (actual: unknown): ConformanceMatchers;
  any(constructor: unknown): unknown;
}
/* eslint-enable ts/method-signature-style */

/**
 * The test-runner primitives the suite is written against, so the same file
 * mounts under `bun test` (`import { … } from "bun:test"`) and under
 * `node --test` (`node:test` + the `expect` package).
 */
export interface ConformanceHarness {
  readonly describe: (name: string, fn: () => void) => void;
  readonly test: (name: string, fn: () => void) => void;
  readonly beforeEach: (fn: () => void) => void;
  readonly afterEach: (fn: () => void) => void;
  readonly expect: ConformanceExpect;
}

export function describeE2eeRepoConformance(target: E2eeRepoTarget, harness: ConformanceHarness): void {
  const { describe, test, expect, beforeEach, afterEach } = harness;
  describe(`[${target.name}] E2eeRepo`, () => {
    let opened: ReturnType<E2eeRepoTarget["open"]> | undefined;
    beforeEach(() => {
      opened = target.open();
    });
    afterEach(() => {
      opened?.close();
      opened = undefined;
    });
    const e2ee = (): E2eeRepo => opened!.repo;
    const key = (fill: number) => new Uint8Array(32).fill(fill);
    const bytes = (...values: number[]) => new Uint8Array(values);
    const fp = (c: string) => c.repeat(64);
    /** 2026-01-01T00:00:00Z in epoch-ms; KeyPackage lifetimes are unix seconds around it. */
    const NOW = 1_767_225_600_000;
    const NOW_S = NOW / 1000;
    const kp = (ref: string, extra: Record<string, unknown> = {}) =>
      ({ ref, partyId: "p1", bytes: bytes(1, 2, 3), notAfter: NOW_S + 3600, ...extra });
    const scope = (extra: Partial<NewE2eeScopeRow> = {}): NewE2eeScopeRow =>
      ({ taskId: "t1", profileId: "gino-task-v1", groupId: key(7), dropPublicKey: key(8), creatorPartyId: "creator", createdAt: 1_000, ...extra });
    const commit = (extra: Partial<E2eeCommitUnit> = {}): E2eeCommitUnit =>
      ({ taskId: "t1", expectedEpoch: 0, bytes: bytes(0xC0), submitterPartyId: "creator", dropPublicKey: key(9), acceptedAt: 5_000, ...extra });
    const pin = (partyId: string, fill = 1) =>
      e2ee().pinPartyIfAbsent({ partyId, kind: "agent", publicKey: key(fill), fingerprint: fp(String(fill)), pinnedAt: 100 });

    test("pinPartyIfAbsent: the first key is pinned and a later pin returns it unchanged", () => {
      const first = pin("p1", 1);
      expect(first).toEqual({
        partyId: "p1",
        kind: "agent",
        publicKey: key(1),
        fingerprint: fp("1"),
        capability: null,
        pendingPublicKey: null,
        pendingFingerprint: null,
        keyChangedAt: null,
        pinnedAt: 100,
        updatedAt: 100,
      });
      const again = e2ee().pinPartyIfAbsent({ partyId: "p1", kind: "client", publicKey: key(2), fingerprint: fp("2"), capability: { versions: [1] } });
      expect(again).toEqual(first);
      expect(e2ee().getParty("p1")).toEqual(first);
      e2ee().pinPartyIfAbsent({ partyId: "c1", kind: "client", publicKey: key(3), fingerprint: fp("3"), capability: { versions: [1] } });
      expect(e2ee().listParties().map(p => [p.partyId, p.kind])).toEqual([["p1", "agent"], ["c1", "client"]]);
      expect(e2ee().getParty("c1")!.capability).toEqual({ versions: [1] });
      expect(e2ee().getParty("nope")).toBeUndefined();
    });

    test("setPartyCapability replaces the capability and stamps updatedAt", () => {
      pin("p1");
      e2ee().setPartyCapability("p1", { versions: [1], mls_suites: [1] }, 200);
      expect(e2ee().getParty("p1")).toMatchObject({ capability: { versions: [1], mls_suites: [1] }, updatedAt: 200, pinnedAt: 100 });
      e2ee().setPartyCapability("p1", null, 300);
      expect(e2ee().getParty("p1")).toMatchObject({ capability: null, updatedAt: 300 });
      e2ee().setPartyCapability("ghost", {}, 300);
      expect(e2ee().getParty("ghost")).toBeUndefined();
    });

    test("recordKeyChange keeps the pinned key and records the pending one", () => {
      pin("p1", 1);
      expect(e2ee().recordKeyChange("p1", key(2), fp("2"), 500)).toBe(true);
      expect(e2ee().getParty("p1")).toMatchObject({
        publicKey: key(1),
        fingerprint: fp("1"),
        pendingPublicKey: key(2),
        pendingFingerprint: fp("2"),
        keyChangedAt: 500,
        pinnedAt: 100,
        updatedAt: 500,
      });
      expect(e2ee().recordKeyChange("ghost", key(2), fp("2"), 500)).toBe(false);
    });

    test("repinParty promotes the pending key, clears it, and purges the party's KeyPackages", () => {
      pin("p1", 1);
      pin("p2", 5);
      e2ee().insertKeyPackage(kp("aa"));
      e2ee().putLastResortKeyPackage(kp("ab"));
      e2ee().insertKeyPackage(kp("ba", { partyId: "p2" }));
      expect(e2ee().repinParty("p1", 600)).toBeUndefined(); // no pending key
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 1, lastResort: true });
      e2ee().recordKeyChange("p1", key(2), fp("2"), 500);
      const repinned = e2ee().repinParty("p1", 600)!;
      expect(repinned).toMatchObject({ publicKey: key(2), fingerprint: fp("2"), pendingPublicKey: null, pendingFingerprint: null, keyChangedAt: null, pinnedAt: 600, updatedAt: 600 });
      expect(e2ee().getParty("p1")).toEqual(repinned);
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 0, lastResort: false });
      expect(e2ee().claimKeyPackage("p1", NOW)).toBeUndefined();
      expect(e2ee().keyPackageCounts("p2", NOW)).toEqual({ oneTime: 1, lastResort: false });
      expect(e2ee().repinParty("ghost", 600)).toBeUndefined();
    });

    test("insertKeyPackage is idempotent on ref", () => {
      pin("p1");
      expect(e2ee().insertKeyPackage(kp("aa", { bytes: bytes(1) }))).toBe(true);
      expect(e2ee().insertKeyPackage(kp("aa", { bytes: bytes(2) }))).toBe(false);
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 1, lastResort: false });
      expect(e2ee().claimKeyPackage("p1", NOW)!.bytes).toEqual(bytes(1));
    });

    test("a last-resort upload replaces the party's previous last-resort KeyPackage", () => {
      pin("p1");
      pin("p2");
      e2ee().putLastResortKeyPackage(kp("lr1", { bytes: bytes(1) }));
      e2ee().putLastResortKeyPackage(kp("lr-other", { partyId: "p2" }));
      e2ee().putLastResortKeyPackage(kp("lr2", { bytes: bytes(2) }));
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 0, lastResort: true });
      expect(e2ee().partyOfKeyPackageRef("lr1")).toBeUndefined();
      expect(e2ee().partyOfKeyPackageRef("lr2")).toBe("p1");
      expect(e2ee().claimKeyPackage("p1", NOW)).toMatchObject({ ref: "lr2", lastResort: true, bytes: bytes(2) });
      expect(e2ee().claimKeyPackage("p2", NOW)).toMatchObject({ ref: "lr-other" });
      // Re-uploading the same ref is a replacement too.
      e2ee().putLastResortKeyPackage(kp("lr2", { bytes: bytes(2), notAfter: NOW_S + 7200 }));
      expect(e2ee().claimKeyPackage("p1", NOW)).toMatchObject({ ref: "lr2", notAfter: NOW_S + 7200 });
    });

    test("claim: oldest one-time first, expired deleted and never returned, last-resort returned but not consumed", () => {
      pin("p1");
      e2ee().insertKeyPackage(kp("late", { createdAt: 300 }));
      e2ee().insertKeyPackage(kp("early-a", { createdAt: 100 }));
      e2ee().insertKeyPackage(kp("early-b", { createdAt: 100 }));
      e2ee().insertKeyPackage(kp("expired", { createdAt: 50, notAfter: NOW_S - 1 }));
      e2ee().insertKeyPackage(kp("edge", { createdAt: 400, notAfter: NOW_S })); // expires after NOW_S
      e2ee().putLastResortKeyPackage(kp("lr", { createdAt: 10 }));
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 4, lastResort: true });
      expect(e2ee().claimKeyPackage("p1", NOW)).toEqual({ ref: "early-a", partyId: "p1", bytes: bytes(1, 2, 3), lastResort: false, notAfter: NOW_S + 3600, createdAt: 100 });
      expect(e2ee().partyOfKeyPackageRef("expired")).toBeUndefined(); // purged by the claim
      expect(e2ee().claimKeyPackage("p1", NOW)!.ref).toBe("early-b");
      expect(e2ee().claimKeyPackage("p1", NOW)!.ref).toBe("late");
      expect(e2ee().claimKeyPackage("p1", NOW)!.ref).toBe("edge");
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 0, lastResort: true });
      expect(e2ee().claimKeyPackage("p1", NOW)).toMatchObject({ ref: "lr", lastResort: true });
      expect(e2ee().claimKeyPackage("p1", NOW)).toMatchObject({ ref: "lr", lastResort: true });
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 0, lastResort: true });
      // An expired last-resort KeyPackage is deleted too.
      expect(e2ee().keyPackageCounts("p1", NOW + 7_200_000)).toEqual({ oneTime: 0, lastResort: false });
      expect(e2ee().claimKeyPackage("p1", NOW + 7_200_000)).toBeUndefined();
      expect(e2ee().claimKeyPackage("ghost", NOW)).toBeUndefined();
    });

    test("claimed refs keep resolving to their party through the claims map", () => {
      pin("p1");
      pin("p2");
      e2ee().insertKeyPackage(kp("aa"));
      e2ee().insertKeyPackage(kp("bb", { partyId: "p2" }));
      expect(e2ee().partyOfKeyPackageRef("aa")).toBe("p1");
      expect(e2ee().partyOfKeyPackageRef("bb")).toBe("p2");
      expect(e2ee().claimKeyPackage("p1", NOW)!.ref).toBe("aa");
      expect(e2ee().keyPackageCounts("p1", NOW)).toEqual({ oneTime: 0, lastResort: false });
      expect(e2ee().partyOfKeyPackageRef("aa")).toBe("p1");
      expect(e2ee().partyOfKeyPackageRef("unknown")).toBeUndefined();
    });

    test("two claims never return the same one-time KeyPackage", () => {
      pin("p1");
      for (const ref of ["k1", "k2", "k3"]) {
        e2ee().insertKeyPackage(kp(ref));
      }
      const claimed = [1, 2, 3].map(() => e2ee().claimKeyPackage("p1", NOW)!.ref);
      expect(new Set(claimed).size).toBe(3);
      expect(e2ee().claimKeyPackage("p1", NOW)).toBeUndefined();
      expect(claimed.map(ref => e2ee().partyOfKeyPackageRef(ref))).toEqual(["p1", "p1", "p1"]);
    });

    test("insertScopeIfAbsent creates the scope once at epoch 0 with leaf 0 = the creator", () => {
      expect(e2ee().insertScopeIfAbsent(scope())).toBe(true);
      expect(e2ee().getScope("t1")).toEqual({ taskId: "t1", profileId: "gino-task-v1", groupId: key(7), epoch: 0, dropPublicKey: key(8), creatorPartyId: "creator", createdAt: 1_000 });
      expect(e2ee().listMembers("t1")).toEqual([{ taskId: "t1", leafIndex: 0, partyId: "creator" }]);
      expect(e2ee().isMember("t1", "creator")).toBe(true);
      expect(e2ee().isMember("t1", "other")).toBe(false);
      // Never replaced: another group id / profile / creator changes nothing.
      expect(e2ee().insertScopeIfAbsent(scope({ profileId: "other", groupId: key(1), dropPublicKey: key(2), creatorPartyId: "intruder" }))).toBe(false);
      expect(e2ee().getScope("t1")).toMatchObject({ profileId: "gino-task-v1", groupId: key(7), dropPublicKey: key(8), creatorPartyId: "creator" });
      expect(e2ee().listMembers("t1")).toEqual([{ taskId: "t1", leafIndex: 0, partyId: "creator" }]);
      expect(e2ee().getScope("t2")).toBeUndefined();
      expect(e2ee().listMembers("t2")).toEqual([]);
      // Never deleted: the repository offers no way to drop a scope.
      expect(Object.keys(e2ee()).filter(k => /delete|remove/i.test(k) && /scope/i.test(k))).toEqual([]);
    });

    test("acceptCommit appends the commit and its key-history entries contiguously and applies the whole unit", () => {
      e2ee().insertScopeIfAbsent(scope());
      e2ee().insertScopeIfAbsent(scope({ taskId: "t2" }));
      expect(e2ee().appendEntry({ taskId: "t1", expectedEpoch: 0, kind: "proposal", bytes: bytes(0xA0), submitterPartyId: "creator", acceptedAt: 4_000 })).toEqual({ ok: true, seq: 1 });
      const result = e2ee().acceptCommit(commit({
        epochLink: bytes(0x11, 0x22),
        keyHistory: [{ kind: "key_history", bytes: bytes(0xB1) }, { kind: "key_history_sealed", bytes: bytes(0xB2) }],
        welcomes: [{ partyId: "runner", bytes: bytes(0xD1) }, { partyId: "client", bytes: bytes(0xD2) }],
        add: [{ leafIndex: 1, partyId: "runner" }, { leafIndex: 2, partyId: "client" }],
      }));
      expect(result).toEqual({ ok: true, seq: 2, epoch: 1, keyHistorySeqs: [3, 4] });
      expect(e2ee().getScope("t1")).toMatchObject({ epoch: 1, dropPublicKey: key(9), groupId: key(7) });
      expect(e2ee().lastSeq("t1")).toBe(4);
      expect(e2ee().readLog("t1", 0, 10)).toEqual({
        entries: [
          { taskId: "t1", seq: 1, kind: "proposal", epoch: 0, bytes: bytes(0xA0), dropPublicKey: null, submitterPartyId: "creator", acceptedAt: 4_000 },
          { taskId: "t1", seq: 2, kind: "commit", epoch: 0, bytes: bytes(0xC0), dropPublicKey: key(9), submitterPartyId: "creator", acceptedAt: 5_000 },
          { taskId: "t1", seq: 3, kind: "key_history", epoch: 1, bytes: bytes(0xB1), dropPublicKey: null, submitterPartyId: "creator", acceptedAt: 5_000 },
          { taskId: "t1", seq: 4, kind: "key_history_sealed", epoch: 1, bytes: bytes(0xB2), dropPublicKey: null, submitterPartyId: "creator", acceptedAt: 5_000 },
        ],
        more: false,
      });
      expect(e2ee().getEpochLink("t1", 1)).toEqual(bytes(0x11, 0x22));
      expect(e2ee().listUnackedWelcomes("runner")).toMatchObject([{ taskId: "t1", partyId: "runner", seq: 2, bytes: bytes(0xD1), createdAt: 5_000, ackedAt: null }]);
      expect(e2ee().listUnackedWelcomes("client")).toMatchObject([{ seq: 2, bytes: bytes(0xD2) }]);
      expect(e2ee().listMembers("t1").map(m => [m.leafIndex, m.partyId])).toEqual([[0, "creator"], [1, "runner"], [2, "client"]]);
      // Other scopes keep their own log and seq numbering.
      expect(e2ee().lastSeq("t2")).toBe(0);
      expect(e2ee().acceptCommit(commit({ taskId: "t2" }))).toEqual({ ok: true, seq: 1, epoch: 1, keyHistorySeqs: [] });

      // Next epoch: remove a leaf, re-use it for a new party, entries continue at seq 5.
      expect(e2ee().acceptCommit(commit({ expectedEpoch: 1, bytes: bytes(0xC1), dropPublicKey: key(10), submitterPartyId: "runner", removeLeaves: [2], add: [{ leafIndex: 2, partyId: "client-2" }], acceptedAt: 6_000 })))
        .toEqual({ ok: true, seq: 5, epoch: 2, keyHistorySeqs: [] });
      expect(e2ee().listMembers("t1").map(m => [m.leafIndex, m.partyId])).toEqual([[0, "creator"], [1, "runner"], [2, "client-2"]]);
      expect(e2ee().isMember("t1", "client")).toBe(false);
      expect(e2ee().acceptCommit(commit({ expectedEpoch: 2, removeLeaves: [1, 2] }))).toMatchObject({ ok: true, seq: 6, epoch: 3 });
      expect(e2ee().listMembers("t1").map(m => m.partyId)).toEqual(["creator"]);
    });

    test("acceptCommit on epoch_conflict writes nothing and reports the current epoch", () => {
      e2ee().insertScopeIfAbsent(scope());
      e2ee().acceptCommit(commit({ add: [{ leafIndex: 1, partyId: "runner" }] }));
      const before = { scope: e2ee().getScope("t1"), log: e2ee().readLog("t1", 0, 10), members: e2ee().listMembers("t1") };
      const stale = e2ee().acceptCommit(commit({
        bytes: bytes(0xEE),
        dropPublicKey: key(0xEE),
        epochLink: bytes(0xEE),
        keyHistory: [{ kind: "key_history", bytes: bytes(0xEE) }],
        welcomes: [{ partyId: "late", bytes: bytes(0xEE) }],
        removeLeaves: [1],
        add: [{ leafIndex: 2, partyId: "late" }],
      }));
      expect(stale).toEqual({ ok: false, code: "epoch_conflict", epoch: 1 });
      expect(e2ee().acceptCommit(commit({ expectedEpoch: 5 }))).toEqual({ ok: false, code: "epoch_conflict", epoch: 1 });
      expect(e2ee().getScope("t1")).toEqual(before.scope);
      expect(e2ee().readLog("t1", 0, 10)).toEqual(before.log);
      expect(e2ee().listMembers("t1")).toEqual(before.members);
      expect(e2ee().getEpochLink("t1", 1)).toBeUndefined();
      expect(e2ee().listUnackedWelcomes("late")).toEqual([]);
      expect(e2ee().acceptCommit(commit({ taskId: "ghost" }))).toEqual({ ok: false, code: "no_scope" });
      expect(e2ee().lastSeq("ghost")).toBe(0);
    });

    test("appendEntry requires the current epoch and continues the seq", () => {
      e2ee().insertScopeIfAbsent(scope());
      e2ee().acceptCommit(commit());
      expect(e2ee().appendEntry({ taskId: "t1", expectedEpoch: 0, kind: "proposal", bytes: bytes(1), submitterPartyId: "creator" })).toEqual({ ok: false, code: "epoch_conflict", epoch: 1 });
      expect(e2ee().lastSeq("t1")).toBe(1);
      expect(e2ee().appendEntry({ taskId: "t1", expectedEpoch: 1, kind: "key_history_sealed", bytes: bytes(2), submitterPartyId: "client", acceptedAt: 9_000 })).toEqual({ ok: true, seq: 2 });
      expect(e2ee().appendEntry({ taskId: "t1", expectedEpoch: 1, kind: "key_history", bytes: bytes(3), submitterPartyId: "client" })).toEqual({ ok: true, seq: 3 });
      expect(e2ee().readLog("t1", 1, 10).entries.map(e => [e.seq, e.kind, e.epoch, e.submitterPartyId])).toEqual([[2, "key_history_sealed", 1, "client"], [3, "key_history", 1, "client"]]);
      expect(e2ee().readLog("t1", 1, 10).entries[0]!.acceptedAt).toBe(9_000);
      expect(e2ee().readLog("t1", 2, 10).entries[0]!.acceptedAt).toBeGreaterThan(0);
      expect(e2ee().appendEntry({ taskId: "ghost", expectedEpoch: 0, kind: "proposal", bytes: bytes(1), submitterPartyId: "x" })).toEqual({ ok: false, code: "no_scope" });
    });

    test("readLog / readLogFromEpoch page in seq order and report more", () => {
      e2ee().insertScopeIfAbsent(scope());
      e2ee().appendEntry({ taskId: "t1", expectedEpoch: 0, kind: "proposal", bytes: bytes(1), submitterPartyId: "creator" }); // seq 1, epoch 0
      e2ee().acceptCommit(commit({ keyHistory: [{ kind: "key_history", bytes: bytes(2) }] })); // seq 2 (epoch 0), 3 (epoch 1)
      e2ee().acceptCommit(commit({ expectedEpoch: 1 })); // seq 4, epoch 1
      e2ee().appendEntry({ taskId: "t1", expectedEpoch: 2, kind: "proposal", bytes: bytes(5), submitterPartyId: "creator" }); // seq 5, epoch 2
      const seqs = (p: { entries: { seq: number }[]; more: boolean }) => [p.entries.map(e => e.seq), p.more];
      expect(seqs(e2ee().readLog("t1", 0, 2))).toEqual([[1, 2], true]);
      expect(seqs(e2ee().readLog("t1", 2, 2))).toEqual([[3, 4], true]);
      expect(seqs(e2ee().readLog("t1", 3, 2))).toEqual([[4, 5], false]);
      expect(seqs(e2ee().readLog("t1", 5, 2))).toEqual([[], false]);
      expect(seqs(e2ee().readLogFromEpoch("t1", 0, 10))).toEqual([[1, 2, 3, 4, 5], false]);
      expect(seqs(e2ee().readLogFromEpoch("t1", 1, 10))).toEqual([[3, 4, 5], false]);
      expect(seqs(e2ee().readLogFromEpoch("t1", 1, 2))).toEqual([[3, 4], true]);
      expect(seqs(e2ee().readLogFromEpoch("t1", 2, 10))).toEqual([[5], false]);
      expect(seqs(e2ee().readLogFromEpoch("t1", 3, 10))).toEqual([[], false]);
      expect(seqs(e2ee().readLog("ghost", 0, 10))).toEqual([[], false]);
    });

    test("epoch links: the first link wins, including over a commit unit's link", () => {
      e2ee().insertScopeIfAbsent(scope());
      expect(e2ee().putEpochLinkIfAbsent("t1", 1, bytes(1, 1))).toEqual({ inserted: true, bytes: bytes(1, 1) });
      expect(e2ee().putEpochLinkIfAbsent("t1", 1, bytes(2, 2))).toEqual({ inserted: false, bytes: bytes(1, 1) });
      e2ee().acceptCommit(commit({ epochLink: bytes(3, 3) }));
      expect(e2ee().getEpochLink("t1", 1)).toEqual(bytes(1, 1));
      expect(e2ee().getEpochLink("t1", 2)).toBeUndefined();
      expect(e2ee().putEpochLinkIfAbsent("t1", 2, bytes(4))).toEqual({ inserted: true, bytes: bytes(4) });
      expect(e2ee().getEpochLink("t2", 1)).toBeUndefined();
    });

    test("welcomes: list unacked per party (and task), ack by id scoped to the party, drop on leave", () => {
      e2ee().insertScopeIfAbsent(scope());
      e2ee().insertScopeIfAbsent(scope({ taskId: "t2" }));
      e2ee().acceptCommit(commit({ welcomes: [{ partyId: "runner", bytes: bytes(1) }, { partyId: "client", bytes: bytes(2) }] }));
      e2ee().acceptCommit(commit({ taskId: "t2", welcomes: [{ partyId: "runner", bytes: bytes(3) }] }));
      const runner = e2ee().listUnackedWelcomes("runner");
      expect(runner.map(w => [w.taskId, w.bytes])).toEqual([["t1", bytes(1)], ["t2", bytes(3)]]);
      expect(runner[1]!.id).toBeGreaterThan(runner[0]!.id);
      expect(e2ee().listUnackedWelcomes("runner", "t2").map(w => w.id)).toEqual([runner[1]!.id]);
      expect(e2ee().ackWelcome("client", runner[0]!.id, 7_000)).toBe(false); // foreign party
      expect(e2ee().ackWelcome("runner", runner[0]!.id, 7_000)).toBe(true);
      expect(e2ee().listUnackedWelcomes("runner").map(w => w.taskId)).toEqual(["t2"]);
      expect(e2ee().ackWelcome("runner", 999_999, 7_000)).toBe(false);
      expect(e2ee().dropUnackedWelcomes("t1", "client")).toBe(1);
      expect(e2ee().listUnackedWelcomes("client")).toEqual([]);
      expect(e2ee().dropUnackedWelcomes("t1", "runner")).toBe(0); // acked → kept
      expect(e2ee().dropUnackedWelcomes("t2", "runner")).toBe(1);
      expect(e2ee().listUnackedWelcomes("runner")).toEqual([]);
    });

    test("delivery cursor advances only forward", () => {
      e2ee().insertScopeIfAbsent(scope());
      expect(e2ee().readDeliveryCursor("t1", "runner")).toBe(0);
      expect(e2ee().advanceDeliveryCursor("t1", "runner", 0, 1_000)).toBe(false);
      expect(e2ee().advanceDeliveryCursor("t1", "runner", 3, 1_000)).toBe(true);
      expect(e2ee().advanceDeliveryCursor("t1", "runner", 2, 2_000)).toBe(false);
      expect(e2ee().advanceDeliveryCursor("t1", "runner", 3, 2_000)).toBe(false);
      expect(e2ee().readDeliveryCursor("t1", "runner")).toBe(3);
      expect(e2ee().advanceDeliveryCursor("t1", "runner", 4, 3_000)).toBe(true);
      expect(e2ee().readDeliveryCursor("t1", "runner")).toBe(4);
      expect(e2ee().readDeliveryCursor("t1", "client")).toBe(0);
    });

    test("binary values round-trip byte for byte as plain Uint8Array and never alias caller buffers", () => {
      const all = new Uint8Array(256).map((_, i) => i);
      const input = new Uint8Array(all);
      const pk = key(0xFF);
      e2ee().pinPartyIfAbsent({ partyId: "p1", kind: "agent", publicKey: pk, fingerprint: fp("f") });
      e2ee().insertKeyPackage(kp("aa", { bytes: input }));
      e2ee().insertScopeIfAbsent(scope({ groupId: new Uint8Array(32) }));
      e2ee().acceptCommit(commit({ bytes: input, epochLink: input, welcomes: [{ partyId: "p1", bytes: input }] }));
      // Mutating the caller's buffers after the write changes nothing stored.
      input.fill(0xAA);
      pk.fill(0);
      const party = e2ee().getParty("p1")!;
      expect(party.publicKey).toEqual(key(0xFF));
      expect(party.publicKey.constructor).toBe(Uint8Array);
      const entry = e2ee().readLog("t1", 0, 1).entries[0]!;
      for (const value of [entry.bytes, e2ee().getEpochLink("t1", 1)!, e2ee().listUnackedWelcomes("p1")[0]!.bytes, e2ee().claimKeyPackage("p1", NOW)!.bytes]) {
        expect(value.constructor).toBe(Uint8Array);
        expect(value).toEqual(all);
      }
      expect(e2ee().getScope("t1")!.groupId).toEqual(new Uint8Array(32));
      // Mutating a returned buffer changes nothing stored either.
      entry.bytes.fill(0);
      party.publicKey.fill(0);
      expect(e2ee().readLog("t1", 0, 1).entries[0]!.bytes).toEqual(all);
      expect(e2ee().getParty("p1")!.publicKey).toEqual(key(0xFF));
    });
  });
}
