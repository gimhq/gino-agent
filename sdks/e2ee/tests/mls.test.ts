// MLS scope groups through the wasm package, against an in-memory DS log.

import type { CommitUnit, LogEntry } from "../src/index";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  E2eeError,
  FieldMapEngine,
  Identity,
  init,
  KeyPackageStore,
  ScopeGroup,
  withEpochLinks,
} from "../src/index";

const PROFILE = "gino.task-content.v1";
const SCOPE = "t-1";
const LOCATION = `scope:${SCOPE}|frame:message|field:text`;
const text = new TextEncoder();

/** The DS of one scope: the handshake log and the epoch links. */
class Ds {
  readonly log: LogEntry[] = [];
  readonly links = new Map<number, Uint8Array>();

  /** Accepts a commit unit and returns the `seq` of its commit. */
  accept(unit: CommitUnit): number {
    const seq = this.log.length + 1;
    this.log.push({ seq, kind: "commit", epoch: unit.epoch, bytes: unit.commit, dropPublicKey: unit.dropPublicKey });
    if (unit.epochLink !== null)
      this.links.set(unit.epoch + 1, unit.epochLink);
    for (const record of unit.keyHistory)
      this.log.push({ seq: this.log.length + 1, kind: record.kind, epoch: unit.epoch + 1, bytes: record.bytes });
    return seq;
  }

  /** Applies every entry after the member's `seq`. */
  catchUp(group: ScopeGroup): void {
    for (const entry of this.log.slice(group.seq))
      group.apply(entry);
  }
}

function codeOf(run: () => unknown): unknown {
  try {
    run();
    return null;
  }
  catch (error) {
    expect(error).toBeInstanceOf(E2eeError);
    return (error as E2eeError).toJSON();
  }
}

/** Alice creates the scope's group and adds Bob. */
function twoMembers(policy: "full" | "from_join" = "full") {
  const ds = new Ds();
  const alice = Identity.generate();
  const bob = Identity.generate();
  const aliceGroup = ScopeGroup.create(alice, PROFILE, SCOPE, policy);
  const epoch0 = aliceGroup.sealContent(LOCATION, text.encode("before bob"));
  const bobKeyPackages = new KeyPackageStore();
  const unit = aliceGroup.addMembers(alice, [bobKeyPackages.generate(bob)]);
  const seq = ds.accept(unit);
  aliceGroup.commitAccepted(seq);
  const bobGroup = ScopeGroup.join(bobKeyPackages, PROFILE, SCOPE, unit.welcome!, seq);
  return { ds, alice, bob, aliceGroup, bobGroup, epoch0, unit };
}

beforeAll(async () => {
  await init();
});

describe("scope group", () => {
  test("create, add a member, both export the same k_e and drop key", () => {
    const { aliceGroup, bobGroup, unit, alice, bob } = twoMembers();
    expect(aliceGroup.epoch).toBe(1);
    expect(bobGroup.epoch).toBe(1);
    expect(bobGroup.seq).toBe(1);
    expect(bobGroup.current()).toEqual(aliceGroup.current());
    expect(bobGroup.dropPublicKey()).toEqual(unit.dropPublicKey);
    expect(aliceGroup.dropPublicKey()).toEqual(unit.dropPublicKey);
    expect(bobGroup.members()).toEqual([alice.publicKey, bob.publicKey]);
    expect(bobGroup.groupId).toEqual(aliceGroup.groupId);
    expect(bobGroup.policy()).toBe("full");
  });

  test("seal and open content and a field-mapped frame", () => {
    const { aliceGroup, bobGroup } = twoMembers();
    const envelope = aliceGroup.sealContent(LOCATION, text.encode("hello"));
    expect(new TextDecoder().decode(bobGroup.open(envelope, LOCATION))).toBe("hello");

    const engine = FieldMapEngine.forProfile(PROFILE);
    const frame = { type: "message", taskId: SCOPE, data: { text: "summarize" } };
    const sealed = aliceGroup.sealFrame<{ data: { text: { e2ee: string } } }>(engine, "message", frame);
    expect(typeof sealed.data.text.e2ee).toBe("string");
    expect(bobGroup.openFrame<typeof frame>(engine, "message", sealed)).toEqual(frame);
    expect(codeOf(() => bobGroup.openFrame(engine, "message", frame))).toEqual({ code: "plaintext_rejected" });
  });

  test("history before the join through epoch links, a missing link is history_unavailable", async () => {
    const { ds, bobGroup, epoch0 } = twoMembers();
    expect(codeOf(() => bobGroup.open(epoch0, LOCATION))).toEqual({ code: "history_unavailable", epoch: 0 });

    const fetched: number[] = [];
    const opened = await withEpochLinks(bobGroup, async (epoch) => {
      fetched.push(epoch);
      return ds.links.get(epoch) ?? null;
    }, () => bobGroup.open(epoch0, LOCATION));
    expect(new TextDecoder().decode(opened)).toBe("before bob");
    expect(fetched).toEqual([1]);
  });

  test("from_join writes no link; key history sealed to the joiner's leaf restores it", () => {
    const ds = new Ds();
    const alice = Identity.generate();
    const aliceGroup = ScopeGroup.create(alice, PROFILE, SCOPE, "from_join");
    const epoch0 = aliceGroup.sealContent(LOCATION, text.encode("old"));

    const carol = Identity.generate();
    const carolStore = new KeyPackageStore();
    const unit = aliceGroup.addMembers(alice, [carolStore.generate(carol)], { fromEpoch: 0, sealed: true });
    expect(unit.epochLink).toBeNull();
    expect(unit.keyHistory.map(r => r.kind)).toEqual(["key_history_sealed"]);
    const seq = ds.accept(unit);
    aliceGroup.commitAccepted(seq);
    ds.catchUp(aliceGroup);

    const carolGroup = ScopeGroup.join(carolStore, PROFILE, SCOPE, unit.welcome!, seq);
    ds.catchUp(carolGroup);
    expect(new TextDecoder().decode(carolGroup.open(epoch0, LOCATION))).toBe("old");

    const dave = Identity.generate();
    const daveStore = new KeyPackageStore();
    const daveUnit = aliceGroup.addMembers(alice, [daveStore.generate(dave)]);
    const daveSeq = ds.accept(daveUnit);
    aliceGroup.commitAccepted(daveSeq);
    ds.catchUp(carolGroup);
    const daveGroup = ScopeGroup.join(daveStore, PROFILE, SCOPE, daveUnit.welcome!, daveSeq);
    expect(codeOf(() => daveGroup.open(epoch0, LOCATION))).toEqual({ code: "history_unavailable", epoch: 0 });
  });

  test("self-update and removal in DS order", () => {
    const { ds, alice, bob, aliceGroup, bobGroup } = twoMembers();
    const update = bobGroup.selfUpdate(bob);
    expect(bobGroup.hasPendingCommit).toBe(true);
    bobGroup.commitAccepted(ds.accept(update));
    ds.catchUp(aliceGroup);
    expect(aliceGroup.epoch).toBe(2);
    expect(aliceGroup.current()).toEqual(bobGroup.current());
    const epoch2 = aliceGroup.sealContent(LOCATION, text.encode("epoch 2"));

    const removal = aliceGroup.removeMembers(alice, [bob.publicKey]);
    aliceGroup.commitAccepted(ds.accept(removal));
    expect(bobGroup.apply(ds.log.at(-1)!)).toEqual({ type: "commit", epoch: 3, selfRemoved: true });
    expect(bobGroup.isMember).toBe(false);
    expect(aliceGroup.members()).toEqual([alice.publicKey]);

    const epoch3 = aliceGroup.sealContent(LOCATION, text.encode("after removal"));
    expect(codeOf(() => bobGroup.open(epoch3, LOCATION))).toEqual({ code: "epoch_unknown", epoch: 3 });
    expect(new TextDecoder().decode(bobGroup.open(epoch2, LOCATION))).toBe("epoch 2");
    expect(codeOf(() => bobGroup.current())).toEqual({ code: "not_member" });
  });

  test("a concurrent commit discards the pending one", () => {
    const { ds, alice, bob, aliceGroup, bobGroup } = twoMembers();
    aliceGroup.selfUpdate(alice);
    bobGroup.commitAccepted(ds.accept(bobGroup.selfUpdate(bob)));
    expect(codeOf(() => aliceGroup.selfUpdate(alice))).toEqual({ code: "commit_pending" });
    ds.catchUp(aliceGroup);
    expect(aliceGroup.hasPendingCommit).toBe(false);
    expect(aliceGroup.current()).toEqual(bobGroup.current());
    expect(codeOf(() => aliceGroup.commitRejected())).toEqual({ code: "no_pending_commit" });
  });

  test("snapshot and restore", () => {
    const { ds, alice, aliceGroup, bobGroup, epoch0 } = twoMembers();
    const restored = ScopeGroup.restore(aliceGroup.snapshot());
    expect(restored.epoch).toBe(1);
    expect(restored.seq).toBe(1);
    expect(restored.current()).toEqual(aliceGroup.current());
    expect(new TextDecoder().decode(restored.open(epoch0, LOCATION))).toBe("before bob");

    restored.commitAccepted(ds.accept(restored.selfUpdate(alice)));
    ds.catchUp(bobGroup);
    expect(bobGroup.current()).toEqual(restored.current());

    const store = new KeyPackageStore();
    store.generate(Identity.generate(), true);
    expect(KeyPackageStore.restore(store.snapshot()).snapshot()).toEqual(store.snapshot());
    expect(codeOf(() => ScopeGroup.restore(new Uint8Array([1, 2, 3])))).toEqual({ code: "storage" });
  });

  test("log gaps and identities", () => {
    const { ds, bob, bobGroup } = twoMembers();
    const entry = { ...ds.log[0]!, seq: 5 };
    expect(() => bobGroup.apply(entry)).toThrow(E2eeError);
    try {
      bobGroup.apply(entry);
    }
    catch (error) {
      expect(error).toMatchObject({ code: "log_gap", expected: 2, got: 5 });
    }
    expect(bobGroup.apply(ds.log[0]!)).toEqual({ type: "replayed" });
    expect(Identity.fromSeed(bob.seed).publicKey).toEqual(bob.publicKey);
    expect(codeOf(() => Identity.fromSeed(new Uint8Array(31)))).toEqual({ code: "malformed" });
  });
});
