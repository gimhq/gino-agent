// Keyless Delivery Service inspection through the wasm package.

import { beforeAll, describe, expect, test } from "bun:test";
import {
  E2eeError,
  Identity,
  init,
  inspectKeyPackage,
  inspectMessage,
  KeyPackageStore,
  ScopeGroup,
  welcomeRecipients,
} from "../src/index";

const PROFILE = "gino.task-content.v1";
const SCOPE = "t-1";

function errorOf(run: () => unknown): E2eeError {
  try {
    run();
  }
  catch (error) {
    expect(error).toBeInstanceOf(E2eeError);
    return error as E2eeError;
  }
  throw new Error("no error thrown");
}

function party() {
  const identity = Identity.generate();
  const keyPackages = new KeyPackageStore();
  return { identity, keyPackages, keyPackage: (lastResort = false) => keyPackages.generate(identity, lastResort) };
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

beforeAll(async () => {
  await init();
});

describe("inspectKeyPackage", () => {
  test("one-time and last-resort KeyPackages", () => {
    const alice = party();
    for (const lastResort of [false, true]) {
      const info = inspectKeyPackage(alice.keyPackage(lastResort));
      expect(info.publicKey).toEqual(alice.identity.publicKey);
      expect(info.lastResort).toBe(lastResort);
      expect(info.ref.length).toBe(32);
      expect(info.notBefore).toBeLessThanOrEqual(now());
      expect(info.notAfter).toBeGreaterThanOrEqual(now());
    }
  });

  test("the ref is the one a Welcome names", () => {
    const alice = party();
    const bob = party();
    const keyPackage = bob.keyPackage();
    const group = ScopeGroup.create(alice.identity, PROFILE, SCOPE);
    const unit = group.addMembers(alice.identity, [keyPackage]);
    expect(welcomeRecipients(unit.welcome!)).toEqual([inspectKeyPackage(keyPackage).ref]);
  });

  test("lifetime against an explicit now", () => {
    const bytes = party().keyPackage();
    const { notBefore, notAfter } = inspectKeyPackage(bytes);
    expect(inspectKeyPackage(bytes, notBefore).notAfter).toBe(notAfter);
    const early = errorOf(() => inspectKeyPackage(bytes, notBefore - 1));
    expect(early.code).toBe("malformed");
    expect(early.reason).toBe("KeyPackage not yet valid");
    expect(early.message).toBe("malformed: KeyPackage not yet valid");
    const late = errorOf(() => inspectKeyPackage(bytes, notAfter + 1));
    expect(late.code).toBe("malformed");
    expect(late.reason).toBe("KeyPackage expired");
  });

  test("bad signature, tampered, truncated and wrong suite", () => {
    const bytes = party().keyPackage();
    const badSignature = bytes.slice();
    badSignature[badSignature.length - 1]! ^= 1;
    expect(errorOf(() => inspectKeyPackage(badSignature)).code).toBe("malformed");
    const tampered = bytes.slice();
    tampered[tampered.length >> 1]! ^= 1;
    expect(errorOf(() => inspectKeyPackage(tampered)).code).toBe("malformed");
    expect(errorOf(() => inspectKeyPackage(bytes.slice(0, -1))).code).toBe("malformed");
    // version, wire_format, protocol_version, then the suite.
    const wrongSuite = bytes.slice();
    wrongSuite[7] = 0x03;
    expect(errorOf(() => inspectKeyPackage(wrongSuite)).code).toBe("unsupported_suite");
  });
});

describe("inspectMessage", () => {
  test("add, self-update and remove commits", () => {
    const alice = party();
    const bob = party();
    const carol = party();
    const bobKeyPackage = bob.keyPackage();
    const carolKeyPackage = carol.keyPackage();
    const aliceGroup = ScopeGroup.create(alice.identity, PROFILE, SCOPE);

    const add = aliceGroup.addMembers(alice.identity, [bobKeyPackage, carolKeyPackage]);
    const added = inspectMessage(add.commit);
    expect(added.groupId).toEqual(aliceGroup.groupId);
    expect(added.epoch).toBe(0);
    expect(added.contentType).toBe("commit");
    expect(added.senderLeaf).toBe(0);
    expect(added.adds).toEqual([inspectKeyPackage(bobKeyPackage).ref, inspectKeyPackage(carolKeyPackage).ref]);
    expect(added.removes).toEqual([]);
    expect(added.proposalRefs).toEqual([]);
    expect(welcomeRecipients(add.welcome!).length).toBe(2);
    aliceGroup.commitAccepted(1);

    const bobGroup = ScopeGroup.join(bob.keyPackages, PROFILE, SCOPE, add.welcome!, 1);
    const updated = inspectMessage(bobGroup.selfUpdate(bob.identity).commit);
    expect(updated.epoch).toBe(1);
    expect(updated.senderLeaf).toBe(1);
    expect(updated.updatesPath).toBe(true);
    expect(updated.adds).toEqual([]);
    expect(updated.removes).toEqual([]);

    const removed = inspectMessage(aliceGroup.removeMembers(alice.identity, [carol.identity.publicKey]).commit);
    expect(removed.senderLeaf).toBe(0);
    expect(removed.removes).toEqual([2]);
    expect(removed.adds).toEqual([]);
  });

  test("other wire formats are malformed", () => {
    const alice = party();
    const bob = party();
    const keyPackage = bob.keyPackage();
    const group = ScopeGroup.create(alice.identity, PROFILE, SCOPE);
    const unit = group.addMembers(alice.identity, [keyPackage], { fromEpoch: 0 });
    const [record] = unit.keyHistory;
    expect(record?.kind).toBe("key_history");

    const privateMessage = errorOf(() => inspectMessage(record!.bytes));
    expect(privateMessage.code).toBe("malformed");
    expect(privateMessage.reason).toBe("expected a PublicMessage, got a PrivateMessage");
    expect(errorOf(() => inspectMessage(unit.welcome!)).reason).toBe("expected a PublicMessage, got a Welcome");
    expect(errorOf(() => inspectMessage(keyPackage)).reason).toBe("expected a PublicMessage, got a KeyPackage");
    expect(errorOf(() => inspectMessage(unit.commit.slice(0, -1))).code).toBe("malformed");

    expect(errorOf(() => welcomeRecipients(unit.commit)).code).toBe("malformed");
    expect(errorOf(() => welcomeRecipients(keyPackage)).code).toBe("malformed");
  });
});
