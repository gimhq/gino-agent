// The relay over the in-memory repository with real MLS material: the key
// directory, scope registration, commit acceptance, delivery to runners,
// runner `e2ee_request`s and the error envelopes.

import type { E2eeCommitSubmission, RelayEventMap, RelayFrame } from "../src/ds/index";
import type { CommitUnit } from "../src/index";
import { beforeAll, beforeEach, describe, expect, it } from "bun:test";
import {
  E2EE_PROFILE_ID,
  E2eeDsError,
  E2eeRelay,
  loadRelayWasm,
  memoryE2eeRepo,
  RelayError,
  RelayNotFoundError,
  RelayValidationError,
} from "../src/ds/index";
import { encodeB64url as b64, decodeB64url, Identity, KeyPackageStore, ScopeGroup } from "../src/index";

interface Agents {
  online: Set<string>;
  sent: Array<{ agentId: string; frame: RelayFrame }>;
  queued: Array<{ agentId: string; frame: RelayFrame }>;
}

let agents: Agents;
let tasks: Set<string>;
let events: Array<{ name: keyof RelayEventMap; payload: unknown }>;
let relay: E2eeRelay;
let clients = 0;

function capability(identity: Identity): Record<string, unknown> {
  return { versions: [1], mls_suites: [1], credential: { type: "basic", public_key: b64(identity.publicKey) } };
}

function runner(agentId: string, keyPackages = 2): { identity: Identity; store: KeyPackageStore } {
  const identity = Identity.generate();
  const store = new KeyPackageStore();
  relay.observeAgentCapability(agentId, capability(identity));
  relay.publishKeyPackages(agentId, { one_time: Array.from({ length: keyPackages }, () => b64(store.generate(identity))) });
  agents.online.add(agentId);
  return { identity, store };
}

function client(): { partyId: string; identity: Identity } {
  const identity = Identity.generate();
  clients += 1;
  const { partyId } = relay.enrollClient({ clientId: `device-${clients}`, publicKey: b64(identity.publicKey) });
  return { partyId, identity };
}

function encryptedTask(taskId = "t-1"): { taskId: string; partyId: string; identity: Identity; group: ScopeGroup } {
  tasks.add(taskId);
  const { partyId, identity } = client();
  const group = ScopeGroup.create(identity, E2EE_PROFILE_ID, taskId);
  relay.registerScope(taskId, { profile_id: E2EE_PROFILE_ID, group_id: b64(group.groupId), drop_public_key: b64(group.dropPublicKey()), creator: partyId });
  return { taskId, partyId, identity, group };
}

function submission(partyId: string, unit: CommitUnit): E2eeCommitSubmission {
  return {
    party_id: partyId,
    commit: b64(unit.commit),
    drop_public_key: b64(unit.dropPublicKey),
    ...(unit.welcome ? { welcome: b64(unit.welcome) } : {}),
    ...(unit.epochLink ? { epoch_link: b64(unit.epochLink) } : {}),
    ...(unit.keyHistory.length > 0 ? { key_history: unit.keyHistory.map(k => ({ kind: k.kind, message: b64(k.bytes) })) } : {}),
  };
}

function request(agentId: string, taskId: string, data: unknown): Record<string, unknown> {
  relay.handleAgentRequest(agentId, { taskId, reqId: "r-1", data });
  const last = agents.sent.at(-1)!;
  expect(last.agentId).toBe(agentId);
  expect(last.frame).toMatchObject({ type: "e2ee_response", taskId, reqId: "r-1" });
  return last.frame.data as Record<string, unknown>;
}

beforeAll(() => {
  loadRelayWasm();
});

beforeEach(() => {
  agents = { online: new Set(), sent: [], queued: [] };
  tasks = new Set();
  events = [];
  relay = new E2eeRelay({
    repo: memoryE2eeRepo(),
    agents: {
      isOnline: id => agents.online.has(id),
      send: (agentId, frame) => void agents.sent.push({ agentId, frame }),
      enqueue: (agentId, frame) => void agents.queued.push({ agentId, frame }),
    },
    taskExists: id => tasks.has(id),
    emit: (name, payload) => void events.push({ name, payload }),
  });
});

describe("key directory", () => {
  it("pins the first key, records a key change and re-pins on the operator's call", () => {
    const first = Identity.generate();
    relay.observeAgentCapability("agent-1", capability(first));
    expect(relay.isCapable("agent-1")).toBe(true);
    const pinned = relay.party("agent-1")!;

    const second = Identity.generate();
    relay.observeAgentCapability("agent-1", capability(second));
    const changed = relay.party("agent-1")!;
    expect(changed.fingerprint).toBe(pinned.fingerprint);
    expect(changed.key_change_warning?.pinned_fingerprint).toBe(pinned.fingerprint);
    expect(events.map(e => e.name)).toEqual(["e2ee.key_changed"]);

    const refused = (() => {
      try {
        relay.claimKeyPackage("agent-1");
      }
      catch (err) {
        return err;
      }
    })();
    expect(refused).toBeInstanceOf(RelayError);
    expect((refused as RelayError).toJSON()).toEqual({ success: false, error: { code: "key_changed", message: expect.any(String) } });

    const repinned = relay.repin("agent-1");
    expect(repinned.fingerprint).toBe(changed.key_change_warning!.pending_fingerprint);
    expect(repinned.key_change_warning).toBeUndefined();
    expect(() => relay.repin("agent-1")).toThrow(RelayError);
    expect(() => relay.repin("nobody")).toThrow(RelayNotFoundError);
  });

  it("ignores an absent or invalid capability", () => {
    relay.observeAgentCapability("agent-1", undefined);
    relay.observeAgentCapability("agent-1", { versions: [2], mls_suites: [1], credential: { type: "basic", public_key: b64(new Uint8Array(32)) } });
    expect(relay.party("agent-1")).toBeUndefined();
    expect(relay.isCapable("agent-1")).toBe(false);
  });

  it("refuses a client key that is not 32 bytes with a 422 envelope", () => {
    let error: unknown;
    try {
      relay.enrollClient({ clientId: "c", publicKey: b64(new Uint8Array(16)) });
    }
    catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(RelayValidationError);
    expect((error as RelayValidationError).statusCode).toBe(422);
    expect((error as RelayValidationError).toJSON().error).toMatchObject({ code: "VALIDATION_ERROR", details: { fieldErrors: { public_key: expect.any(Array) } } });
  });

  it("stores valid KeyPackages, rejects the rest per index and answers an agent upload with its outbox id", () => {
    const { identity, store } = runner("agent-1", 0);
    relay.acceptAgentKeyPackages("agent-1", { one_time: [b64(store.generate(identity)), "AAAA"], last_resort: b64(store.generate(identity, true)) }, "out-1");
    expect(agents.sent).toEqual([{
      agentId: "agent-1",
      frame: { type: "e2ee_key_package_status", id: "out-1", data: { one_time: 1, last_resort: true, rejected: [{ code: "malformed", index: 1 }] } },
    }]);

    const claimed = relay.claimKeyPackage("agent-1");
    expect(claimed.last_resort).toBe(false);
    expect(agents.sent.at(-1)!.frame).toEqual({ type: "e2ee_key_package_status", data: { one_time: 0, last_resort: true } });
    expect(relay.claimKeyPackage("agent-1").last_resort).toBe(true);
  });
});

describe("delivery service", () => {
  it("registers a scope once, for an existing task only", () => {
    const creator = encryptedTask();
    expect(relay.scope(creator.taskId)).toMatchObject({ epoch: 0, members: [{ leaf_index: 0, party_id: creator.partyId, kind: "client" }] });
    expect(events).toContainEqual({ name: "e2ee.scope_registered", payload: { taskId: creator.taskId, creator: creator.partyId } });

    const input = { profile_id: E2EE_PROFILE_ID, group_id: b64(creator.group.groupId), drop_public_key: b64(creator.group.dropPublicKey()), creator: creator.partyId };
    expect(() => relay.registerScope("missing", input)).toThrow(RelayNotFoundError);
    let error: unknown;
    try {
      relay.registerScope(creator.taskId, input);
    }
    catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(E2eeDsError);
    expect((error as E2eeDsError).statusCode).toBe(409);
    expect((error as E2eeDsError).code).toBe("scope_exists");
  });

  it("accepts a commit adding a runner, delivers the Welcome and the log, and acks the Welcome on msg_ack", () => {
    runner("agent-1");
    const creator = encryptedTask();
    const unit = creator.group.addMembers(creator.identity, [decodeB64url(relay.claimKeyPackage("agent-1").key_package)]);
    const accepted = relay.submitCommit(creator.taskId, submission(creator.partyId, unit));
    creator.group.commitAccepted(accepted.seq);
    expect(accepted).toEqual({ seq: 1, epoch: 1 });
    expect(relay.isMember(creator.taskId, "agent-1")).toBe(true);
    expect(events.at(-1)).toEqual({ name: "e2ee.commit", payload: { taskId: creator.taskId, seq: 1, epoch: 1, submitter: creator.partyId, added: ["agent-1"], removed: [] } });

    const welcome = agents.queued.find(q => q.frame.type === "e2ee_welcome")!;
    expect(welcome).toMatchObject({ agentId: "agent-1", frame: { taskId: creator.taskId, data: { seq: 1 } } });
    expect(relay.welcomes("agent-1")).toHaveLength(1);
    relay.onMessageAck("agent-1", { type: "e2ee_log", taskId: creator.taskId, data: { seq: 1 } });
    expect(relay.welcomes("agent-1")).toHaveLength(1);
    relay.onMessageAck("agent-1", welcome.frame);
    expect(relay.welcomes("agent-1")).toEqual([]);

    // The cursor starts at the commit: the runner gets the entries after it as `e2ee_log`.
    const update = relay.submitCommit(creator.taskId, submission(creator.partyId, creator.group.selfUpdate(creator.identity)));
    expect(update).toEqual({ seq: 2, epoch: 2 });
    const logged = agents.queued.filter(q => q.frame.type === "e2ee_log").map(q => (q.frame.data as { seq: number }).seq);
    expect(logged).toEqual([2]);
  });

  it("answers runner requests and maps rejections into the response", () => {
    runner("agent-1");
    const creator = encryptedTask();
    const unit = creator.group.addMembers(creator.identity, [decodeB64url(relay.claimKeyPackage("agent-1").key_package)]);
    creator.group.commitAccepted(relay.submitCommit(creator.taskId, submission(creator.partyId, unit)).seq);

    expect(request("agent-1", creator.taskId, { op: "log", after_seq: 0 })).toMatchObject({ ok: true, epoch: 1, more: false, entries: [{ seq: 1, kind: "commit", epoch: 0 }] });
    expect(request("agent-1", creator.taskId, { op: "link", epoch: 1 })).toMatchObject({ ok: true, epoch: 1 });
    expect(request("agent-1", creator.taskId, { op: "nope" })).toEqual({ ok: false, error: { code: "malformed", message: "invalid e2ee_request" }, epoch: 1 });
    expect(request("agent-1", "unknown", { op: "log", after_seq: 0 })).toEqual({ ok: false, error: { code: "not_member", message: "unknown scope" } });
    expect(request("stranger", creator.taskId, { op: "log", after_seq: 0 })).toMatchObject({ ok: false, error: { code: "not_member" }, epoch: 1 });

    // A stale commit (epoch 0) is answered with the current epoch.
    expect(request("agent-1", creator.taskId, { op: "commit", commit: b64(unit.commit), drop_public_key: b64(unit.dropPublicKey) }))
      .toMatchObject({ ok: false, error: { code: "epoch_conflict" }, epoch: 1 });

    const before = agents.sent.length;
    relay.handleAgentRequest("agent-1", { taskId: creator.taskId, data: { op: "log", after_seq: 0 } });
    expect(agents.sent).toHaveLength(before);
  });

  it("renders a DS rejection's epoch as the envelope details", () => {
    const error = new E2eeDsError("epoch_conflict", "stale", 3);
    expect(error.toJSON()).toEqual({ success: false, error: { code: "epoch_conflict", message: "stale", details: { epoch: 3 } } });
    expect(new E2eeDsError("link_exists", "taken", undefined, "AA").toJSON().error.details).toEqual({ link: "AA" });
    expect(new E2eeDsError("malformed", "bad").toJSON().error).toEqual({ code: "malformed", message: "bad" });
  });
});
