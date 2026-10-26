// The client helpers against an in-memory host admin API.

import type { DeviceSnapshot, SealedValue } from "../src/index";
import { beforeAll, describe, expect, test } from "bun:test";
import {
  decodeB64url,
  E2eeClient,
  E2eeClientError,
  E2eeError,
  encodeB64url,
  FieldMapEngine,
  groupId,
  Identity,
  init,
  KeyPackageStore,
  ScopeGroup,
  sealFile,
} from "../src/index";
import { BASE, FakeHost, TOKEN } from "./fake-host";

const PROFILE = "gino.task-content.v1";
const AGENT = "agent-1";
const TASK = { owner_id: "owner-1", engine: "claude", model: "sonnet" };
const text = new TextDecoder();

let engine: FieldMapEngine;

beforeAll(async () => {
  await init();
  engine = FieldMapEngine.forProfile(PROFILE);
});

/** A runner party: an identity with KeyPackages published at the host and its groups. */
class Runner {
  readonly identity = Identity.generate();
  readonly store = new KeyPackageStore();
  readonly groups = new Map<string, ScopeGroup>();

  constructor(readonly host: FakeHost, readonly agentId = AGENT) {
    host.registerAgent(agentId, this.identity.publicKey);
    host.publish(agentId, [this.store.generate(this.identity), this.store.generate(this.identity)], this.store.generate(this.identity, true));
  }

  /** Joins from its Welcome and applies the rest of the log. */
  join(taskId: string): ScopeGroup {
    const welcome = this.host.welcomes.find(w => w.partyId === this.agentId && w.task_id === taskId && !w.acked)!;
    welcome.acked = true;
    const group = ScopeGroup.join(this.store, PROFILE, taskId, decodeB64url(welcome.welcome), welcome.seq);
    this.groups.set(taskId, group);
    this.sync(taskId);
    return group;
  }

  sync(taskId: string): void {
    const group = this.groups.get(taskId)!;
    for (const entry of this.host.entries(taskId, group.seq))
      group.apply(entry);
  }

  /** Seals a transcript event and stores it as the host's transcript row. */
  reply(taskId: string, threadId: string, seq: number, data: Record<string, unknown>): void {
    const frame = { type: "thread_message", taskId, threadId, data: { seq, ...data } };
    const sealed = this.groups.get(taskId)!.sealFrame<{ data: Record<string, unknown> }>(engine, "thread_message", frame).data;
    this.thread(taskId, threadId).messages.push({
      seq,
      kind: sealed.kind,
      role: null,
      content: sealed.content ?? null,
      tool: null,
      input: sealed.input ?? null,
      output: sealed.output ?? null,
      toolUseId: null,
      parentToolUseId: null,
      createdAt: seq,
    });
  }

  result(taskId: string, threadId: string, outboxId: string, data: { result?: string; error?: string }): void {
    const frame = { type: "thread_result", taskId, threadId, outboxId, data: { status: "succeeded", ...data } };
    const sealed = this.groups.get(taskId)!.sealFrame<{ data: { result?: SealedValue; error?: SealedValue } }>(engine, "thread_result", frame).data;
    this.thread(taskId, threadId).run = { status: "succeeded", outboxId, result: sealed.result ?? null, error: sealed.error ?? null, failureReason: null, encryptionError: null };
  }

  thread(taskId: string, threadId: string) {
    const key = `${taskId}/${threadId}`;
    if (!this.host.threads.has(key))
      this.host.threads.set(key, { messages: [], run: null });
    return this.host.threads.get(key)!;
  }
}

function setup() {
  const host = new FakeHost();
  const snapshots: DeviceSnapshot[] = [];
  const options = { baseUrl: `${BASE}/`, token: TOKEN, fetch: host.fetch, onSnapshot: (s: DeviceSnapshot) => void snapshots.push(s) };
  const client = E2eeClient.create("laptop", options);
  return { host, client, snapshots, options };
}

/** An enrolled client with an encrypted task its runner joined. */
async function withRunner() {
  const ctx = setup();
  await ctx.client.enroll({ oneTime: 2 });
  const { taskId } = await ctx.client.createEncryptedTask(TASK);
  const runner = new Runner(ctx.host);
  const added = await ctx.client.addRunner(taskId, AGENT);
  runner.join(taskId);
  return { ...ctx, taskId, runner, added };
}

async function rejection(promise: Promise<unknown>): Promise<E2eeClientError> {
  try {
    await promise;
  }
  catch (error) {
    expect(error).toBeInstanceOf(E2eeClientError);
    return error as E2eeClientError;
  }
  throw new Error("no rejection");
}

describe("enroll and create", () => {
  test("enroll pins the identity key and publishes one-time and last-resort KeyPackages", async () => {
    const { host, client, snapshots } = setup();
    const { party, keyPackages } = await client.enroll({ oneTime: 3 });
    expect(party.partyId).toBe("client:laptop");
    expect(party.fingerprint).toBe(client.fingerprint);
    expect(keyPackages).toEqual({ one_time: 3, last_resort: true });
    expect(host.calls.map(c => `${c.method} ${c.path}`)).toEqual(["POST /e2ee/clients", "POST /e2ee/parties/client%3Alaptop/key-packages"]);
    expect(host.calls[0]!.body).toMatchObject({ client_id: "laptop", capability: { versions: [1], mls_suites: [1], credential: { type: "basic" } } });
    // The KeyPackage private keys were persisted before the upload.
    expect(snapshots).toHaveLength(1);
    expect(snapshots[0]!.identity).toEqual(client.identity.seed);
    for (const call of host.calls)
      expect(JSON.stringify(call.body)).not.toContain(encodeB64url(client.identity.seed));
  });

  test("createEncryptedTask mints a ULID and registers the epoch-0 group", async () => {
    const { host, client } = setup();
    await client.enroll();
    const { taskId, task } = await client.createEncryptedTask(TASK, { policy: "full" });
    expect(taskId).toMatch(/^[0-7][0-9a-hjkmnp-tv-z]{25}$/);
    const group = client.group(taskId)!;
    expect(group.epoch).toBe(0);
    expect(host.calls.at(-1)!.body).toEqual({
      ...TASK,
      id: taskId,
      e2ee: { profile_id: PROFILE, group_id: encodeB64url(groupId(PROFILE, taskId)), drop_public_key: encodeB64url(group.dropPublicKey()), creator: "client:laptop" },
    });
    expect(task.e2ee?.epoch).toBe(0);
  });

  test("a refused create keeps no group", async () => {
    const { host, client } = setup();
    host.before = (call) => {
      if (call.path === "/tasks")
        throw Object.assign(new Error("down"));
    };
    await expect(client.createEncryptedTask(TASK)).rejects.toThrow("down");
    expect(client.snapshot().groups).toEqual({});
  });
});

describe("membership", () => {
  test("addRunner claims, commits with link and Welcome, assigns; the runner opens the prompt", async () => {
    const { host, client, taskId, runner, added } = await withRunner();
    expect(added).toMatchObject({ seq: 1, epoch: 1, lastResort: false, party: { partyId: AGENT }, dispatch: { placed: true, agentId: AGENT } });
    const commit = host.calls.find(c => c.path.endsWith("/commits"))!.body as Record<string, unknown>;
    expect(commit.party_id).toBe("client:laptop");
    expect(typeof commit.welcome).toBe("string");
    expect(typeof commit.epoch_link).toBe("string");
    expect(host.tasks.get(taskId)!.agentId).toBe(AGENT);
    expect(client.group(taskId)!.epoch).toBe(1);
    expect(runner.groups.get(taskId)!.current()).toEqual(client.group(taskId)!.current());

    const sealed = client.sealPrompt(taskId, "summarize the repo");
    const frame = { type: "message", taskId, data: { text: sealed } };
    expect(runner.groups.get(taskId)!.openFrame<object>(engine, "message", frame)).toEqual({ ...frame, data: { text: "summarize the repo" } });

    const cron = client.sealCronPrompt(taskId, "daily digest");
    const cronFrame = { type: "cron_upsert", taskId, data: { prompt: cron } };
    expect(runner.groups.get(taskId)!.openFrame<{ data: { prompt: string } }>(engine, "cron_upsert", cronFrame).data.prompt).toBe("daily digest");

    await client.sendPrompt(taskId, "next", { newThread: true });
    const sent = host.calls.at(-1)!;
    expect(sent.path).toBe(`/tasks/${taskId}/message`);
    expect(sent.body).toMatchObject({ new_thread: true, text: { e2ee: expect.any(String) } });
  });

  test("addRunner without assign leaves the task unplaced", async () => {
    const { host, client } = setup();
    await client.enroll();
    const { taskId } = await client.createEncryptedTask(TASK);
    void new Runner(host);
    const added = await client.addRunner(taskId, AGENT, { assign: false });
    expect(added.dispatch).toBeUndefined();
    expect(host.tasks.get(taskId)!.agentId).toBeNull();
  });

  test("epoch_conflict: the pending commit is discarded, the group catches up and the commit is retried once", async () => {
    const { host, client, taskId, runner } = await withRunner();
    // The runner's Update lands between the client's catch-up and its submission.
    let raced = false;
    host.before = (call) => {
      if (call.path.endsWith("/commits") && !raced) {
        raced = true;
        const group = runner.groups.get(taskId)!;
        group.commitAccepted(host.commit(taskId, AGENT, group.selfUpdate(runner.identity)).seq);
      }
    };
    const rotated = await client.rotate(taskId);
    expect(rotated).toEqual({ seq: 3, epoch: 3 });
    expect(host.calls.filter(c => c.path.endsWith("/commits"))).toHaveLength(3);
    runner.sync(taskId);
    expect(runner.groups.get(taskId)!.current()).toEqual(client.group(taskId)!.current());
  });

  test("a second epoch_conflict is surfaced", async () => {
    const { host, client, taskId, runner } = await withRunner();
    host.before = (call) => {
      if (call.path.endsWith("/commits")) {
        runner.sync(taskId);
        const group = runner.groups.get(taskId)!;
        group.commitAccepted(host.commit(taskId, AGENT, group.selfUpdate(runner.identity)).seq);
      }
    };
    const error = await rejection(client.rotate(taskId));
    expect([error.code, error.status, error.details]).toEqual(["epoch_conflict", 409, { epoch: 3 }]);
    expect(client.group(taskId)!.hasPendingCommit).toBe(false);
  });

  test("a lost commit response is settled from the log", async () => {
    const { host, client, taskId } = await withRunner();
    host.after = (call) => {
      if (call.path.endsWith("/commits")) {
        host.after = undefined;
        throw new TypeError("connection reset");
      }
    };
    expect(await client.setPolicy(taskId, "from_join")).toEqual({ seq: 2, epoch: 2 });
    expect(client.group(taskId)!.policy()).toBe("from_join");
  });

  test("removeMember, rotate and setPolicy advance the epoch for every member", async () => {
    const { host, client, taskId, runner } = await withRunner();
    await client.setPolicy(taskId, { from_epoch: 1 });
    await client.rotate(taskId);
    runner.sync(taskId);
    expect(runner.groups.get(taskId)!.policy()).toEqual({ from_epoch: 1 });
    expect(runner.groups.get(taskId)!.current()).toEqual(client.group(taskId)!.current());

    expect(await client.removeMember(taskId, AGENT)).toEqual({ seq: 4, epoch: 4 });
    expect(host.calls.at(-1)).toMatchObject({ method: "POST", path: `/e2ee/scopes/${taskId}/commits` });
    runner.sync(taskId);
    expect(runner.groups.get(taskId)!.isMember).toBe(false);
    expect(client.group(taskId)!.members()).toEqual([client.identity.publicKey]);
  });

  test("key changes: a pending change refuses the claim, a key differing from the pin is refused locally", async () => {
    const { host, client } = setup();
    await client.enroll();
    const { taskId } = await client.createEncryptedTask(TASK);
    void new Runner(host);
    await client.addMember(taskId, AGENT);

    // The host re-pinned the agent to a new identity: this device pinned the old one.
    const replacement = new Runner(host);
    const error = await rejection(client.addMember(taskId, replacement.agentId));
    expect([error.code, error.status]).toEqual(["key_changed", 0]);

    host.parties.get(AGENT)!.pendingKey = encodeB64url(Identity.generate().publicKey);
    const pending = await rejection(client.addMember(taskId, AGENT));
    expect([pending.code, pending.status]).toEqual(["key_changed", 409]);
    expect(client.group(taskId)!.epoch).toBe(1);
  });

  test("a key change warning on a claim is surfaced", async () => {
    const { host, client } = setup();
    await client.enroll();
    const { taskId } = await client.createEncryptedTask(TASK);
    void new Runner(host);
    const realFetch = host.fetch;
    const options = { baseUrl: BASE, token: TOKEN, fetch: async (input: string, init: RequestInit) => {
      const response = await realFetch(input, init);
      if (!input.endsWith("/claim"))
        return response;
      const json = await response.json() as { data: { party: Record<string, unknown> } };
      json.data.party.key_change_warning = { pinned_fingerprint: "a", pending_fingerprint: "b", pending_fingerprint_display: "b", changed_at: 1 };
      return Response.json(json);
    } };
    const restored = E2eeClient.restore(client.snapshot(), options);
    const added = await restored.addMember(taskId, AGENT);
    expect(added.keyChangeWarning).toMatchObject({ pending_fingerprint: "b" });
  });

  test("join: a second device joins from its Welcome, acks it and reads history through epoch links", async () => {
    const { host, client, taskId, runner, options } = await withRunner();
    runner.reply(taskId, "th-1", 1, { kind: "assistant_text", content: "epoch one answer" });
    await client.rotate(taskId);

    const phone = E2eeClient.create("phone", options);
    expect((await rejection(phone.join(taskId))).code).toBe("no_welcome");
    await phone.enroll({ oneTime: 1 });
    await client.addMember(taskId, phone.partyId);
    const group = await phone.join(taskId);
    expect(group.epoch).toBe(3);
    expect(host.welcomes.find(w => w.partyId === phone.partyId)!.acked).toBe(true);

    const transcript = await phone.openTranscript(taskId, "th-1");
    expect(transcript[0]!.content).toEqual({ ok: true, value: "epoch one answer" });
    const links = host.calls.filter(c => c.path.includes("/links/")).map(c => c.path.split("/").at(-1));
    expect(links).toEqual(["3", "2"]);

    // Restored from its snapshot, the device keeps the recovered keys.
    const restored = E2eeClient.restore(phone.snapshot(), options);
    expect(await restored.openTranscript(taskId, "th-1")).toEqual(transcript);
    expect(host.calls.filter(c => c.path.includes("/links/"))).toHaveLength(2);
  });
});

describe("opening output", () => {
  test("transcript fields open one by one; a failure stays on its value", async () => {
    const { client, taskId, runner } = await withRunner();
    runner.reply(taskId, "th-1", 1, { kind: "assistant_text", content: "hello" });
    runner.reply(taskId, "th-1", 2, { kind: "tool_use", tool: "Bash", input: { command: "ls" } });
    runner.reply(taskId, "th-1", 3, { kind: "tool_result", output: { is_error: false, content: [{ type: "text", text: "a.txt" }] } });
    runner.reply(taskId, "th-1", 4, { kind: "host_action", input: { method: "notify", params: { to: "ops" } } });
    // A value moved to another seq no longer opens (its location binds the seq).
    const rows = runner.thread(taskId, "th-1").messages as Array<Record<string, unknown>>;
    rows.push({ ...rows[0]!, seq: 5 });

    const opened = await client.openTranscript(taskId, "th-1");
    expect(opened.map(m => m.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(opened[0]!.content).toEqual({ ok: true, value: "hello" });
    expect(opened[1]!.input).toEqual({ ok: true, value: { command: "ls" } });
    expect(opened[2]!.output).toEqual({ ok: true, value: { is_error: false, content: [{ type: "text", text: "a.txt" }] } });
    expect(opened[3]!.input).toEqual({ ok: true, value: { method: "notify", params: { to: "ops" } } });
    expect(opened[4]!.content!.ok).toBe(false);
    expect((opened[4]!.content as { error: E2eeError }).error.code).toBe("open_failed");
  });

  test("history_unavailable is reported per value when a link is absent", async () => {
    const { host, client, taskId, runner, options } = await withRunner();
    runner.reply(taskId, "th-1", 1, { kind: "assistant_text", content: "old" });
    await client.rotate(taskId);
    const phone = E2eeClient.create("phone", options);
    await phone.enroll({ oneTime: 1 });
    await client.addMember(taskId, phone.partyId);
    await phone.join(taskId);
    runner.sync(taskId);
    runner.reply(taskId, "th-1", 2, { kind: "assistant_text", content: "new" });
    host.scopes.get(taskId)!.links.delete(2);

    const opened = await phone.openTranscript(taskId, "th-1");
    expect((opened[0]!.content as { error: E2eeError }).error.toJSON()).toEqual({ code: "history_unavailable", epoch: 1 });
    expect(opened[1]!.content).toEqual({ ok: true, value: "new" });
  });

  test("openResult binds the run's outboxId", async () => {
    const { client, taskId, runner, host } = await withRunner();
    expect(await client.openResult(taskId, "th-1")).toBeNull();
    runner.result(taskId, "th-1", "01k8zz0000000000000000r001", { result: "all done" });
    expect(await client.openResult(taskId, "th-1")).toEqual({
      status: "succeeded",
      outboxId: "01k8zz0000000000000000r001",
      failureReason: null,
      encryptionError: null,
      result: { ok: true, value: "all done" },
    });
    (host.threads.get(`${taskId}/th-1`)!.run as { outboxId: string }).outboxId = "01k8zz0000000000000000r002";
    const moved = await client.openResult(taskId, "th-1");
    expect((moved!.result as { error: E2eeError }).error.code).toBe("open_failed");
  });

  test("sealAttachment seals the file and binds its name to the envelope sha256", async () => {
    const { client, taskId, runner } = await withRunner();
    const bytes = new TextEncoder().encode("attachment body");
    const sealed = client.sealAttachment(taskId, "notes.md", bytes);
    expect(sealed.uploadName).toBe(`${sealed.descriptor.sha256}.bin`);
    expect(sealed.descriptor).toMatchObject({ content_type: "application/octet-stream", size: sealed.envelope.length });
    const group = runner.groups.get(taskId)!;
    expect(text.decode(group.open(sealed.envelope, `scope:${taskId}|field:file`))).toBe("attachment body");
    const frame = { type: "message", taskId, data: { attachments: [{ name: sealed.descriptor.name, sha256: sealed.descriptor.sha256 }] } };
    expect(group.openFrame<{ data: { attachments: Array<{ name: string }> } }>(engine, "message", frame).data.attachments[0]!.name).toBe("notes.md");
    const swapped = { ...frame, data: { attachments: [{ name: sealed.descriptor.name, sha256: "0".repeat(64) }] } };
    expect(() => group.openFrame(engine, "message", swapped)).toThrow(E2eeError);
  });

  test("openOutputFile opens the name and the bytes, refusing bytes of another sha256", async () => {
    const { client, taskId, runner } = await withRunner();
    const group = runner.groups.get(taskId)!;
    const { epoch, k } = group.current();
    const file = sealFile(k, epoch, `scope:${taskId}|field:file`, new TextEncoder().encode("report body"));
    const frame = { type: "thread_result", taskId, threadId: "th-1", outboxId: "01k8zz0000000000000000r003", data: { status: "succeeded", attachments: [{ name: "report.txt", sha256: file.sha256 }] } };
    const name = group.sealFrame<{ data: { attachments: Array<{ name: SealedValue }> } }>(engine, "thread_result", frame).data.attachments[0]!.name;
    const descriptor = { taskId, threadId: "th-1", name, sha256: file.sha256 };

    const opened = await client.openOutputFile(descriptor, file.envelope);
    expect(opened.name).toEqual({ ok: true, value: "report.txt" });
    expect(opened.content.ok && text.decode(opened.content.value)).toBe("report body");

    const other = sealFile(k, epoch, `scope:${taskId}|field:file`, new TextEncoder().encode("other"));
    const refused = await client.openOutputFile(descriptor, other.envelope);
    expect(refused.name.ok).toBe(true);
    expect((refused.content as { error: E2eeError }).error.code).toBe("malformed");
  });

  test("uploadAttachment, listAttachments and downloadAttachment round-trip the envelope", async () => {
    const { client, taskId, runner, host } = await withRunner();
    const sealed = client.sealAttachment(taskId, "notes.md", new TextEncoder().encode("attachment body"));
    const descriptor = await client.uploadAttachment(taskId, sealed);
    expect(descriptor).toEqual({ ...sealed.descriptor, id: "att-1", ref: "/agent/attachments/att-1" });
    expect(host.calls.at(-1)).toMatchObject({ method: "POST", path: `/tasks/${taskId}/attachments`, body: sealed.envelope });

    const listed = await client.listAttachments(taskId, "th-1");
    expect(listed).toMatchObject([{ id: "att-1", taskId, sha256: sealed.descriptor.sha256, size: sealed.envelope.length }]);
    expect(await client.listAttachments(taskId, "th-other")).toEqual([]);
    const bytes = await client.downloadAttachment(taskId, "att-1");
    expect(bytes).toEqual(sealed.envelope);
    expect(text.decode(runner.groups.get(taskId)!.open(bytes, `scope:${taskId}|field:file`))).toBe("attachment body");

    // A runner output file opens from its listed row and downloaded bytes.
    const group = runner.groups.get(taskId)!;
    const { epoch, k } = group.current();
    const file = sealFile(k, epoch, `scope:${taskId}|field:file`, new TextEncoder().encode("report body"));
    const frame = { type: "thread_result", taskId, threadId: "th-1", data: { attachments: [{ name: "report.txt", sha256: file.sha256 }] } };
    const name = group.sealFrame<{ data: { attachments: Array<{ name: SealedValue }> } }>(engine, "thread_result", frame).data.attachments[0]!.name;
    host.attachments.push({ row: { id: "att-out", taskId, threadId: "th-1", name, contentType: "application/octet-stream", size: file.size, sha256: file.sha256, direction: "outbound", createdAt: 0 }, bytes: file.envelope });
    const output = (await client.listAttachments(taskId)).find(a => a.direction === "outbound")!;
    const opened = await client.openOutputFile(output, await client.downloadAttachment(taskId, output.id));
    expect(opened.name).toEqual({ ok: true, value: "report.txt" });
    expect(opened.content.ok && text.decode(opened.content.value)).toBe("report body");

    await expect(client.downloadAttachment(taskId, "att-missing")).rejects.toMatchObject({ status: 404, code: "NOT_FOUND" });
  });

  test("an unknown task is not_member", async () => {
    const { client } = setup();
    expect(() => client.sealPrompt("01k8zz0000000000000000t404", "x")).toThrow(E2eeError);
    await expect(client.sync("01k8zz0000000000000000t404")).rejects.toMatchObject({ code: "not_member" });
  });
});
