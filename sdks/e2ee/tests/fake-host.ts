// An in-memory stand-in for the host admin API the client helpers call: the
// key directory, one Delivery Service log per task and the task routes, served
// through an injected `fetch`.

import type { FetchLike } from "../src/index";
import { createHash } from "node:crypto";
import { expect } from "bun:test";
import {
  decodeB64url,
  encodeB64url,
  fingerprint,
  fingerprintDisplay,
  inspectKeyPackage,
  inspectMessage,
  welcomeRecipients,
} from "../src/index";

export const BASE = "https://host.test/api/admin";
export const TOKEN = "admin-token";

interface Party {
  publicKey: string;
  oneTime: string[];
  lastResort?: string;
  pendingKey?: string;
}

export interface LogRow {
  seq: number;
  kind: string;
  epoch: number;
  message: string;
  drop_public_key?: string;
}

interface Scope {
  epoch: number;
  log: LogRow[];
  links: Map<number, string>;
}

interface Welcome {
  id: number;
  partyId: string;
  task_id: string;
  seq: number;
  welcome: string;
  acked: boolean;
}

export interface Call {
  method: string;
  path: string;
  body: unknown;
}

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, readonly details?: unknown) {
    super(code);
  }
}

function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
}

export class FakeHost {
  readonly parties = new Map<string, Party>();
  readonly scopes = new Map<string, Scope>();
  readonly tasks = new Map<string, Record<string, unknown>>();
  readonly welcomes: Welcome[] = [];
  /** KeyPackageRef (hex) of each claimed KeyPackage → the claiming party. */
  readonly claimed = new Map<string, string>();
  /** Per task and thread: the transcript rows and run the task routes return. */
  readonly threads = new Map<string, { messages: unknown[]; run: unknown }>();
  /** Attachment rows the task routes list, with their stored bytes. */
  readonly attachments: Array<{ row: Record<string, unknown> & { id: string; taskId: string; threadId: string }; bytes: Uint8Array }> = [];
  readonly calls: Call[] = [];
  /** Runs before a route is served; throw to fail the request. */
  before: ((call: Call) => void) | undefined = undefined;
  /** Runs after a route is served; throw to lose the response. */
  after: ((call: Call) => void) | undefined = undefined;

  readonly fetch: FetchLike = async (input, init) => {
    const url = new URL(input);
    expect(url.origin + url.pathname.slice(0, "/api/admin".length)).toBe(BASE);
    expect((init.headers as Record<string, string>).authorization).toBe(`Bearer ${TOKEN}`);
    const body = init.body instanceof Uint8Array ? init.body : init.body ? JSON.parse(String(init.body)) : undefined;
    const call: Call = { method: init.method ?? "GET", path: url.pathname.slice("/api/admin".length), body };
    this.calls.push(call);
    try {
      this.before?.(call);
      const data = this.route(call, url.searchParams);
      this.after?.(call);
      if (data instanceof Uint8Array)
        return new Response(data as Uint8Array<ArrayBuffer>, { headers: { "content-type": "application/octet-stream" } });
      return Response.json({ success: true, data });
    }
    catch (error) {
      if (error instanceof HttpError)
        return Response.json({ success: false, error: { code: error.code, message: error.code, ...(error.details !== undefined ? { details: error.details } : {}) } }, { status: error.status });
      throw error;
    }
  };

  /** Registers an agent party with its pinned key (what `POST /agent/register` does). */
  registerAgent(agentId: string, publicKey: Uint8Array): void {
    this.parties.set(agentId, { publicKey: encodeB64url(publicKey), oneTime: [] });
  }

  publish(partyId: string, oneTime: Uint8Array[], lastResort?: Uint8Array): void {
    this.route({ method: "POST", path: `/e2ee/parties/${partyId}/key-packages`, body: { one_time: oneTime.map(encodeB64url), ...(lastResort ? { last_resort: encodeB64url(lastResort) } : {}) } }, new URLSearchParams());
  }

  /** Accepts a commit unit submitted outside the client (another member). */
  commit(taskId: string, partyId: string, unit: { commit: Uint8Array; dropPublicKey: Uint8Array; welcome: Uint8Array | null; epochLink: Uint8Array | null }): { seq: number; epoch: number } {
    return this.route({
      method: "POST",
      path: `/e2ee/scopes/${taskId}/commits`,
      body: {
        party_id: partyId,
        commit: encodeB64url(unit.commit),
        drop_public_key: encodeB64url(unit.dropPublicKey),
        ...(unit.welcome ? { welcome: encodeB64url(unit.welcome) } : {}),
        ...(unit.epochLink ? { epoch_link: encodeB64url(unit.epochLink) } : {}),
      },
    }, new URLSearchParams()) as { seq: number; epoch: number };
  }

  entries(taskId: string, afterSeq: number) {
    return this.scopes.get(taskId)!.log.filter(e => e.seq > afterSeq).map(e => ({
      seq: e.seq,
      kind: e.kind as "commit",
      epoch: e.epoch,
      bytes: decodeB64url(e.message),
      dropPublicKey: e.drop_public_key ? decodeB64url(e.drop_public_key) : null,
    }));
  }

  private party(partyId: string): Party {
    const party = this.parties.get(partyId);
    if (!party)
      throw new HttpError(404, "NOT_FOUND");
    return party;
  }

  private summary(partyId: string) {
    const party = this.party(partyId);
    const key = decodeB64url(party.publicKey);
    return {
      partyId,
      fingerprint: fingerprint(key),
      fingerprint_display: fingerprintDisplay(key),
      ...(party.pendingKey ? { key_change_warning: { pinned_fingerprint: fingerprint(key), pending_fingerprint: fingerprint(decodeB64url(party.pendingKey)), pending_fingerprint_display: "", changed_at: 0 } } : {}),
    };
  }

  private view(partyId: string) {
    const party = this.party(partyId);
    return {
      ...this.summary(partyId),
      kind: partyId.startsWith("client:") ? "client" : "agent",
      public_key: party.publicKey,
      capability: null,
      capable: true,
      key_packages: { one_time: party.oneTime.length, last_resort: party.lastResort !== undefined },
    };
  }

  private scope(taskId: string): Scope {
    const scope = this.scopes.get(taskId);
    if (!scope)
      throw new HttpError(404, "NOT_FOUND");
    return scope;
  }

  private route({ method, path, body }: Call, query: URLSearchParams): unknown {
    const b = (body ?? {}) as Record<string, unknown>;
    const str = (name: string) => b[name] as string;
    const parts = path.split("/").slice(1).map(decodeURIComponent);
    const at = (pattern: string) => {
      const p = pattern.split("/").slice(1);
      return p.length === parts.length && p.every((seg, i) => seg.startsWith(":") || seg === parts[i]);
    };
    const key = `${method} `;
    if (key === "POST " && at("/e2ee/clients")) {
      const partyId = `client:${str("client_id")}`;
      const existing = this.parties.get(partyId);
      if (!existing)
        this.parties.set(partyId, { publicKey: str("public_key"), oneTime: [] });
      else if (existing.publicKey !== str("public_key"))
        existing.pendingKey = str("public_key");
      return this.view(partyId);
    }
    if (key === "GET " && at("/e2ee/parties/:id"))
      return this.view(parts[2]!);
    if (key === "POST " && at("/e2ee/parties/:id/key-packages")) {
      const party = this.party(parts[2]!);
      const rejected: Array<{ code: string; index?: number }> = [];
      const valid = (kp: string) => hexOf(inspectKeyPackage(decodeB64url(kp)).publicKey) === hexOf(decodeB64url(party.publicKey));
      (b.one_time as string[] | undefined ?? []).forEach((kp, index) => (valid(kp) ? party.oneTime.push(kp) : rejected.push({ code: "malformed", index })));
      if (str("last_resort"))
        party.lastResort = str("last_resort");
      return { one_time: party.oneTime.length, last_resort: party.lastResort !== undefined, ...(rejected.length > 0 ? { rejected } : {}) };
    }
    if (key === "POST " && at("/e2ee/parties/:id/key-packages/claim")) {
      const partyId = parts[2]!;
      const party = this.party(partyId);
      if (party.pendingKey)
        throw new HttpError(409, "key_changed");
      const kp = party.oneTime.shift() ?? party.lastResort;
      if (!kp)
        throw new HttpError(409, "no_key_package");
      this.claimed.set(hexOf(inspectKeyPackage(decodeB64url(kp)).ref), partyId);
      return { key_package: kp, last_resort: kp === party.lastResort, party: this.summary(partyId) };
    }
    if (key === "GET " && at("/e2ee/parties/:id/welcomes")) {
      return this.welcomes.filter(w => w.partyId === parts[2] && !w.acked && (!query.get("task_id") || w.task_id === query.get("task_id")))
        .map(({ id, task_id, seq, welcome }) => ({ id, task_id, seq, welcome }));
    }
    if (key === "POST " && at("/e2ee/parties/:id/welcomes/:wid/ack")) {
      const welcome = this.welcomes.find(w => w.partyId === parts[2] && w.id === Number(parts[4]));
      if (!welcome)
        throw new HttpError(404, "NOT_FOUND");
      welcome.acked = true;
      return { acked: true };
    }
    if (key === "POST " && at("/e2ee/scopes/:task/commits")) {
      const scope = this.scope(parts[2]!);
      const info = inspectMessage(decodeB64url(str("commit")));
      if (info.epoch !== scope.epoch)
        throw new HttpError(409, "epoch_conflict", { epoch: scope.epoch });
      const seq = scope.log.length + 1;
      scope.log.push({ seq, kind: "commit", epoch: scope.epoch, message: str("commit"), drop_public_key: str("drop_public_key") });
      scope.epoch += 1;
      if (str("epoch_link"))
        scope.links.set(scope.epoch, str("epoch_link"));
      for (const record of (b.key_history as Array<{ kind: string; message: string }> | undefined) ?? [])
        scope.log.push({ seq: scope.log.length + 1, kind: record.kind, epoch: scope.epoch, message: record.message });
      if (str("welcome")) {
        for (const ref of welcomeRecipients(decodeB64url(str("welcome")))) {
          const partyId = this.claimed.get(hexOf(ref));
          if (partyId)
            this.welcomes.push({ id: this.welcomes.length + 1, partyId, task_id: parts[2]!, seq, welcome: str("welcome"), acked: false });
        }
      }
      return { seq, epoch: scope.epoch };
    }
    if (key === "GET " && at("/e2ee/scopes/:task/log")) {
      const scope = this.scope(parts[2]!);
      const fromEpoch = query.get("from_epoch");
      const entries = fromEpoch !== null
        ? scope.log.slice(Math.max(0, scope.log.findIndex(e => e.epoch >= Number(fromEpoch))))
        : scope.log.filter(e => e.seq > Number(query.get("after_seq") ?? 0));
      return { entries, more: false, epoch: scope.epoch };
    }
    if (key === "GET " && at("/e2ee/scopes/:task/links/:epoch")) {
      const link = this.scope(parts[2]!).links.get(Number(parts[4]));
      return link === undefined ? {} : { link };
    }
    if (key === "POST " && at("/tasks")) {
      expect(b.e2ee).toBeDefined();
      this.scopes.set(str("id"), { epoch: 0, log: [], links: new Map() });
      const task = { ...b, agentId: null, status: "pending-assignment", e2ee: { ...(b.e2ee as object), epoch: 0 } };
      this.tasks.set(str("id"), task);
      return { task, dispatch: null };
    }
    if (key === "POST " && at("/tasks/:id/assign")) {
      const task = this.tasks.get(parts[1]!)!;
      task.agentId = str("agent_id");
      return { placed: true, agentId: str("agent_id") };
    }
    if (key === "POST " && at("/tasks/:id/attachments")) {
      const bytes = body as Uint8Array;
      const sha256 = hexOf(new Uint8Array(createHash("sha256").update(bytes).digest()));
      if (query.get("sha256") !== sha256 || query.get("name") !== `${sha256}.bin`)
        throw new HttpError(400, "SHA_MISMATCH");
      const id = `att-${this.attachments.length + 1}`;
      const row = { id, taskId: parts[1]!, threadId: "th-1", name: query.get("name"), contentType: "application/octet-stream", size: bytes.length, sha256, direction: "inbound", createdAt: 0 };
      this.attachments.push({ row, bytes });
      return { id, name: row.name, content_type: row.contentType, size: row.size, sha256, ref: `/agent/attachments/${id}` };
    }
    if (key === "GET " && at("/tasks/:id/attachments"))
      return this.attachments.map(a => a.row).filter(r => r.taskId === parts[1] && (!query.get("thread") || r.threadId === query.get("thread")));
    if (key === "GET " && at("/tasks/:id/attachments/:attachmentId")) {
      const found = this.attachments.find(a => a.row.taskId === parts[1] && a.row.id === parts[3]);
      if (!found)
        throw new HttpError(404, "NOT_FOUND");
      return found.bytes;
    }
    if (key === "POST " && at("/tasks/:id/message"))
      return { threadId: "th-1", msgId: "m-1", seeded: true };
    if (key === "GET " && at("/tasks/:id")) {
      const thread = this.threads.get(`${parts[1]}/${query.get("thread")}`) ?? { messages: [], run: null };
      const after = Number(query.get("after") ?? 0);
      const limit = Number(query.get("limit") ?? 200);
      const messages = (thread.messages as Array<{ seq: number }>).filter(m => m.seq > after).slice(0, limit);
      return { threadId: query.get("thread"), run: thread.run, messages };
    }
    throw new HttpError(404, `no route ${method} ${path}`);
  }
}
