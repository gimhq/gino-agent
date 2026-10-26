// Delivery of a group's Delivery Service records to its runners (protocol §5.3
// "Delivery to the runner").
//
// Every agent party holding a leaf of a task's group receives the group's
// handshake log as durable host→agent frames through the outbox: an
// `e2ee_welcome` when it joins, then one `e2ee_log` per entry in `seq` order.
// The `(taskId, agentId)` delivery cursor records the last `seq` enqueued, so
// each entry is enqueued once per agent; the outbox replays unacked frames on
// reconnect, so the agent need not be online.
import type { RelayAgents } from "./ports";
import type { E2eeLogEntryRow, E2eeRepo } from "./repo";
import type { E2eeLogEntry } from "./schemas";
import { encodeB64url } from "@gino/e2ee";

/** Page size of log reads (runner requests, client reads, delivery). */
export const E2EE_LOG_PAGE_LIMIT = 100;

export interface DeliveryDeps {
  readonly repo: E2eeRepo;
  readonly agents: RelayAgents;
  readonly clock: () => number;
}

/** A durable frame the agent acknowledged with `msg_ack`. */
export interface AckedFrame {
  type: string;
  taskId?: string | null | undefined;
  data: unknown;
}

/** A stored log entry in the wire shape of `e2ee_log.data` / `e2ee_response.entries[]`. */
export function logEntryData(row: E2eeLogEntryRow): E2eeLogEntry {
  return {
    seq: row.seq,
    kind: row.kind,
    epoch: row.epoch,
    message: encodeB64url(row.bytes),
    ...(row.dropPublicKey ? { drop_public_key: encodeB64url(row.dropPublicKey) } : {}),
  };
}

/**
 * Enqueue an `e2ee_welcome` for an agent joining at the commit `seq` and
 * start its cursor there, so the entries after the commit follow the Welcome.
 */
export function deliverWelcome(deps: DeliveryDeps, taskId: string, agentId: string, seq: number, welcome: Uint8Array): void {
  deps.agents.enqueue(agentId, { type: "e2ee_welcome", taskId, data: { welcome: encodeB64url(welcome), seq } });
  deps.repo.advanceDeliveryCursor(taskId, agentId, seq, deps.clock());
}

/** Enqueue the entries after the agent's cursor, up to `untilSeq` when given, advancing the cursor per entry. */
export function deliverLog(deps: DeliveryDeps, taskId: string, agentId: string, untilSeq = Number.MAX_SAFE_INTEGER): void {
  const { repo } = deps;
  let cursor = repo.readDeliveryCursor(taskId, agentId);
  while (cursor < untilSeq) {
    const page = repo.readLog(taskId, cursor, E2EE_LOG_PAGE_LIMIT);
    for (const row of page.entries) {
      if (row.seq > untilSeq) {
        return;
      }
      deps.agents.enqueue(agentId, { type: "e2ee_log", taskId, data: logEntryData(row) });
      repo.advanceDeliveryCursor(taskId, agentId, row.seq, deps.clock());
      cursor = row.seq;
    }
    if (!page.more) {
      return;
    }
  }
}

/** Mark the Welcome behind an acked `e2ee_welcome` frame acked. No-op for any other frame. */
export function ackWelcomeFrame(deps: DeliveryDeps, agentId: string, frame: AckedFrame): void {
  if (frame.type !== "e2ee_welcome" || frame.taskId == null) {
    return;
  }
  const seq = (frame.data as { seq?: unknown } | null)?.seq;
  for (const welcome of deps.repo.listUnackedWelcomes(agentId, frame.taskId)) {
    if (welcome.seq === seq) {
      deps.repo.ackWelcome(agentId, welcome.id, deps.clock());
    }
  }
}
