// What the relay needs from its host: storage, the agent channel, the task
// lookup, and optionally a logger, an event sink, a clock and the wasm bytes.
import type { E2eePartyKind, E2eeRepo } from "./repo";
import type { RelayWasmSource } from "./wasm";

/** A host→agent frame the relay sends: the protocol envelope without `v`. */
export interface RelayFrame {
  type: string;
  /** The answered upload's outbox id (`e2ee_key_package_status`). */
  id?: string;
  taskId?: string;
  reqId?: string;
  data: object;
}

/** The host's agent channel (protocol §5.3 delivery). */
export interface RelayAgents {
  readonly isOnline: (agentId: string) => boolean;
  /** Push a live-only frame, best effort: never stored, never replayed. */
  readonly send: (agentId: string, frame: RelayFrame) => void;
  /**
   * Store a durable frame in the agent's outbox and push it when online. It
   * is replayed until the agent `msg_ack`s it, at which point the host calls
   * `E2eeRelay.onMessageAck` with it.
   */
  readonly enqueue: (agentId: string, frame: RelayFrame & { taskId: string }) => void;
}

/** A pino-style logger: `(fields, message)`. Only fingerprints, ids, codes and counts are logged. */
export interface RelayLogger {
  readonly debug: (fields: object, msg: string) => void;
  readonly info: (fields: object, msg: string) => void;
  readonly warn: (fields: object, msg: string) => void;
}

/** The events the relay emits, by name. */
export interface RelayEventMap {
  /** A party presented an identity key other than its pinned one; it stays pending until `repin`. */
  "e2ee.key_changed": { partyId: string; kind: E2eePartyKind; fingerprint: string; pendingFingerprint: string };
  /** A task became encrypted: its scope was created with the creator at leaf 0. */
  "e2ee.scope_registered": { taskId: string; creator: string };
  /** The Delivery Service accepted a commit: `seq` is its log position, `epoch` the new epoch. */
  "e2ee.commit": { taskId: string; seq: number; epoch: number; submitter: string; added: string[]; removed: string[] };
}

export interface RelayDeps {
  readonly repo: E2eeRepo;
  readonly agents: RelayAgents;
  /** Whether a task exists; a scope is registered for an existing task only. */
  readonly taskExists: (taskId: string) => boolean;
  readonly logger?: RelayLogger | undefined;
  readonly emit?: (<K extends keyof RelayEventMap>(name: K, payload: RelayEventMap[K]) => void) | undefined;
  /** Epoch-ms; defaults to `Date.now`. */
  readonly clock?: (() => number) | undefined;
  /** The wasm module; defaults to the file shipped with the package. */
  readonly wasm?: RelayWasmSource | undefined;
}
