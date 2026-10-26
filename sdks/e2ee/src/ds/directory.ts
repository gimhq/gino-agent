// The key directory of the host acting as MLS Delivery Service (e2ee spec
// §3.5, §2.7; protocol §3 `e2ee`, §5.3 KeyPackages).
//
// Per party the directory holds the pinned Ed25519 identity key, a pending key
// change, the latest valid `e2ee` capability and the KeyPackage pool. The host
// only ever handles public keys and opaque MLS bytes; every KeyPackage is
// validated by `@gino/e2ee` (OpenMLS) before it is stored. Public keys are
// logged and emitted only as fingerprints.
import type { RelayAgents, RelayDeps, RelayEventMap, RelayLogger } from "./ports";
import type { E2eePartyKind, E2eePartyRow, E2eeRepo } from "./repo";
import type { E2eeKeyPackagesData } from "./schemas";
import type { RelayWasmSource } from "./wasm";
import { decodeB64url, E2eeError, encodeB64url, fingerprint, fingerprintDisplay, inspectKeyPackage } from "@gino/e2ee";
import { sameBytes, toHex } from "./bytes";
import { RelayError, RelayNotFoundError, RelayValidationError } from "./errors";
import { E2eeCapability } from "./schemas";
import { loadRelayWasm } from "./wasm";

/** Directory party ids of clients carry this prefix; agent ids never contain `:`, so the two never collide. */
export const CLIENT_PARTY_PREFIX = "client:";

/** The directory party id of an enrolled client. */
export function clientPartyId(clientId: string): string {
  return `${CLIENT_PARTY_PREFIX}${clientId}`;
}

/** Why one uploaded KeyPackage was refused. */
export type E2eeKeyPackageRejectCode = "malformed" | "unsupported_suite" | "key_changed";

/** One refused KeyPackage of an upload: `index` into its `one_time`, absent for its `last_resort`. */
export interface E2eeKeyPackageRejection {
  code: E2eeKeyPackageRejectCode;
  index?: number;
}

/** A party's KeyPackage pool at the host, in the `e2ee_key_package_status.data` shape. */
export interface E2eeKeyPackageStatus {
  /** Unclaimed, unexpired one-time KeyPackages. */
  one_time: number;
  /** Whether a current last-resort KeyPackage is held. */
  last_resort: boolean;
  /** The refused KeyPackages of the answered upload; absent when none was refused. */
  rejected?: E2eeKeyPackageRejection[];
}

/** A KeyPackage upload: base64url `MLSMessage` KeyPackages (the `e2ee_key_packages.data` shape). */
export interface E2eeKeyPackageUpload {
  one_time?: string[] | undefined;
  last_resort?: string | undefined;
}

/** A key change awaiting an operator re-pin, shown as a warning. */
export interface E2eeKeyChangeWarning {
  /** Fingerprint of the pinned key (canonical hex). */
  pinned_fingerprint: string;
  /** Fingerprint of the new, not yet trusted key. */
  pending_fingerprint: string;
  pending_fingerprint_display: string;
  /** When the change was last seen, epoch-ms. */
  changed_at: number;
}

/** The identity summary of a party, as handed to a client adding it. */
export interface E2eePartySummary {
  partyId: string;
  /** SHA-256 of the pinned key, 64 lower-case hex characters. */
  fingerprint: string;
  /** The fingerprint in 16 groups of 4. */
  fingerprint_display: string;
  key_change_warning?: E2eeKeyChangeWarning;
}

/** One directory party as the admin surface shows it. */
export interface E2eePartyView extends E2eePartySummary {
  kind: E2eePartyKind;
  /** The pinned Ed25519 public key, base64url. */
  public_key: string;
  /** The latest valid `e2ee` capability, or `null` (a client enrolled without one). */
  capability: Record<string, unknown> | null;
  /** Whether the party is e2ee-capable (see `E2eeDirectory.isCapable`). */
  capable: boolean;
  key_packages: { one_time: number; last_resort: boolean };
  pinned_at: number;
  updated_at: number;
}

/** A claimed KeyPackage of a party (e2ee spec §3.5). */
export interface E2eeKeyPackageClaim {
  /** The KeyPackage (`MLSMessage`), base64url. */
  key_package: string;
  /** Whether it is the party's last-resort KeyPackage (returned, not consumed). */
  last_resort: boolean;
  party: E2eePartySummary;
}

/** Client enrollment: the client's own id (the party id gets the `client:` prefix) and its identity key. */
export interface E2eeClientEnrollment {
  clientId: string;
  /** The client's Ed25519 public key, base64url (32 bytes). */
  publicKey: string;
  /** The client's `e2ee` capability (e2ee spec §10); its `credential.public_key` must equal `publicKey`. */
  capability?: Record<string, unknown> | undefined;
}

/** `RelayDeps` with the defaults applied. */
interface ResolvedDeps {
  readonly repo: E2eeRepo;
  readonly agents: RelayAgents;
  readonly taskExists: (taskId: string) => boolean;
  readonly logger: RelayLogger;
  readonly emit: <K extends keyof RelayEventMap>(name: K, payload: RelayEventMap[K]) => void;
  readonly clock: () => number;
  readonly wasm: RelayWasmSource | undefined;
}

function noop(): void {}
const silent: RelayLogger = { debug: noop, info: noop, warn: noop };

interface ValidCapability {
  capability: Record<string, unknown>;
  publicKey: Uint8Array;
}

/**
 * The `e2ee` capability if it makes the party e2ee-capable (e2ee spec §10),
 * else `null`. Needs no wasm: `E2eeCapability` already checks the strict
 * base64url form of the key.
 */
function validCapability(raw: unknown): ValidCapability | null {
  const parsed = E2eeCapability.safeParse(raw);
  if (!parsed.success) {
    return null;
  }
  const { versions, mls_suites, credential } = parsed.data;
  if (!versions.includes(1) || !mls_suites.includes(1) || credential.type !== "basic") {
    return null;
  }
  const publicKey = Uint8Array.from(atob(credential.public_key.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
  return publicKey.length === 32 ? { capability: parsed.data, publicKey } : null;
}

/** `E2eeDirectory.isCapable` over the storage alone. */
export function isPartyCapable(repo: E2eeRepo, partyId: string): boolean {
  const row = repo.getParty(partyId);
  return row != null && validCapability(row.capability) != null;
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * The host's key directory: identity pinning, key-change warnings, client
 * enrollment and the KeyPackage pools.
 *
 * Party ids: an agent is its `agentId`; a client is `client:<clientId>`
 * (`clientPartyId`). Agent ids never contain `:`, so they never collide.
 *
 * Pinning: the FIRST key seen for a party is pinned. A different key is never
 * applied silently — it is recorded as a pending key change (fingerprint and
 * time), announced with `e2ee.key_changed` and a warning log, and stays
 * pending until an operator calls `repin`. While a change is pending the party
 * stays e2ee-capable and its KeyPackages under the pinned key are accepted,
 * but KeyPackages under the new key are refused (`key_changed`) and claims are
 * refused, so no client adds an unverified key.
 */
export class E2eeDirectory {
  protected readonly deps: ResolvedDeps;

  constructor(deps: RelayDeps) {
    this.deps = {
      repo: deps.repo,
      agents: deps.agents,
      taskExists: deps.taskExists,
      logger: deps.logger ?? silent,
      emit: deps.emit ?? noop,
      clock: deps.clock ?? Date.now,
      wasm: deps.wasm,
    };
  }

  protected get repo(): E2eeRepo {
    return this.deps.repo;
  }

  protected ready(): void {
    loadRelayWasm(this.deps.wasm);
  }

  /** A strict base64url 32-byte key, or `null`. */
  private decodeKey(text: string): Uint8Array | null {
    this.ready();
    try {
      const bytes = decodeB64url(text);
      return bytes.length === 32 ? bytes : null;
    }
    catch {
      return null;
    }
  }

  private summary(row: E2eePartyRow): E2eePartySummary {
    this.ready();
    const warning: E2eeKeyChangeWarning | undefined = row.pendingPublicKey && row.pendingFingerprint
      ? {
          pinned_fingerprint: row.fingerprint,
          pending_fingerprint: row.pendingFingerprint,
          pending_fingerprint_display: fingerprintDisplay(row.pendingPublicKey),
          changed_at: row.keyChangedAt ?? row.updatedAt,
        }
      : undefined;
    return {
      partyId: row.partyId,
      fingerprint: row.fingerprint,
      fingerprint_display: fingerprintDisplay(row.publicKey),
      ...(warning ? { key_change_warning: warning } : {}),
    };
  }

  private view(row: E2eePartyRow): E2eePartyView {
    const counts = this.repo.keyPackageCounts(row.partyId, this.deps.clock());
    return {
      ...this.summary(row),
      kind: row.kind,
      public_key: encodeB64url(row.publicKey),
      capability: row.capability,
      capable: validCapability(row.capability) != null,
      key_packages: { one_time: counts.oneTime, last_resort: counts.lastResort },
      pinned_at: row.pinnedAt,
      updated_at: row.updatedAt,
    };
  }

  private requireParty(partyId: string): E2eePartyRow {
    const row = this.repo.getParty(partyId);
    if (!row) {
      throw new RelayNotFoundError("e2ee party", partyId);
    }
    return row;
  }

  /**
   * Pin `publicKey` for a party under the first-key rule, store its capability
   * when given and changed, and record a key change for a key that is neither
   * the pinned nor the already pending one.
   */
  private pin(partyId: string, kind: E2eePartyKind, publicKey: Uint8Array, capability: Record<string, unknown> | null): E2eePartyRow {
    this.ready();
    const now = this.deps.clock();
    const fp = fingerprint(publicKey);
    const existing = this.repo.getParty(partyId);
    if (!existing) {
      const row = this.repo.pinPartyIfAbsent({ partyId, kind, publicKey, fingerprint: fp, capability, pinnedAt: now });
      this.deps.logger.info({ partyId, kind, fingerprint: row.fingerprint }, "e2ee identity key pinned");
      return row;
    }
    if (capability !== null && !sameJson(existing.capability, capability)) {
      this.repo.setPartyCapability(partyId, capability, now);
    }
    if (existing.fingerprint !== fp && existing.pendingFingerprint !== fp) {
      this.repo.recordKeyChange(partyId, publicKey, fp, now);
      this.deps.logger.warn(
        { partyId, kind: existing.kind, fingerprint: existing.fingerprint, pendingFingerprint: fp },
        "e2ee identity key changed — the new key is pending an operator re-pin",
      );
      this.deps.emit("e2ee.key_changed", { partyId, kind: existing.kind, fingerprint: existing.fingerprint, pendingFingerprint: fp });
    }
    return this.requireParty(partyId);
  }

  /**
   * Apply the `e2ee` capability an agent sent on `register` or `heartbeat`. A
   * valid one pins the first key, stores the capability and records a key
   * change for a different key. An absent or invalid one changes nothing.
   * The host calls this for every `register` and `heartbeat`.
   */
  observeAgentCapability(agentId: string, raw: unknown): void {
    if (raw == null) {
      return;
    }
    const valid = validCapability(raw);
    if (!valid) {
      this.deps.logger.debug({ agentId }, "e2ee capability ignored (not e2ee-capable)");
      return;
    }
    this.pin(agentId, "agent", valid.publicKey, valid.capability);
  }

  /**
   * Whether a party is e2ee-capable: a key is pinned and its latest capability
   * is valid (e2ee spec §10). A pending key change does not make a party
   * incapable. Unknown parties are not capable.
   */
  isCapable(partyId: string): boolean {
    return isPartyCapable(this.repo, partyId);
  }

  /** Every party, in enrollment order. */
  parties(): E2eePartyView[] {
    return this.repo.listParties().map(row => this.view(row));
  }

  /** One party, or `undefined`. */
  party(partyId: string): E2eePartyView | undefined {
    const row = this.repo.getParty(partyId);
    return row ? this.view(row) : undefined;
  }

  /**
   * Enroll a client (party id `client:<clientId>`) under the same first-key
   * rule as runners: the first key is pinned, a different key on a later call
   * is recorded as a pending key change. Returns the party.
   * @throws RelayValidationError a public key that is not base64url of 32 bytes, or
   * a capability that is invalid or names another key.
   */
  enrollClient(input: E2eeClientEnrollment): E2eePartyView {
    const publicKey = this.decodeKey(input.publicKey);
    if (!publicKey) {
      throw new RelayValidationError("Validation failed", { fieldErrors: { public_key: ["must be base64url of a 32-byte Ed25519 key"] } });
    }
    let capability: Record<string, unknown> | null = null;
    if (input.capability !== undefined) {
      const valid = validCapability(input.capability);
      if (!valid) {
        throw new RelayValidationError("Validation failed", { fieldErrors: { capability: ["not a valid e2ee capability"] } });
      }
      if (!sameBytes(valid.publicKey, publicKey)) {
        throw new RelayValidationError("Validation failed", { fieldErrors: { capability: ["credential.public_key does not match public_key"] } });
      }
      capability = valid.capability;
    }
    return this.view(this.pin(clientPartyId(input.clientId), "client", publicKey, capability));
  }

  /**
   * Operator re-pin: the pending key becomes the pinned key and every stored
   * KeyPackage of the party is purged (they were made under the old key).
   * Pushes a pool status to an online agent party.
   * @throws RelayNotFoundError unknown party; `RelayError` 409 `no_pending_key` when
   * no key change is pending.
   */
  repin(partyId: string): E2eePartyView {
    const before = this.requireParty(partyId);
    const row = this.repo.repinParty(partyId, this.deps.clock());
    if (!row) {
      throw new RelayError("No key change is pending for this party", 409, "no_pending_key");
    }
    this.deps.logger.info({ partyId, previousFingerprint: before.fingerprint, fingerprint: row.fingerprint }, "e2ee identity key re-pinned by operator");
    if (row.kind === "agent") {
      this.pushStatus(partyId);
    }
    return this.view(row);
  }

  /** The party's pool level (`0` / `false` for an unknown party). */
  status(partyId: string): E2eeKeyPackageStatus {
    const counts = this.repo.keyPackageCounts(partyId, this.deps.clock());
    return { one_time: counts.oneTime, last_resort: counts.lastResort };
  }

  /** Verify and store one KeyPackage; the refusal code, or `null` when stored. */
  private storeKeyPackage(party: E2eePartyRow | undefined, encoded: string, lastResort: boolean): E2eeKeyPackageRejectCode | null {
    if (!party) {
      return "malformed";
    }
    const now = this.deps.clock();
    let bytes: Uint8Array;
    let info: ReturnType<typeof inspectKeyPackage>;
    try {
      bytes = decodeB64url(encoded);
      info = inspectKeyPackage(bytes, Math.floor(now / 1000));
    }
    catch (err) {
      if (err instanceof E2eeError && err.code === "unsupported_suite") {
        return "unsupported_suite";
      }
      return "malformed";
    }
    if (!sameBytes(info.publicKey, party.publicKey)) {
      return party.pendingPublicKey ? "key_changed" : "malformed";
    }
    if (info.lastResort !== lastResort) {
      return "malformed";
    }
    const row = { ref: toHex(info.ref), partyId: party.partyId, bytes, notAfter: info.notAfter, createdAt: now };
    if (lastResort) {
      this.repo.putLastResortKeyPackage(row);
    }
    else {
      this.repo.insertKeyPackage(row);
    }
    return null;
  }

  /** Verify and store an upload; never throws for a bad KeyPackage (it is listed in `rejected`). */
  private store(partyId: string, upload: E2eeKeyPackageUpload): E2eeKeyPackageStatus {
    this.ready();
    const party = this.repo.getParty(partyId);
    const rejected: E2eeKeyPackageRejection[] = [];
    (upload.one_time ?? []).forEach((encoded, index) => {
      const code = this.storeKeyPackage(party, encoded, false);
      if (code) {
        rejected.push({ code, index });
      }
    });
    if (upload.last_resort !== undefined) {
      const code = this.storeKeyPackage(party, upload.last_resort, true);
      if (code) {
        rejected.push({ code });
      }
    }
    if (rejected.length > 0) {
      this.deps.logger.warn({ partyId, rejected }, "e2ee KeyPackages rejected");
    }
    return { ...this.status(partyId), ...(rejected.length > 0 ? { rejected } : {}) };
  }

  /**
   * Publish KeyPackages for a party (e2ee spec §3.5). Each one is validated
   * (signatures, suite `0x0001`, lifetime, capabilities, credential) and must
   * carry the party's pinned key; one-time KeyPackages must not carry
   * `last_resort` and the last-resort slot must. A new last-resort
   * KeyPackage replaces the previous one. Refusals are listed per KeyPackage:
   * `unsupported_suite`, `key_changed` (a key awaiting re-pin), else
   * `malformed`.
   * @throws RelayNotFoundError unknown party.
   */
  publishKeyPackages(partyId: string, upload: E2eeKeyPackageUpload): E2eeKeyPackageStatus {
    this.requireParty(partyId);
    return this.store(partyId, upload);
  }

  /**
   * Apply an agent's `e2ee_key_packages` frame and answer with the live-only
   * `e2ee_key_package_status` carrying `id` = the upload's `outboxId`. An
   * agent with no pinned key gets every KeyPackage rejected `malformed`.
   */
  acceptAgentKeyPackages(agentId: string, data: E2eeKeyPackagesData, outboxId?: string): void {
    const status = this.store(agentId, data);
    this.deps.agents.send(agentId, { type: "e2ee_key_package_status", ...(outboxId != null ? { id: outboxId } : {}), data: status });
  }

  /**
   * Push the live-only `e2ee_key_package_status` (no `id`, no `rejected`) to an
   * agent party if it is online. No-op for an agent the directory does not know.
   * The host calls this when an agent's socket opens.
   */
  pushStatus(agentId: string): void {
    if (!this.deps.agents.isOnline(agentId) || !this.repo.getParty(agentId)) {
      return;
    }
    this.deps.agents.send(agentId, { type: "e2ee_key_package_status", data: this.status(agentId) });
  }

  /**
   * Claim one KeyPackage of a party (e2ee spec §3.5): the oldest one-time
   * KeyPackage, deleted in the same unit so no two claims return it, else the
   * last-resort one, returned and kept. Expired KeyPackages are never
   * returned. A claim of an agent's KeyPackage pushes it a pool status.
   * @throws RelayNotFoundError unknown party; `RelayError` 409 `key_changed` while a
   * key change is pending; `RelayError` 409 `no_key_package` when the pool and
   * the last-resort slot are empty.
   */
  claimKeyPackage(partyId: string): E2eeKeyPackageClaim {
    const party = this.requireParty(partyId);
    if (party.pendingPublicKey) {
      throw new RelayError("The party's identity key changed and awaits an operator re-pin", 409, "key_changed");
    }
    const claimed = this.repo.claimKeyPackage(partyId, this.deps.clock());
    if (!claimed) {
      throw new RelayError("The party has no KeyPackage available", 409, "no_key_package");
    }
    if (party.kind === "agent") {
      this.pushStatus(partyId);
    }
    this.ready();
    return { key_package: encodeB64url(claimed.bytes), last_resort: claimed.lastResort, party: this.summary(party) };
  }
}
