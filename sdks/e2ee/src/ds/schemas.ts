// The e2ee members and frames of the wire protocol (docs/protocol.md §5.3,
// docs/e2ee/spec.md) as zod schemas. A host reuses them in its own frame
// schemas so both validate the same shapes.
import { z } from "zod";

// Each schema shares its name with its inferred type, which trips `ts/no-redeclare`.
/* eslint-disable ts/no-redeclare */

/** Binary value on the wire: base64url without padding, canonical trailing bits (e2ee spec §5.1). */
export const Base64Url = z.string().min(1).regex(/^(?:[\w-]{4})*(?:[\w-][AQgw]|[\w-]{2}[AEIMQUYcgkosw048])?$/);
/** A 32-byte value in the `Base64Url` form (43 characters). */
export const Bytes32 = z.string().regex(/^[\w-]{42}[AEIMQUYcgkosw048]$/);
/** Unsigned JSON integer (`seq`, `epoch`), at most 2^53 − 1. */
export const Uint = z.number().int().nonnegative();

/**
 * A sealed value (e2ee spec §12.4): replaces the plaintext at a mapped path
 * with an object of exactly one member, so extra members fail.
 */
export const SealedValue = z.strictObject({ e2ee: Base64Url });
export type SealedValue = z.infer<typeof SealedValue>;

/**
 * The `e2ee` capability object (e2ee spec §10). Loose: receivers ignore
 * unknown members. Whether the party is e2ee-capable (versions contain 1,
 * suites contain 1, a 32-byte key) is decided by the receiver, not here.
 */
export const E2eeCapability = z.looseObject({
  versions: z.array(z.number().int()),
  mls_suites: z.array(z.number().int()),
  credential: z.looseObject({ type: z.string(), public_key: Base64Url }),
});
export type E2eeCapability = z.infer<typeof E2eeCapability>;

/** `task_upsert.data.e2ee` — present iff the task is encrypted; never removed once set. */
export const TaskE2ee = z.looseObject({
  profile_id: z.string(),
  group_id: Bytes32,
});
export type TaskE2ee = z.infer<typeof TaskE2ee>;

/** One handshake log entry of a task's group (e2ee spec §3.1). */
export const E2eeLogEntry = z.looseObject({
  seq: Uint.min(1),
  kind: z.enum(["commit", "proposal", "key_history", "key_history_sealed"]),
  epoch: Uint,
  message: Base64Url,
  /** `commit` entries: the drop public key of epoch `epoch + 1`. */
  drop_public_key: Bytes32.optional(),
});
export type E2eeLogEntry = z.infer<typeof E2eeLogEntry>;

/** `e2ee_key_packages.data` — KeyPackages for the runner's directory entry (e2ee spec §3.5). */
export const E2eeKeyPackagesData = z.looseObject({
  one_time: z.array(Base64Url).optional(),
  last_resort: Base64Url.optional(),
});
export type E2eeKeyPackagesData = z.infer<typeof E2eeKeyPackagesData>;

/**
 * `e2ee_key_package_status.data` — the runner's pool at the host. `rejected`
 * lists KeyPackages of the answered upload the host refused: `index` into
 * its `one_time`, absent for its `last_resort`.
 */
export const E2eeKeyPackageStatusData = z.looseObject({
  one_time: Uint,
  last_resort: z.boolean(),
  rejected: z.array(z.looseObject({ code: z.string(), index: Uint.optional() })).optional(),
});
export type E2eeKeyPackageStatusData = z.infer<typeof E2eeKeyPackageStatusData>;

/** A key-history entry submitted with a commit (e2ee spec §5.7). */
const E2eeKeyHistory = z.looseObject({
  kind: z.enum(["key_history", "key_history_sealed"]),
  message: Base64Url,
});

/**
 * `e2ee_request.data` — one Delivery Service operation on the task's group
 * (e2ee spec §3.2, §3.4, §3.7), discriminated on `op`.
 */
export const E2eeRequestData = z.discriminatedUnion("op", [
  z.looseObject({ op: z.literal("log"), after_seq: Uint }),
  z.looseObject({ op: z.literal("log_from_epoch"), epoch: Uint }),
  z.looseObject({ op: z.literal("link"), epoch: Uint.min(1) }),
  z.looseObject({ op: z.literal("put_link"), epoch: Uint.min(1), link: Base64Url }),
  z.looseObject({
    op: z.literal("commit"),
    commit: Base64Url,
    drop_public_key: Bytes32,
    epoch_link: Base64Url.optional(),
    key_history: z.array(E2eeKeyHistory).optional(),
  }),
]);
export type E2eeRequestData = z.infer<typeof E2eeRequestData>;

/**
 * `e2ee_response.data` — the outcome of one `e2ee_request`. `ok: false`
 * carries `error` (`code` is a Delivery Service rejection code); otherwise
 * `entries` + `more` (log reads), `link` (link read; absent = no link), or
 * `seq` (accepted commit). `epoch` is the group's current epoch.
 */
export const E2eeResponseData = z.looseObject({
  ok: z.boolean(),
  error: z.looseObject({ code: z.string(), message: z.string().optional() }).optional(),
  entries: z.array(E2eeLogEntry).optional(),
  more: z.boolean().optional(),
  epoch: Uint.optional(),
  seq: Uint.min(1).optional(),
  link: Base64Url.optional(),
});
export type E2eeResponseData = z.infer<typeof E2eeResponseData>;

/** `e2ee_welcome.data` — a Welcome for the runner and the log `seq` of its commit. */
export const E2eeWelcomeData = z.looseObject({
  welcome: Base64Url,
  seq: Uint.min(1),
});
export type E2eeWelcomeData = z.infer<typeof E2eeWelcomeData>;
