/** A spec §11 failure code. */
export type EncryptionErrorCode
  = | "not_member"
    | "epoch_unknown"
    | "history_unavailable"
    | "link_invalid"
    | "open_failed"
    | "aad_mismatch"
    | "plaintext_rejected"
    | "unsupported_version"
    | "unsupported_suite"
    | "malformed"
    | "drop_key_mismatch"
    | "seal_failed";

/** A §11 code, or a local group condition that is not an `encryption_error`. */
export type E2eeErrorCode = EncryptionErrorCode | "log_gap" | "commit_pending" | "no_pending_commit" | "storage";

interface ErrorDetail {
  code: E2eeErrorCode;
  epoch?: number;
  expected?: number;
  got?: number;
  reason?: string;
}

/** A failure of the e2ee core. */
export class E2eeError extends Error {
  readonly code: E2eeErrorCode;
  /** The epoch involved, for the §11 codes that carry one. */
  readonly epoch: number | undefined;
  /** For `log_gap`: the next `seq` expected and the one given. */
  readonly expected: number | undefined;
  readonly got: number | undefined;
  /** For the DS inspection helpers: a short reason naming no secret. */
  readonly reason: string | undefined;

  constructor(detail: ErrorDetail) {
    super(
      detail.epoch !== undefined
        ? `${detail.code} (epoch ${detail.epoch})`
        : detail.reason !== undefined ? `${detail.code}: ${detail.reason}` : detail.code,
    );
    this.name = "E2eeError";
    this.code = detail.code;
    this.epoch = detail.epoch;
    this.expected = detail.expected;
    this.got = detail.got;
    this.reason = detail.reason;
  }

  /** The `encryption_error` object of a §11 failure. */
  toJSON(): { code: E2eeErrorCode; epoch?: number } {
    return this.epoch === undefined ? { code: this.code } : { code: this.code, epoch: this.epoch };
  }
}

function toE2eeError(error: unknown): unknown {
  if (!(error instanceof Error))
    return error;
  try {
    const detail = JSON.parse(error.message) as ErrorDetail;
    return typeof detail.code === "string" ? new E2eeError(detail) : error;
  }
  catch {
    return error;
  }
}

/** Runs a wasm call, rethrowing its failures as {@link E2eeError}. */
export function call<T>(run: () => T): T {
  try {
    return run();
  }
  catch (error) {
    throw toE2eeError(error);
  }
}
