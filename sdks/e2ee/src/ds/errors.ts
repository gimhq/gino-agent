// The errors the relay throws. Each carries the HTTP status and the stable
// `code` a host renders, and `toJSON()` renders the error envelope.

/** The JSON error envelope of a relay error. */
export interface RelayErrorBody {
  success: false;
  error: { code: string; message: string; details?: unknown };
}

/**
 * Base class of every error the relay throws deliberately. `statusCode` is the
 * HTTP status a host should answer with, `code` the identifier a client matches
 * on and `details` (when set) is rendered into the envelope verbatim.
 */
export class RelayError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly code: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "RelayError";
  }

  toJSON(): RelayErrorBody {
    return {
      success: false,
      error: { code: this.code, message: this.message, ...(this.details !== undefined ? { details: this.details } : {}) },
    };
  }
}

/** `404` / `NOT_FOUND` — the addressed party, task, scope or Welcome does not exist. */
export class RelayNotFoundError extends RelayError {
  constructor(resource: string, id?: string) {
    super(id ? `${resource} ${id} not found` : `${resource} not found`, 404, "NOT_FOUND");
    this.name = "RelayNotFoundError";
  }
}

/** `422` / `VALIDATION_ERROR` — the input is well-formed but not acceptable; `details` names the fields. */
export class RelayValidationError extends RelayError {
  constructor(message: string, details: unknown) {
    super(message, 422, "VALIDATION_ERROR", details);
    this.name = "RelayValidationError";
  }
}

/** Delivery Service rejection codes (e2ee spec §3.8) the relay raises. */
export type E2eeDsCode = "epoch_conflict" | "link_exists" | "malformed" | "not_member" | "scope_exists";

const DS_STATUS: Record<E2eeDsCode, number> = {
  epoch_conflict: 409,
  link_exists: 409,
  scope_exists: 409,
  not_member: 403,
  malformed: 422,
};

/**
 * A Delivery Service rejection. `code` is the DS code; `epoch` (the current
 * epoch, `epoch_conflict`) and `link` (the stored record, base64url,
 * `link_exists`) are rendered as the error envelope's `details`.
 */
export class E2eeDsError extends RelayError {
  constructor(
    public readonly dsCode: E2eeDsCode,
    message: string,
    public readonly epoch?: number,
    public readonly link?: string,
  ) {
    super(message, DS_STATUS[dsCode], dsCode, epoch !== undefined ? { epoch } : link !== undefined ? { link } : undefined);
    this.name = "E2eeDsError";
  }
}
