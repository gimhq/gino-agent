/** The `fetch` the client calls; inject one bound to the host or a test double. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Where the host admin API lives and how to authenticate to it. */
export interface AdminEndpoint {
  /** The admin API root, e.g. `https://host.example/api/admin`. */
  baseUrl: string;
  /** The admin bearer token. */
  token: string;
  fetch?: FetchLike;
}

/**
 * A request the host refused (`status` and the error `code` of its
 * `{success: false, error}` envelope, `details` as sent), or a local refusal
 * of the client (`status` 0), e.g. `key_changed` for a key that differs from
 * the one pinned on this device.
 */
export class E2eeClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(code: string, message: string, status = 0, details?: unknown) {
    super(message);
    this.name = "E2eeClientError";
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

interface Envelope<T> {
  success?: boolean;
  data?: T;
  error?: { code?: string; message?: string; details?: unknown };
}

/** JSON calls to the admin API with the shared `{success, data}` envelope. */
export class AdminApi {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly fetch: FetchLike;

  constructor(endpoint: AdminEndpoint) {
    this.baseUrl = endpoint.baseUrl.replace(/\/+$/, "");
    this.token = endpoint.token;
    this.fetch = endpoint.fetch ?? ((input, init) => globalThis.fetch(input, init));
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = body !== undefined ? { "content-type": "application/json" } : {};
    return this.envelope<T>(method, path, await this.send(method, path, headers, body !== undefined ? JSON.stringify(body) : undefined));
  }

  /** Posts raw bytes; the response is the JSON envelope. */
  async postBytes<T>(path: string, bytes: Uint8Array, headers: Record<string, string> = {}): Promise<T> {
    const response = await this.send("POST", path, { "content-type": "application/octet-stream", ...headers }, bytes as Uint8Array<ArrayBuffer>);
    return this.envelope<T>("POST", path, response);
  }

  /** Gets raw bytes; a refusal is read from the error envelope. */
  async getBytes(path: string): Promise<Uint8Array> {
    const response = await this.send("GET", path, {});
    if (!response.ok)
      await this.envelope("GET", path, response);
    return new Uint8Array(await response.arrayBuffer());
  }

  private send(method: string, path: string, headers: Record<string, string>, body?: BodyInit): Promise<Response> {
    return this.fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.token}`, ...headers },
      ...(body !== undefined ? { body } : {}),
    });
  }

  /** The `data` of a `{success: true}` envelope; anything else throws `E2eeClientError`. */
  private async envelope<T>(method: string, path: string, response: Response): Promise<T> {
    const json = await response.json().catch(() => null) as Envelope<T> | null;
    if (!response.ok || json?.success !== true) {
      const error = json?.error;
      throw new E2eeClientError(
        error?.code ?? "http_error",
        error?.message ?? `${method} ${path} failed with ${response.status}`,
        response.status,
        error?.details,
      );
    }
    return json.data as T;
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  post<T>(path: string, body: unknown = {}): Promise<T> {
    return this.request<T>("POST", path, body);
  }
}

const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

/** A ULID (lower-case Crockford base32): 48-bit milliseconds, 80 random bits. */
export function ulid(now = Date.now()): string {
  let time = "";
  for (let rest = now, i = 0; i < 10; i++, rest = Math.floor(rest / 32))
    time = CROCKFORD[rest % 32] + time;
  const random = crypto.getRandomValues(new Uint8Array(16));
  let suffix = "";
  for (const byte of random)
    suffix += CROCKFORD[byte & 31];
  return time + suffix;
}
