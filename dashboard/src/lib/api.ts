/** Browser-side API client. Every call goes to the same-origin /api/proxy; no tokens in JS. */

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
    readonly requestId?: string | null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type FetchLike = typeof fetch;

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Record<string, string | number | undefined | null>;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const clean = path.replace(/^\/+/, "");
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const qs = params.toString();
  return `/api/proxy/${clean}${qs ? `?${qs}` : ""}`;
}

export async function parseError(response: Response): Promise<ApiError> {
  let code = "http_error";
  let message = response.statusText || `request failed (${response.status})`;
  let details: unknown;
  let requestId: string | null = response.headers.get("x-request-id");
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string; details?: unknown; request_id?: string } };
    if (body.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      details = body.error.details;
      requestId = body.error.request_id ?? requestId;
    }
  } catch {
    // non-JSON error body: keep the HTTP status text
  }
  return new ApiError(response.status, code, message, details, requestId);
}

export function createApi(fetchImpl: FetchLike = (...args) => fetch(...args)) {
  async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json", ...options.headers };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetchImpl(buildUrl(path, options.query), {
      method: options.method ?? "GET",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      signal: options.signal,
    });
    if (response.status === 401 && typeof window !== "undefined") {
      window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
    }
    if (!response.ok) throw await parseError(response);
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }
  return { request };
}

export const api = createApi();
