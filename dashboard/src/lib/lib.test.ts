import { ApiError, buildUrl, createApi, parseError } from "./api";
import { describeParams, formatBytes, formatDate, formatDuration, isTerminal, shortId } from "./format";
import { ACCESS_COOKIE, REFRESH_COOKIE, apiBaseUrl, clearedCookies, refreshTokens, secureCookies, sessionCookies } from "./session";
import { parseSse, streamEvents } from "./sse";
import { cn } from "./utils";

const json = (body: unknown, init: ResponseInit = {}) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" }, ...init });

describe("api client", () => {
  it("builds proxy URLs and drops empty query values", () => {
    expect(buildUrl("/v1/jobs", { status: "queued", project_id: undefined, before: "", limit: 5 })).toBe("/api/proxy/v1/jobs?status=queued&limit=5");
    expect(buildUrl("v1/me")).toBe("/api/proxy/v1/me");
  });

  it("parses the error envelope and falls back for non-JSON bodies", async () => {
    const err = await parseError(json({ error: { code: "depth_exhausted", message: "too deep", details: { required_depth: 3 }, request_id: "r1" } }, { status: 422 }));
    expect(err).toMatchObject({ status: 422, code: "depth_exhausted", message: "too deep", requestId: "r1" });
    expect(err.details).toEqual({ required_depth: 3 });
    const plain = await parseError(new Response("<html>", { status: 502, statusText: "Bad Gateway", headers: { "x-request-id": "h1" } }));
    expect(plain).toMatchObject({ code: "http_error", message: "Bad Gateway", requestId: "h1" });
    const empty = await parseError(new Response("", { status: 500 }));
    expect(empty.message).toBe("request failed (500)");
  });

  it("sends JSON, returns parsed bodies and undefined for 204", async () => {
    const calls: Array<[string, RequestInit]> = [];
    const fetchImpl = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push([String(url), init ?? {}]);
      return calls.length === 1 ? json({ id: "p1" }, { status: 201 }) : new Response(null, { status: 204 });
    });
    const api = createApi(fetchImpl as unknown as typeof fetch);
    await expect(api.request("v1/projects", { method: "POST", body: { name: "x" }, headers: { "Idempotency-Key": "k" } })).resolves.toEqual({ id: "p1" });
    expect(calls[0]?.[1]).toMatchObject({ method: "POST", body: '{"name":"x"}', credentials: "same-origin" });
    expect((calls[0]?.[1].headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect((calls[0]?.[1].headers as Record<string, string>)["Idempotency-Key"]).toBe("k");
    await expect(api.request("v1/x", { method: "DELETE" })).resolves.toBeUndefined();
  });

  it("throws ApiError and sends the user to login on 401", async () => {
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign, pathname: "/jobs" });
    const api = createApi((async () => json({ error: { code: "unauthorized", message: "nope" } }, { status: 401 })) as unknown as typeof fetch);
    await expect(api.request("v1/me")).rejects.toBeInstanceOf(ApiError);
    expect(assign).toHaveBeenCalledWith("/login?next=%2Fjobs");
    vi.unstubAllGlobals();
  });
});

describe("server-sent events", () => {
  it("parses events, multi-line data, comments and CRLF, keeping the remainder", () => {
    const { messages, rest } = parseSse('event: status\ndata: {"a":1}\n\n: heartbeat\n\ndata: line1\r\ndata: line2\r\n\r\nevent: partial\ndata: x');
    expect(messages).toEqual([
      { event: "status", data: '{"a":1}' },
      { event: "message", data: "line1\nline2" },
    ]);
    expect(rest).toBe("event: partial\ndata: x");
    expect(parseSse("field-without-colon\n\n").messages).toEqual([]);
  });

  it("streams chunks split across reads", async () => {
    const encoder = new TextEncoder();
    const chunks = ["event: status\nda", 'ta: {"status":"running"}\n\nevent: status\ndata: {"status":"succeeded"}\n\n'];
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        chunks.forEach((c) => controller.enqueue(encoder.encode(c)));
        controller.close();
      },
    });
    const seen: string[] = [];
    await streamEvents("/x", (m) => seen.push(JSON.parse(m.data).status), { fetchImpl: (async () => new Response(body, { status: 200 })) as unknown as typeof fetch });
    expect(seen).toEqual(["running", "succeeded"]);
    await expect(streamEvents("/x", () => undefined, { fetchImpl: (async () => new Response(null, { status: 404 })) as unknown as typeof fetch })).rejects.toThrow(/404/);
  });
});

describe("formatting", () => {
  it("formats bytes, durations, dates and ids", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(35 * 1024 * 1024)).toBe("35 MB");
    expect(formatBytes(null)).toBe("—");
    expect(formatBytes(Number.NaN)).toBe("—");
    expect(formatDuration(0.25)).toBe("250 ms");
    expect(formatDuration(12.34)).toBe("12.3 s");
    expect(formatDuration(125)).toBe("2 min 5 s");
    expect(formatDuration(undefined)).toBe("—");
    expect(formatDate(null)).toBe("—");
    expect(formatDate("not a date")).toBe("—");
    expect(formatDate("2026-11-12T10:00:00Z")).toMatch(/2026/);
    expect(shortId("01a1cf89-906e-76f2-9df7-6647b94e6927")).toBe("b94e6927");
    expect(shortId(null)).toBe("—");
  });

  it("describes parameters and terminal states", () => {
    expect(describeParams({ poly_modulus_degree: 8192, coeff_mod_bit_sizes: [60, 40, 40, 60], scale_bits: 40, security_level: 128 })).toBe(
      "N=8192 · 128-bit · 2 levels · scale 2^40",
    );
    expect(describeParams(null)).toBe("—");
    expect(isTerminal("succeeded") && isTerminal("failed") && isTerminal("cancelled")).toBe(true);
    expect(isTerminal("queued") || isTerminal("running")).toBe(false);
  });

  it("merges class names", () => {
    expect(cn("px-2", false, "px-4")).toBe("px-4");
  });
});

describe("session cookies (BFF)", () => {
  const tokens = { access_token: "a", refresh_token: "r", expires_in: 900, organization_id: "o", role: "owner" };

  it("keeps tokens in httpOnly, SameSite=Strict cookies; refresh scoped to /api", () => {
    const [access, refresh] = sessionCookies(tokens);
    expect(access).toMatchObject({ name: ACCESS_COOKIE, value: "a", options: { httpOnly: true, sameSite: "strict", path: "/" } });
    expect(refresh).toMatchObject({ name: REFRESH_COOKIE, value: "r", options: { httpOnly: true, path: "/api" } });
    expect(clearedCookies().every((c) => c.options.maxAge === 0 && c.value === "")).toBe(true);
  });

  it("marks cookies Secure in production unless explicitly disabled", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(secureCookies()).toBe(true);
    vi.stubEnv("CC_INSECURE_COOKIES", "1");
    expect(secureCookies()).toBe(false);
    vi.unstubAllEnvs();
    expect(secureCookies()).toBe(false);
  });

  it("resolves the API base URL and refreshes tokens", async () => {
    vi.stubEnv("CC_API_URL", "https://api.example.com/");
    expect(apiBaseUrl()).toBe("https://api.example.com");
    vi.unstubAllEnvs();
    expect(apiBaseUrl()).toBe("http://localhost:8000");
    const ok = await refreshTokens("r", (async () => json(tokens)) as unknown as typeof fetch);
    expect(ok?.access_token).toBe("a");
    const denied = await refreshTokens("r", (async () => json({}, { status: 401 })) as unknown as typeof fetch);
    expect(denied).toBeNull();
  });
});
