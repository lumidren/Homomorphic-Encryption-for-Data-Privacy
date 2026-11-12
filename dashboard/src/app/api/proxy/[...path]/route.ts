import { cookies } from "next/headers";
import { type NextRequest, NextResponse } from "next/server";

import { ACCESS_COOKIE, REFRESH_COOKIE, apiBaseUrl, clearedCookies, refreshTokens, sessionCookies } from "@/lib/session";

export const dynamic = "force-dynamic";

const ALLOWED_PREFIX = "v1/";
const FORWARDED_REQUEST_HEADERS = ["content-type", "idempotency-key", "accept"];
const FORWARDED_RESPONSE_HEADERS = ["content-type", "x-request-id", "retry-after", "cache-control"];

/**
 * Same-origin proxy to the API. Attaches the bearer token from the httpOnly cookie, refreshes it
 * once on 401, and streams responses through unchanged (including Server-Sent Events).
 */
async function forward(request: NextRequest, path: string[]): Promise<Response> {
  const target = path.join("/");
  if (!target.startsWith(ALLOWED_PREFIX) || target.includes("..")) {
    return NextResponse.json({ error: { code: "not_found", message: "unknown API path" } }, { status: 404 });
  }
  const jar = await cookies();
  let access = jar.get(ACCESS_COOKIE)?.value;
  const refresh = jar.get(REFRESH_COOKIE)?.value;
  const body = ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer();
  const url = `${apiBaseUrl()}/${target}${request.nextUrl.search}`;

  const send = (token: string | undefined) => {
    const headers = new Headers();
    for (const name of FORWARDED_REQUEST_HEADERS) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }
    if (token) headers.set("authorization", `Bearer ${token}`);
    return fetch(url, { method: request.method, headers, body, cache: "no-store", redirect: "manual" });
  };

  let upstream = await send(access);
  let renewed: ReturnType<typeof sessionCookies> | null = null;
  if (upstream.status === 401 && refresh) {
    const tokens = await refreshTokens(refresh);
    if (tokens) {
      access = tokens.access_token;
      renewed = sessionCookies(tokens);
      upstream = await send(access);
    } else {
      renewed = clearedCookies();
    }
  }

  const headers = new Headers();
  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = upstream.headers.get(name);
    if (value) headers.set(name, value);
  }
  if (headers.get("content-type")?.startsWith("text/event-stream")) {
    headers.set("cache-control", "no-store");
    headers.set("x-accel-buffering", "no");
  }
  const response = new NextResponse(upstream.body, { status: upstream.status, headers });
  for (const cookie of renewed ?? []) response.cookies.set(cookie.name, cookie.value, cookie.options);
  return response;
}

type Context = { params: Promise<{ path: string[] }> };

export async function GET(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}
export async function POST(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}
export async function PATCH(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}
export async function DELETE(request: NextRequest, context: Context) {
  return forward(request, (await context.params).path);
}
