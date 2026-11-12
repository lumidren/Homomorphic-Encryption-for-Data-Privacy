import { cookies } from "next/headers";
import { type NextRequest, NextResponse } from "next/server";

import { ACCESS_COOKIE, REFRESH_COOKIE, type TokenPair, apiBaseUrl, clearedCookies, sessionCookies } from "@/lib/session";

export const dynamic = "force-dynamic";

const MODES = { login: "/v1/auth/login", register: "/v1/auth/register" } as const;

/** Log in or register; the tokens become httpOnly cookies and are never returned to the browser. */
export async function POST(request: NextRequest) {
  const mode = request.nextUrl.searchParams.get("mode") === "register" ? "register" : "login";
  const upstream = await fetch(`${apiBaseUrl()}${MODES[mode]}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: await request.text(),
    cache: "no-store",
  });
  const payload = (await upstream.json()) as TokenPair | { error: unknown };
  if (!upstream.ok || !("access_token" in payload)) {
    return NextResponse.json(payload, { status: upstream.status });
  }
  const response = NextResponse.json({ organization_id: payload.organization_id, role: payload.role }, { status: upstream.status });
  for (const cookie of sessionCookies(payload)) response.cookies.set(cookie.name, cookie.value, cookie.options);
  return response;
}

/** Log out: revoke the refresh family and deny-list the access token server-side, clear cookies. */
export async function DELETE() {
  const jar = await cookies();
  const access = jar.get(ACCESS_COOKIE)?.value;
  const refresh = jar.get(REFRESH_COOKIE)?.value;
  if (access) {
    await fetch(`${apiBaseUrl()}/v1/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${access}` },
      body: JSON.stringify({ refresh_token: refresh ?? null }),
      cache: "no-store",
    }).catch(() => undefined);
  }
  const response = new NextResponse(null, { status: 204 });
  for (const cookie of clearedCookies()) response.cookies.set(cookie.name, cookie.value, cookie.options);
  return response;
}
