/**
 * Server-only session handling (backend-for-frontend).
 *
 * The API issues JSON tokens. The dashboard never hands them to browser JavaScript: they live in
 * httpOnly, SameSite=Strict cookies set by the dashboard's own route handlers, and every API call
 * goes through /api/proxy, which attaches the bearer token server-side. An XSS bug in the UI
 * therefore cannot exfiltrate a token.
 */
import "server-only";

export const ACCESS_COOKIE = "cc_access";
export const REFRESH_COOKIE = "cc_refresh";

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  organization_id: string;
  role: string;
}

export function apiBaseUrl(): string {
  const url = process.env.CC_API_URL ?? "http://localhost:8000";
  return url.replace(/\/+$/, "");
}

export function secureCookies(): boolean {
  return process.env.NODE_ENV === "production" && process.env.CC_INSECURE_COOKIES !== "1";
}

export interface CookieSpec {
  name: string;
  value: string;
  options: { httpOnly: true; secure: boolean; sameSite: "strict"; path: string; maxAge: number };
}

const REFRESH_MAX_AGE = 30 * 24 * 3600;

export function sessionCookies(tokens: TokenPair): CookieSpec[] {
  const base = { httpOnly: true as const, secure: secureCookies(), sameSite: "strict" as const, path: "/" };
  return [
    // The JWT inside expires after ~15 minutes on its own; the cookie lives as long as the session so
    // page navigations keep working and /api/proxy can refresh the token transparently on 401.
    { name: ACCESS_COOKIE, value: tokens.access_token, options: { ...base, maxAge: REFRESH_MAX_AGE } },
    // The refresh cookie is only ever sent to the dashboard's own API routes.
    { name: REFRESH_COOKIE, value: tokens.refresh_token, options: { ...base, path: "/api", maxAge: REFRESH_MAX_AGE } },
  ];
}

export function clearedCookies(): CookieSpec[] {
  const base = { httpOnly: true as const, secure: secureCookies(), sameSite: "strict" as const };
  return [
    { name: ACCESS_COOKIE, value: "", options: { ...base, path: "/", maxAge: 0 } },
    { name: REFRESH_COOKIE, value: "", options: { ...base, path: "/api", maxAge: 0 } },
  ];
}

/** Exchange a refresh token for a new pair; null when the session is no longer valid. */
export async function refreshTokens(refreshToken: string, fetchImpl: typeof fetch = fetch): Promise<TokenPair | null> {
  const response = await fetchImpl(`${apiBaseUrl()}/v1/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refreshToken }),
    cache: "no-store",
  });
  if (!response.ok) return null;
  return (await response.json()) as TokenPair;
}
