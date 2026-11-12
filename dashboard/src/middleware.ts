import { type NextRequest, NextResponse } from "next/server";

const PUBLIC = ["/login", "/register"];

/** Send visitors without a session to /login; the API remains the authority on validity. */
export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const hasSession = request.cookies.has("cc_access");
  if (PUBLIC.includes(pathname)) {
    return hasSession ? NextResponse.redirect(new URL("/", request.url)) : NextResponse.next();
  }
  if (!hasSession) {
    const login = new URL("/login", request.url);
    if (pathname !== "/") login.searchParams.set("next", pathname);
    return NextResponse.redirect(login);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|icon.svg).*)"],
};
