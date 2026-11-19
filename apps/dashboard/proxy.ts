import { NextRequest, NextResponse } from "next/server";

/**
 * Strict CSP with a fresh nonce per request (Phase 9, ADR-0031 §1). Next.js reads the nonce
 * from this header and puts it on its own scripts; nothing else may run: no inline handlers,
 * no eval (production), no third-party origins. The page never needs connect-src beyond
 * 'self': the browser talks only to this dashboard, never to the gateway.
 */
const SESSION_COOKIE = "__Host-agw_session";

/** A top-level navigation that arrives from another site (GitHub after "Create GitHub App" or
 *  "Install") carries no SameSite=Strict session cookie, so the page would send the admin to the
 *  login screen. Answer it once with a script-free same-site hop to the same URL: the browser
 *  then sends the cookie, and a signed-out user still lands on /login as before. */
function sameSiteBounce(request: NextRequest): NextResponse | null {
  if (request.method !== "GET") return null;
  if (request.headers.get("sec-fetch-site") !== "cross-site") return null;
  if (request.headers.get("sec-fetch-mode") !== "navigate") return null;
  if (request.cookies.has(SESSION_COOKIE)) return null;
  const target = request.nextUrl.pathname + request.nextUrl.search;
  const esc = target.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
  const html = `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=${esc}"><title>Continuing...</title><a href="${esc}">Continue</a>`;
  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    },
  });
}

export function proxy(request: NextRequest) {
  const bounce = sameSiteBounce(request);
  if (bounce) return bounce;
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDev = process.env.NODE_ENV === "development";
  const https = request.nextUrl.protocol === "https:";
  // C2 (ADR-0035): the GitHub App manifest flow is a plain form POST from an integration's
  // page to github.com. Only those pages may submit a form to GitHub; nothing else changes.
  const githubForm = request.nextUrl.pathname.startsWith("/integrations/");
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    `form-action 'self'${githubForm ? " https://github.com" : ""}`,
    "frame-ancestors 'none'",
    ...(https ? ["upgrade-insecure-requests"] : []),
  ].join("; ");
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("x-pathname", request.nextUrl.pathname + request.nextUrl.search);
  requestHeaders.set("Content-Security-Policy", csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
