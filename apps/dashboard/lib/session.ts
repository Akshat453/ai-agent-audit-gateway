import "server-only";

import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies, headers } from "next/headers";

/**
 * Session + CSRF (Phase 9, ADR-0031 §1).
 *
 * - The gateway session token lives ONLY in an httpOnly, Secure, SameSite=Strict, `__Host-`
 *   cookie on the dashboard origin. Browser JS can never read it; nothing goes to
 *   localStorage.
 * - CSRF: every state-changing request (an HTML form POST to /api/...) must carry
 *   `csrf = HMAC-SHA256(AGW_DASHBOARD_SECRET, session token)` (synchronizer token, rendered
 *   into the form by the server) AND pass an Origin / Sec-Fetch-Site same-origin check.
 *   SameSite=Strict is a third, independent layer.
 */
export const SESSION_COOKIE = "__Host-agw_session";

function secret(): Buffer {
  const s = process.env.AGW_DASHBOARD_SECRET ?? "";
  if (s.length < 32) {
    throw new Error("AGW_DASHBOARD_SECRET (>= 32 chars) is required"); // fail closed
  }
  return Buffer.from(s, "utf8");
}

export function csrfFor(token: string): string {
  return createHmac("sha256", secret()).update("agw-dashboard-csrf/v1\0" + token).digest("base64url");
}

export async function sessionToken(): Promise<string | null> {
  const v = (await cookies()).get(SESSION_COOKIE)?.value;
  return v && /^agws_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/.test(v) ? v : null;
}

export async function csrfToken(): Promise<string> {
  const token = await sessionToken();
  return token ? csrfFor(token) : "";
}

/** Same-origin check for a state-changing request (independent of the token). */
export function sameOrigin(req: Request): boolean {
  const site = req.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin") return false;
  const origin = req.headers.get("origin");
  // "null" is what browsers send when the referrer policy hides the origin: then the
  // (unforgeable by page script) Sec-Fetch-Site header must say same-origin.
  if (origin === null || origin === "null") return site === "same-origin";
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

export function csrfValid(token: string | null, presented: unknown): boolean {
  if (!token || typeof presented !== "string" || presented.length === 0) return false;
  const a = Buffer.from(csrfFor(token));
  const b = Buffer.from(presented);
  return a.length === b.length && timingSafeEqual(a, b);
}

export async function nonce(): Promise<string | undefined> {
  return (await headers()).get("x-nonce") ?? undefined;
}

export const cookieOptions = {
  httpOnly: true,
  secure: true, // browsers accept Secure cookies on http://localhost; use HTTPS elsewhere
  sameSite: "strict" as const,
  path: "/",
};
