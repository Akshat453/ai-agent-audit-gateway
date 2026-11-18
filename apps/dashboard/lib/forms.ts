import "server-only";

import { NextResponse } from "next/server";

import { csrfValid, sameOrigin, sessionToken } from "@/lib/session";

import { safeNext } from "@/lib/next";

export { safeNext };

/** Common guard for every state-changing route handler: same origin + CSRF token + session. */
export async function guarded(req: Request): Promise<{ token: string; form: FormData } | NextResponse> {
  if (!sameOrigin(req)) {
    return NextResponse.json({ error: "CROSS_SITE_REQUEST" }, { status: 403 });
  }
  const token = await sessionToken();
  if (!token) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return NextResponse.json({ error: "BAD_FORM" }, { status: 400 });
  }
  if (!csrfValid(token, form.get("csrf"))) {
    return NextResponse.json({ error: "CSRF_TOKEN_INVALID" }, { status: 403 });
  }
  return { token, form };
}

/** 303 to a same-origin path. The Location is RELATIVE: the server's idea of its own host
 *  (req.url) can differ from the origin the browser used, which would drop the cookie. */
export function back(_req: Request, path: string, params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return new NextResponse(null, { status: 303, headers: { Location: qs ? `${path}?${qs}` : path } });
}

export function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === "string" ? v : "";
}

/** 303 to a same-origin path that may already carry a query; `params` replace same-named ones. */
export function backTo(path: string, params: Record<string, string> = {}) {
  const u = new URL(path, "http://x");
  for (const k of ["result", "error", "fields", "stepped", "ver", "cred"]) u.searchParams.delete(k);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  const qs = u.searchParams.toString();
  return new NextResponse(null, { status: 303, headers: { Location: qs ? `${u.pathname}?${qs}` : u.pathname } });
}

export const CONNECTOR_ID_RE = /^[0-9a-fA-F-]{36}$/;

/** Where a C2 form returns to: its `next` field when it is a same-origin path, else `fallback`. */
export function nextOf(form: FormData, fallback: string): string {
  return safeNext(str(form, "next"), fallback);
}
