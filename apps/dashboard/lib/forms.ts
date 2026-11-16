import "server-only";

import { NextResponse } from "next/server";

import { csrfValid, sameOrigin, sessionToken } from "@/lib/session";

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
