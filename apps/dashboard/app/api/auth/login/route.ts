import { NextResponse } from "next/server";

import { back, safeNext, str } from "@/lib/forms";
import { GATEWAY_URL } from "@/lib/gateway";
import { SESSION_COOKIE, cookieOptions, sameOrigin } from "@/lib/session";

export async function POST(req: Request) {
  if (!sameOrigin(req)) return back(req, "/login", { error: "origin" });
  const form = await req.formData();
  const r = await fetch(GATEWAY_URL + "/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tenant: str(form, "tenant"), username: str(form, "username"), password: str(form, "password") }),
    cache: "no-store",
  });
  // C2: pages that need a signed-in human (OAuth consent, device enrollment) return here.
  const next = safeNext(str(form, "next"), "/");
  if (!r.ok) return back(req, "/login", next === "/" ? { error: "credentials" } : { error: "credentials", next });
  const data = (await r.json()) as { session_token: string; expires_at: string };
  const res = new NextResponse(null, { status: 303, headers: { Location: next } });
  res.cookies.set(SESSION_COOKIE, data.session_token, { ...cookieOptions, expires: new Date(data.expires_at) });
  return res;
}
