import { NextResponse } from "next/server";

import { back, str } from "@/lib/forms";
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
  if (!r.ok) return back(req, "/login", { error: "credentials" });
  const data = (await r.json()) as { session_token: string; expires_at: string };
  const res: NextResponse = back(req, "/");
  res.cookies.set(SESSION_COOKIE, data.session_token, { ...cookieOptions, expires: new Date(data.expires_at) });
  return res;
}
