import { NextResponse } from "next/server";

import { back, str } from "@/lib/forms";
import { GATEWAY_URL } from "@/lib/gateway";
import { SESSION_COOKIE, cookieOptions, sameOrigin } from "@/lib/session";

/** Self-service sign-up (dev/test gateways only): a new tenant + its first admin, signed in. */
export async function POST(req: Request) {
  if (!sameOrigin(req)) return back(req, "/signup", { error: "origin" });
  const form = await req.formData();
  if (str(form, "password") !== str(form, "confirm")) return back(req, "/signup", { error: "mismatch" });
  const r = await fetch(GATEWAY_URL + "/v1/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      organization: str(form, "organization"),
      tenant: str(form, "tenant"),
      username: str(form, "username"),
      password: str(form, "password"),
    }),
    cache: "no-store",
  });
  if (r.status === 404) return back(req, "/signup", { error: "disabled" });
  if (r.status === 409) return back(req, "/signup", { error: "taken" });
  if (!r.ok) return back(req, "/signup", { error: "invalid" });
  const data = (await r.json()) as { session_token: string; expires_at: string };
  const res = new NextResponse(null, { status: 303, headers: { Location: "/" } });
  res.cookies.set(SESSION_COOKIE, data.session_token, { ...cookieOptions, expires: new Date(data.expires_at) });
  return res;
}
