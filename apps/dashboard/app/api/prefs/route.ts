import { NextResponse } from "next/server";

import { guarded, str } from "@/lib/forms";
import { PREF_COOKIES, type Prefs } from "@/lib/prefs";

/** Set one UI preference cookie. Harmless, but still a state change: same-origin + CSRF
 *  (guarded) like every other mutating route. Values are allowlisted. */
export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const key = str(g.form, "key") as keyof Prefs;
  const value = str(g.form, "value");
  const spec = PREF_COOKIES[key];
  if (!spec || !(spec.values as readonly string[]).includes(value)) {
    return NextResponse.json({ error: "BAD_PREFERENCE" }, { status: 400 });
  }
  const res = NextResponse.json({ ok: true });
  res.cookies.set(spec.name, value, {
    httpOnly: true, // the server renders from it; page JS never needs to read it
    secure: true,
    sameSite: "strict",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
  return res;
}
