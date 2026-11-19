import { NextResponse } from "next/server";

import { guarded, str } from "@/lib/forms";
import { PREF_COOKIES, REPO_COOKIE, REPO_RE } from "@/lib/prefs";

/** Set one UI preference cookie. Harmless, but still a state change: same-origin + CSRF
 *  (guarded) like every other mutating route. Values are allowlisted. */
export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const key = str(g.form, "key");
  const value = str(g.form, "value");
  // ADR-0040: the repository scope is a repository id (validated shape) or "all".
  const spec = key === "repo" ? { name: REPO_COOKIE, values: [] as readonly string[] } : PREF_COOKIES[key as keyof typeof PREF_COOKIES];
  const ok = key === "repo" ? value === "all" || REPO_RE.test(value) : !!spec && (spec.values as readonly string[]).includes(value);
  if (!spec || !ok) {
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
