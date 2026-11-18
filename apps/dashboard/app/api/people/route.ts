import { NextResponse } from "next/server";

import { guarded, str } from "@/lib/forms";
import { INVITE_ROLES } from "@/lib/connectors";
import { errorOf, sendJson } from "@/lib/gateway";

const NO_STORE = { "Cache-Control": "no-store" };

/** Invite a person. Answered as JSON (fetch from the People page), NOT a redirect: the
 *  temporary password must never travel in a URL; the page shows it once from memory. */
export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const username = str(g.form, "username").trim();
  const roles = g.form.getAll("roles").filter((r): r is string => typeof r === "string" && (INVITE_ROLES as readonly string[]).includes(r));
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(username) || !roles.length) {
    return NextResponse.json({ error: "REQUEST_INVALID", fields: [!roles.length ? "roles" : "username"] }, { status: 422, headers: NO_STORE });
  }
  const r = await sendJson("POST", "/v1/people", g.token, { username, roles });
  if (r.status === 201) {
    const d = r.data as { username: string; roles: string[]; temporary_password: string };
    return NextResponse.json({ username: d.username, roles: d.roles, temporary_password: d.temporary_password }, { status: 201, headers: NO_STORE });
  }
  const e = errorOf(r.status, r.data);
  return NextResponse.json({ error: e.code, fields: e.fields }, { status: r.status, headers: NO_STORE });
}
