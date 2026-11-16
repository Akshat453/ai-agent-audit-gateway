import { back, guarded } from "@/lib/forms";
import { GATEWAY_URL } from "@/lib/gateway";
import { SESSION_COOKIE, cookieOptions } from "@/lib/session";

export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  await fetch(GATEWAY_URL + "/v1/auth/logout", {
    method: "POST",
    headers: { Authorization: `Session ${g.token}` },
    cache: "no-store",
  });
  const res = back(req, "/login");
  res.cookies.set(SESSION_COOKIE, "", { ...cookieOptions, maxAge: 0 });
  return res;
}
