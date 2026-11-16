import { back, guarded } from "@/lib/forms";
import { postJson } from "@/lib/gateway";

export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const r = await postJson("/v1/dashboard/verifications", g.token, {});
  return back(req, "/verification", r.status === 202 ? { queued: "1" } : { error: `HTTP_${r.status}` });
}
