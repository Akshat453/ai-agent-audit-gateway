import { back, backTo, guarded, safeNext, str } from "@/lib/forms";
import { postJson } from "@/lib/gateway";

export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const r = await postJson("/v1/auth/step-up", g.token, { password: str(g.form, "password") });
  const params: Record<string, string> = r.status === 200 ? { stepped: "1" } : { error: "STEP_UP_FAILED" };
  // C2: admin pages pass `next` (a same-origin path); approvals pass approval_id (Phase 9).
  const next = str(g.form, "next");
  if (next) return backTo(safeNext(next), params);
  const id = str(g.form, "approval_id");
  const path = /^[0-9a-f-]{36}$/.test(id) ? `/approvals/${id}` : "/approvals";
  return back(req, path, params);
}
