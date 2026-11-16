import { back, guarded, str } from "@/lib/forms";
import { postJson } from "@/lib/gateway";

export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const id = str(g.form, "approval_id");
  const path = /^[0-9a-f-]{36}$/.test(id) ? `/approvals/${id}` : "/approvals";
  const r = await postJson("/v1/auth/step-up", g.token, { password: str(g.form, "password") });
  return back(req, path, r.status === 200 ? { stepped: "1" } : { error: "STEP_UP_FAILED" });
}
