import { back, guarded, str } from "@/lib/forms";
import { postJson } from "@/lib/gateway";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const decision = str(g.form, "decision");
  if (decision !== "APPROVE" && decision !== "REJECT") return back(req, `/approvals/${id}`, { error: "BAD_DECISION" });
  const r = await postJson(`/v1/approvals/${id}/decision`, g.token, {
    decision,
    reason: str(g.form, "reason"),
    action_digest: str(g.form, "action_digest"),
    nonce: str(g.form, "nonce"),
  });
  if (r.status === 200) {
    const state = (r.data as { state?: string } | null)?.state ?? "";
    return back(req, `/approvals/${id}`, { result: state });
  }
  const code = (r.data as { error?: { code?: string } } | null)?.error?.code ?? `HTTP_${r.status}`;
  return back(req, `/approvals/${id}`, { error: code });
}
