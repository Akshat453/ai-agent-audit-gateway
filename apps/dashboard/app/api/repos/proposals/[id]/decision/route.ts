import { CONNECTOR_ID_RE, backTo, guarded, str } from "@/lib/forms";
import { errorOf, sendJson } from "@/lib/gateway";

/** Approve / reject an .agentguard.yaml loosening proposal (admin + step-up on the gateway). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const decision = str(g.form, "decision");
  if (decision !== "approve" && decision !== "reject") return backTo("/repos", { error: "BAD_FORM" });
  const r = await sendJson("POST", `/v1/repos/proposals/${id}/decision`, g.token, { decision, reason: str(g.form, "reason").slice(0, 1000) });
  if (r.status === 200) return backTo("/repos", { result: decision === "approve" ? "APPROVED" : "REJECTED" });
  return backTo("/repos", { error: errorOf(r.status, r.data).code });
}
