import { CONNECTOR_ID_RE, backTo, guarded } from "@/lib/forms";
import { errorOf, sendJson } from "@/lib/gateway";

/** Delete (type-to-confirm in the UI; admin + step-up on the gateway). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const r = await sendJson("DELETE", `/v1/connectors/${id}`, g.token);
  if (r.status === 204) return backTo("/integrations", { result: "DELETED" });
  return backTo(`/integrations/${id}`, { error: errorOf(r.status, r.data).code });
}
