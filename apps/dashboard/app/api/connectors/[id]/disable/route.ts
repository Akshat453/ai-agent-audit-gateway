import { CONNECTOR_ID_RE, backTo, guarded, nextOf } from "@/lib/forms";
import { errorOf, sendJson } from "@/lib/gateway";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const back = nextOf(g.form, `/integrations/${id}`);
  const r = await sendJson("POST", `/v1/connectors/${id}/disable`, g.token);
  if (r.status === 200) return backTo(back, { result: "DISABLED" });
  return backTo(back, { error: errorOf(r.status, r.data).code });
}
