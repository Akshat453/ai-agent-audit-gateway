import { back, guarded, str } from "@/lib/forms";
import { postJson } from "@/lib/gateway";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const r = await postJson(`/v1/actions/${id}/reconcile`, g.token, {
    observed: str(g.form, "observed"),
    justification: str(g.form, "justification"),
  });
  if (r.status === 200) return back(req, "/incidents", { reconciled: (r.data as { code: string }).code });
  const code = (r.data as { error?: { code?: string } } | null)?.error?.code ?? `HTTP_${r.status}`;
  return back(req, "/incidents", { error: code });
}
