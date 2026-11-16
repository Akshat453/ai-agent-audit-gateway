import { GATEWAY_URL } from "@/lib/gateway";
import { sessionToken } from "@/lib/session";

/** Download a payload-free evidence bundle (auditor/admin; the gateway enforces the role). */
export async function GET(_req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) return new Response(null, { status: 404 });
  const token = await sessionToken();
  if (!token) return new Response(null, { status: 401 });
  const r = await fetch(`${GATEWAY_URL}/v1/dashboard/events/${id}/bundle`, {
    headers: { Authorization: `Session ${token}` },
    cache: "no-store",
  });
  return new Response(await r.text(), {
    status: r.status,
    headers: {
      "Content-Type": "application/json",
      ...(r.ok ? { "Content-Disposition": `attachment; filename="bundle-${id}.json"` } : {}),
    },
  });
}
