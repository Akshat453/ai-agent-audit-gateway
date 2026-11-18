import { NextResponse } from "next/server";

import { CONNECTOR_ID_RE, guarded } from "@/lib/forms";
import { errorOf, sendJson } from "@/lib/gateway";

const NO_STORE = { "Cache-Control": "no-store" };

/** GitHub App install link (single-use state, admin + step-up on the gateway). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const r = await sendJson("POST", `/v1/connectors/${id}/github/install`, g.token);
  if (r.status !== 200) return NextResponse.json({ error: errorOf(r.status, r.data).code }, { status: r.status, headers: NO_STORE });
  const url = (r.data as { url?: unknown }).url;
  if (typeof url !== "string" || !url.startsWith("https://github.com/")) return NextResponse.json({ error: "BAD_GATEWAY_RESPONSE" }, { status: 502, headers: NO_STORE });
  return NextResponse.json({ url }, { headers: NO_STORE });
}
