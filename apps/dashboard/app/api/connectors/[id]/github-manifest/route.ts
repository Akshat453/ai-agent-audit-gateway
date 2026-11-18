import { NextResponse } from "next/server";

import { CONNECTOR_ID_RE, guarded } from "@/lib/forms";
import { errorOf, sendJson } from "@/lib/gateway";

const NO_STORE = { "Cache-Control": "no-store" };

/** GitHub App manifest flow, step 1 (JSON for the client component): the gateway mints a
 *  single-use state and the manifest; the browser then posts the manifest form to GitHub. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const r = await sendJson("POST", `/v1/connectors/${id}/github/manifest`, g.token);
  if (r.status !== 200) return NextResponse.json({ error: errorOf(r.status, r.data).code }, { status: r.status, headers: NO_STORE });
  const d = r.data as { action?: unknown; manifest?: unknown };
  const action = typeof d.action === "string" ? d.action : "";
  // Only ever post the manifest to GitHub itself (the CSP form-action allows nothing else).
  if (!action.startsWith("https://github.com/")) return NextResponse.json({ error: "BAD_GATEWAY_RESPONSE" }, { status: 502, headers: NO_STORE });
  return NextResponse.json({ action, manifest: d.manifest ?? {} }, { headers: NO_STORE });
}
