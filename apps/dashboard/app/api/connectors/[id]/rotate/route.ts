import { CONNECTOR_ID_RE, backTo, guarded, nextOf, str } from "@/lib/forms";
import { CREDENTIAL_FIELDS } from "@/lib/connector-form";
import { errorOf, sendJson } from "@/lib/gateway";

/** Replace the sealed credentials. The new values travel only to the gateway; the redirect
 *  carries the new credential VERSION, never a value. */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const back = nextOf(g.form, `/integrations/${id}`);
  const fields = CREDENTIAL_FIELDS[str(g.form, "type_id")] ?? [];
  const credentials: Record<string, string> = {};
  for (const f of fields) {
    const v = str(g.form, `cred.${f}`);
    if (v) credentials[f] = v;
  }
  if (!Object.keys(credentials).length) return backTo(back, { error: "REQUEST_INVALID", fields: "credentials" });
  const r = await sendJson("POST", `/v1/connectors/${id}/rotate`, g.token, { credentials });
  if (r.status === 200) {
    const v = (r.data as { credential_version?: number } | null)?.credential_version;
    return backTo(back, { result: "ROTATED", ...(typeof v === "number" ? { cred: String(v) } : {}) });
  }
  const e = errorOf(r.status, r.data);
  return backTo(back, { error: e.code, ...(e.fields.length ? { fields: e.fields.join(",") } : {}) });
}
