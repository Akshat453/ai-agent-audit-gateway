import { CONNECTOR_ID_RE, backTo, guarded, nextOf, str } from "@/lib/forms";
import { CONFIG_FIELDS, buildConnector } from "@/lib/connector-form";
import { GATEWAY_URL, errorOf, sendJson } from "@/lib/gateway";

/** PATCH name + config (never credentials: those only change through Rotate). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const back = nextOf(g.form, `/integrations/${id}`);
  const typeId = str(g.form, "type_id");
  const b = buildConnector(typeId, (k) => str(g.form, k), (k) => g.form.getAll(k).filter((v): v is string => typeof v === "string"), false);
  if (b.bad.length) return backTo(back, { error: b.bad.includes("config.actions") ? "BAD_JSON" : "REQUEST_INVALID", fields: b.bad.join(",") });
  const body: Record<string, unknown> = { name: str(g.form, "name").trim() };
  if (typeId in CONFIG_FIELDS) body.config = b.config; // agent clients have no configuration
  if (typeId === "github") {
    // The App registration (app_id, slug, installation ids) arrived from GitHub, not this
    // form: keep it, change only the owner fields.
    const cur = await fetch(`${GATEWAY_URL}/v1/connectors/${id}`, { headers: { Authorization: `Session ${g.token}` }, cache: "no-store" });
    const current = cur.ok ? ((await cur.json()) as { config?: Record<string, unknown> }).config ?? {} : {};
    body.config = { ...current, ...b.config };
  }
  const r = await sendJson("PATCH", `/v1/connectors/${id}`, g.token, body);
  if (r.status === 200) return backTo(back, { result: "UPDATED" });
  const e = errorOf(r.status, r.data);
  return backTo(back, { error: e.code, ...(e.fields.length ? { fields: e.fields.join(",") } : {}) });
}
