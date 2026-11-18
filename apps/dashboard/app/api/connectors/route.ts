import { backTo, guarded, nextOf, str } from "@/lib/forms";
import { buildConnector } from "@/lib/connector-form";
import { errorOf, sendJson } from "@/lib/gateway";

/** Create a connector (C2). Credentials go to the gateway only: they never appear in the
 *  redirect, a log line or the next page (write-only). */
export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const typeId = str(g.form, "type_id");
  const name = str(g.form, "name").trim();
  const slug = str(g.form, "slug").trim();
  if (!/^[a-z][a-z0-9_]{1,40}$/.test(typeId)) return backTo("/integrations", { error: "BAD_FORM" });
  const back = nextOf(g.form, `/integrations/new?type=${typeId}`);
  const keep = { name: name.slice(0, 120), slug: slug.slice(0, 24) }; // non-secret, to refill the form
  const b = buildConnector(typeId, (k) => str(g.form, k), (k) => g.form.getAll(k).filter((v): v is string => typeof v === "string"));
  if (b.bad.length) return backTo(back, { ...keep, error: b.bad.includes("config.actions") ? "BAD_JSON" : "REQUEST_INVALID", fields: b.bad.join(",") });
  const r = await sendJson("POST", "/v1/connectors", g.token, { type_id: typeId, slug, name, config: b.config, credentials: b.credentials });
  if (r.status === 201) {
    const id = (r.data as { connector_id?: string } | null)?.connector_id ?? "";
    return backTo(`/integrations/new?type=${typeId}&id=${id}&step=test`, { result: "CREATED" });
  }
  const e = errorOf(r.status, r.data);
  return backTo(back, { ...keep, error: e.code, ...(e.fields.length ? { fields: e.fields.join(",") } : {}) });
}
