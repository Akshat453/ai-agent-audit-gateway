import { CONNECTOR_ID_RE, backTo, guarded, nextOf, str } from "@/lib/forms";
import { APPROVAL_RULES, APPROVER_ROLES, RISKS } from "@/lib/connectors";
import { errorOf, sendJson } from "@/lib/gateway";

const NAME_RE = /^[a-z][a-z0-9_]{0,35}$/;

function agents(raw: string): string[] | null {
  if (raw === "devices") return ["devices"];
  if (raw === "*") return ["*"];
  try {
    const v: unknown = JSON.parse(raw); // a custom agent list carried through unchanged
    if (Array.isArray(v) && v.length && v.every((a) => typeof a === "string" && /^[0-9a-f-]{36}$/.test(a))) return v as string[];
  } catch {
    /* fall through */
  }
  return null;
}

/** One classification change for many actions = ONE new policy version (the gateway merges).
 *  An action left on "Unclassified" that was classified before is removed (denied again). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!CONNECTOR_ID_RE.test(id)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const back = nextOf(g.form, `/integrations/${id}`);
  const actions: Record<string, unknown> = {};
  for (const v of g.form.getAll("action")) {
    if (typeof v !== "string" || !NAME_RE.test(v)) return backTo(back, { error: "BAD_FORM" });
    const risk = str(g.form, `risk:${v}`);
    const was = str(g.form, `was:${v}`) === "1";
    if (!risk) {
      if (was) actions[v] = null;
      continue;
    }
    const approval = str(g.form, `approval:${v}`) || "auto";
    const role = str(g.form, `role:${v}`) || "approver";
    const allowed = agents(str(g.form, `agents:${v}`) || "devices");
    if (!(RISKS as string[]).includes(risk) || !APPROVAL_RULES.some((r) => r.value === approval) || !(APPROVER_ROLES as string[]).includes(role) || !allowed) {
      return backTo(back, { error: "REQUEST_INVALID", fields: `actions.${v}` });
    }
    let constraints: unknown = {};
    try {
      constraints = JSON.parse(str(g.form, `constraints:${v}`) || "{}");
    } catch {
      constraints = {};
    }
    actions[v] = { risk, approval, approver_role: role, allowed_agents: allowed, constraints };
  }
  if (!Object.keys(actions).length) return backTo(back, { error: "UNCHANGED" });
  const r = await sendJson("POST", `/v1/connectors/${id}/classify`, g.token, { actions });
  if (r.status === 200) {
    const d = r.data as { policy_version?: number; changed?: string[] } | null;
    if (!d?.changed?.length) return backTo(back, { error: "UNCHANGED" });
    return backTo(back, { result: "CLASSIFIED", ver: String(d.policy_version ?? "") });
  }
  const e = errorOf(r.status, r.data);
  return backTo(back, { error: e.code, ...(e.fields.length ? { fields: e.fields.join(",") } : {}) });
}
