import { backTo, guarded, str } from "@/lib/forms";
import { USER_CODE_RE, normalizeUserCode } from "@/lib/connectors";
import { errorOf, sendJson } from "@/lib/gateway";

/** Approve / deny a device enrollment (agw login). The approving human becomes the developer. */
export async function POST(req: Request, ctx: { params: Promise<{ code: string }> }) {
  const code = normalizeUserCode((await ctx.params).code);
  if (!USER_CODE_RE.test(code)) return new Response(null, { status: 404 });
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const d = str(g.form, "decision");
  if (d !== "approve" && d !== "deny") return backTo(`/enroll?code=${code}`, { error: "BAD_FORM" });
  const r = await sendJson("POST", `/v1/device/requests/${code}/decision`, g.token, { approve: d === "approve" });
  if (r.status === 200) return backTo(`/enroll?code=${code}`, { result: d === "approve" ? "ENROLL_APPROVED" : "ENROLL_DENIED" });
  return backTo(`/enroll?code=${code}`, { error: errorOf(r.status, r.data).code });
}
