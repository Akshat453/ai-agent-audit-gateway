import { GATEWAY_URL } from "@/lib/gateway";
import { sessionToken } from "@/lib/session";

const KINDS = new Set(["denied", "outcome_unknown", "failed", "security", "alerts"]);

export async function GET(req: Request) {
  const token = await sessionToken();
  if (!token) return new Response(null, { status: 401 });
  const kind = new URL(req.url).searchParams.get("kind");
  const q = kind && KINDS.has(kind) ? `?kind=${kind}` : "";
  const r = await fetch(`${GATEWAY_URL}/v1/dashboard/incidents/export${q}`, {
    headers: { Authorization: `Session ${token}` },
    cache: "no-store",
  });
  return new Response(await r.text(), {
    status: r.status,
    headers: {
      "Content-Type": "application/json",
      ...(r.ok ? { "Content-Disposition": 'attachment; filename="incident-bundles.json"' } : {}),
    },
  });
}
