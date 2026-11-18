import { NextResponse } from "next/server";

import { gatewayFor } from "@/lib/gateway";
import { sessionToken } from "@/lib/session";

/** Command-palette lookup (read-only). The browser still talks only to the dashboard; the
 *  gateway call happens here with the httpOnly session cookie. */
export async function GET(req: Request) {
  const token = await sessionToken();
  if (!token) return NextResponse.json({ error: "UNAUTHENTICATED" }, { status: 401 });
  const q = new URL(req.url).searchParams.get("q")?.trim() ?? "";
  if (q.length < 1 || q.length > 80) return NextResponse.json([]);
  const { data, response } = await gatewayFor(token).GET("/v1/dashboard/search", { params: { query: { q } } });
  if (!response.ok || !data) return NextResponse.json([], { status: response.status === 401 ? 401 : 200 });
  return NextResponse.json(data, { headers: { "Cache-Control": "no-store" } });
}
