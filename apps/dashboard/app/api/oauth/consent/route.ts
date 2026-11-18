import { NextResponse } from "next/server";

import { backTo, guarded, str } from "@/lib/forms";
import { errorOf, sendJson } from "@/lib/gateway";

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

/** MCP OAuth consent decision. The gateway validates the client's redirect_uri (registered,
 *  localhost or https) and returns where to send the browser. That target is a different
 *  origin, and a 303 after a form POST is checked against the page's CSP form-action in some
 *  browsers, so the hand-off is a tiny no-script page with a meta refresh and a link. */
export async function POST(req: Request) {
  const g = await guarded(req);
  if (!("token" in g)) return g;
  const params: Record<string, string> = {};
  // The authorization request's query parameters, passed through unchanged (the page put each
  // in a hidden `p.<name>` field); the gateway re-validates all of them.
  for (const [k, v] of g.form.entries()) {
    if (k.startsWith("p.") && typeof v === "string" && Object.keys(params).length < 20 && /^[a-z_]{1,40}$/.test(k.slice(2))) {
      params[k.slice(2)] = v.slice(0, 2048);
    }
  }
  const allow = str(g.form, "decision") === "allow";
  const r = await sendJson("POST", "/v1/oauth/consent", g.token, { params, allow });
  const to = (r.data as { redirect_to?: unknown } | null)?.redirect_to;
  if (r.status !== 200 || typeof to !== "string" || !/^(https:\/\/|http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?\/)/.test(to)) {
    const qs = new URLSearchParams(params).toString();
    return backTo(`/oauth/consent?${qs}`, { error: r.status === 200 ? "invalid_redirect" : errorOf(r.status, r.data).code });
  }
  const url = escapeHtml(to);
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="0;url=${url}"><title>Returning to your app</title></head><body><main><p>${allow ? "Access allowed." : "Access denied."} Returning to your app&hellip;</p><p><a href="${url}">Continue</a></p></main></body></html>`;
  return new NextResponse(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      "Referrer-Policy": "no-referrer",
    },
  });
}
