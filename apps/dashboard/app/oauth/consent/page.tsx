import { Check, ShieldCheck, X } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { CsrfField } from "@/components/legacy";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import type { ConsentInfo } from "@/lib/connectors";
import { GATEWAY_URL } from "@/lib/gateway";
import { csrfToken, sessionToken } from "@/lib/session";

export const metadata: Metadata = { title: "Allow access" };

const ERRORS: Record<string, string> = {
  invalid_client: "This application is not registered with the gateway. Start the connection again from the application.",
  invalid_redirect_uri: "The application's return address is not allowed. Nothing was shared.",
  invalid_request: "The request from the application is incomplete or malformed. Start again from the application.",
  invalid_target: "The application asked for a different server than this gateway.",
  invalid_scope: "The application asked for access this gateway does not grant.",
  unsupported_response_type: "The application uses an unsupported sign-in flow.",
  access_denied: "Access was denied.",
};

/** MCP OAuth consent (C2): a coding agent (an MCP client) asks to act as the signed-in developer
 *  through the gateway's MCP endpoint. Every query parameter is passed through unchanged and
 *  re-validated by the gateway on both the lookup and the decision. */
export default async function Consent({ searchParams }: { searchParams: Promise<Record<string, string | string[]>> }) {
  const raw = await searchParams;
  const params: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (k === "error" || !/^[a-z_]{1,40}$/.test(k)) continue;
    const s = Array.isArray(v) ? v[0] : v;
    if (typeof s === "string") params[k] = s.slice(0, 2048);
  }
  const qs = new URLSearchParams(params).toString();
  const token = await sessionToken();
  if (!token) redirect(`/login?next=${encodeURIComponent(`/oauth/consent?${qs}`)}`);
  const csrf = await csrfToken();
  const r = await fetch(`${GATEWAY_URL}/v1/oauth/consent?${qs}`, { headers: { Authorization: `Session ${token}` }, cache: "no-store" });
  if (r.status === 401) redirect(`/login?next=${encodeURIComponent(`/oauth/consent?${qs}`)}`);
  const body = (await r.json().catch(() => null)) as (ConsentInfo & { error?: unknown }) | null;
  const info = r.ok && body && !body.error ? body : null;
  const gwError = !info ? (typeof body?.error === "string" ? body.error : `HTTP_${r.status}`) : null;
  const decisionError = typeof raw.error === "string" ? raw.error : null;

  return (
    <div className="mx-auto max-w-xl">
      <PageHeader title="Allow access?" crumbs={[{ label: "Setup" }, { label: "Allow access" }]}
        description="A coding agent wants to use the gateway's MCP tools on your behalf." />
      {decisionError ? <Notice kind="bad">{ERRORS[decisionError] ?? `The gateway answered ${decisionError}. Nothing was shared.`}</Notice> : null}
      {!info ? (
        <Notice kind="bad">{ERRORS[gwError ?? ""] ?? `This request cannot be completed (${gwError}). Start again from the application.`}</Notice>
      ) : (
        <Card data-testid="consent">
          <CardHeader title={<span className="inline-flex items-center gap-2"><ShieldCheck aria-hidden="true" className="size-4 text-brand-11" />{info.client_name || info.client_id}</span>}
            description="wants to act as you through the gateway" />
          <CardBody className="space-y-4 text-dense">
            <dl className="grid grid-cols-[8rem_1fr] gap-y-2">
              <dt className="text-gray-11">Application</dt><dd className="break-all">{info.client_name} <span className="font-mono text-caption text-gray-11">({info.client_id})</span></dd>
              <dt className="text-gray-11">Returns to</dt><dd className="break-all font-mono">{info.redirect_host}</dd>
              <dt className="text-gray-11">Server</dt><dd className="break-all font-mono">{info.resource}</dd>
              <dt className="text-gray-11">Access</dt><dd className="font-mono">{info.scope}</dd>
              <dt className="text-gray-11">As</dt><dd>{info.developer} <span className="text-gray-11">(you)</span></dd>
            </dl>
            <p className="text-caption text-gray-11">Allowing enrolls this application as one of your devices. Every tool call it makes is checked by policy, may need approval, and is recorded as evidence under your name. Only allow an application you just started yourself.</p>
            <form method="post" action="/api/oauth/consent" className="flex flex-wrap gap-2">
              <CsrfField csrf={csrf} />
              {Object.entries(params).map(([k, v]) => <input key={k} type="hidden" name={`p.${k}`} value={v} />)}
              <Button type="submit" name="decision" value="allow" variant="approve"><Check />Allow</Button>
              <Button type="submit" name="decision" value="deny" variant="danger-outline"><X />Deny</Button>
            </form>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
