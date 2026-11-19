import { Check, Laptop, X } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { ErrorState } from "@/components/empty-state";
import { CsrfField } from "@/components/legacy";
import { PlainLine } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { USER_CODE_RE, normalizeUserCode, type DeviceRequest } from "@/lib/connectors";
import { agentKindLabel } from "@/src/humanize";
import { getJson, me } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { csrfToken, sessionToken } from "@/lib/session";

export const metadata: Metadata = { title: "Enroll a device" };

const RESULTS: Record<string, [string, "good" | "bad" | "warn"]> = {
  ENROLL_APPROVED: ["Approved. The CLI picks up its device key within a few seconds; the device now acts for you.", "good"],
  ENROLL_DENIED: ["Denied. The CLI gets no key.", "good"],
  FORBIDDEN: ["This code is no longer pending (already decided or expired). Run agw login again for a new code.", "bad"],
  NOT_FOUND: ["No pending device with this code in your tenant. Check the code in your terminal.", "bad"],
};

export default async function Enroll({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const code = sp.code ? normalizeUserCode(sp.code) : "";
  if (!(await sessionToken())) redirect(`/login?next=${encodeURIComponent(`/enroll${code ? `?code=${code}` : ""}`)}`);
  const [who, csrf, p] = await Promise.all([me(), csrfToken(), prefs()]);
  const valid = USER_CODE_RE.test(code);
  const lookup = valid ? await getJson<DeviceRequest>(`/v1/device/requests/${code}`) : null;
  const req = lookup?.body ?? null;
  const flash = sp.result ?? sp.error;
  const [text, kind] = flash ? RESULTS[flash] ?? [`The gateway answered ${flash}.`, "bad" as const] : [null, null];

  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader title="Enroll a device" help="enroll" crumbs={[{ label: "Setup" }, { label: "Enroll a device" }]}
        description="Approve the code agw login printed in your terminal. The device then acts on your behalf, as you." />
      {text ? <Notice kind={kind ?? "info"}>{text}</Notice> : null}
      <PlainLine>
        <span className="block font-medium">Connect a developer's computer in three steps:</span>
        <span className="block">1. On that computer, run <code className="font-mono">agw login</code> in a terminal. It shows a short code.</span>
        <span className="block">2. Type that code below and press Look up.</span>
        <span className="block">3. Approve it - but only if you started it yourself just now. The computer will then act as you.</span>
      </PlainLine>
      <Card className="mb-4">
        <CardHeader title="Device code" />
        <CardBody>
          <form method="get" action="/enroll" className="flex flex-wrap items-end gap-3">
            <div>
              <Label htmlFor="user-code">Code from your terminal</Label>
              <Input id="user-code" name="code" defaultValue={code} required placeholder="ABCD-EFGH" maxLength={12} autoComplete="off" spellCheck={false}
                className="mt-1.5 w-48 font-mono uppercase tracking-widest" aria-describedby="user-code-hint" />
            </div>
            <Button type="submit">Look up</Button>
          </form>
          <p id="user-code-hint" className="mt-2 text-caption text-gray-11">Format XXXX-XXXX. Only enter a code you just saw in your own terminal.</p>
          {code && !valid ? <p role="alert" className="mt-2 text-caption font-medium text-bad-11">That is not a valid code (8 letters, XXXX-XXXX).</p> : null}
        </CardBody>
      </Card>

      {valid && !req ? (
        <ErrorState what={lookup?.status === 404 ? "No device request with this code in your tenant. Check the code, or run agw login again." : "The gateway did not return this device request."} />
      ) : null}

      {req ? (
        <Card data-testid="device-request">
          <CardHeader title={<span className="inline-flex items-center gap-2"><Laptop aria-hidden="true" className="size-4" />{req.label}</span>}
            action={<StatusBadge value={`ENROLL_${req.status.toUpperCase()}`} />} />
          <CardBody className="space-y-4 text-dense">
            <p className="text-body text-gray-12" data-testid="device-sentence">{agentKindLabel(req.agent_kind)} on &quot;{req.label}&quot; wants to act as you ({who.username}). Approve only if you just ran agw login on that computer.</p>
            <Technical view={p.view} hint="code, agent kind and request time">
            <dl className="grid grid-cols-[9rem_1fr] gap-y-2">
              <dt className="text-gray-11">Code</dt><dd className="font-mono">{req.user_code}</dd>
              <dt className="text-gray-11">Agent</dt><dd className="font-mono">{req.agent_kind}</dd>
              <dt className="text-gray-11">Device label</dt><dd>{req.label}</dd>
              <dt className="text-gray-11">Requested</dt><dd><Timestamp iso={req.created_at} tz={p.tz} /></dd>
              <dt className="text-gray-11">Developer</dt><dd>{who.username} <span className="text-gray-11">(you, if you approve)</span></dd>
            </dl>
            </Technical>
            {req.status === "pending" ? (
              <form method="post" action={`/api/device/${req.user_code}/decision`} className="flex flex-wrap gap-2">
                <CsrfField csrf={csrf} />
                <Button type="submit" name="decision" value="approve" variant="approve"><Check />Approve this device</Button>
                <Button type="submit" name="decision" value="deny" variant="danger-outline"><X />Deny</Button>
              </form>
            ) : <p className="text-gray-11">This request is no longer pending.</p>}
          </CardBody>
        </Card>
      ) : null}
    </div>
  );
}
