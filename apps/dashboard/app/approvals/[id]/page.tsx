import { ArrowRight, Check, ShieldAlert, X } from "lucide-react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { CodeView } from "@/components/code-view";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Countdown } from "@/components/expiry-countdown";
import { ErrorState } from "@/components/empty-state";
import { HashChip } from "@/components/hash-chip";
import { CsrfField } from "@/components/legacy";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { FlashToast } from "@/components/ui/toast";
import type { ApprovalView } from "@/lib/approval";
import { UUID_RE, middle } from "@/lib/format";
import { gateway, getJson, me } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { csrfToken } from "@/lib/session";

export const metadata: Metadata = { title: "Approval" };

const MESSAGES: Record<string, [string, "good" | "bad" | "warn"]> = {
  APPROVED: ["Approved. The gateway re-validated the action and authorized it.", "good"],
  REJECTED: ["Rejected. The action will not run.", "good"],
  PENDING: ["Your approval is recorded and signed; another approver is needed (four-eyes).", "good"],
  STEP_UP_REQUIRED: ["Re-enter your password (step-up) before approving a CRITICAL action. Nothing was decided.", "warn"],
  STEP_UP_FAILED: ["Step-up failed: the password was not accepted. Nothing was decided.", "bad"],
  APPROVAL_EXPIRED: ["This approval has expired. Nothing was executed.", "bad"],
  APPROVAL_STALE: ["The action changed since you opened it. Reload and review again. Nothing was decided.", "bad"],
  FORBIDDEN: ["Your role cannot decide approvals.", "bad"],
  APPROVAL_NOT_PENDING: ["This approval is no longer pending.", "bad"],
  APPROVAL_ALREADY_DECIDED: ["You already decided this approval (four-eyes needs a different approver).", "bad"],
  BAD_DECISION: ["The decision was not understood. Nothing was decided.", "bad"],
};

export default async function Approval({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string>> }) {
  const { id } = await params;
  const sp = await searchParams;
  if (!UUID_RE.test(id)) notFound();
  const gw = await gateway();
  const [{ body: v, status }, who, csrf, session, p, next] = await Promise.all([
    getJson<ApprovalView>(`/v1/approvals/${id}`),
    me(),
    csrfToken(),
    gw.GET("/v1/dashboard/session"),
    prefs(),
    gw.GET("/v1/dashboard/approvals", { params: { query: { state: "PENDING", limit: 2, sort: "expires_at", order: "asc" } } }),
  ]);
  if (!v) {
    return (
      <div className="mx-auto max-w-6xl">
        <PageHeader title="Approval" crumbs={[{ label: "Approvals", href: "/approvals" }, { label: middle(id) }]} />
        <ErrorState what={status === 404 ? "This approval does not exist in your tenant." : "You cannot view approvals."} />
      </div>
    );
  }
  const a = v.action;
  const secondsLeft = Math.round((Date.parse(v.expires_at) - Date.now()) / 1000);
  const expired = v.state === "EXPIRED" || secondsLeft <= 0;
  const pending = v.state === "PENDING" && !expired;
  // C1 (ADR-0034): coding approvals are routed to a role; the gateway enforces it as well.
  const canDecide = who.roles.includes(v.required_role ?? "approver");
  const needsStepUp = who.step_up_levels.includes(a.risk.level);
  const stepUpLeft = session.data?.step_up_remaining_seconds ?? null;
  const critical = a.risk.level === "CRITICAL";
  const last6 = a.action_id.replaceAll("-", "").slice(-6);
  const msg = sp.result ?? sp.error;
  const [msgText, msgKind] = msg ? (MESSAGES[msg] ?? [`Gateway answered: ${msg}`, "warn" as const]) : [null, null];
  const nextPending = (next.data?.rows ?? []).find((r) => r.approval_id !== v.approval_id);
  const shownState = expired && v.state === "PENDING" ? "EXPIRED" : v.state;
  const target = a.target_rendered;

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title={`Approval: ${a.tool.id}@${a.tool.version}`}
        help="approvals"
        crumbs={[{ label: "Operations" }, { label: "Approvals", href: "/approvals" }, { label: middle(v.approval_id, 8, 4) }]}
        description="Review exactly what will run. Values are shown escaped; secret fields are redacted markers."
        meta={<><StatusBadge value={shownState} /><RiskBadge level={a.risk.level} /><span className="text-caption text-gray-11">requested <Timestamp iso={v.requested_at} tz={p.tz} /></span></>}
      />
      {msgText ? (
        <>
          <Notice kind={msgKind ?? "warn"}>
            {msgText}
            {(msg === "APPROVED" || msg === "REJECTED" || msg === "PENDING") && nextPending ? (
              <> <a href={`/approvals/${nextPending.approval_id}`} className="ml-1 inline-flex items-center gap-1 font-medium">Review next pending<ArrowRight aria-hidden="true" className="size-3.5" /></a></>
            ) : null}
          </Notice>
          <FlashToast title={msgText} tone={msgKind === "good" ? "ok" : msgKind === "bad" ? "bad" : "info"} />
        </>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-[1fr_360px]">
        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader title={pending ? "You are approving" : "This approval covered"} description="One exact action. Any change to tool, version, arguments, target or policy invalidates the approval." />
            <CardBody>
              <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-dense sm:grid-cols-[10rem_1fr]">
                <dt className="text-gray-11">Tool</dt><dd><code className="font-mono">{a.tool.id}</code> <span className="text-gray-11">version</span> <code className="font-mono">{a.tool.version}</code></dd>
                <dt className="text-gray-11">Target</dt><dd><CodeView text={target} max={1000} label="target" /></dd>
                <dt className="text-gray-11">Environment</dt><dd>{a.environment}</dd>
                <dt className="text-gray-11">Agent</dt><dd>{a.agent.name}</dd>
                <dt className="text-gray-11">Delegation</dt><dd>{a.delegation_depth ? `delegated, depth ${a.delegation_depth}` : "direct (no delegation)"}</dd>
                <dt className="text-gray-11">Policy</dt><dd>{a.policy.id} v{a.policy.version} → <StatusBadge value={a.policy.effect} /> <span className="text-caption text-gray-11">{a.policy.rules.join(", ")}</span></dd>
                <dt className="text-gray-11">Approvals</dt>
                <dd>
                  {v.required_approvals} required
                  {v.decisions.length ? <span className="text-gray-11"> · {v.decisions.map((d) => `${d.approver}: ${d.decision}`).join(", ")}</span> : <span className="text-gray-11"> · none yet</span>}
                </dd>
                <dt className="text-gray-11">Action</dt><dd className="flex flex-wrap gap-3"><HashChip value={a.action_id} href={`/actions/${a.action_id}`} label="action" /> <span className="text-gray-11">run</span> <HashChip value={a.run_id} href={`/runs/${a.run_id}`} label="run" /></dd>
              </dl>
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Risk" description={`Score ${a.risk.score}${a.risk.rules.length ? ` · rules ${a.risk.rules.join(", ")}` : ""}`} action={<RiskBadge level={a.risk.level} />} />
            <CardBody>
              <ul className="list-disc space-y-1 pl-5 text-dense">
                {[...a.risk.reasons, ...a.policy.reasons].map((r) => <li key={r}>{r}</li>)}
              </ul>
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Exact arguments" description="Canonical JSON, escaped. This is what the digest binds." />
            <CardBody><CodeView text={a.args_rendered} max={4000} label="arguments" /></CardBody>
          </Card>
        </div>

        {/* decision column */}
        <aside className="space-y-4 lg:sticky lg:top-16 lg:self-start" aria-label="Decision">
          <Card>
            <CardHeader title="Decision" />
            <CardBody className="space-y-4 text-dense">
              <div>
                <div className="mb-1 text-caption font-medium text-gray-11">Expiry</div>
                {pending ? <Countdown expiresAt={v.expires_at} initialSeconds={secondsLeft} /> : <span data-testid="countdown" className="font-semibold">{expired ? "EXPIRED" : v.state}</span>}
                <div className="mt-0.5 text-caption text-gray-11"><Timestamp iso={v.expires_at} tz={p.tz} /></div>
              </div>
              <div>
                <div className="mb-1 text-caption font-medium text-gray-11">Action digest</div>
                <code className="block break-all font-mono text-caption text-gray-12" data-testid="digest">{v.action_digest}</code>
              </div>

              {pending && canDecide && needsStepUp ? (
                <form method="post" action="/api/auth/step-up" className="space-y-2 rounded-md border border-warn-7 bg-warn-3 p-3">
                  <CsrfField csrf={csrf} />
                  <input type="hidden" name="approval_id" value={v.approval_id} />
                  <div className="flex items-center gap-1.5 font-medium text-warn-12"><ShieldAlert aria-hidden="true" className="size-4" />Step-up required for {a.risk.level}</div>
                  {stepUpLeft ? (
                    <p className="text-caption text-ok-11" data-testid="step-up-ok">Step-up active · {Math.max(1, Math.round(stepUpLeft / 60))} min left</p>
                  ) : null}
                  <Label htmlFor="stepup-pw" className="text-warn-12">
                    {a.risk.level} action: re-enter your password (step-up, valid {who.step_up_window_seconds} s)
                  </Label>
                  <Input id="stepup-pw" name="password" type="password" required autoComplete="current-password" />
                  <Button type="submit" size="sm">Re-authenticate</Button>
                  {sp.stepped ? <p className="text-caption font-medium text-ok-11">re-authenticated</p> : null}
                </form>
              ) : null}

              {pending && canDecide ? (
                <>
                  {/* The decision is ONE plain form; the dialogs' buttons submit it. */}
                  <form id="decision-form" method="post" action={`/api/approvals/${v.approval_id}/decision`}>
                    <CsrfField csrf={csrf} />
                    <input type="hidden" name="action_digest" value={v.action_digest} />
                    <input type="hidden" name="nonce" value={v.nonce} />
                  </form>
                  <div className="flex flex-col gap-2">
                    <ConfirmDialog
                      formId="decision-form"
                      testId="approve-dialog"
                      title={`Approve ${a.tool.id}@${a.tool.version}?`}
                      description="This authorizes exactly the action below, once. It cannot be undone after the tool runs."
                      confirmLabel="Confirm approval"
                      confirmVariant="approve"
                      submitName="decision"
                      submitValue="APPROVE"
                      typeToConfirm={critical ? last6 : undefined}
                      reason={{ label: "Reason (recorded, signed)", name: "reason", required: false, placeholder: "Optional" }}
                      trigger={<Button variant="approve" size="lg" className="w-full"><Check />Approve exactly this action</Button>}
                    >
                      <ul className="space-y-1.5 rounded-md border border-gray-6 bg-gray-2 p-3 text-dense">
                        <li><span className="text-gray-11">Run</span> <code className="font-mono">{a.tool.id}@{a.tool.version}</code> <span className="text-gray-11">as</span> {a.agent.name} <span className="text-gray-11">in</span> {a.environment}</li>
                        <li className="break-all"><span className="text-gray-11">Target</span> <code className="font-mono text-caption">{target.length > 240 ? `${target.slice(0, 240)}… [TRUNCATED]` : target}</code></li>
                        <li><span className="text-gray-11">Risk</span> <RiskBadge level={a.risk.level} size="sm" /> <span className="text-gray-11">score {a.risk.score}</span></li>
                        <li className="break-all"><span className="text-gray-11">Digest</span> <code className="font-mono text-caption">{a.action_id ? middle(v.action_digest, 12, 8) : ""}</code></li>
                        <li><span className="text-gray-11">Single-use; expires</span> <Timestamp iso={v.expires_at} tz={p.tz} /></li>
                      </ul>
                      {critical ? <p className="text-caption text-gray-11" data-testid="confirm-code">{last6}</p> : null}
                    </ConfirmDialog>
                    <ConfirmDialog
                      formId="decision-form"
                      testId="reject-dialog"
                      title={`Reject ${a.tool.id}@${a.tool.version}?`}
                      description="The action will not run. Your reason is recorded and signed."
                      confirmLabel="Reject this action"
                      confirmVariant="danger"
                      submitName="decision"
                      submitValue="REJECT"
                      reason={{ label: "Reason (recorded, signed)", name: "reason", required: true, placeholder: "Why is this not acceptable?" }}
                      trigger={<Button variant="danger-outline" className="w-full"><X />Reject</Button>}
                    />
                  </div>
                </>
              ) : null}
              {pending && !canDecide ? <Notice className="mb-0">Your role ({who.roles.join(", ")}) can view but not decide approvals.</Notice> : null}
              {expired ? <div data-testid="expired-notice"><Notice kind="bad" className="mb-0">Expired: this approval can no longer be decided. Nothing was executed.</Notice></div> : null}
              {!pending && !expired ? <p className="text-caption text-gray-11">{v.state_reason ?? "This approval is no longer pending."}</p> : null}
            </CardBody>
          </Card>
        </aside>
      </div>
    </div>
  );
}
