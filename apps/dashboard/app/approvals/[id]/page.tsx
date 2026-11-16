import { notFound } from "next/navigation";

import { Countdown } from "@/components/Countdown";
import { Badge, Card, CsrfField, Notice, Page, SafeText } from "@/components/ui";
import { getJson, me } from "@/lib/gateway";
import { csrfToken } from "@/lib/session";

type View = {
  approval_id: string; state: string; state_reason: string | null; required_approvals: number;
  requested_at: string; expires_at: string; action_digest: string; nonce: string;
  action: {
    action_id: string; run_id: string; status: string; agent: { id: string; name: string };
    tool: { id: string; version: string }; environment: string; args_rendered: string;
    target_rendered: string; delegation_depth: number | null;
    risk: { level: string; score: number; rules: string[]; reasons: string[] };
    policy: { id: string; version: number; effect: string; rules: string[]; reasons: string[]; controls: string[] };
  };
  decisions: { approver: string; decision: string; decided_at_us: number }[];
};

const MESSAGES: Record<string, [string, "good" | "bad" | "warn"]> = {
  APPROVED: ["Approved. The gateway re-validated the action and authorized it.", "good"],
  REJECTED: ["Rejected. The action will not run.", "good"],
  PENDING: ["Your approval is recorded and signed; another approver is needed (four-eyes).", "good"],
  STEP_UP_REQUIRED: ["Re-enter your password (step-up) before approving a CRITICAL action.", "warn"],
  STEP_UP_FAILED: ["Step-up failed.", "bad"],
  APPROVAL_EXPIRED: ["This approval has expired. Nothing was executed.", "bad"],
  APPROVAL_STALE: ["The action changed since you opened it. Reload and review again.", "bad"],
  FORBIDDEN: ["Your role cannot decide approvals.", "bad"],
  APPROVAL_NOT_PENDING: ["This approval is no longer pending.", "bad"],
  APPROVAL_ALREADY_DECIDED: ["You already decided this approval (four-eyes needs a different approver).", "bad"],
};

export default async function Approval({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string>> }) {
  const { id } = await params;
  const sp = await searchParams;
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) notFound();
  const [{ body: v, status }, who, csrf] = await Promise.all([getJson<View>(`/v1/approvals/${id}`), me(), csrfToken()]);
  if (!v) return <Page title="Approval">{status === 404 ? "Not found." : "You cannot view approvals."}</Page>;
  const a = v.action;
  const secondsLeft = Math.round((Date.parse(v.expires_at) - Date.now()) / 1000);
  const expired = v.state === "EXPIRED" || secondsLeft <= 0;
  const pending = v.state === "PENDING" && !expired;
  const canDecide = who.roles.includes("approver");
  const needsStepUp = who.step_up_levels.includes(a.risk.level);
  const msg = sp.result ?? sp.error;
  return (
    <Page title={`Approval: ${a.tool.id}@${a.tool.version}`} lead="Review exactly what will run. Values are shown escaped; secret fields are redacted markers.">
      {msg ? <Notice kind={(MESSAGES[msg] ?? [msg, "warn"])[1]}>{(MESSAGES[msg] ?? [`Gateway answered: ${msg}`, "warn"])[0]}</Notice> : null}
      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Action">
          <dl className="grid grid-cols-[10rem_1fr] gap-x-2 gap-y-1 text-sm">
            <dt>State</dt><dd><Badge value={expired && v.state === "PENDING" ? "EXPIRED" : v.state} /> {v.state_reason ?? ""}</dd>
            <dt>Expiry</dt><dd>{pending ? <Countdown expiresAt={v.expires_at} initialSeconds={secondsLeft} /> : <span data-testid="countdown" className="font-bold">{expired ? "EXPIRED" : v.state}</span>} <span className="text-xs">({v.expires_at})</span></dd>
            <dt>Tool</dt><dd><code>{a.tool.id}</code> version <code>{a.tool.version}</code></dd>
            <dt>Environment</dt><dd>{a.environment}</dd>
            <dt>Agent</dt><dd>{a.agent.name}</dd>
            <dt>Delegation depth</dt><dd>{a.delegation_depth ?? "direct"}</dd>
            <dt>Risk</dt><dd><Badge value={a.risk.level} /> score {a.risk.score}</dd>
            <dt>Risk rules</dt><dd>{a.risk.rules.join(", ") || "-"}</dd>
            <dt>Policy</dt><dd>{a.policy.id} v{a.policy.version} → <Badge value={a.policy.effect} /> ({a.policy.rules.join(", ")})</dd>
            <dt>Approvals needed</dt><dd>{v.required_approvals} ({v.decisions.map((d) => `${d.approver}: ${d.decision}`).join(", ") || "none yet"})</dd>
            <dt>Action digest</dt><dd><code className="break-all" data-testid="digest">{v.action_digest}</code></dd>
          </dl>
          <h3 className="mt-3 font-semibold">Risk reasons</h3>
          <ul className="list-inside list-disc text-sm">{a.risk.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        </Card>
        <Card title="Exact arguments (canonical, escaped)">
          <h3 className="text-sm font-semibold">Target</h3>
          <SafeText text={a.target_rendered} max={1000} label="target" />
          <h3 className="mt-2 text-sm font-semibold">Arguments</h3>
          <SafeText text={a.args_rendered} max={4000} label="arguments" />
        </Card>
      </div>
      {pending && canDecide ? (
        <Card title="Decide">
          {needsStepUp ? (
            <form method="post" action="/api/auth/step-up" className="mb-3 flex flex-wrap items-end gap-2 rounded border border-amber-700 bg-amber-50 p-2">
              <CsrfField csrf={csrf} />
              <input type="hidden" name="approval_id" value={v.approval_id} />
              <label className="text-sm">
                {a.risk.level} action: re-enter your password (step-up, valid {who.step_up_window_seconds} s)
                <input name="password" type="password" required autoComplete="current-password" className="ml-2 rounded border border-slate-400 px-2 py-1" />
              </label>
              <button type="submit" className="rounded border border-amber-800 px-2 py-1 text-sm">Re-authenticate</button>
              {sp.stepped ? <span className="text-sm font-semibold text-green-900">re-authenticated</span> : null}
            </form>
          ) : null}
          <form method="post" action={`/api/approvals/${v.approval_id}/decision`} className="space-y-2">
            <CsrfField csrf={csrf} />
            <input type="hidden" name="action_digest" value={v.action_digest} />
            <input type="hidden" name="nonce" value={v.nonce} />
            <label className="block text-sm">
              Reason (recorded, signed)
              <input name="reason" maxLength={1024} className="mt-1 block w-full rounded border border-slate-400 px-2 py-1" />
            </label>
            <div className="flex gap-2">
              <button type="submit" name="decision" value="APPROVE" className="rounded bg-green-800 px-3 py-1 font-semibold text-white">Approve exactly this action</button>
              <button type="submit" name="decision" value="REJECT" className="rounded bg-red-800 px-3 py-1 font-semibold text-white">Reject</button>
            </div>
          </form>
        </Card>
      ) : null}
      {pending && !canDecide ? <Notice>Your role ({who.roles.join(", ")}) can view but not decide approvals.</Notice> : null}
      {expired ? <div data-testid="expired-notice"><Notice kind="bad">Expired: this approval can no longer be decided. Nothing was executed.</Notice></div> : null}
    </Page>
  );
}
