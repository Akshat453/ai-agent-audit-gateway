import { ArrowRight } from "lucide-react";
import type { Metadata } from "next";

import { ApprovalsTable } from "@/components/approvals-table";
import { CodeView } from "@/components/code-view";
import { ErrorState } from "@/components/empty-state";
import { HashChip } from "@/components/hash-chip";
import { PlainLine } from "@/components/humanize/plain";
import { RepoBanner } from "@/components/humanize/repo-switcher";
import { PageHeader } from "@/components/page-header";
import { SplitPanel } from "@/components/split-panel";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { APPROVAL_STATES, type ApprovalView } from "@/lib/approval";
import { UUID_RE } from "@/lib/format";
import { gateway, getJson } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { repoScope } from "@/lib/repo-scope";
import { ALL_RISKS } from "@/lib/status";
import { agentName, approvalRequest, riskWord, spanWords } from "@/src/humanize";

export const metadata: Metadata = { title: "Approvals" };

const PAGE = 25;
const SORTS = ["expires_at", "requested_at", "risk", "tool"] as const;

export default async function Approvals({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const state = sp.state === "ALL" ? undefined : APPROVAL_STATES.includes(sp.state ?? "") ? sp.state : "PENDING";
  const risk = ALL_RISKS.includes(sp.risk ?? "") ? sp.risk : undefined;
  const tool = sp.tool && /^[a-z0-9_.-]{1,64}$/i.test(sp.tool) ? sp.tool : undefined;
  const sort = (SORTS as readonly string[]).includes(sp.sort ?? "") ? (sp.sort as (typeof SORTS)[number]) : "expires_at";
  const order = sp.order === "desc" ? "desc" : "asc";
  const page = Math.max(1, Number(sp.page ?? "1") || 1);
  const sel = sp.sel && UUID_RE.test(sp.sel) ? sp.sel : null;

  const gw = await gateway();
  const scope = await repoScope();
  const [list, p, view] = await Promise.all([
    gw.GET("/v1/dashboard/approvals", {
      params: { query: { state: state as never, risk: risk as never, tool, sort, order, limit: PAGE, offset: (page - 1) * PAGE, ...(scope.id ? { repo_id: scope.id } : {}) } },
    }),
    prefs(),
    sel ? getJson<ApprovalView>(`/v1/approvals/${sel}`) : Promise.resolve(null),
  ]);
  const fetchedAt = new Date().toISOString();

  let panel = null;
  if (sel && view?.body) {
    const v = view.body;
    panel = (
      <SplitPanel title={`${v.action.tool.id}@${v.action.tool.version}`} fullHref={`/approvals/${v.approval_id}`}>
        <div className="space-y-4 text-dense">
          <p className="text-body text-gray-12" data-testid="panel-sentence">{agentName(v.action.agent.name)} wants to {approvalRequest({ tool: v.action.tool, agent: v.action.agent, risk_level: v.action.risk.level, state: v.state }).verb}. Risk: {riskWord(v.action.risk.level)}.</p>
          <div className="flex flex-wrap gap-2"><StatusBadge value={v.state} /><RiskBadge level={v.action.risk.level} /></div>
          <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-2">
            <dt className="text-gray-11">Agent</dt><dd>{v.action.agent.name}</dd>
            <dt className="text-gray-11">Environment</dt><dd>{v.action.environment}</dd>
            <dt className="text-gray-11">Policy</dt><dd>{v.action.policy.id} v{v.action.policy.version}</dd>
            <dt className="text-gray-11">Action</dt><dd><HashChip value={v.action.action_id} href={`/actions/${v.action.action_id}`} label="action" /></dd>
            <dt className="text-gray-11">Run</dt><dd><HashChip value={v.action.run_id} href={`/runs/${v.action.run_id}`} label="run" /></dd>
          </dl>
          <div>
            <h3 className="mb-1 text-caption font-medium text-gray-11">Why it needs approval</h3>
            <ul className="list-disc space-y-0.5 pl-4">{[...v.action.risk.reasons, ...v.action.policy.reasons].map((r) => <li key={r}>{r}</li>)}</ul>
          </div>
          <div>
            <h3 className="mb-1 text-caption font-medium text-gray-11">Target</h3>
            <CodeView text={v.action.target_rendered} max={600} label="target preview" />
          </div>
          <div>
            <h3 className="mb-1 text-caption font-medium text-gray-11">Arguments (preview)</h3>
            <CodeView text={v.action.args_rendered} max={600} label="arguments preview" />
          </div>
          <a href={`/approvals/${v.approval_id}`} className="inline-flex h-8 items-center gap-1.5 rounded-md bg-brand-9 px-3 text-dense font-medium text-white no-underline hover:bg-brand-10 hover:no-underline">
            Review and decide<ArrowRight aria-hidden="true" className="size-4" />
          </a>
        </div>
      </SplitPanel>
    );
  }

  return (
    <div className="mx-auto max-w-[1440px]">
      <PageHeader
        title="Approvals"
        help="approvals"
        crumbs={[{ label: "Operations" }, { label: "Approvals" }]}
        description="Actions the policy will not run without a human. Soonest expiry first; open one to review exactly what will run."
      />
      <RepoBanner name={scope.name} />
      {list.data ? (() => {
        const pendingRows = list.data.rows.filter((r) => r.state === "PENDING" && r.expires_at);
        const soonest = pendingRows.map((r) => Date.parse(r.expires_at ?? "")).filter((t) => !Number.isNaN(t)).sort((x, y) => x - y)[0];
        const left = soonest !== undefined ? Math.round((soonest - Date.parse(fetchedAt)) / 1000) : null;
        return (
          <PlainLine>
            {state === "PENDING" || state === undefined
              ? pendingRows.length
                ? `${pendingRows.length} request${pendingRows.length === 1 ? " is" : "s are"} waiting for a person.${left !== null && left > 0 ? ` The soonest expires in ${spanWords(left)}.` : ""} Open one to see exactly what would run, then approve or reject it.`
                : "Nothing is waiting for approval right now."
              : `Showing ${list.data.total} ${String(state ?? "").toLowerCase()} request${list.data.total === 1 ? "" : "s"}.`}
          </PlainLine>
        );
      })() : null}
      {list.data ? (
        <ApprovalsTable rows={list.data.rows} total={list.data.total} pageSize={PAGE} fetchedAt={fetchedAt} panel={panel} tz={p.tz} nowMs={Date.parse(fetchedAt)} />
      ) : (
        <ErrorState
          what={list.response.status === 403 ? "Your role cannot see approvals. Ask an admin to give you the approver or auditor role." : "AgentGuard could not load the approvals list. Try again in a moment."}
          requestId={list.response.headers.get("x-request-id")}
          retryHref="/approvals"
        />
      )}
    </div>
  );
}
