import { ArrowRight, CircleHelp } from "lucide-react";
import type { Metadata } from "next";

import { ActivityChart } from "@/components/charts/activity-chart";
import { EmptyState, ErrorState } from "@/components/empty-state";
import { PlainLine } from "@/components/humanize/plain";
import { RepoBanner } from "@/components/humanize/repo-switcher";
import { Technical } from "@/components/humanize/technical";
import { KpiTile } from "@/components/kpi-tile";
import { OnboardingChecklist } from "@/components/onboarding/checklist";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Tooltip } from "@/components/ui/overlay";
import { cn } from "@/lib/cn";
import type { Onboarding } from "@/lib/connectors";
import { count, delta, duration } from "@/lib/format";
import { gateway } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { repoScope } from "@/lib/repo-scope";
import { SERIES } from "@/lib/series";
import { approvalRequest, plainStatus, today } from "@/src/humanize";

export const metadata: Metadata = { title: "Overview" };

const RANGES = [["24h", "24 h"], ["7d", "7 days"], ["30d", "30 days"]] as const;
type Range = (typeof RANGES)[number][0];
const RISK_FILL: Record<string, string> = { LOW: "fill-info-9", MEDIUM: "fill-warn-9", HIGH: "fill-high-9", CRITICAL: "fill-bad-9" };

export default async function Overview({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const range: Range = (RANGES.map((r) => r[0]) as string[]).includes(sp.range ?? "") ? (sp.range as Range) : "24h";
  const gw = await gateway();
  const scope = await repoScope();
  const repo = scope.id ? { repo_id: scope.id } : {};
  const [ov, act, pend, inc, health, p, onboarding, session] = await Promise.all([
    gw.GET("/v1/dashboard/overview", { params: { query: { days: 30, ...repo } } }),
    gw.GET("/v1/dashboard/activity", { params: { query: { range, ...repo } } }),
    gw.GET("/v1/dashboard/approvals", { params: { query: { state: "PENDING", limit: 5, sort: "expires_at", order: "asc", ...repo } } }),
    gw.GET("/v1/dashboard/incidents", { params: { query: { kind: ["outcome_unknown", "alerts"], limit: 5, ...repo } } }),
    gw.GET("/v1/dashboard/health"),
    prefs(),
    gw.GET("/v1/onboarding"), // C2: new-tenant checklist
    gw.GET("/v1/dashboard/session"),
  ]);
  const ob = onboarding.data as Onboarding | undefined;
  const checklist = ob && Array.isArray(ob.steps) && !ob.complete
    ? <OnboardingChecklist data={ob} isAdmin={(session.data?.roles ?? []).includes("admin")} /> : null;
  if (!ov.data || !act.data) {
    return (
      <div className="mx-auto max-w-7xl">
        <PageHeader title="Overview" help="overview" />
        {checklist}
        <ErrorState what="The gateway did not return the overview." requestId={ov.response.headers.get("x-request-id")} retryHref="/" />
      </div>
    );
  }
  const o = ov.data;
  const a = act.data;
  const rangeLabel = RANGES.find((r) => r[0] === range)?.[1] ?? range;
  const pipe = a.pipeline;
  const lastResult = (o.last_verification?.result as string | undefined) ?? null;
  const unsealedOld = (pipe.recorded.oldest_waiting_seconds ?? 0) > 600;
  const unanchoredOld = (pipe.sealed.oldest_waiting_seconds ?? 0) > 3600;
  const evidence = lastResult && lastResult !== "VERIFIED" ? lastResult : unsealedOld || unanchoredOld ? "UNANCHORED" : lastResult ?? "UNANCHORED";
  const evidenceTone = evidence === "VERIFIED" ? "ok" : ["TAMPERED", "INVALID_PROOF", "UNTRUSTED_ANCHOR", "ERROR"].includes(evidence) ? "bad" : "warn";
  const riskTotal = Object.values(o.risk).reduce((x, y) => x + y, 0);
  const riskMax = Math.max(1, ...Object.values(o.risk));
  const attention = (pend.data?.rows.length ?? 0) + (inc.data?.length ?? 0);

  return (
    <div className="mx-auto max-w-[1440px]">
      <PageHeader
        title="Overview"
        help="overview"
        description="What your agents asked to do, what the policy decided, what waits for a human, and how far the evidence is from an on-chain anchor."
        actions={
          <nav aria-label="Time range" className="inline-flex rounded-md border border-gray-7 p-0.5">
            {RANGES.map(([k, label]) => (
              <a key={k} href={`/?range=${k}`} aria-current={k === range ? "true" : undefined}
                className={cn("rounded-sm px-2.5 py-1 text-caption font-medium no-underline hover:no-underline",
                  k === range ? "bg-gray-4 text-gray-12" : "text-gray-11 hover:text-gray-12")}>
                {label}
              </a>
            ))}
          </nav>
        }
      />

      {checklist}
      <RepoBanner name={scope.name} />

      {p.view === "simple" ? (
        <Card className="mb-6" data-testid="today">
          <CardHeader title="Today in plain English" />
          <CardBody><p className="text-body text-gray-12" data-testid="plain-headline">{today({ actions: a.current.actions, denied: a.current.denied, pending: o.pending_approvals, evidence, rangeLabel })}</p></CardBody>
        </Card>
      ) : <PlainLine>{today({ actions: a.current.actions, denied: a.current.denied, pending: o.pending_approvals, evidence, rangeLabel })}</PlainLine>}

      {/* KPI row */}
      <section aria-label="Key figures" className="mb-6 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <KpiTile label={`Actions (${rangeLabel})`} value={count(a.current.actions)} delta={delta(a.current.actions, a.previous.actions)} goodWhen="neutral"
          spark={a.buckets.map((b) => b.total)} href="/runs" linkLabel="open runs" explain="Everything agents asked AgentGuard to do." />
        <KpiTile label={`Denied (${rangeLabel})`} value={count(a.current.denied)} delta={delta(a.current.denied, a.previous.denied)} goodWhen="down"
          spark={a.buckets.map((b) => b.DENY)} href="/incidents" linkLabel="open denied incidents" tone={a.current.denied ? "warn" : undefined} explain="Requests AgentGuard stopped. Nothing was done for these." />
        <KpiTile label="Pending approvals" value={count(o.pending_approvals)} tone={o.pending_approvals ? "warn" : undefined}
          sub={o.pending_approvals ? `oldest waiting ${duration(o.oldest_pending_approval_seconds)}` : "nothing waiting"} href="/approvals?state=PENDING" linkLabel="review pending approvals" explain="Requests paused until a person says yes or no." />
        <KpiTile label="Evidence health" tone={evidenceTone}
          value={<StatusBadge value={evidence} size="lg" />}
          sub={o.last_verification ? <>last check <Timestamp iso={o.last_verification.at as string} tz={p.tz} /></> : "no verification yet"}
          href="/verification" linkLabel="open verification" explain={`Whether the log is untouched: ${plainStatus(evidence).toLowerCase()}.`} />
      </section>

      {p.view === "simple" ? (
        <Card className="mb-6">
          <CardHeader title="Needs you" description="Approvals waiting for a person, results nobody can confirm, and monitoring alerts" />
          {attention === 0 ? (
            <EmptyState title="Nothing needs you right now">When an agent needs a yes or no, it appears here and under Approvals.</EmptyState>
          ) : (
            <ul className="divide-y divide-gray-4 text-dense" data-testid="needs-you">
              {(pend.data?.rows ?? []).map((r) => {
                const q = approvalRequest(r);
                return (
                  <li key={r.approval_id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
                    <span>{q.actor} wants to {q.verb}{q.object ? <> <code className="rounded-sm bg-gray-3 px-1 font-mono">{q.object}</code></> : null}{q.tail}. <span className="text-gray-11">Expires <Timestamp iso={r.expires_at} tz={p.tz} compact className="text-gray-11" />.</span></span>
                    <a href={`/approvals/${r.approval_id}`} className="text-caption font-medium">Review</a>
                  </li>
                );
              })}
              {(inc.data ?? []).map((i, n) => (
                <li key={`${i.kind}-${i.action_id ?? n}-${i.at ?? ""}`} className="px-4 py-3">
                  {i.kind === "outcome_unknown" ? <>Nobody knows whether <code className="font-mono">{i.tool ?? "an action"}</code> happened. <a href="/incidents?kind=outcome_unknown">Record the result</a></> : <>Monitoring alert: {i.code ?? i.kind}. <a href="/verification">Open Verification</a></>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      ) : null}
      <Technical view={p.view} hint="charts, the evidence pipeline and system health">
      {/* Row 2 */}
      <div className="mb-6 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Actions over time" description={`By policy decision, ${rangeLabel}, ${a.bucket_seconds >= 86400 ? "daily" : a.bucket_seconds >= 21600 ? "6-hour" : "hourly"} buckets (UTC)`}
            action={
              <ul className="flex flex-wrap gap-3 text-caption text-gray-11" aria-label="Legend">
                {SERIES.map((s) => (
                  <li key={s.key} className="inline-flex items-center gap-1.5">
                    <svg width="10" height="10" aria-hidden="true"><rect width="10" height="10" rx="2" fill={s.color} /></svg>{s.label}
                  </li>
                ))}
              </ul>
            } />
          <CardBody>
            <p className="sr-only">
              {`${count(a.current.actions)} actions in the last ${rangeLabel}: ${a.buckets.reduce((x, b) => x + b.ALLOW, 0)} allowed, ${a.buckets.reduce((x, b) => x + b.REQUIRE_APPROVAL, 0)} needed approval, ${a.buckets.reduce((x, b) => x + b.DENY, 0)} denied.`}
            </p>
            {a.current.actions === 0 ? (
              <EmptyState title="No actions in this period">Actions appear here as soon as an agent calls a tool through the gateway.</EmptyState>
            ) : (
              <ActivityChart buckets={a.buckets} range={range} />
            )}
            <details className="mt-3 text-caption">
              <summary className="cursor-pointer text-gray-11 hover:text-gray-12">Show as table</summary>
              <div className="mt-2 max-h-64 overflow-auto rounded-md border border-gray-6">
                <table className="w-full text-caption">
                  <caption className="sr-only">Actions per bucket by decision</caption>
                  <thead className="bg-gray-2 text-gray-11"><tr><th scope="col" className="px-2 py-1 text-left font-medium">Bucket start (UTC)</th>{SERIES.map((s) => <th key={s.key} scope="col" className="px-2 py-1 text-right font-medium">{s.label}</th>)}</tr></thead>
                  <tbody>
                    {a.buckets.filter((b) => b.total > 0).map((b) => (
                      <tr key={b.start} className="border-t border-gray-4">
                        <td className="px-2 py-1 font-mono">{b.start.replace("T", " ").replace("Z", "")}</td>
                        <td className="px-2 py-1 text-right tabular">{b.ALLOW}</td>
                        <td className="px-2 py-1 text-right tabular">{b.REQUIRE_APPROVAL}</td>
                        <td className="px-2 py-1 text-right tabular">{b.DENY}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </details>
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Risk distribution" description="All actions, last 30 days" />
          <CardBody>
            <ul className="space-y-3">
              {Object.entries(o.risk).map(([level, n]) => (
                <li key={level} className="grid grid-cols-[6.5rem_1fr_3.5rem] items-center gap-3">
                  <RiskBadge level={level} />
                  <svg viewBox="0 0 100 10" preserveAspectRatio="none" className="h-2.5 w-full" role="img" aria-label={`${level}: ${n} of ${riskTotal}`}>
                    <rect x="0" y="0" width="100" height="10" rx="2" className="fill-gray-4" />
                    <rect x="0" y="0" width={Math.max(n ? 1.5 : 0, (n / riskMax) * 100)} height="10" rx="2" className={RISK_FILL[level] ?? "fill-gray-9"} />
                  </svg>
                  <span className="text-right text-dense tabular">{count(n)} <span className="text-gray-11">{riskTotal ? `${Math.round((n / riskTotal) * 100)}%` : ""}</span></span>
                </li>
              ))}
            </ul>
            <div className="mt-5 border-t border-gray-5 pt-4">
              <h3 className="mb-2 text-caption font-medium text-gray-11">Decisions, all time</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(o.decisions).map(([k, v]) => (
                  <span key={k} className="inline-flex items-center gap-1.5"><StatusBadge value={k} /><span className="text-dense tabular">{count(v)}</span></span>
                ))}
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      {/* Row 3 */}
      <div className="mb-6 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader title="Needs your attention" description="Soonest-expiring approvals first, then unknown outcomes and alerts"
            action={<a href="/approvals?state=PENDING" className="inline-flex items-center gap-1 text-caption font-medium">All approvals<ArrowRight aria-hidden="true" className="size-3.5" /></a>} />
          {attention === 0 ? (
            <EmptyState title="Nothing needs you right now">Pending approvals, actions with an unknown outcome and monitor alerts show up here.</EmptyState>
          ) : (
            <ul className="divide-y divide-gray-4">
              {(pend.data?.rows ?? []).map((r) => (
                <li key={r.approval_id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                  <RiskBadge level={r.risk_level} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-dense font-medium"><code className="font-mono">{r.tool.id}</code> by {r.agent.name}{r.delegated_by ? <span className="text-gray-11"> (delegated by {r.delegated_by})</span> : null}</div>
                    <div className="text-caption text-gray-11">Approval requested <Timestamp iso={r.requested_at} tz={p.tz} className="text-gray-11" /> · expires <Timestamp iso={r.expires_at} tz={p.tz} className="text-gray-11" /></div>
                  </div>
                  <a href={`/approvals/${r.approval_id}`} className="inline-flex h-7 items-center rounded-md border border-gray-7 px-2.5 text-caption font-medium text-gray-12 no-underline hover:bg-gray-3 hover:no-underline">Review</a>
                </li>
              ))}
              {(inc.data ?? []).map((i, n) => (
                <li key={`${i.kind}-${i.action_id ?? n}-${i.at ?? ""}`} className="flex flex-wrap items-center gap-3 px-4 py-3">
                  <StatusBadge value={i.kind === "outcome_unknown" ? "OUTCOME_UNKNOWN" : i.status ?? "ERROR"} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-dense font-medium">{i.kind === "outcome_unknown" ? <>Unknown outcome: <code className="font-mono">{i.tool ?? "tool"}</code></> : <>Alert: {i.code ?? i.kind}</>}</div>
                    <div className="text-caption text-gray-11"><Timestamp iso={i.at} tz={p.tz} className="text-gray-11" /></div>
                  </div>
                  {i.action_id ? <a href={`/actions/${i.action_id}`} className="inline-flex h-7 items-center rounded-md border border-gray-7 px-2.5 text-caption font-medium text-gray-12 no-underline hover:bg-gray-3 hover:no-underline">Open</a> : <a href="/incidents" className="text-caption">Incidents</a>}
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader title="Evidence pipeline" description="Every event: recorded → sealed into an epoch → anchored → final on chain" />
          <CardBody>
            <ol className="space-y-0">
              {([
                ["Recorded", pipe.recorded, "in the hash chain", "not sealed yet"],
                ["Sealed", pipe.sealed, "in a Merkle epoch", "not anchored yet"],
                ["Anchored", pipe.anchored, "included on chain", "not final yet"],
                ["Finalized", pipe.finalized, "final on chain", ""],
              ] as const).map(([name, st, what, waiting], i, all) => {
                const total = pipe.recorded.count || 1;
                const pct = Math.round((st.count / total) * 100);
                const lag = st.oldest_waiting_seconds;
                return (
                  <li key={name} className="relative flex gap-3 pb-4 last:pb-0">
                    {i < all.length - 1 ? <span aria-hidden="true" className="absolute left-[9px] top-5 h-full w-px bg-gray-6" /> : null}
                    <span aria-hidden="true" className={cn("relative z-10 mt-0.5 flex size-[19px] shrink-0 items-center justify-center rounded-full border-2",
                      st.count && pct === 100 ? "border-ok-9 bg-ok-9" : st.count ? "border-brand-9 bg-gray-1" : "border-gray-7 bg-gray-1")}>
                      {st.count && pct === 100 ? <svg viewBox="0 0 12 12" className="size-2.5"><path d="M2.5 6.2 5 8.5l4.5-5" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg> : null}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-baseline justify-between gap-2">
                        <span className="text-dense font-medium">{name}</span>
                        <span className="text-dense tabular">{count(st.count)} <span className="text-caption text-gray-11">{pct}%</span></span>
                      </div>
                      <div className="text-caption text-gray-11">
                        {what}
                        {waiting && lag !== null && lag !== undefined ? <> · oldest {waiting}: <span className={cn("tabular", lag > 3600 ? "font-medium text-warn-12" : "")}>{duration(lag)}</span></> : null}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>
            {!pipe.anchoring_configured ? <p className="mt-3 text-caption text-gray-11">Anchoring is not configured for this tenant.</p> : null}
          </CardBody>
        </Card>
      </div>

      {/* Row 4: system health */}
      <section id="health" aria-labelledby="health-title" className="scroll-mt-16">
        <div className="mb-2 flex items-center gap-2">
          <h2 id="health-title" className="text-section font-semibold">System health</h2>
          <Tooltip content="Gateway and database answer this page; worker = queued jobs; anchoring = anchor progress; monitor = the latest independent verification run.">
            <span tabIndex={0} className="text-gray-11"><CircleHelp className="size-4" aria-label="About system health" /></span>
          </Tooltip>
        </div>
        <ul className="flex flex-wrap gap-2">
          {(health.data ?? []).map((c) => (
            <li key={c.name} className="inline-flex items-center gap-2 rounded-md border border-gray-6 bg-gray-1 px-3 py-2 text-dense">
              <span aria-hidden="true" className={cn("size-2 rounded-full", { ok: "bg-ok-9", degraded: "bg-warn-9", down: "bg-bad-9", off: "bg-gray-8" }[c.status])} />
              <span className="font-medium capitalize">{c.name}</span>
              <span className="text-gray-11">{c.status === "ok" ? "OK" : c.status === "off" ? "Off" : c.status === "down" ? "Down" : "Degraded"} · {c.detail}</span>
              {c.at ? <Timestamp iso={c.at} tz={p.tz} className="text-caption text-gray-11" /> : null}
            </li>
          ))}
        </ul>
      </section>
      </Technical>
    </div>
  );
}
