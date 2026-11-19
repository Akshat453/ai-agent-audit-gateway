import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { ErrorState } from "@/components/empty-state";
import { FullTarget } from "@/components/humanize/full-target";
import { PhraseView } from "@/components/humanize/phrase";
import { IntactBadge, PlainLine, PlainSteps, PlainStory } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { EvidenceTimeline } from "@/components/evidence/timeline";
import { PullRequestsCard } from "@/components/github/pull-requests";
import { HashChip } from "@/components/hash-chip";
import { LifecycleStepper } from "@/components/lifecycle";
import { PageHeader } from "@/components/page-header";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { Timestamp } from "@/components/timestamp";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EMPTY, UUID_RE, middle } from "@/lib/format";
import { gateway } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { ruleBook } from "@/lib/rulebook";
import { actionStory, agentName, phraseOf, plainSteps } from "@/src/humanize";

export const metadata: Metadata = { title: "Action" };

export default async function ActionDetail({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string>> }) {
  const { id } = await params;
  const sp = await searchParams;
  if (!UUID_RE.test(id)) notFound();
  const gw = await gateway();
  const [{ data: a, response }, p, book] = await Promise.all([
    gw.GET("/v1/dashboard/actions/{action_id}", { params: { path: { action_id: id } } }),
    prefs(),
    ruleBook(),
  ]);
  if (!a) {
    return (
      <div className="mx-auto max-w-6xl">
        <PageHeader title="Action" crumbs={[{ label: "Operations" }, { label: "Runs", href: "/runs" }, { label: middle(id) }]} help="action" />
        <ErrorState what={response.status === 404 ? "This action does not exist in your organization. Check the link, or find it from its session under Runs." : "AgentGuard could not load this action. Try again in a moment."}
          requestId={response.headers.get("x-request-id")} retryHref={`/actions/${id}`} />
      </div>
    );
  }
  const epochs = [...new Set(a.events.map((e) => e.epoch_no).filter((n): n is number => n !== null && n !== undefined))];
  const anchors = a.events.map((e) => e.anchor).filter((x) => x);
  const broken = a.events.filter((e) => !e.hash_ok || e.link_ok === false || e.stored_copy_ok === false).length;
  const tab = sp.tab && ["overview", "evidence", "related"].includes(sp.tab) ? sp.tab : "evidence";
  const reasons = [...new Set(a.events.flatMap((e) => e.reasons))];
  const story = actionStory(a, book, p.tz);
  const phrase = phraseOf(a);
  const tone = a.status === "DENIED" || a.status === "FAILED" ? "bad" : a.status === "PENDING_APPROVAL" || a.status === "OUTCOME_UNKNOWN" ? "warn" : "ok";
  const headline = (
    <>{story.headline.lead}: {story.headline.actor} {story.headline.verb} <PhraseView phrase={phrase} />{story.headline.where}.</>
  );
  const steps = plainSteps(a).map((st) => ({ ...st, at: st.at ? <Timestamp iso={st.at} tz={p.tz} compact className="text-gray-11" /> : undefined }));

  return (
    <div className="mx-auto max-w-[1280px]">
      <PageHeader
        title={<span className="font-mono">{a.tool.id}<span className="text-gray-11">@{a.tool.version ?? "?"}</span></span>}
        help="action"
        crumbs={[{ label: "Operations" }, { label: "Runs", href: "/runs" }, { label: `Run ${middle(a.run_id, 6, 4)}`, href: `/runs/${a.run_id}` }, { label: `Action ${middle(a.action_id, 6, 4)}` }]}
        description={`Requested by ${p.view === "simple" ? agentName(a.agent.name) : a.agent.name} in ${a.environment}${a.delegation ? `, delegated by ${a.delegation.issuer ?? "another agent"}` : ""}.`}
        meta={<><StatusBadge value={a.status} /><RiskBadge level={a.risk_level} /><span className="text-caption text-gray-11">decision</span><StatusBadge value={a.decision} /></>}
      />

      {p.view === "simple" ? (
        <PlainStory headline={headline} tone={tone} happened={story.happened} why={story.why} who={story.who} canDo={story.canDo}>
          <FullTarget value={phrase.object} kind={phrase.kind} />
          <IntactBadge intact={story.intact} />
          <PlainSteps steps={steps} />
        </PlainStory>
      ) : <><PlainLine>{headline}</PlainLine><div className="mb-4"><FullTarget value={phrase.object} kind={phrase.kind} /></div></>}
      <PullRequestsCard runId={a.run_id} />
      <Technical view={p.view}>
      <Card className="mb-4">
        <CardBody><LifecycleStepper events={a.events} status={a.status} decision={a.decision} tz={p.tz} /></CardBody>
      </Card>

      <Tabs defaultValue={tab}>
        <TabsList aria-label="Action sections">
          <TabsTrigger value="evidence">Evidence timeline{broken ? <span className="ml-1.5 rounded-full border border-bad-7 bg-bad-3 px-1.5 text-[11px] font-semibold text-bad-12">{broken}<span className="sr-only"> broken</span></span> : null}</TabsTrigger>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="related">Related</TabsTrigger>
        </TabsList>

        <TabsContent value="evidence">
          <Card>
            <CardHeader title="Evidence timeline" description="Each lifecycle event, its hash, and the hash the next event commits to. Arguments and results are never shown." />
            <CardBody><EvidenceTimeline nodes={a.events} tz={p.tz} toolId={a.tool.id} /></CardBody>
          </Card>
        </TabsContent>

        <TabsContent value="overview">
          <Card>
            <CardHeader title="Overview" />
            <CardBody>
              <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-dense sm:grid-cols-[11rem_1fr]">
                <dt className="text-gray-11">Action id</dt><dd><HashChip value={a.action_id} label="action" head={8} tail={8} /></dd>
                <dt className="text-gray-11">Status</dt><dd><StatusBadge value={a.status} />{a.error_code ? <span className="ml-2 font-mono text-caption text-bad-11">{a.error_code}</span> : null}</dd>
                <dt className="text-gray-11">Decision</dt><dd><StatusBadge value={a.decision} /></dd>
                <dt className="text-gray-11">Risk</dt><dd><RiskBadge level={a.risk_level} /></dd>
                <dt className="text-gray-11">Tool</dt><dd><code className="font-mono">{a.tool.id}@{a.tool.version ?? "?"}</code></dd>
                <dt className="text-gray-11">Agent</dt><dd>{a.agent.name}</dd>
                {a.coding ? (<>
                  <dt className="text-gray-11">Action type</dt><dd><code className="font-mono">{a.coding.action_type}</code></dd>
                  <dt className="text-gray-11">Target (reported by the agent)</dt>
                  <dd>{a.coding.target ? <code className="break-all font-mono text-caption">{JSON.stringify(a.coding.target)}</code> : <span className="text-gray-11">not recorded for this action</span>}</dd>
                  <dt className="text-gray-11">Change size</dt><dd>{a.coding.diff ? `${a.coding.diff.files} file(s), +${a.coding.diff.added} / -${a.coding.diff.removed} lines` : EMPTY}</dd>
                </>) : null}
                {a.session ? (<>
                  <dt className="text-gray-11">Session</dt>
                  <dd>{a.session.agent_kind} {a.session.agent_version ?? ""} · developer {a.session.developer ?? EMPTY} · device {a.session.device ?? EMPTY} · repo {a.session.repo ?? EMPTY}{a.session.issue_number ? ` · issue #${a.session.issue_number}` : ""}</dd>
                </>) : null}
                <dt className="text-gray-11">Environment</dt><dd>{a.environment}</dd>
                <dt className="text-gray-11">Policy</dt><dd>{a.policy.id} v{a.policy.version} <a href="/policies" className="ml-1 text-caption">view policies</a></dd>
                <dt className="text-gray-11">Policy reasons</dt><dd>{reasons.length ? <ul className="list-disc pl-4">{reasons.map((r) => <li key={r}>{r}</li>)}</ul> : <span className="text-gray-11">{EMPTY}</span>}</dd>
                <dt className="text-gray-11">Created</dt><dd><Timestamp iso={a.created_at} tz={p.tz} /></dd>
                <dt className="text-gray-11">Last update</dt><dd><Timestamp iso={a.updated_at} tz={p.tz} /></dd>
              </dl>
              <p className="mt-4 rounded-md border border-gray-6 bg-gray-2 p-3 text-caption text-gray-11">
                Arguments and results are encrypted per event. An admin can grant an auditor a disclosure for specific events; it is opened with <code className="font-mono">agw-verify --auditor-key</code>.
              </p>
            </CardBody>
          </Card>
        </TabsContent>

        <TabsContent value="related">
          <Card>
            <CardHeader title="Related" />
            <CardBody>
              <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-dense sm:grid-cols-[11rem_1fr]">
                <dt className="text-gray-11">Run</dt><dd><HashChip value={a.run_id} href={`/runs/${a.run_id}`} label="run" /></dd>
                <dt className="text-gray-11">Delegation</dt>
                <dd>{a.delegation ? <>{a.delegation.issuer ?? "issuer"} → {a.agent.name} (depth {a.delegation.depth ?? "?"}) <HashChip value={a.delegation.delegation_id} label="delegation" /></> : <span className="text-gray-11">direct (no delegation)</span>}</dd>
                <dt className="text-gray-11">Approvals</dt>
                <dd>
                  {a.approvals.length ? (
                    <ul className="space-y-1">
                      {a.approvals.map((ap) => (
                        <li key={ap.approval_id} className="flex flex-wrap items-center gap-2">
                          <HashChip value={ap.approval_id} href={`/approvals/${ap.approval_id}`} label="approval" /><StatusBadge value={ap.state} />
                          <span className="text-caption text-gray-11">requested <Timestamp iso={ap.requested_at} tz={p.tz} /></span>
                        </li>
                      ))}
                    </ul>
                  ) : <span className="text-gray-11">none required</span>}
                </dd>
                <dt className="text-gray-11">Epochs</dt>
                <dd>{epochs.length ? epochs.map((n) => <a key={n} href={`/epochs?epoch=${n}`} className="mr-2">epoch {n}</a>) : <span className="text-gray-11">not sealed yet</span>}</dd>
                <dt className="text-gray-11">Anchors</dt>
                <dd>{anchors.length ? <span className="inline-flex flex-wrap gap-2">{[...new Map(anchors.map((x) => [x?.tx_hash ?? "", x])).values()].map((x) => x ? <span key={x.tx_hash ?? "none"} className="inline-flex items-center gap-1"><StatusBadge value={x.status} />{x.tx_hash ? <HashChip value={x.tx_hash} label="anchor transaction" href={x.explorer_url ?? undefined} /> : null}</span> : null)}</span> : <span className="text-gray-11">not anchored yet</span>}</dd>
                <dt className="text-gray-11">Events</dt><dd><a href={`/evidence?action_id=${a.action_id}`}>All {a.events.length} events of this action</a></dd>
              </dl>
            </CardBody>
          </Card>
        </TabsContent>
      </Tabs>
      </Technical>
    </div>
  );
}
