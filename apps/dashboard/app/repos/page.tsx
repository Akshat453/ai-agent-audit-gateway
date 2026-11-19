import { Check, X } from "lucide-react";
import type { Metadata } from "next";

import { CodeView } from "@/components/code-view";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { EmptyState, ErrorState } from "@/components/empty-state";
import { CsrfField } from "@/components/legacy";
import { Notice } from "@/components/notice";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { StepUpCard } from "@/components/step-up";
import { Timestamp } from "@/components/timestamp";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { message, viewer } from "@/lib/c2";
import { tierKey, type Repo } from "@/lib/connectors";
import { prefs } from "@/lib/prefs";


export const metadata: Metadata = { title: "Repositories" };

function List({ label, items }: { label: string; items: string[] }) {
  return (
    <div>
      <dt className="text-caption font-medium text-gray-11">{label}</dt>
      <dd className="mt-0.5">{items.length ? <ul className="flex flex-wrap gap-1">{items.map((x) => <li key={x}><code className="rounded-sm bg-gray-3 px-1 font-mono text-caption">{x}</code></li>)}</ul> : <span className="text-caption text-gray-11">none</span>}</dd>
    </div>
  );
}

export default async function Repos({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const { gw, isAdmin, csrf, stepUpRemaining, stepUpWindow } = await viewer();
  const [res, p] = await Promise.all([gw.GET("/v1/repos"), prefs()]);
  const header = (
    <PageHeader toggle={false} title="Repositories" help="repos" crumbs={[{ label: "Setup" }, { label: "Repositories" }]}
      description="Repositories registered by agw init, the tighten-only policy overlay from their .agentguard.yaml, and loosening proposals waiting for an admin." />
  );
  if (!res.data) {
    return (
      <div className="mx-auto max-w-6xl">
        {header}
        <ErrorState what={res.response.status === 403 ? "Your role cannot view repositories (admin, auditor, security or maintainer)." : "The gateway did not return the repositories."}
          requestId={res.response.headers.get("x-request-id")} retryHref="/repos" />
      </div>
    );
  }
  const repos = (res.data as { repos?: Repo[] }).repos ?? [];
  const msg = message(sp.result ?? sp.error);
  const pending = repos.reduce((n, r) => n + r.proposals.length, 0);
  return (
    <div className="mx-auto max-w-6xl">
      {header}
      {msg ? <Notice kind={msg.kind}>{msg.text}</Notice> : null}
      {isAdmin && pending ? <StepUpCard csrf={csrf} next="/repos" remaining={stepUpRemaining} windowSeconds={stepUpWindow} what="decide proposals" /> : null}
      {repos.length === 0 ? (
        <Card><EmptyState title="No repositories yet">A developer runs <code className="font-mono">agw init</code> inside a repository on an enrolled device; it registers here with its .agentguard.yaml.</EmptyState></Card>
      ) : (
        <div className="space-y-4">
          {repos.map((r) => {
            const o = r.overlay ?? {};
            const sensitive = (o.sensitive ?? []).map((s) => (typeof s === "string" ? s : `${s.path}${s.level ? ` (${s.level})` : ""}`));
            return (
              <Card key={r.repo_id} data-testid={`repo-${r.name}`}>
                <CardHeader title={r.name} description={r.remote_url}
                  action={<span className="text-caption text-gray-12">policy v{r.policy_version}</span>} />
                <CardBody className="space-y-4">
                  {Object.keys(r.agents ?? {}).length ? (
                    <div>
                      <h3 className="mb-1 text-caption font-medium text-gray-11">Coding agents set up here</h3>
                      <ul className="flex flex-wrap gap-2">
                        {Object.entries(r.agents).map(([kind, a]) => (
                          <li key={kind} className="inline-flex items-center gap-1.5 text-dense"><code className="font-mono">{kind}</code>{tierKey(a.tier) ? <StatusBadge value={tierKey(a.tier)!} size="sm" /> : null}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                  <dl className="grid gap-3 sm:grid-cols-2">
                    <List label="Sensitive paths" items={sensitive} />
                    <List label="Denied paths" items={o.deny_paths ?? []} />
                    <List label="Denied commands" items={o.deny_commands ?? []} />
                    <List label="Allowed paths (approved loosening)" items={o.allow_paths ?? []} />
                    <List label="Allowed commands (approved loosening)" items={o.allow_commands ?? []} />
                  </dl>
                  {r.proposals.length ? (
                    <section aria-label={`Proposals for ${r.name}`} className="space-y-3">
                      <h3 className="text-dense font-semibold">Loosening proposals</h3>
                      {r.proposals.map((pr) => (
                        <div key={pr.proposal_id} className="rounded-md border border-warn-7 p-3" data-testid="proposal">
                          <div className="mb-2 flex flex-wrap items-center gap-2 text-caption text-gray-11">
                            <StatusBadge value="PROPOSAL_PENDING" size="sm" />proposed <Timestamp iso={pr.created_at} tz={p.zone} />
                          </div>
                          <CodeView text={pr.diff || "(no textual change)"} max={6000} label="proposed policy diff" />
                          {isAdmin ? (
                            <>
                              <form id={`prop-${pr.proposal_id}`} method="post" action={`/api/repos/proposals/${pr.proposal_id}/decision`}><CsrfField csrf={csrf} /></form>
                              <div className="mt-3 flex flex-wrap gap-2">
                                <ConfirmDialog formId={`prop-${pr.proposal_id}`} title={`Approve loosening for ${r.name}?`}
                                  description="The overlay becomes the proposed one (a new repository policy version). Agents in this repository get the allowed paths or commands."
                                  confirmLabel="Approve proposal" confirmVariant="approve" submitName="decision" submitValue="approve"
                                  reason={{ label: "Reason (recorded)", name: "reason", required: false, placeholder: "Optional" }}
                                  trigger={<Button variant="approve" size="sm"><Check />Approve</Button>} />
                                <ConfirmDialog formId={`prop-${pr.proposal_id}`} title={`Reject loosening for ${r.name}?`} description="Nothing is loosened. The decision is recorded."
                                  confirmLabel="Reject proposal" confirmVariant="danger" submitName="decision" submitValue="reject"
                                  reason={{ label: "Reason (recorded)", name: "reason", required: true, placeholder: "Why not?" }}
                                  trigger={<Button variant="danger-outline" size="sm"><X />Reject</Button>} />
                              </div>
                            </>
                          ) : null}
                        </div>
                      ))}
                    </section>
                  ) : null}
                </CardBody>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
