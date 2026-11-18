import { StatusBadge } from "@/components/status-badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { getJson } from "@/lib/gateway";

type PR = { repo: string; number: number; state: string; conclusion: string | null; html_url: string | null; summary: string };

export function checkKey(conclusion: string | null): string {
  return conclusion === "success" ? "CHECK_SUCCESS" : conclusion === "failure" ? "CHECK_FAILURE"
    : conclusion === "in_progress" ? "CHECK_IN_PROGRESS" : "CHECK_NONE";
}

/** C3: pull requests linked to a run, with the AgentGuard evidence check. Server component. */
export async function PullRequestsCard({ runId }: { runId: string }) {
  const { body } = await getJson<{ pull_requests: PR[] }>(`/v1/dashboard/runs/${runId}/prs`);
  const prs = body?.pull_requests ?? [];
  if (!prs.length) return null;
  return (
    <Card className="mb-4" data-testid="run-prs">
      <CardHeader title="Pull requests" description="Opened from this run. The AgentGuard evidence check blocks merging unless every commit is recorded and verified." />
      <CardBody>
        <ul className="divide-y divide-gray-4 text-dense">
          {prs.map((p) => (
            <li key={`${p.repo}#${p.number}`} className="flex flex-wrap items-center gap-3 py-2">
              {p.html_url ? <a href={p.html_url} rel="noreferrer noopener" className="font-mono underline">{p.repo}#{p.number}</a>
                : <span className="font-mono">{p.repo}#{p.number}</span>}
              <span className="text-caption text-gray-11">{p.state}</span>
              <StatusBadge value={checkKey(p.conclusion)} />
              {p.summary ? <span className="text-caption text-gray-11">{(p.summary.split("\n")[0] ?? "").slice(0, 160)}</span> : null}
            </li>
          ))}
        </ul>
      </CardBody>
    </Card>
  );
}
