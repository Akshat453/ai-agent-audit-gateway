import { StatusBadge } from "@/components/status-badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { checkKey } from "@/components/github/pull-requests";
import { getJson } from "@/lib/gateway";

type Gh = {
  installation_ids: number[]; repos: string[]; mode: string; app_slug: string | null; webhook_url: string;
  deliveries: { event: string; action: string | null; verified: boolean; outcome: string; received_at: string }[];
  pull_requests: { repo: string; number: number; state: string; conclusion: string | null; html_url: string | null; run_id: string | null }[];
};

/** C3: installation, repositories, webhook health and tracked PRs of a GitHub connector. */
export async function GithubStatusCard({ connectorId }: { connectorId: string }) {
  const { body: g } = await getJson<Gh>(`/v1/connectors/${connectorId}/github`);
  if (!g) return null;
  const verified = g.deliveries.filter((d) => d.verified).length;
  const last = g.deliveries[0];
  return (
    <Card data-testid="github-status">
      <CardHeader title="GitHub status" description="Where the App is installed, how events arrive, and the evidence check on tracked pull requests." />
      <CardBody>
        <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-dense">
          <dt className="text-gray-11">Installations</dt><dd>{g.installation_ids.length ? g.installation_ids.join(", ") : "not installed"}</dd>
          <dt className="text-gray-11">Repositories</dt><dd className="font-mono">{g.repos.join(", ") || "none configured"}</dd>
          <dt className="text-gray-11">Event delivery</dt><dd>{g.mode === "polling" ? "polling (every 60 s)" : "webhook"}</dd>
          <dt className="text-gray-11">Webhook URL</dt><dd className="font-mono break-all">{g.webhook_url}</dd>
          <dt className="text-gray-11">Webhook health</dt>
          <dd>{last ? `${verified} of the last ${g.deliveries.length} deliveries verified (latest ${last.event}${last.action ? `/${last.action}` : ""}: ${last.outcome})` : "no deliveries yet"}</dd>
        </dl>
        {g.pull_requests.length ? (
          <ul className="mt-3 divide-y divide-gray-4 text-dense">
            {g.pull_requests.map((p) => (
              <li key={`${p.repo}#${p.number}`} className="flex flex-wrap items-center gap-3 py-1.5">
                <span className="font-mono">{p.repo}#{p.number}</span>
                <span className="text-caption text-gray-11">{p.state}</span>
                <StatusBadge value={checkKey(p.conclusion)} />
                {p.run_id ? <a className="underline text-caption" href={`/runs/${p.run_id}`}>run</a> : null}
              </li>
            ))}
          </ul>
        ) : null}
      </CardBody>
    </Card>
  );
}
