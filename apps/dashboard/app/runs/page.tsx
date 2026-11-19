import { EmptyState } from "@/components/empty-state";
import { PlainLine } from "@/components/humanize/plain";
import { RepoBanner } from "@/components/humanize/repo-switcher";
import { Technical } from "@/components/humanize/technical";
import { Badge, Page, short } from "@/components/legacy";
import { Timestamp } from "@/components/timestamp";
import { gateway } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { repoScope } from "@/lib/repo-scope";
import { agentName, githubRunTitle, runCounts, sessionTitle } from "@/src/humanize";

export default async function Runs() {
  const scope = await repoScope();
  const [{ data }, p] = await Promise.all([(await gateway()).GET("/v1/dashboard/runs", { params: { query: { limit: 100, ...(scope.id ? { repo_id: scope.id } : {}) } } }), prefs()]);
  const rows = data ?? [];
  const sessions = rows.filter((r) => r.session).length;
  return (
    <Page title="Runs" help="runs" lead={p.view === "simple" ? "Each line is one agent working session: who ran it, where, and what AgentGuard decided." : "A run groups the actions an agent submitted under one run id. Delegated runs carry a verified delegation chain."}>
      <RepoBanner name={scope.name} />
      <PlainLine>{rows.length ? `${rows.length} session${rows.length === 1 ? "" : "s"} shown, ${sessions} of them coding-agent sessions${rows.some((r) => !r.session && r.repos?.length) ? "; \"GitHub steps\" lines are the agent's GitHub actions (read issue, submit change, open pull request)" : ""}. Open one to see its story.` : "No agent sessions yet."}</PlainLine>
      {p.view === "simple" ? (
        rows.length ? (
          <ul className="mb-4 divide-y divide-gray-4 rounded-md border border-gray-6 bg-gray-1" aria-label="Sessions" data-testid="run-sentences">
            {rows.map((r) => (
              <li key={r.run_id} className="flex flex-wrap items-baseline justify-between gap-2 px-4 py-3 text-dense">
                <a href={`/runs/${r.run_id}`} className="font-medium text-gray-12">
                  {r.session ? sessionTitle(r.session, r.first_at, p.zone) : r.repos?.length ? githubRunTitle(r.agents, r.repos) : `Session by ${r.agents.map(agentName).join(", ")}`}
                </a>
                <span className="text-gray-11">{runCounts(r)} · last active <Timestamp iso={r.last_at} tz={p.zone} compact /></span>
              </li>
            ))}
          </ul>
        ) : <EmptyState title="No sessions yet">Sessions appear when an agent starts working through AgentGuard (for a coding agent: run it in a repository where <code className="font-mono">agw init</code> was done).</EmptyState>
      ) : null}
      <Technical view={p.view}>
      <table aria-label="Runs">
        <thead><tr><th scope="col">Run</th><th scope="col">Agents</th><th scope="col">Actions</th><th scope="col">Statuses</th><th scope="col">Delegated</th><th scope="col">Last activity</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.run_id}>
              <td><a href={`/runs/${r.run_id}`}><code>{short(r.run_id, 13)}</code></a></td>
              <td>{r.agents.join(", ")}</td>
              <td>{r.actions}</td>
              <td className="space-x-1">{Object.entries(r.statuses).map(([k, v]) => <span key={k}><Badge value={k} /> {v}</span>)}</td>
              <td>{r.delegated ? "yes" : ""}</td>
              <td>{r.last_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
      </Technical>
    </Page>
  );
}
