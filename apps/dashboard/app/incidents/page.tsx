import { PlainLine } from "@/components/humanize/plain";
import { RepoBanner } from "@/components/humanize/repo-switcher";
import { Technical } from "@/components/humanize/technical";
import { Badge, Card, CsrfField, Notice, Page, SafeText, short } from "@/components/legacy";
import { Timestamp } from "@/components/timestamp";
import { gateway, me } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { repoScope } from "@/lib/repo-scope";
import { csrfToken } from "@/lib/session";
import { INCIDENT_KINDS, incidentSentence } from "@/src/humanize";

const KINDS = ["denied", "outcome_unknown", "failed", "security", "alerts"] as const;
type Kind = (typeof KINDS)[number];

function Reconcile({ actionId, csrf }: { actionId: string; csrf: string }) {
  return (
    <Card title="Reconcile (operator)">
      <form method="post" action={`/api/actions/${actionId}/reconcile`} className="space-y-1 text-sm">
        <CsrfField csrf={csrf} />
        <label className="block">Observed outcome
          <select name="observed" className="ml-1 rounded border border-slate-400">
            <option value="NOT_EXECUTED">not executed</option>
            <option value="COMPLETED">completed</option>
            <option value="FAILED">failed</option>
          </select>
        </label>
        <label className="block">Justification (what you checked)
          <textarea name="justification" required minLength={10} maxLength={2000} className="block w-full rounded border border-slate-400" />
        </label>
        <button type="submit" className="rounded border border-slate-600 px-2">Record ACTION_RECONCILED</button>
        <p className="text-xs">The gateway never retries an ambiguous action; this only records what you observed.</p>
      </form>
    </Card>
  );
}

export default async function Incidents({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const kind = (KINDS as readonly string[]).includes(sp.kind ?? "") ? (sp.kind as Kind) : undefined;
  const scope = await repoScope();
  const [{ data }, who, csrf, p] = await Promise.all([
    (await gateway()).GET("/v1/dashboard/incidents", { params: { query: { limit: 200, ...(kind ? { kind: [kind] } : {}), ...(scope.id ? { repo_id: scope.id } : {}) } } }),
    me(),
    csrfToken(),
    prefs(),
  ]);
  const admin = who.roles.includes("admin");
  const exporter = admin || who.roles.includes("auditor");
  const rows = data ?? [];
  return (
    <Page title="Incidents" help="incidents" lead={p.view === "simple" ? "Things that went wrong or were stopped, each with what to do about it." : "Denied actions, ambiguous outcomes, failures, security violations and monitor alerts."}>
      {sp.reconciled ? <Notice kind="good">Recorded ACTION_RECONCILED ({sp.reconciled}). Nothing was retried.</Notice> : null}
      {sp.error ? <Notice kind="bad">Gateway answered: {sp.error}</Notice> : null}
      <RepoBanner name={scope.name} />
      <PlainLine>{rows.length ? `${rows.length} incident${rows.length === 1 ? "" : "s"}${kind ? ` of kind "${INCIDENT_KINDS[kind]?.label ?? kind}"` : ""}. Most blocks need no action: they show AgentGuard doing its job.` : "No incidents. Nothing was blocked, failed or flagged."}</PlainLine>
      <nav aria-label="Incident kind" className="mb-3 flex flex-wrap gap-3 text-sm">
        <a href="/incidents" aria-current={!kind ? "page" : undefined}>all</a>
        {KINDS.map((k) => <a key={k} href={`/incidents?kind=${k}`} aria-current={k === kind ? "page" : undefined}>{p.view === "simple" ? INCIDENT_KINDS[k]?.label ?? k : k}</a>)}
        {exporter ? <a className="ml-auto" href={`/api/incidents/export${kind ? `?kind=${kind}` : ""}`}>Export bundle set (JSON)</a> : null}
      </nav>
      {p.view === "simple" ? (
        <ul className="mb-4 space-y-2" aria-label="Incidents in plain English" data-testid="incident-sentences">
          {rows.map((i, n) => (
            <li key={`${i.kind}-${i.action_id ?? n}`} className="rounded-md border border-gray-6 bg-gray-1 px-4 py-3 text-dense">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span><strong>{INCIDENT_KINDS[i.kind]?.label ?? i.kind}:</strong> {incidentSentence(i)}</span>
                <Timestamp iso={i.at} tz={p.zone} compact />
              </div>
              <p className="mt-1 text-caption text-gray-11">What to do: {INCIDENT_KINDS[i.kind]?.todo ?? "Look at the details."}{" "}
                {i.action_id ? <a href={`/actions/${i.action_id}`}>Open the action</a> : null}{i.run_id ? <> · <a href={`/runs/${i.run_id}`}>Open the session</a></> : null}
              </p>
              {i.reconcilable && admin && i.action_id ? <div className="mt-2"><Reconcile actionId={i.action_id} csrf={csrf} /></div> : null}
            </li>
          ))}
        </ul>
      ) : null}
      <Technical view={p.view}>
      <table aria-label="Incidents">
        <thead><tr><th scope="col">When</th><th scope="col">Kind</th><th scope="col">Action / run</th><th scope="col">Tool</th><th scope="col">Status / code</th><th scope="col">Detail</th></tr></thead>
        <tbody>
          {rows.map((i, n) => (
            <tr key={`${i.kind}-${i.action_id ?? n}`}>
              <td className="text-xs">{i.at}</td>
              <td>{i.kind}</td>
              <td className="text-xs">{i.action_id ? <code>{short(i.action_id)}</code> : "-"}{i.run_id ? <> · <a href={`/runs/${i.run_id}`}>run</a></> : null}</td>
              <td>{i.tool ?? "-"}</td>
              <td><Badge value={i.status} />{i.code ? <div className="text-xs">{i.code}</div> : null}</td>
              <td className="w-1/3">
                <SafeText text={JSON.stringify(i.detail)} max={400} />
                {i.reconcilable && admin && p.view === "technical" && i.action_id ? <Reconcile actionId={i.action_id} csrf={csrf} /> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      </Technical>
    </Page>
  );
}
