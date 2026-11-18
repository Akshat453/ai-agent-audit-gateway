import { Badge, Card, CsrfField, Notice, Page, SafeText, short } from "@/components/legacy";
import { gateway, me } from "@/lib/gateway";
import { csrfToken } from "@/lib/session";

const KINDS = ["denied", "outcome_unknown", "failed", "security", "alerts"] as const;
type Kind = (typeof KINDS)[number];

export default async function Incidents({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const kind = (KINDS as readonly string[]).includes(sp.kind ?? "") ? (sp.kind as Kind) : undefined;
  const [{ data }, who, csrf] = await Promise.all([
    (await gateway()).GET("/v1/dashboard/incidents", { params: { query: { limit: 200, ...(kind ? { kind: [kind] } : {}) } } }),
    me(),
    csrfToken(),
  ]);
  const admin = who.roles.includes("admin");
  const exporter = admin || who.roles.includes("auditor");
  return (
    <Page title="Incidents" lead="Denied actions, ambiguous outcomes, failures, security violations and monitor alerts.">
      {sp.reconciled ? <Notice kind="good">Recorded ACTION_RECONCILED ({sp.reconciled}). Nothing was retried.</Notice> : null}
      {sp.error ? <Notice kind="bad">Gateway answered: {sp.error}</Notice> : null}
      <nav aria-label="Incident kind" className="mb-3 flex flex-wrap gap-3 text-sm">
        <a href="/incidents" aria-current={!kind ? "page" : undefined}>all</a>
        {KINDS.map((k) => <a key={k} href={`/incidents?kind=${k}`} aria-current={k === kind ? "page" : undefined}>{k}</a>)}
        {exporter ? <a className="ml-auto" href={`/api/incidents/export${kind ? `?kind=${kind}` : ""}`}>Export bundle set (JSON)</a> : null}
      </nav>
      <table aria-label="Incidents">
        <thead><tr><th scope="col">When</th><th scope="col">Kind</th><th scope="col">Action / run</th><th scope="col">Tool</th><th scope="col">Status / code</th><th scope="col">Detail</th></tr></thead>
        <tbody>
          {(data ?? []).map((i, n) => (
            <tr key={`${i.kind}-${i.action_id ?? n}`}>
              <td className="text-xs">{i.at}</td>
              <td>{i.kind}</td>
              <td className="text-xs">{i.action_id ? <code>{short(i.action_id)}</code> : "-"}{i.run_id ? <> · <a href={`/runs/${i.run_id}`}>run</a></> : null}</td>
              <td>{i.tool ?? "-"}</td>
              <td><Badge value={i.status} />{i.code ? <div className="text-xs">{i.code}</div> : null}</td>
              <td className="w-1/3">
                <SafeText text={JSON.stringify(i.detail)} max={400} />
                {i.reconcilable && admin ? (
                  <Card title="Reconcile (operator)">
                    <form method="post" action={`/api/actions/${i.action_id}/reconcile`} className="space-y-1 text-sm">
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
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Page>
  );
}
