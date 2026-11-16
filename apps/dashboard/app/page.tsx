import { Badge, Card, Page, Stat, age } from "@/components/ui";
import { gateway } from "@/lib/gateway";

// fixed classes: inline style attributes are blocked by the strict CSP
const BAR = ["w-0", "w-4", "w-8", "w-12", "w-16", "w-20", "w-24", "w-28", "w-32"];

export default async function Overview() {
  const { data } = await (await gateway()).GET("/v1/dashboard/overview", { params: { query: { days: 14 } } });
  if (!data) return <Page title="Overview">Unavailable.</Page>;
  const max = Math.max(1, ...data.actions_per_day.map((d) => d.count));
  const total = Object.values(data.risk).reduce((a, b) => a + b, 0) || 1;
  return (
    <Page title="Overview" lead="Your tenant only. Counts come from the gateway's operational tables; evidence integrity comes from verification.">
      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Pending approvals" value={data.pending_approvals} hint={`oldest ${age(data.oldest_pending_approval_seconds)}`} />
        <Stat label="Unsealed events" value={data.unsealed_events} hint={`oldest ${age(data.oldest_unsealed_seconds)}`} />
        <Stat label="Unanchored epochs" value={data.anchoring_configured ? data.unanchored_epochs : "n/a"} hint={data.anchoring_configured ? `oldest ${age(data.oldest_unanchored_seconds)}` : "anchoring not configured"} />
        <Stat label="Verification failures (14 d)" value={data.verification_failures} hint={data.last_verification ? `last: ${data.last_verification.result}` : "no report yet"} />
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <Card title="Actions per day">
          <table aria-label="Actions per day">
            <thead><tr><th scope="col">Day</th><th scope="col">Actions</th></tr></thead>
            <tbody>
              {data.actions_per_day.map((d) => (
                <tr key={d.day}>
                  <td>{d.day}</td>
                  <td>
                    <span className={`inline-block h-3 bg-blue-800 align-middle ${BAR[Math.round((d.count / max) * 8)]}`} aria-hidden="true" /> {d.count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
        <Card title="Decisions by outcome">
          <table aria-label="Decisions">
            <thead><tr><th scope="col">Decision</th><th scope="col">Count</th></tr></thead>
            <tbody>{Object.entries(data.decisions).map(([k, v]) => <tr key={k}><td><Badge value={k} /></td><td>{v}</td></tr>)}</tbody>
          </table>
          <h3 className="mt-3 font-semibold">Statuses</h3>
          <table aria-label="Statuses">
            <thead><tr><th scope="col">Status</th><th scope="col">Count</th></tr></thead>
            <tbody>{Object.entries(data.statuses).map(([k, v]) => <tr key={k}><td><Badge value={k} /></td><td>{v}</td></tr>)}</tbody>
          </table>
        </Card>
        <Card title="Risk distribution">
          <table aria-label="Risk distribution">
            <thead><tr><th scope="col">Level</th><th scope="col">Actions</th><th scope="col">Share</th></tr></thead>
            <tbody>
              {Object.entries(data.risk).map(([k, v]) => (
                <tr key={k}><td><Badge value={k} /></td><td>{v}</td><td>{Math.round((v / total) * 100)}%</td></tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-sm">Alerts (24 h): <strong>{data.open_alerts}</strong> · <a href="/incidents">incidents</a></p>
        </Card>
      </div>
    </Page>
  );
}
