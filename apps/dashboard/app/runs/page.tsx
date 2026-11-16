import { Badge, Page, short } from "@/components/ui";
import { gateway } from "@/lib/gateway";

export default async function Runs() {
  const { data } = await (await gateway()).GET("/v1/dashboard/runs", { params: { query: { limit: 100 } } });
  return (
    <Page title="Runs" lead="A run groups the actions an agent submitted under one run id. Delegated runs carry a verified delegation chain.">
      <table aria-label="Runs">
        <thead><tr><th scope="col">Run</th><th scope="col">Agents</th><th scope="col">Actions</th><th scope="col">Statuses</th><th scope="col">Delegated</th><th scope="col">Last activity</th></tr></thead>
        <tbody>
          {(data ?? []).map((r) => (
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
    </Page>
  );
}
