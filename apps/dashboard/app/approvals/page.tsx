import { Badge, Page, short } from "@/components/ui";
import { getJson } from "@/lib/gateway";

type Row = {
  approval_id: string; action_id: string; state: string; tool: { id: string; version: string };
  environment: string; risk_level: string; required_approvals: number; requested_at: string; expires_at: string;
};
const STATES = ["PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED", "INVALIDATED"];

export default async function Approvals({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const state = STATES.includes(sp.state ?? "") ? (sp.state as string) : "PENDING";
  const { body } = await getJson<{ approvals: Row[] }>(`/v1/approvals?state=${state}&limit=200`);
  return (
    <Page title="Approval center" lead="Each approval binds one exact action (tool, version, args digest, target, policy version, expiry, single-use nonce).">
      <nav aria-label="Approval state" className="mb-3 flex gap-2 text-sm">
        {STATES.map((s) => (
          <a key={s} href={`/approvals?state=${s}`} aria-current={s === state ? "page" : undefined} className={s === state ? "font-bold" : ""}>{s}</a>
        ))}
      </nav>
      <table aria-label="Approvals">
        <thead><tr><th scope="col">Approval</th><th scope="col">State</th><th scope="col">Tool</th><th scope="col">Env</th><th scope="col">Risk</th><th scope="col">Approvers</th><th scope="col">Expires</th></tr></thead>
        <tbody>
          {(body?.approvals ?? []).map((a) => (
            <tr key={a.approval_id}>
              <td><a href={`/approvals/${a.approval_id}`}><code>{short(a.approval_id, 13)}</code></a></td>
              <td><Badge value={a.state} /></td>
              <td>{a.tool.id}@{a.tool.version}</td>
              <td>{a.environment}</td>
              <td><Badge value={a.risk_level} /></td>
              <td>{a.required_approvals}</td>
              <td>{a.expires_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {body && body.approvals.length === 0 ? <p className="mt-2 text-sm">None.</p> : null}
    </Page>
  );
}
