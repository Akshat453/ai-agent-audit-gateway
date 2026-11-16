import { notFound } from "next/navigation";

import { Badge, Card, Page, short } from "@/components/ui";
import { gateway } from "@/lib/gateway";

const INDENT = ["ml-0", "ml-6", "ml-12", "ml-18"];

export default async function Run({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) notFound();
  const { data } = await (await gateway()).GET("/v1/dashboard/runs/{run_id}", { params: { path: { run_id: id } } });
  if (!data) notFound();
  return (
    <Page title={`Run ${short(id, 13)}`} lead="Lifecycle events in recording order (seq). Payloads (args, results) are never shown here.">
      {data.delegations.length ? (
        <Card title="Delegation tree">
          <ul className="space-y-1 text-sm" aria-label="Delegations">
            {data.delegations.map((d) => (
              <li key={d.delegation_id} className={INDENT[Math.min(d.depth - 1, 3)]}>
                <strong>{d.issuer}</strong> → <strong>{d.child}</strong> (depth {d.depth}) tools [{d.tools.join(", ")}], max risk <Badge value={d.max_risk} />, uses {d.uses}/{d.max_uses}
                {d.revoked ? <> · <Badge value="REVOKED" /></> : null}
                {d.issuer_run ? <> · issued in run <a href={`/runs/${d.issuer_run}`}><code>{short(d.issuer_run)}</code></a></> : null}
                {d.child_runs.length ? <> · used in {d.child_runs.map((r) => <a key={r} className="mr-1" href={`/runs/${r}`}><code>{short(r)}</code></a>)}</> : null}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
      {data.approvals.length ? (
        <Card title="Approvals">
          <ul className="text-sm">
            {data.approvals.map((a) => (
              <li key={a.approval_id as string}>
                <a href={`/approvals/${a.approval_id as string}`}>{short(a.approval_id as string)}</a> <Badge value={a.state as string} /> requires {String(a.required_approvals)} · expires {String(a.expires_at)}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
      <table aria-label="Timeline">
        <thead>
          <tr>
            <th scope="col">Seq</th><th scope="col">Event</th><th scope="col">Agent / actor</th><th scope="col">Tool</th>
            <th scope="col">Decision / status</th><th scope="col">Risk</th><th scope="col">Links</th><th scope="col">Epoch / anchor</th>
          </tr>
        </thead>
        <tbody>
          {data.events.map((e) => (
            <tr key={e.event_id}>
              <td>{e.seq}</td>
              <td><code>{e.type}</code><div className="text-xs text-slate-600">{e.evidence_class} · {e.occurred_at}</div></td>
              <td>{e.agent ?? `${String(e.actor.kind)}:${short(String(e.actor.id))}`}</td>
              <td>{e.tool ? `${String(e.tool.id)}${e.tool.ver ? "@" + String(e.tool.ver) : ""}` : ""}</td>
              <td>
                <Badge value={e.decision ?? e.status} />
                {e.code ? <div className="text-xs">{e.code}</div> : null}
                {e.reasons.length ? <div className="text-xs">{e.reasons.join(", ")}</div> : null}
                {e.approval ? <div className="text-xs">approval {short(String(e.approval.id ?? ""))} {String(e.approval.dec ?? "")}</div> : null}
              </td>
              <td>{e.risk ? <><Badge value={String(e.risk.level)} /> <span className="text-xs">{String(e.risk.score)}</span></> : ""}</td>
              <td className="text-xs">
                {e.delegation ? <div>delegation {short(String(e.delegation.id))} depth {String(e.delegation.depth)}</div> : null}
                {e.refs ? <div>refs.parent <code>{short(String(e.refs.parent), 12)}</code></div> : null}
              </td>
              <td className="text-xs">
                {e.epoch_no !== null ? <>epoch {e.epoch_no}</> : <Badge value="UNSEALED" />}
                {e.anchor ? (
                  <div><Badge value={String(e.anchor.status)} />{e.anchor.explorer_url ? <> <a href={String(e.anchor.explorer_url)} rel="noreferrer noopener" target="_blank">tx</a></> : null}</div>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Page>
  );
}
