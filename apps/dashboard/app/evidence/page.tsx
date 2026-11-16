import { Badge, Notice, Page, SafeText, short } from "@/components/ui";
import { gateway, me } from "@/lib/gateway";

const UUID = /^[0-9a-fA-F-]{36}$/;

export default async function Evidence({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const query: Record<string, string | number> = { limit: 100 };
  if (sp.type && /^[A-Z_]{3,40}$/.test(sp.type)) query.type = sp.type;
  if (sp.run_id && UUID.test(sp.run_id)) query.run_id = sp.run_id;
  if (sp.action_id && UUID.test(sp.action_id)) query.action_id = sp.action_id;
  if (sp.from_seq && /^\d+$/.test(sp.from_seq)) query.from_seq = Number(sp.from_seq);
  const [{ data }, who] = await Promise.all([
    (await gateway()).GET("/v1/dashboard/events", { params: { query } }),
    me(),
  ]);
  const auditor = who.roles.includes("auditor") || who.roles.includes("admin");
  return (
    <Page title="Evidence explorer" lead="Event headers (structural, non-sensitive) as committed in the hash chain.">
      <Notice>
        Payloads (args, results, approval comments) are never shown here. They are encrypted per event and reachable
        only through a disclosure grant: an admin grants specific events to an auditor, who exports them
        HPKE-sealed to their own key and opens them with <code>agw-verify --auditor-key</code>.
      </Notice>
      <form method="get" className="mb-3 flex flex-wrap items-end gap-2 text-sm" aria-label="Filter">
        <label>Type <input name="type" defaultValue={sp.type ?? ""} className="ml-1 rounded border border-slate-400 px-1" /></label>
        <label>Run id <input name="run_id" defaultValue={sp.run_id ?? ""} className="ml-1 rounded border border-slate-400 px-1" /></label>
        <label>Action id <input name="action_id" defaultValue={sp.action_id ?? ""} className="ml-1 rounded border border-slate-400 px-1" /></label>
        <label>From seq <input name="from_seq" defaultValue={sp.from_seq ?? ""} className="ml-1 w-20 rounded border border-slate-400 px-1" /></label>
        <button type="submit" className="rounded border border-slate-500 px-2">Filter</button>
      </form>
      <table aria-label="Event headers">
        <thead><tr><th scope="col">Seq</th><th scope="col">Type</th><th scope="col">Event hash</th><th scope="col">Header</th>{auditor ? <th scope="col">Bundle</th> : null}</tr></thead>
        <tbody>
          {(data?.events ?? []).map((e) => (
            <tr key={e.event_id}>
              <td>{e.seq}</td>
              <td><Badge value={e.type} /><div className="text-xs">{e.occurred_at}</div></td>
              <td><code>{short(e.event_hash, 16)}…</code></td>
              <td className="w-1/2"><SafeText text={JSON.stringify(e.header, null, 1)} max={1500} label={`header ${e.seq}`} /></td>
              {auditor ? <td><a href={`/api/bundles/${e.event_id}`}>download</a></td> : null}
            </tr>
          ))}
        </tbody>
      </table>
    </Page>
  );
}
