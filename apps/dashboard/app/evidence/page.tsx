import { PlainLine } from "@/components/humanize/plain";
import { RepoBanner } from "@/components/humanize/repo-switcher";
import { Technical } from "@/components/humanize/technical";
import { Term } from "@/components/humanize/term";
import { Badge, Notice, Page, SafeText, short } from "@/components/legacy";
import { gateway, me } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { repoScope } from "@/lib/repo-scope";
import { ruleBook } from "@/lib/rulebook";
import { eventLabel, explainHeader } from "@/src/humanize";

const UUID = /^[0-9a-fA-F-]{36}$/;

export default async function Evidence({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const query: Record<string, string | number> = { limit: 100 };
  if (sp.type && /^[A-Z_]{3,40}$/.test(sp.type)) query.type = sp.type;
  if (sp.run_id && UUID.test(sp.run_id)) query.run_id = sp.run_id;
  if (sp.action_id && UUID.test(sp.action_id)) query.action_id = sp.action_id;
  if (sp.from_seq && /^\d+$/.test(sp.from_seq)) query.from_seq = Number(sp.from_seq);
  const scope = await repoScope();
  if (scope.id) query.repo_id = scope.id;
  const [{ data }, who, p, book] = await Promise.all([
    (await gateway()).GET("/v1/dashboard/events", { params: { query } }),
    me(),
    prefs(),
    ruleBook(),
  ]);
  const auditor = who.roles.includes("auditor") || who.roles.includes("admin");
  const events = data?.events ?? [];
  const plain = (h: Record<string, unknown>) => explainHeader(h, book, { tz: p.tz }).headline;
  return (
    <Page title="Evidence explorer" help="events" lead={p.view === "simple" ? "The tamper-evident log: every step every agent took, each record chained to the one before it." : "Event headers (structural, non-sensitive) as committed in the hash chain."}>
      <RepoBanner name={scope.name} />
      {scope.name ? <p className="mb-2 text-caption text-gray-11">Records that belong to no repository (settings changes, batch seals, integrity checks) are hidden while a repository is selected.</p> : null}
      <PlainLine>{events.length ? <>Showing the latest {events.length} log records. Each one is <Term term="hash">fingerprinted</Term> and <Term term="prev hash">chained</Term> to the one before it, so any later change shows.</> : "No log records match."}</PlainLine>
      {p.view === "simple" ? (
        <ol className="mb-4 divide-y divide-gray-4 rounded-md border border-gray-6 bg-gray-1 text-dense" aria-label="Log in plain English" data-testid="event-sentences">
          {events.map((e) => (
            <li key={e.event_id} className="flex flex-wrap items-baseline gap-x-3 px-4 py-2">
              <a href={`/events/${e.event_id}`} className="w-14 shrink-0 tabular text-gray-11">#{e.seq}</a>
              <span className="font-medium text-gray-12">{eventLabel(e.type)}</span>
              <span className="text-gray-11">{plain(e.header as Record<string, unknown>)}</span>
            </li>
          ))}
        </ol>
      ) : null}
      <Technical view={p.view}>
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
        <thead><tr><th scope="col">Seq</th><th scope="col">Type</th><th scope="col">In plain words</th><th scope="col">Event hash</th><th scope="col">Header</th>{auditor ? <th scope="col">Bundle</th> : null}</tr></thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.event_id}>
              <td><a href={`/events/${e.event_id}`}>{e.seq}</a></td>
              <td><Badge value={e.type} /><div className="text-xs">{e.occurred_at}</div></td>
              <td className="text-xs">{plain(e.header as Record<string, unknown>)}</td>
              <td><code>{short(e.event_hash, 16)}…</code></td>
              <td className="w-1/2"><SafeText text={JSON.stringify(e.header, null, 1)} max={1500} label={`header ${e.seq}`} /></td>
              {auditor ? <td><a href={`/api/bundles/${e.event_id}`}>download</a></td> : null}
            </tr>
          ))}
        </tbody>
      </table>
      </Technical>
    </Page>
  );
}
