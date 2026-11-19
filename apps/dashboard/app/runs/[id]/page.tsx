import { notFound } from "next/navigation";

import { AgentText } from "@/components/humanize/agent-text";
import { PlainLine, PlainStory } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { Badge, Card, Page, short } from "@/components/legacy";
import { PullRequestsCard } from "@/components/github/pull-requests";
import { Timestamp } from "@/components/timestamp";
import { cn } from "@/lib/cn";
import { gateway } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { ruleBook } from "@/lib/rulebook";
import { agentKindLabel, agentName, clock, runStory, sessionTitle, type CodingLike } from "@/src/humanize";

const INDENT = ["ml-0", "ml-6", "ml-12", "ml-18"];
const TONE = { ok: "text-ok-11", bad: "text-bad-11", warn: "text-warn-11", info: "text-info-11" } as const;

export default async function Run({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) notFound();
  const [{ data }, p, book] = await Promise.all([(await gateway()).GET("/v1/dashboard/runs/{run_id}", { params: { path: { run_id: id } } }), prefs(), ruleBook()]);
  if (!data) notFound();
  const s = data.session ?? null;
  const first = data.events[0]?.occurred_at ?? null;
  const title = sessionTitle(s, first, p.tz);
  const coding = data.coding as Record<string, CodingLike>;
  const story = runStory(data.events, coding, data.people ?? {}, book);
  const actions = new Set(data.events.map((e) => e.action_id).filter(Boolean)).size;
  const agents = [...new Set(data.events.map((e) => e.agent).filter((x): x is string => !!x))].map(agentName);
  const who: [string, string][] = s
    ? ([["Developer", s.developer ?? "—"], ["Agent", agentKindLabel(s.agent_kind, s.agent_version)], ["Device", s.device ?? "—"], ["Repository", s.repo ?? "—"], ["Issue", s.issue_number ? `#${s.issue_number}` : "—"]] as [string, string][])
    : [["Agents", agents.join(", ") || "—"]];
  const storyView = (
          <section aria-label="Session story">
      <h2 className="mb-2 text-caption font-semibold uppercase tracking-wide text-gray-11">Story</h2>
      <ol className="space-y-2 text-dense" data-testid="run-story">
        {story.map((l, i) => (
          <li key={`${l.actionId ?? "e"}-${i}`} className="flex flex-wrap items-baseline gap-x-2">
            <span className="w-20 shrink-0 tabular text-gray-11">{clock(l.at, p.tz)}</span>
            <span>
              {l.actionId ? <a href={`/actions/${l.actionId}`} className="text-gray-12">{l.object ? <>{l.verb} <AgentText value={l.object} /></> : l.verb}</a> : l.verb}
              {l.steps.map((st, k) => <span key={k} className={cn("ml-1", TONE[st.tone])}>→ {st.text}</span>)}
              {l.why ? <span className="block text-caption text-gray-11" data-testid="story-why">Why: {l.why}</span> : null}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
  const summary = `${title}: ${actions} action${actions === 1 ? "" : "s"}${s?.status ? `, session ${s.status}` : ""}.`;
  return (
    <Page title={p.view === "simple" ? title : `Run ${short(id, 13)}`} help="run" lead={p.view === "simple" ? "Everything the agent asked to do in this session, in order, and what AgentGuard decided." : "Lifecycle events in recording order (seq). Payloads (args, results) are never shown here."}>
      {p.view === "simple" ? (
        <PlainStory headline={summary} who={who} canDo={[{ label: "See open approvals", href: "/approvals" }, { label: "Run an integrity check", href: "/verification" }]}>
{storyView}
        </PlainStory>
      ) : (
        <>
          <PlainLine>{summary}</PlainLine>
          <div className="mb-4 rounded-md border border-gray-6 bg-gray-1 p-4">{storyView}</div>
        </>
      )}
      <PullRequestsCard runId={id} />
      <Technical view={p.view}>
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
              <td><a href={`/events/${e.event_id}`}>{e.seq}</a></td>
              <td><code>{e.type}</code>{e.action_id ? <> · <a href={`/actions/${e.action_id}`} className="text-xs">action</a></> : null}<div className="text-xs text-slate-600">{e.evidence_class} · {e.occurred_at}</div></td>
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
      {s ? <p className="mt-2 text-caption text-gray-11">Session {s.session_id} · {s.agent_kind} {s.agent_version ?? ""} · started <Timestamp iso={s.started_at} tz={p.tz} /></p> : null}
      </Technical>
    </Page>
  );
}

