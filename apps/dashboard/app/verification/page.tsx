import { PlainStory } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { Badge, Card, CsrfField, Notice, Page, RESULT_EXPLANATION, SafeText, short } from "@/components/legacy";
import { Timestamp } from "@/components/timestamp";
import { prefs } from "@/lib/prefs";
import { verificationWords } from "@/src/humanize";
import { gateway, getJson, me } from "@/lib/gateway";
import { csrfToken } from "@/lib/session";

export default async function Verification({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const [{ data }, who, csrf, p] = await Promise.all([(await gateway()).GET("/v1/dashboard/verifications", { params: { query: { limit: 50 } } }), me(), csrfToken(), prefs()]);
  const latest = data?.reports[0];
  const full = latest ? await getJson<{ report: Record<string, unknown> }>(`/v1/dashboard/verifications/${latest.report_id}`) : null;
  const canRun = who.roles.includes("auditor") || who.roles.includes("admin");
  return (
    <Page title="Verification" help="verification" lead="The monitor re-verifies your tenant's chain, epochs and anchors with the same independent verifier an auditor runs, and records every report as evidence in the monitoring stream.">
      {(() => {
        if (!latest) return <PlainStory headline="No integrity check has run yet." tone="warn" canDo={[{ label: "Run one with the button below (auditors and admins)." }]} />;
        const w = verificationWords(latest, (full?.body?.report as Record<string, unknown> | undefined) ?? null);
        return (
          <PlainStory headline={w.headline} tone={w.tone}
            happened={[<>Last checked <Timestamp iso={latest.created_at} tz={p.tz} />, {latest.trigger === "manual" ? `requested by ${latest.requested_by ?? "a person"}` : "automatically"}.</>]}
            canDo={[{ label: w.next }]} />
        );
      })()}
      {sp.queued ? <Notice kind="good">Verification queued: the worker runs it within seconds. Reload to see the report.</Notice> : null}
      {canRun ? (
        <form method="post" action="/api/verifications" className="mb-4">
          <CsrfField csrf={csrf} />
          <button type="submit" className="rounded bg-blue-800 px-3 py-1 font-semibold text-white">Run verification now</button>
          {data?.pending_requests ? <span className="ml-2 text-sm">{data.pending_requests} queued</span> : null}
        </form>
      ) : null}
      <Technical view={p.view}>
      <Notice kind="warn">
        <strong>Dashboard status is a convenience view; independent verification uses the CLI.</strong> Download an
        evidence bundle (Evidence explorer), obtain the trust roots (chain id, contract, recorder id) out of band, then run:
        <pre className="mt-1 whitespace-pre-wrap">agw-verify event --bundle bundle.json --trust-config pinned-trust.json</pre>
      </Notice>
      <Card title="What the results mean">
        <dl className="grid grid-cols-[11rem_1fr] gap-y-1 text-sm">
          {Object.entries(RESULT_EXPLANATION).map(([k, v]) => (
            <div key={k} className="contents"><dt><Badge value={k} /></dt><dd>{v}</dd></div>
          ))}
        </dl>
      </Card>
      <Card title="Reports">
        <table aria-label="Verification reports">
          <thead><tr><th scope="col">When</th><th scope="col">Result</th><th scope="col">Reason</th><th scope="col">Range</th><th scope="col">Trigger</th><th scope="col">Alerts</th><th scope="col">Evidence event</th></tr></thead>
          <tbody>
            {(data?.reports ?? []).map((r) => (
              <tr key={r.report_id}>
                <td className="text-xs">{r.created_at}</td>
                <td><Badge value={r.result} /></td>
                <td className="text-xs">{r.reason ?? ""}</td>
                <td className="text-xs">{r.first_seq ?? "-"}–{r.last_seq ?? "-"}</td>
                <td className="text-xs">{r.trigger}{r.requested_by ? ` (${r.requested_by})` : ""}</td>
                <td>{r.alerts}</td>
                <td className="text-xs"><code>{short(r.event_id)}</code></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {full?.body ? (
        <Card title="Latest report (as recorded)">
          <SafeText text={JSON.stringify(full.body.report, null, 1)} max={6000} label="latest report" />
        </Card>
      ) : null}
      </Technical>
    </Page>
  );
}
