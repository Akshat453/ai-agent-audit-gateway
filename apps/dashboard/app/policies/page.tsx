import { Card, Notice, Page, SafeText } from "@/components/legacy";
import { lineDiff } from "@/lib/diff";
import { gateway } from "@/lib/gateway";
import { ruleBook } from "@/lib/rulebook";
import { describeRule } from "@/src/humanize";

const pretty = (d: unknown) => JSON.stringify(d, null, 2);

export default async function Policies({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const { data } = await (await gateway()).GET("/v1/dashboard/policies");
  if (!data) return <Page title="Policies" toggle={false}>Unavailable.</Page>;
  const byId = new Map<string, typeof data.policies>();
  for (const p of data.policies) byId.set(p.policy_id, [...(byId.get(p.policy_id) ?? []), p]);
  // Opened from an action's "see rule" link: say what that rule means (ADR-0039).
  const focus = sp.rule && /^[A-Za-z0-9:@*_.-]{1,80}$/.test(sp.rule) ? describeRule(await ruleBook(), sp.rule) : null;
  return (
    <Page title="Policies" toggle={false} lead="Authorization policy and risk policy versions, immutable and referenced by every decision.">
      {focus ? <Notice><span data-testid="focused-rule"><strong>{focus.name}</strong> ({focus.id}): {focus.why || "No description."}</span></Notice> : null}
      <Notice>Read-only. {data.note}.</Notice>
      {[...byId.entries()].map(([id, versions]) => (
        <Card key={id} title={`Policy "${id}"`}>
          {versions.map((v, idx) => {
            const prev = idx > 0 ? versions[idx - 1] : undefined;
            return (
              <details key={v.version} className="mb-2" open={idx === versions.length - 1}>
                <summary className="cursor-pointer font-semibold">
                  v{v.version} · {v.created_at} · by {v.created_by}{prev ? ` · diff vs v${prev.version}` : ""}
                </summary>
                {prev ? (
                  <pre tabIndex={0} className="mt-1 overflow-auto rounded border border-slate-300 bg-white p-2" aria-label={`diff v${prev.version} to v${v.version}`}>
                    {lineDiff(pretty(prev.document), pretty(v.document)).map((l, i) => (
                      <div key={i} className={l.op === "+" ? "bg-green-100 text-green-950" : l.op === "-" ? "bg-red-100 text-red-950" : ""}>
                        {l.op} {l.text}
                      </div>
                    ))}
                  </pre>
                ) : (
                  <SafeText text={pretty(v.document)} max={8000} />
                )}
              </details>
            );
          })}
        </Card>
      ))}
      <Card title="Risk policies">
        {data.risk_policies.map((r) => (
          <details key={`${r.policy_id}-${r.version}`} className="mb-2">
            <summary className="cursor-pointer font-semibold">{r.policy_id} v{r.version} · digest <code>{r.digest.slice(0, 16)}…</code></summary>
            <SafeText text={pretty(r.document)} max={8000} />
          </details>
        ))}
      </Card>
    </Page>
  );
}
