import { Card, Notice, Page, SafeText } from "@/components/ui";
import { lineDiff } from "@/lib/diff";
import { gateway } from "@/lib/gateway";

const pretty = (d: unknown) => JSON.stringify(d, null, 2);

export default async function Policies() {
  const { data } = await (await gateway()).GET("/v1/dashboard/policies");
  if (!data) return <Page title="Policies">Unavailable.</Page>;
  const byId = new Map<string, typeof data.policies>();
  for (const p of data.policies) byId.set(p.policy_id, [...(byId.get(p.policy_id) ?? []), p]);
  return (
    <Page title="Policies" lead="Authorization policy and risk policy versions, immutable and referenced by every decision.">
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
