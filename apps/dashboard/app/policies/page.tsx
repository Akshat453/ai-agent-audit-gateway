import { PlainLine } from "@/components/humanize/plain";
import { Technical } from "@/components/humanize/technical";
import { Card, Notice, Page, SafeText } from "@/components/legacy";
import { cn } from "@/lib/cn";
import { lineDiff } from "@/lib/diff";
import { gateway } from "@/lib/gateway";
import { prefs } from "@/lib/prefs";
import { ruleBook } from "@/lib/rulebook";
import { describeRule, effectWord, policyChanges, type RuleDoc } from "@/src/humanize";

const pretty = (d: unknown) => JSON.stringify(d, null, 2);

const FAMILY: Record<string, string> = {
  PATH: "Files", SECRET: "Secrets", CMD: "Commands", PKG: "Dependencies", NET: "Network", GIT: "Git",
  CONTENT: "What a change contains", WEB: "Web pages", MCP: "MCP tools", CODE: "Unclear requests", REPO: "Repository rules",
  HITL: "Approvals", APPROVAL: "Approvals", SYS: "System checks", CAP: "Risk levels", LVL: "Risk levels", MR: "Risk rules",
  CX: "Integrations", GH: "GitHub",
};
const familyOf = (id: string) => (/^[a-z]/.test(id) ? "Default rules" : FAMILY[id.split("-")[0] ?? ""] ?? "Other");

export default async function Policies({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const sp = await searchParams;
  const [{ data }, p, book] = await Promise.all([(await gateway()).GET("/v1/dashboard/policies"), prefs(), ruleBook()]);
  if (!data) return <Page title="Policies" help="policies">AgentGuard could not load the policies. Try again in a moment.</Page>;
  const byId = new Map<string, typeof data.policies>();
  for (const pol of data.policies) byId.set(pol.policy_id, [...(byId.get(pol.policy_id) ?? []), pol]);
  const focus = sp.rule && /^[A-Za-z0-9:@*_.-]{1,80}$/.test(sp.rule) ? sp.rule : null;
  const groups = new Map<string, string[]>();
  for (const id of Object.keys(book.rules)) groups.set(familyOf(id), [...(groups.get(familyOf(id)) ?? []), id]);
  return (
    <Page title="Policies" help="policies" lead={p.view === "simple" ? "The rules AgentGuard applies: what agents may do on their own, what needs a person, and what is always blocked." : "Authorization policy and risk policy versions, immutable and referenced by every decision."}>
      <PlainLine>Rules are never edited in place: every change creates a new version, and every decision records the version it used.</PlainLine>
      {focus ? (
        <Notice kind="info">
          <span data-testid="focused-rule"><strong>{describeRule(book, focus).name}</strong> ({focus}): {describeRule(book, focus).why || "No description."} If you think this rule was applied wrongly, tell your AgentGuard admin and include this rule id and the action link.</span>
        </Notice>
      ) : null}
      {p.view === "simple" ? (
        <>
          {[...byId.entries()].map(([id, versions]) => {
            const latest = versions[versions.length - 1];
            const doc = (latest?.document ?? {}) as { rules?: RuleDoc[]; default_effect?: string };
            return (
              <Card key={id} title={`Policy "${id}" (version ${latest?.version ?? "?"})`}>
                <ul className="space-y-1 text-sm" data-testid="policy-rules">
                  {(doc.rules ?? []).map((r) => (
                    <li key={r.rule_id}><strong>{describeRule(book, r.rule_id).name}</strong> - {describeRule(book, r.rule_id).why || effectWord(r.effect)} <span className="text-gray-11">({r.rule_id}: {effectWord(r.effect)})</span></li>
                  ))}
                  {doc.default_effect ? <li className="text-gray-11">Anything no rule covers is {effectWord(doc.default_effect)}.</li> : null}
                </ul>
                <h3 className="mb-1 mt-3 text-caption font-semibold uppercase tracking-wide text-gray-11">History in words</h3>
                <ul className="space-y-1 text-sm">
                  {versions.map((v, i) => (
                    <li key={v.version}>Version {v.version} ({v.created_by}): {policyChanges(i ? (versions[i - 1]?.document as never) : null, v.document as never, book).join(" ")}</li>
                  ))}
                </ul>
              </Card>
            );
          })}
          <Card title="Coding agent and system rules">
            <p className="mb-2 text-sm text-gray-11">What each rule id in a decision means. These descriptions are kept next to the rules themselves.</p>
            {[...groups.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([family, ids]) => (
              <section key={family} className="mb-3" aria-label={family}>
                <h3 className="text-sm font-semibold">{family}</h3>
                <ul className="mt-1 space-y-0.5 text-sm">
                  {ids.sort().map((rid) => (
                    <li key={rid} id={`rule-${rid}`} className={cn(focus === rid && "rounded-sm bg-warn-3 px-1")}>
                      <strong>{book.rules[rid]?.name}</strong> - {book.rules[rid]?.why} <code className="text-xs text-gray-11">{rid}</code>
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </Card>
        </>
      ) : null}
      <Technical view={p.view}>
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
      </Technical>
    </Page>
  );
}
