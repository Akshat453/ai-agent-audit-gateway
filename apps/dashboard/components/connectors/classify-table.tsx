import { CsrfField } from "@/components/legacy";
import { RiskBadge, StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { inputClass } from "@/components/ui/input";
import { cn } from "@/lib/cn";
import { APPROVAL_RULES, APPROVER_ROLES, RISKS, allowedAgentsLabel, type ConnectorAction } from "@/lib/connectors";

const sel = cn(inputClass, "h-7 min-w-[7.5rem] pr-6 text-caption");

function agentsValue(a: string[]): string {
  if (a.length === 1 && (a[0] === "devices" || a[0] === "*")) return a[0];
  return JSON.stringify(a);
}

/** The classification table (C2): one row per action. Names, descriptions and schemas may come
 *  from an MCP upstream: they are UNTRUSTED and rendered as React text (escaped) only.
 *  Admins get one plain form whose submit creates ONE new policy version for all changes. */
export function ClassifyTable({ connectorId, actions, editable, csrf, next, submitLabel = "Save classification" }: {
  connectorId: string; actions: ConnectorAction[]; editable: boolean; csrf: string; next: string; submitLabel?: string;
}) {
  const table = (
    <div className="overflow-x-auto">
      <table className="w-full text-dense" data-testid="classify-table">
        <caption className="sr-only">Actions and their classification</caption>
        <thead className="border-b border-gray-5 bg-gray-2 text-left text-caption text-gray-11">
          <tr>
            <th scope="col" className="px-3 py-2 font-medium">Action</th>
            <th scope="col" className="px-3 py-2 font-medium">Side effect</th>
            <th scope="col" className="px-3 py-2 font-medium">Suggested</th>
            <th scope="col" className="px-3 py-2 font-medium">Current</th>
            <th scope="col" className="px-3 py-2 font-medium">Risk</th>
            <th scope="col" className="px-3 py-2 font-medium">Approval</th>
            <th scope="col" className="px-3 py-2 font-medium">Approver role</th>
            <th scope="col" className="px-3 py-2 font-medium">Allowed agents</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-4">
          {actions.map((a, i) => {
            const c = a.classification;
            const av = c ? agentsValue(c.allowed_agents) : "devices";
            return (
              <tr key={a.name} className="align-top" data-testid={`action-${a.name}`}>
                <th scope="row" className="max-w-[22rem] px-3 py-2 text-left font-normal">
                  <code className="font-mono font-medium text-gray-12">{a.name}</code>
                  {a.upstream_name && a.upstream_name !== a.name ? <span className="ml-1 text-caption text-gray-11">(upstream {a.upstream_name})</span> : null}
                  {a.description ? <p className="mt-0.5 line-clamp-3 break-words text-caption text-gray-11">{a.description}</p> : null}
                  {editable ? (
                    <>
                      <input type="hidden" name="action" value={a.name} />
                      <input type="hidden" name={`was:${a.name}`} value={c ? "1" : "0"} />
                      <input type="hidden" name={`constraints:${a.name}`} value={JSON.stringify(c?.constraints ?? {})} />
                    </>
                  ) : null}
                </th>
                <td className="px-3 py-2 font-mono text-caption">{a.side_effect}</td>
                <td className="px-3 py-2"><RiskBadge level={a.suggested_risk} size="sm" /></td>
                <td className="px-3 py-2"><StatusBadge value={c ? "CLASSIFIED" : "UNCLASSIFIED"} size="sm" /></td>
                {editable ? (
                  <>
                    <td className="px-3 py-2">
                      <select name={`risk:${a.name}`} aria-label={`Risk for ${a.name}`} defaultValue={c?.risk ?? a.proposed?.risk ?? ""} className={sel} id={`risk-${i}`}>
                        <option value="">Unclassified (denied)</option>
                        {RISKS.map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td className="px-3 py-2">
                      <select name={`approval:${a.name}`} aria-label={`Approval rule for ${a.name}`} defaultValue={c?.approval ?? a.proposed?.approval ?? "auto"} className={sel}>
                        {APPROVAL_RULES.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
                      </select>
                    </td>
                    <td className="px-3 py-2">
                      <select name={`role:${a.name}`} aria-label={`Approver role for ${a.name}`} defaultValue={c?.approver_role ?? a.proposed?.approver_role ?? "approver"} className={sel}>
                        {APPROVER_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td className="px-3 py-2">
                      <select name={`agents:${a.name}`} aria-label={`Allowed agents for ${a.name}`} defaultValue={av} className={sel}>
                        <option value="devices">Enrolled devices</option>
                        <option value="*">Any agent</option>
                        {av !== "devices" && av !== "*" ? <option value={av}>{allowedAgentsLabel(c?.allowed_agents ?? [])} (keep)</option> : null}
                      </select>
                    </td>
                  </>
                ) : (
                  <>
                    <td className="px-3 py-2">{c ? <RiskBadge level={c.risk} size="sm" /> : <span className="text-gray-11">—</span>}</td>
                    <td className="px-3 py-2">{c ? APPROVAL_RULES.find((r) => r.value === c.approval)?.label ?? c.approval : "—"}</td>
                    <td className="px-3 py-2">{c ? c.approver_role : "—"}</td>
                    <td className="px-3 py-2">{c ? allowedAgentsLabel(c.allowed_agents) : "—"}</td>
                  </>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
  if (!editable) return table;
  return (
    <form method="post" action={`/api/connectors/${connectorId}/classify`} data-testid="classify-form">
      <CsrfField csrf={csrf} />
      <input type="hidden" name="next" value={next} />
      {table}
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-gray-5 px-4 py-3">
        <p className="text-caption text-gray-11">Saving creates one new policy version. Actions left on “Unclassified” stay denied.</p>
        <Button type="submit" variant="primary">{submitLabel}</Button>
      </div>
    </form>
  );
}
