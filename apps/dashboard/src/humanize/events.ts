/** One evidence record in plain words (event page, event lists, timelines) (ADR-0039).
 *  Built from the SEALED header's structured fields; the request contents (command text, file
 *  contents, arguments) are encrypted in the payload and are not part of a header. */

import { toolPhrase } from "./actions";
import { EVIDENCE_CLASS, eventSentence } from "./event-types";
import { describeRule, reasonInWords, type RuleBook } from "./rules";
import { plainStatus, riskWord } from "./statuses";
import { longTime } from "./time";

type Header = Record<string, unknown>;
export type Explained = { headline: string; details: string[] };

function actorWords(actor: unknown): string {
  const a = (actor ?? {}) as { kind?: string };
  return { agent: "the AI agent", human: "a person", gateway: "AgentGuard", system: "AgentGuard (background job)" }[a.kind ?? ""] ?? "someone";
}

export function explainHeader(h: Header, book?: RuleBook, opts: { people?: Record<string, string>; tz?: string } = {}): Explained {
  const type = String(h.type ?? "");
  const tool = (h.tool ?? {}) as { id?: string };
  const what = tool.id ? toolPhrase(tool.id).text : null;
  const policy = (h.policy ?? {}) as { effect?: string; reasons?: unknown[]; rules?: unknown[]; id?: string; ver?: number };
  const risk = (h.risk ?? {}) as { level?: string; score?: number };
  const outcome = (h.outcome ?? {}) as { status?: string; code?: string };
  const approval = (h.approval ?? {}) as { approver?: string; req?: number; votes?: number };
  const report = (h.report ?? {}) as { tenant?: string; result?: string };
  const violation = (h.violation ?? {}) as { kind?: string; claimed?: string };
  const approver = approval.approver ? opts.people?.[approval.approver] ?? null : null;
  let headline = eventSentence(type, { what, approver, code: outcome.code ?? violation.kind ?? null, tenant: report.tenant ?? null, result: report.result ?? outcome.status ?? null });
  const details: string[] = [];
  if (type === "POLICY_EVALUATED" && policy.effect) {
    headline = `AgentGuard checked the rules${what ? ` for the request to ${what}` : ""} and ${policy.effect === "DENY" ? "blocked it" : policy.effect === "REQUIRE_APPROVAL" ? "asked a person to approve it" : "allowed it"}.`;
    const rules = (policy.rules ?? []).map(String);
    for (const id of rules) {
      const d = book ? describeRule(book, id) : null;
      if (d?.known) details.push(`${d.why} (rule ${id})`);
    }
    if (!details.length) for (const r of (policy.reasons ?? []).map(String)) details.push(reasonInWords(r));
    if (risk.level) details.push(`Risk: ${riskWord(risk.level)}${risk.score !== undefined ? ` (score ${risk.score})` : ""}.`);
    if (policy.id) details.push(`Rules used: ${policy.id} version ${String(policy.ver ?? "?")}.`);
  }
  if (type === "ACTION_REQUESTED") details.push("The exact request (command, file, arguments) is stored encrypted with this record.");
  if (type === "ACTION_AUTHORIZED") {
    const code = (h.code ?? {}) as { adapter?: string };
    if (code.adapter === "agent-executed") details.push("The agent carries this out itself on the developer's machine; AgentGuard records that it was allowed.");
    details.push("The fingerprint of the exact request is sealed here, so a different request would not match.");
  }
  if (type === "APPROVAL_GRANTED" && approval.req) details.push(`Approvals needed: ${approval.req}; so far: ${String(approval.votes ?? "?")}. The decision is signed.`);
  if (outcome.status && type !== "POLICY_EVALUATED") details.push(`Result: ${plainStatus(outcome.status)}${outcome.code ? ` (${outcome.code})` : ""}.`);
  if (violation.claimed) details.push(`Detail: ${violation.claimed}.`);
  const cls = EVIDENCE_CLASS[String(h.class ?? "")];
  details.push(`Recorded by ${actorWords(h.actor)}${typeof h.ts === "number" ? `, ${longTime(new Date(h.ts / 1000).toISOString(), opts.tz ?? "utc")}` : ""}${cls ? ` (${cls})` : ""}.`);
  return { headline, details };
}

/** One line for a timeline/list node when only the type and decision are known. */
export function explainNode(n: { type: string; decision?: string | null; status?: string | null }, toolId?: string | null): string {
  const what = toolId ? toolPhrase(toolId).text : null;
  if (n.type === "POLICY_EVALUATED" && n.decision) {
    return `AgentGuard checked the rules and ${n.decision === "DENY" ? "blocked it" : n.decision === "REQUIRE_APPROVAL" ? "asked a person to approve it" : "allowed it"}.`;
  }
  return eventSentence(n.type, { what, result: n.status ?? null });
}

