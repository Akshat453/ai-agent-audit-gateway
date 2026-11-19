/**
 * Plain-English explanation of an evidence record (the sealed header, or a timeline node).
 * Display only: it never changes what is recorded. Command text, file contents and arguments
 * are NOT in the header (they are encrypted in the payload), so the text says what KIND of
 * thing happened and what was decided, not the exact command.
 */

type Header = Record<string, unknown>;

export type Explained = { headline: string; details: string[] };

const CODING: Record<string, string> = {
  file_read: "read a file",
  file_write: "change a file",
  file_delete: "delete a file",
  command_exec: "run a shell command",
  search: "search the code",
  web_fetch: "fetch a web page",
  mcp_call: "call an MCP tool",
  git_op: "run a git command",
};

const GITHUB: Record<string, string> = {
  github_issue_get: "read a GitHub issue",
  github_issue_list: "list GitHub issues",
  github_issue_comment: "comment on a GitHub issue",
  git_submit_change: "submit its code change (push a branch to GitHub)",
  github_pr_create: "open a pull request",
  github_pr_comment: "comment on a pull request",
  github_pr_status: "check a pull request's status",
};

/** "run a shell command", "open a pull request", or the raw id if unknown. */
export function toolPhrase(toolId: string | undefined | null): string {
  if (!toolId) return "do something";
  if (toolId.startsWith("coding.")) return CODING[toolId.slice(7)] ?? `use ${toolId}`;
  if (toolId.startsWith("cx_")) {
    const action = Object.keys(GITHUB).find((k) => toolId.endsWith(`_${k}`));
    if (action) return GITHUB[action] ?? action;
    return `use the integration action ${toolId.slice(3)}`;
  }
  return `use the tool ${toolId}`;
}

function who(actor: unknown): string {
  const a = (actor ?? {}) as { kind?: string; id?: string };
  switch (a.kind) {
    case "agent": return "The AI agent";
    case "human": return "A person";
    case "gateway": return "AgentGuard";
    case "system": return "AgentGuard (background job)";
    default: return "Someone";
  }
}

const EFFECT: Record<string, string> = {
  ALLOW: "allowed it",
  DENY: "blocked it",
  REQUIRE_APPROVAL: "asked a person to approve it",
};

function decisionLine(policy: Header | undefined): string[] {
  if (!policy) return [];
  const out: string[] = [];
  const effect = String(policy.effect ?? "");
  out.push(`Decision: the policy ${EFFECT[effect] ?? effect.toLowerCase()}.`);
  const reasons = Array.isArray(policy.reasons) ? (policy.reasons as unknown[]).map(String) : [];
  if (reasons.length) out.push(`Why: ${reasons.join(" ")}`);
  const rules = Array.isArray(policy.rules) ? (policy.rules as unknown[]).map(String) : [];
  if (rules.length) out.push(`Rules that matched: ${rules.join(", ")}.`);
  if (policy.id) out.push(`Policy used: ${String(policy.id)} version ${String(policy.ver ?? "?")}.`);
  return out;
}

function riskLine(risk: Header | undefined): string[] {
  if (!risk?.level) return [];
  return [`Risk: ${String(risk.level)} (score ${String(risk.score ?? "?")}).`];
}

function when(us: unknown): string | null {
  return typeof us === "number" ? new Date(us / 1000).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC") : null;
}

/** Explain a full sealed header (event page). */
export function explainHeader(h: Header): Explained {
  const type = String(h.type ?? "");
  const tool = (h.tool ?? {}) as { id?: string };
  const what = toolPhrase(tool.id);
  const actor = who(h.actor);
  const outcome = (h.outcome ?? {}) as { status?: string; code?: string };
  const approval = (h.approval ?? {}) as Header;
  const code = (h.code ?? {}) as Header;
  const details: string[] = [];
  let headline: string;

  switch (type) {
    case "ACTION_REQUESTED":
      headline = `The AI agent asked to ${what}.`;
      details.push("The exact request (command, file, arguments) is stored encrypted with this record; only a person with a disclosure grant can open it.");
      if (h.env) details.push(`Environment: ${String(h.env)}.`);
      break;
    case "POLICY_EVALUATED": {
      const effect = String(((h.policy ?? {}) as Header).effect ?? "");
      headline = `AgentGuard checked the request to ${what} and ${EFFECT[effect] ?? "decided"}.`;
      details.push(...decisionLine(h.policy as Header | undefined), ...riskLine(h.risk as Header | undefined));
      break;
    }
    case "ACTION_DENIED":
      headline = `The request to ${what} was blocked.`;
      if (outcome.code) details.push(`Reason code: ${outcome.code}.`);
      break;
    case "APPROVAL_REQUIRED":
      headline = `The request to ${what} is waiting for a person to approve it.`;
      details.push("Open Approvals to approve or reject it.");
      break;
    case "APPROVAL_GRANTED":
      headline = `A person approved the request${what !== "do something" ? ` to ${what}` : ""}.`;
      if (approval.req) details.push(`Approvals needed: ${String(approval.req)}; approvals so far: ${String(approval.votes ?? "?")}.`);
      details.push("The decision is signed by AgentGuard, so it cannot be changed later.");
      break;
    case "APPROVAL_DENIED":
      headline = "A person rejected the request.";
      break;
    case "APPROVAL_EXPIRED":
      headline = "Nobody decided in time, so the approval request expired and the action did not happen.";
      break;
    case "ACTION_AUTHORIZED":
      headline = `AgentGuard gave the final go-ahead to ${what}.`;
      if (code.adapter === "agent-executed") {
        details.push("The agent carries this out itself on the developer's machine; AgentGuard records that it was allowed.");
      } else if (code.adapter) {
        details.push(`AgentGuard carries it out itself (${String(code.adapter)}).`);
      }
      details.push("The fingerprint of the exact arguments (\"args\") is sealed here, so a different command than the approved one would not match.");
      break;
    case "ACTION_DISPATCHED":
      headline = `AgentGuard started to ${what}.`;
      break;
    case "ACTION_COMPLETED":
      headline = `Done: the action to ${what} finished successfully.`;
      break;
    case "ACTION_FAILED":
      headline = `The action to ${what} failed.`;
      if (outcome.code) details.push(`Error: ${outcome.code}.`);
      break;
    case "ACTION_OUTCOME_UNKNOWN":
      headline = "AgentGuard could not tell whether the action happened (for example, a timeout). Someone needs to check and record the result.";
      break;
    case "ACTION_RECONCILED":
      headline = `A person checked and recorded the real result: ${String(outcome.status ?? "?").toLowerCase()}.`;
      break;
    case "SECURITY_VIOLATION": {
      const v = (h.violation ?? {}) as { kind?: string; claimed?: string };
      const kinds: Record<string, string> = {
        AGENT_ID_MISMATCH: "An agent used credentials that do not belong to it.",
        AGENT_ON_HUMAN_ENDPOINT: "An agent tried to use a page meant only for people (for example, to approve its own request).",
        DELEGATION_REFUSED: "An agent tried to give another agent more power than it has.",
        CODING_UNDECIDED_ACTION: "A coding agent reported doing something AgentGuard never allowed.",
      };
      headline = `Security alert: ${kinds[v.kind ?? ""] ?? v.kind ?? "unknown"}`;
      if (v.claimed) details.push(`Detail: ${v.claimed}.`);
      break;
    }
    case "EPOCH_SEALED":
      headline = "AgentGuard sealed a batch of log records together so none of them can be changed unnoticed.";
      break;
    case "VERIFICATION_REPORT": {
      const r = (h.report ?? {}) as { tenant?: string; result?: string };
      headline = `The monitor checked the logs of "${String(r.tenant ?? "?")}": ${String(r.result ?? "?")}.`;
      break;
    }
    case "DISCLOSURE_GRANTED":
      headline = "An admin allowed an auditor to read the encrypted contents of some records.";
      break;
    case "DISCLOSURE_ACCESSED":
      headline = "An auditor opened encrypted record contents they were allowed to read.";
      break;
    case "PAYLOAD_DELETED":
      headline = "The encrypted contents of a record were deleted (retention or erasure request). The record itself stays.";
      break;
    case "DELEGATION_CREATED":
      headline = "An agent handed part of its permissions to another agent.";
      break;
    case "DELEGATION_REVOKED":
      headline = "A hand-over of permissions between agents was cancelled.";
      break;
    case "CONNECTOR_ADDED": headline = "An admin added an integration."; break;
    case "CONNECTOR_UPDATED": headline = "An admin changed an integration's settings."; break;
    case "CONNECTOR_ACTION_CLASSIFIED": headline = "An admin set which integration actions are allowed or need approval."; break;
    case "CONNECTOR_CREDENTIAL_ROTATED": headline = "An admin replaced an integration's secret."; break;
    case "CONNECTOR_DISABLED": headline = "An admin turned an integration off."; break;
    case "CONNECTOR_DELETED": headline = "An admin deleted an integration."; break;
    case "DEVICE_ENROLLED": headline = "A developer's computer was connected to AgentGuard."; break;
    case "REPO_POLICY_CHANGED": headline = "A repository's AgentGuard rules (.agentguard.yaml) changed."; break;
    default:
      headline = `${actor} recorded a ${type} event.`;
  }
  const at = when(h.ts);
  details.push(`Recorded by: ${actor === "The AI agent" ? "the AI agent" : actor}${at ? `, at ${at}` : ""}.`);
  if (h.tenant) details.push(`Organization: ${String(h.tenant)}.`);
  return { headline, details };
}

/** One-line explanation for a timeline node (no full header available). */
export function explainNode(n: { type: string; decision?: string | null; status?: string | null }, toolId?: string | null): string {
  const h: Header = { type: n.type, tool: { id: toolId ?? undefined } };
  if (n.decision) h.policy = { effect: n.decision };
  if (n.status) h.outcome = { status: n.status };
  return explainHeader(h).headline;
}
