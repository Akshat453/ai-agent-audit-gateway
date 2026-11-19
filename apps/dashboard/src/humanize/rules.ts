/** Rule ids -> short name + one-sentence reason (ADR-0039). The descriptions live NEXT TO the
 *  policies in the gateway (versioned with them) and arrive through
 *  GET /v1/dashboard/rule-descriptions; this module only looks them up and formats them. */

export type RuleText = { name: string; why: string };
export type RuleBook = { rules: Record<string, RuleText>; patterns: Record<string, RuleText> };

export const EMPTY_BOOK: RuleBook = { rules: {}, patterns: {} };

/** Rules that only ALLOW (an ordinary file, a known-safe command...) never explain a block or
 *  an approval; they are dropped whenever another rule matched. */
const NOISE = new Set([
  "PATH-LOW", "PATH-READ", "CMD-ALLOW", "CMD-ASSIGN", "CMD-SHELL-SETTING", "MCP-ALLOWED", "WEB-DOCS",
  "REPO-ALLOW-CMD", "REPO-ALLOW-PATH",
]);
const isNoise = (id: string) => NOISE.has(id) || id.startsWith("REPO-OVERLAY-");

export function describeRule(book: RuleBook, id: string): RuleText & { id: string; known: boolean } {
  const exact = book.rules[id];
  if (exact) return { ...exact, id, known: true };
  for (const [pat, entry] of Object.entries(book.patterns)) {
    if (pat.endsWith("*") && id.startsWith(pat.slice(0, -1))) {
      return { name: entry.name, why: entry.why.replace("{suffix}", id.slice(pat.length - 1)), id, known: true };
    }
  }
  return { name: id, why: "", id, known: false };
}

/** The human reasons for a set of matched rules, most specific first, without duplicates. */
export function ruleReasons(book: RuleBook, ids: readonly string[]): (RuleText & { id: string })[] {
  const useful = ids.some((i) => !isNoise(i)) ? ids.filter((i) => !isNoise(i)) : ids;
  const seen = new Set<string>();
  const out: (RuleText & { id: string })[] = [];
  for (const id of useful) {
    const d = describeRule(book, id);
    if (!d.known || seen.has(d.why)) continue;
    seen.add(d.why);
    out.push({ id: d.id, name: d.name, why: d.why });
  }
  return out;
}

/** The gateway's policy reason codes (engine.ReasonCode) in words. */
export const REASON_CODES: Record<string, string> = {
  TOOL_NOT_REGISTERED: "The agent asked for a tool that does not exist.",
  ARGS_SCHEMA_INVALID: "The request's details were invalid.",
  ENVIRONMENT_NOT_ALLOWED: "This tool may not run in this environment.",
  SCOPE_MISSING: "The agent lacks the permission this tool needs.",
  AGENT_DISABLED: "This agent has been switched off.",
  POLICY_RULE_DENY: "A policy rule blocks this.",
  NO_MATCHING_ALLOW: "No rule allows this, so it is blocked by default.",
  POLICY_REQUIRES_APPROVAL: "A policy rule requires a person to approve this.",
  CRITICAL_REQUIRES_APPROVAL: "Critical actions need the right reviewer to approve.",
  HIGH_REQUIRES_APPROVAL: "High-risk actions need a person to approve.",
  MEDIUM_REQUIRES_APPROVAL: "This tool needs approval even at medium risk.",
  CRITICAL_DENIED: "Critical actions are blocked.",
  RISK_RULE_DENY: "A risk rule blocks this.",
  RISK_RULE_REQUIRES_APPROVAL: "A risk rule requires a person to approve this.",
  DELEGATION_INVALID: "The hand-over of permissions is invalid.",
  DELEGATION_NOT_FOR_AGENT: "The hand-over was meant for a different agent.",
  DELEGATION_EXPIRED: "The hand-over of permissions has expired.",
  DELEGATION_REVOKED: "The hand-over of permissions was cancelled.",
  DELEGATION_EXHAUSTED: "The hand-over has been used up.",
  DELEGATION_DEPTH_EXCEEDED: "Too many agents in the hand-over chain.",
  DELEGATION_ISSUER_INACTIVE: "The agent that handed over permissions is switched off.",
  DELEGATION_SCOPE_MISSING: "The hand-over does not include this permission.",
  DELEGATION_TOOL_NOT_ALLOWED: "The hand-over does not include this tool.",
  DELEGATION_RISK_EXCEEDED: "The action is riskier than the hand-over allows.",
  CONNECTOR_ACTION_UNCLASSIFIED: "An admin has not set rules for this integration action yet, so it is blocked.",
  CONNECTOR_DISABLED: "This integration is turned off.",
  CONNECTOR_AGENT_NOT_ALLOWED: "This agent may not use this integration action.",
  CONNECTOR_ARG_CONSTRAINT: "The request is outside the limits an admin set for this action.",
  CONNECTOR_ACTION_DENIED: "An admin blocked this integration action.",
  CONNECTOR_REQUIRES_APPROVAL: "An admin set this integration action to need approval.",
  CONNECTOR_CONTENT_DENIED: "The submitted change breaks a content rule.",
};

/** A reason string from a decision: a code becomes words; a sentence stays as it is. */
export function reasonInWords(reason: string): string {
  return REASON_CODES[reason] ?? reason;
}
