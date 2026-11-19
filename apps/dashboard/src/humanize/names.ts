/** Names people recognise (ADR-0039): devices, agent kinds, sessions, roles. The full technical
 *  id always stays available in Technical details. */

import { shortDate } from "./time";

/** "device:akshat:Akshats-MacBook-Air:01a1efb5" -> "akshat on Akshats-MacBook-Air". */
export function agentName(name: string | null | undefined): string {
  if (!name) return "an agent";
  const m = /^device:([^:]+):(.+?)(?::[0-9a-f]{6,})?$/i.exec(name);
  return m ? `${m[1]} on ${m[2]}` : name;
}

const KINDS: Record<string, string> = {
  claude_code: "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
  gemini_cli: "Gemini CLI",
  mcp_generic: "VS Code (MCP)",
  other: "Coding agent",
};

/** ("claude_code", "2.1.319") -> "Claude Code 2.x". */
export function agentKindLabel(kind: string | null | undefined, version?: string | null): string {
  const base = (kind && KINDS[kind]) ?? (kind ? kind.replaceAll("_", " ") : "Coding agent");
  const major = version ? /^(\d+)\./.exec(version)?.[1] : undefined;
  return major ? `${base} ${major}.x` : base;
}

export type SessionLike = {
  agent_kind: string; agent_version?: string | null; developer?: string | null; device?: string | null;
  repo?: string | null; issue_number?: number | null; started_at?: string | null;
};

/** "Claude Code session by akshat on MintRail - issue #12" (fallback: "Session started 18 Nov, 11:18 PM"). */
export function sessionTitle(s: SessionLike | null | undefined, startedAt?: string | null, tz: "local" | "utc" = "local"): string {
  if (!s) return startedAt ? `Session started ${shortDate(startedAt, tz)}` : "Agent session";
  const who = s.developer ? ` by ${s.developer}` : "";
  const where = s.repo ? ` on ${s.repo}` : "";
  const issue = s.issue_number ? ` - issue #${s.issue_number}` : "";
  return `${agentKindLabel(s.agent_kind)} session${who}${where}${issue}`;
}

export const ROLE_WORDS: Record<string, string> = {
  admin: "admin (changes settings)",
  approver: "approver (decides approvals)",
  auditor: "auditor (reviews evidence)",
  security: "security reviewer",
  maintainer: "code maintainer",
  ledger_lead: "ledger lead (money code)",
};

export function roleWords(roles: readonly string[]): string {
  return roles.map((r) => ROLE_WORDS[r] ?? r).join(", ");
}

/** "owner/name" -> "name". */
export function repoShort(full: string): string {
  return full.includes("/") ? full.slice(full.lastIndexOf("/") + 1) : full;
}

/** A run with no coding session whose actions are GitHub steps (ADR-0042):
 *  "GitHub steps by akshat on MintRail". */
export function githubRunTitle(agents: readonly string[], repos: readonly string[]): string {
  const who = agents.length ? ` by ${agents.map(agentName).map((n) => n.split(" on ")[0]).join(", ")}` : "";
  return `GitHub steps${who} on ${repos.map(repoShort).join(", ")}`;
}
