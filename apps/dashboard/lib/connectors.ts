/** C2 (ADR-0035) connector, repo, people, enrollment and onboarding shapes. The gateway returns
 *  these as free-form JSON (dict[str, Any] in the OpenAPI document), so the dashboard declares
 *  the fields it reads here. Every string that came from an MCP upstream (action names,
 *  descriptions, schemas) is UNTRUSTED and is rendered as React text only. */

export type Category = "code_hosting" | "agent_client" | "tool" | "notification" | "anchoring" | "mcp_upstream";
export type Risk = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ApprovalRule = "auto" | "always" | "deny";
export type ApproverRole = "approver" | "security" | "ledger_lead" | "maintainer";

export type ActionDef = {
  name: string;
  description: string;
  side_effect: "read" | "write" | "delete" | "execute" | string;
  suggested_risk: Risk | string;
  input_schema: Record<string, unknown>;
};

export type ArgConstraint = { allowed?: string[] | null; pattern?: string | null; max_length?: number | null; min?: number | null; max?: number | null };

export type Classification = {
  risk: Risk;
  approval: ApprovalRule;
  approver_role: ApproverRole;
  allowed_agents: string[];
  constraints: Record<string, ArgConstraint>;
};

export type Setup = {
  tier?: "enforced" | "hooked" | "advisory" | "mcp_only" | string;
  tier_reason?: string;
  commands?: string[];
  mcp_url?: string;
  hook_kind?: string | null;
  read_only?: boolean;
  configured_by?: string;
};

export type CatalogType = {
  id: string;
  name: string;
  category: Category;
  auth: string;
  description: string;
  creatable: boolean;
  dynamic_actions: boolean;
  actions: ActionDef[];
  config_schema: Record<string, unknown>;
  credential_fields: string[];
  setup: Setup;
};

export type Health = { ok: boolean; code: string; checked_at?: string; [k: string]: unknown };

export type ConnectorSummary = {
  connector_id: string | null;
  type_id: string;
  category: Category;
  slug: string;
  name: string;
  status: "connected" | "needs_attention" | "disabled" | string;
  policy_version: number;
  credential_version?: number;
  unclassified_actions: number;
  last_health?: Health | null;
  created_at?: string;
  read_only?: boolean;
  config?: Record<string, unknown>;
};

export type ConnectorAction = ActionDef & { upstream_name: string | null; classification: Classification | null; proposed?: Classification | null };

export type ConnectorDetail = ConnectorSummary & {
  config: Record<string, unknown>;
  credentials: { fields: string[]; set: boolean; version: number };
  actions: ConnectorAction[];
  health: Health[];
  usage: { calls: number; denials: number; approvals: number };
  events: { seq: number; type: string; event_id: string; occurred_at: string }[];
  setup: Setup;
};

export type Repo = {
  repo_id: string;
  name: string;
  remote_url: string;
  policy_version: number;
  agents: Record<string, { tier?: string; [k: string]: unknown }>;
  overlay: {
    sensitive?: (string | { path: string; level?: string })[];
    deny_paths?: string[];
    deny_commands?: string[];
    allow_paths?: string[];
    allow_commands?: string[];
  };
  proposals: { proposal_id: string; items: Record<string, unknown>[]; status: string; diff: string; created_at: string }[];
};

export type Person = { username: string; roles: string[]; status: string };
export type DeviceRequest = { user_code: string; agent_kind: string; label: string; status: string; created_at: string };
export type OnboardingStep = { id: string; label: string; done: boolean; href?: string; available?: boolean; note?: string };
export type Onboarding = { steps: OnboardingStep[]; complete: boolean };
export type ConsentInfo = { client_id: string; client_name: string; redirect_host: string; resource: string; scope: string; developer: string };

export const CATEGORY_LABEL: Record<Category, string> = {
  code_hosting: "Code hosting",
  agent_client: "Coding agents",
  notification: "Notifications",
  tool: "Tools",
  mcp_upstream: "MCP servers",
  anchoring: "Anchoring",
};
export const CATEGORY_ORDER: Category[] = ["code_hosting", "agent_client", "notification", "tool", "mcp_upstream", "anchoring"];
export const CATEGORY_HELP: Record<Category, string> = {
  code_hosting: "Repositories the gateway watches and protects (GitHub App).",
  agent_client: "Coding agents on developer machines. Each developer enrolls a device with agw login.",
  notification: "Where approval requests and security alerts are sent. Each also offers one tool action.",
  tool: "External APIs your agents can call through the gateway, one classified action at a time.",
  mcp_upstream: "Remote MCP servers. Their tools are discovered, start unclassified and are denied until classified.",
  anchoring: "The public blockchain anchor for evidence epochs. Configured by the operator; read-only here.",
};

export const RISKS: Risk[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
export const APPROVAL_RULES: { value: ApprovalRule; label: string }[] = [
  { value: "auto", label: "Auto (no human)" },
  { value: "always", label: "Always ask a human" },
  { value: "deny", label: "Deny" },
];
export const APPROVER_ROLES: ApproverRole[] = ["approver", "security", "ledger_lead", "maintainer"];
export const INVITE_ROLES = ["approver", "admin", "auditor", "security", "ledger_lead", "maintainer"] as const;
export const AGENT_CLIENT_TYPES = ["claude_code", "codex", "cursor", "gemini_cli", "vscode", "antigravity", "generic_mcp"];

export const SLUG_RE = /^[a-z][a-z0-9]{1,23}$/;
export const USER_CODE_RE = /^[A-Z]{4}-[A-Z]{4}$/;

/** "ABCD-EFGH" from whatever the developer typed (letters only, as the gateway normalizes). */
export function normalizeUserCode(raw: string): string {
  const s = raw.toUpperCase().replace(/[^A-Z]/g, "");
  return s.length >= 8 ? `${s.slice(0, 4)}-${s.slice(4, 8)}` : s;
}

/** Status-table keys for connector states (lib/status.ts). */
export function connectorStatusKey(status: string): string {
  return { connected: "CONNECTED", needs_attention: "NEEDS_ATTENTION", disabled: "DISABLED" }[status] ?? status.toUpperCase();
}

export function tierKey(tier: string | undefined): string | null {
  return tier ? `TIER_${tier.toUpperCase()}` : null;
}

export function allowedAgentsLabel(a: string[]): string {
  if (a.length === 1 && a[0] === "devices") return "Enrolled developer devices";
  if (a.includes("*")) return "Any agent with connectors:invoke";
  return `${a.length} specific agent${a.length === 1 ? "" : "s"}`;
}
