/** Builds a connector's `config` and `credentials` from the per-type form (C2). Field names in
 *  the form are `config.<field>` and `cred.<field>`. Empty inputs are omitted, so the gateway's
 *  own defaults and validation apply (it is the authority: this only shapes the request).
 *  Credentials are returned separately and must never be echoed, logged or put in a URL. */

export type Built = { config: Record<string, unknown>; credentials: Record<string, string>; bad: string[] };

const list = (v: string) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

/** The client and the route handler both validate the http_api actions JSON (an array). */
export function parseActionsJson(raw: string): { ok: true; value: unknown[] } | { ok: false; error: string } {
  if (!raw.trim()) return { ok: true, value: [] };
  try {
    const v: unknown = JSON.parse(raw);
    if (!Array.isArray(v)) return { ok: false, error: "Actions must be a JSON array of action definitions." };
    if (v.some((a) => typeof a !== "object" || a === null || Array.isArray(a))) return { ok: false, error: "Each action must be a JSON object." };
    return { ok: true, value: v };
  } catch (e) {
    return { ok: false, error: `Not valid JSON: ${(e as Error).message}` };
  }
}

export const CONFIG_FIELDS: Record<string, string[]> = {
  slack: ["default_channel", "notify_on"],
  email: ["mode", "from_address", "allowed_domains", "smtp_host", "smtp_port", "smtp_username", "http_url"],
  http_api: ["base_url", "allowed_hosts", "auth_header_name", "health_path", "actions"],
  mcp_upstream: ["url", "allowed_hosts"],
  github: ["owner_type", "owner", "repos", "mode", "protected_branches"],
};

export function buildConnector(typeId: string, get: (k: string) => string, getAll: (k: string) => string[], withCredentials = true): Built {
  const c = (k: string) => get(`config.${k}`).trim();
  const config: Record<string, unknown> = {};
  const bad: string[] = [];
  const put = (k: string, v: unknown) => {
    if (v !== "" && v !== undefined && v !== null) config[k] = v;
  };
  switch (typeId) {
    case "slack":
      put("default_channel", c("default_channel"));
      config.notify_on = getAll("config.notify_on").filter((x) => ["approval_required", "security_violation", "connector_change"].includes(x));
      break;
    case "email": {
      put("mode", c("mode"));
      put("from_address", c("from_address"));
      config.allowed_domains = list(c("allowed_domains"));
      put("smtp_host", c("smtp_host"));
      const port = c("smtp_port");
      if (port) {
        if (/^\d{1,5}$/.test(port)) config.smtp_port = Number(port);
        else bad.push("config.smtp_port");
      }
      put("smtp_username", c("smtp_username"));
      put("http_url", c("http_url"));
      break;
    }
    case "http_api": {
      put("base_url", c("base_url"));
      config.allowed_hosts = list(c("allowed_hosts").toLowerCase());
      put("auth_header_name", c("auth_header_name"));
      put("health_path", c("health_path"));
      const parsed = parseActionsJson(get("config.actions"));
      if (parsed.ok) config.actions = parsed.value;
      else bad.push("config.actions");
      break;
    }
    case "mcp_upstream":
      put("url", c("url"));
      config.allowed_hosts = list(c("allowed_hosts").toLowerCase());
      break;
    case "github":
      put("owner_type", c("owner_type") || "org");
      put("owner", c("owner"));
      config.repos = list(c("repos"));
      put("mode", c("mode") || "webhook");
      if (c("protected_branches")) config.protected_branches = list(c("protected_branches"));
      break;
    default:
      break; // agent clients: no configuration
  }
  const credentials: Record<string, string> = {};
  if (withCredentials) {
    for (const f of CREDENTIAL_FIELDS[typeId] ?? []) {
      const v = get(`cred.${f}`);
      if (v) credentials[f] = v;
    }
  }
  return { config, credentials, bad };
}

/** Credential fields the console asks for per type (GitHub's arrive from the App manifest flow). */
export const CREDENTIAL_FIELDS: Record<string, string[]> = {
  slack: ["webhook_url", "bot_token"],
  email: ["smtp_password", "api_key"],
  http_api: ["auth_header_value"],
  mcp_upstream: ["bearer_token"],
};

export const CREDENTIAL_LABEL: Record<string, string> = {
  webhook_url: "Incoming webhook URL",
  bot_token: "Bot token (xoxb-…)",
  smtp_password: "SMTP password",
  api_key: "HTTP API key",
  auth_header_value: "Auth header value",
  bearer_token: "Bearer token",
  pem: "App private key",
  webhook_secret: "Webhook secret",
  client_secret: "Client secret",
};
