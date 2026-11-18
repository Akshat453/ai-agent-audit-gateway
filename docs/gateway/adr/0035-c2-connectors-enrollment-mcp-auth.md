# ADR-0035: C2 connectors, device enrollment, remote MCP with sign-in, tighten-only repo policy, `agw init`
Status: Accepted · Date: 2026-11-18 · Deciders: C2 implementation (pending owner review)

## Context
C2 is meant to make AgentGuard adoptable in minutes:
- an admin adds connectors from an Integrations page;
- a developer runs `agw login` and `agw init`, and every coding agent is connected;
- adding a connector must never weaken policy.

The prompt fixes five security invariants:
1. new actions are UNCLASSIFIED and denied;
2. credentials are write-only;
3. admin + step-up + evidence on every change;
4. `.agentguard.yaml` can only tighten;
5. classification changes are new policy versions.

**Current external docs** (fetched 2026-11-18; facts in §5 and in coding-agents.md):
- **MCP 2026-07-28** is stateless. `initialize` and sessions are removed. `server/discover` is mandatory. `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers must match the body. Results carry `resultType`.
- **MCP authorization** requires:
  - Protected Resource Metadata (RFC 9728) at the root and path-inserted well-known URIs;
  - AS metadata (RFC 8414) with `code_challenge_methods_supported`;
  - PKCE S256;
  - `resource` (RFC 8707) on authorization and token requests, with audience validation;
  - client registration via CIMD (preferred) or DCR (deprecated, still used by Cursor and Gemini CLI);
  - `iss` in the authorization response (RFC 9207);
  - rotating refresh tokens for public clients.
- **GitHub App manifest flow:** form POST with `manifest`, then `code`, then `POST /app-manifests/{code}/conversions`, within one hour. The install step's `installation_id` is spoofable.
- **Slack:** incoming webhooks; `chat.postMessage` with a bot token; `auth.test`.

**Mapping (prompt → repository):**

| Prompt | Repository |
|---|---|
| "apps/gateway/connectors/" | the package `apps/gateway/src/agw_gateway/connectors/` |
| policy | 04 + ADR-0026 + ADR-0034 |
| approvals | ADR-0027 |
| privacy/encryption | 07 + ADR-0029 |
| dashboard design | 16 + ADR-0033 |
| `~/projects/agentguard/*` | `~/Desktop/*` (the answer key was never opened; MintRail only read) |

## Decision

### 1. Connector framework
- **A type is code:**
  - a `ConnectorManifest` (id, name, category, auth method, actions with an input schema, side effect and suggested risk);
  - a Pydantic config model (non-secret);
  - a Pydantic credential model (secret);
  - health / test-connection;
  - an executor;
  - for dynamic types, discovery.
- **Input schemas** are a small JSON-Schema subset: string, integer, boolean and array of string; no floats, no nesting. A strict, `extra="forbid"` Pydantic model is built from them.
- **Instances** live per tenant in `connectors`: non-secret `config` JSON, `credentials_sealed`, `status` (connected / needs_attention / disabled), `last_health` and `created_by`.
- **Actions** are stored in `connector_actions`. Descriptions are untrusted text: stored, rendered escaped, never used in decisions, and never forwarded to an MCP client's model (the gateway writes its own tool descriptions).
- **Registration into the existing tool registry.** `ToolRegistry` gains a per-tenant dynamic source: `cx_<slug>_<action>` resolves to a `ConnectorToolSpec` at tool version `1.0.<classification version>`. The normal pipeline (identity → risk → policy → approval → evidence → executor) is unchanged.
- **The classification reaches the pure policy engine** as a `ConnectorConstraint` (as delegation does in ADR-0030):
  - **System checks** deny for: `CONNECTOR_ACTION_UNCLASSIFIED`, `CONNECTOR_DISABLED`, `CONNECTOR_AGENT_NOT_ALLOWED`, `CONNECTOR_ARG_CONSTRAINT`, and `CONNECTOR_ACTION_DENIED` (approval rule `deny`).
  - **Approval rule `always`** turns ALLOW into REQUIRE_APPROVAL.
  - **The chosen risk is the tool's base risk.** The risk engine can raise it, never lower it. For example, a Slack post classified LOW still scores HIGH (irreversible external write) and needs a human.
  - **Approvals** are routed to the classification's `approver_role`.
  - **Revalidation at approval time** uses the CURRENT classification.
  - **At dispatch,** a connector disabled or deleted since authorization never reaches its adapter (`get_any` returns None, so the action fails as TOOL_UNAVAILABLE).
- **Results** are filtered by Phase 7 field classes per type: only public/internal fields go back to the agent. For HTTP actions these are the admin-classified response fields.
- **Classification versions** are append-only rows in `connector_policies` (trigger-protected). A superseded version is not callable; earlier actions keep their `tool_version` and the `cx:<slug>@v<n>` rule id in POLICY_EVALUATED.
- **Connector tools are not mirrored into the global `tool_registry` table.** Its key `(tool_id, version)` is not tenant-scoped; `connector_actions` + `connector_policies` are the record. *Doc change: 11 §4.*

### 2. Credentials: write-only
- **Validation and storage.** Credentials are validated by the type's model and sealed with the Phase 7 envelope (`EnvelopeCipher.seal_json`, AAD = tenant + `connector_credentials` + connector id).
- **Read paths** return only `{fields, set, version}`.
- **Validation errors** name fields only.
- **Rotation** replaces the sealed blob and bumps `credential_version`.
- **Delete** sets the blob to NULL (the ciphertext is destroyed; the KEK-wrapped DEK goes with it).
- **Tests:** a canary token is never in any API response (including errors), log, config row, sealed bytes or evidence header.

### 3. Admin + step-up + evidence
Every change needs role `admin` and a step-up within the configured window, and writes its evidence event in the same transaction:
- add, update, enable → `CONNECTOR_ADDED`, `CONNECTOR_UPDATED`;
- classify → `CONNECTOR_ACTION_CLASSIFIED`, one per action, carrying the version and document digest;
- rotate → `CONNECTOR_CREDENTIAL_ROTATED`;
- disable → `CONNECTOR_DISABLED`;
- delete → `CONNECTOR_DELETED`;
- GitHub App registration and installation → `CONNECTOR_UPDATED`.

These are new event types with a new top-level header map `connector {id, type, ver, act?, cred?, digest?}`. The verifier's key allowlist gains `connector`, `device` and `repo`, the same kind of v1 addition as ADR-0029/0030/0031. Read paths are open to admin, auditor and security; test-connection to admin.

### 4. Built-in types
- **GitHub (code_hosting):**
  - config and the manifest flow: "Create GitHub App" posts the manifest;
  - a single-use `state` is minted for an admin with step-up, stored as a hash, and expires in one hour;
  - the callback converts the code through `SafeHttp` and stores `pem`, `webhook_secret` and `client_secret` sealed;
  - the install URL carries a fresh state, and the setup callback accepts `installation_id` only with that state;
  - C3 verifies the installation with the App JWT (`app_jwt`, RS256);
  - no actions until C3.
- **Agent clients** (Claude Code, Codex, Cursor, Gemini CLI, VS Code, Antigravity, generic MCP): no actions. Setup shows the tier, commands, MCP URL and enrollment link. Tiers from C1's table:

  | Tier | Agents |
  |---|---|
  | `enforced` | Claude Code, Codex |
  | `hooked` | Cursor |
  | `advisory` | Gemini CLI |
  | `mcp_only` | VS Code, Antigravity, generic MCP |

- **Slack:** an incoming webhook (a secret) for notifications, plus an optional bot token for `post_message`. Test connection uses `auth.test` or posts a test message.
- **Email:** SMTP (STARTTLS) or an HTTP provider; `send_email` with a recipient-domain allowlist.
- **Generic HTTP API:** see §6 for SSRF.
  - `base_url` plus an exact host allowlist.
  - A secret auth header.
  - Admin-defined actions: method, path template, input schema, side effect, and response field classes.
  - GET must be `read`.
  - A changed action definition loses its classification (new version).
- **Anchoring:** the Phase 6 settings are shown read-only under Integrations: host only for the RPC URL, which may carry a key. No behaviour change.
- **MCP upstream:**
  - **Connection:** Streamable HTTP. The client side follows MCP 2026-07-28, falling back to 2025-11-25 `initialize`.
  - **Discovery:** test connection discovers the tools; every one is UNCLASSIFIED, with suggested risk HIGH and side effect `execute` (the upstream effect is unknown).
  - **Schemas:** an input schema outside the subset is replaced by `{arguments_json: string}`.
  - **Names:** sanitized; the original name is kept in `upstream_name`.

### 5. Device enrollment and the remote MCP endpoint with sign-in
- **Device enrollment (RFC 8628):**
  - **Flow:** `POST /v1/device/authorize`, then the developer approves at the dashboard's `/enroll`, then `POST /v1/device/token`, which returns `authorization_pending`, `slow_down`, `access_denied` or `expired_token`.
  - **The key is issued exactly once.** Device codes are stored as hashes only.
  - **The approving human becomes the developer.**
  - **The runtime role still cannot write `agents` or `humans`.** The SECURITY DEFINER function `agw_enroll_device` is the only path, and it creates one coding device with the fixed scopes `coding:device` and `connectors:invoke`, bound to an active human of the tenant. `agw_invite_human` (admin-checked) backs "invite people".
  - **Evidence:** `DEVICE_ENROLLED` with a `device` map.
- **MCP OAuth server (in the gateway):**
  - **Metadata:** PRM at both well-known paths; AS metadata with S256 only, `client_id_metadata_document_supported`, a DCR registration endpoint and `iss` support. CIMD documents are fetched through `SafeHttp`.
  - **Authorize:** validates the client, the exact redirect URI (https or loopback), S256, `resource == <public_url>/mcp` and scope, then redirects to the dashboard consent page.
  - **Consent:** shows the client and the developer. On approval it binds a single-use 2-minute code to client, redirect, PKCE challenge, resource and device. Each (developer, client) pair gets its own device, so tokens are developer + device bound.
  - **Token:**
    - access tokens are opaque `agwm_…`, valid 10 minutes, stored as hashes, with resource (audience) checked on every request;
    - refresh tokens rotate, and reuse revokes the family;
    - a failed redemption still burns the code.
  - **Lifecycle:** a disabled device or developer invalidates its tokens at once.
- **Remote MCP endpoint `POST /mcp`, dual era:**
  - **Modern (2026-07-28):** `_meta` validation, header and body consistency (`-32020` / 400), `server/discover`, `resultType`, and `ttlMs` + `cacheScope: private` on `tools/list`.
  - **Legacy:** `initialize` / `notifications/initialized` / `ping`, without sessions.
  - **Other rules:** an `Origin` allowlist (403 otherwise); GET/DELETE return 405; 401 carries `WWW-Authenticate: Bearer resource_metadata=…, scope=…`.
  - **Tools** are the classified, enabled connector actions the device may call.
  - **`tools/call`** is an ordinary `POST /v1/actions`; a pending approval is returned as `isError` with the approval link.
  - **This replaces Phase 8's operator-issued exchange tokens** for IDE use; the RFC 8693 exchange stays for server integrations.

### 6. SSRF protection (HTTP and MCP-upstream connectors, CIMD fetches)
`SafeHttp` enforces:
- https only;
- no userinfo;
- an exact host allowlist (port 443 unless listed);
- a single DNS resolution, where EVERY address must be globally routable (private, loopback, link-local/metadata, CGNAT, multicast, reserved, IPv4-mapped/6to4/NAT64 forms refused);
- the connection made to the validated IP, with `Host` and TLS SNI set to the name, so DNS rebinding cannot redirect it;
- no redirects, no environment proxies, and bounded time and size.

### 7. Repositories and `.agentguard.yaml`: tighten only
- **Registration and parsing.** `agw init` registers the repo and sends the file's TEXT. The gateway parses it (`yaml.safe_load`, 64 KiB, a small schema).
- **Tightening is applied at once** as an append-only repo policy version: new `sensitive_paths` (high / critical, with an optional owner role), a raised level, new `deny_paths` or `deny_commands`. It writes `REPO_POLICY_CHANGED TIGHTENED`.
- **Loosening is ignored, reported, and turned into ONE pending proposal**, de-duplicated by content. Loosening means `allow_paths`, `allow_commands`, or removing or downgrading an earlier tightening.
- **Unknown keys and invalid entries** are reported.
- **Admin decision.** An admin with step-up approves (new version, `PROPOSAL_APPROVED`) or rejects (`PROPOSAL_REJECTED`) in the dashboard, with a diff.
- **Applying the overlay.** `CodingPolicy.with_overlay` merges it into the coding policy of sessions in that repository; the overlay digest is folded into the policy digest.
- **Limits on approved exceptions:**
  - `allow_paths` only relaxes HIGH-path asks;
  - `allow_commands` only relaxes "unknown command" asks;
  - neither touches a secret, a CRITICAL path, a content rule or a denied command.

### 8. `agw` CLI additions
- **`agw login` / `logout`:**
  - device code; the key goes to the OS keychain (macOS `security -i` with the secret on stdin; Linux `secret-tool` via stdin) or a 0600 file outside any git checkout;
  - the config holds only a reference;
  - `logout` removes the local key. Server-side device revocation is via the dashboard and agents table (gap: no self-service revoke API yet).
- **`agw init`** (detection, per-agent generation and ownership markers are described in wiring.py):
  - **Detection:** repo root, package managers, languages, CODEOWNERS, existing agent configs, installed agents.
  - **Hook configs** for the four hook-capable agents: timeout 120 s, Claude `onFailure: block`, Cursor `failClosed`, Gemini timeout in ms.
  - **MCP config** for every agent and IDE in its own format: `.mcp.json`, `.codex/config.toml` (marked block), `.cursor/mcp.json`, Gemini `httpUrl`, `.vscode/mcp.json`, `.agents/mcp_config.json`.
  - **A marked AGENTS.md section.**
  - **`.agentguard.yaml`** with suggested sensitive paths, only if absent; an optional hardened devcontainer.
  - **Changes to existing files** are shown as a diff and need `--yes` or an interactive yes.
  - **Ownership** is by markers, so re-runs are idempotent and uninstall removes only what init added. Created files are deleted only if unchanged.
  - **Finally** the repo is registered (tiers + yaml).
- **`agw doctor`:**
  - gateway reachable; logged in; repo registered with pending proposals;
  - per agent: tier, hook present and pointing to `agw hook`, timeout and fail-closed settings, MCP config, managed enforcement;
  - `agw` on PATH; push and credential exposure;
  - non-zero exit on any FAIL, with fix instructions.
- **`agw uninstall`.**

## Consequences
**Gains**
- Integrations go through the existing enforcement and evidence pipeline unchanged.
- Policy can only be tightened by repos and connectors. Loosening is always an explicit, step-up, evidenced admin act.
- IDEs can sign in to the gateway's MCP endpoint with standard OAuth.

**Costs and limits**
- **Notifications:** Slack/Email notification *dispatch* on approval events is not wired yet; the channels exist, and `notify()` and test-connection work.
- **Device revocation:** there is no self-service device revocation API.
- **Invited people:** they get a temporary password with no forced change.
- **CIMD fetches:** they use the connector SSRF client; no CIMD caching policy beyond the clients table.
- **Codex `.codex/config.toml`:** edited with a marked block, not a TOML parser.
- **Clock:** the GitHub App JWT is untested against live GitHub (mocked conversion and `/app`).
- **First protected PR:** the onboarding step "first protected PR" waits for C3.
