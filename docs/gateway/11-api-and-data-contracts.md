# 11 — API and Data Contracts

Status: Accepted (Phase 0). Phase 1 implements §1–§6. Later phases add endpoints marked
*(Phase N)*. ADR: 0015 (agent auth).

## 1. General

- Base path `/v1`. JSON request/response bodies, `application/json; charset=utf-8`.
- Every response carries `X-Request-Id` (server-generated UUIDv7, echoed into logs).
- Times are RFC 3339 UTC with `Z`. IDs are UUID strings.
- Unknown request fields → `422` (envelope models use `extra="forbid"`). Note that invalid
  **tool args** are not a 422. They are a recorded DENY (§5.1).

## 2. Uniform error model

```json
{ "error": { "code": "IDEMPOTENCY_KEY_REUSED", "message": "Idempotency-Key was used with a different request body.", "request_id": "0193…" } }
```

| HTTP | `code` | When |
|---|---|---|
| 400 | `IDEMPOTENCY_KEY_MISSING` / `IDEMPOTENCY_KEY_INVALID` | header absent / malformed |
| 401 | `UNAUTHENTICATED` | missing, malformed, unknown, revoked or expired key (same code for all, no oracle) |
| 403 | `AGENT_ID_MISMATCH` | body `agent_id` ≠ authenticated agent (also recorded as `SECURITY_VIOLATION`) |
| 404 | `NOT_FOUND` | resource absent **or** owned by another agent (no existence oracle) |
| 409 | `IDEMPOTENCY_KEY_REUSED` | same key, different fingerprint |
| 413 | `PAYLOAD_TOO_LARGE` | body > 256 KiB |
| 422 | `REQUEST_INVALID` | envelope schema violation (field *names* only, never values) |
| 503 | `DEPENDENCY_UNAVAILABLE` | DB (or later KEK) unavailable. Nothing executed. |
| 500 | `INTERNAL` | unexpected. No details. |

Rules: `message` is a fixed string per code. Tool args, arg values, API keys and payloads are
**never** included in errors or logs. Logging uses an allow-list of fields: request_id,
agent_id, tenant_id, tool_id, action_id, decision, status, error code, latency. A Phase 1 test
captures logs during a denied request containing a canary arg value and asserts the canary is
absent.

## 3. Authentication (Phase 1; ADR-0015)

- Header: `Authorization: Bearer agw_<key_id>_<secret>`. `key_id` is 16 hex chars (public
  lookup handle). `secret` is 43 chars base64url (32 random bytes).
- Stored: `agent_credentials.key_id` (unique), `key_digest = H(TAG("AGW/apikey/v1") ‖ utf8(full_token))`.
  The plaintext is shown once at creation. A fast hash is appropriate because the secret has
  256 bits of entropy (no dictionary attack). A slow KDF would add latency without security.
- Verification: parse → look up by `key_id` → `hmac.compare_digest(stored, computed)`. If the
  `key_id` is unknown, still compute a digest and compare against a dummy, so timing doesn't
  reveal which ids exist. Check `revoked_at IS NULL`, `expires_at > now()` and agent `status = active`.
- Result: `AuthenticatedAgent{tenant_id, agent_id, scopes}`. **This is the only source of agent
  identity.** If a body contains `agent_id` and it differs → 403 + `SECURITY_VIOLATION` event
  (`violation.kind = AGENT_ID_MISMATCH`, `violation.claimed` = the claimed id), and nothing else
  is processed.
- Later: mTLS client certs or OIDC workload identity (Phase 10+). The `AuthenticatedAgent`
  contract stays the same.

## 4. Tool registry contract (Phase 1)

```python
class ToolSpec(BaseModel, frozen=True):
    tool_id: str                       # ^[a-z][a-z0-9_]{1,63}$
    version: str                       # semver
    operation_type: Literal["read","create","update","delete","execute"]
    sensitivity: Literal["public","internal","confidential","restricted"]
    base_risk: Literal["LOW","MEDIUM","HIGH","CRITICAL"]
    environments_allowed: frozenset[Literal["dev","staging","prod"]]
    required_scope: str                # e.g. "tools:public_doc_search"
    is_idempotent: bool
    external_effect: bool
    target_field: str | None           # arg naming the target resource (approval binding)
    tags: frozenset[str] = frozenset() # e.g. {"privilege_change"}
    args_model: type[BaseModel]        # model_config = ConfigDict(extra="forbid", strict=True)
    adapter: type[ToolAdapter]

class ToolAdapter(Protocol):
    def execute(self, args: BaseModel, ctx: ExecutionContext) -> ToolResult: ...
    # Phase 4 optional: def probe(self, action_id: UUID) -> ProbeResult
```

Tools are registered **in code**. At startup the registry is synced into `tool_registry`
(insert-if-absent, keyed on `(tool_id, version)`; a changed spec for an existing version is a
startup error). Only `(tool_id, version)` pairs present in both code and table are callable.

## 5. Endpoints (Phase 1)

### 5.1 `POST /v1/actions`

Headers: `Authorization`, `Idempotency-Key` (required).

```json
{
  "run_id": "0193d0c2-…",            // client-chosen UUID grouping a run
  "tool": "create_ticket",
  "tool_version": "1.0.0",            // optional; default = the single enabled version, else 422
  "environment": "dev",
  "args": { "title": "…", "body": "…" },
  "agent_id": "…",                    // optional; if present MUST equal the authenticated agent
  "intent": { "summary": "…" },        // optional, ≤ 1 KiB, stored in payload only
  "context": { "sources": [ { "uri": "…", "sha256": "…" } ] }   // optional
}
```

Response `201 Created` (first time) or `200 OK` + `Idempotent-Replayed: true` (replay):

```json
{
  "action_id": "0193…",
  "status": "AUTHORIZED",             // DENIED | PENDING_APPROVAL | AUTHORIZED (executor proceeds async)
  "decision": {
    "effect": "ALLOW",
    "policy_id": "default", "policy_version": 1,
    "matched_rule_ids": ["allow-medium-ticket"],
    "reasons": [],
    "risk_level": "MEDIUM"
  },
  "links": { "self": "/v1/actions/0193…", "timeline": "/v1/runs/0193d0c2-…/timeline" }
}
```

A DENY is a successful evaluation: `201` with `status: "DENIED"` and reason codes (04 §3). The
denial is evidence, so it is persisted, never executed, and never a 4xx.

### 5.2 `GET /v1/actions/{action_id}`

Only the owning agent. Returns `status`, `decision`, timestamps and `result` (adapter's
`ToolResult.public` part, if COMPLETED) or `error_code`. Raw args are not returned.

### 5.3 `GET /v1/tools`

Returns only tools the authenticated agent may call: registered, enabled, `required_scope` in
the agent's scopes. Each entry gives `tool_id, version, operation_type, environments_allowed,
args_schema` (JSON Schema from the Pydantic model).

### 5.4 `GET /v1/runs/{run_id}/timeline`

Events for actions with this `run_id` **owned by the authenticated agent**, ordered by `seq`:
`[{seq, event_id, type, occurred_at, action_id, tool, decision?, status?, reasons?}]`.
Payload content (args, results) is omitted.

### 5.5 `GET /v1/health` → `200 {"status":"ok"}` (process liveness, no DB).
### 5.6 `GET /v1/ready` → `200 {"status":"ready"}` if `SELECT 1` as `agw_app` succeeds, else `503`.

### 5.7 Later

*(Phase 5, implemented, ADR-0027)* human auth `POST /v1/auth/login` / `POST /v1/auth/logout`
(`Authorization: Session <token>`); `GET /v1/approvals?state=PENDING`,
`GET /v1/approvals/{id}` (exact tool, args rendered safely, target, risk reasons,
`action_digest`, `nonce`), `POST /v1/approvals/{id}/decision {decision, reason,
action_digest, nonce}` (the echo must match), `GET /v1/approvals-signing-keys`;
`GET /v1/actions/{id}?wait=N` long-poll. Agent keys on these endpoints → 403
`AGENT_NOT_PERMITTED` + SECURITY_VIOLATION. *(Later)* `POST /v1/actions/{id}:reconcile`. *(Phase 3)* `GET /v1/events/{seq}/proof`.
*(Phase 7)* `POST /v1/exports` (bundle). *(Phase 10)* MCP adapter front-end.
*(Phase 6)* The `GET /v1/epochs/{n|latest}` and `GET /v1/events/{id}/proof` responses gain an optional, **untrusted** `anchor` claim: `{chain_id, contract, recorder_id, epoch_no, status, tx_hash, block_number}` (bundle schema updated). Verifiers compare it with their pins and never take trust roots from it. Operator CLI `python -m agw_worker.anchoring.admin` (`recorder-id`, `deploy`, `record-deployment`, `register`, `trust-config`). `agw-verify event|epochs --chain-rpc URL --trust-config pinned.json` (exit 5 = UNTRUSTED_ANCHOR).

### 5.8 Coding-agent API (C1, implemented, ADR-0034)

Callers use a **device key**: an agent credential with only the `coding:device` scope, bound to a developer in `coding_devices`, sent as `Authorization: Bearer agw_…`.
- Any other credential gets 403 `CODING_DEVICE_REQUIRED`.
- Body and rate limits are the global ones.
- The `agw` CLI (`packages/agw-cli`) is the reference client; the agent capability table is in [coding-agents.md](coding-agents.md).

| Endpoint | Body → response |
|---|---|
| `POST /v1/coding/sessions` | `{agent_kind, agent_version?, native_session_id?, repo?{remote_url, head_sha}, workspace_root?, issue?{number, text_sha256}}` → 201 `{session_id, run_id}` (the same id; it is the evidence run) |
| `POST /v1/coding/decide` | `{session_id, action: agw.coding-action/1, diff?, correlation_id?}` → `{decision: allow\|deny\|ask, reason, rule_ids, risk_level, action_id, status, action_digest, policy{id,version}, approval?{approval_id, state, required_role, required_approvals, expires_at, link}}`. An identical `ask` while pending returns the same approval; after approval the identical retry consumes it and returns `allow`; after rejection, `deny`. 409 `CODING_SESSION_CLOSED`; 413 if the diff exceeds `AGW_CODING_MAX_DIFF_BYTES` |
| `GET /v1/coding/actions/{id}?wait=N` | `{action_id, status, risk_level, approval_state}`. Long-polls until the status or approval state changes (owner device only, else 404) |
| `POST /v1/coding/observe` | `{session_id, action_id? \| correlation_id?, action_type?, success, exit_code?, result_sha256?, files_touched[], duration_ms?}` → 202 `{recorded: COMPLETED\|FAILED\|duplicate\|violation}`. Anything not AUTHORIZED gives `violation`: a SECURITY_VIOLATION `CODING_UNDECIDED_ACTION` |
| `POST /v1/coding/sessions/{id}/end` | → `{session_id, status: ENDED, actions{status: n}}` |
| `GET /v1/coding/status` | `{tenant, device{id,label}, developer, open_sessions, policy{id, version, digest}}` |

**Settings:** `AGW_CODING_POLICY_FILE` (default: the bundled `coding-mintrail` v1), `AGW_CODING_DASHBOARD_URL` (approval links) and `AGW_CODING_MAX_DIFF_BYTES`.

**Tables** (migration 0011): `coding_devices`, `coding_sessions`, `coding_actions`; `agw_app` gets SELECT/INSERT plus column-level UPDATE only. The approving roles `security`, `ledger_lead` and `maintainer` are added.

### 5.9 C2: connectors, enrollment, repos, MCP (implemented, ADR-0035)

**Human session endpoints** (admin with a recent step-up for every change):

| Endpoint | Purpose |
|---|---|
| `GET /v1/connectors/catalog` | the types: manifests, config schema, credential field names, setup/tier |
| `GET /v1/connectors` · `POST /v1/connectors` | list (admin/auditor/security) · add `{type_id, slug, name, config, credentials}` (credentials are write-only) |
| `GET /v1/connectors/{id}` · `PATCH` · `DELETE` | detail (credentials only as `{fields, set, version}`), update name/config, delete (sealed credentials destroyed) |
| `POST …/{id}/test` · `/classify` · `/rotate` · `/disable` · `/enable` | health check (and discovery for MCP upstreams); `{actions:{name: classification\|null}}` creates a new policy version; rotate credentials |
| `POST …/{id}/github/manifest` · `/github/install`; `GET /v1/connectors/github/manifest-callback` · `/setup-callback` | GitHub App manifest + install flow (single-use state) |
| `GET /v1/repos` · `POST /v1/repos/proposals/{id}/decision` | repositories, overlays, pending `.agentguard.yaml` proposals with diff; approve/reject |
| `GET /v1/people` · `POST /v1/people` | list · invite (temporary password shown once) |
| `GET /v1/onboarding` | the new-tenant checklist |
| `GET /v1/device/requests/{user_code}` · `POST …/decision` | approve or deny a device enrollment |
| `GET` / `POST /v1/oauth/consent` | MCP OAuth consent (the dashboard page) |

**Device-key endpoints:** `POST /v1/coding/repos` (register + `.agentguard.yaml` text) and `GET /v1/coding/repos/status?remote_url=`.

**Public endpoints:**
- `POST /v1/device/authorize` and `POST /v1/device/token` (RFC 8628 errors as `{"error": …}`/400);
- `/.well-known/oauth-protected-resource[/mcp]` and `/.well-known/oauth-authorization-server`;
- `POST /oauth/register` (DCR), `GET /oauth/authorize`, `POST /oauth/token` and `POST /oauth/revoke`;
- `POST /mcp` (Bearer `agwm_…`; MCP 2026-07-28 + legacy). GET and DELETE on `/mcp` return 405.

**Connector actions** are called like any tool: `POST /v1/actions {tool: "cx_<slug>_<action>", …}`.

**Settings:** `AGW_PUBLIC_URL`, `AGW_DEVICE_CODE_TTL_SECONDS`, `AGW_MCP_ACCESS_TOKEN_TTL_SECONDS` and `AGW_MCP_REFRESH_TOKEN_TTL_SECONDS`.

### 5.10 C3: GitHub dev-tools and the evidence check (implemented, ADR-0036)

**Connector actions** (`cx_<slug>_<action>`, device key or MCP; `environment: "dev"`):

| Action | Arguments (all take optional `repo` = one of the connector's repos) | Proposed |
|---|---|---|
| `github_issue_get` · `github_issue_list` | `number` · `state`, `labels`, `per_page` | LOW |
| `github_issue_comment` | `number`, `body` | MEDIUM |
| `git_submit_change` | `session_id`, `issue_number`, `branch` (`fix\|feat/MR-<issue>-<slug>`), `base_sha`, `commit_message`, `change_format` (`diff`\|`bundle`), `change` (base64) | MEDIUM; raised by content (C1 rules) |
| `github_pr_create` | `branch`, `title`, `issue_number`, optional `base`, `draft`; the body is the gateway's evidence template | MEDIUM |
| `github_pr_comment` · `github_pr_status` | `number`, `body` · `number` | MEDIUM · LOW |

`git_submit_change` returns `{branch, head_sha, tree_sha, commits, diff_digest, files}`; `github_pr_create` returns `{number, html_url, check}`; `github_pr_status` returns `{number, state, merged, head_sha, check, summary}`.

**Human session endpoints:**

| Endpoint | Purpose |
|---|---|
| `POST /v1/connectors/{id}/classify-proposed` | admin + step-up: accept the manifest proposals as a new classification version |
| `GET /v1/connectors/{id}/github` | installation ids, repos, mode, recent deliveries (event, action, verified, outcome, time) and tracked PRs |
| `GET /v1/dashboard/runs/{run_id}/prs` | PRs opened in a run, with check conclusion and link |

**Public endpoint:** `POST /v1/webhooks/github/{connector_id}`. It is authenticated only by `X-Hub-Signature-256`: 401 on a bad or missing signature, 200 "duplicate delivery" on a repeated `X-GitHub-Delivery`, 202 with the evaluation result otherwise.

**Tables** (migration 0013): `github_commits` (append-only), `github_prs`, `github_deliveries`, `github_tamper_notices`.

**Settings:** `AGW_GITHUB_POLL_SECONDS` (default 60). `AGW_GITHUB_CLONE_ROOT` (local bare repos instead of github.com) is honoured only when `AGW_ENV` is dev or test, and ignored otherwise.

### 5.11 Self-service sign-up (dev/test only)

Public:
- `GET /v1/auth/signup` → `{"enabled": bool}`.
- `POST /v1/auth/signup {organization, tenant, username, password}` → 201 with the same session fields as login, plus `tenant` and `username`.

Behaviour:
- It creates a **new** tenant (genesis chain and epoch heads) and its first human, with roles admin, approver, auditor, maintainer and security, through the SECURITY DEFINER `agw_signup_tenant` (migration 0014). The runtime role still has no INSERT on `tenants` or `humans`.
- An existing tenant id gets 409, and nothing changes.
- Rules: tenant id `^[a-z0-9][a-z0-9-]{2,62}$`, username `^[a-z0-9][a-z0-9._-]{0,63}$`, password 12–1024 characters. Violations get 422 with field names only.
- Off by default (404). `AGW_SIGNUP_ENABLED=true` is refused outside dev/test.

The compose `ui` profile enables it. Its `ui-provision` service registers each new tenant's anchoring recorder on the local Anvil contract. `AGW_UI_SEED_DEMO=0` starts the stack without the demo tenant. Dashboard: `/signup`, linked from `/login` when enabled.

### 5.12 Plain-English console additions (read-only, ADR-0039)
- `GET /v1/dashboard/rule-descriptions` (any signed-in human):
  - `{rules: {id: {name, why}}, patterns: {"PREFIX*": {name, why}}, policies: [{policy_id, versions}]}`;
  - `{suffix}` in a pattern's `why` is the matched rest of the id.
- `GET /v1/dashboard/actions/{id}` adds:
  - `coding` (`action_type`, `target` = redacted paths / command / argv / url / query / mcp tool, or `null` if not recorded, `diff` = `{files, added, removed}`, `session_id`);
  - `session` (`agent_kind`, `agent_version`, `developer`, `device`, `repo`, `repo_url`, `issue_number`, `status`, `started_at`, `ended_at`);
  - `approvals[].decisions` (`approver` username, `decision`, `decided_at`);
  - `events[].rules`.
- `GET /v1/dashboard/runs` adds `session` and `decisions` (counts per decision).
- `GET /v1/dashboard/runs/{id}` adds `session`, `coding` (per action id) and `people` (approver id → username).
- `GET /v1/dashboard/approvals` rows add `action_type`, `target` (one line), `agent_kind` and `issue_number`.
- **Never returned:** file contents or diffs (counts only), or secret values (replaced by `[REDACTED]` before storage).

### 5.13 Repository scope (read-only, ADR-0040)
- **Optional `repo_id` (UUID)** on `GET /v1/dashboard/runs`, `/approvals`, `/events`, `/incidents`, `/activity` and `/overview`: only runs whose coding session was started in that repository.
- **Tenant-scoped:** another tenant's id matches nothing.
- **Incidents:** monitor alerts are tenant-wide and stay.
- **`GET /v1/dashboard/repo-choices`** (any signed-in human): `[{repo_id, name, sessions}]`.
- **Run detail:** `events[].rules` lists the matched rule ids from the sealed record.

## 6. Database contracts

Exact Phase 1 tables: [14-phase-1-handoff.md §3](14-phase-1-handoff.md). Later additions:
`epoch_heads`, `epochs` (Phase 3), `anchors` and `anchor_recorders` (Phase 6, migration 0006, ADR-0028 §4), `humans`, `human_sessions`, `approvals`,
`approval_decisions`, `approval_uses`, `approval_signing_keys` (Phase 5, migration 0005),
`evidence_payloads` (Phase 2 ledger; plaintext `content` dropped by migration 0008),
`payload_objects`, `payload_keys`, `tenant_redaction_keys`, `auditor_keys`,
`disclosure_grants`, `retention_policies`, `legal_holds` (Phase 7, migration 0007; ADR-0029).
*(Phase 7 endpoints)*
- `POST /v1/auditor-keys`
- `POST /v1/disclosures`
- `POST /v1/disclosures/{id}/revoke`
- `POST /v1/disclosures/{id}/export`
- `GET /v1/auth/me`

All human sessions only; an agent key gets 403 AGENT_NOT_PERMITTED.

*(Phase 8, ADR-0030; agent credentials)* `POST /v1/delegations {child_agent_id, scopes, tools,
max_risk_level, expires_at, max_uses, purpose, parent_token?, run_id?}` -> token (once);
`POST /v1/delegations/{id}/revoke`; `GET /v1/delegations/{id}/timeline`;
`GET /v1/delegation-signing-keys`. `POST /v1/actions` accepts `delegation: {token}` (exclusive
with the Phase 4 declared `depth`). `POST /v1/oauth/token` (RFC 8693 token exchange; integration
client credential `agwi_…`): exchanges an agent key bound to an MCP adapter's audience for a
short-lived `agwx_…` gateway token. The gateway API refuses audience-bound keys (401).
Tables (migration 0009): `delegations`, `delegation_signing_keys`, `integration_clients`,
`exchanged_tokens`; `actions.delegation_id`, `agent_credentials.audience`.

*(Phase 9, ADR-0031; human sessions)* `GET /v1/dashboard/{config, overview, runs, runs/{id},
events, events/{id}/bundle, epochs, policies, incidents, incidents/export, verifications,
verifications/{id}, alerts}` (tenant-scoped; never payloads; bundles/exports and
`POST /v1/dashboard/verifications` need auditor/admin), `POST /v1/actions/{id}/reconcile`
(admin; OUTCOME_UNKNOWN only), `POST /v1/auth/step-up` (CRITICAL approvals need a step-up
within 300 s, else 403 STEP_UP_REQUIRED). OpenAPI: `python -m agw_gateway.openapi` (not served).
Tables (migration 0010): `monitor_reports`, `monitor_alerts`, `monitor_requests`;
`human_sessions.stepped_up_at`; reserved tenant `_monitor`. Evidence tables (`evidence_events`, `policies`,
`evidence_payloads`) are append-only (08 §2).
