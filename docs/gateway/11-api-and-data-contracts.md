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

*(Phase 4)* `GET /v1/approvals?status=pending`, `POST /v1/approvals/{id}:grant|:deny`
(human auth), `POST /v1/actions/{id}:reconcile`. *(Phase 3)* `GET /v1/events/{seq}/proof`.
*(Phase 7)* `POST /v1/exports` (bundle). *(Phase 10)* MCP adapter front-end.

## 6. Database contracts

Exact Phase 1 tables: [14-phase-1-handoff.md §3](14-phase-1-handoff.md). Later additions:
`epoch_heads`, `epochs`, `anchors` (Phase 3/6), `approvals`, `approval_uses` (Phase 4),
`evidence_payloads`, `payload_keys` (Phase 5). Evidence tables (`evidence_events`, `policies`,
`evidence_payloads`) are append-only (08 §2).
