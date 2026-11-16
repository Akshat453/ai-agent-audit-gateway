# ADR-0030: Phase 8 delegation tokens, agent integrations (SDK, LangGraph, MCP), real adapters, containment
Status: Accepted · Date: 2026-11-16 · Deciders: Phase 8 implementation (pending owner review)

## Context
The Phase 8 prompt asks for four things:
- a typed agent SDK;
- gateway-signed delegation tokens, with effective permission as the intersection of the chain, revalidated at use, and DELEGATION_CREATED evidence;
- LangGraph and MCP adapters, plus single- and multi-agent examples;
- one read-only and one approved-write real adapter, a containment demo and a prompt-injection corpus.

The core must not depend on any agent framework.

**Docs and the prompt disagree here:**
1. **Missing doc.** The prompt says to read `01-system-boundaries.md`. No such file exists: 01 is the source analysis. Boundaries are in 02 §1/§7, 03 assumption 4 and R3, and I used those.
2. **Event name.** 05 §3 names the event `DELEGATION_ISSUED` (Phase 10). The prompt calls it DELEGATION_CREATED, and that name is used; `DELEGATION_ISSUED` was never written. DELEGATION_REVOKED is added.
3. **Header shape.** 05 §4 puts delegation provenance in the payload (`{"from","parent","scope"}`). This phase adds a top-level header map `delegation` and writes the already-specified `refs.parent`. That is the same kind of v1 addition ADR-0029 made with `disclosure`/`erasure`: no v1 record ever used these keys, the verifier's key allowlist gains `delegation`, and `refs` was already allowed.
4. **Roadmap.** The roadmap puts delegation tokens and the MCP front-end in Phase 10 and "experiments + monitoring" in Phase 8. The prompts are the schedule (as in Phases 4–7). Monitoring and the `_monitor` stream are still not built.
5. **MCP spec revision.** I checked the current spec before writing the adapter. It is **2026-07-28**: stateless requests, `server/discover`, `Mcp-Method` headers. The Python SDK is **2.3.0** (`mcp.server.Server` with `on_list_tools`/`on_call_tool`, `mcp.Client`, `httpx2`). Neither matches older memory; the adapter is built on what the installed SDK actually provides.

## Decision

### 1. Token format: Ed25519 over compact deterministic CBOR (not Biscuit)
```
agwd1.<b64url(claims_cbor)>.<b64url(sig)>
claims = {v:1, id, ten, iss, sub, dep, par?, sc[sorted], tl[sorted], mr, exp, mu, iat, kid}
sig    = Ed25519(delegation key, TAG("AGW/delegation-sig/v1") || claims_cbor)
th     = SHA-256(TAG("AGW/delegation-token/v1") || claims_cbor || sig)    (the token hash)
```
- **Strict parsing.** No padding variants, canonical CBOR (`encode(decode(x)) == x`), unknown claim keys rejected, length ≤ 4 KiB.
- **Parent link.** `par` is the parent token's hash, so a chain is hash-linked.
- **Why not Biscuit.** Its value is holder-side offline attenuation. We need the opposite: every hop recorded as evidence, use counts and revocation enforced centrally, and the CURRENT scopes of every issuer re-checked at use. A Datalog engine would add a dependency without removing the database lookup.
- **Signing key.** The key (`AGW_DELEGATION_SIGNING_KEY_FILE`) is separate from the approval key. Without it, issuing returns 503 and every presented token is DENIED `DELEGATION_INVALID` (fail closed).
- **Rotation.** Only the configured key verifies, so rotating it invalidates outstanding tokens (by design: they are short-lived).

### 2. Semantics: intersection, never expansion, revalidated at every use
**The database is authoritative.** A token is valid only if all of these hold:
- the signature verifies;
- its hash equals the stored row's;
- `sub` is the authenticated agent;
- for every link root → leaf: not revoked, not expired (DB clock), not exhausted, every issuer active in the same tenant, chain shape intact;
- depth ≤ `AGW_DELEGATION_MAX_DEPTH` (default 2).

**Effective permission** = the child's own scopes ∩ every link's scopes ∩ every issuer's current scopes. Tools are the ∩ of every link's allowlist; max risk is the minimum over the chain. Consequences:
- A child never gains a scope it lacks itself. A delegation constrains and attributes; it does not grant.
- Reducing a parent's scopes, or revoking any ancestor, takes effect on the child's next request.

**Issue time.**
- Scopes, tools, risk, expiry and uses can only narrow the parent's.
- Authority checks run first, so an escalation attempt is refused as `DELEGATION_EXCEEDS_PARENT`.
- Every refusal is recorded as SECURITY_VIOLATION `{kind: DELEGATION_REFUSED, claimed: <code>}`.

**Use is consumed on every link**, in tx1, with one conditional UPDATE and a `uses <= max_uses` CHECK. A lost race re-evaluates once and is DENIED `DELEGATION_EXHAUSTED`. DENIED requests consume nothing.

**Re-checked later as well:**
- At approval authorization, the chain is re-resolved and policy re-evaluated.
- Right before dispatch, a no-longer-covering chain gives ACTION_FAILED `DELEGATION_INVALID` with no adapter call.

**Policy engine.** It is still pure. A `DelegationConstraint` input adds these system DENYs: `DELEGATION_*` failure codes, `DELEGATION_SCOPE_MISSING` and `DELEGATION_TOOL_NOT_ALLOWED`. It also adds a final, non-overridable `DELEGATION_RISK_EXCEEDED`.

**Risk.** The risk factor `delegation_depth` uses the verified depth, with reason `DELEGATION_VERIFIED`. The agent-declared `delegation.depth` (Phase 4) still exists, but it is exclusive with a token (422).

**Approval binding.** `delegation_ref` = `{id, th, depth, declared_by: "gateway"}`.

### 3. Evidence (delegation provenance, Paper B field 8)
- **DELEGATION_CREATED (A2A)**
  - Header: `delegation {id, depth, th, from, to, sc, tl, mr, exp, mu, kid, par?, root?}`, `run` (the parent's run) and `refs.parent` (the parent delegation's DELEGATION_CREATED hash, for sub-delegations).
  - Payload: `{purpose}`, encrypted. Sealed promptly (risk level HIGH).
- **Child ACTION_REQUESTED**
  - Header: `delegation {id, depth, th, from, root, ev}` and `refs.parent = event_hash(DELEGATION_CREATED)`. The parent/child link is hash-bound, not just by id.
  - Payload: `delegation {id, chain[root..leaf], depth, declared_by: "gateway"}`.
- **DELEGATION_REVOKED (A2A)**: `delegation {id, depth, th}` and `refs.parent`.
- **Views.** `GET /v1/delegations/{id}/timeline` gives any issuer in the chain the delegation tree and every child event (no payloads). The run timeline shows `delegation`/`refs`.

### 4. Endpoints
`POST /v1/delegations` · `POST /v1/delegations/{id}/revoke` (any issuer in the chain) · `GET /v1/delegations/{id}/timeline` · `GET /v1/delegation-signing-keys` · `POST /v1/oauth/token` (§6). `POST /v1/actions` accepts `delegation: {token}`.

### 5. SDK and LangGraph
- **`agw_sdk.Client.call()`**
  - One Idempotency-Key per logical call, reused on every retry (transport errors, 502/503/504). A lost response can therefore never create a second action.
  - Long-polls through approvals.
  - Maps outcomes to `Denied`, `ApprovalRequired`, `ApprovalExpired`, `ToolFailed`, `OutcomeUnknown`, `StillRunning`.
  - Has delegate, revoke and timeline helpers. It holds no tool credentials, and an injected `http_client` is never modified.
- **`agw_langgraph`**
  - Gateway tools become `StructuredTool`s, so every invocation goes through `Client.call`.
  - Denials and pending approvals are tool ERRORS carrying the gateway status.
  - Digests of retrieved content (`results[].sha256`, `sha256`) are attached to later calls as `context.sources`.
- **Framework independence.** import-linter forbids `agw_gateway`/`agw_worker`/`agw_sdk` from importing LangGraph, LangChain, MCP or the integrations, and forbids the integrations from importing server internals.

### 6. MCP adapter (`agw_mcp`, spec 2026-07-28, Streamable HTTP)
- **Dynamic tools.** A low-level `mcp.server.Server`: `tools/list` returns exactly the authenticated agent's permitted tools (plus `agw_action_status`), and `tools/call` = `Client.call`.
- **Results.** COMPLETED gives `is_error=false` with structured content. DENIED / PENDING_APPROVAL / FAILED / OUTCOME_UNKNOWN give `is_error=true` with status, reasons and `action_id`.
- **Authorization.** The adapter is an OAuth resource server (SDK `RequireAuthMiddleware`): RFC 9728 metadata, 401 + `WWW-Authenticate: Bearer resource_metadata=…`, `validate_token_resource=True`.
  - **Audience.** It accepts only tokens issued FOR IT. An agent key has `agent_credentials.audience` = the adapter's canonical URI, and the gateway API refuses audience-bound keys, so neither kind of key works at the other.
  - **No passthrough.** The adapter validates a token at its issuer (the gateway) by RFC 8693 token exchange, authenticated as a registered integration client (`agwi_…`, bound to that audience). The exchange returns a separate gateway token (`agwx_…`, ≤ 15 min by CHECK) bound to the subject credential (revoking the agent's key kills it at once) and to the client (`context.via = "mcp:<name>"`). The client's MCP token is never used as an access token anywhere else.
  - **Delegation.** A delegation token travels in the `AGW-Delegation` header and the run id in `AGW-Run-Id`.
- **Deviations from the spec's flow.**
  - Tokens are provisioned out of band (`admin create-agent-key --audience`); the gateway does not run an interactive OAuth authorization-code + PKCE flow and publishes no RFC 8414 metadata.
  - The token endpoint uses Bearer client credentials and our uniform error body, not RFC 6749 form errors.
  - Both are follow-ups if third-party MCP clients must self-onboard.

### 7. Real adapters (registered only when configured; credentials only in the gateway)
- **`public_api_get` 1.0.0** (read, LOW)
  - Exact `host[:port]` allowlist, enforced in arg validation (a recorded DENY before any I/O) and again in the adapter.
  - https only, except `AGW_HTTP_ALLOW_PLAIN` hosts.
  - No redirects, no proxy env, a size cap, returns a body SHA-256.
- **`send_email_smtp` 1.0.0** (create, MEDIUM with `medium_effect = REQUIRE_APPROVAL`, external effect, irreversible)
  - Every send needs an approval.
  - Recipient-domain allowlist; CR/LF in the subject rejected.
  - The relay password is a gateway secret (`AGW_SMTP_PASSWORD[_FILE]`). Tested against Mailpit, pinned by digest.
- **`public_doc_search`** results gain `uri`, `sha256` and `excerpt`. The args schema is unchanged, so the registry spec is stable.

### 8. Prompt injection
The corpus has 13 documents, each run in 2 modes (delegated worker, and direct agent), with a deliberately gullible deterministic model that tries every embedded `ACTION:` instruction.
- **Expected outcome:** 0 unauthorized executions, every attempt recorded, and the source document's SHA-256 in the ACTION_REQUESTED context provenance.
- **Limit (stated):** an injection that asks for an action the agent IS allowed to perform (e.g. a ticket) is not blocked by policy. That is what approvals, tight delegations and review are for.

### 9. Containment
Docker networks are `internal: true`: agentnet (agent ↔ gateway), toolnet (gateway ↔ tools), dbnet (gateway ↔ Postgres). The agent container resolves and reaches only the gateway; tool containers, Postgres and the internet are unreachable by name and by IP. Only the gateway has the SMTP secret.

## Consequences
- **Delegation constrains, it does not grant.** Agents are provisioned with their own scopes, and a delegation narrows and attributes them. A design where a child borrows authority it lacks would need a new ADR.
- **No re-wrap for queued sealed args after rotation (unchanged).** Pending child actions are re-checked against the chain, but queued sealed args are not re-wrapped (Phase 7 limit).
- **Agents' own delegations.** An injected agent can still delegate scopes it legitimately holds to another agent (recorded as DELEGATION_CREATED); whatever is then done under that delegation is still bound by policy and approvals.
- **Containment is a deployment property**, not code. It does not hold against host compromise, a shared Docker daemon, other routes (VPN, sidecars) or credentials leaked elsewhere.
- **Added latency** (measured, `experiments/integrations/results/latency.md`): decision ~15 ms median. A full call (~300 ms) is dominated by the 0.25 s long-poll re-check.
