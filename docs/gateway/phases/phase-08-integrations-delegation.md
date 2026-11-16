# Phase 8: Agent integrations + delegation

Status: implemented 2026-11-16 · ADR: [0030](../adr/0030-phase8-delegation-integrations.md) · Not committed (the owner commits).

## 1. What changed

| Area | Change |
|---|---|
| Delegation (`agw_gateway/delegation/`) | `token.py` is the Ed25519 / canonical-CBOR token codec. `constraint.py` is the pure chain result the policy engine reads. `service.py` issues, revokes, resolves (whole chain against the DB), consumes uses per link and rechecks. |
| Policy / risk | Pure system DENYs: `DELEGATION_*` failure codes, `DELEGATION_SCOPE_MISSING`, `DELEGATION_TOOL_NOT_ALLOWED`, and a final `DELEGATION_RISK_EXCEEDED`. The risk factor `delegation_depth` gets the verified depth (`DELEGATION_VERIFIED`). |
| Action service | `delegation: {token}` (exclusive with the declared depth). Resolve, then evaluate, then consume uses in tx1 (a lost race re-evaluates once). `actions.delegation_id`. ACTION_REQUESTED header `delegation` + `refs.parent`. Payload `delegation {id, chain, depth, declared_by: gateway}`. `context.via` for MCP calls. |
| Approvals / executor | The approval binding includes `{id, th}`. Authorization re-resolves the chain and re-evaluates. The executor rechecks the chain before dispatch (`DELEGATION_INVALID`, no adapter call). |
| Evidence | New types DELEGATION_CREATED and DELEGATION_REVOKED (A2A). Header keys `delegation` and `refs`. Violation kind `DELEGATION_REFUSED`. The verifier allows the `delegation` key. |
| Auth | `agent_credentials.audience` (audience-bound keys are refused by the gateway API). `integration_clients` (`agwi_…`). RFC 8693 `POST /v1/oauth/token` gives `exchanged_tokens` (`agwx_…`, ≤ 15 min, tied to the subject key). |
| API | `POST /v1/delegations`, `/{id}/revoke`, `GET /{id}/timeline`, `GET /v1/delegation-signing-keys`, `POST /v1/oauth/token`. The run timeline shows `delegation`/`refs`. |
| Real adapters | `public_api_get` (allowlisted read, no redirects, size cap, body digest) and `send_email_smtp` (approval always, domain allowlist, header-injection guard, relay secret in the gateway only). `public_doc_search` hits gain `uri`, `sha256` and `excerpt`. |
| SDK (`agw_sdk`) | `call()` uses one idempotency key per logical call with retries, waits for approval, and maps outcomes to typed exceptions. `delegate` / `revoke_delegation` / `delegation_timeline`. Per-request auth (an injected client is never mutated). |
| `integrations/langgraph` | `agw_langgraph`: gateway tools as `StructuredTool`s through the SDK, errors-not-fake-success, provenance tracking. |
| `integrations/mcp` | `agw_mcp`: low-level MCP Server (SDK 2.3.0, spec 2026-07-28, Streamable HTTP), per-agent `tools/list`, resource server + RFC 9728 metadata, token exchange, `agw_action_status`, CLI `agw-mcp`. |
| Examples | `examples/agentlib` (provider-neutral LLM: deterministic `MockLLM` + `AnthropicLLM`; LangGraph graph; MCP-backed tools; multi-agent scenario; injection harness). `examples/single-agent/llm_agent.py`. `examples/multi-agent/{run.py,verify_offline.py}`. `examples/injection/corpus` (13 docs). `examples/containment/` (compose, probe, run.sh). |
| Infra | `infra/docker/gateway/Dockerfile` (gateway / agent targets, bases pinned by digest), `entrypoint.sh`, `.dockerignore`. Mailpit added to the root compose (pinned by digest). |
| Migration | `0009_phase8_delegation`. |
| Tooling | Make targets `containment`, `injection-corpus`, `delegation-mutations`, `integration-latency`, `dev-delegation-key`. `make lint` mypy-checks the integrations. Coverage gate adds delegation, auth, SDK, LangGraph and MCP. Two new import-linter contracts. |
| Docs | ADR-0030. Updates to 03 (T26–T28), 05 (types, header keys), 06 (three tags), 11 (endpoints, tables), 13 (note), README, ADR index. |

## 2. Decisions (details in ADR-0030)
1. **Token format.** Gateway-signed Ed25519 over canonical CBOR, not Biscuit: we want every hop recorded and central revocation and use counts, not holder-side attenuation. The DB row is authoritative, and the signature makes forgery fail before the lookup.
2. **Intersection.** Effective permission = the child's own scopes ∩ every link ∩ every issuer's CURRENT scopes. A delegation constrains and attributes; it never grants.
3. **Rechecks.** Revalidated at request, approval authorization and dispatch. Revocation cascades through descendants without rewriting them.
4. **Uses.** Consumed on every link, in tx1, with a DB CHECK. DENIED requests consume nothing.
5. **Refusals are evidence.** A refused delegation request is recorded as a SECURITY_VIOLATION (`DELEGATION_REFUSED`); authority checks run first.
6. **MCP authorization.** The adapter accepts only audience-bound tokens and exchanges them at the issuer (RFC 8693) for separate short-lived gateway tokens. No passthrough in either direction.
7. **Adapter registration.** Real adapters are registered only when configured. Their allowlists live in arg validation (a DENY is recorded before any I/O) and are checked again in the adapter.
8. **Deliberately gullible mock.** The mock LLM follows injected `ACTION:` lines, so injection runs are reproducible; the gateway is what is being tested.

## 3. Work done: required tests

| Requirement | Test(s) | Result |
|---|---|---|
| Child requests a scope the parent lacks → DENY | `test_parent_cannot_delegate_a_scope_it_lacks` (issue: 403 + SECURITY_VIOLATION), `test_child_using_a_scope_the_chain_lacks_is_denied` (use: `DELEGATION_SCOPE_MISSING`, adapter 0), `test_tool_outside_allowlist_and_risk_above_cap_denied`, `test_subdelegation_can_only_narrow` | pass |
| Expired / revoked / over-used token → DENY | `test_expired_token_denied`, `test_revoked_token_denied_and_revocation_recorded`, `test_over_used_token_denied`, `test_concurrent_over_use_never_exceeds_max_uses` (12 concurrent requests with max 3: exactly 3 allowed, `uses = 3`) | pass |
| Token tampering / forged signature → DENY | `test_tampered_and_forged_tokens_denied` (5 forgeries: widened claims with the old signature, re-signed by an attacker key, flipped signature bit, re-signed by the real key with widened scopes, garbage), `test_token_presented_by_another_agent_denied`, unit `test_delegation_units.py` (18) | pass |
| Depth > limit → DENY | `test_depth_limit_at_issue_and_at_use` (depth 3 refused at issue; lowering the limit kills an existing depth-2 token) | pass |
| Parent scope reduced → child loses it immediately | `test_parent_scope_reduced_child_loses_it_immediately` (the next request is DENIED; 2 already-AUTHORIZED actions are FAILED `DELEGATION_INVALID` before dispatch; adapter 0), `test_root_revocation_cascades_to_subdelegation`, `test_revocation_while_pending_approval_blocks_authorization` | pass |
| Full multi-agent run → parent/child links; bundles verify | `test_multi_agent.py::...[sdk]` and `[mcp]`: DELEGATION_CREATED in the planner run, child requests hash-linked (`refs.parent`), the planner's timeline view, one human approval, every event's bundle VERIFIED against roots anchored on Anvil; `test_evidence_links_child_actions_to_the_delegation` | pass |
| Agent container cannot reach tool endpoints | `test_containment.py` / `make containment` (slow, real Docker networks) | pass, §5 |
| Injection corpus (≥ 10) → 0 unauthorized executions | `test_prompt_injection.py`: 13 docs × 2 modes = 26 runs | **0** executions, §5 |
| MCP conformance against the SDK's client | `test_mcp_adapter.py` (6): the SDK client negotiates `2026-07-28`; 401 + `resource_metadata`; RFC 9728 document; audience enforcement both ways; per-agent `tools/list`; COMPLETED / DENIED / PENDING_APPROVAL → approve → `agw_action_status`; delegation via header; key revocation stops the agent at once | pass |

Also tested:
- SDK (`test_sdk.py`, 10): a lost response after send gets 2 retries with the same key, giving 1 action and 1 adapter call; approval waiting; reject/expire mapping; `ToolFailed` on a revoked delegation; provenance sources; no credential in `repr`.
- External adapters (`test_external_adapters.py`, 11): metadata-IP / off-allowlist / userinfo / file URLs DENIED with no request made; redirect not followed; size cap; SMTP approval then delivery to Mailpit; relay password absent from responses, logs and `repr`; domain and CR/LF injection DENIED.

**Mutation check** (`make delegation-mutations`): **25/25** caught. The first run caught 22; the 3 survivors were defense in depth (two independent checks per attack). I sharpened the tests (a forged token that reuses a real id; the signature mutation runs against its unit test; the redundant child-binding checks are mutated together). Results: `experiments/delegation/results/mutations.txt`.

## 4. Acceptance
Two agents delegate a permitted task through LangGraph and through MCP; the email step is approved by a human; every resulting event verifies offline against anchored roots. In `make demo` (live stack: gateway, worker, agw-mcp, Anvil, Mailpit):
```
planner -> DELEGATION_CREATED … depth=1 tools=['create_ticket', 'send_email_smtp'] max_risk=HIGH uses=3
human sees: tool=send_email_smtp risk=HIGH agent=demo-worker delegation_depth=1
MULTI-AGENT (sdk) OK
MULTI-AGENT (mcp) OK
SMTP sink received 2 approved email(s) from the gateway
exported 38 bundles from 2 multi-agent runs
MULTI-AGENT OFFLINE VERIFICATION OK (38/38 VERIFIED)
```
The offline step runs after the gateway and worker are stopped: operator export, then `agw-verify event --trust-config pinned-trust.json` against the chain. The full excerpt, including the planner's delegation timeline with `delegation.ev` and `refs.parent` links, is in `experiments/integrations/results/demo-phase8.txt`.

## 5. Measurements
**Integration effort and added latency** (`make integration-latency`, `experiments/integrations/results/latency.md`): N = 60 per path, localhost, Postgres in Docker.

| path | median ms | p95 ms |
|---|---|---|
| direct adapter (no gateway) | 0.09 | 0.21 |
| SDK, decision only (POST → committed decision + evidence) | 14.72 | 26.62 |
| SDK, full call (incl. execution + result long-poll) | 309.6 | 351.6 |
| LangGraph tool → SDK | 305.7 | 426.7 |
| MCP client → agw-mcp → SDK | 321.1 | 360.6 |

Enforcement plus evidence adds about 15 ms. A full call is dominated by the 0.25 s server re-check interval of the result long-poll. LangGraph adds nothing measurable; MCP adds about 12 ms (one HTTP hop + token-exchange cache).

LOC (code lines excluding docstrings/comments, and total): agw_sdk client + errors 330 / 442; agw_langgraph 122 / 161; agw_mcp 253 / 316; example glue (graph + multi-agent) 224 / 281.

**Injection corpus** (`experiments/injection/results/injection-table.md`):
- **Delegated mode:** every attempt was blocked by the delegation (`DELEGATION_SCOPE_MISSING`), by arg validation (allowlist / schema), by an approval no human gave, or by 403s for agent-id spoofing, self-approval and delegation escalation. Each refusal is a SECURITY_VIOLATION.
- **Direct mode:** blocked by policy and risk (`CRITICAL_DENIED`, `RISK_RULE_DENY`, …).
- **Unauthorized executions:** 0 of 26 runs.
- **Provenance:** every tool attempt's ACTION_REQUESTED carries the injected document's SHA-256.

**Containment** (`make containment`): from inside the agent container:
- `gateway:8080` CONNECTED.
- mailpit, public-api and postgres: `NO_DNS` by name and unreachable by IP; the gateway's toolnet IP is unreachable too.
- 1.1.1.1 and 8.8.8.8 are unreachable, and a public hostname gets `NO_DNS`.
- No credential env vars; `/creds` holds only the agent's own key.
- Through the gateway, `public_api_get` COMPLETED and `delete_record` was DENIED.

## 6. Commands run (clean state)
`make down`, then `.env` refreshed from `.env.example` (it differed only by the new Phase 8 line), then `.venv` removed, then `make up && make migrate && make test && make demo`:
- migrations 0001 → 0009; ruff clean; mypy: no issues in 118 source files; import-linter 8 contracts kept;
- **813 passed** (1 deselected: the slow containment test); coverage 89% overall, gated 92%, risk 100%;
- the first demo run failed at `MULTI-AGENT (mcp)`. The mock worker stopped polling `agw_action_status` when it saw `DISPATCHED` (it only polled on `PENDING_APPROVAL`), so the timeline was read before ACTION_COMPLETED. The mock now polls every non-final status (`examples/agentlib/llm.py`). This was a race in the example agent, not the gateway. `make demo` was rerun on the same clean stack: exit 0, all phases OK, `MULTI-AGENT OFFLINE VERIFICATION OK (38/38 VERIFIED)`.

Also: `make vectors` exit 0; `make verify-isolated` OK (no new verifier dependencies); `make containment` exit 0 (`experiments/integrations/results/containment-probe.json`); `make injection-corpus` 0/26; `make delegation-mutations` 25/25.

## 7. Known gaps
- **MCP onboarding.** The gateway is the authorization server but has no interactive OAuth code + PKCE flow or RFC 8414 metadata; MCP tokens are provisioned by the operator. The token endpoint uses Bearer client auth and our error body.
- **Containment is a deployment control.** It fails against host or daemon compromise, extra network routes, or tool credentials leaked elsewhere (03 R3).
- **Injection of allowed actions.** An injection that asks for an action the agent may legitimately do is not blocked by policy. An injected agent can also delegate scopes it legitimately holds; those delegations are recorded and still bound by policy.
- **Delegation constrains only.** A child must hold scopes itself. A "borrow the parent's authority" model is not implemented.
- **Key rotation.** Rotating the delegation signing key invalidates every outstanding token.
- **A2A content.** The A2A message (the token handoff) is not itself evidence; the delegation is.
- **Not built.** Monitoring and the `_monitor` stream (roadmap row 8) remain unbuilt.
- **Long-poll latency.** The 0.25 s re-check dominates a full call; a notify-based wakeup would cut it.
