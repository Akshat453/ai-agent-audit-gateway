# ADR-0034: C1 coding-agent integration API, coding risk policy, `agw` CLI
Status: Accepted · Date: 2026-11-18 · Deciders: C1 implementation (pending owner review)

## Context
The C1 prompt asks for one vendor-neutral API that any coding agent asks before each action:
Claude Code, Codex, Cursor, Gemini CLI, and MCP-only IDEs. It also asks for:
- a coding-specific deterministic risk policy for the MintRail repository;
- Phase 5 approvals routed by path owner;
- an `agw` CLI with one adapter per agent that fails closed;
- the same rate limits, evidence and monitoring as every other gateway action.

**The prompt and reality disagree here:**

1. **Paths.** The prompt names `~/projects/agentguard/{ai-agent-audit-gateway,MintRail,mintrail-private}`. They are at `~/Desktop/…`. The answer-key directory was never opened. The policy denies reads of `**/mintrail-private/**` wherever it is.
2. **Doc names.** The prompt's "risk/policy, approvals, event schema, privacy/encryption, MCP adapter" docs map as follows:

   | Prompt topic | Actual doc |
   |---|---|
   | risk/policy | 04 + ADR-0026 |
   | approvals | 04 §5 + ADR-0027 (there is no separate approvals doc) |
   | event schema | 05 |
   | privacy/encryption | 07 + ADR-0029 |
   | MCP adapter | ADR-0030 + phases/phase-08 |

3. **MintRail paths.** `api/src/payments/**`, `api/src/refunds/**`, `api/src/auth/**` and `packages/shared/src/money/**` **do not exist** in MintRail. The real files are:
   - `api/src/services/{payments,refunds,dashboard-auth}.ts`
   - `api/src/schema/{payments,refunds}.ts`
   - `api/src/{keys,scopes,signing}.ts`
   - `packages/shared/src/{money,signatures}.ts`

   The webhook verifier is `signal/src/verify.ts`. Nothing matches `signal/**/sign*` today.
4. **"MCP-only IDEs".** The current docs show pre-tool hooks for VS Code / Copilot agent mode and for Antigravity (coding-agents.md §1). C1 builds the `mcp_generic` adapter it asks for. Native adapters for those two IDEs are left for later.
5. **Native "ask".** Codex and Gemini CLI have no ask. Cursor has ask only for shell and MCP. Where an ask exists, it is a *local* prompt.

## Decision

### 1. A coding action is an ordinary gateway action
- **Tool id.** It is `coding.<action_type>` (version `1`), environment `dev`, with run id = coding session id.
- **One transaction.** `actions` + `coding_actions` (+ `approvals`), then ACTION_REQUESTED, POLICY_EVALUATED, and ACTION_AUTHORIZED | ACTION_DENIED | APPROVAL_REQUIRED.
- **Nothing is dispatched.** The agent executes the action on the developer's machine.
- **Post-action.** `observe` writes ACTION_COMPLETED / ACTION_FAILED (actor = agent), with the exit code, result digest and files touched.
- **Unauthorized runs.** A report of something never authorized is a SECURITY_VIOLATION `CODING_UNDECIDED_ACTION` (new `violation.kind`).
- **Reuse.** Rate limits, chain, sealing, anchoring and the monitor are reused unchanged.
- **No new event types**, so the verifier is unchanged.

### 2. Normalized model `agw.coding-action/1`
- **Model.** A Pydantic model in `agw_gateway/coding/model.py`. Its JSON Schema is committed at `packages/schemas/coding/coding-action-v1.schema.json` (drift test).
- **Validation.** The CLI's output is validated against that file, so the CLI imports nothing from the gateway.
- **Diffs.** File contents never travel. Writes carry a diff:
  - it is evaluated by the content rules;
  - it is stored only in the encrypted ACTION_REQUESTED payload (Phase 7);
  - it is not stored at all when the secret scanner fires.
- **Headers carry digests.** Code provenance extends the existing `code` map with optional keys `kind`, `repo` (SHA-256 of the remote URL; the URL is in the payload), `head` (git sha) and `diff` (SHA-256). These are keys inside an existing map, the precedent being ADR-0026's `risk`. Every non-coding record is unchanged, and the verifier checks top-level keys only.
- **Context provenance.** The session's issue (`issue:#N` + text digest) goes in the payload sources.
- **Delegation.** The payload `delegation` says developer (human) → agent, asserted by the gateway.

### 3. Identity: per-developer device keys
- **Device keys are agent credentials.** A device key is an ordinary agent credential (`agw_…`, Bearer) with the single scope `coding:device`, so it cannot call any gateway tool. `coding_devices` binds it to a human, the developer.
- **The developer is never taken from a request.**
- **Issuing keys.** Keys are issued by an admin: `python -m agw_gateway.admin create-device-key`, or `make device-key`.
- **Session ownership.** Sessions belong to one device; others get 404. A session declares the agent kind, and a later action with a different kind is denied (`CODE-SESSION-MISMATCH`).

### 4. Coding policy (`coding-mintrail` v1)
- **Two parts.** A versioned TOML file holds the lists. Pure modules hold the rules: `policy`, `commands`, `content`, `globs`, `rules`. The import-linter contract that forbids I/O and LLMs now covers them.
- **Digest.** `SHA-256(TAG("AGW/coding-policy/v1") || file bytes)` is recorded in POLICY_EVALUATED (`risk.cv = coding-policy-v1`) and bound into approvals.
- **Combination.** deny > ask > allow, and the level is the maximum over all hits. Mandatory rules (secrets, denied commands, content rules) are denies. Unknown action types, unparseable commands and anything an adapter marked `incomplete` ask; nothing unknown is allowed.
- **Headers carry rule ids only, never reason text.** A reason may name a path.
- **Additions to the prompt's lists**, all stricter except one:
  - the real MintRail paths (§Context 3);
  - other `package.json` edits are HIGH;
  - CRITICAL for `GEMINI.md`, `.cursorrules`, `.agents/**`, `.husky/**`, `.git/**` and writes outside the workspace;
  - removing test cases → ask CRITICAL;
  - GitHub MCP push tools → deny, read-only GitHub MCP → allow;
  - harmless read-only commands (`pwd`, `wc`, `find` without `-exec`).
- **The one narrowing:** `id_*` is applied to extension-less key names and `*.pub`, so `id_mapper.ts` is not a secret. `.env.example`, `.env.sample` and `.env.template` are readable.

### 5. Approvals: routed, waited for, consumed by the identical retry
- **Routing.** "ask" creates a Phase 5 approval with `required_role`:
  - CRITICAL → `security`;
  - `ledger/**` → `ledger_lead`;
  - otherwise `maintainer`.

  These three roles are new. Migration 0011 widens the `humans.roles` and `approvals.required_role` CHECKs. Deciding requires the routed role (`human.has(ap.required_role)`). Signature validation counts only approvers holding that role. Existing approvals keep `approver`, so their behaviour is unchanged.
- **Unchanged from Phase 5.** CRITICAL still needs two distinct approvers (four-eyes) and a recent step-up.
- **What the approval is bound to.** The coding action digest:

  ```
  SHA-256(TAG("AGW/coding-action/v1") || cbor({v, tenant, device, developer, session, kind,
         type, normalized targets, content digests, policy id, version, digest, level}))
  ```

  The git HEAD is recorded but not bound.
- **Where approval ends.** For a `coding.*` action, `ApprovalService.authorize` stops at APPROVED (`NOOP AWAITING_AGENT_RETRY`); the sweeper skips such rows.
- **Consuming the approval.** The agent's next decide with the **same digest** in the same session goes through `ApprovalService.consume_for_retry`. Under the same lock order (approval → action → chain head) it checks:
  - APPROVED and unexpired (DB clock);
  - same tenant;
  - action still pending;
  - enough valid signed decisions by the routed role;
  - the digest equals both stored digests;
  - the device is still active.

  Then it inserts `approval_uses(nonce)` (single use is a primary key), sets CONSUMED, writes POLICY_EVALUATED + ACTION_AUTHORIZED, and returns **allow**.
- **Retries in other states:**
  - a retry while PENDING returns the same ask (no new rows);
  - after REJECTED → deny;
  - after CONSUMED or EXPIRED → a new action and a new approval;
  - any change (diff, target, command, a new policy version) → a different digest → a new approval.
- **The waiting hook** polls `GET /v1/coding/actions/{id}?wait=` for up to `approval_wait_seconds` (default 90). It always stops 15 s before the agent's hook timeout. If no approval arrives, it blocks with `Approval pending: <link>. Retry after approval.`
- **What the approver sees.** While pending, the exact normalized action and diff are sealed in `actions.request_args_sealed` (KEK envelope, as in Phase 5/7), so `GET /v1/approvals/{id}` shows them. The seal is cleared when the approval closes.
- **The native ask is never used.** It would let the developer approve their own agent.

### 6. `agw` CLI (`packages/agw-cli`)
- **Packaging.** Standard library only: `pipx install ./packages/agw-cli`. An import-linter contract forbids the gateway apps, the workspace packages, httpx, requests and pydantic.
- **Layout.** One module per subcommand (`hook`, `status`, `session`; C2 adds more). A shared `config` holds the device key file (mode 600 enforced) and the env/TOML settings. Adapters sit behind a registry, each with an `AgentSpec` (events, timeout unit, config locations, managed config) for C2 to generate configuration.
- **Fail closed.**
  - The client turns every unusable answer into `GatewayUnavailable`: connection errors, timeouts, non-JSON, unexpected 4xx/5xx, and a schema-invalid decision.
  - The hook turns that, missing config, an unreadable payload or any exception into the agent's native **deny** with `AgentGuard unavailable - action blocked`.
  - Top-level crashes exit 2, which blocks in every agent.
  - Post and session events never block.
- **Allow output.** For Claude Code an allow prints nothing (the agent's own permission flow continues); `AGW_ALLOW_MODE=explicit` prints `permissionDecision: "allow"` instead.

### 7. Proposed doc changes (made in this phase)
- **New docs.** coding-agents.md (the capability table, reused later), this ADR, `phases/phase-c1-coding-agent-api.md`, and the 11 §5.8 endpoint section.
- **Small notes.** 04 (the coding policy is a separate policy family), 05 (`code` map keys, `violation.kind`).
- **The prompt's "MCP-only IDEs" wording** should become "IDEs whose hooks are not yet supported (VS Code agent mode, Antigravity: hooks exist, adapters pending)".

## Consequences
**Gains**
- Every coding agent's actions produce the same tamper-evident evidence as any other agent action.
- Approvals are routed, single-use and bound to the exact diff.
- Every MintRail trap in the 191-case table (27 named traps) is caught. Eleven guard mutations are each caught by a named test.

**Costs and limits** (coding-agents.md §5)
- The hook is client-side. Whether it is mandatory depends on each vendor's managed-settings support; Gemini CLI has none, and Cursor's is undocumented.
- Codex and Gemini fail open on a killed hook.
- Content rules are regular expressions, not semantics.
- Actions taken outside hooked tools are invisible; only an observed but undecided action is flagged.
- The dashboard shows coding approvals through the existing views. Dashboard deciding is still gated on the `approver` role; deciding for `security`, `ledger_lead` or `maintainer` is through the API / `agw-approve` until the dashboard's role checks are widened (Part B).
