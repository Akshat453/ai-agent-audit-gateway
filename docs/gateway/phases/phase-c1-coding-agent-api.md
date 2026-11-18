# C1: Coding-agent integration API

Status: implemented 2026-11-18 · ADR: [0034](../adr/0034-c1-coding-agent-integration.md) · Agent reference: [coding-agents.md](../coding-agents.md) · Not committed (the owner commits).

Coding agents ask the gateway before each action through one vendor-neutral API: `allow`, `deny`, or `ask` a routed human. They then report what ran. The supported agents are Claude Code, Codex, Cursor, Gemini CLI, MCP through a filtering proxy, and a generic JSON protocol. A deterministic coding policy for MintRail decides. Each decision becomes ordinary gateway evidence: the hash chain, sealing, anchoring and the monitor all apply.

## 1. What changed

| Area | Change |
|---|---|
| Gateway | **`agw_gateway/coding/`**:<br>- `model` (`agw.coding-action/1`)<br>- pure `policy`, `commands` (shell parser), `content` (diff rules), `globs`, `rules`, `digest`<br>- `service` (sessions, decide, observe, end)<br>- `policies/coding-mintrail-v1.toml`<br>**`api/coding_routes.py`**: 6 endpoints (11 §5.8).<br>**Settings:** `AGW_CODING_POLICY_FILE`, `AGW_CODING_DASHBOARD_URL`, `AGW_CODING_MAX_DIFF_BYTES`. |
| Approvals | `NewApproval` takes a `role`. Deciding requires `ap.required_role`. Signature checks count only that role. `authorize()` leaves coding approvals APPROVED. The new `consume_for_retry` consumes them for the identical retry (ADR-0034 §5). For existing approvals `required_role` stays `approver`, so behaviour is unchanged. |
| Identity | New roles `security`, `ledger_lead`, `maintainer`. Device keys are agent credentials with the scope `coding:device`, bound to a developer in `coding_devices` (`admin create-device-key`, `make device-key`). |
| Schema | Migration **0011**: `coding_devices`, `coding_sessions`, `coding_actions`, and widened role CHECKs. Column-level grants only.<br>`agw_schemas`: optional `code.{kind, repo, head, diff}`; `violation.kind` `CODING_UNDECIDED_ACTION`.<br>Tags `AGW/coding-action/v1`, `AGW/coding-repo/v1`, `AGW/coding-policy/v1`. |
| CLI | **`packages/agw-cli`** (standard library only; `pipx install ./packages/agw-cli`):<br>- `agw hook | status | session start|end`<br>- adapters for `claude_code`, `codex`, `cursor`, `gemini_cli`, `mcp_generic`, `other` behind a registry; each carries an `AgentSpec` for C2 config generation<br>- fails closed |
| Schemas | `packages/schemas/coding/coding-action-v1.schema.json` (generated from the model; drift test). |
| Dashboard | Approval detail: `canDecide` uses the approval's `required_role`. The nav's approval viewers include the new roles. The gateway enforces the role either way. |
| Build | uv workspace member `agw-cli`. Import-linter: the CLI may not import any workspace package, httpx, pydantic or requests; the coding policy modules joined the "pure" contract. Makefile: `coding-policy`, `coding-cli`, `coding-mutations`, `device-key`. |
| Docs | coding-agents.md (capability table from the current vendor docs), ADR-0034, 11 §5.8, notes in 04 and 05, README and ADR indexes. |

## 2. Doc mapping (prompt topic → repository doc)

| Prompt | Repository |
|---|---|
| risk/policy | 04-risk-and-policy-design.md, ADR-0026 |
| approvals | 04 §5, ADR-0027 (no separate approvals doc exists) |
| event schema | 05-event-schema.md, ADR-0023 |
| privacy/encryption | 07-key-management-and-privacy.md, ADR-0029 |
| MCP adapter (Phase 8) | ADR-0030, phases/phase-08-integrations-delegation.md |
| `~/projects/agentguard/*` | `~/Desktop/{ai-agent-audit-gateway,MintRail}`. The answer key (`~/Desktop/mintrail-private`) was never opened |

## 3. Decisions

ADR-0034 records them in full. The main ones:

1. **No new event types.**
   - A coding action is `coding.<type>` on the normal lifecycle (AUTHORIZED → COMPLETED/FAILED, without DISPATCHED), so the independent verifier is unchanged.
   - Repo, HEAD and diff digests are optional keys inside the existing `code` map.
2. **Native "ask" is never emitted.** In every agent it is a local prompt, which would let the developer approve their own agent. The gateway ask is instead a routed approval:
   - the hook waits for it, up to 90 s and always below the agent's hook timeout;
   - the identical retry consumes it once;
   - if it is still pending, the hook blocks with `Approval pending: <link>. Retry after approval.`
3. **Claude Code allow prints nothing.** The agent's own permission rules still apply, because AgentGuard is necessary, not sufficient. `AGW_ALLOW_MODE=explicit` prints `permissionDecision: "allow"` instead.
4. **The policy is stricter than the prompt in places** (the full list is in ADR-0034 §4):
   - MintRail's real paths are added;
   - other `package.json` edits are HIGH;
   - writes outside the workspace and removed test cases are CRITICAL asks;
   - GitHub MCP push tools are denied.

   It is less strict in one place: `id_*` is applied to key-like names only, and `.env.example` is readable.
5. **Approval bindings.** CRITICAL keeps four-eyes and step-up (ADR-0027). An approval is bound to the coding action digest, which includes the policy version and diff but not the git HEAD.

## 4. Work done and evidence

All commands were run in this session.

| Check | Command | Result |
|---|---|---|
| Policy table (191 labeled actions: 44 allow / 61 ask / 86 deny; 27 named MintRail traps) | `make coding-policy` | `211 passed` (the table at 100 %, plus determinism, glob, normalisation, parser and schema-drift tests) |
| Adapter golden tests, tool vocabularies, fail-closed (no gateway) | `make coding-cli` | `80 passed` |
| Coding API e2e (real Postgres): allow/deny/ask, routing, wait/consume once/replay/changed action, reject, expiry, four-eyes CRITICAL, identity, canary | `uv run pytest apps/gateway/tests/e2e/test_coding_api.py` | `10 passed` |
| **Acceptance:** the `agw` binary (subprocess, real HTTP) against a live gateway, 6 agents × allow/deny/ask in native format; a human approval during the wait becomes allow; the session chain verified by `agw_verifier` | `uv run pytest apps/gateway/tests/e2e/test_coding_cli_e2e.py` | `8 passed` |
| Guards can fail | `make coding-mutations` | 11/11 guard removals caught by named tests; files restored byte-identical |
| Full suite + gates | `make test` (ruff, format, mypy 138 files, import-linter 9 contracts, pytest, coverage gates) | `1165 passed, 1 deselected`, exit 0. Gated packages 92 % (≥ 85); risk 100 %. Coding modules (not in the gate): `coding/service.py` 95 %, `coding/policy.py` 79 %. Afterwards `test_agw_cli_normalize.py` (2 tests, test-only) was added: `make coding-cli` 80 passed, ruff and format clean |
| Standalone install | `uv venv` + `uv pip install ./packages/agw-cli` (Python 3.12) | Only `agw-cli 0.1.0` installed; no gateway, httpx or pydantic importable; `agw hook` against a dead URL printed the Claude deny JSON |
| Dashboard drift + types | `make dashboard-check` | exit 0 |

**Bugs the tests found and fixed during the phase:**
- **A post-action report could pair with a newer pending retry** that reused the same `tool_use_id`, instead of the action that ran. `observe` now prefers the AUTHORIZED action.
- **Policy fixes:** `~/.ssh` as a directory is now secret, `dbPassword = "…"` is now caught, and `chmod -x` is no longer mistaken for a flag.

## 5. Limitations and gaps

These are given per agent in coding-agents.md §5.

1. **The hook is client-side.**
   - Making it mandatory needs vendor managed settings: Claude Code and Codex have them, Cursor has MDM (whether users can disable it is undocumented), and Gemini CLI has none.
   - Codex and Gemini CLI fail **open** when the hook process is killed or times out. The CLI catches its own errors and denies, but cannot prevent an external kill.
2. **Content rules are regular expressions.** An obfuscated bypass can evade them; the path-based HIGH/CRITICAL approvals are the backstop.
3. **Actions outside hooked tools are invisible.** A post report with no decision is flagged (`CODING_UNDECIDED_ACTION`).
4. **VS Code agent mode and Antigravity now have hook systems.** Native adapters for them are not built; `mcp_generic` needs a filtering proxy, which is not built either.
5. **Golden payloads.** Codex and Gemini docs give field tables but no verbatim pre-tool samples, so those golden payloads are built from the field tables (`packages/agw-cli/tests/golden/SOURCES.md`). No real agent binary was run in this phase.
6. **Recursive search over secrets.** `grep -r` / `rg` over a directory that contains `.env` is allowed (the operand is not a secret path). `rg` honours `.gitignore`; `grep -r` does not.
7. **C2 scope, not built:** `agw login`, `init`, `doctor` and `uninstall` (generated agent configs).
8. **Coding actions in the dashboard** are shown through the existing approval views, which have no coding-specific layout (Phase 9.5 Part B).
