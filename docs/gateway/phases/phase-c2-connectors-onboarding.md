# C2: Connectors, Integrations page, `agw login` / `init` / `doctor`

Status: implemented 2026-11-18 · ADR: [0035](../adr/0035-c2-connectors-enrollment-mcp-auth.md) · Agent reference: [coding-agents.md](../coding-agents.md) §6 · Not committed (the owner commits).

An admin adds connectors from the Integrations page. A developer runs `agw login` and `agw init`, and the repository's coding agents are wired to AgentGuard. Adding a connector never weakens policy:
- its actions start unclassified and denied;
- classification is a risk floor (the risk engine can still raise it);
- repositories can only tighten their policy;
- every loosening is a step-up, evidenced admin decision.

## 1. What changed

| Area | Change |
|---|---|
| Connector framework | `agw_gateway/connectors/`:<br>- `manifest` (types, input-schema subset, classification documents)<br>- `constraint` (pure, consumed by the policy engine)<br>- `tools` (per-tenant dynamic tool source `cx_<slug>_<action>`, tool version = classification version)<br>- `service` (CRUD, sealed credentials, classify, rotate, disable, delete, health, GitHub flow)<br>- `ssrf` (`SafeHttp`)<br>- `types/` (github, agent clients ×7, slack, email, http_api, mcp_upstream, anchoring) |
| Pipeline | `ToolRegistry(dynamic=…)` and tenant-aware `resolve`/`get_any`. `EvaluationInput.connector` adds system DENYs and the approval rule "always". Approvals go to the classified role. Approval revalidation uses the current classification. |
| Identity | `enrollment.py`: RFC 8628 device code. `mcp_remote/oauth.py`: OAuth AS (PRM, AS metadata, DCR, CIMD, PKCE S256, `resource` binding, `iss`, rotating refresh). `mcp_remote/server.py`: remote MCP endpoint, 2026-07-28 + legacy. |
| Repos | `coding/repos.py`: registration, tighten-only `.agentguard.yaml` overlay, proposals. `CodingPolicy.with_overlay`. |
| API | `api/c2_routes.py`, `api/mcp_routes.py`; people invite; onboarding checklist. Coding, C2 and consent routes added to the OpenAPI contract; dashboard types regenerated. |
| Schema | Migration **0012**:<br>- tables: `connectors`, `connector_actions`, `connector_policies` (append-only), `connector_health`, `device_enrollments`, `oauth_*`, `repos`, `repo_policies` (append-only), `repo_proposals`, `github_manifest_states`<br>- SECURITY DEFINER `agw_enroll_device` and `agw_invite_human`<br>- events `CONNECTOR_*` ×6, `DEVICE_ENROLLED`, `REPO_POLICY_CHANGED`<br>Header maps `connector`, `device` and `repo` (the verifier allowlist is updated). |
| CLI | `agw login` / `logout` (keychain or 0600 file), `agw init`, `agw doctor`, `agw uninstall`. Modules: `keystore`, `detect`, `wiring`. |
| Dashboard | Pages `/integrations` (catalog, installed), `/integrations/new` (configure, test, classify, review), `/integrations/[id]` (masked config, Rotate, health, actions, usage, evidence), `/repos` (proposals with diff), `/people` (invite, temporary password shown once), `/enroll`, `/oauth/consent`. Overview onboarding checklist. All mutations go through `guarded` route handlers. CSP: `form-action` adds `https://github.com` on `/integrations/*` only (GitHub App manifest POST). The consent hand-off is a no-script page with its own `default-src 'none'` CSP. |
| Tests | Gateway: `test_connectors.py` (8), `test_c2_identity.py` (7), `test_repo_policy.py` (2), `test_c2_cli_e2e.py` (1), `unit/test_ssrf.py` (32). CLI: `test_agw_cli_init.py` (23, including 18 golden files). Dashboard: `e2e/integrations.spec.ts` (9), and a11y over 10 more screens in light and dark. Mutations: `c2_mutation_check.py` (13). |
| Docs | ADR-0035, this file, 11 §5.9, coding-agents.md §6, README and ADR indexes |

## 2. Doc mapping

| Prompt topic | Repository doc |
|---|---|
| policy | 04, ADR-0026, ADR-0034 |
| approvals | ADR-0027 |
| privacy/encryption | 07, ADR-0029 |
| dashboard design | 16, ADR-0033 |
| coding-agents.md | coding-agents.md (C1) |
| `apps/gateway/connectors/` | `apps/gateway/src/agw_gateway/connectors/` |
| `~/projects/agentguard/*` | `~/Desktop/*`. The answer key was never opened. MintRail was only read (`git ls-files` for the fixture); its 52 pre-existing uncommitted changes are untouched. |

## 3. Work done and evidence

| Check | Command | Result |
|---|---|---|
| Connector invariants (unclassified denied, write-only canary, admin + step-up + evidence, versions, MCP upstream, HTTP SSRF settings, GitHub flow, catalog) | `pytest apps/gateway/tests/e2e/test_connectors.py` | `8 passed` |
| Device code, runtime-role limits, people/onboarding, OAuth (PKCE, single-use, refresh reuse, audience), MCP endpoint (both eras, headers, tools) | `pytest apps/gateway/tests/e2e/test_c2_identity.py` | `7 passed` |
| `.agentguard.yaml` tighten-only, proposals, admin decision | `pytest apps/gateway/tests/e2e/test_repo_policy.py` | `2 passed` |
| SSRF (private/metadata/mapped IPs, rebinding, pinning, redirects, schemes, allowlist) | `pytest apps/gateway/tests/unit/test_ssrf.py` | `32 passed` |
| `agw init` goldens (MintRail skeleton, Python repo, empty repo × 6 agents), dry run, idempotency, user content kept, uninstall exact | `make coding-cli` | `103 passed` (all CLI tests) |
| **Acceptance:** `agw login` (approved in parallel), `agw init --dry-run` on the MintRail skeleton shows files and tiers and writes nothing, `agw init` registers, `agw doctor` reports per-agent tiers | `pytest apps/gateway/tests/e2e/test_c2_cli_e2e.py` | `1 passed` |
| Real MintRail copy (rsync to scratch without node_modules/.env) | `agw init --dry-run` | pnpm, typescript, CODEOWNERS; installed claude_code/cursor/antigravity → enforced/hooked/mcp_only; 7 files to create |
| Guards can fail | `make c2-mutations` | `13/13` caught; files restored byte-identical |
| Full suite + gates | `make test` | `1240 passed, 1 deselected`, exit 0; gated 92 %; risk 100 % |
| Dashboard e2e (real gateway, production build) | `make dashboard-e2e` | `27 passed` (18 existing + 9 new, a11y light/dark), exit 0 |
| Drift / types / deps | `make dashboard-check`; `npm audit` | exit 0; 0 vulnerabilities |

**Found by tests and fixed:**
- The connector detail's evidence list compared the id without dashes, so it was always empty (found by the dashboard work; a gateway assertion was added).
- Device `slow_down` polls, refresh-reuse revocation and failed code redemptions were rolled back when the error was raised inside the transaction. They are now committed before the error is returned.

## 4. Decisions (details in ADR-0035)

1. **Classification is a floor, not a ceiling.** The admin's chosen risk is the tool's base risk, and the risk engine may raise it. For example, a Slack post classified LOW is still HIGH, an irreversible external write, so it needs approval.
2. **Connector tools are not mirrored into `tool_registry`.** That table's key is not tenant-scoped; `connector_actions` and `connector_policies` are the record.
3. **MCP endpoint: dual era.** It serves 2026-07-28 (stateless, `server/discover`) and legacy `initialize` on one endpoint, because clients still ship the older revision.
4. **Tool descriptions sent to MCP clients are written by the gateway.** An upstream's untrusted description never reaches the client's model.
5. **Runtime role.** It still has no INSERT on `agents` or `humans`. Two narrow SECURITY DEFINER functions are the only paths.
6. **Failed redemptions burn the code.** A failed OAuth code redemption, and a refresh-token reuse, change state BEFORE the error is returned. Tests caught that raising inside the transaction would roll this back.

## 5. Gaps and limitations

1. **Notifications.** Slack/Email notification dispatch on approval and security events is not wired. The channels, `notify()` and test-connection exist.
2. **Device revocation.** There is no self-service revocation; logout only removes the local key. Invited people get a temporary password with no forced change.
3. **Live services.** GitHub (conversion, `/app`, installation) and Slack are tested against mocks only; no live GitHub App was created.
4. **VS Code / Antigravity** are `mcp_only`: their hook systems exist (C1 note), but no adapters are built.
5. **"First protected pull request"** waits for C3 (GitHub actions).
6. **Codex `config.toml`** is edited with a marked block, not a TOML parser.
7. **Dashboard gaps:**
   - The GitHub manifest/install flow and the MCP-upstream / HTTP-API create paths have no Playwright coverage (they need github.com or a real upstream).
   - The constraints editor is missing; existing per-argument constraints are carried through unchanged.
   - No test checks that untrusted MCP descriptions render escaped. They are React text only.
   - `docs/gateway/16-dashboard-design.md` has no new screenshots.
