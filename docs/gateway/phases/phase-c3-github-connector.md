# C3: GitHub through the gateway, server-side submits, the "AgentGuard evidence" check

Status: implemented 2026-11-18 (mocked GitHub; the live path is described, not run) · ADR: [0036](../adr/0036-c3-github-connector-evidence-check.md) · Owner steps: [github-app-setup.md](../github-app-setup.md) · Not committed (the owner commits).

Any MCP-capable agent or IDE does its Git and GitHub work through seven gateway dev-tools:
- agents never hold a GitHub credential;
- the gateway applies their changes server-side and pushes them with the App's installation token;
- a check run, "AgentGuard evidence", passes only when every commit on the PR was pushed by the gateway and its evidence verifies.

A ruleset that requires that check (owner step §3) makes GitHub refuse any other merge.

## 1. What changed

| Area | Change |
|---|---|
| GitHub package | `agw_gateway/github/`:<br>- `client.py`: App JWT → repo-scoped installation token (memory only), `SafeHttp`, repo allowlist, branch rules<br>- `gitops.py`: index-only apply of diff or bundle on a fresh clone; path, symlink, submodule and size refusals; token only through `GIT_CONFIG_*` env<br>- `actions.py`: the seven actions, C1 assessment of the full diff, the submit flow, the PR body template<br>- `checks.py`: check evaluation and publishing, webhook (HMAC, dedupe), polling, tamper flip + comment, connector health |
| Connector framework | `Assessment`: a pre-decision content inspection (floor, deny, rule ids, facts, approver role, `critical_approval`). `ActionManifest` gains `reversible`, `environments` and `proposed`. Connector types may `assess`. `ExecContext` carries tenant, connector, action, run, agent and engine. |
| Policy engine | ReasonCode `CONNECTOR_CONTENT_DENIED`. Content rule ids are added to the decision. A connector critical exception turns the implicit default-deny into REQUIRE_APPROVAL (rule `CX-CRITICAL-EXCEPTION`); explicit DENY still wins. |
| Pipeline | `_evaluate` runs the assessor, applies the floor and records the assessment facts in the intent. Approvals route to the assessment's role. Execution re-assesses and fails if the result is stricter (`CHANGE_REASSESSED_STRICTER`). |
| MCP | Built-in connector types expose their trusted manifest description, which steers agents to `git_submit_change` instead of `git push`. `tools/call` uses the action's environment. |
| Worker | Periodic `poll_once` (`AGW_GITHUB_POLL_SECONDS`, default 60). `Monitor.on_report` hook → re-evaluate PRs on TAMPERED/INCOMPLETE and comment once. |
| API | `POST /v1/webhooks/github/{id}`, `POST /v1/connectors/{id}/classify-proposed`, `GET /v1/connectors/{id}/github`, `GET /v1/dashboard/runs/{id}/prs`. The onboarding step "First protected pull request" is now real: done after the first PR whose check passed. |
| Schema | Migration **0013**: `github_commits` (append-only trigger), `github_prs`, `github_deliveries`, `github_tamper_notices`, with grants. |
| Dashboard | A PullRequestsCard on the run and action pages. A GitHub status card on the connector page (installation, repos, mode, recent deliveries, PRs). An "Accept proposed classification" form. Check statuses in `lib/status.ts`. OpenAPI and types regenerated. |
| Image | `infra/docker/gateway/Dockerfile` installs `git`. The pinned base had none, so server-side submits could not have run in the container. Verified: `git version 2.47.3` in the rebuilt base stage. |
| Tests | `unit/test_gitops.py` (19), `e2e/test_github.py` (6), `e2e/test_github_live.py` (1, skipped unless `AGW_GITHUB_LIVE=1`), `tests/githubkit.py` (local bare repos + stateful fake GitHub API), `c3_mutation_check.py` (11) and `make c3-mutations`. |
| Docs | `github-app-setup.md` (owner steps), ADR-0036, this file, 11 §5.10, the coding-agents.md §6 note, README and ADR indexes. |

## 2. Doc mapping

| Prompt topic | Repository doc |
|---|---|
| GitHub App setup | `docs/gateway/github-app-setup.md` (new) |
| policy / C1 rules | 04, ADR-0026, ADR-0034, `coding/policies/coding-mintrail-v1.toml` |
| connectors, MCP endpoint | ADR-0035 |
| evidence, epochs, anchors, monitor | 05, 06, 09, ADR-0028, Phase 9 |
| `~/projects/agentguard/*` | `~/Desktop/*`. The answer key was never opened. MintRail was not read or modified in C3; the tests use a synthetic MintRail-shaped repository. |

## 3. Work done and evidence

| Check | Command | Result |
|---|---|---|
| Change application: rename, delete, binary, new file, bundle, conflict, traversal, `.git` paths, escaping and absolute symlinks, in-repo symlink, submodule, large blob, crafted `.GIT` tree in a bundle, bundle not on base, garbage, token only in env, C1 rules on the full diff | `pytest apps/gateway/tests/unit/test_gitops.py` | `19 passed` |
| Mocked end-to-end:<br>- token flow and repo scoping, token canary (logs, evidence, API)<br>- every action<br>- full flow → check success; manual push → failure "not recorded by AgentGuard"<br>- HIGH (`ledger/**` → ledger lead) and CRITICAL (CI → two security approvers, four-eyes); approval/digest binding<br>- content denies<br>- branch name, issue mismatch, protected branch, non-fast-forward, traversal<br>- failure matrix, fork, forged webhook, dedupe, polling<br>- tamper → flip + one comment<br>- a commit listing shorter than the PR's commit count → failure<br>- run PRs, MCP dev-tools and descriptions | `pytest apps/gateway/tests/e2e/test_github.py` | `6 passed` |
| Live (flagged) | `AGW_GITHUB_LIVE=1 pytest …/test_github_live.py` | not run (needs the owner's App); skipped without the flag |
| Guards can fail | `make c3-mutations` | `11/11` caught; files restored byte-identical |
| Lint / types / layering | `ruff check .`, `ruff format --check .`, `mypy apps/gateway/src`, `lint-imports` | clean; 130 files; 9 contracts kept |
| Full suite + gates | `make test` | `1265 passed, 1 skipped, 1 deselected`, exit 0; gated 92 %; risk 100 % |
| OpenAPI drift + dashboard types | `make dashboard-check` | exit 0 |
| Dashboard e2e | `make dashboard-e2e` | `27 passed`, exit 0 (migration 0013 applied to the compose database first with `make migrate`) |

**Found by tests and mutations, then fixed:**
- **Submits scored HIGH.** The risk engine scored every submit HIGH: write + external + prod. The actions are now declared `dev` and reversible (ADR-0036 §6).
- **CRITICAL hit default-deny.** A CRITICAL diff hit default-deny instead of asking for approval. Fixed by the connector critical exception (§7).
- **Dedupe used `rowcount`.** `rowcount` is unreliable with `ON CONFLICT DO NOTHING`, so webhook dedupe and the tamper notice now use `RETURNING`.
- **Polling leaked across tests.** Polling picked up other tests' connectors; fixtures now disable their connector on teardown.
- **Mutations missed three guards on the first run.** The protected-branch, repo-allowlist and `_safe_path` checks were each shadowed by another layer (the branch pattern, the fake's 404, `git apply`'s own refusals). Tests were added that reach each guard directly.

## 4. Decisions (details in ADR-0036)

1. **The classification is a proposal until an admin accepts it** (step-up, a new version, evidence). Until then every GitHub action is denied.
2. **Server-side, index-only git.** No checkout, hooks, filters or global config. The token is passed as an env-only `http.extraHeader`.
3. **C1 rules run on the full combined diff before the decision.** The approval is bound to the action digest, which covers the change. Execution re-assesses the change.
4. **The check is fail-closed.** Missing seal or verification → `in_progress`. Anything unrecorded or unverifiable → `failure`, naming the commit or rule.
5. **The actions are declared `environment: dev`, reversible.** Risk comes from the content, not from "prod".
6. **Mocks:** a stateful `httpx.MockTransport` fake and local bare repositories, not respx (not a dependency). `AGW_GITHUB_CLONE_ROOT` is dev/test only.

## 5. Gaps and limitations

1. **Live GitHub was not exercised.** No App exists yet. The live test and the owner steps are written but have not been run.
2. **Merge enforcement depends on the owner's ruleset** (github-app-setup.md §3). On a personal repository the owner can still push directly; the check then fails, but nothing stops the push.
3. **The check needs an independent monitor report.** With the default monitor interval, a PR can sit at `in_progress` for minutes after the epoch is sealed.
4. **Repository scope.** One installation (the first id) per connector. A connector has a single repository list; repos in other installations are not supported.
5. **Commit cap.** GitHub lists at most 250 commits of a PR. Larger PRs (and any listing shorter than the PR's commit count) fail with "could not all be listed". The fix for this was found while writing this section: the first version read one page of 100 and would have passed a hand-pushed 101st commit. A test and a mutation now cover it.
6. **Images.** The dashboard, compose images and the running stack need `make rebuild` to pick up `git` in the image.
7. **Dashboard.** The new GitHub cards have no dedicated Playwright test; they are covered by type checks and the gateway e2e only.
