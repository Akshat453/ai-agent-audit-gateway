# ADR-0036: C3 GitHub connector: gateway-only pushes, server-side change application, the "AgentGuard evidence" check
Status: Accepted · Date: 2026-11-18 · Deciders: C3 implementation (pending owner review)

## Context
C3 has three goals:
- every MCP-capable agent or IDE does its Git and GitHub work **only** through the gateway;
- agents never hold a GitHub credential;
- GitHub refuses a merge into `main` unless AgentGuard has verified evidence for every commit.

C2 (ADR-0035) already provides the GitHub connector type (App manifest and install flow, sealed credentials), the per-tenant remote MCP endpoint, device keys and the classification model.

**External facts** (docs.github.com, fetched 2026-11-18; owner steps in [github-app-setup.md](../github-app-setup.md)):
- App JWT: RS256, `iss` = client id (or app id), at most 10 minutes. `POST /app/installations/{id}/access_tokens` accepts `repositories` to narrow the token. Tokens expire after one hour.
- REST version header `X-GitHub-Api-Version: 2026-03-10`.
- Webhooks are signed with `X-Hub-Signature-256` (HMAC-SHA256 over the raw body). `X-GitHub-Delivery` is unique per delivery.
- Check runs: `POST /repos/{o}/{r}/check-runs`, then `PATCH` with `status`/`conclusion`. A ruleset's "required status checks" can pin the expected source App.
- `GET /repos/{o}/{r}/rules/branches/{branch}` returns the active rules for a branch, with Metadata read.

## Decisions

### 1. Seven dev-tool actions, proposed (not applied) classification
`github_issue_get`, `github_issue_list`, `github_issue_comment`, `git_submit_change`, `github_pr_create`, `github_pr_comment` and `github_pr_status` are connector actions (`cx_<slug>_<action>`).

Each manifest carries a **proposal**: LOW for reads and status, MEDIUM for comments, submit and PR create. The proposal is not applied. The actions stay UNCLASSIFIED and denied (C2 invariant 1) until an admin, with a step-up, calls `POST /v1/connectors/{id}/classify-proposed`. That call creates a normal classification version with evidence.

On the C2 MCP endpoint, built-in connector types show the **trusted manifest description**, which tells agents to use `git_submit_change` instead of `git push`. Upstream (third-party) descriptions are never trusted this way.

### 2. Token handling
`github/client.py`:
- A JWT is exchanged for an installation token restricted to the connector's configured `repos`.
- The token lives in process memory only, until 5 minutes before `expires_at`. It is dropped on any 401.
- The token is never stored, logged, returned or put in evidence. A canary test checks responses, evidence and the database.
- Every call goes through C2's `SafeHttp`: `api.github.com` only, public IPs, no redirects, timeouts.
- A `repo` argument outside the configured list fails before any request is made.

### 3. `git_submit_change` is applied server-side, index-only
The agent sends a **diff** or a **bundle** with `base_sha`, `branch` and `issue_number`. The gateway clones the repository fresh into a temporary directory and builds the commit without a working tree:
- diff: `read-tree base`, then `apply --cached --binary`, `write-tree`, `commit-tree`;
- bundle: `bundle verify`, then `fetch`, and `merge-base --is-ancestor base head`.

So no checkout runs, no hooks run, no filters run, and no global config is read.

The token is passed only as `http.extraHeader` through `GIT_CONFIG_*` environment variables, never in argv or a URL. A test asserts this.

Refusals, all before any push:

| Refusal | Code |
|---|---|
| Path traversal, absolute paths, `.git` in any case | `PATH_NOT_ALLOWED` |
| Symlinks resolving outside the repo or into `.git` | `SYMLINK_ESCAPES_REPO` |
| Submodules (mode 160000) | `SUBMODULE_NOT_ALLOWED` |
| Blob > 1 MiB | `BLOB_TOO_LARGE` |
| More than 500 files | `TOO_MANY_FILES` |
| Change or diff > 4 MiB | `CHANGE_TOO_LARGE` |
| Conflicts and non-applying patches | `PATCH_DOES_NOT_APPLY` |
| Bundles not on `base_sha` | rejected |

`git apply` already refuses some of these. The gateway's own checks run on the resulting **tree**, so a hand-crafted bundle is caught too (tested).

**Branch rules:**
- The branch must match `^(fix|feat)/MR-<issue>-<slug>$`, and `<issue>` must equal `issue_number`.
- The branch must not be in the connector's `protected_branches` (default `main`, `master`).
- It must have no active GitHub ruleset rule.
- The push must be a fast-forward.

### 4. C1 rules on the full diff, through a pre-decision Assessment
The connector type may **assess** an action before the policy decision. `connectors.constraint.Assessment` carries a risk floor, deny, rule ids, facts, the approver role and `critical_approval`.

For `git_submit_change`, the assessment prepares the change and runs the C1 `CodingPolicy`, with the repository's tighten-only overlay, over every changed file:
- writes are checked with their diff section;
- deletes are checked as deletes;
- a rename is checked as a delete of the old path, so renaming a test away counts as deleting it.

Results:
- C1 `deny` → the action is DENIED (`CONNECTOR_CONTENT_DENIED`).
- C1 `ask` → at least HIGH, with an approval routed to the C1 role (for example the ledger lead for `ledger/**`).
- CRITICAL (CI, infra, deleting tests) → two security approvers (four-eyes).

The approval is bound to the action digest. The digest covers `change`, so it is bound to the exact diff.

At execution, the change is prepared and assessed **again**. If the result is stricter than what was decided, execution fails with `CHANGE_REASSESSED_STRICTER`. Evidence records:
- the diff digest;
- the tree sha;
- the commit shas;
- the session, issue and branch.

### 5. The check
`github/checks.py` evaluates a PR when one of these arrives:
- a verified webhook (`pull_request` opened, synchronize or reopened; `check_suite` or `check_run` requested or rerequested);
- polling, every `AGW_GITHUB_POLL_SECONDS` (default 60), for PRs whose head changed;
- a monitor report.

The result is published as the check run "AgentGuard evidence". It is SUCCESS only if all of these hold:
1. The PR is not from a fork.
1. The commit listing (paginated, at most 250, GitHub's cap) has exactly the PR's `commits` count. Otherwise the check fails, so a commit cannot hide beyond the listing.
2. Every PR commit is in `github_commits` for this tenant. The table is append-only and written only by `git_submit_change`. A commit not in it fails the check with "commits not recorded by AgentGuard".
3. Each contributing action is COMPLETED, has ACTION_AUTHORIZED and has no ACTION_DENIED. If it required approval, the approval is CONSUMED and its digest equals the action digest.
4. All of their events are in a SEALED epoch. For CRITICAL actions, the anchor must also be FINALIZED.
5. The latest monitor report is VERIFIED or UNANCHORED and covers the highest event sequence involved.

If (4) or (5) is not yet met, the check is `in_progress`. If the latest report is TAMPERED or INCOMPLETE (or another bad result), the check is `failure`.

**Webhooks:**
- The signature is checked with `hmac.compare_digest` against the connector's sealed secret; a bad or missing signature gets 401 and nothing changes.
- Deliveries are de-duplicated by `X-GitHub-Delivery` (`INSERT … ON CONFLICT DO NOTHING RETURNING`).

**Tamper:** `Monitor.on_report` calls `on_monitor_report`. On a bad report, every open PR with gateway commits for that tenant is re-evaluated, which flips it to failure. One comment is posted per (PR, report).

### 6. Why the GitHub actions are declared `environment: dev`
The risk engine scores *write + external effect + prod* as HIGH. With `prod`, every normal submit would need an approval. That defeats the C1 design, where content decides the risk.

The GitHub manifests therefore declare `environments=("dev",)` and `reversible=True`: a branch push and a PR are reversible, and `main` is protected by the check. A normal submit is MEDIUM and auto-allowed.

Sensitive content still raises the risk through §4. Production deploys are not GitHub actions.

### 7. Connector critical exception in the policy engine
Tenant policy has no rule that allows CRITICAL, so a CRITICAL content finding hit the implicit default-deny.

When a connector assessment sets `critical_approval`, the engine replaces the **implicit** default-deny with REQUIRE_APPROVAL from two security approvers, and adds the rule id `CX-CRITICAL-EXCEPTION`. An explicit DENY rule still wins. This mirrors the existing `critical_exception` for classified actions.

## Consequences
- Merging to `main` requires the owner's ruleset (github-app-setup.md §3). Without it, the check is advisory.
- A personal repository has no push restrictions for other users. Direct pushes by the owner are possible, but the check fails them. Agents have no credential.
- Webhooks need a public URL or a tunnel. Otherwise polling mode adds up to 60 s latency.
- Server-side git needs the `git` CLI where the executor runs. The pinned Python base image had none (checked: `exec: "git": executable file not found`). C3 adds it to `infra/docker/gateway/Dockerfile`; the images must be rebuilt (`make rebuild`).
- The mocked suite uses a stateful `httpx.MockTransport` fake plus local bare repositories (`CLONE_ROOT`, dev/test only). It does not use respx, which is not a dependency. Live behaviour is covered by `test_github_live.py` (`AGW_GITHUB_LIVE=1`) and has not been run.
