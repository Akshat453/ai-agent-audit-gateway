# ADR-0040: Console scoped to one repository; run story says why
Status: Accepted · Date: 2026-11-19 · Deciders: the owner (Akshat)

## Context
With more than one repository protected, runs, approvals, events and incidents from every repository appeared in one list. The run page also did not say, per action, why something was blocked or needed a person.

## Decision
1. **Repository scope.** A run belongs to a repository when its coding session was started there (`coding_sessions.repo_digest = repos.remote_digest`).
   - These endpoints accept an optional `repo_id` and then include only that repository's runs:
     - `GET /v1/dashboard/runs`, `/approvals`, `/events`, `/incidents`, `/activity`, `/overview`.
   - Tenant isolation is unchanged: the sub-query is tenant-scoped, so another tenant's repository id matches nothing.
   - Raw SQL uses a literal `CAST(:repo AS uuid) IS NULL OR run_id IN (...)` guard with bound parameters.
2. **`GET /v1/dashboard/repo-choices`.** Repository id, name and session count for any signed-in human; names only. Approvers need the switcher but cannot read `/v1/repos` (overlays and proposals stay admin, auditor, security and maintainer only).
3. **Console.**
   - A repository switcher in the top bar ("All repositories" or one repository), remembered per user in the `agw_repo` cookie (value validated: a UUID or `all`; a stale id falls back to all).
   - Runs, approvals, events, incidents and the overview follow it, show "Showing only <repo>" with one click back, and the pending-approvals badge counts that repository only.
   - Not scoped:
     - non-repository records (settings changes, batch seals, integrity checks);
     - monitor alerts, which concern the whole log;
     - epochs, since one batch can hold records of several repositories.
4. **Run story.** `TimelineEvent.rules` (from the sealed record) lets each blocked or approval-needing action say why in words ("Why: The change would remove webhook signature checks."). The story is shown in Technical view too.

## Consequences
- Non-coding runs (API agents) have no repository and appear only under "All repositories".
- Actions recorded before migration 0015 still show "Asked to edit a file" without the path: the target was never stored in readable form for them.
- Tests:
  - `tests/e2e/test_console_repo_scope.py`: every list scoped; another tenant sees nothing; rule ids in the run story;
  - `e2e/repo-scope.spec.ts`: switch, remember, one click back, the story's "Why".
