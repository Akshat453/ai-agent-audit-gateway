# ADR-0042: Integration (GitHub) actions belong to the repository they target
Status: Accepted · Date: 2026-11-19 · Deciders: the owner (Akshat)

## Context
GitHub tool calls arrive over MCP under one run per device and client (`uuid5(agent, client)`), not under the Claude Code session. With the repository switcher (ADR-0040), that run was not linked to any repository:
- under "All repositories" it looked like a second MintRail session;
- with MintRail selected it disappeared.

## Decision
- **Recording.** Migration 0016 adds `action_repos(action_id, tenant_id, repo "owner/name")`; the runtime role has INSERT and SELECT only.
  - The decision transaction records the call's `repo` argument, else the connector's default (first configured) repository, for GitHub connector actions.
  - It has no effect on the decision.
- **Scope.** A row belongs to a repository when:
  - its run is a coding session started there, or
  - its action is recorded in `action_repos` for that repository. The repository URL is normalised (https or ssh, with or without `.git`) and must end in `/owner/name` or `:owner/name`.
- **One condition everywhere.** `coding_view.in_repo` applies this to runs, approvals, events, incidents and the overview; the raw-SQL activity and overview counts use the same literal clause.
- **Runs.** The list and run detail return `repos`. The console titles such a run "GitHub steps by akshat on MintRail" and explains that the coding steps are in the Claude Code session.
- **Backfill.** `backfill-coding-targets` (and `make backfill-targets`) also fills `action_repos` for older GitHub actions, from the `repo` argument in their own payload or the connector default. Idempotent; evidence is only read.

## Consequences
- The owner's stack: 8 of 8 GitHub actions linked to `Akshat453/MintRail`.
- The GitHub steps are still a separate run from the Claude Code session. Merging them would need the MCP call to carry the session id, which Claude Code does not send.
- Test: `tests/e2e/test_github.py::test_github_actions_belong_to_their_repository`.
