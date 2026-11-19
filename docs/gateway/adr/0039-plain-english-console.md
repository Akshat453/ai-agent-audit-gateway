# ADR-0039: Plain-English console (Simple / Technical view)
Status: Accepted · Date: 2026-11-19 · Deciders: the owner (Akshat)

## Context
The console showed what engineers and auditors need: rule ids, event types, hashes, epochs and raw headers. A manager, an auditor new to the product, or an interviewer could not tell from a page what the agent tried, on which file, whether it ran, why, who approved, and whether the evidence is intact.

The owner's requirement:
- every page understandable in about 10 seconds;
- **nothing technical removed**;
- no LLM-generated text;
- no change to gateway behaviour.

## Decision
1. **Two views.** `agw_view` cookie, `simple` (default) or `technical`, remembered per user and rendered by the server (no flash).
   - It is switched from the user menu and from a toggle in every page header.
   - **Simple view:** plain summary first; today's technical content is folded under **Technical details** on the same page.
   - **Technical view:** today's layout, plus a one-line plain summary on top.
   - Work surfaces never fold: approve/reject, the classification table, proposal decisions, step-up, the approvals table.
2. **One source of words.** `apps/dashboard/src/humanize/`:
   - `glossary`, `event-types` (all 29 schema types), `statuses`, `actions` (action type + target → verb phrase), `rules`, `names`, `time`;
   - `stories` and `events` (page-level sentences).
   - Pure functions over structured API fields, with templates only. Unit tests fail if a schema event type, status, coding action type, GitHub action or policy reason code has no words.
3. **Rule descriptions live with the rules.** `coding/policies/coding-mintrail-descriptions.toml` and `policies/rule_descriptions.toml` hold a `name` and a one-sentence `why` per rule id, plus `*` patterns (`REPO-OVERLAY-v*`, `cx:*`, `GH-*`).
   - They are **companion files**, not edits to the policy files. The policy files' bytes are hashed into every decision (policy digest), so changing them would alter the recorded digest of an existing version.
   - Served read-only by `GET /v1/dashboard/rule-descriptions`. The dashboard caches them for 10 minutes.
   - A gateway test collects every rule id literal from the source and fails if one has no description.
4. **Names people recognise.**
   - `device:akshat:Laptop:…` → "akshat on Laptop";
   - `claude_code` 2.1.x → "Claude Code 2.x";
   - runs → "Claude Code session by akshat on MintRail - issue #12".
   - Times: local by default, "18 Nov 2026, 11:18:15 PM IST · 2 h ago", exact UTC on hover; a UTC/Local switch. Durations in words ("approved 5 min later").
5. **Paths and commands are shown; contents are not.** A path or command is metadata of the action.
   - At decision time the coding service stores the action's targets in `coding_actions.target_sealed` (migration 0015):
     - every secret value in a command, URL or argv is replaced by `[REDACTED]`: env assignments, `--token` style flags, `Authorization:` headers, URL credentials and the C1 secret patterns;
     - clipped to 2,000 characters;
     - sealed under the KEK (ops context `coding_target`, like approval request args, ADR-0029).
   - Diffs are reduced to counts (`diff_files`, `diff_added`, `diff_removed`).
   - File contents and diffs are never stored for display or returned.
   - Actions recorded before 0015 show "not recorded".
6. **Read-only API additions** (tenant-scoped, no new writes):
   - action detail: `coding` (type, target, diff counts), `session` (developer, device, agent, repository, issue), and approvals with `decisions` (who, when);
   - evidence nodes: `rules` (from the sealed record);
   - runs: `session`, `decisions`;
   - run detail: `session`, `coding` per action, `people` (approver names);
   - approval rows: `action_type`, `target`, `agent_kind`, `issue_number`;
   - `GET /v1/dashboard/rule-descriptions`.
7. **Agent-reported text** (paths, commands) is rendered as escaped text in code style, with a "reported by the agent" tooltip. It is never markup.

## Consequences
- **Inventory.** `docs/gateway/console-field-inventory.md` lists what each page rendered BEFORE this change, generated from the code (530 items, 18 pages).
  - `e2e/inventory.spec.ts` compares Technical view with a baseline captured on the unchanged console (`e2e/inventory.baseline.json`): text labels, columns, fields, regions, links, test hooks, status values and id/hash chips.
  - Ids and numbers are normalised; the baseline was verified stable across two fresh seeds before any page changed.
- **Existing browser specs** pin Technical view through the login helper, because they test today's layout. The new `plain.spec.ts` tests Simple view, and the accessibility scan covers both views (light theme = Simple, dark = Technical).
- **Loading state.** A route-level loading screen (`app/loading.tsx`) was tried and removed: React's streaming applies `style="display:none"`, which the CSP (unchanged) blocks. Pages are server-rendered and never had a loading screen; error and empty states now say what to do next.
- **Rate limit.** The per-session API rate limit (burst 60) is reachable when a script opens many pages within seconds. The rule-description cache keeps the plain layer from adding to it.
