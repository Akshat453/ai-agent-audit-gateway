# Phase 9.5 UX audit of the Phase 9 dashboard

This audit is of the dashboard **before** the redesign. The screenshots in `before/` were captured by `scripts/screenshots.mjs` against the compose `ui` stack with the seeded demo data, on 2026-11-16, at a viewport of 1440 × 1000. The Phase 9 dashboard is functionally correct and secure: its tests pass and the CSP is strict. The problems listed here are about usability.

Severity: **H** blocks or misleads an operator, **M** slows them down, **L** is cosmetic.

## Cross-cutting

| # | Problem | Sev |
|---|---|---|
| X1 | **No information architecture.** There is one flat row of 8 underlined text links. There are no groups, no active state and no icons, and the row has no room left for more pages. | M |
| X2 | **Status is shown inconsistently.** One `Badge` uses 4 tones, so HIGH looks like PENDING (both amber) and LOW looks like COMPLETED (both green). UNANCHORED, a normal transient state, shows in warning amber. Nothing explains what a status means. | H |
| X3 | **Ids and hashes are cut to their first 8 or 16 characters.** There is no way to see the full value or copy it, and most of them are not links, so pages are dead ends. | M |
| X4 | **Timestamps are raw ISO strings with microseconds.** For example `2026-11-16T13:38:54.557901Z`: there is no relative time and no timezone choice. | M |
| X5 | **No dark mode, no density control, no keyboard shortcuts, no search.** You cannot jump to an action or event by its id. | M |
| X6 | **Body text, tables and badges all use about the same weight and size,** so nothing stands out as the place to look first. | L |
| X7 | **Lists don't paginate, sort or filter server-side,** and nothing refreshes them. You have to reload by hand to see new approvals. | H |

## Per screen

| Screen | File | Problems | Sev |
|---|---|---|---|
| Login | `before/01-login.png` | Generic page layout with the global footer. No product identity. "Login failed." is the only message and gives no hint what to check. | L |
| Overview | `before/02-overview.png` | Four counts with no trend or comparison with the previous period. "Actions per day" is a table holding one bar. Decisions and statuses are two plain tables. Nothing says what needs attention now. Nothing links to a filtered list. System health is not shown. | H |
| Runs list | `before/03-runs.png` | Truncated run ids, no filters, no paging. | M |
| Run timeline | `before/04-run-timeline-delegation.png` | An 8-column table of raw events. Event type, time and evidence class are crammed into one cell. The hash chain, which is the project's core idea, is not visible at all: no `prev → hash` links and no proof. You can't open a single action or event. | H |
| Approvals list | `before/05-approval-center.png` | Absolute expiry timestamps rather than a countdown. The list is sorted by request time, not by urgency. State filters are underlined links. No agent, target or delegation column. | H |
| Approval detail | `before/06a-approval-detail.png` | **The approve button posts immediately, without restating the action.** The digest wraps across lines. Risk reasons are a bare list under a card. The countdown is plain text that never turns amber. "Delegation depth: direct" gives no delegation chain. | H |
| CRITICAL approval | `before/06b-approval-critical-step-up.png` | The step-up form and the approve form sit side by side, with no indication of whether step-up is currently active. Nothing beyond the step-up guards against approving the wrong CRITICAL action. | H |
| Evidence explorer | `before/07-evidence-explorer.png` | The page is **40,048 px tall**: 100 rows, each with a raw JSON header dump. No paging, no link to a single event, no visual of the chain or the proof. | H |
| Epochs and anchors | `before/08-epochs-anchors.png` | A wide table where the anchor lifecycle (Sealed → Submitted → Included → Finalized) is a single status word, with no stepper and no explorer link where it is configured. | M |
| Verification | `before/09-verification.png` | The result explanations sit in a static card, away from the result itself. There is no "what to do next". | M |
| Policies | `before/10-policies.png` | Raw JSON documents with no diff between versions. | M |
| Incidents | `before/11-incidents.png` | A mixed list of kinds with no severity ordering. | M |

## What Part A addresses

| Area | Problems fixed |
|---|---|
| Shell, status system, data formatting | X1–X7 everywhere |
| **Overview** | KPIs with trend, sparkline and link; actions-over-time chart; needs-attention list; evidence pipeline; system health |
| **Approvals** | list with countdowns; split panel; detail page with confirmation dialogs, CRITICAL type-to-confirm and inline step-up status |
| **Action and Event detail** | new pages: the evidence timeline and the proof explorer |

Runs, the evidence explorer, epochs, verification, policies and incidents are Part B. In Part A they render inside the new shell with the new tokens, but keep their Phase 9 layout.
