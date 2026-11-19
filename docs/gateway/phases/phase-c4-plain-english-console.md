# Phase: plain-English console (ADR-0039)

## Goal
A first-time viewer can answer from Simple view alone:
- what the agent tried, and on which file or command;
- whether it ran, and why;
- who approved;
- whether the evidence is intact.

Nothing technical is removed: Technical view is today's console plus a summary line.

## What changed
**Gateway (read-only additions, plus one stored display field)**
- Migration `0015_console_display`: `coding_actions.target_sealed` (redacted targets, sealed under the KEK) and `diff_files` / `diff_added` / `diff_removed`.
- `coding/display.py`: `redact`, `display_target`, `diff_summary`.
- `api/coding_view.py`: session and target views.
- New fields on the action, run, run-list and approvals endpoints, plus `GET /v1/dashboard/rule-descriptions` (API §5.12).
- `policies/descriptions.py` and two companion description files (more than 100 rule ids and 3 patterns).

**Dashboard**
- `src/humanize/*`: the single source of words.
- `components/humanize/*`: `Technical` (the fold), `PlainStory`, `PlainLine`, `IntactBadge`, `PlainSteps`, `AgentText`, `PhraseView`, `Term` (glossary tooltip), `ViewToggle`.
- The `agw_view` preference and the user-menu switch. Local time is the default; `Timestamp` uses the new format.
- Every page: a headline, plus the page-specific plain content:

| Page | Plain content |
|---|---|
| Overview | "Today in plain English", KPI explanations, "Needs you" |
| Runs | one sentence per session |
| Run | the session story |
| Action | What happened / Why / Who / What you can do, plain stepper, "Is this record intact?" |
| Approvals | a "Request" column, and the dialog restates the request |
| Events | one sentence per record, plus an "In plain words" column |
| Event | plain card with the intact badge |
| Epochs | batch sentences, with Locked → Sent → Included → Permanent |
| Verification | the result in words, with what to do next |
| Policies | every rule with its description, history in words, and `?rule=` focus |
| Incidents | the kind in words, with what to do |
| Integrations | status in words, tiers in words |
| Integration | numbered setup steps with done / to do |
| Repositories | each repo and proposal in words |
| People | one sentence per person |
| Enroll | three numbered steps, and the request in words |

- Help drawer: new topics (runs, run, events, epochs, verification, policies, incidents) and "Words on this page" from the glossary.

## Tests
- Gateway:
  - `tests/unit/test_coding_display.py` (22): redaction, clipping, diff counts;
  - `tests/unit/test_rule_descriptions.py` (4): coverage of every emitted rule id;
  - `tests/e2e/test_console_coding_view.py` (5): path and redacted command shown, contents never shown, stored copy sealed, other tenants get 404, approver names.
- Dashboard unit (`make dashboard-unit`, 13): label completeness, template snapshots, escaping, canaries.
- Browser (`make dashboard-e2e`, 39), including:
  - `inventory.spec.ts`: every pre-change item still renders in Technical view;
  - `plain.spec.ts`: a headline on every page in Simple view; the action example; the toggle persists; UTC/Local; the run story escapes agent text; no secret or diff content on any page; the approval sentence;
  - `a11y.spec.ts`: axe in both views.
- Screenshots: `docs/gateway/screenshots/human-readable/<page>-simple.png` and `-technical.png`. The pre-change console is in `screenshots/redesign/after/` (Phase 9.5).


## Follow-up: one repository at a time, and the run story says why (ADR-0040)
- **Repository switcher** in the top bar. Runs, approvals, events, incidents and the overview follow it; it is remembered per user, with "Show all repositories" one click away.
- **Run story** (both views): each action in plain words, the decision chain, and "Why: ..." for every block or approval.
- **Tests:**
  - gateway `test_console_repo_scope.py` (2);
  - browser `repo-scope.spec.ts` (2);
  - the seed has a second repository (`second-repo`, issue #3).
