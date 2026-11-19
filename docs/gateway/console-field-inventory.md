# Console field inventory

Generated from the dashboard code by `node apps/dashboard/scripts/inventory.mjs` (`make console-inventory`) on
2026-11-19, BEFORE the plain-English layer was added: it is the list of what must not be lost. Do not edit by hand.
It lists every technical item each page renders: columns, fields, section titles, headings,
badges, ids/hashes, links, labelled regions and test hooks, per source file (the page and the
components it imports).

Contract (plain-English console, ADR-0039): nothing in this list is removed. Each item is
visible inline, under **Technical details**, or in **Technical view**. `e2e/inventory.spec.ts`
walks every page in Technical view and asserts that every item that rendered before the change
(`e2e/inventory.baseline.json`, captured on the pre-change console) still renders.

## Overview `/`

**app/page.tsx**

- column: `Bucket start (UTC)`
- section: `Overview`, `Actions over time`, `No actions in this period`, `Risk distribution`, `Needs your attention`, `Nothing needs you right now`, `Evidence pipeline`, `Show as table`
- heading: `Decisions, all time`, `System health`
- badge: `StatusBadge evidence`, `RiskBadge level`, `StatusBadge k`, `RiskBadge r.risk_level`, `StatusBadge i.kind`
- region: `Time range`, `Key figures`, `Legend`, `About system health`
- link: `/runs`, `/incidents`, `/approvals`, `/verification`, `/approvals/`, `/actions/`

**components/charts/activity-chart.tsx**

- region: `Stacked area chart of actions per bucket by decision; the same numbers are in the table below`

**components/onboarding/checklist.tsx**

- section: `Get started`
- test hook: `onboarding`

**components/page-header.tsx**

- region: `Breadcrumb`

## Runs `/runs`

**app/runs/page.tsx**

- column: `Run`, `Agents`, `Actions`, `Statuses`, `Delegated`, `Last activity`
- section: `Runs`
- badge: `Badge k`
- region: `Runs`
- link: `/runs/`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

## Run detail `/runs/[id]`

**app/runs/[id]/page.tsx**

- column: `Seq`, `Event`, `Agent / actor`, `Tool`, `Decision / status`, `Risk`, `Links`, `Epoch / anchor`
- section: `Delegation tree`, `Approvals`
- badge: `Badge d.max_risk`, `Badge REVOKED`, `Badge a.state`, `Badge e.decision`, `Badge String(e.risk.level)`, `Badge UNSEALED`, `Badge String(e.anchor.status)`
- region: `Delegations`, `Timeline`
- link: `/runs/`, `/approvals/`, `/events/`, `/actions/`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

**components/github/pull-requests.tsx**

- section: `Pull requests`
- badge: `StatusBadge checkKey(p.conclusion)`
- test hook: `run-prs`

## Action detail `/actions/[id]`

**app/actions/[id]/page.tsx**

- field: `Action id`, `Status`, `Decision`, `Risk`, `Tool`, `Agent`, `Environment`, `Policy`, `Policy reasons`, `Created`, `Last update`, `Run`, `Delegation`, `Approvals`, `Epochs`, `Anchors`, `Events`
- section: `Action`, `Evidence timeline`, `Overview`, `Related`
- badge: `StatusBadge a.status`, `RiskBadge a.risk_level`, `StatusBadge a.decision`, `StatusBadge ap.state`, `StatusBadge x.status`
- id/hash: `action`, `run`, `delegation`, `approval`, `anchor transaction`
- region: `Action sections`
- link: `/policies`, `/runs/`, `/approvals/`, `/epochs`, `/evidence`

**components/evidence/timeline.tsx**

- badge: `RiskBadge n.risk_level`, `StatusBadge n.decision`, `StatusBadge n.status`, `StatusBadge UNANCHORED`, `StatusBadge n.anchor.status`
- region: `Evidence timeline`
- link: `/events/`, `/epochs`

**components/github/pull-requests.tsx**

- section: `Pull requests`
- badge: `StatusBadge checkKey(p.conclusion)`
- test hook: `run-prs`

**components/lifecycle.tsx**

- region: `Lifecycle`

**components/page-header.tsx**

- region: `Breadcrumb`

## Approvals `/approvals`

**app/approvals/page.tsx**

- field: `Agent`, `Environment`, `Policy`, `Action`, `Run`
- section: `Approvals`
- heading: `Why it needs approval`, `Target`, `Arguments (preview)`
- badge: `StatusBadge v.state`, `RiskBadge v.action.risk.level`
- id/hash: `action`, `run`
- link: `/actions/`, `/runs/`, `/approvals/`

**components/approvals-table.tsx**

- column: `Risk`, `Tool`, `Agent`, `Requested by`, `Requested`, `Expires in`, `State`, `Approvals`, `Approval`
- section: `No approvals match`
- badge: `RiskBadge row.original.risk_level`, `StatusBadge row.original.state`
- id/hash: `approval`
- link: `/approvals/`

**components/data-table.tsx**

- region: `Choose visible columns`, `Copy a link to this view`, `Refresh now`, `Quick filters`, `Pagination`, `Previous page`, `Next page`
- test hook: `updated-ago`

**components/code-view.tsx**

- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

**components/split-panel.tsx**

- region: `Details`, `Resize details panel`, `Close details`

## Approval detail `/approvals/[id]`

**app/approvals/[id]/page.tsx**

- field: `Tool`, `Target`, `Environment`, `Agent`, `Delegation`, `Policy`, `Approvals`, `Action`
- section: `Approval`, `Risk`, `Exact arguments`, `Decision`
- badge: `StatusBadge shownState`, `RiskBadge a.risk.level`, `StatusBadge a.policy.effect`
- id/hash: `action`, `run`
- region: `Decision`
- test hook: `countdown`, `digest`, `step-up-ok`, `confirm-code`, `expired-notice`
- link: `/approvals/`, `/actions/`, `/runs/`

**components/code-view.tsx**

- test hook: `safe-text`, `truncated`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

## Events (evidence explorer) `/evidence`

**app/evidence/page.tsx**

- column: `Seq`, `Type`, `Event hash`, `Header`, `Bundle`
- section: `Evidence explorer`
- badge: `Badge e.type`
- region: `Filter`, `Event headers`
- link: `/events/`, `/api/bundles/`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

## Event detail `/events/[id]`

**app/events/[id]/page.tsx**

- field: `Type`, `Sequence`, `Tenant`, `Recorded`, `Observed`, `Actor`, `Action`, `Run`, `Seq range`, `Tree size`, `Merkle root`, `Epoch root`, `Seal reason`
- section: `Event`, `What happened`, `Proof explorer`, `Raw record`, `Metadata`, `Hash chain`, `Payload`
- badge: `StatusBadge VERIFIED`, `StatusBadge TAMPERED`, `RiskBadge n.risk_level`, `StatusBadge UNANCHORED`, `StatusBadge n.anchor.status`, `StatusBadge INCOMPLETE`
- id/hash: `action`, `run`, `event hash`, `prev hash`, `payload digest`, `Merkle root`, `epoch root`
- region: `Chain checks`
- test hook: `event-plain`
- check: `hash`, `link`, `stored-copy`
- link: `/api/bundles/`, `/actions/`, `/runs/`

**components/code-view.tsx**

- test hook: `safe-text`, `truncated`

**components/evidence/proof-explorer.tsx**

- heading: `Inclusion path · epoch`, `Epoch roots → on-chain anchor`
- badge: `StatusBadge res.result`, `StatusBadge anchor.status`
- id/hash: `leaf hash = SHA-256(0x00 ‖ event hash)`, `computed Merkle root`, `stored Merkle root`, `contract`, `transaction`, `expected`, `computed`
- region: `Recomputed checks`
- test hook: `proof-explorer`

**components/page-header.tsx**

- region: `Breadcrumb`

## Epochs & anchors `/epochs`

**app/epochs/page.tsx**

- column: `Epoch`, `Seq range`, `Size`, `Root`, `Sealed`, `Anchor`, `Tx`, `Times`
- section: `Epochs & anchors`
- badge: `Badge e.anchor_status`
- region: `Epochs`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

## Verification `/verification`

**app/verification/page.tsx**

- column: `When`, `Result`, `Reason`, `Range`, `Trigger`, `Alerts`, `Evidence event`
- section: `Verification`, `What the results mean`, `Reports`, `Latest report (as recorded)`
- badge: `Badge k`, `Badge r.result`
- region: `Verification reports`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

## Policies `/policies`

**app/policies/page.tsx**

- section: `Policies`, `Risk policies`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

## Incidents `/incidents`

**app/incidents/page.tsx**

- column: `When`, `Kind`, `Action / run`, `Tool`, `Status / code`, `Detail`
- section: `Incidents`, `Reconcile (operator)`
- badge: `Badge i.status`
- region: `Incident kind`, `Incidents`
- link: `/incidents`, `/api/incidents/export`, `/runs/`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

## Integrations `/integrations`

**app/integrations/page.tsx**

- column: `Name`, `Type`, `Status`, `Unclassified actions`, `Policy version`, `Added`
- section: `Integrations`, `Installed`, `No connectors yet`, `No integration matches`
- heading: `Catalog`
- badge: `StatusBadge connectorStatusKey(c.status)`, `StatusBadge READ_ONLY`, `StatusBadge tier`
- region: `Categories`
- test hook: `installed`, `unclassified-count`
- link: `/integrations/`, `/integrations/new`

**components/page-header.tsx**

- region: `Breadcrumb`

## Integration detail `/integrations/[id]`

**app/integrations/[id]/page.tsx**

- section: `Integration`, `Actions and classification`, `No actions yet`, `GitHub App`, `Set up developer machines`, `Configuration`, `Evidence`, `No events`, `Usage`, `Health`, `Danger zone`
- badge: `StatusBadge connectorStatusKey(c.status)`, `StatusBadge h.ok`
- region: `Connector status`
- test hook: `policy-version`, `connector-events`, `health-history`
- link: `/events/`

**components/connectors/classify-table.tsx**

- column: `Action`, `Side effect`, `Suggested`, `Current`, `Risk`, `Approval`, `Approver role`, `Allowed agents`
- badge: `RiskBadge a.suggested_risk`, `StatusBadge c`, `RiskBadge c.risk`
- test hook: `classify-table`, `classify-form`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

**components/connectors/config-view.tsx**

- field: `Configuration`
- test hook: `config-view`, `credentials-view`

**components/code-view.tsx**

- test hook: `safe-text`, `truncated`

**components/connectors/config-form.tsx**

- test hook: `connector-form`, `json-error`

**components/connectors/github-panel.tsx**

- heading: `1. Register the GitHub App`, `2. Install on repositories`
- test hook: `github-panel`

**components/github/github-status.tsx**

- field: `Installations`, `Repositories`, `Event delivery`, `Webhook URL`, `Webhook health`
- section: `GitHub status`
- badge: `StatusBadge checkKey(p.conclusion)`
- test hook: `github-status`
- link: `/runs/`

**components/github/pull-requests.tsx**

- section: `Pull requests`
- badge: `StatusBadge checkKey(p.conclusion)`
- test hook: `run-prs`

**components/connectors/rotate-dialog.tsx**

- section: `Rotate credentials`
- test hook: `rotate-dialog`

**components/connectors/setup-panel.tsx**

- field: `MCP URL`, `Device enrollment`, `Hook adapter`
- heading: `Enforcement tier`, `On each developer machine`
- badge: `StatusBadge tier`
- region: `setup commands`
- test hook: `setup-panel`
- link: `/enroll`

**components/step-up.tsx**

- test hook: `step-up-ok`, `step-up-form`

## Add integration `/integrations/new`

**app/integrations/new/page.tsx**

- section: `Add integration`, `Set up developer machines`, `Track it as an integration (optional)`, `Configure`, `Test connection`, `Classify actions`, `Review`
- badge: `StatusBadge connectorStatusKey(c.status)`, `StatusBadge lastHealth.ok`, `RiskBadge a.classification.risk`, `StatusBadge a.classification`
- test hook: `last-health`, `policy-version`
- link: `/integrations`, `/integrations/`

**components/connectors/classify-table.tsx**

- column: `Action`, `Side effect`, `Suggested`, `Current`, `Risk`, `Approval`, `Approver role`, `Allowed agents`
- badge: `RiskBadge a.suggested_risk`, `StatusBadge c`, `RiskBadge c.risk`
- test hook: `classify-table`, `classify-form`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

**components/connectors/config-view.tsx**

- field: `Configuration`
- test hook: `config-view`, `credentials-view`

**components/code-view.tsx**

- test hook: `safe-text`, `truncated`

**components/connectors/config-form.tsx**

- test hook: `connector-form`, `json-error`

**components/connectors/github-panel.tsx**

- heading: `1. Register the GitHub App`, `2. Install on repositories`
- test hook: `github-panel`

**components/connectors/setup-panel.tsx**

- field: `MCP URL`, `Device enrollment`, `Hook adapter`
- heading: `Enforcement tier`, `On each developer machine`
- badge: `StatusBadge tier`
- region: `setup commands`
- test hook: `setup-panel`
- link: `/enroll`

**components/connectors/stepper.tsx**

- region: `Progress`

**components/step-up.tsx**

- test hook: `step-up-ok`, `step-up-form`

## Repositories `/repos`

**app/repos/page.tsx**

- section: `Repositories`, `No repositories yet`
- heading: `Coding agents set up here`, `Loosening proposals`
- badge: `StatusBadge tierKey(a.tier)!`, `StatusBadge PROPOSAL_PENDING`
- test hook: `proposal`

**components/code-view.tsx**

- test hook: `safe-text`, `truncated`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`

**components/step-up.tsx**

- test hook: `step-up-ok`, `step-up-form`

## People `/people`

**app/people/page.tsx**

- column: `Username`, `Roles`, `Status`
- section: `People`, `Invite a person`, `Members`
- badge: `StatusBadge h.status`
- test hook: `people`

**components/page-header.tsx**

- region: `Breadcrumb`

**components/people/invite-form.tsx**

- test hook: `invited`, `temporary-password`

**components/step-up.tsx**

- test hook: `step-up-ok`, `step-up-form`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

## Enroll a device `/enroll`

**app/enroll/page.tsx**

- field: `Code`, `Agent`, `Device label`, `Requested`, `Developer`
- section: `Enroll a device`, `Device code`
- badge: `StatusBadge `ENROLL_${req.status.toUpperCase()`
- test hook: `device-request`

**components/legacy.tsx**

- badge: `RiskBadge value`, `StatusBadge value`
- test hook: `safe-text`, `truncated`

**components/page-header.tsx**

- region: `Breadcrumb`
