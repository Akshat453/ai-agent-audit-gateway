# Phase 9.5: Dashboard redesign, "AgentGuard Console" (Part A)

Status: Part A implemented 2026-11-16 · ADR: [0033](../adr/0033-phase9-5-dashboard-redesign.md) · Design spec: [16-dashboard-design.md](../16-dashboard-design.md) · Not committed (the owner commits) · **Part B waits for owner approval.**

The redesign is frontend only. Gateway behaviour is unchanged; the only gateway additions are **read-only** endpoints with tests (§3). Nothing under `experiments/`, no raw results and nothing in `research/results.md` was touched.

## 1. What changed

| Area | Change |
|---|---|
| Docs | **UX audit** of the Phase 9 UI with before-screenshots ([screenshots/redesign/ux-audit.md](../screenshots/redesign/ux-audit.md), `before/`). [16-dashboard-design.md](../16-dashboard-design.md) covers the visual system, layout, pages, signature views, UX and a11y rules, with wireframes. ADR-0033 covers the stack, CSP evidence, budget and endpoints. |
| Design tokens | `app/globals.css`: Radix Colors (slate, iris, jade, tomato, amber, orange, blue; light and dark) as `gray`/`brand`/`ok`/`bad`/`warn`/`high`/`info` Tailwind tokens; the type scale (title, section, body, dense, caption, kpi); radii and motion; `--row-h` density. Geist Sans and Mono are self-hosted through `next/font/local`. |
| Status system | `lib/status.ts` is the ONE mapping table (tone, icon, label, explanation). `StatusBadge` / `RiskBadge` render every status from it, always as icon + text with a tooltip. |
| Base components | `components/`: StatusBadge, RiskBadge, HashChip (middle-truncated, copy, popover, link), Timestamp (relative + exact, UTC/local), PageHeader (breadcrumbs, help), DataTable (TanStack v8, URL state, token filters, quick filters, column visibility, share view, polling, j/k/Enter/Esc), SplitPanel (resizable), EmptyState / ErrorState, ConfirmDialog (restate, type-to-confirm, required reason), KpiTile + Sparkline, Notice, CodeView (escaped JSON highlighting, TRUNCATED marker), Countdown, LifecycleStepper. `components/ui/` holds shadcn-style primitives on Radix (button, input, card, dialog, menu, tooltip/popover, toast) plus own WAI-ARIA tabs. |
| App shell | `components/shell/`: top bar (mark, product name from `lib/brand.ts`, tenant pill, DEV badge, search, alerts bell, theme toggle, user menu with step-up minutes, density, timezone, shortcuts, log out); grouped, collapsible side nav filtered by role, with a live pending-approvals badge and a health footer; help drawer; command palette (cmdk, code-split, id/hash search); shortcut sheet; toasts. Preferences go through `POST /api/prefs` (CSRF) into httpOnly cookies the server renders from. |
| Pages | **Overview** (KPIs with delta and sparkline, actions-over-time chart with legend and table, risk bars, needs-your-attention, evidence pipeline, system health). **Approvals** list (split panel) and detail (summary card, risk, exact args, decision column with confirm dialogs, CRITICAL type-to-confirm, inline step-up). **Action detail** (lifecycle stepper; tabs: evidence timeline, overview, related). **Event detail** (proof explorer, header, chain checks, payload, epoch). **Login** (centered card, mark, a single non-enumerating error). |
| Signature views | 1: evidence timeline (`components/evidence/timeline.tsx`). 2: proof explorer (`components/evidence/proof-explorer.tsx` + `lib/merkle.ts`, Web Crypto, mirrors the verifier). |
| Legacy pages | Runs, Events, Epochs, Verification, Policies and Incidents keep their Phase 9 layout inside the new shell, re-skinned (`components/legacy.tsx`, `.legacy` CSS). Their rows now link to the new event and action pages. Rebuilt in Part B. |
| Gateway (read-only) | `api/console_routes.py`: 7 endpoints (§3). `openapi.py` includes them. `apps/dashboard/openapi.json` and `lib/api/schema.d.ts` were regenerated. |
| Tests | Gateway: `tests/e2e/test_console_api.py` (10). Dashboard e2e: existing specs updated (selectors and dialog steps only), new `e2e/console.spec.ts` (7), `a11y.spec.ts` now covers both themes and the new pages, and the seed adds one `keyboard` approval. |
| Tooling | `scripts/screenshots-redesign.mjs` (light/dark/responsive screenshots; fails on any CSP violation or page error). `scripts/bundle-report.mjs` (gzipped first-load JS per route, 300 KB budget). |
| Compose | Anvil persists its state (`agw-anvil` volume). `make start` / `make stop` start and stop the whole stack (done earlier this session; ADR-0032 note). |

## 2. Decisions (details in ADR-0033)

1. **ADR-0033, not 0032.** The prompt said ADR-0032, but that number is Phase 10's.
2. **sonner was rejected** because its `<style>` injection would need `unsafe-inline`; Radix Toast is used instead.
3. **Radix Tabs were replaced** by own ARIA tabs, because Radix server-renders `style="animation-duration:0s"`.
4. **Client-only rendering for some components.** Recharts, the toaster and cmdk render only after mount or open, so their styles go through the CSSOM, which CSP allows. Radix scroll-lock `<style>` tags get the request nonce through `get-nonce`.
5. **Theme, density, timezone and nav** are server-rendered from httpOnly cookies: no flash, no inline script. No "system" theme, because it would need a script.
6. **The approvals list doesn't include the target**, because the target needs the sealed arguments. It's shown in the split panel through the existing approval view.
7. **The proof explorer is auditor/admin** because it reads the evidence bundle (the Phase 9 rule). Everyone sees the hash-chain checks.
8. **"After a decision, return to the next pending item"** is a "Review next pending" link next to the result, not an automatic redirect, so the decision result (CONSUMED / REJECTED) stays visible and testable.
9. **Badge text is step 12, not step 11:** axe measured step 11 on step 3 at about 4.2:1 in light mode.
10. **tailwind-merge** is extended with the type scale. Without that it dropped `text-white`, so the Sign in button failed contrast.

## 3. New read-only endpoints

| Endpoint | Roles | Notes |
|---|---|---|
| `GET /v1/dashboard/activity?range=24h\|7d\|30d` | any human | buckets per decision, current vs previous totals, pipeline |
| `GET /v1/dashboard/approvals` | approver, auditor, admin | sort whitelist `expires_at`/`requested_at`/`risk`/`tool`, filters `state`/`risk`/`tool`, limit ≤ 200, offset |
| `GET /v1/dashboard/actions/{id}` | any human | metadata + evidence nodes (`hash_ok`, `link_ok`, epoch, anchor); no args or results |
| `GET /v1/dashboard/events/{id}` | any human | header + canonical header bytes + node checks + epoch |
| `GET /v1/dashboard/session` | any human | env, roles, step-up time remaining |
| `GET /v1/dashboard/health` | any human | gateway, database, worker, anchoring, monitor |
| `GET /v1/dashboard/search?q=` | any human | UUID or ≥ 8-hex prefix, tenant-scoped, ≤ 10 hits |

All of them reject agent keys (403) and have no session-less access (401).

## 4. Work done and evidence (commands run in this session)

| Check | Command | Result |
|---|---|---|
| New endpoints | `uv run pytest apps/gateway/tests/e2e/test_console_api.py` | `10 passed` |
| Those tests can fail | Remove one guard at a time (tenant filter ×2, hash recompute, sort), then run the named test | 4/4 caught; file restored byte-identical |
| Full gateway suite + gates | `make test` (ruff, format, mypy 128 files, import-linter, pytest, coverage gates) | `858 passed, 1 deselected`; gated packages 92 % (≥ 85); risk 100 %; `console_routes.py` 93 %; exit 0 |
| Dashboard e2e (real gateway, production build) | `make dashboard-e2e` | `18 passed`: 11 existing tests (selectors and dialog steps only, no assertion removed) + 7 new console tests |
| Accessibility | in `make dashboard-e2e` (`a11y.spec.ts`) | axe wcag2a+aa: 0 serious/critical on login + 13 pages, **light and dark** |
| CSP | `console.spec.ts` + `node scripts/screenshots-redesign.mjs` | fresh nonce, no `unsafe-*`, no external origins, no server `style=` on 4 pages; `no CSP violations, no page errors` over 30 screenshots |
| OpenAPI / type drift | `make dashboard-check` | exit 0 |
| Dependencies | `npm audit` | `found 0 vulnerabilities` |
| Bundle budget | `node scripts/bundle-report.mjs` | all routes ≤ 300 KB except `/` 301.5 KB (reason in ADR-0033 §4); table in `screenshots/redesign/bundle-report.md` |
| Workflows | `actionlint` 1.7.7 on `ci.yml` (new `dashboard-e2e` job) + `experiments.yml` | exit 0. The job itself has not run on GitHub yet. |
| Full demo | `make start` (`docker compose --profile ui up -d --build`) | all services up, dashboard 200, `alice` login 200 |

**Fixed along the way:**

- **Phase 10 rate-limit e2e test.** It flaked under load: at 60/min a token refilled during a slow request. It's now 1/min, so it can't refill during the test.
- **Phase 4 `test_low_only_traffic_seals_on_age`.** It failed once in the first full run and passed alone and in the full rerun. It is a timing race, unrelated to this phase.

## 5. Remaining UX issues (ranked by impact) and Part B

1. **Six pages still have the Phase 9 layout:** Runs, Events (the 40,000 px page), Epochs/Anchors, Verification, Policies, Incidents. They need DataTable, split panels, anchor stepper, result cards and the policy diff viewer. **Part B.**
2. **Missing pages:** Actions list, Agents, Tools, Delegations, Alerts, Disclosure grants. Their nav items are hidden until they exist, and the Overview risk bars can't link to a filtered Actions list yet. **Part B.**
3. **Tamper demo** (signature view 3; dev + admin + demo tenant, otherwise 404) is not built. **Part B**, with its 404 tests.
4. **Proof explorer vs server verifier** for every Phase 10 tamper case is not yet tested. **Part B.**
5. **`/` is 301.5 KB** gzipped JS, 1.5 KB over budget, because of Recharts (105 KB). Part B: visx or a small hand-written SVG for the one chart.
6. **Visual regression snapshots** (per page, light and dark) aren't automated yet; Part A has the reviewed screenshot set. **Part B.**
7. **Below 1024 px the split panel hides** (Shift+Enter or the id link opens the full page); below 768 px the side nav hides (the palette remains).
8. **The approvals list shows no target** (see decision 6).
9. **Re-running only the `ui-demo` container** re-runs `ui-init`, which rotates the MCP integration token without restarting `ui-mcp`, so the demo's MCP step fails. `make start` (everything) is fine. This is existing Phase 9 compose behaviour, not changed here.
10. **Hash-prefix search** uses `encode(event_hash,'hex') LIKE` (a sequential scan per tenant). That's fine at demo scale; an index on a hex prefix if it's ever slow.

## 6. Screenshots

- Before: `docs/gateway/screenshots/redesign/before/` (12).
- After: `docs/gateway/screenshots/redesign/after/` (30). Every Part A page in light and dark, the confirm dialog, CRITICAL, the split panel, palette and help drawer, legacy-in-new-shell, and 1024 px / 768 px.
- The Phase 9 screenshots in `docs/gateway/screenshots/*.png` are untouched; Part B moves them to `phase-09/`.
