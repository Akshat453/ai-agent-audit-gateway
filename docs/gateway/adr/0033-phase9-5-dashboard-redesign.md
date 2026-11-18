# ADR-0033: Phase 9.5 dashboard redesign ("AgentGuard Console"): stack, CSP and budgets

Status: Accepted (Part A) · Date: 2026-11-16 · Deciders: Phase 9.5 implementation (pending owner review)

## Context

The Phase 9 dashboard (ADR-0031) is correct and secure, but hard to use (see `docs/gateway/screenshots/redesign/ux-audit.md`). Phase 9.5 is a frontend-only redesign. Its hard constraints are:

- strict CSP with a per-request nonce, no `unsafe-inline` and no `unsafe-eval`, no external origins;
- an httpOnly, Secure, SameSite=Strict session;
- CSRF protection plus a same-origin check;
- escaped rendering, with the explicit TRUNCATED marker;
- approvals echo the digest and nonce;
- the CRITICAL step-up flow is unchanged;
- no payloads shown without a disclosure grant;
- no change to gateway behaviour; any data the UI needs comes from new read-only endpoints with tests.

**Docs and the prompt disagree here (working rule 6):**

1. **ADR number.** The prompt says to record the stack in ADR-0032, but ADR-0032 is already the Phase 10 evaluation and hardening ADR. This ADR is 0033, and the ADR index points to it.
2. **"Phases 0–10 are complete and committed".** Phase 10 is not finished: its experiments and `research/results.md` are still in progress. Phase 9.5 does not touch `experiments/`, raw results or `results.md`.
3. **Toasts: sonner.** sonner was rejected under the prompt's own rule (§2 below).
4. **Tabs.** The shadcn Tabs (Radix) were replaced by an own component (§2 below).

## Decision

### 1. Stack (all versions pinned exactly, each released at least 2 weeks before 2026-11-16)

| Concern | Choice | Version |
|---|---|---|
| Primitives | shadcn/ui pattern: source in `components/ui/`, built on Radix | dialog 1.3.1, dropdown-menu 2.2.1, popover 1.3.1, tooltip 1.4.1, toast 1.3.1, slot 1.5.0 |
| Tables | TanStack Table v8, manual (server-side) sorting, filtering and pagination | 8.21.3 |
| Charts | Recharts (SVG), rendered client-side only (§2) | 3.10.1 |
| Command palette | cmdk, code-split and loaded on first open | 1.1.1 |
| Toasts | Radix Toast (sonner rejected, §2) | 1.3.1 |
| Icons | lucide-react | 1.66.0 |
| Colors | `@radix-ui/colors`: slate, iris, jade, tomato, amber, orange, blue (light and dark) | 3.0.0 |
| Fonts | Geist Sans and Geist Mono (SIL OFL), from the `geist` package via `next/font/local`, served from `/_next/static` | 1.9.0 |
| Utilities | clsx, tailwind-merge (extended with the custom type scale), class-variance-authority | 2.1.1 / 3.7.0 / 0.7.1 |
| Nonce plumbing | get-nonce (already a Radix dependency, now direct) | 1.0.1 |

- **Not used:** Cloudscape, MUI, Ant Design and Chakra, as the prompt requires.
- **`npm audit`:** 0 vulnerabilities after the change.

### 2. CSP evidence: what broke and how it was fixed without relaxing the policy

The policy is unchanged: `style-src 'self' 'nonce-…'`, which blocks `style="…"` attributes in server HTML. The redesign surfaced 5 issues, all fixed:

| Library | Problem found | Fix |
|---|---|---|
| **sonner** | It injects an un-nonced `<style>` on module load, so it would need `unsafe-inline`. | **Rejected** under the prompt's rule; Radix Toast is used instead. |
| Radix Toast | The viewport wrapper is server-rendered with `style="pointer-events:none"`. The browser reported `style-src-attr` violations. | The `Toaster` renders after mount, so React applies the style through the CSSOM, which CSP allows. |
| Radix Tabs | Inactive panels are server-rendered with `style="animation-duration:0s"`. 2 violations per action page. | An own WAI-ARIA tabs component (`components/ui/tabs.tsx`) with the same API. `@radix-ui/react-tabs` was removed. |
| Radix scroll lock (Dialog, Menu) | It injects a `<style>` when a modal opens. | It reads the nonce through `get-nonce`. `NonceSetter` passes the request nonce from the server layout, so the tag is allowed by `'nonce-…'`. |
| Recharts | SVG and tooltip style objects would be inline attributes if server-rendered. | The chart renders only after mount, so styles go through the CSSOM. A skeleton is server-rendered in its place. |
| cmdk | Renders an sr-only label with an inline style. | It only ever renders client-side, inside a dialog opened by the user. |

**Evidence (all run in this session):**

- `apps/dashboard/scripts/screenshots-redesign.mjs` covers every Part A page in both themes, including opened dialogs, the palette and the help drawer. It exits non-zero on any CSP violation and printed `no CSP violations, no page errors`.
- e2e `console.spec.ts` › "CSP: per-request nonce…" checks:
  - a fresh nonce per response;
  - `script-src 'self' 'nonce-…' 'strict-dynamic'` and `style-src 'self' 'nonce-…'`;
  - no `unsafe-inline`, `unsafe-eval` or `unsafe-hashes`;
  - no `http(s)://` origins in the policy;
  - every script and stylesheet URL is same-origin;
  - **no `style="` attribute in the server HTML** of 4 pages.
- Every e2e test asserts there were no CSP console errors (`watch()`).

### 3. Theme, density and timezone without inline script

- **Where they live.** Preferences are cookies (`agw_theme`, `agw_density`, `agw_tz`, `agw_nav`), httpOnly and SameSite=Strict, read by the server layout. The server renders `<html class="light|dark density-compact">`, so there is no flash of the wrong theme and no inline script.
- **How they change.** Through `POST /api/prefs`: same-origin check, CSRF token, allowlisted keys and values. The UI applies the class optimistically, because a preference is harmless, and reverts if the save fails. This is the only optimistic UI; approvals never are.
- **What's not supported.** A "system" theme option would need a client hint or a script, so it is not offered; the default is light.

### 4. Bundle budget (300 KB gzipped first-load JS per route)

Measured by `scripts/bundle-report.mjs`: each route loads in a fresh browser context against the production build, and every script it fetched is gzipped. The result is in `docs/gateway/screenshots/redesign/bundle-report.md`.

- **Every route is under budget except `/` (Overview) at 301.5 KB.**
- **Written reason:**
  - Recharts is 105 KB gzipped of that, for a single stacked area chart.
  - The prompt asks for Recharts, and it does run under the CSP, so it was kept for Part A.
- **Part B action:** draw that one chart with visx (shape and scale) or a small hand-written SVG, which would take about 100 KB off `/`.
- The command palette was code-split, taking about 2.5 KB off every route.

### 5. New READ-ONLY gateway endpoints (`api/console_routes.py`)

All of them:

- need a human session (an agent key gets 403 `AGENT_NOT_PERMITTED`);
- are tenant-scoped;
- return no payloads, arguments or results;
- were added to the OpenAPI schema, with the typed client regenerated (`make dashboard-api`).

| Endpoint | Purpose |
|---|---|
| `GET /v1/dashboard/activity?range=24h\|7d\|30d` | decision buckets, current vs previous period totals, evidence pipeline counts and oldest waiting |
| `GET /v1/dashboard/approvals` | approvals with agent and delegation issuer; server-side sort (whitelist), filter and pagination. Viewers are the same as `GET /v1/approvals`. The target is **not** listed (it needs the sealed arguments); it shows in the split panel through the existing approval view. |
| `GET /v1/dashboard/actions/{id}` | action metadata plus its evidence nodes: hash, prev, `hash_ok` (recomputed), `link_ok` (prev = stored hash of seq−1), epoch and anchor |
| `GET /v1/dashboard/events/{id}` | one header, its canonical bytes (the public structural header), node checks and epoch record |
| `GET /v1/dashboard/session` | env, roles, step-up time remaining (user menu) |
| `GET /v1/dashboard/health` | gateway, database, worker (queued jobs), anchoring and monitor chips |
| `GET /v1/dashboard/search?q=` | command palette: exact UUID, or a hash or root prefix of at least 8 hex characters |

- **Tests:** `apps/gateway/tests/e2e/test_console_api.py`, 10 tests. They cover:
  - session and role requirements;
  - no canary argument value in any response;
  - tenant scoping;
  - sort, filter and pagination;
  - the evidence chain;
  - an insider edit of `canonical_bytes` flipping `hash_ok`;
  - a rewritten stored hash flipping the next event's `link_ok`;
  - the session step-up window;
  - health;
  - search.
- **Mutation check:** removing the tenant filter (action and event), the hash recomputation or the sort order makes the named test fail (4 of 4 caught).

### 6. Proof explorer: what the browser recomputes

`lib/merkle.ts` mirrors the independent verifier (`agw_verifier.chain.event_hash`, `merkle.inclusion_ok` / `epoch_root`, `epochs.verify_bundle` order) with Web Crypto SHA-256. It uses only public values from the auditor/admin evidence bundle: the canonical header, the audit path and the epoch records.

- **Checks:** the event hash, position, RFC 9162 inclusion, the epoch roots and their prev links, and the trust root.
- **What it doesn't check:** it does **not** query the chain. The anchor is shown "as claimed", and the page says the CLI checks it.
- **Who can see it:** approvers see the hash-chain checks but not the bundle-based explorer, because the bundle stays an auditor/admin read as in ADR-0031.
- **Part B:** the test that the browser result equals the server verifier result for every Phase 10 tamper case.

## Consequences

- One more layer of UI code. The single mapping table (`lib/status.ts`) and the single list component (`DataTable`) keep it consistent.
- The fallback in `globals.css` keeps the Phase 9 utility colors readable in dark mode until Part B deletes them with the old pages.
- Accessibility: axe reports 0 serious or critical findings on 13 pages × 2 themes plus login. Getting there meant fixes to the Radix-scale text pairs (step 11 on step 3 in light mode is about 4.2:1, so badges use step 12 text with tinted fill, border and icon).
- Remaining UX issues and Part B scope are listed in `docs/gateway/phases/phase-09.5-dashboard-redesign.md`.
