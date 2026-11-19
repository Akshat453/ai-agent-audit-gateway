# 16. Dashboard design: AgentGuard Console

> **Thesis:** cloud-console structure, modern product finish, evidence as the hero.
>
> - **Structure:** grouped side nav, filterable dense tables, split panels, detail pages with tabs.
> - **Finish:** calm neutral surfaces, one accent, crisp type, thin borders, real dark mode, keyboard-first.
> - **Hero:** tamper-evidence made visible: hash-linked timelines, Merkle proof paths, on-chain anchors.

Stack and CSP evidence are in ADR-0033; the audit of the old UI is in `screenshots/redesign/ux-audit.md`. The product name lives in one constant (`apps/dashboard/lib/brand.ts`). The branding is original: a shield-with-chain-link mark (`components/shell/logo.tsx`) and no third-party names or trade dress.

## 3. Visual system

### 3.1 Color

The colors are Radix Colors scales, exposed as CSS variables and Tailwind tokens (`app/globals.css`). Steps:

| Steps | Role |
|---|---|
| 1–2 | app background |
| 3–5 | component background, hover, active |
| 6–8 | borders |
| 9–10 | solid fills |
| 11 | low-contrast text |
| 12 | high-contrast text |

| Token | Scale | Used for |
|---|---|---|
| `gray-*` | slate | every neutral surface, border and text |
| `brand-*` | iris | primary buttons, active nav item, focus ring, links, selection. **Never status.** |
| `ok-*` | jade | VERIFIED, COMPLETED, FINALIZED, ALLOW, APPROVED, CONSUMED |
| `bad-*` | tomato | TAMPERED, INVALID_PROOF, UNTRUSTED_ANCHOR, DENY, DENIED, FAILED, REJECTED; risk CRITICAL |
| `warn-*` | amber | INCOMPLETE, PENDING_APPROVAL, OUTCOME_UNKNOWN, REQUIRE_APPROVAL, PENDING; risk MEDIUM |
| `high-*` | orange | risk HIGH |
| `info-*` | blue | risk LOW, SUBMITTED, INCLUDED, AUTHORIZED, DISPATCHED |
| `gray` (neutral state) | slate | UNANCHORED, SEALED, EXPIRED, CANCELLED, INVALIDATED |

**Rules:**

- **One mapping table.** `lib/status.ts` maps each status and risk level to a tone, an icon, a label and a plain-language explanation. `<StatusBadge>` and `<RiskBadge>` are the only status renderers.
- **Never color alone.** Every badge is icon plus text, and its tooltip explains it.
- **Contrast.** Badge **text uses step 12**: step 11 on step 3 measures about 4.2:1 in light mode, under AA. The tone comes from the tinted fill (3), the border (7) and the icon (11, which is non-text and only needs 3:1).
- **Solid fills** with text (approve, danger, count pills) use the step and text color that pass in each theme: light uses step 11 with white text; dark uses step 9–10 with near-black text.
- **Surfaces.** Light: app `gray-1`, sidebar `gray-2`, cards `gray-1` with a `gray-6` border. Dark uses the same steps from the dark scales. No pure black.
- **Text contrast.** Body text is step 12, secondary text step 11. axe checks WCAG AA in both themes in CI (e2e `a11y.spec.ts`).

### 3.2 Typography

Geist Sans for interface text; Geist Mono for ids, hashes, code and numbers in tables. The `geist` package is self-hosted through `next/font/local` (CSP `font-src 'self'`).

| Token | Size / line height | Use |
|---|---|---|
| `text-title` | 20/28 semibold | page title |
| `text-section` | 15/22 semibold | section and card title |
| `text-body` | 14/20 | body |
| `text-dense` | 13/18 | tables, dense UI |
| `text-caption` | 12/16 medium | labels, captions |
| `text-kpi` | 28/32 semibold, tabular-nums | KPI numbers |

Numeric columns use `tabular-nums` and are right-aligned. tailwind-merge is extended with these sizes (`lib/cn.ts`): otherwise it reads `text-body` as a text color and drops `text-white`, a real bug that axe caught.

### 3.3 Space, shape, depth, motion

- **Space:** 4 px grid (4/8/12/16/24/32/48).
- **Radius:** 6 px for inputs, buttons and cards; 4 px for badges; full for avatars.
- **Borders and shadows:** 1 px borders. Shadows only on overlays: menus, popovers, dialogs, the palette, toasts.
- **Motion:** 120–180 ms ease-out, opacity and transform only (`animate-in`, `animate-slide`). `prefers-reduced-motion` reduces all animation to 1 ms.

### 3.4 Density

Comfortable (default) gives 44 px table rows; compact gives 36 px. The toggle is in the user menu, and the choice is remembered per user in a cookie (`agw_density`). It is implemented as a `--row-h` CSS variable switched by `html.density-compact`.

### 3.5 Data formatting (`lib/format.ts`, `components/hash-chip.tsx`, `components/timestamp.tsx`)

- **Hashes and ids** are middle-truncated mono, e.g. `a3f9c1…7be2`. A copy button appears on hover or focus. The full value is in a popover, or, when it's an entity, the chip is a link whose accessible name holds the full id.
- **Timestamps** are relative ("3 min ago"), with the exact time in a tooltip. The server renders exact UTC first, so there is no hydration mismatch. The UTC or local toggle is in the user menu (`agw_tz`).
- **Durations** read "850 ms", "1.2 s", "4 min", "3.5 h". **Counts** use thousands separators.
- **Empty values** show an em dash (`—`) in muted text, never blank.

## 4. Layout and navigation

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ [shield] AgentGuard Console  (● tenant demo) [DEV]   [ Search or jump to…  Ctrl K ]  🔔3 ☾ (A) │ 48 px
├──────────────┬───────────────────────────────────────────────────────────────────────┤
│ Overview     │ Operations › Approvals                                                │
│ OPERATIONS   │ Approvals (?)                                    [primary] [⋯]        │
│  Runs        │ one-line description                                                  │
│  Approvals 2 │ ┌ filter: risk = HIGH ×  [/] ┐ [Columns] [Share view] ⟳ updated 3 s ago  │
│ EVIDENCE     │ (Pending)(Critical pending)(Consumed)…                                │
│  Events      │ ┌──────────────────────────────────────────┐ ┌── split panel ─────────┐ │
│  Epochs      │ │ Risk  Tool   Agent  Requested  Expires ↑  │ │ send_email@1.0.0  ↗ × │ │
│  Verification│ │ HIGH  send…  demo…  7 min ago  7:37       │ │ PENDING HIGH          │ │
│ GOVERNANCE   │ │ CRIT  upda…  demo…  7 min ago  7:37       │ │ why · target · args   │ │
│  Policies    │ └──────────────────────────────────────────┘ │ [Review and decide →] │ │
│ SECURITY     │ 1–2 of 2                 ‹ Prev  Page 1/1  Next › └──────────────────┘ │
│  Incidents   │                                                                       │
│ ● All normal │                                                                       │
│ « Collapse   │                                                                       │
└──────────────┴───────────────────────────────────────────────────────────────────────┘
```

**Top bar** (`components/shell/app-shell.tsx`):

- logo mark and product name;
- tenant pill;
- environment badge (amber, hidden when `env = prod`);
- search button that opens the palette;
- alerts bell with the count for the last 24 h;
- theme toggle;
- user menu: name, roles, step-up status with minutes left, density, timezone, keyboard shortcuts, log out.

**Side nav:**

- 240 px wide, collapsing to a 56 px icon rail; the state is remembered in the `agw_nav` cookie.
- Grouped as Overview, then Operations, Evidence, Governance and Security (`lib/nav.ts`).
- Items are filtered by role. Part B pages are hidden until they exist (`ready: false`), so the nav has no dead links.
- Approvals carries a live pending badge.
- The footer shows a health dot plus the version.

**Content:**

- Breadcrumbs, then the page header: title, "?" help, one-line description, and actions on the right.
- Fluid width; detail pages max 1280 px.

**Other panels:**

- **Help drawer (right):** plain-language explanation of the page plus every status it shows, from `lib/help.ts` and the status table.
- **Split panel:** selecting a row sets `?sel=` in the URL. The server renders the panel, which is resizable by drag or by Arrow keys on its handle, and has an "Open full page" link. Esc closes it.

**Command palette** (Ctrl/Cmd K, cmdk, code-split):

- jump to any visible page;
- paste a UUID (action, run, event or approval) or a hash or root prefix of at least 8 hex characters, which goes through `/api/search` to `GET /v1/dashboard/search`;
- quick actions: review pending approvals, run verification, toggle theme, show shortcuts.

**Keyboard:**

| Keys | Action |
|---|---|
| Ctrl/Cmd K | command palette |
| `/` | focus the table filter |
| `g` then `o`, `r`, `a`, `e`, `v`, `p`, `i` | navigate |
| `j` / `k` | move through table rows |
| Enter | open the row's split panel |
| Shift+Enter | open the row's full page |
| Esc | close a panel or dialog |
| `?` | shortcut sheet |

## 5. Pages

**Overview** (Part A, `app/page.tsx`):

```
[Actions (24 h) 31 ↗ +12% ~~] [Denied (24 h) 2 ~~] [Pending approvals 2 · oldest 7 min] [Evidence health ✓VERIFIED]
┌ Actions over time (stacked area by decision, 24h|7d|30d, legend, table) ┐ ┌ Risk distribution (bars) ┐
┌ Needs your attention (approvals by expiry, unknown outcomes, alerts) ┐   ┌ Evidence pipeline         ┐
                                                                            │ ● Recorded 181  oldest… │
                                                                            │ ○ Sealed 180            │
                                                                            │ ○ Anchored 180          │
                                                                            │ ○ Finalized 180         │
System health: (● gateway OK) (● database OK) (● worker 0 queued) (● anchoring) (● monitor VERIFIED)
```

Every tile, item and chip links to a filtered list or the entity. **Gap:** the risk bars aren't linked yet, because the Actions list is Part B.

**List pages** share one `<DataTable>` (`components/data-table.tsx`, TanStack Table v8 in manual mode):

- **Toolbar:**
  - token filters (`field = value`, chips with remove; an unknown field is explained, not ignored);
  - quick-filter chips; saved views are the URL plus a "Share view" button that copies it;
  - column visibility;
  - refresh with "updated N s ago".
- **Server-side work:** sort, filter and pagination all happen on the server. Filters, sort, page and the selected row live in the URL.
- **Polling:** every 10 s, or every 5 s on Approvals; paused when the tab is hidden.
- **States:** skeletons, a helpful empty state, and an error state with retry and the request id.
- **Bulk approve doesn't exist.**

**Approvals** (Part A):

- **List:** sorted by soonest expiry. Columns: risk, tool, agent, requested-by (delegation), requested, expires-in countdown, state, votes, id.
- **Detail:**

```
Approvals › 01a1e5…613e
Approval: send_email@1.0.0 (?)   [PENDING] [HIGH] requested 8 min ago
┌ You are approving ──────────────────────────────┐ ┌ Decision ──────────────────┐
│ Tool · Target (code view) · Environment · Agent  │ │ expires in 7:20 (amber <2m)│
│ Delegation · Policy → REQUIRE APPROVAL · votes   │ │ Action digest (mono)       │
│ Action ↗  Run ↗                                  │ │ [step-up form if CRITICAL] │
├ Risk (score, reasons as bullets) ────────────────┤ │ [✓ Approve exactly this …] │
├ Exact arguments (escaped JSON, TRUNCATED marker) ┤ │ [× Reject]                 │
└──────────────────────────────────────────────────┘ └────────────────────────────┘
```

- **Approve** opens a dialog that restates the run (tool, agent, environment, target, risk, digest, single use and expiry), with an optional signed reason.
  - CRITICAL also requires typing the last 6 characters of the action id, plus a valid step-up. The password form is inline; the gateway still enforces it (STEP_UP_REQUIRED).
- **Reject** needs a reason.
- The decision stays one plain HTML form (CSRF, digest, nonce); the dialog's button is its submitter.
- After a decision: an inline status message, a toast, and "Review next pending".

**Action detail** (Part A): header with status, risk and decision. A lifecycle stepper (Requested > Evaluated > Approval > Authorized > Dispatched > Completed | Failed | Unknown) with times; a waiting approval shows amber. Tabs: **Evidence timeline** (signature view 1), Overview, Related (run, delegation, approvals, epochs, anchors, events).

**Event detail** (Part A): header metadata; **proof explorer** (signature view 2; auditor/admin, because it reads the evidence bundle); header JSON (escaped); hash-chain checks; payload card ("Encrypted, available only through a disclosure grant", plus the digest); epoch card.

**Part B:** Runs, Actions list, Events, Epochs/Anchors, Verification, Policies (diff), Incidents and Alerts, Agents, Tools, Delegations, Disclosure grants, and the tamper demo (signature view 3).

## 6. Signature views

1. **Evidence timeline** (`components/evidence/timeline.tsx`):
   - **Nodes:** each shows the event type, sequence number, time, risk, decision or status, short hash, "sealed in epoch N" and the anchor status.
   - **Connectors:** `#N.prev = hash #N−1 (abcd…)`, with both full values in a tooltip. A solid jade connector means the link holds; a **red dashed** one is broken, with the reason ("this record was edited" / "stored hash changed").
   - **Interleaved events:** events of other actions between two nodes are counted on the connector.
   - **Source of the checks:** `hash_ok` and `link_ok` come from the gateway, which recomputes them from the stored bytes.
   - **Readable copy (ADR-0038):** `stored_copy_ok` says whether the `body` copy and the indexed columns still equal the sealed record; the values shown are always decoded from the sealed bytes, never from `body`.
   - **Plain English:** the event page opens with a "What happened" card and every timeline step has a one-line sentence (`lib/explain.ts`); the raw sealed record stays below it.
2. **Proof explorer** (`components/evidence/proof-explorer.tsx`, `lib/merkle.ts`):
   - **Path:** leaf, then each sibling (left or right) up to the Merkle root, then the epoch root, then later epochs (each committing to its predecessor), then the anchor (chain, contract, tx, block, finality).
   - **Ticks:** every step is recomputed in the browser with Web Crypto from public values only, and gets a pass or fail tick.
   - **Label:** "Visual check. The CLI is the authoritative verifier."
3. **Tamper demo** is Part B: dev only, admin only, demo tenant only, otherwise 404.

## 7. UX principles (review checklist)

- **Every status explains itself** (tooltip and help drawer).
- **No dead ends.** Ids, hashes, agents, epochs and transactions link to their entity, or show the full value with copy.
- **Dangerous actions confirm and restate.** Nothing irreversible happens on a single click, and there is no approve button in lists.
- **Live data:**
  - list pages poll every 10 s, Approvals every 5 s;
  - polling pauses while the tab is hidden;
  - "updated N s ago" is shown.
- **Optimistic UI only for preferences;** never for approvals.
- **Errors** say what happened and what to do, with the request id.
- **Responsive:** fully usable down to 1024 px. Below `md` the side nav hides (the palette remains), and below `lg` the split panel hides ("Open full page" through Shift+Enter or the id link). Read-only views and approvals work on a 768 px tablet.

## 8. Accessibility (WCAG 2.2 AA)

- Keyboard reachable everywhere, with a visible iris focus ring (`:focus-visible`) and a skip link to `#main`.
- Landmarks: banner, `nav` "Main", `main`, `complementary` for details and decision. Icon-only buttons have aria-labels.
- Charts have a text summary (sr-only) and a "Show as table" view.
- Dialogs trap and restore focus (Radix). The palette is a dialog.
- Tabs are WAI-ARIA, with roving tabindex and arrow keys.
- Reduced motion is respected.
- **Verification:** `e2e/a11y.spec.ts` runs axe (wcag2a and wcag2aa) on login plus 13 pages, in light **and** dark. Result: zero serious or critical findings.


## Plain-English layer (ADR-0039)
- **Views.** Simple view (default) and Technical view. The `agw_view` cookie is switched from the user menu or the page-header toggle.
- **Simple view.** Each page opens with a plain headline. Detail pages add the "What happened / Why / Who / What you can do" block; the technical content folds under "Technical details" on the same page.
- **Technical view.** Today's layout plus the summary line.
- **Words.** All user-facing words for technical concepts come from `apps/dashboard/src/humanize/`.
- **Inventory.** `docs/gateway/console-field-inventory.md` lists what must never disappear; `e2e/inventory.spec.ts` enforces it.
