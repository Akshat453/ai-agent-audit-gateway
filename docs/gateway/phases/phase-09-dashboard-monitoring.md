# Phase 9: Audit dashboard + monitoring

Status: implemented 2026-11-16 · ADR: [0031](../adr/0031-phase9-dashboard-monitoring.md) · Not committed (the owner commits).

## 1. What changed

| Area | Change |
|---|---|
| `apps/dashboard` (new) | Next.js 16 App Router, TypeScript strict, Tailwind 4. A backend-for-frontend: the browser talks only to the dashboard. `proxy.ts` sets the nonce CSP. `lib/session.ts` holds the `__Host-` httpOnly cookie, the HMAC CSRF token and the same-origin check. `lib/gateway.ts` is the openapi-fetch client over the generated `lib/api/schema.d.ts`. Screens: login, overview, runs, run timeline (delegation tree, approvals, epoch/anchor per event), approval center + detail (escaped args with a truncation marker, expiry countdown, digest + nonce echo, step-up), evidence explorer, epochs & anchors, verification, policies (diffs), incidents (export, reconcile). Route handlers: login/logout/step-up, decision, verification request, bundle and incident downloads, reconcile. `Dockerfile` (standalone, pinned by digest). |
| Gateway: dashboard API | `api/dashboard_routes.py`: human sessions only, tenant-scoped, never payloads (§3 of ADR-0031). `openapi.py` dumps the schema for client generation. |
| Gateway: step-up | `POST /v1/auth/step-up`. `human_sessions.stepped_up_at`. Approving a CRITICAL action needs a step-up within 300 s (gateway-enforced, `STEP_UP_REQUIRED`). `agw-approve` steps up automatically. |
| Gateway: reconciliation | `execution/manual_reconcile.py`, `POST /v1/actions/{id}/reconcile` (admin): OUTCOME_UNKNOWN becomes ACTION_RECONCILED (A2H) with the observation and justification. Never retried. |
| Gateway: traces | `tracing.py`: OTel SDK, off by default. An allowlisted `span()` helper plus an `AllowlistExporter` that strips everything else. Spans: `http.request`, `action.decision`, `action.dispatch`, `monitor.verify`. |
| Worker: monitoring | `agw_worker/monitoring/`: runs the independent `agw_verifier` over every tenant's exported chain and epochs (plus on-chain checks). Compares anchor roots and checks ages, OUTCOME_UNKNOWN and gaps. Writes VERIFICATION_REPORT to the `_monitor` chain, `monitor_reports` and `monitor_alerts`. Alerts go to the log and an HMAC-signed webhook. Picks up dashboard requests (`monitor_requests`) about every 1 s. Prometheus metrics. |
| Schemas / verifier | Event types VERIFICATION_REPORT (SYS) and ACTION_RECONCILED (A2H). Header key `report`; payload sections `report` and `reconciliation`. `TenantId` admits the reserved `_monitor`. The verifier allowlist gains `report`. |
| Migration | `0010_phase9_monitoring`: `_monitor` tenant and chain, `monitor_reports`, `monitor_alerts`, `monitor_requests`, `stepped_up_at`, event types. |
| Infra | Compose profile `ui` (`ui-init`, `ui-gateway`, `ui-worker`, `ui-mcp`, `ui-demo`, `ui-dashboard`; database `agw_ui`). Compose profile `monitoring` (Prometheus, Grafana; pinned). `infra/docker/ui/*`, Dockerfile `runtime` target, `infra/prometheus`, `infra/grafana` (dashboard JSON + provisioning). |
| Tooling | Make targets `dashboard-api`, `dashboard-check` (OpenAPI/types drift + tsc), `dashboard-e2e`, `ui-up`, `ui-screenshots`, `monitoring-mutations`. `.env.example` Phase 9 block. |
| Docs | ADR-0031, this file, `docs/gateway/screenshots/` (12 PNGs), and updates to 03 (T29–T31, T21), 05, 06 (tag `AGW/monitor-report/v1`), 11, 13, README, ADR index. |

## 2. Decisions (details in ADR-0031)
1. **Dashboard = BFF.** The session lives only in a `__Host-` httpOnly Secure SameSite=Strict cookie. Every POST needs an HMAC synchronizer token **and** a same-origin check. The CSP is strict with a nonce, no `unsafe-inline` or `unsafe-eval`, and no inline style attributes.
2. **No payloads on any dashboard endpoint.** Approvers see args only in the approval view, because they must see what they approve. Payloads stay behind disclosure grants.
3. **The monitor runs the independent verifier,** in the worker. The API process never imports the verifier: the dashboard's "Run verification now" queues a request.
4. **VERIFICATION_REPORT lives in the reserved `_monitor` tenant** (ADR-0019), with the report digest in the header and the full report as the encrypted payload.
5. **Step-up for CRITICAL approvals** and **reconciliation** are enforced by the gateway; the UI only hides controls.
6. **Traces are off by default.** When on, two layers keep them to allowlisted attributes.
7. **The `ui` profile uses its own database (`agw_ui`)** and fails closed on missing secrets inside the containers. Compose interpolates every profile, so it cannot use `:?`.

## 3. Work done: required tests

| Requirement | Test(s) | Result |
|---|---|---|
| Playwright: login, approve flow, reject flow, expired approval shows expired | `e2e/auth.spec.ts`, `e2e/approvals.spec.ts` (also: CRITICAL step-up flow) | pass |
| Auditor cannot approve; approver cannot see payloads without a grant | Playwright `security.spec.ts` (no form; a forged POST with a valid CSRF token gets FORBIDDEN from the gateway; no bundle link, `/api/bundles` refused, no arg value on the evidence page). pytest `test_auditor_cannot_approve_and_approver_cannot_read_payloads` (real grant → `NOT_GRANTEE`; bundle → `ROLE_REQUIRED`), `test_no_payload_or_arg_values_in_any_dashboard_response` (canary across 9 endpoints × 3 roles) | pass |
| XSS: malicious args/results render escaped | Playwright `XSS` spec (`<img onerror>`, `<script>`; no img/script elements, no dialog, `window.__xss` undefined, truncation marker shown) | pass |
| CSRF on the decision endpoint rejected without a token | Playwright `CSRF` spec (no token → 403 `CSRF_TOKEN_INVALID`; wrong token → 403; cross-site Origin → 403 `CROSS_SITE_REQUEST`; approval still PENDING) | pass |
| Monitoring detects an injected DB tamper within one cycle and raises an alert | `test_db_tamper_detected_within_one_cycle_and_alerted` (one header byte flipped by a superuser; the next single run → TAMPERED at the right seq; VERIFICATION_FAILED delivered to the webhook with a valid HMAC), plus `test_tamper_in_unsealed_tail_detected_by_chain`, `test_anchor_root_mismatch_alert`, `test_sequence_gap_alert`, `test_operational_alerts`, `test_outcome_unknown_alert`, `test_no_age_alerts_below_thresholds`, `test_dashboard_requested_run`, `test_clean_tenant_verifies_and_report_is_evidence` | 9 pass |
| Lighthouse/axe basic accessibility on the main screens | Playwright `a11y.spec.ts`: axe WCAG 2 A/AA on login + 10 screens, no serious/critical violations, and no CSP violations or page errors | pass (axe only; no Lighthouse run) |

Also tested:
- Dashboard API (8): agent keys get 403 + violation; tenant scoping; run timeline with the delegation tree; step-up (missing, wrong password, expired window); reconcile (role, once only, no retry, evidence); tracing allowlist with a hostile span and canaries.
- The Playwright suite also checks the cookie flags, empty localStorage/sessionStorage, the CSP header and logout.

**Mutation check** (`make monitoring-mutations`): **13/13** caught (`experiments/monitoring/results/mutations.txt`). The first run caught 11. The 2 survivors were weak tests, which I strengthened:
- a tampered unsealed tail in a windowed run, which only the chain check sees;
- an age test with a 1.2 s item against a 5 s threshold.

## 4. Acceptance
`docker compose --profile ui up --build` on a clean stack:
- `ui-init`: database agw_ui, migrations 0001–0010, contract on Anvil, tenant demo.
- `ui-demo` exit 0: LLM agent, `MULTI-AGENT (sdk) OK`, `MULTI-AGENT (mcp) OK`, then a pending HIGH email, a pending CRITICAL IAM change and a DENIED delete for the dashboard.
- The worker anchored every epoch (5 FINALIZED) and the monitor recorded VERIFIED reports in the `_monitor` chain.
- The dashboard serves at http://localhost:3000.

Screenshots: `docs/gateway/screenshots/01-login … 11-incidents.png` (`make ui-screenshots`).

## 5. Commands run
- **Clean state.** `docker compose --profile ui --profile monitoring down -v`; `.env` (identical to `.env.example`) and `.venv` removed. Then `make up && make migrate && make test && make demo && make dashboard-check && make dashboard-e2e`:
  - migrations 0001 → 0010;
  - ruff clean; mypy no issues in 125 source files; 8 import contracts kept;
  - **830 passed**; coverage 89% overall, 92% gated, 100% risk.
- **First demo run: FAILED** at `MULTI-AGENT (sdk)`. The cause was an orphaned gateway from an earlier e2e run: `e2e/run.sh` killed the `uv run` wrapper but not its python child, so a gateway with an in-process executor and no SMTP config kept claiming outbox jobs from the shared dev database (the email failed with `TOOL_UNAVAILABLE`). Fix: `run.sh` now also kills whatever listens on its two ports, and I verified no process is left afterwards. After killing the orphans, `make demo && make dashboard-check && make dashboard-e2e` → exit 0: all demo phases OK, `MULTI-AGENT OFFLINE VERIFICATION OK (38/38 VERIFIED)`, Playwright **10 passed**.
- **Also fixed during the phase:** a units bug in the monitor (unsealed age in ms compared with a threshold in seconds), found because the `ui` stack raised a false UNSEALED_AGE alert. I added a test and a mutation for it.
- **Docker disk full.** During the phase the Docker VM ran out of disk. I removed only the Docker **build cache** (`docker builder prune`, 13.5 GB). No images or volumes were touched: other projects' containers share this Docker.

## 6. Known gaps
- **Monitoring stream not anchored.** The `_monitor` chain is sealed but not anchored until an operator registers a recorder for it.
- **Monitor scope.** The monitor cannot see a truncated unsealed tail (03 R2) or semantic falsehood.
- **Full-chain verification each cycle.** The monitor re-verifies the whole chain every cycle (capped by `AGW_MONITOR_MAX_EVENTS`). Incremental checkpoints are a follow-up.
- **No OUTCOME_UNKNOWN in the UI demo data.** Producing one needs a crash. Reconciliation is covered by pytest and the incidents UI.
- **Prometheus/Grafana not exercised.** The `monitoring` profile was validated with `docker compose config` only; Prometheus scraping and the Grafana dashboard were not run in this session.
- **Accessibility.** axe only, no Lighthouse; only serious/critical findings are gated.
- **Dashboard server compromise.** It would expose live session cookies, but no tool credentials or KEK.
- **Plain HTTP on localhost only.** The dev stack serves plain HTTP on localhost (Secure cookies are allowed there); any other deployment needs TLS.
