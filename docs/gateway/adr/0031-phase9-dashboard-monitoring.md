# ADR-0031: Phase 9 audit dashboard, monitoring evidence stream, reconciliation, step-up, traces
Status: Accepted · Date: 2026-11-16 · Deciders: Phase 9 implementation (pending owner review)

## Context
The Phase 9 prompt asks for six things:
- a Next.js + TypeScript + Tailwind dashboard over the existing API, with human sessions, CSRF protection, a strict CSP and a typed client generated from OpenAPI;
- screens for overview, runs, the approval center, evidence, epochs and anchors, verification, policies and incidents;
- a monitoring service writing VERIFICATION_REPORT evidence (Paper A §5), with alerts, Prometheus and Grafana;
- OpenTelemetry traces with an attribute allowlist;
- a reconciliation UI for OUTCOME_UNKNOWN;
- `docker compose --profile ui up` showing the Phase 8 demo.

**Docs and the prompt disagree here:**
1. **Missing docs.** The prompt says to read `07-approval-security.md` and `10-privacy-and-storage.md`. Neither exists. Approval security is ADR-0027 + 04 §5; privacy is 07 (key management and privacy) + ADR-0029. Those were used.
2. **Event name.** ADR-0019 / 05 §3 name the monitoring event `MONITOR_REPORT`. The prompt calls it VERIFICATION_REPORT, and that name is used; `MONITOR_REPORT` was never written. The reserved tenant `_monitor` (ADR-0019) is used as specified, which needs the tenant-id CHECK and the header `TenantId` pattern to admit exactly this one reserved id.
3. **Traces.** Phase 7 asserted "no OTel SDK installed" (ADR-0029 §8). Phase 9 installs the SDK but keeps it OFF by default; the canary test now asserts the no-op provider by default, plus a new allowlist test with tracing ON.
4. **Roadmap.** Roadmap row 9 says the dashboard is read-only with no write endpoints. The prompt adds approve/reject, step-up, verification requests and reconciliation. These are thin forms over gateway endpoints that already exist or are added here. Policy changes remain read-only.
5. **ACTION_RECONCILED.** 05 §3 lists it for "Phase 4" (not built then). It is built now: operator-recorded only, no automatic probe.

## Decision

### 1. Dashboard architecture (apps/dashboard, Next.js 16 App Router, TS strict, Tailwind 4)
- **Backend-for-frontend.** The browser talks ONLY to the dashboard; server components and route handlers call the gateway with `Authorization: Session <token>`. The gateway URL never reaches the browser.
- **Session.** The gateway session token is stored only in a `__Host-agw_session` cookie (httpOnly, Secure, SameSite=Strict, Path=/). Nothing is in localStorage or sessionStorage; Playwright asserts this.
- **CSRF.** Every state change is an HTML form POST to `/api/...` and must pass three independent checks:
  1. a synchronizer token `HMAC-SHA256(AGW_DASHBOARD_SECRET, "agw-dashboard-csrf/v1\0" || session token)`, rendered into the form;
  2. a same-origin check (`Origin`, or `Sec-Fetch-Site: same-origin` when the browser sends `Origin: null`);
  3. SameSite=Strict.

  Missing or wrong token → 403 `CSRF_TOKEN_INVALID`; cross-site → 403 `CROSS_SITE_REQUEST`. The gateway's own endpoints use header auth, not cookies, so they are not CSRF-able.
- **CSP.** Strict, with a per-request nonce (Next 16 `proxy.ts`):
  - `script-src 'self' 'nonce-…' 'strict-dynamic'`, `style-src 'self' 'nonce-…'`;
  - `default-src 'self'`, `connect-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`, `frame-ancestors 'none'`;
  - no `unsafe-inline` and no `unsafe-eval` in production;
  - no inline `style=` attributes anywhere.

  Static headers: nosniff, X-Frame-Options DENY, `Referrer-Policy: same-origin` (`no-referrer` made Chrome send `Origin: null` on form posts), COOP/CORP same-origin, `Cache-Control: no-store`.
- **Escaping.** All untrusted text is rendered by React, never with `dangerouslySetInnerHTML`, inside `<pre>` blocks with an explicit `[TRUNCATED: showing N of M characters]` marker.
- **Roles.** Every role check is the GATEWAY's; the UI only hides controls.
- **Typed client.** `python -m agw_gateway.openapi` dumps the schema (the running gateway still serves no `/openapi.json`). `openapi-typescript` generates `lib/api/schema.d.ts`, and `openapi-fetch` is the client. `make dashboard-check` fails on drift.

### 2. Dashboard API (gateway, human sessions only, tenant-scoped, never payloads)
- **Endpoints.** `GET /v1/dashboard/{config, overview, runs, runs/{id}, events, events/{id}/bundle, epochs, policies, incidents, incidents/export, verifications, verifications/{id}, alerts}`, `POST /v1/dashboard/verifications`, `POST /v1/actions/{id}/reconcile`, `POST /v1/auth/step-up`.
- **Read endpoints.** Any human role. Bundle download and incident export (payload-free bundles) need auditor/admin; verification requests need auditor/admin; reconciliation needs admin.
- **No payloads.** Responses carry headers and operational metadata only. Approvers see args only in the approval view, by design (they must see what they approve). Payloads remain behind disclosure grants (ADR-0029).

### 3. Monitoring (agw_worker.monitoring)
For every tenant, the worker exports the chain (headers) and epochs and runs the INDEPENDENT verifier (`agw_verifier.verify_lines`, `verify_epochs`; on-chain `verify_epochs_on_chain` when a chain RPC is configured).
- **Anchors.** DB anchor roots are compared with DB epoch roots.
- **Operational checks:**
  - oldest unsealed event;
  - oldest sealed-but-unfinalized epoch;
  - OUTCOME_UNKNOWN count;
  - oldest pending approval;
  - sequence gaps.
- **Record.** One transaction writes VERIFICATION_REPORT (SYS) into the `_monitor` chain: header `report {tenant, first, last, result, digest = H(TAG("AGW/monitor-report/v1") ‖ cbor(report)), alerts, trigger}`, and the full report as the encrypted payload. It also writes `monitor_reports` and `monitor_alerts` rows.
- **Alerts.** A structured log line plus an optional webhook (HMAC-SHA256 `X-AGW-Signature`), with a per-(tenant, kind) cool-down; critical alerts are never suppressed.
- **Dashboard runs.** "Run verification now" inserts a `monitor_requests` row, and the worker picks it up within about 1 s. The API process does not contain the verifier (ADR-0016 independence).
- **Locally sealed epochs.** Without anchoring for a tenant, the verifier's UNANCHORED epoch result is expected ("verified locally") and does not fail the report.
- **Units.** Ages are integer milliseconds (CBOR has no floats).
- **Metrics.** Bounded labels only: `agw_monitor_runs_total{result}`, `agw_monitor_alerts_total{kind}`, and age/count gauges. Prometheus config and a Grafana dashboard JSON are in `infra/`, behind the compose profile `monitoring`.

### 4. Step-up for CRITICAL approvals (gateway-enforced)
- **Rule.** APPROVE of an action whose risk level is in `AGW_STEP_UP_LEVELS` (default CRITICAL) needs `human_sessions.stepped_up_at` within `AGW_STEP_UP_WINDOW_SECONDS` (default 300), else 403 `STEP_UP_REQUIRED`. The age is computed by the DB clock.
- **Endpoint.** `POST /v1/auth/step-up {password}` re-verifies the password (Argon2) for the current session.
- **Rejects.** REJECT never needs step-up.
- **Other clients.** `agw-approve` steps up automatically for CRITICAL approvals.

### 5. Reconciliation (ADR-0011 unchanged: never auto-retry)
- **Who and what.** An admin records `observed ∈ {COMPLETED, FAILED, NOT_EXECUTED}` with a justification of at least 10 characters.
- **Effect.** One transaction writes ACTION_RECONCILED (A2H, actor = the human; header `outcome {status, code: RECONCILED_<observed>}`; payload `reconciliation {observed, justification, by}`) and sets the action COMPLETED or FAILED.
- **Constraints.** Only from OUTCOME_UNKNOWN, and only once. No outbox job is ever created.

### 6. Traces
`AGW_OTEL_ENABLED` (default false) turns on OTLP/HTTP export (or the console). Two layers keep content out of traces:
1. **Helper.** `tracing.span()` keeps only allowlisted scalar attributes: ids, codes, enums, `http.method/route/status_code`.
2. **Exporter.** `AllowlistExporter` re-creates every span with only allowlisted attributes and no events or links, so a span from any other library cannot leak either.

There is no automatic HTTP instrumentation (it would record URLs and headers).

### 7. Compose profile `ui`
- **Images.** A Python `runtime` image (all workspace packages + examples + contract artifact) runs init, gateway, worker, MCP and demo. A Node standalone image (pinned by digest) runs the dashboard.
- **Database.** A separate database, `agw_ui`, in the same Postgres, so the stack does not collide with host demos.
- **Init.** Applies the same per-database privileges as roles.sql, then migrates, generates dev keys into a private volume, deploys the contract on Anvil (Anvil's public test mnemonic, dev only), seeds the demo and registers the recorder.
- **Demo.** Replays the Phase 8 demo and leaves pending work for the UI.
- **Fail closed.** Compose interpolates every profile, so the profile's secrets use `:-` and the containers fail closed (init refuses an unset demo password; the dashboard refuses a short secret; Grafana refuses an empty admin password).

## Consequences
- **Two identity paths.** The dashboard is a confidential BFF: compromise of the dashboard server exposes live sessions (cookies) but no tool credentials or KEK.
- **Monitor scope.** The monitor detects edits, reorders, gaps and anchor mismatches in what it can read; it cannot detect a truncated unsealed tail (03 R2) or semantic falsehood (Paper A §5). Its reports are evidence of what was checked, not of correctness.
- **Monitor stream anchoring.** The `_monitor` chain is sealed like any tenant but is not anchored unless a recorder is registered for it (operator step; left as a follow-up).
- **Accessibility.** The axe checks cover WCAG 2 A/AA serious and critical findings on the main screens. This is not a full Lighthouse audit.
