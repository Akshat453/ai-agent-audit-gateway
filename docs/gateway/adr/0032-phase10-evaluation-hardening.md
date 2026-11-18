# ADR-0032: Phase 10 evaluation harness, ablation flags, rate and size limits

Status: Accepted · Date: 2026-11-16 · Deciders: Phase 10 implementation (pending owner review)

## Context

The Phase 10 prompt asks for:
- reproducible experiments RQ1–RQ7, run on ONE codebase with feature flags for the ablation configurations C0–C6;
- hardening: dependency, code, container and secrets scans, rate limiting, request size limits, adapter timeouts, a DB least-privilege review and a backup/restore drill;
- CI, and a write-up (`docs/gateway/research/results.md`).

**Docs and the prompt disagree here:**
1. **Ablation ladder.** 10 §5 plans Paper B's cumulative ladder (Baseline ⊂ Schema ⊂ Chain ⊂ Merkle ⊂ Full) extended with gateway layers. The prompt defines C0–C6 (plain → authorization → CBOR events → chain + Merkle → fixed anchoring → adaptive → approvals + CRITICAL pre-anchor). The prompt's ladder is used, and 10 §5 is updated to point here. Paper B's "Schema" step is our C2. "Chain" and "Merkle" are not separable in our design, because sealing needs a chain, so they form one step, C3.
2. **Experiment layout.** 10 §5 lists `benchmarks/...`, `risk/...` and `ablations/` directories. The harness is `experiments/rq1_latency … rq7_audit`, one command each (`make rqN`). The older Phase 2–9 experiment directories remain as they were.
3. **RQ6 "real agents".** No hosted LLM is called. CI has no credentials, and the gateway is what is under test, not the model. The agents are real LangGraph graphs, with MCP and SDK transports, driven by the deterministic, gullible `MockLLM`, which already exists since Phase 8. This is a threat to validity and is stated in results.md.
4. **RQ5 "network partition".** Neither toxiproxy nor iptables is available on the development machine (macOS Docker Desktop). The partition is a `docker pause` of the database container: TCP stays established and nothing answers, which is the worst case for a client.

## Decision

### 1. Ablation flags: one codebase, dev/test only

`AGW_ABLATION ∈ {C1..C6}` (unset = production behaviour = C6). Settings validation refuses the flag unless `AGW_ENV ∈ {dev, test}`, so production always runs the full system.

| Config | Gateway authZ | Evidence writer | Hash chain | Sealing | Anchoring | Approvals | CRITICAL pre-anchor |
|---|---|---|---|---|---|---|---|
| C0 | no (tool called directly) | – | – | – | – | – | – |
| C1 | yes | `none` (no events) | – | – | – | off: REQUIRE_APPROVAL → ALLOW, rule `ABLATION-NO-APPROVAL` | off |
| C2 | yes | `records` (CBOR headers, `prev` = 0³²) | no | – | – | off | off |
| C3 | yes | `chain` | yes | fixed 100 | – | off | off |
| C4 | yes | chain | yes | fixed 100 | fixed interval | off | off |
| C5 | yes | chain | yes | risk-adaptive | risk-adaptive | off | off |
| C6 | yes | chain | yes | risk-adaptive | risk-adaptive | **on** | **on** |

- **Where the flags act.** The gateway reads the flag in `build_state`, which selects the writer mode, the gate rules and `ActionService(no_approvals=…)`. The worker reads it in `__main__`: no sealer for C1/C2, a fixed policy for C3/C4, no anchorer for C1–C3.
- **Delegation** needs evidence, so it is unavailable in C1.
- **Stage timers.** `agw_gateway.timing` records per-stage durations (auth, risk, policy, durable_write, dispatch_tx, adapter, result_tx, seal) only while the harness enables it. It is off by default and costs one boolean check per stage.
- **Reporting.** Security-control effects (C0 vs C1, C5 vs C6 in RQ4) are reported separately from evidence effects (C1 → C2 → C3 in RQ1, C4 vs C5 in RQ2).

### 2. Harness conventions (`experiments/`)

- One command per experiment (`make rq1` … `make rq7`, `make experiments`).
- A committed `config.toml` with fixed seeds.
- Results go to `experiments/<rq>/results/`: raw CSV, a summary CSV recomputed from the raw CSV, and `env.json` (CPU, RAM, OS, Python, Docker, Postgres image, git commit if available).
- Figures come only from the CSVs (`make plots`).
- Statistics: mean over ≥ 5 runs, with a 95 % percentile bootstrap CI (2,000 resamples, seeded).
- Latency samples keep EVERY request: a fail-closed 503 is an answer too and stays in the percentiles. RQ1 also reports the error rate and throughput.
- The C0 baseline for RQ1 is an in-process call of the same no-op tool. C0 for RQ4/RQ6 is the agent calling the adapters directly.

### 3. Rate limit and body size limit (hardening)

- **Implementation.** Both are plain ASGI middleware (`api/limits.py`) outside routing, so they act before authentication, body parsing and every endpoint.
- **Body size.** A declared `Content-Length` above `AGW_MAX_BODY_BYTES` (256 KiB) gets 413 `PAYLOAD_TOO_LARGE` at once. A chunked body is read up to the limit + 1 byte; above that it gets 413.
  - Before Phase 10, only `POST /v1/actions` enforced the limit. Login, approval decisions, delegations and token exchange read unbounded bodies.
- **Rate limit.** A token bucket per credential (`AGW_RATE_LIMIT_PER_MINUTE` = 600, `AGW_RATE_LIMIT_BURST` = 60).
  - The key is SHA-256 of the `Authorization` header, so the raw credential is never stored. Without a header, the key is the client address.
  - Exceeding the limit gets 429 `RATE_LIMITED` with `Retry-After`.
  - Health, readiness and metrics are exempt.
  - At most 50,000 buckets are kept (LRU), so random credentials cannot exhaust memory.
  - The state is per process: N replicas allow N × the rate. A shared limiter (Redis or the edge proxy) is the production follow-up.
  - Set to 0 to turn it off; the experiments do this so they measure the gateway rather than the limiter.

### 4. Scanners and CI

- **`make hardening-ci`** (and a CI job) runs pip-audit (on the exported lock), npm audit and bandit. It fails on any known-vulnerable dependency or any MEDIUM/HIGH bandit finding.
- **Reviewed bandit findings.** Bandit doesn't honour ruff's `noqa`, so the three reviewed false positives also carry `# nosec <id>` with the reason.
- **`make hardening`** adds, with scanners pinned in `experiments/hardening/run.py`:
  - semgrep;
  - gitleaks (Docker, directory mode);
  - trivy over the built images;
  - Slither;
  - the DB grants review;
  - the backup/restore drill.
- **CI jobs:** lint (incl. integrations mypy), unit (3.12/3.13), integration + coverage gates, contracts (Foundry image), vectors checked by both implementations + verifier isolation, e2e smoke (compose + demo + dashboard drift), dependency/code audit, gitleaks.
- **Experiments workflow.** `experiments.yml` runs any RQ on `workflow_dispatch` only and uploads the results.

## Consequences

- One flag changes behaviour in security-relevant places. That is acceptable only because it is refused outside dev/test (tested: `test_ablation_refused_in_prod`).
- Rate limiting is per process; the edge proxy should still limit by IP.
- RQ6 shows integration behaviour, not LLM behaviour.
- `make start` / `make stop` start and stop the whole `ui` stack while keeping its data. The compose Anvil now persists its chain state in the `agw-anvil` volume.
  - Before this, Anvil's state lived in memory only, so a stop/start lost the contract.
  - The pinned demo tenant then (correctly) refused to re-pin to the redeployed contract, and `ui-init` failed.
  - `make down` still wipes everything.
- The partition result (RQ5) shows a gap: there is no client-side DB query timeout, so requests block while a database is frozen. The design is still fail-safe, because nothing executes without its committed evidence. The finding and follow-up are in results.md.
