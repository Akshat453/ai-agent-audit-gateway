# Phase 1 — Core Execution Gateway

Status: **Done**, 2026-11-15. This record was backfilled during Phase 2 from the Phase 1 report.
Backlog: [14-phase-1-handoff.md](../14-phase-1-handoff.md).

## What was built

| Area | Where |
|---|---|
| Repo, tooling | uv workspace (`pyproject.toml`, `uv.lock`), ruff, mypy (strict on the gateway), pytest, import-linter, `Makefile` (`up down migrate lint test demo`), `docker-compose.yml` (Postgres 16 on host port 54329), `.env.example`, `.github/workflows/ci.yml` |
| DB roles | `infra/docker/postgres/{roles.sql,init/01-roles.sh}`: `agw_migrator` (owner) and `agw_app` (least privilege) |
| Schema | `apps/gateway/migrations/versions/0001_phase1_core.py`: 11 tables, grants, append-only triggers on `evidence_events` and `policies`, default policy v1 seed |
| Gateway | `apps/gateway/src/agw_gateway/`: `auth/` (hashed API keys), `tools/` (registry, 3 demo adapters), `risk/` and `policies/` (pure), `execution/` (tx1 + idempotency, outbox executor, reconciler, crash hooks), `evidence/` (writer), `api/` (endpoints, uniform errors, log allow-list), `admin.py` |
| Clients | `packages/gateway-sdk` (`agw_sdk.Client`), `examples/single-agent` (scripted agent, optional `--llm` agent) |

Endpoints: `POST /v1/actions`, `GET /v1/actions/{id}`, `GET /v1/tools`, `GET /v1/runs/{id}/timeline`, `GET /v1/health`, `GET /v1/ready`.

## Decisions

| Decision | Why | Record |
|---|---|---|
| Validated args kept in `outbox_jobs.args` until the job finishes | The executor needs durable args; no payload store existed yet | [ADR-0020](../adr/0020-phase1-dispatch-args-in-outbox.md) |
| Compose Postgres on host port 54329 (`AGW_PG_HOST_PORT`), `AGW_DEMO_CORPUS_DIR` | 5432 was taken locally; the corpus path had to be configurable | 00 §7 |
| Idempotent tools re-dispatched at most 3 times, then `OUTCOME_UNKNOWN` (`RETRIES_EXHAUSTED`) | Bound retries even for idempotent tools | executor/reconciler code |
| Adapter timeout → `OUTCOME_UNKNOWN` | No adapter guarantees "no effect on timeout" (08 §8) | executor code |
| Hand-written `uuid7()` | Python 3.12 has no `uuid.uuid7` | `ids.py` |

## Results
`make up && make migrate && make test && make demo` passed from a clean state: 140 tests, 97% coverage on policies/auth/tools/execution. 10 of 10 mutation checks were caught, after one weak test (input echo on path-parameter 422s) was strengthened.

## Known gaps carried forward
- Tests-first was not followed strictly; mutation checks were used as the substitute evidence.
- Tool enablement is read once at startup.
- A late adapter result after the reconciler has recorded `OUTCOME_UNKNOWN` is dropped (resolution belongs to the approvals/reconciliation phase).
- CI and the `--llm` agent have not been run.
