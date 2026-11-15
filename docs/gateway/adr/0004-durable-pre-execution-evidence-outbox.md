# ADR-0004: Durable pre-execution evidence via transactional outbox
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
If authorization evidence is "queued in memory" and the process crashes after the side effect, the side effect is unevidenced. Neither paper specifies durability ordering.
## Decision
`ACTION_AUTHORIZED` and the DISPATCH `outbox_jobs` row commit in the **same** Postgres transaction as `ACTION_REQUESTED`/`POLICY_EVALUATED` (tx1), before any tool side effect. The executor claims jobs with `FOR UPDATE SKIP LOCKED` and commits `ACTION_DISPATCHED` before calling the adapter. The outbox row is the source of truth, including for the Phase 1 in-process executor.
## Consequences
+ Every side effect is preceded by two durable records (authorized, dispatched). + No message broker or dual write.
− Throughput bound by Postgres. Measured in Phase 8.
## Alternatives rejected
In-memory queue, Celery/Redis (dual write), writing evidence after the call.
