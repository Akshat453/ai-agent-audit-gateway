# ADR-0020: Phase 1 keeps validated dispatch args in `outbox_jobs.args` until the job finishes
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 1 implementation (pending owner review)

## Context
The executor must pass the validated args to the adapter after tx1 has committed, possibly in another process or after a restart (ADR-0004: the outbox row is the source of truth). 14 §3 lists no column that holds them: the payload store (`evidence_payloads`, encrypted) arrives in Phase 5, and `evidence_events` must not hold sensitive content (05 §4).
## Decision
Add `outbox_jobs.args jsonb NULL` (operational, mutable table). tx1 writes the *validated* args (Pydantic JSON dump) only for ALLOW decisions. The dispatch tx re-validates them against the tool's strict model before calling the adapter. When the job reaches DONE or FAILED the column is set to NULL. DENY / REQUIRE_APPROVAL requests persist no args at all in Phase 1.
## Consequences
+ Dispatch survives crashes and works out of process with no in-memory state. + Plaintext args live only for the lifetime of a pending/claimed job.
− Until Phase 5, args of in-flight jobs are plaintext in Postgres, readable by roles with SELECT on `outbox_jobs`. − Intent payloads (args of denied requests, `intent`, `context`) are not yet retained as evidence.
Phase 5 replaces this column with a reference to the encrypted `ACTION_REQUESTED` payload and drops it.
## Alternatives rejected
Args in `actions` (would outlive the job, kept for every DENY). Args in the evidence `body` (sensitive content in records, 05 §4). In-memory hand-off (violates ADR-0004).
