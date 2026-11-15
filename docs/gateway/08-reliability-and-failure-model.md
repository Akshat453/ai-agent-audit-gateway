# 08 — Reliability and Failure Model

Status: Accepted (Phase 0). ADRs: 0003, 0004, 0011, 0018. Sources: Paper B §III-C (single-writer
path), §VIII-A(5) (anchoring availability); Paper A §8 (operational questions).

## 1. Transactions

Every evidence event is inserted **in the same transaction** as the state change it records.
Nothing is "queued in memory".

| Tx | Writes | Commits before |
|---|---|---|
| **tx1** (request) | `idempotency_keys`, `actions`, `ACTION_REQUESTED`, `POLICY_EVALUATED`, then one of: `ACTION_DENIED` / `APPROVAL_REQUIRED` / `ACTION_AUTHORIZED` + `outbox_jobs(DISPATCH)`; (Phase 3+) `outbox_jobs(SEAL)` for HIGH+ | HTTP response |
| **claim** | `outbox_jobs.status=CLAIMED`, `lease_expires_at` | dispatch tx |
| **dispatch** | `ACTION_DISPATCHED`, `actions.status=DISPATCHED` | **adapter call** |
| **result** | `ACTION_COMPLETED`/`ACTION_FAILED`, `actions.status`, `outbox_jobs.status=DONE` | — |
| **reconcile** | `ACTION_OUTCOME_UNKNOWN` (or `ACTION_RECONCILED`), `outbox_jobs.status=FAILED` | — |
| **seal** (Phase 3) | `epochs`, `anchors(PENDING)`, `outbox_jobs(ANCHOR)` | — |

Policy and risk evaluation (pure, no I/O) happen **before** tx1 opens, so the chain-head lock
(§3) is held as briefly as possible. The policy version used is read before evaluation and
recorded. Policies are immutable rows, so the version can't change under the evaluation.

## 2. Immutability enforcement (two independent layers)

| Layer | Mechanism | Phase 1 test |
|---|---|---|
| Privileges | `agw_migrator` owns all tables. `agw_app` gets `SELECT, INSERT` on `evidence_events`, `policies`, `evidence_payloads`. **No** `UPDATE, DELETE, TRUNCATE`. `agw_app` isn't the owner, so it can't `ALTER TABLE … DISABLE TRIGGER`. | As `agw_app`: `UPDATE`/`DELETE`/`TRUNCATE` fail with SQLSTATE `42501` (insufficient_privilege). |
| Trigger | `agw_forbid_mutation()` raises `SQLSTATE 'P0001'`, message `'<table> is append-only'`. Fired `BEFORE UPDATE OR DELETE … FOR EACH ROW` and `BEFORE TRUNCATE … FOR EACH STATEMENT`. The statement-level one is needed because row triggers don't fire on TRUNCATE. | As `agw_migrator` (which has the privileges): the same statements fail with the trigger's error. |

A Postgres superuser can still disable triggers. That's residual risk R8 (03 §6), detected for
sealed data by hashes and anchors.

## 3. Sequence allocation (single writer per tenant; ADR-0018)

```sql
UPDATE tenants SET next_seq = next_seq + :n
 WHERE tenant_id = :tenant
RETURNING next_seq - :n AS first_seq;      -- Phase 2 also reads/updates head_event_hash
```

- The row lock is held until tx commit, so transactions that write events for one tenant
  commit **in seq order**. A rolled-back tx also rolls back its seq increment. So `seq` is
  **gap-free** and readers never see seq `s+1` committed before `s`.
- This is the "single-writer path" Paper B §III-C/§V uses. Its cost is that evidence writes
  serialize per tenant. Phase 8 measures throughput per tenant. Tenants don't contend with each
  other.
- `agw_app` gets column-level `UPDATE (next_seq, head_event_hash)` on `tenants` only.

## 4. Outbox and executor

`outbox_jobs` columns: `job_id`, `kind` (`DISPATCH` | `SEAL` | `ANCHOR`), `action_id`
(unique for DISPATCH), `tenant_id`, `status` (`PENDING` | `WAITING_ANCHOR` | `CLAIMED` |
`DONE` | `FAILED`), `available_at`, `attempts`, `claimed_by`, `lease_expires_at`,
`last_error_code`, `created_at`.

Claim (one short tx):
```sql
SELECT job_id FROM outbox_jobs
 WHERE kind = 'DISPATCH' AND status = 'PENDING' AND available_at <= now()
 ORDER BY job_id
 FOR UPDATE SKIP LOCKED
 LIMIT :batch;
UPDATE outbox_jobs SET status='CLAIMED', claimed_by=:worker, attempts=attempts+1,
       lease_expires_at = now() + :lease WHERE job_id = ANY(:ids);
```

Then: dispatch tx (ACTION_DISPATCHED) → adapter call with timeout `< lease` → result tx.
Phase 1 runs the executor in-process (`AGW_EXECUTOR_MODE=inprocess`). It still claims from the
outbox table, so the row is the source of truth (Phase 1 prompt, item 7).

## 5. Idempotency

- `Idempotency-Key` header is required on `POST /v1/actions`: 1–128 chars, `[A-Za-z0-9_\-:.]`.
- `request_fingerprint = H(TAG("AGW/request/v1") || cbor(normalized_request))`. Here
  `normalized_request` = `{tool, tool_version, environment, run_id, args}`, with args as
  received (pre-validation, so even an invalid request has a stable fingerprint). Phase 1 may use
  sorted-key compact JSON instead of CBOR. The key table records `fingerprint_alg` so Phase 2 can
  switch.
- `idempotency_keys` PK = `(agent_id, key)`. It is inserted **first** in tx1. A concurrent
  duplicate blocks on the uncommitted unique-index entry. When the first tx commits, the second
  gets a unique violation, re-reads the row, and:
  - same fingerprint → returns the stored response (`200`, header `Idempotent-Replayed: true`);
  - different fingerprint → `409 IDEMPOTENCY_KEY_REUSED`.
- If the first tx rolls back, the second proceeds normally.
- Keys expire after 24 h (`expires_at`). Expired keys are deleted by a job. This table is
  operational, not evidence.
- Required test: 20 concurrent identical requests → 1 `actions` row, 1 `ACTION_REQUESTED`, ≤ 1
  adapter call.

## 6. Crash points

| # | Crash after | Durable state | Recovery | Side effects |
|---|---|---|---|---|
| C1 | nothing / mid-tx1 | none (rolled back) | Client retries with same key → processed fresh | none |
| C2 | tx1 commit | AUTHORIZED, job PENDING | Executor claims after restart | none yet |
| C3 | claim commit | job CLAIMED | Lease expires → job back to PENDING (no DISPATCHED exists, so the adapter was provably not called) | none |
| C4 | dispatch commit (DISPATCHED), before or during the adapter call | DISPATCHED, lease running | Lease expires → **ambiguous**. Non-idempotent tool: `ACTION_OUTCOME_UNKNOWN`, job FAILED, **never re-invoked** (ADR-0011). Idempotent tool (`is_idempotent` and adapter accepts `idempotency_token = action_id`): re-dispatch with a new `attempt` number. | unknown |
| C5 | adapter returned, before result commit | same as C4 | same as C4 | happened, unrecorded |
| C6 | result commit | COMPLETED/FAILED | none | recorded |
| C7 | (Phase 6, CRITICAL) job WAITING_ANCHOR | AUTHORIZED, epoch sealed, anchor pending | Anchorer continues. Gate re-checked on restart. Timeout → `ACTION_FAILED(ANCHOR_TIMEOUT)`. | none |

Phase 1 test: a crash hook between dispatch commit and the adapter call, then the reconciler
runs → status OUTCOME_UNKNOWN, spy adapter call count = 0. A second variant crashes after the
adapter call and asserts the call count stays 1.

## 7. Reconciliation

The reconciler runs periodically. It selects DISPATCH jobs `CLAIMED` with `lease_expires_at <
now()`:
- If no ACTION_DISPATCHED exists for the action → release the job to PENDING (C3).
- Else if the tool is non-idempotent → write `ACTION_OUTCOME_UNKNOWN` (reason
  `LEASE_EXPIRED_AFTER_DISPATCH`) and set the job FAILED.
- (Phase 4) Adapters MAY implement `probe(action_id) → Completed | Failed | Unknown`, e.g. look
  up a ticket by client token. A definite answer writes `ACTION_RECONCILED`. Otherwise a human
  resolves it through the API, and the human identity is recorded.

## 8. Fail-closed matrix

| Dependency down | POST /v1/actions | Dispatch | Evidence |
|---|---|---|---|
| PostgreSQL | **503 `DEPENDENCY_UNAVAILABLE`**, nothing executes | impossible (claim needs DB) | n/a |
| KEK / KMS (Phase 5) | **503**: payloads can't be encrypted, so the event can't be written | stops | — |
| MinIO (Phase 5) | Small payloads unaffected (stored in Postgres). Large-blob requests → 503. | continues | Bundle export delayed |
| Chain RPC (Phase 6) | Accepted | LOW–HIGH continue. CRITICAL waits → `ANCHOR_TIMEOUT`. | Epochs keep sealing. Anchors queue. The compromise window grows (Paper B §VIII-A(5)), and the monitor alerts. |
| Adapter timeout | — | `ACTION_FAILED(TIMEOUT)` if the adapter guarantees no effect on timeout, else `ACTION_OUTCOME_UNKNOWN` | recorded |

`/v1/ready` returns 503 if the DB check (`SELECT 1` as `agw_app`) fails. `/v1/health` is
liveness only.

## 9. Timeouts and limits (defaults)

Request body ≤ 256 KiB. Adapter timeout 10 s. Lease 30 s (> adapter timeout + margin).
Reconciler interval 10 s. DB statement timeout 5 s for tx1. All are settings.
