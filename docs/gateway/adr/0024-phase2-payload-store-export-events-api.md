# ADR-0024: Phase 2 plaintext payload store, operator-only export, scoped /v1/events
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 2 implementation (pending owner review)

## Decision
1. **Payload store.** `evidence_payloads(event_id PK → evidence_events, tenant_id, seq, storage='plaintext', content ≤ 1 MiB)` is append-only, with the same triggers and grants as `evidence_events`. It is written in the event's transaction (consistent with ADR-0017). Access goes through `PayloadStore.store_payload()/load_payload()`, so the encryption phase swaps `PlaintextPayloadStore` for an AES-256-GCM store (ADR-0012) without touching the header commitment, which is over the plaintext canonical bytes (06 §5). Each payload carries a fresh 32-byte salt and its event id (ADR-0013) already.
2. **Export.** `python -m agw_gateway.admin export-chain --tenant T --out export.jsonl` (format `agw-export/v1`, documented in `evidence/export.py`). It is an operator CLI only: exports contain plaintext payloads in Phase 2, so there is no agent-facing HTTP endpoint. `chain-head --tenant T` prints the current head, for use as a trusted head.
3. **`GET /v1/events`.** It returns headers only, never payloads. Filters: `agent_id`, `action_id`, `run_id`, `tool`, `type`, `from_seq`, `to_seq`, `limit` ≤ 500, with `next_from_seq` paging. An agent sees only its own events unless it holds the scope `audit:events:read`, which allows tenant-wide reads. No cross-tenant access.
## Consequences
− Until encryption lands, payload plaintext sits in Postgres and in exports (marked in code, schema and docs). − Agents have no self-service export (by design).
