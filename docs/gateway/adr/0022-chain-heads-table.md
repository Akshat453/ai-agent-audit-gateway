# ADR-0022: Per-tenant chain head in `chain_heads`, locked with SELECT … FOR UPDATE
Status: Accepted · Date: 2026-11-15 · Deciders: Phase 2 implementation (pending owner review) · Supersedes the *mechanism* of ADR-0018 (its decision, single writer per tenant under a row lock, stands)

## Context
ADR-0018 allocates seq with `UPDATE tenants SET next_seq = next_seq + n … RETURNING`, and says Phase 2 also keeps `head_event_hash` on `tenants`. The Phase 2 prompt specifies a dedicated `chain_heads(tenant PK, last_seq, last_hash)` row read with `SELECT … FOR UPDATE`.
## Decision
- New table `chain_heads(tenant_id PK → tenants, last_seq bigint DEFAULT -1, last_hash bytea(32) DEFAULT ZERO32, updated_at)`.
- One row is created per tenant at tenant creation (`ensure_tenant`). Migration 0002 backfills existing tenants and drops `tenants.next_seq`.
- `EvidenceWriter.append` runs `SELECT last_seq, last_hash … FOR UPDATE` in the caller's transaction. It assigns `seq = last_seq + 1, prev = last_hash` per event, inserts the events and payloads, and updates the head in the same transaction.
- `agw_app` gets `SELECT` plus column `UPDATE(last_seq, last_hash, updated_at)` only.
## Consequences
+ The chain head (seq and hash) lives in one row the writer already locks. The tenants table is no longer a hot row.
+ Gap-free seq: allocation is inside the transaction, so a rollback returns the range (tested).
− Same single-writer-per-tenant bottleneck as ADR-0018. Phase 2 measured, locally and unvalidated, 470 events/s with 8 threads on 1 tenant vs 1,222 events/s on 8 tenants. Tenants scale independently; a single hot tenant does not.
− A privileged attacker who deletes a suffix can rewind `chain_heads` consistently. Only an externally held head detects that (Phase 3 epochs and later anchors; see Phase 2 doc).
