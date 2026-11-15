# ADR-0018: Per-tenant seq allocation by chain-head row lock (single writer)
Status: Accepted; mechanism superseded by [ADR-0022](0022-chain-heads-table.md) · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
The hash chain needs a gap-free, commit-ordered `seq` and the predecessor hash at insert time. Paper B §III-C/§V uses a single-writer path.
## Decision
In each evidence-writing tx: `UPDATE tenants SET next_seq = next_seq + n ... RETURNING` (Phase 2 also reads and updates `head_event_hash`). The row lock is held until commit, so commits are in seq order, and rollbacks don't leave gaps. Sealing uses a separate `epoch_heads` lock so it doesn't block writers.
## Consequences
+ INV-8 by construction. + Simple.
− Evidence writes serialize per tenant. tx1 is kept short (policy evaluated before the tx). Throughput is measured in Phase 8. Tenants scale independently.
## Alternatives rejected
Postgres SEQUENCE (gaps on rollback, commit order ≠ seq order). Assigning seq at seal time (the hash chain needs `prev` at insert).
