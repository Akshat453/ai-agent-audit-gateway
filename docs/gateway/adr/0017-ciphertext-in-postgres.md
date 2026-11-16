# ADR-0017: Store payload ciphertext in Postgres in the event's transaction; MinIO for large blobs and bundles
Status: Accepted, **superseded in part by [ADR-0029](0029-phase7-encryption-disclosure.md)** (threshold 64 KiB, ciphertext in `payload_objects`, deletable only via the evidenced erasure path) · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Writing the ciphertext to an object store and the event to Postgres is a dual write. A crash between them yields an event whose payload is missing, or orphaned ciphertext.
## Decision
Payloads ≤ 1 MiB: ciphertext goes into append-only `evidence_payloads` in the same tx as the event. Wrapped DEKs go into mutable `payload_keys` (re-wrap, erasure). Larger blobs go to MinIO first, content-addressed, referenced by digest, with orphans garbage-collected. MinIO also stores exported evidence bundles.
## Consequences
+ Atomic evidence + payload. + MinIO outage doesn't block small actions.
− DB size grows with payloads. Monitor, and archive old epochs to bundles if needed.
