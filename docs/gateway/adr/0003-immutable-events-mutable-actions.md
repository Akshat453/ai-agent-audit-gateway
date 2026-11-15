# ADR-0003: Immutable lifecycle events; mutable operational actions table
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Fast status queries need mutable state. Evidence must never change (Paper B §II-C edit/delete threats).
## Decision
`actions` holds current status (mutable). `evidence_events` is append-only: no UPDATE/DELETE/TRUNCATE grants for `agw_app`, a row trigger and a TRUNCATE statement trigger that raise, and the table is owned by `agw_migrator`. `policies` (and later `evidence_payloads`) get the same treatment. The event sequence is authoritative. `actions.status` must be derivable from it.
## Consequences
+ Two independent DB-level defences, both tested. + Later hashing covers a stable set of rows.
− Phase 1 rows can't be backfilled with canonical bytes (see 14 §8). − A superuser can still disable triggers (R8). Hash chain + anchors detect that for sealed data.
