# ADR-0019: Monitoring evidence stream as a separate system tenant chain
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper A §5: verification reports "can be hashed and anchored as a separate monitoring evidence stream".
## Decision
The monitor (Phase 8) appends `MONITOR_REPORT` events to the reserved tenant `_monitor`, which has its own chain, epochs and anchors like any tenant. Agents can't authenticate into `_monitor`.
## Consequences
+ The supervisory process is itself tamper-evident. + Consistent with "one chain per security domain" (ADR-0008).
− Reports cover only what the monitor checks. They don't prove semantic correctness (Paper A §5).
