# ADR-0008: One hash chain per tenant; risk changes sealing time, not order. Separate risk queues rejected.
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper A §5 proposes routine events in periodic Merkle batches and high-impact events anchored immediately or individually. One reading is separate queues/chains per risk level.
## Decision
Each tenant (security domain) has exactly one `seq`-ordered chain containing **all** its events. Epochs are contiguous seq ranges. Seal triggers: `max_events` OR `max_age` OR a committed event with risk ≥ HIGH (seal everything pending up to and including it). The CRITICAL authorization gets its own epoch (ADR-0009). HIGH/CRITICAL epochs are anchored with priority.
## Alternatives rejected: separate risk queues/chains
- No total order across queues. Reconstructing "review (LOW) before execution (HIGH)" (Paper A §5, segregation of duties) would need timestamps, which aren't an ordering source (Paper A §4), or forgeable cross-references.
- Suppression of the rarely anchored low queue doesn't break the high queue's continuity, so it goes undetected.
- N continuity checks plus a merge rule in the verifier.
- More anchors on average (one cadence per queue).
Full comparison: 09 §3.
## Consequences
+ One continuity check. Ordering is never ambiguous. + Latency for HIGH events equals the separate-queue design.
− Bursts of HIGH events produce many small epochs. Mitigated by `anchorBatch` and monitoring.
