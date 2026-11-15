# ADR-0009: CRITICAL pre-action anchoring gate
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
For the most dangerous actions we want a public commitment to the exact authorization *before* the side effect, so the operator can't rewrite it after an incident (Paper A §7 scenario; Paper B §II-D Scenario 1).
## Decision
For a CRITICAL action, the authorizing tx writes `ACTION_AUTHORIZED` at seq `s`, a DISPATCH job in `WAITING_ANCHOR` with a deadline, and a SEAL job. The sealer seals pending `[.., s−1]`, then `[s, s]` as its own epoch. The anchorer submits both in order. The job is released to PENDING only when that epoch's anchor reaches `AGW_ANCHOR_FINALITY`. If the deadline passes first: `ACTION_FAILED(ANCHOR_TIMEOUT)`, no side effect. Release and timeout both lock the job row and check status, so exactly one wins. `ACTION_DISPATCHED` records the anchor reference. Details: 09 §5.
## Consequences
+ INV-10. + A one-leaf epoch makes the gate check trivial.
− Adds anchor-finality latency to CRITICAL actions (measured in Phase 6). − Chain outage blocks CRITICAL actions (intended: fail closed).
− Anchoring is not authorization. It cannot make an unauthorized action acceptable.
