# ADR-0011: Non-idempotent tools are never auto-retried after an ambiguous outcome
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
A crash or timeout after dispatch leaves it unknown whether the side effect happened (08 §6, C4/C5).
## Decision
If `ACTION_DISPATCHED` exists and no result was recorded when the lease expires: for a non-idempotent tool, write `ACTION_OUTCOME_UNKNOWN` and route to reconciliation (adapter `probe` or human; Phase 4). Never re-invoke. Only tools declared `is_idempotent`, whose adapter accepts `idempotency_token = action_id`, may be re-dispatched, with an incremented attempt number.
## Consequences
+ INV-6: at most one invocation of a non-idempotent tool per action.
− Some actions need human resolution.
