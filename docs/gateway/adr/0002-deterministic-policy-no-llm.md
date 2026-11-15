# ADR-0002: Authorization is deterministic policy code; no LLM in allow/deny
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
An LLM in the decision path is prompt-injectable (T5) and not reproducible, so an auditor couldn't re-derive a decision.
## Decision
Risk classification and policy evaluation are pure functions with explicit inputs (no I/O, clock, randomness or model calls). Decisions record `policy_id`, `policy_version`, `matched_rule_ids`, reason codes, risk factors and engine/classifier versions. import-linter forbids LLM SDK imports in `agw_gateway.policies` and `agw_gateway.risk`.
## Consequences
+ Re-running a recorded evaluation gives the same result. + Testable with Hypothesis.
− Less "smart" policies. Any future ML signal may only *raise* risk, via a new ADR.
