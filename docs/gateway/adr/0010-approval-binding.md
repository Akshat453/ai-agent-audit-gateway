# ADR-0010: Approvals bind the exact action tuple and are single-use
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper A §2 lists "mismatch between an approved action and the executed action". Paper B §III-B(3) asks for a token binding the approver to the specific action.
## Decision
An approval binds `{tenant, agent_id, tool_id, tool_version, args_digest, target, policy_id, policy_version, action_id, expires_at, nonce}`. `binding_digest = H(TAG("AGW/approval/v1") || cbor(binding))`. At dispatch the gateway re-evaluates policy and recomputes the binding. Any difference invalidates the approval and requires a new evaluation and a new approval. The nonce is single-use (unique constraint inserted in the dispatch tx). Expiry is checked against DB time at claim. The approver identity comes from the human's authenticated session (Phase 4).
## Consequences
+ INV-11. + Verifier check V10 can prove "approved == executed" at digest level.
− Any arg change, even cosmetic after validation, needs re-approval (intended).
