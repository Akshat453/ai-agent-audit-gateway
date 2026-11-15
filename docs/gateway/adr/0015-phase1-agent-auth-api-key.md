# ADR-0015: Phase 1 agent authentication: per-agent API key, stored as SHA-256 digest, Bearer token
Status: Accepted · Date: 2026-11-15 · Deciders: project owner (Phase 0)

## Context
Paper A §3 requires events to be bound to authenticated identities *before* hashing. Phase 1 needs a simple, sound mechanism.
## Decision
Token `agw_<key_id>_<secret>` (32 random bytes). DB stores `key_id` and `H(TAG("AGW/apikey/v1")||token)` only. Lookup by `key_id`, `hmac.compare_digest`, dummy compare for unknown ids, revocation and expiry checks. Agent identity comes **only** from the credential. A mismatching body `agent_id` → 403 + `SECURITY_VIOLATION` event. A fast hash is adequate because the secret has 256-bit entropy.
## Consequences
+ Simple, testable, no plaintext at rest.
− Bearer tokens can be stolen in transit or from agent hosts. mTLS / OIDC workload identity come in Phase 10, behind the same `AuthenticatedAgent` contract.
